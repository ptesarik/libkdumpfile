/** @internal @file src/addrxlat/vtop.c
 * @brief Virtual to physical address translation.
 */
/* Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   libkdumpfile is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.
*/

#include "addrxlat-priv.h"

void
addrxlat_set_pgt(addrxlat_ctx *ctx, addrxlat_pgt_t *pgt)
{
	if (ctx->pgt)
		internal_pgt_decref(ctx->pgt);
	internal_pgt_incref(pgt);
	ctx->pgt = pgt;
}

addrxlat_pgt_t *
addrxlat_get_pgt(addrxlat_ctx *ctx)
{
	if (ctx->pgt)
		internal_pgt_incref(ctx->pgt);
	return ctx->pgt;
}

addrxlat_status
addrxlat_set_paging_form(addrxlat_ctx *ctx, const addrxlat_paging_form_t *pf)
{
	addrxlat_pgt_t *pgt;
	addrxlat_status status;

	pgt = internal_pgt_new();
	if (!pgt)
		return set_error(ctx, addrxlat_nomem,
				 "Cannot allocate pgt");

	status = internal_pgt_set_form(pgt, pf);
	if (status != addrxlat_ok) {
		internal_pgt_decref(pgt);
		return set_error(ctx, status,
				 "Cannot set paging form");
	}

	if (ctx->pgt)
		internal_pgt_decref(ctx->pgt);
	ctx->pgt = pgt;

	return addrxlat_ok;
}

/** Read the raw PTE value.
 * @param ctx    Address translation object.
 * @param state  Page table walk state.
 * @returns      Error status.
 *
 * On successful return, @c state->raw_pte contains the raw
 * PTE value for the current translation step.
 */
static addrxlat_status
read_pte(addrxlat_ctx *ctx, addrxlat_pgt_walk_t *state)
{
	const addrxlat_pgt_t *pgt = ctx->pgt;
	uint64_t pte64;
	uint32_t pte32;
	addrxlat_pte_t pte;
	addrxlat_status status;

	state->base.addr += state->idx[state->level] << pgt->pte_shift;

	switch(pgt->pte_shift) {
	case 2:
		status = ctx->cb_read32(ctx->priv, &state->base, &pte32);
		pte = pte32;
		break;

	case 3:
		status = ctx->cb_read64(ctx->priv, &state->base, &pte64);
		pte = pte64;
		break;

	default:
		return set_error(ctx, addrxlat_notimpl,
				 "Unsupported PTE size: %u",
				 1 << pgt->pte_shift);
	}

	if (status == addrxlat_ok)
		state->raw_pte = pte;
	return status;
}

DEFINE_INTERNAL(pgt_start)

addrxlat_status
addrxlat_pgt_start(addrxlat_ctx *ctx, addrxlat_pgt_walk_t *state,
		   addrxlat_addr_t addr)
{
	const addrxlat_pgt_t *pgt = ctx->pgt;
	unsigned short i;
	addrxlat_status status;

	for (i = 0; i < pgt->pf.levels; ++i) {
		unsigned short bits = pgt->pf.bits[i];
		addrxlat_addr_t mask = bits < sizeof(addrxlat_addr_t) * 8
			? ((addrxlat_addr_t)1 << bits) - 1
			: ~(addrxlat_addr_t)0;
		state->idx[i] = addr & mask;
		addr >>= bits;
	}
	state->idx[i] = addr;

	state->level = 0;
	status = pgt->pgt_step(ctx, state);
	if (status == addrxlat_continue)
		state->level = pgt->pf.levels;
	return status;
}

DEFINE_INTERNAL(pgt_next)

addrxlat_status
addrxlat_pgt_next(addrxlat_ctx *ctx, addrxlat_pgt_walk_t *state)
{
	const addrxlat_pgt_t *pgt = ctx->pgt;
	addrxlat_status status;

	if (!state->level)
		return addrxlat_ok;

	--state->level;
	if (!state->level) {
		state->base.as = ADDRXLAT_KPHYSADDR;
		state->base.addr += state->idx[0];
		return addrxlat_ok;
	}

	status = read_pte(ctx, state);
	if (status != addrxlat_ok)
		return status;

	return pgt->pgt_step(ctx, state);
}

DEFINE_INTERNAL(pgt)

addrxlat_status
addrxlat_pgt(addrxlat_ctx *ctx, addrxlat_pgt_walk_t *state,
	     addrxlat_addr_t addr)
{
	addrxlat_status status;

	status = internal_pgt_start(ctx, state, addr);
	while (status == addrxlat_continue)
		status = internal_pgt_next(ctx, state);

	return status;
}

/** Update page table walk state for huge page.
 * @param ctx    Address translation object.
 * @param state  Page table walk state.
 * @returns      Always @c addrxlat_continue.
 *
 * This function skips all lower paging levels and updates the state
 * so that the next page table step adds the correct page offset and
 * terminates.
 */
addrxlat_status
pgt_huge_page(addrxlat_ctx *ctx, addrxlat_pgt_walk_t *state)
{
	const addrxlat_pgt_t *pgt = ctx->pgt;
	addrxlat_addr_t off = 0;

	while (state->level > 1) {
		--state->level;
		off |= state->idx[state->level];
		off <<= pgt->pf.bits[state->level - 1];
	}
	state->idx[0] |= off;
	return addrxlat_continue;
}

/** Null pgt function. It does not modify anything and always succeeds. */
addrxlat_status
pgt_none(addrxlat_ctx *ctx, addrxlat_pgt_walk_t *state)
{
	return addrxlat_continue;
}

DEFINE_INTERNAL(by_def)

/** Translate an address using direct page table origin.
 * @param ctx    Address translation object.
 * @param paddr  Address.
 * @param def    Translation definition.
 */
static addrxlat_status
pgt_xlat_by_def(addrxlat_ctx *ctx, addrxlat_addr_t *paddr,
		const addrxlat_def_t *def)
{
	addrxlat_pgt_walk_t state;
	addrxlat_status status;

	state.base = (def->method == ADDRXLAT_PGT
		      ? def->pgt
		      : *def->ppgt);
	status = internal_pgt(ctx, &state, *paddr);
	if (status == addrxlat_ok)
		*paddr = state.base.addr;
	return status;
}

addrxlat_status
addrxlat_by_def(addrxlat_ctx *ctx, addrxlat_addr_t *paddr,
		const addrxlat_def_t *def)
{
	switch (def->method) {
	case ADDRXLAT_NONE:
		return set_error(ctx, addrxlat_invalid,
				 "No translation defined");

	case ADDRXLAT_LINEAR:
		*paddr -= def->off;
		return addrxlat_ok;

	case ADDRXLAT_LINEAR_IND:
		*paddr -= *def->poff;
		return addrxlat_ok;

	case ADDRXLAT_PGT:
	case ADDRXLAT_PGT_IND:
		return pgt_xlat_by_def(ctx, paddr, def);

	default:
		return set_error(ctx, addrxlat_invalid,
				 "Unknown translation method: %u\n",
				 (unsigned) def->method);
	}
}
