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

/** Read the raw PTE value.
 * @param state  Page table walk state.
 * @returns      Error status.
 *
 * On successful return, @c state->raw_pte contains the raw
 * PTE value for the current translation step.
 */
static addrxlat_status
read_pte(addrxlat_walk_t *state)
{
	addrxlat_ctx_t *ctx = state->ctx;
	const struct pgt_extra_def *pgt = &state->meth->extra.pgt;
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

DEFINE_INTERNAL(walk_init)

addrxlat_status
addrxlat_walk_init(addrxlat_walk_t *state, addrxlat_ctx_t *ctx,
		   const addrxlat_meth_t *meth, addrxlat_addr_t addr)
{
	state->ctx = ctx;
	state->meth = meth;

	return meth->walk_init(state, addr);
}

DEFINE_INTERNAL(walk_next)

addrxlat_status
addrxlat_walk_next(addrxlat_walk_t *state)
{
	const addrxlat_meth_t *meth = state->meth;
	addrxlat_status status;

	if (!state->level)
		return addrxlat_ok;

	--state->level;
	if (!state->level) {
		state->base.as = meth->def.target_as;
		state->base.addr += state->idx[0];
		return addrxlat_ok;
	}

	status = read_pte(state);
	if (status != addrxlat_ok)
		return status;

	state->base.as = meth->def.target_as;
	return meth->walk_step(state);
}

DEFINE_INTERNAL(walk)

addrxlat_status
addrxlat_walk(addrxlat_ctx_t *ctx, const addrxlat_meth_t *meth,
	      addrxlat_addr_t *paddr)
{
	addrxlat_walk_t walk;
	addrxlat_status status;

	status = internal_walk_init(&walk, ctx, meth, *paddr);
	while (status == addrxlat_continue)
		status = internal_walk_next(&walk);

	if (status == addrxlat_ok)
		*paddr = walk.base.addr;
	return status;
}

/** Update page table walk state for huge page.
 * @param state  Page table walk state.
 * @returns      Always @c addrxlat_continue.
 *
 * This function skips all lower paging levels and updates the state
 * so that the next page table step adds the correct page offset and
 * terminates.
 */
addrxlat_status
pgt_huge_page(addrxlat_walk_t *state)
{
	const addrxlat_def_pgt_t *pgt = &state->meth->def.param.pgt;
	addrxlat_addr_t off = 0;

	while (state->level > 1) {
		--state->level;
		off |= state->idx[state->level];
		off <<= pgt->pf.bits[state->level - 1];
	}
	state->idx[0] |= off;
	return addrxlat_continue;
}
