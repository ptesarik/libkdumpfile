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
addrxlat_set_pgt_root(addrxlat_ctx *ctx, addrxlat_fulladdr_t addr)
{
	ctx->pgt_root = addr;
}

addrxlat_fulladdr_t
addrxlat_get_pgt_root(addrxlat_ctx *ctx)
{
	return ctx->pgt_root;
}

/** Read the raw PTE value.
 * @param ctx    Address translation object.
 * @param state  VTOP translation state.
 * @returns      Error status.
 *
 * On successful return, @c state->raw_pte contains the raw
 * PTE value for the current translation step.
 */
static addrxlat_status
read_pte(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	addrxlat_fulladdr_t ptep;
	uint64_t pte64;
	uint32_t pte32;
	addrxlat_pte_t pte;
	addrxlat_status status;

	ptep = state->base;
	ptep.addr += state->idx[state->level] << ctx->pte_shift;

	switch(ctx->pte_shift) {
	case 2:
		status = ctx->cb_read32(ctx, ptep, &pte32, NULL);
		pte = pte32;
		break;

	case 3:
		status = ctx->cb_read64(ctx, ptep, &pte64, NULL);
		pte = pte64;
		break;

	default:
		return set_error(ctx, addrxlat_notimpl,
				 "Unsupported PTE size: %u",
				 1 << ctx->pte_shift);
	}

	if (status == addrxlat_ok)
		state->raw_pte = pte;
	return status;
}

addrxlat_status
addrxlat_vtop_start(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state,
		    addrxlat_addr_t vaddr)
{
	unsigned short i;
	addrxlat_status status;

	state->base = ctx->pgt_root;
	for (i = 0; i < ctx->pf->levels; ++i) {
		unsigned short bits = ctx->pf->bits[i];
		addrxlat_addr_t mask = bits < sizeof(addrxlat_addr_t) * 8
			? ((addrxlat_addr_t)1 << bits) - 1
			: ~(addrxlat_addr_t)0;
		state->idx[i] = vaddr & mask;
		vaddr >>= bits;
	}

	state->level = 0;
	status = ctx->vtop_step(ctx, state);
	if (status == addrxlat_continue)
		state->level = ctx->pf->levels;
	return status;
}

addrxlat_status
addrxlat_vtop_next(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
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

	return ctx->vtop_step(ctx, state);
}

addrxlat_status
addrxlat_vtop_pgt(addrxlat_ctx *ctx,
		  addrxlat_addr_t vaddr, addrxlat_addr_t *paddr)
{
	addrxlat_vtop_state_t state;
	addrxlat_status status;

	status = addrxlat_vtop_start(ctx, &state, vaddr);
	while (status == addrxlat_continue)
		status = addrxlat_vtop_next(ctx, &state);

	if (status == addrxlat_ok)
		*paddr = state.base.addr;

	return status;
}

/** Null vtop function. It does not modify anything and always succeeds. */
addrxlat_status
vtop_none(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	return addrxlat_continue;
}
