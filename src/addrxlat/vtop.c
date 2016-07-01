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

void
addrxlat_vtop_start(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state,
		    addrxlat_addr_t vaddr)
{
	unsigned short i;

	state->level = ctx->pf->levels;
	state->base = ctx->pgt_root;
	for (i = 0; i < ctx->pf->levels; ++i) {
		unsigned short bits = ctx->pf->bits[i];
		addrxlat_addr_t mask = bits < sizeof(addrxlat_addr_t) * 8
			? ((addrxlat_addr_t)1 << bits) - 1
			: ~(addrxlat_addr_t)0;
		state->idx[i] = vaddr & mask;
		vaddr >>= bits;
	}
}

addrxlat_status
addrxlat_vtop_next(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	if (!state->level)
		return addrxlat_ok;

	--state->level;
	if (!state->level) {
		state->base.as = ADDRXLAT_KPHYSADDR;
		state->base.addr += state->idx[0];
		return addrxlat_ok;
	}

	return ctx->vtop_step(ctx, state);
}

addrxlat_status
addrxlat_vtop_pgt(addrxlat_ctx *ctx,
		  addrxlat_addr_t vaddr, addrxlat_addr_t *paddr)
{
	addrxlat_vtop_state_t state;
	addrxlat_status status;

	addrxlat_vtop_start(ctx, &state, vaddr);
	do {
		status = addrxlat_vtop_next(ctx, &state);
	} while (status == addrxlat_continue);

	if (status == addrxlat_ok)
		*paddr = state.base.addr;

	return status;
}

addrxlat_status
vtop_simple(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	addrxlat_fulladdr_t ptep;
	uint32_t pte32;
	uint64_t pte64;
	addrxlat_status status;

	ptep = state->base;
	ptep.addr += state->idx[state->level] * ctx->pf->pteval_size;
	switch (ctx->pf->pteval_size) {
	case 4:
		status = ctx->cb_read32(ctx, ptep, &pte32, NULL);
		pte64 = pte32;
		break;

	case 8:
		status = ctx->cb_read64(ctx, ptep, &pte64, NULL);
		break;

	default:
		return set_error(ctx, addrxlat_notimplemented,
				 "Unsupported PTE size: %zd",
				 ctx->pf->pteval_size);
	}
	if (status != addrxlat_ok)
		return status;

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = pte64 & ctx->page_mask;

	return addrxlat_continue;
}
