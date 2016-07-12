/** @internal @file src/addrxlat/ia32.c
 * @brief Routines specific to Intel IA32.
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

#define PGD_PSE_HIGH_SHIFT	13
#define PGD_PSE_HIGH_BITS	8
#define PGD_PSE_HIGH_MASK	(((uint64_t)1 << PGD_PSE_HIGH_BITS)-1)
#define pgd_pse_high(pgd)	\
	((((pgd) >> PGD_PSE_HIGH_SHIFT) & PGD_PSE_HIGH_MASK) << 32)

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX_PAE	52
#define PHYSADDR_SIZE_PAE	((uint64_t)1 << PHYSADDR_BITS_MAX_PAE)
#define PHYSADDR_MASK_PAE	(~(PHYSADDR_SIZE_PAE-1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

/** IA32 vtop function.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
vtop_ia32(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table"
	};
	static const char pte_name[][4] = {
		"pte",
		"pgd",
	};

	if (!state->level)
		return state->idx[ctx->pf.levels]
			? set_error(ctx, addrxlat_invalid,
				    "Virtual address too big")
			: addrxlat_continue;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	if (state->level == 2 && (state->raw_pte & _PAGE_PSE)) {
		--state->level;
		state->base.addr = (state->raw_pte & ctx->pgt_mask[1]) |
			pgd_pse_high(state->raw_pte);
		state->idx[0] |= state->idx[1] << ctx->pf.bits[0];
	} else
		state->base.addr = state->raw_pte & ctx->pgt_mask[0];

	return addrxlat_continue;
}

/** IA32 PAE vtop function.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
vtop_ia32_pae(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Page directory",
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pgd",
	};

	if (!state->level)
		return state->idx[ctx->pf.levels]
			? set_error(ctx, addrxlat_invalid,
				    "Virtual address too big")
			: addrxlat_continue;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = state->raw_pte & ~PHYSADDR_MASK_PAE;
	if (state->level == 2 && (state->raw_pte & _PAGE_PSE)) {
		--state->level;
		state->base.addr &= ctx->pgt_mask[1];
		state->idx[0] |= state->idx[1] << ctx->pf.bits[0];
	} else
		state->base.addr &= ctx->pgt_mask[0];

	return addrxlat_continue;
}
