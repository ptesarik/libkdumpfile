/** @internal @file src/addrxlat/x86_64.c
 * @brief Routines specific to AMD64 and Intel 64.
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

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX	52
#define PHYSADDR_SIZE		((uint64_t)1 << PHYSADDR_BITS_MAX)
#define PHYSADDR_MASK		(~(PHYSADDR_SIZE-1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

/** Check whether an address is canonical.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Zero if @c state corresponds to a canonical address,
 *               non-zero otherwise.
 *
 * All bits above the virtual address space size must be copies of the
 * highest bit.
 */
static int
is_noncanonical(addrxlat_ctx *ctx, addrxlat_pgt_state_t *state)
{
	unsigned short lvl = ctx->pf.levels;
	struct {
		int bit : 1;
	} s;
	addrxlat_addr_t signext;

	s.bit = state->idx[lvl - 1] >> (ctx->pf.bits[lvl - 1] - 1);
	signext = s.bit & (ctx->pgt_mask[lvl - 1] >> ctx->vaddr_bits);
	return state->idx[lvl] != signext;
}

/** AMD64 (Intel 64) page table step function.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
pgt_x86_64(addrxlat_ctx *ctx, addrxlat_pgt_state_t *state)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Page directory",
		"PDPT table",
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
	};

	if (!state->level)
		return is_noncanonical(ctx, state)
			? set_error(ctx, addrxlat_invalid,
				    "Non-canonical address")
			: addrxlat_continue;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = state->raw_pte & ~PHYSADDR_MASK;
	if (state->level >= 2 && state->level <= 3 &&
	    (state->raw_pte & _PAGE_PSE)) {
		state->base.addr &= ctx->pgt_mask[state->level - 1];
		return pgt_huge_page(ctx, state);
	}

	state->base.addr &= ctx->pgt_mask[0];
	return addrxlat_continue;
}
