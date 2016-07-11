/** @internal @file src/addrxlat/ppc64.c
 * @brief Routines specific to IBM POWER.
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

/** Bit position of the virtual address region.
 */
#define REGION_SHIFT	60

#define USER_REGION_ID          0x0
#define KERNEL_REGION_ID        0xc
#define VMALLOC_REGION_ID       0xd /* FIXME: only true for Book3S! */
#define VMEMMAP_REGION_ID       0xf

/**  A page table entry is huge if the bottom two bits != 00.
 */
#define HUGE_PTE_MASK     ((addrxlat_pte_t)0x03)

static addrxlat_status
check_vtop_state(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	unsigned short lvl = ctx->pf->levels;
	unsigned region;
	addrxlat_addr_t mask;

	region = state->idx[lvl] >> (REGION_SHIFT - ctx->vaddr_bits);
	if (region != VMALLOC_REGION_ID && region != USER_REGION_ID)
		return set_error(ctx, addrxlat_invalid,
				 "Region 0x%x has no page tables", region);

	mask = (1ULL << (REGION_SHIFT - ctx->vaddr_bits)) - 1;
	if (state->idx[lvl] & mask)
		return set_error(ctx, addrxlat_invalid,
				 "Virtual address too big");

	return addrxlat_continue;
}

/**  Check whether a page table entry is huge.
 * @param pte  Page table entry (value).
 * @returns    Non-zero if this is a huge page entry.
 */
static inline int
is_hugepte(addrxlat_pte_t pte)
{
	return (pte & HUGE_PTE_MASK) != 0x0;
}

/** Update VTOP state for huge page.
 * @param ctx    Address translation object.
 * @param state  VTOP translation state.
 * @returns      Always @c addrxlat_continue.
 *
 * This function skips all lower paging levels and updates the state
 * so that the next VTOP step adds the correct page offset and terminates.
 */
addrxlat_status
huge_page(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = (state->raw_pte >>
			    ctx->pf->rpn_shift) << ctx->pf->bits[0];
	return vtop_huge_page(ctx, state);
}

/** IBM POWER vtop function.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
vtop_ppc64(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
	};

	if (!state->level)
		return check_vtop_state(ctx, state);

	if (!state->raw_pte)
		return set_error(ctx, addrxlat_notpresent,
				 "%s[%u] is none",
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level]);

	if (state->level > 1) {
		addrxlat_addr_t table_size;

		if (is_hugepte(state->raw_pte))
			return huge_page(ctx, state);

		table_size = ((addrxlat_addr_t)1 << ctx->pte_shift <<
			      ctx->pf->bits[state->level - 1]);
		state->base.as = ADDRXLAT_KVADDR;
		state->base.addr = state->raw_pte & ~(table_size - 1);
	} else {
		state->base.as = ADDRXLAT_MACHPHYSADDR;
		state->base.addr = (state->raw_pte >>
				    ctx->pf->rpn_shift) << ctx->pf->bits[0];
	}

	return addrxlat_continue;
}
