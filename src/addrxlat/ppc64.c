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

/**  Page entry flag for a huge page directory.
 * The corresponding entry is huge if the most significant bit is zero.
 */
#define PD_HUGE           ((addrxlat_pte_t)1 << 63)

/**  Page shift of a huge page directory.
 * If PD_HUGE is zero, the huge page shift is stored in the least
 * significant bits of the entry.
 */
#define HUGEPD_SHIFT_MASK 0x3f

/**  A page table entry is huge if the bottom two bits != 00.
 */
#define HUGE_PTE_MASK     ((addrxlat_pte_t)0x03)

#define MMU_PAGE_4K	0
#define MMU_PAGE_16K	1
#define MMU_PAGE_64K	2
#define MMU_PAGE_64K_AP 3	/* "Admixed pages" (hash64 only) */
#define MMU_PAGE_256K	4
#define MMU_PAGE_1M	5
#define MMU_PAGE_4M	6
#define MMU_PAGE_8M	7
#define MMU_PAGE_16M	8
#define MMU_PAGE_64M	9
#define MMU_PAGE_256M	10
#define MMU_PAGE_1G	11
#define MMU_PAGE_16G	12
#define MMU_PAGE_64G	13

#define MMU_PAGE_COUNT	14

/** Map from MMU page size to page shift. */
static unsigned mmu_pshift[MMU_PAGE_COUNT] = {
	[MMU_PAGE_4K] = 12,
	[MMU_PAGE_16K] = 14,
	[MMU_PAGE_64K] = 16,
	[MMU_PAGE_64K_AP] = 16,
	[MMU_PAGE_256K] = 18,
	[MMU_PAGE_1M] = 20,
	[MMU_PAGE_4M] = 22,
	[MMU_PAGE_8M] = 23,
	[MMU_PAGE_16M] = 24,
	[MMU_PAGE_64M] = 26,
	[MMU_PAGE_256M] = 28,
	[MMU_PAGE_1G] = 30,
	[MMU_PAGE_16G] = 34,
	[MMU_PAGE_64G] = 36,
};

/**  Check whether a Linux page directory is huge.
 * @param pte  Page table entry (value).
 * @returns    Non-zero if this is a huge page directory entry.
 */
static inline int
is_hugepd_linux(addrxlat_pte_t pte)
{
	return !(pte & PD_HUGE);
}

/**  Get the huge page directory shift.
 * @param hpde  Huge page directory entry.
 * @returns     Huge page bit shift.
 */
static inline unsigned
hugepd_shift(addrxlat_pte_t hpde)
{
	unsigned mmu_psize = (hpde & HUGEPD_SHIFT_MASK) >> 2;
	return mmu_psize < MMU_PAGE_COUNT
		? mmu_pshift[mmu_psize]
		: 0U;
}

/**  Translate a Linux huge page using its directory entry.
 * @param state  Page table walk state.
 * @returns      Always @c addrxlat_continue.
 */
static addrxlat_status
huge_pd_linux(addrxlat_walk_t *state)
{
	const struct pgt_xlat *pgt = &state->def->pgt;
	addrxlat_addr_t off;
	unsigned pdshift;
	unsigned short i;

	pdshift = hugepd_shift(state->raw_pte);
	if (!pdshift)
		return set_error(state->ctx, addrxlat_invalid,
				 "Invalid hugepd shift");

	state->base.as = ADDRXLAT_KVADDR;
	state->base.addr = (state->raw_pte & ~HUGEPD_SHIFT_MASK) | PD_HUGE;

	/* Calculate the total byte offset below current table. */
	off = 0;
	i = state->level;
	while (--i) {
		off |= state->idx[i];
		off <<= pgt->pf.bits[i - 1];
	}

	/* Calculate the index in the huge page table. */
	state->idx[1] = off >> pdshift;

	/* Update the page byte offset. */
	off &= ((addrxlat_addr_t)1 << pdshift) - 1;
	state->idx[0] |= off;

	state->level = 2;
	return addrxlat_continue;
}

/**  Check whether a Linux page table entry is huge.
 * @param pte  Page table entry (value).
 * @returns    Non-zero if this is a huge page entry.
 */
static inline int
is_hugepte_linux(addrxlat_pte_t pte)
{
	return (pte & HUGE_PTE_MASK) != 0x0;
}

/** Update page table walk state for Linux huge page.
 * @param state      Page table walk state.
 * @param rpn_shift  RPN shift.
 * @returns          Always @c addrxlat_continue.
 *
 * This function skips all lower paging levels and updates the state
 * so that the next page table translation step adds the correct page
 * offset and terminates.
 */
static addrxlat_status
huge_page_linux(addrxlat_walk_t *state, unsigned rpn_shift)
{
	const struct pgt_xlat *pgt = &state->def->pgt;

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = (state->raw_pte >>
			    rpn_shift) << pgt->pf.bits[0];
	return pgt_huge_page(state);
}

/** 64-bit IBM POWER Linux page table step function for RPN shift 30.
 * @param state      Page table walk state.
 * @param rpn_shift  RPN shift.
 * @returns          Error status.
 */
static addrxlat_status
pgt_ppc64_linux(addrxlat_walk_t *state, unsigned rpn_shift)
{
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
	};
	const struct pgt_xlat *pgt = &state->def->pgt;

	if (!state->raw_pte)
		return set_error(state->ctx, addrxlat_notpresent,
				 "%s[%u] is none",
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level]);

	if (state->level > 1) {
		addrxlat_addr_t table_size;

		if (is_hugepte_linux(state->raw_pte))
			return huge_page_linux(state, rpn_shift);

		if (is_hugepd_linux(state->raw_pte))
			return huge_pd_linux(state);

		table_size = ((addrxlat_addr_t)1 << pgt->pte_shift <<
			      pgt->pf.bits[state->level - 1]);
		state->base.as = ADDRXLAT_KVADDR;
		state->base.addr = state->raw_pte & ~(table_size - 1);
	} else {
		state->base.as = ADDRXLAT_MACHPHYSADDR;
		state->base.addr = (state->raw_pte >>
				    rpn_shift) << pgt->pf.bits[0];
	}

	return addrxlat_continue;
}

/** 64-bit IBM POWER Linux page table step function with RPN shift 30.
 * @param state  Page table walk state.
 * @returns      Error status.
 */
addrxlat_status
pgt_ppc64_linux_rpn30(addrxlat_walk_t *state)
{
	return pgt_ppc64_linux(state, 30);
}
