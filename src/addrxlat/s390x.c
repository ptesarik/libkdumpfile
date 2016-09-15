/** @internal @file src/addrxlat/s390x.c
 * @brief Routines specific to IBM z/Architecture.
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

/* Use IBM's official bit numbering to match spec... */
#define PTE_MASK(bits)		(((uint64_t)1<<bits) - 1)
#define PTE_VAL(x, shift, bits)	(((x) >> (64-(shift)-(bits))) & PTE_MASK(bits))

#define PTE_FC(x)	PTE_VAL(x, 53, 1)
#define PTE_I(x)	PTE_VAL(x, 58, 1)
#define PTE_TF(x)	PTE_VAL(x, 56, 2)
#define PTE_TT(x)	PTE_VAL(x, 60, 2)
#define PTE_TL(x)	PTE_VAL(x, 62, 2)

/* Page-Table Origin has 2K granularity in hardware */
#define PTO_MASK	(~(((uint64_t)1 << 11) - 1))

/** IBM z/Architecture page table step function.
 * @param state  Page table walk state.
 * @returns      Error status.
 */
addrxlat_status
pgt_s390x(addrxlat_walk_t *state)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Segment table",
		"Region 3 table",
		"Region 2 table",
		"Region 1 table"
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
		"rg1",		/* Invented; does not exist in the wild. */
	};
	const struct pgt_xlat *pgt = &state->def->pgt;

	if (PTE_I(state->raw_pte))
		return set_error(state->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	if (state->level >= 2 && PTE_TT(state->raw_pte) != state->level - 2)
		return set_error(state->ctx, addrxlat_invalid,
				 "Table type field %u in %s",
				 (unsigned) PTE_TT(state->raw_pte),
				 pgt_full_name[state->level]);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = state->raw_pte;

	if (state->level >= 2 && state->level <= 3 &&
	    PTE_FC(state->raw_pte)) {
		state->base.addr &= pgt->pgt_mask[state->level - 1];
		return pgt_huge_page(state);
	}

	if (state->level >= 3) {
		unsigned pgidx = state->idx[state->level - 1] >>
			(pgt->pf.bits[state->level - 1] - pgt->pf.bits[0]);
		if (pgidx < PTE_TF(state->raw_pte) ||
		    pgidx > PTE_TL(state->raw_pte))
			return set_error(state->ctx, addrxlat_notpresent,
					 "%s index %u not within %u and %u",
					 pgt_full_name[state->level-1],
					 (unsigned) state->idx[state->level-1],
					 (unsigned) PTE_TF(state->raw_pte),
					 (unsigned) PTE_TL(state->raw_pte));
	}

	state->base.addr &= (state->level == 2 ? PTO_MASK : pgt->pgt_mask[0]);
	return addrxlat_continue;
}
