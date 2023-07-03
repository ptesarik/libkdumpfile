/** @internal @file src/addrxlat/aarch32.c
 * @brief Routines specific to 32-bit Arm with short descriptors.
 */
/* Copyright (C) 2023 Petr Tesarik <petr@tesarici.cz>

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

#define PTE_MASK(bits)		(((uint64_t)1<<bits) - 1)
#define PTE_VAL(x, shift, bits)	(((x) >> (shift)) & PTE_MASK(bits))

#define PTE_TYPE(x)	PTE_VAL((x), 0, 2)
#define PTE_SECTYPE(x)	PTE_VAL((x), 18, 1)

#define SMALL_PAGE_MASK	PTE_MASK(12)
#define LARGE_PAGE_MASK	PTE_MASK(16)
#define PAGE_TABLE_MASK	PTE_MASK(10)

#define SECT_MASK	PTE_MASK(20)

#define SUPERSECT_MASK		PTE_MASK(24)
#define SUPERSECT_32_35(pte)	PTE_VAL((pte), 20, 4)
#define SUPERSECT_36_39(pte)	PTE_VAL((pte), 5, 4)

/** Descriptive names for page tables.
 * These names are used in error messages.
 */
static const char pgt_full_name[][16] = {
	"Page",
	"Level 2 table",
	"Level 1 table",
};

/** Short names for page table entries.
 * These names are used in error messages. They are named after their
 * use in the Linux kernel. This may have to change if you add support
 * for other operating systems.
 */
static const char pte_name[][4] = {
	"pte",
	"pgd",
};

/** Set an appropriate error message if the VALID bit is zero.
 * @param step  Current step state.
 * @returns     Error status.
 */
static addrxlat_status
pte_not_present(addrxlat_step_t *step)
{
	return !step->ctx->noerr.notpresent
		? set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
			    "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
			    pgt_full_name[step->remain - 1],
			    pte_name[step->remain - 1],
			    (unsigned) step->idx[step->remain],
			    step->raw.pte)
		: ADDRXLAT_ERR_NOTPRESENT;
}

/** Add overlapping index bits from a higher-level table.
 * @param step	Current step state.
 * @param bits	Number of overlapping bits.
 *
 * Some paging forms reuse low bits from the table index as high bits in
 * a lower-level index (or offset within page). The paging form definition
 * assigns these bits to the higher-level table to allow walking up to that
 * table with the generic page-table helpers. Use this function to adjust
 * the index into the next level.
 */
static void
add_overlap(addrxlat_step_t *step, unsigned bits)
{
	const addrxlat_paging_form_t *pf = &step->meth->param.pgt.pf;
	unsigned shift = pf->fieldsz[step->remain - 1];

	step->idx[step->remain - 1] +=
		(step->idx[step->remain] & ADDR_MASK(bits)) << shift;
}

/** Arm AArch32 page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_aarch32(addrxlat_step_t *step)
{
	addrxlat_pte_t pte;
	unsigned char type;
	addrxlat_status status;

	status = read_pte32(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	type = PTE_TYPE(pte);
	if (!type)
		return pte_not_present(step);

	step->base.as = step->meth->target_as;
	if (step->remain > 1) {
		/* Level 1 descriptor */
		if (type != 1) {
			if (PTE_SECTYPE(pte)) {
				/* Supersection */
				add_overlap(step, 4);
				step->base.addr = (pte & ~SUPERSECT_MASK) |
					(SUPERSECT_32_35(pte) << 32) |
					(SUPERSECT_36_39(pte) << 36);
			} else {
				/* Section */
				step->base.addr = pte & ~SECT_MASK;
			}
			return pgt_huge_page(step);
		}
		step->base.addr = pte & ~PAGE_TABLE_MASK;
	} else {
		/* Level 2 descriptor */
		if (type == 1) {
			/* Large page */
			add_overlap(step, 4);
			step->base.addr = pte & ~LARGE_PAGE_MASK;
		} else
			/* Small page */
			step->base.addr = pte & ~SMALL_PAGE_MASK;
		step->elemsz = 1;
	}

	return ADDRXLAT_OK;
}
