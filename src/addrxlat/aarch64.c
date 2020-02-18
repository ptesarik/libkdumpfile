/** @internal @file src/addrxlat/aarch64.c
 * @brief Routines specific to ARM AArch64
 */
/* Copyright (C) 2020 Petr Tesarik <ptesarik@suse.com>

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

#include <stdlib.h>

#include "addrxlat-priv.h"

/* Maximum physical address bits (architectural limit) */
#define PA_MAX_BITS	48
#define PA_MASK		ADDR_MASK(PA_MAX_BITS)

#define PTE_MASK(bits)		(((uint64_t)1<<bits) - 1)
#define PTE_VAL(x, shift, bits)	(((x) >> (shift)) & PTE_MASK(bits))

#define PTE_VALID(x)	PTE_VAL(x, 0, 1)
#define PTE_TYPE(x)	((enum pte_type)PTE_VAL(x, 0, 2))

/** Values for the @ref PTE_TYPE field. */
enum pte_type {
	PTE_TYPE_BLOCK = 1,	/**< Block descriptor. */
	PTE_TYPE_TABLE = 3,	/**< Table descriptor. */
};

/** 1G page mask. */
#define PAGE_MASK_1G		ADDR_MASK(30)

/** Descriptive names for page tables.
 * These names are used in error messages.
 */
static const char pgt_full_name[][16] = {
	"Page",
	"Level 3 table",
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
	"pmd",
	"pud",
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

/** Set an appropriate error message if the entry contains invalid data.
 * @param step  Current step state.
 * @returns     Error status.
 */
static addrxlat_status
pte_invalid(addrxlat_step_t *step)
{
	return set_error(step->ctx, ADDRXLAT_ERR_INVALID,
			 "Invalid %s entry: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
			 pgt_full_name[step->remain - 1],
			 pte_name[step->remain - 1],
			 (unsigned) step->idx[step->remain],
			 step->raw.pte);
}

/** ARM AArch64 page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_aarch64(addrxlat_step_t *step)
{
	addrxlat_status status;

	status = read_pte64(step);
	if (status != ADDRXLAT_OK)
		return status;

	if (!PTE_VALID(step->raw.pte))
		return pte_not_present(step);

	step->base.addr = step->raw.pte & PA_MASK;
	step->base.as = step->meth->target_as;

	if (PTE_TYPE(step->raw.pte) == PTE_TYPE_BLOCK) {
		addrxlat_addr_t mask = pf_table_mask(
			&step->meth->param.pgt.pf, step->remain);
		if (mask > PAGE_MASK_1G)
			return pte_invalid(step);
		step->base.addr &= ~mask;
		return pgt_huge_page(step);
	}

	step->base.addr &= ~pf_page_mask(&step->meth->param.pgt.pf);
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}
