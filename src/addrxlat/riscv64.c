/** @internal @file src/addrxlat/riscv64.c
 * @brief Routines specific to RISC-V Sv39, Sv48 and Sv57
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

#include <stdlib.h>
#include <string.h>

#include "addrxlat-priv.h"
#include <linux/version.h>

/** Maximum physical page number bits (architectural limit). */
#define PPN_MAX_BITS	44

/** Page shift (log2 4K). */
#define PAGE_SHIFT	12

/** Page mask. */
#define PAGE_MASK	ADDR_MASK(PAGE_SHIFT)

#define PTE_MASK(bits)		(((uint64_t)1<<bits) - 1)
#define PTE_VAL(x, shift, bits)	(((x) >> (shift)) & PTE_MASK(bits))

/** Values for the @ref PTE_PERM field. */
enum pte_page_perm {
	PTE_PAGE_TABLE = 0,	/**< Pointer to next level of page table. */
	PTE_PAGE_RO = 1,	/**< Read-only page. */
	PTE_PAGE_RW = 3,	/**< Read-write page. */
	PTE_PAGE_XO = 4,	/**< Execute-only page. */
	PTE_PAGE_RX = 5,	/**< Read-execute page. */
	PTE_PAGE_RWX = 7,	/**< Read-write-execute page. */
};

#define PTE_VALID(x)	PTE_VAL(x, 0, 1)
#define PTE_PERM(x)	((enum pte_page_perm)PTE_VAL(x, 1, 3))
#define PTE_PPN(x)	PTE_VAL(x, 10, PPN_MAX_BITS)

/** Descriptive names for page tables.
 * These names are used in error messages.
 */
static const char pgt_full_name[][16] = {
	"Page",
	"Level 0 table",
	"Level 1 table",
	"Level 2 table",
	"Level 3 table",
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
	"p4d",
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
			 pgt_full_name[step->remain],
			 pte_name[step->remain - 1],
			 (unsigned) step->idx[step->remain],
			 step->raw.pte);
}

/** RISC-V 64-bit page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_riscv64(addrxlat_step_t *step)
{
	addrxlat_pte_t pte;
	addrxlat_status status;

	status = read_pte64(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	if (!PTE_VALID(pte))
		return pte_not_present(step);

	step->base.addr = PTE_PPN(pte) << PAGE_SHIFT;
	step->base.as = step->meth->target_as;

	if (step->remain > 1 && PTE_PERM(pte) != PTE_PAGE_TABLE) {
		addrxlat_addr_t mask = pf_table_mask(
			&step->meth->param.pgt.pf, step->remain);
		step->base.addr &= ~mask;
		return pgt_huge_page(step);
	}
	if (step->remain == 1 && PTE_PERM(pte) == PTE_PAGE_TABLE)
		return pte_invalid(step);

	step->base.addr &= ~PAGE_MASK;
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}
