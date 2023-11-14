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

/** Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX	56
#define PHYSADDR_MASK		ADDR_MASK(PHYSADDR_BITS_MAX)

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

/** Determine Linux page table root.
 * @param ctl	     Initialization data.
 * @param[out] root  Page table root address (set on successful return).
 * @returns	     Error status.
 */
static addrxlat_status
get_linux_pgtroot(struct os_init_data *ctl, addrxlat_fulladdr_t *root)
{
	addrxlat_addr_t va_pa_offset;
	addrxlat_status status;

	status = get_symval(ctl->ctx, "swapper_pg_dir", &root->addr);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine page table virtual address");
	root->as = ADDRXLAT_KVADDR;

	/* If the read callback can handle virtual addresses, we're done. */
	if (direct_read_ok(ctl->ctx, root))
		return ADDRXLAT_OK;

	status = get_number(ctl->ctx, "va_kernel_pa_offset", &va_pa_offset);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine va_kernel_pa_offset");

	root->addr -= va_pa_offset;
	root->as = ADDRXLAT_KPHYSADDR;
	return ADDRXLAT_OK;
}

/** Initialize a translation map for Linux/riscv64.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
map_linux_riscv64(struct os_init_data *ctl)
{
	addrxlat_meth_t *meth;
	addrxlat_status status;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	if (opt_isset(ctl->popt, rootpgt))
		meth->param.pgt.root = ctl->popt.rootpgt;
	else {
		status = get_linux_pgtroot(ctl, &meth->param.pgt.root);
		if (status != ADDRXLAT_OK)
			return status;
	}

	return ADDRXLAT_OK;
}

/** Determine the number of virtual address bits
 * @param ctl  Initialization data.
 * @returns    Error status.
 *
 * On successful return, the virt_bits option is valid.
 */
static addrxlat_status
get_virt_bits(struct os_init_data *ctl)
{
	addrxlat_addr_t num;
	addrxlat_status status;

	if (opt_isset(ctl->popt, virt_bits))
		return ADDRXLAT_OK;

	if (ctl->os_type == OS_LINUX)
		status = get_number(ctl->ctx, "VA_BITS", &num);
	else
		status = set_error(ctl->ctx, ADDRXLAT_ERR_NOTIMPL,
				   "Unsupported OS type");

	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine VA_BITS");

	ctl->popt.virt_bits = num;
	ctl->popt.isset[ADDRXLAT_OPT_virt_bits] = true;
	return ADDRXLAT_OK;
}

/** Initialize the page table translation method.
 * @param ctl      Initialization data.
 * @returns        Error status.
 */
static addrxlat_status
init_pgt_meth(struct os_init_data *ctl)
{
	static const addrxlat_paging_form_t riscv64_pf = {
		.pte_format = ADDRXLAT_PTE_RISCV64,
		.nfields = 5,
		.fieldsz = { 12, 9, 9, 9, 9, 9 }
	};

	addrxlat_meth_t *meth;
	addrxlat_status status;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;
	if (opt_isset(ctl->popt, rootpgt))
		meth->param.pgt.root = ctl->popt.rootpgt;
	else
		meth->param.pgt.root.as = ADDRXLAT_NOADDR;
	meth->param.pgt.pte_mask = 0;
	meth->param.pgt.pf = riscv64_pf;

	status = get_virt_bits(ctl);
	if (status != ADDRXLAT_OK)
		return status;

	if (ctl->popt.virt_bits == 39)
		meth->param.pgt.pf.nfields = 4;
	else if (ctl->popt.virt_bits == 48)
		meth->param.pgt.pf.nfields = 5;
	else if (ctl->popt.virt_bits == 57)
		meth->param.pgt.pf.nfields = 6;
	else
		return bad_virt_bits(ctl->ctx, ctl->popt.virt_bits);

	return ADDRXLAT_OK;
}

/** Initialize the hardware translation map.
 * @param ctl  Initialization data.
 * @returns    Error status.
 *
 * Set up a generic riscv64 layout with two subranges (kernel and user).
 * The number of virtual address bits must be determined before calling
 * this function.
 */
static addrxlat_status
init_hw_map(struct os_init_data *ctl)
{
	addrxlat_addr_t endoff = ADDR_MASK(ctl->popt.virt_bits - 1);
	struct sys_region layout[] = {
		{  0,  endoff, ADDRXLAT_SYS_METH_PGT },
		{  UINT64_MAX - endoff,  UINT64_MAX, ADDRXLAT_SYS_METH_PGT },
		SYS_REGION_END
	};

	return sys_set_layout(ctl, ADDRXLAT_SYS_MAP_HW, layout);
}

/** Initialize a translation map for a RISC-V 64-bit OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_riscv64(struct os_init_data *ctl)
{
	addrxlat_map_t *map;
	addrxlat_status status;

	status = init_pgt_meth(ctl);
	if (status != ADDRXLAT_OK)
		return status;

	status = init_hw_map(ctl);
	if (status != ADDRXLAT_OK)
		return status;

	map = internal_map_copy(ctl->sys->map[ADDRXLAT_SYS_MAP_HW]);
	if (!map)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
				 "Cannot duplicate hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = map;

	status = sys_set_physmaps(ctl, PHYSADDR_MASK);
	if (status != ADDRXLAT_OK)
		return status;

	if (ctl->os_type == OS_LINUX)
		return map_linux_riscv64(ctl);

	return ADDRXLAT_OK;
}
