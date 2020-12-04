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
#include <linux/version.h>

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
	addrxlat_pte_t pte;
	addrxlat_status status;

	status = read_pte64(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	if (!PTE_VALID(pte))
		return pte_not_present(step);

	step->base.addr = pte & PA_MASK;
	step->base.as = step->meth->target_as;

	if (PTE_TYPE(pte) == PTE_TYPE_BLOCK) {
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

#define is_linear_addr(addr, kernel_ver, va_bits)		   \
	(((kernel_ver) < KERNEL_VERSION(5, 4, 0)) ?		   \
	 (!!((unsigned long)(addr) & (1UL << ((va_bits) - 1)))) :  \
	 (!((unsigned long)(addr) & (1UL << ((va_bits) - 1)))))

static unsigned long
get_page_offset(unsigned long kernel_ver, addrxlat_addr_t va_bits) {
	unsigned long page_offset;

	if (kernel_ver < KERNEL_VERSION(5, 4, 0))
		page_offset = ((0xffffffffffffffffUL) -
				((1UL) << (va_bits - 1)) + 1);
	else
		page_offset = (-(1UL << va_bits));
	return page_offset;
}

/** Determine Linux page table root.
 * @param ctl	     Initialization data.
 * @param[out] root  Page table root address (set on successful return).
 * @returns	     Error status.
 */
static addrxlat_status
get_linux_pgtroot(struct os_init_data *ctl, addrxlat_fulladdr_t *root)
{
	addrxlat_status status;
	addrxlat_addr_t root_va;

	addrxlat_addr_t va_bits;
	addrxlat_addr_t phys_base;
	addrxlat_addr_t kimage_voffset;
	int no_kimage_voffset = 0;

	unsigned long page_offset;
	unsigned long kernel_ver;


	status = get_symval(ctl->ctx, "swapper_pg_dir",
			    &root_va);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine page table virtual address");

	/*
	 * This code will only work with vmcores produced by
	 * Linux Kernel versions 4.12 and above. Makedumpfile
	 * for kernels before 4.12 uses a heuristic based on
	 * reading vmcore load segment addressess and finds
	 * va_bits and phys_offset. This code does not support
	 * such logic.
	 */
	status = get_number(ctl->ctx, "VA_BITS",
			    &va_bits);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine VA_BITS");

	status = get_number(ctl->ctx, "kimage_voffset" ,
			    &kimage_voffset);
	if (status != ADDRXLAT_OK)
		 no_kimage_voffset = 1;

	kernel_ver = ctl->osdesc->ver;


	if (no_kimage_voffset || is_linear_addr(root_va, kernel_ver, va_bits)) {
		status = get_number(ctl->ctx, "PHYS_OFFSET" ,
				    &phys_base);
		if (status != ADDRXLAT_OK)
			return set_error(ctl->ctx, status,
				 "Cannot determine PHYS_OFFSET");

		page_offset = get_page_offset(kernel_ver, va_bits);

		if (kernel_ver < KERNEL_VERSION(5, 4, 0)) {
			 root->addr = ((root_va & ~page_offset) + phys_base);
		} else {
			 root->addr =  (root_va + phys_base - page_offset);
		}
	} else {
	    root->addr = root_va - kimage_voffset;
	}

	root->as =  ADDRXLAT_KPHYSADDR;

	return ADDRXLAT_OK;
}

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX	52
#define PHYSADDR_MASK		ADDR_MASK(PHYSADDR_BITS_MAX)
#define VIRTADDR_MAX		UINT64_MAX


/** Initialize a translation map for Linux/aarch64.
 * @param ctl  Initialization data.
 * @returns	  Error status.
 */
static addrxlat_status
map_linux_aarch64(struct os_init_data *ctl)
{
	static const addrxlat_paging_form_t aarch64_pf = {
		.pte_format = ADDRXLAT_PTE_AARCH64,
		.nfields = 5,
		.fieldsz = { 12, 9, 9, 9, 9, 9 }
	};

	/*
	 * Generic aarch64 layout, depends on current va_bits
	 *
	 * Aarch64 kernel does have a linear mapping region, the location
	 * of which changed in the 5.4 kernel. But since it is covered
	 * by swapper pgt anyway we don't bother to reflect it here.
	 */
	struct sys_region aarch64_layout_generic[] = {
	    {  0,  0,			/* lower half	    */
	       ADDRXLAT_SYS_METH_PGT },

	    {  0,  VIRTADDR_MAX,	 /* higher half	     */
	       ADDRXLAT_SYS_METH_PGT },
	    SYS_REGION_END
	};

	addrxlat_map_t *map;
	addrxlat_meth_t *meth;
	addrxlat_status status;
	addrxlat_addr_t va_bits;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;

	if (ctl->popt.val[OPT_rootpgt].set)
		meth->param.pgt.root = ctl->popt.val[OPT_rootpgt].fulladdr;
	else {
		status = get_linux_pgtroot(ctl, &meth->param.pgt.root);
		if (status != ADDRXLAT_OK)
			return status;
	}

	meth->param.pgt.pte_mask =
		opt_num_default(&ctl->popt, OPT_pte_mask, 0);
	meth->param.pgt.pf = aarch64_pf;

	status = get_number(ctl->ctx, "VA_BITS",
			    &va_bits);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine VA_BITS");

	if (ctl->popt.val[OPT_levels].set) {
		long levels = ctl->popt.val[OPT_levels].num;
		if (levels < 3 || levels > 5)
			return bad_paging_levels(ctl->ctx, levels);
		meth->param.pgt.pf.nfields = levels + 1;
	} else
		meth->param.pgt.pf.nfields = ((va_bits - 12) / 9) + 1;

	/* layout depends on current value of va_bits */
	aarch64_layout_generic[0].last =  ~(-(1ull) << (va_bits));
	aarch64_layout_generic[1].first =  (-(1ull) << (va_bits));

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_HW,
				aarch64_layout_generic);
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

	return ADDRXLAT_OK;
}


/** Initialize a translation map for an aarch64 OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_aarch64(struct os_init_data *ctl)
{
	switch (ctl->osdesc->type) {
	case ADDRXLAT_OS_LINUX:
		return map_linux_aarch64(ctl);

	default:
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "OS type not implemented");
	}
}
