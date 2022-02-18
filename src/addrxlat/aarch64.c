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
#include <string.h>

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

/** Descriptive names for page tables.
 * These names are used in error messages.
 */
static const char pgt_full_name[][16] = {
	"Page",
	"Level 3 table",
	"Level 2 table",
	"Level 1 table",
	"Level 0 table",
	"Level -1 table",
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
		if (step->remain > 4 ||
		    (step->remain > 3 &&
		     step->meth->param.pgt.pf.fieldsz[0] != 9))
			return pte_invalid(step);
		step->base.addr &= ~pf_table_mask(
			&step->meth->param.pgt.pf, step->remain);
		return pgt_huge_page(step);
	}

	step->base.addr &= ~pf_page_mask(&step->meth->param.pgt.pf);
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
	addrxlat_addr_t kimage_voffset;
	addrxlat_status status;

	status = get_symval(ctl->ctx, "swapper_pg_dir", &root->addr);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine page table virtual address");

	/* If the read callback can handle virtual addresses, we're done. */
	if (ctl->ctx->cb.read_caps & ADDRXLAT_CAPS(ADDRXLAT_KVADDR)) {
		addrxlat_buffer_t *buffer;

		root->as = ADDRXLAT_KVADDR;
		status = get_cache_buf(ctl->ctx, root, &buffer);
		if (status == ADDRXLAT_OK)
			return ADDRXLAT_OK;

		clear_error(ctl->ctx);
	}

	status = get_number(ctl->ctx, "kimage_voffset", &kimage_voffset);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine kimage_voffset");

	root->addr -= kimage_voffset;
	root->as = ADDRXLAT_KPHYSADDR;
	return ADDRXLAT_OK;
}

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX	52
#define PHYSADDR_MASK		ADDR_MASK(PHYSADDR_BITS_MAX)
#define VIRTADDR_MAX		UINT64_MAX

/** Get Linux page offset.
 * @param ctl       Initialization data.
 * @param va_bits   Size of virtual addresses in bits (CONFIG_VA_BITS).
 * @param[out] off  Set to PAGE_OFFSET on success.
 * @returns         Error status.
 */
static addrxlat_status
linux_page_offset(struct os_init_data *ctl, unsigned va_bits,
		  addrxlat_addr_t *off)
{
	addrxlat_addr_t top;	/* top VA range address */
	addrxlat_addr_t half;	/* upper half of the top VA range */
	addrxlat_addr_t stext;
	addrxlat_status status;

	top = VIRTADDR_MAX & ~ADDR_MASK(va_bits);
	half = VIRTADDR_MAX & ~ADDR_MASK(va_bits - 1);

	/*
	 * Use any kernel text symbol to decide whether the linear
	 * mapping is in the lower half or the upper half of the
	 * kernel VA range.
	 * Cf. kernel commit 14c127c957c1c6070647c171e72f06e0db275ebf
	 */
	status = get_symval(ctl->ctx, "_stext", &stext);
	if (status == ADDRXLAT_OK) {
		*off = (stext >= half)
			? top
			: half;
	} else if (status == ADDRXLAT_ERR_NODATA) {
		/* Fall back to checking kernel version number. */
		clear_error(ctl->ctx);
		if (opt_isset(ctl->popt, version_code)) {
			*off = (ctl->popt.version_code >= KERNEL_VERSION(5, 4, 0))
				? top
				: half;
			status = ADDRXLAT_OK;
		}
	}

	return status;
}

/** Set up a linear mapping region.
 * @param ctl      Initialization data.
 * @param va_bits  Size of virtual addresses in bits (CONFIG_VA_BITS).
 * @returns        @c ADDRXLAT_OK if the mapping was added.
 */
static addrxlat_status
add_linux_linear_map(struct os_init_data *ctl, unsigned va_bits)
{
	struct sys_region layout[2];
	addrxlat_step_t step;
	addrxlat_addr_t phys;
	addrxlat_meth_t *meth;
	addrxlat_status status;

	status = linux_page_offset(ctl, va_bits, &layout[0].first);
	if (status != ADDRXLAT_OK)
		return status;
	layout[0].last = layout[0].first | ADDR_MASK(va_bits - 1);

	step.ctx = ctl->ctx;
	step.sys = ctl->sys;
	step.meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];

	status = lowest_mapped(&step, &layout[0].first, layout[0].last);
	if (status != ADDRXLAT_OK)
		return status;
	phys = step.base.addr;
	status = highest_mapped(&step, &layout[0].last, layout[0].first);
	if (status != ADDRXLAT_OK)
		return status;
	if (step.base.addr - phys != layout[0].last - layout[0].first)
		return ADDRXLAT_ERR_NOTIMPL;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_DIRECT];
	meth->kind = ADDRXLAT_LINEAR;
	meth->target_as = ADDRXLAT_KPHYSADDR;
	meth->param.linear.off = phys - layout[0].first;

	layout[0].meth = ADDRXLAT_SYS_METH_DIRECT;
	layout[0].act = SYS_ACT_NONE;
	layout[1].meth = ADDRXLAT_SYS_METH_NUM;
	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, layout);
	if (status != ADDRXLAT_OK)
		return status;

	layout[0].meth = ADDRXLAT_SYS_METH_RDIRECT;
	layout[0].first = phys;
	layout[0].last = step.base.addr;
	layout[0].act = SYS_ACT_RDIRECT;
	return sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KPHYS_DIRECT, layout);
}

/** Initialize the page table translation method.
 * @param ctl      Initialization data.
 * @param va_bits  Size of virtual addresses in bits (CONFIG_VA_BITS).
 * @returns        Error status.
 */
static addrxlat_status
init_pgt_meth(struct os_init_data *ctl, unsigned va_bits)
{
	addrxlat_meth_t *meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_UPGT];
	addrxlat_param_pgt_t *pgt = &meth->param.pgt;
	unsigned field_bits;
	unsigned page_bits;
	unsigned i;

	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;

	pgt->root.as = ADDRXLAT_NOADDR;
	pgt->pte_mask = 0;
	pgt->pf.pte_format = ADDRXLAT_PTE_AARCH64;

	if (!opt_isset(ctl->popt, page_shift))
		return set_error(ctl->ctx, ADDRXLAT_ERR_NODATA,
				 "Cannot determine page size");
	page_bits = ctl->popt.page_shift;

	if (opt_isset(ctl->popt, levels)) {
		long levels = ctl->popt.levels;
		if (levels < 3 || levels > 5)
			return bad_paging_levels(ctl->ctx, levels);
		pgt->pf.nfields = levels + 1;
	} else
		pgt->pf.nfields = (va_bits - 4) / (page_bits - 3) + 1;

	field_bits = page_bits;
	for (i = 0; i < pgt->pf.nfields; ++i) {
		pgt->pf.fieldsz[i] = field_bits;
		va_bits -= field_bits;
		field_bits = page_bits - 3;
		if (field_bits > va_bits)
			field_bits = va_bits;
	}

	return ADDRXLAT_OK;
}

/** Initialize a translation map for Linux/aarch64.
 * @param ctl  Initialization data.
 * @returns	  Error status.
 */
static addrxlat_status
map_linux_aarch64(struct os_init_data *ctl)
{
	/*
	 * Generic aarch64 layout, depends on current va_bits
	 */
	struct sys_region aarch64_layout_generic[] = {
	    {  0,  0,			/* bottom VA range: user space */
	       ADDRXLAT_SYS_METH_UPGT },

	    {  0,  VIRTADDR_MAX,	/* top VA range: kernel space */
	       ADDRXLAT_SYS_METH_PGT },
	    SYS_REGION_END
	};

	addrxlat_map_t *map;
	addrxlat_meth_t *meth;
	addrxlat_status status;
	addrxlat_addr_t va_bits;

	status = get_number(ctl->ctx, "TCR_EL1_T1SZ", &va_bits);
	if (status == ADDRXLAT_OK) {
		va_bits = 64 - va_bits;
	} else if (status == ADDRXLAT_ERR_NODATA) {
		clear_error(ctl->ctx);
		status = get_number(ctl->ctx, "VA_BITS", &va_bits);
	}
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine VA_BITS");

	status = init_pgt_meth(ctl, va_bits);
	if (status != ADDRXLAT_OK)
		return status;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	*meth = ctl->sys->meth[ADDRXLAT_SYS_METH_UPGT];
	if (opt_isset(ctl->popt, rootpgt))
		meth->param.pgt.root = ctl->popt.rootpgt;
	else {
		status = get_linux_pgtroot(ctl, &meth->param.pgt.root);
		if (status != ADDRXLAT_OK)
			return status;
	}

	/* layout depends on current value of va_bits */
	aarch64_layout_generic[0].last = ADDR_MASK(va_bits);
	aarch64_layout_generic[1].first = VIRTADDR_MAX - ADDR_MASK(va_bits);

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

	add_linux_linear_map(ctl, va_bits);
	clear_error(ctl->ctx);

	return ADDRXLAT_OK;
}


/** Initialize a translation map for an aarch64 OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_aarch64(struct os_init_data *ctl)
{
	if (ctl->os_type == OS_LINUX)
		return map_linux_aarch64(ctl);

	return set_error(ctl->ctx, ADDRXLAT_ERR_NOTIMPL,
			 "OS type not implemented");
}
