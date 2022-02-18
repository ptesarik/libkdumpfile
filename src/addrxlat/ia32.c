/** @internal @file src/addrxlat/ia32.c
 * @brief Routines specific to Intel IA32.
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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "addrxlat-priv.h"

#define PGD_PSE_HIGH_SHIFT	13
#define PGD_PSE_HIGH_BITS	8
#define PGD_PSE_HIGH_MASK	ADDR_MASK(PGD_PSE_HIGH_BITS)
#define pgd_pse_high(pgd)	\
	((((pgd) >> PGD_PSE_HIGH_SHIFT) & PGD_PSE_HIGH_MASK) << 32)

/* Non-PAE maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX_NONPAE	32
#define PHYSADDR_MASK_NONPAE	ADDR_MASK(PHYSADDR_BITS_MAX_NONPAE)

/* PAE maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX_PAE	52
#define PHYSADDR_MASK_PAE	ADDR_MASK(PHYSADDR_BITS_MAX_PAE)

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

/* Maximum virtual address (architecture limit) */
#define VIRTADDR_MAX		UINT32_MAX

/** Page shift (log2 4K). */
#define PAGE_SHIFT		12

/** Page mask. */
#define PAGE_MASK		ADDR_MASK(PAGE_SHIFT)

/** 2M page shift (log2 2M). */
#define PAGE_SHIFT_2M		21

/** 2M page mask. */
#define PAGE_MASK_2M		ADDR_MASK(PAGE_SHIFT_2M)

/** 4M page shift (log2 4M). */
#define PAGE_SHIFT_4M		22

/** 4M page mask. */
#define PAGE_MASK_4M		ADDR_MASK(PAGE_SHIFT_4M)

/** IA32 page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_ia32(addrxlat_step_t *step)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table"
	};
	static const char pte_name[][4] = {
		"pte",
		"pgd",
	};
	addrxlat_pte_t pte;
	addrxlat_status status;

	status = read_pte32(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	if (!(pte & _PAGE_PRESENT))
		return !step->ctx->noerr.notpresent
			? set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
				    "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				    pgt_full_name[step->remain - 1],
				    pte_name[step->remain - 1],
				    (unsigned) step->idx[step->remain],
				    step->raw.pte)
			: ADDRXLAT_ERR_NOTPRESENT;

	step->base.addr = pte;
	step->base.as = step->meth->target_as;

	if (step->remain == 2 && (pte & _PAGE_PSE)) {
		step->base.addr &= ~PAGE_MASK_4M;
		step->base.addr |= pgd_pse_high(pte);
		return pgt_huge_page(step);
	}

	step->base.addr &= ~PAGE_MASK;
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}

/** IA32 PAE page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_ia32_pae(addrxlat_step_t *step)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Page directory",
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pgd",
	};
	addrxlat_pte_t pte;
	addrxlat_status status;

	status = read_pte64(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	if (!(pte & _PAGE_PRESENT))
		return !step->ctx->noerr.notpresent
			? set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
				    "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				    pgt_full_name[step->remain - 1],
				    pte_name[step->remain - 1],
				    (unsigned) step->idx[step->remain],
				    step->raw.pte)
			: ADDRXLAT_ERR_NOTPRESENT;

	step->base.addr = pte & PHYSADDR_MASK_PAE;
	step->base.as = step->meth->target_as;

	if (step->remain == 2 && (pte & _PAGE_PSE)) {
		step->base.addr &= ~PAGE_MASK_2M;
		return pgt_huge_page(step);
	}

	step->base.addr &= ~PAGE_MASK;
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}

/** Starting virtual address of Linux direct mapping */
#define LINUX_DIRECTMAP	0xc0000000

/** Starting virtual address of Xen direct mapping */
#define XEN_DIRECTMAP	0xff000000

static const addrxlat_paging_form_t ia32_pf = {
	.pte_format = ADDRXLAT_PTE_IA32,
	.nfields = 3,
	.fieldsz = { 12, 10, 10 }
};

static const addrxlat_paging_form_t ia32_pf_pae = {
	.pte_format = ADDRXLAT_PTE_IA32_PAE,
	.nfields = 4,
	.fieldsz = { 12, 9, 9, 2 }
};

/** Check whether a page table hierarchy looks like PAE.
 * @param ctl     Initialization data.
 * @param root    Root page table address
 * @param direct  Starting virtual address of direct mapping
 * @returns       Error status.
 *
 * On successful return, this function sets @c OPT_pae accordingly.
 */
static addrxlat_status
check_pae(struct os_init_data *ctl, const addrxlat_fulladdr_t *root,
	  addrxlat_addr_t direct)
{
	addrxlat_step_t step;
	addrxlat_meth_t meth;
	addrxlat_status status;

	meth.kind = ADDRXLAT_PGT;
	meth.target_as = ADDRXLAT_MACHPHYSADDR;
	meth.param.pgt.root = *root;

	status = sys_set_physmaps(ctl, PHYSADDR_MASK_PAE);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot set up physical mappings");
	meth.param.pgt.pte_mask = 0;
	meth.param.pgt.pf = ia32_pf_pae;
	step.ctx = ctl->ctx;
	step.sys = ctl->sys;
	step.meth = &meth;
	step.base.addr = direct;
	status = internal_walk(&step);
	if (status == ADDRXLAT_OK && step.base.addr == 0) {
		ctl->popt.levels = 3;
		return ADDRXLAT_OK;
	}

	clear_error(ctl->ctx);
	map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS]);
	map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS]);

	status = sys_set_physmaps(ctl, PHYSADDR_MASK_NONPAE);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot set up physical mappings");
	meth.param.pgt.pf = ia32_pf;
	step.ctx = ctl->ctx;
	step.sys = ctl->sys;
	step.meth = &meth;
	step.base.addr = direct;
	status = internal_walk(&step);
	if (status == ADDRXLAT_OK && step.base.addr == 0) {
		ctl->popt.levels = 2;
		return ADDRXLAT_OK;
	}

	clear_error(ctl->ctx);
	map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS]);
	map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS]);

	return set_error(ctl->ctx, ADDRXLAT_ERR_NOTIMPL,
			 "Neither %s nor %s directmap found",
			 "PAE", "non-PAE");
}

/** Determine PAE status resolving root pgt from symbols.
 * @param ctl  Initialization data.
 * @returns    PAE status, see @ref check_pae.
 */
static addrxlat_status
check_pae_sym(struct os_init_data *ctl)
{
	addrxlat_fulladdr_t rootpgt;
	addrxlat_status status;

	if (ctl->os_type != OS_LINUX)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unsupported OS");

	status = get_symval(ctl->ctx, "swapper_pg_dir", &rootpgt.addr);
	if (status != ADDRXLAT_OK)
		return status;

	rootpgt.as = ADDRXLAT_KVADDR;
	return check_pae(ctl, &rootpgt, LINUX_DIRECTMAP);
}

/** Initialize a translation map for an Intel IA32 (non-pae) OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
sys_ia32_nonpae(struct os_init_data *ctl)
{
	addrxlat_meth_t *meth;
	addrxlat_status status;

	status = sys_set_physmaps(ctl, PHYSADDR_MASK_NONPAE);
	if (status != ADDRXLAT_OK)
		return status;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;
	if (opt_isset(ctl->popt, rootpgt))
		meth->param.pgt.root = ctl->popt.rootpgt;
	else
		meth->param.pgt.root.as = ADDRXLAT_NOADDR;
	meth->param.pgt.pte_mask = 0;
	meth->param.pgt.pf = ia32_pf;
	return ADDRXLAT_OK;
}

/** Initialize a translation map for an Intel IA32 (pae) OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
sys_ia32_pae(struct os_init_data *ctl)
{
	addrxlat_meth_t *meth;
	addrxlat_status status;

	status = sys_set_physmaps(ctl, PHYSADDR_MASK_PAE);
	if (status != ADDRXLAT_OK)
		return status;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;
	if (opt_isset(ctl->popt, rootpgt))
		meth->param.pgt.root = ctl->popt.rootpgt;
	else
		meth->param.pgt.root.as = ADDRXLAT_NOADDR;
	meth->param.pgt.pte_mask = 0;
	meth->param.pgt.pf = ia32_pf_pae;
	return ADDRXLAT_OK;
}

/** Try to get vmalloc_start from vmap_area_list.
 * @param ctl   Initialization data.
 * @param addr  VMALLOC start address; set on successful return.
 * @returns     Error status.
 */
static addrxlat_status
try_vmap_area_list(struct os_init_data *ctl, addrxlat_addr_t *addr)
{
	addrxlat_fulladdr_t vmap_area_list;
	addrxlat_addr_t va_start, va_list, list_next;
	uint32_t val;
	addrxlat_step_t dummystep;
	addrxlat_status status;

	status = get_symval(ctl->ctx, "vmap_area_list", &vmap_area_list.addr);
	if (status != ADDRXLAT_OK)
		return status;
	vmap_area_list.as = ADDRXLAT_KVADDR;

	status = get_offsetof(ctl->ctx, "vmap_area", "va_start", &va_start);
	if (status != ADDRXLAT_OK)
		return status;

	status = get_offsetof(ctl->ctx, "vmap_area", "list", &va_list);
	if (status != ADDRXLAT_OK)
		return status;

	status = get_offsetof(ctl->ctx, "list_head", "next", &list_next);
	if (status != ADDRXLAT_OK)
		return status;

	dummystep.ctx = ctl->ctx;
	dummystep.sys = ctl->sys;

	vmap_area_list.addr += list_next;
	status = read32(&dummystep, &vmap_area_list, &val,
			"vmap_area_list node");
	if (status != ADDRXLAT_OK)
		return status;

	vmap_area_list.addr = val - va_list + va_start;
	status = read32(&dummystep, &vmap_area_list, &val,
			"vmap_area start address");
	if (status != ADDRXLAT_OK)
		return status;

	*addr = val;
	return ADDRXLAT_OK;
}

/** Try to get vmalloc_start from vmlist.
 * @param ctl   Initialization data.
 * @param addr  VMALLOC start address; set on successful return.
 * @returns     Error status.
 */
static addrxlat_status
try_vmlist(struct os_init_data *ctl, addrxlat_addr_t *addr)
{
	addrxlat_fulladdr_t vmlist;
	addrxlat_addr_t vm_addr;
	uint32_t val;
	addrxlat_step_t dummystep;
	addrxlat_status status;

	status = get_symval(ctl->ctx, "vmlist", &vmlist.addr);
	if (status != ADDRXLAT_OK)
		return status;
	vmlist.as = ADDRXLAT_KVADDR;

	status = get_offsetof(ctl->ctx, "vm_struct", "addr", &vm_addr);
	if (status != ADDRXLAT_OK)
		return status;

	dummystep.ctx = ctl->ctx;
	dummystep.sys = ctl->sys;

	status = read32(&dummystep, &vmlist, &val, "vmlist");
	if (status != ADDRXLAT_OK)
		return status;

	vmlist.addr = val + vm_addr;
	status = read32(&dummystep, &vmlist, &val, "vmlist address");
	if (status != ADDRXLAT_OK)
		return status;

	*addr = val;
	return ADDRXLAT_OK;
}

/** Adjust Linux directmap limits on IA32.
 * @param ctl   Initialization data.
 * @param vtop  Virtual-to-physical mapping; updated on successful return.
 * @returns     Error status.
 */
static addrxlat_status
set_linux_directmap(struct os_init_data *ctl, addrxlat_map_t *vtop)
{
	addrxlat_addr_t vmalloc_start;
	addrxlat_range_t range;
	addrxlat_status status;

	status = try_vmap_area_list(ctl, &vmalloc_start);
	if (status == ADDRXLAT_ERR_NODATA) {
		clear_error(ctl->ctx);
		status = try_vmlist(ctl, &vmalloc_start);
		if (status == ADDRXLAT_ERR_NODATA) {
			clear_error(ctl->ctx);
			return ADDRXLAT_OK;
		}
	}
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine VMALLOC start");
	if (vmalloc_start <= LINUX_DIRECTMAP)
		return set_error(ctl->ctx, ADDRXLAT_ERR_INVALID,
				 "Invalid VMALLOC start: %"ADDRXLAT_PRIxADDR,
				 vmalloc_start);

	range.meth = ADDRXLAT_SYS_METH_NONE;
	range.endoff = ADDRXLAT_ADDR_MAX - (vmalloc_start - LINUX_DIRECTMAP);
	status = internal_map_set(ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_DIRECT],
				  vmalloc_start - LINUX_DIRECTMAP, &range);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot update reverse directmap");

	range.meth = ADDRXLAT_SYS_METH_DIRECT;
	range.endoff = vmalloc_start - 1 - LINUX_DIRECTMAP;
	status = internal_map_set(vtop, LINUX_DIRECTMAP, &range);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot set up directmap");

	return ADDRXLAT_OK;
}

/** Direct mapping, used temporarily to translate swapper_pg_dir */
static const struct sys_region linux_directmap[] = {
	{ LINUX_DIRECTMAP, VIRTADDR_MAX,
	   ADDRXLAT_SYS_METH_DIRECT, SYS_ACT_DIRECT },
	SYS_REGION_END
};

/** Initialize a translation map for an Intel IA32 OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_ia32(struct os_init_data *ctl)
{
	static const struct sym_spec pgtspec[] = {
		{ ADDRXLAT_SYM_REG, ADDRXLAT_MACHPHYSADDR, "cr3" },
		{ ADDRXLAT_SYM_VALUE, ADDRXLAT_KVADDR, "swapper_pg_dir" },
		{ ADDRXLAT_SYM_NONE }
	};

	addrxlat_range_t range;
	addrxlat_map_t *newmap;
	long levels;
	addrxlat_status status;

	if (ctl->os_type == OS_LINUX) {
		status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS,
					linux_directmap);
		if (status != ADDRXLAT_OK)
			return set_error(ctl->ctx, status,
					 "Cannot set up directmap");
	}

	status = ADDRXLAT_OK;
	if (!opt_isset(ctl->popt, levels)) {
		addrxlat_fulladdr_t *rootpgtopt = &ctl->popt.rootpgt;

		if (!opt_isset(ctl->popt, rootpgt))
			status = check_pae_sym(ctl);
		else if (ctl->os_type == OS_LINUX)
			status = check_pae(ctl, rootpgtopt,
					   LINUX_DIRECTMAP);
		else if (ctl->os_type == OS_XEN)
			status = check_pae(ctl, rootpgtopt,
					   XEN_DIRECTMAP);
		else
			status = ADDRXLAT_ERR_NOTIMPL;
	}

	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine PAE state");

	range.meth = ADDRXLAT_SYS_METH_PGT;
	range.endoff = VIRTADDR_MAX;
	newmap = internal_map_new();
	if (!newmap)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
				 "Cannot set up hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_HW] = newmap;
	status = internal_map_set(newmap, 0, &range);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot set up hardware mapping");

	levels = ctl->popt.levels;
	if (levels == 2)
		status = sys_ia32_nonpae(ctl);
	else if (levels == 3)
		status = sys_ia32_pae(ctl);
	else
		return bad_paging_levels(ctl->ctx, levels);
	if (status != ADDRXLAT_OK)
		return status;

	newmap = internal_map_new();
	if (!newmap)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
				 "Cannot set up virt-to-phys mapping");
	status = internal_map_set(newmap, 0, &range);
	if (status != ADDRXLAT_OK) {
		internal_map_decref(newmap);
		return set_error(ctl->ctx, status,
				 "Cannot set up virt-to-phys mapping");
	}

	if (ctl->os_type == OS_LINUX)  {
		sys_sym_pgtroot(ctl, pgtspec);

		status = set_linux_directmap(ctl, newmap);
		if (status != ADDRXLAT_OK) {
			internal_map_decref(newmap);
			return status;
		}
	}
	if (ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS])
		internal_map_decref(ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS]);
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = newmap;

	return status;
}
