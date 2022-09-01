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

/** Maximum virtual address bits (architectural limit). */
#define VA_MAX_BITS	52

/** Maximum physical address bits (architectural limit).
 * This limit applies only to the original VMSA64 without LPA/LPA2.
 */
#define PA_MAX_BITS	48
#define PA_MASK		ADDR_MASK(PA_MAX_BITS)

/** Mask of the maximum region size without LPA/LPA2.
 * Largest region size depends on the translation granule size. This
 * mask corresponds to the maximum value, i.e. a 1 GiB region in level
 * one translation table for a 4 KiB granule.
 *
 * Note that this maximum can be used to check whether a block descriptor
 * is valid in a given translation lookup level, because a region that
 * would be defined by a (hypothetical) block descriptor in a translation
 * table where block descriptors are not supported would be larger:
 * - For a 16 KiB granule, a block descriptor in level 1 table would
 *   correspond to a 64 GiB region.
 * - For a 64 KiB granule, a block descriptor in level 0 table would
 *   correspond to a 4 TiB region.
 */
#define MAX_REGION_MASK	ADDR_MASK(30)

/** Mask of the maximum region size with LPA.
 * The LPA descriptor format is used only for a 64 KiB translation
 * granule, which supports block descriptors in level 0 tables. The
 * size of that region is 4 TiB.
 */
#define MAX_REGION_MASK_LPA	ADDR_MASK(42)

/** Mask of the maximum region size with LPA2.
 * The LPA2 descriptor format is used for 4 KiB and a 16 KiB
 * translation granule. The maximum region size is 512 GiB (a block
 * descriptor in a level 0 table with 4 KiB granules). A (hypothetical)
 * block descriptor in a level 0 table with 16 KiB granules would
 * correspond to a 128 TiB region.
 */
#define MAX_REGION_MASK_LPA2	ADDR_MASK(39)

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
			 pgt_full_name[step->remain],
			 pte_name[step->remain - 1],
			 (unsigned) step->idx[step->remain],
			 step->raw.pte);
}

/** Arm AArch64 page table step function.
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
		if (step->remain == 1 ||
		    mask > MAX_REGION_MASK)
			return pte_invalid(step);
		step->base.addr &= ~mask;
		return pgt_huge_page(step);
	}

	step->base.addr &= ~pf_page_mask(&step->meth->param.pgt.pf);
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}

/** Arm AArch64 with LPA page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_aarch64_lpa(addrxlat_step_t *step)
{
	addrxlat_pte_t pte;
	addrxlat_status status;

	status = read_pte64(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	if (!PTE_VALID(pte))
		return pte_not_present(step);

	step->base.addr = PTE_VAL(pte, 0, 47) | (PTE_VAL(pte, 12, 4) << 48);
	step->base.as = step->meth->target_as;

	if (PTE_TYPE(pte) == PTE_TYPE_BLOCK) {
		addrxlat_addr_t mask = pf_table_mask(
			&step->meth->param.pgt.pf, step->remain);
		if (step->remain == 1 ||
		    mask > MAX_REGION_MASK_LPA)
			return pte_invalid(step);
		step->base.addr &= ~mask;
		return pgt_huge_page(step);
	}

	step->base.addr &= ~pf_page_mask(&step->meth->param.pgt.pf);
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}

/** Arm AArch64 with LPA2 page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_aarch64_lpa2(addrxlat_step_t *step)
{
	addrxlat_pte_t pte;
	addrxlat_status status;

	status = read_pte64(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	if (!PTE_VALID(pte))
		return pte_not_present(step);

	step->base.addr = PTE_VAL(pte, 0, 49) | (PTE_VAL(pte, 8, 2) << 50);
	step->base.as = step->meth->target_as;

	if (PTE_TYPE(pte) == PTE_TYPE_BLOCK) {
		addrxlat_addr_t mask = pf_table_mask(
			&step->meth->param.pgt.pf, step->remain);
		if (step->remain == 1 ||
		    mask > MAX_REGION_MASK_LPA2)
			return pte_invalid(step);
		step->base.addr &= ~mask;
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
	unsigned long read_caps;
	addrxlat_status status;

	status = get_symval(ctl->ctx, "swapper_pg_dir", &root->addr);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine page table virtual address");

	/* If the read callback can handle virtual addresses, we're done. */
	read_caps = ctl->ctx->cb->read_caps(ctl->ctx->cb);
	if (read_caps & ADDRXLAT_CAPS(ADDRXLAT_KVADDR)) {
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
 * @returns        @c ADDRXLAT_OK if the mapping was added.
 */
static addrxlat_status
add_linux_linear_map(struct os_init_data *ctl)
{
	struct sys_region layout[2];
	addrxlat_step_t step;
	addrxlat_addr_t phys;
	addrxlat_meth_t *meth;
	addrxlat_status status;

	status = linux_page_offset(ctl, ctl->popt.virt_bits, &layout[0].first);
	if (status != ADDRXLAT_OK)
		return status;
	layout[0].last = layout[0].first | ADDR_MASK(ctl->popt.virt_bits - 1);

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

/** Initialize a translation map for Linux/aarch64.
 * @param ctl  Initialization data.
 * @returns	  Error status.
 */
static addrxlat_status
map_linux_aarch64(struct os_init_data *ctl)
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

	status = sys_set_physmaps(ctl, PHYSADDR_MASK);
	if (status != ADDRXLAT_OK)
		return status;

	add_linux_linear_map(ctl);
	clear_error(ctl->ctx);

	return ADDRXLAT_OK;
}

/** Determine the number of virtual address bits
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
determine_virt_bits(struct os_init_data *ctl)
{
	addrxlat_addr_t num;
	addrxlat_status status;

	if (opt_isset(ctl->popt, virt_bits))
		return ADDRXLAT_OK;

	if (ctl->os_type == OS_LINUX) {
		status = get_number(ctl->ctx, "TCR_EL1_T1SZ", &num);
		if (status == ADDRXLAT_OK) {
			num = 64 - num;
		} else if (status == ADDRXLAT_ERR_NODATA) {
			clear_error(ctl->ctx);
			status = get_number(ctl->ctx, "VA_BITS", &num);
		}
	} else
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
 */
static void
init_pgt_meth(struct os_init_data *ctl)
{
	addrxlat_meth_t *meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	addrxlat_param_pgt_t *pgt = &meth->param.pgt;
	unsigned page_bits = ctl->popt.page_shift;
	unsigned num_bits = ctl->popt.virt_bits;
	unsigned field_bits;

	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;

	pgt->root.as = ADDRXLAT_NOADDR;
	pgt->pte_mask = 0;
	pgt->pf.pte_format = num_bits <= 48
		? ADDRXLAT_PTE_AARCH64
		: (page_bits == 16
		   ? ADDRXLAT_PTE_AARCH64_LPA
		   : ADDRXLAT_PTE_AARCH64_LPA2);

	pgt->pf.nfields = 0;
	field_bits = page_bits;
	while (num_bits) {
		pgt->pf.fieldsz[pgt->pf.nfields++] = field_bits;
		num_bits -= field_bits;
		field_bits = page_bits - 3;
		if (field_bits > num_bits)
			field_bits = num_bits;
	}

	ctl->sys->meth[ADDRXLAT_SYS_METH_UPGT] = *meth;
}

/** Initialize the hardware translation map.
 * @param ctl  Initialization data.
 * @returns    Error status.
 *
 * Set up a generic aarch64 layout with two subranges.
 * The number of virtual address bits must be determined before calling
 * this function.
 */
static addrxlat_status
init_hw_map(struct os_init_data *ctl)
{
	addrxlat_addr_t endoff = ADDR_MASK(ctl->popt.virt_bits);
	struct sys_region layout[] = {
		/* bottom VA range: user space */
		{  0,  endoff,
		   ADDRXLAT_SYS_METH_UPGT },

		/* top VA range: kernel space */
		{  VIRTADDR_MAX - endoff,  VIRTADDR_MAX,
		   ADDRXLAT_SYS_METH_PGT },

		SYS_REGION_END
	};

	return sys_set_layout(ctl, ADDRXLAT_SYS_MAP_HW, layout);
}

/** Initialize a translation map for an aarch64 OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_aarch64(struct os_init_data *ctl)
{
	unsigned long va_min_bits;
	addrxlat_map_t *map;
	addrxlat_status status;

	if (!opt_isset(ctl->popt, page_shift))
		return set_error(ctl->ctx, ADDRXLAT_ERR_NODATA,
				 "Cannot determine page size");

	status = determine_virt_bits(ctl);
	if (status != ADDRXLAT_OK)
		return status;

	va_min_bits = 16;
	if (va_min_bits <= ctl->popt.page_shift)
		va_min_bits = ctl->popt.page_shift + 1;
	if (ctl->popt.virt_bits < va_min_bits ||
	    ctl->popt.virt_bits > VA_MAX_BITS)
		return bad_virt_bits(ctl->ctx, ctl->popt.virt_bits);

	init_pgt_meth(ctl);
	status = init_hw_map(ctl);
	if (status != ADDRXLAT_OK)
		return status;

	map = internal_map_copy(ctl->sys->map[ADDRXLAT_SYS_MAP_HW]);
	if (!map)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
				 "Cannot duplicate hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = map;

	if (ctl->os_type == OS_LINUX)
		return map_linux_aarch64(ctl);

	return ADDRXLAT_OK;
}
