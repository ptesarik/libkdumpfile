/** @internal @file src/addrxlat/x86_64.c
 * @brief Routines specific to AMD64 and Intel 64.
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

#include <stdlib.h>

#include "addrxlat-priv.h"

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX	52
#define PHYSADDR_SIZE		((uint64_t)1 << PHYSADDR_BITS_MAX)
#define PHYSADDR_MASK		(~(PHYSADDR_SIZE-1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	48

/** Page size in bits. */
#define PAGE_SHIFT		12

#define NONCANONICAL_START	((uint64_t)1<<(VIRTADDR_BITS_MAX-1))
#define NONCANONICAL_END	(~NONCANONICAL_START)
#define VIRTADDR_MAX		UINT64_MAX

/** Virtual address of the Xen machine-to-physical map. */
#define XEN_MACH2PHYS_ADDR	0xffff800000000000ULL

/** Kernel text mapping (virtual addresses).
 * Note that this mapping has never changed, so these constants
 * apply to all kernel versions.
 */
#define __START_KERNEL_map	0xffffffff80000000ULL
#define __END_KERNEL_map	0xffffffff827fffffULL

/* Original Linux layout (before 2.6.11) */
static const struct sys_region linux_layout_2_6_0[] = {
	{  0x0000000000000000,  0x0000007fffffffff, /* user space       */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0x0000008000000000 - 0x000000ffffffffff     guard hole       */
	{  0x0000010000000000,  0x000001ffffffffff, /* direct mapping   */
	   ADDRXLAT_SYS_METH_DIRECT, SYS_ACT_DIRECT },
	/* 0x0000020000000000 - 0x00007fffffffffff     unused hole      */
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xfffffeffffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xffffff8000000000 - 0xffffffff7fffffff     unused hole      */
	/* 0xffffffff80000000 - 0xffffffff827fffff     kernel text      */
	/* 0xffffffff82800000 - 0xffffffff9fffffff     unused hole      */
	{  0xffffffffa0000000,  0xffffffffafffffff, /* modules          */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xffffffffb0000000 - 0xffffffffff5exxxx     unused hole      */
	{  0xffffffffff5ed000,  0xffffffffffdfffff, /* fixmap/vsyscalls */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	SYS_REGION_END
};

/* Linux layout introduced in 2.6.11 */
static const struct sys_region linux_layout_2_6_11[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	{  0xffff810000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   ADDRXLAT_SYS_METH_DIRECT, SYS_ACT_DIRECT },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_SYS_METH_PGT },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   ADDRXLAT_SYS_METH_PGT },		    /*   (2.6.24+ only) */
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	/* 0xffffffff80000000 - 0xffffffff827fffff     kernel text      */
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   ADDRXLAT_SYS_METH_PGT },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	SYS_REGION_END
};

/** Linux layout with hypervisor area, introduced in 2.6.27 */
static const struct sys_region linux_layout_2_6_27[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   ADDRXLAT_SYS_METH_DIRECT, SYS_ACT_DIRECT },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_SYS_METH_PGT },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	/* 0xffffffff80000000 - 0xffffffff827fffff     kernel text      */
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   ADDRXLAT_SYS_METH_PGT },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	SYS_REGION_END
};

/** Linux layout with 64T direct mapping, introduced in 2.6.31 */
static const struct sys_region linux_layout_2_6_31[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc7ffffffffff, /* direct mapping   */
	   ADDRXLAT_SYS_METH_DIRECT, SYS_ACT_DIRECT },
	/* 0xffffc80000000000 - 0xffffc8ffffffffff     guard hole       */
	{  0xffffc90000000000,  0xffffe8ffffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xffffe90000000000 - 0xffffe9ffffffffff     guard hole       */
	{  0xffffea0000000000,  0xffffeaffffffffff, /* VMEMMAP          */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xffffeb0000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* %esp fixup stack */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xffffff8000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffffef00000000,  0xfffffffeffffffff, /* EFI runtime      */
	   ADDRXLAT_SYS_METH_PGT },		    /*     (3.14+ only) */
	/* 0xffffffff00000000 - 0xffffffff7fffffff     guard hole       */
	/* 0xffffffff80000000 - 0xffffffff827fffff     kernel text      */
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   ADDRXLAT_SYS_METH_PGT },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	SYS_REGION_END
};

/** AMD64 (Intel 64) page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_x86_64(addrxlat_step_t *step)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Page directory",
		"PDPT table",
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
	};
	const struct pgt_extra_def *pgt = &step->meth->extra.pgt;
	addrxlat_status status;

	status = read_pte(step);
	if (status != ADDRXLAT_OK)
		return status;

	if (!(step->raw.pte & _PAGE_PRESENT))
		return set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[step->remain - 1],
				 pte_name[step->remain - 1],
				 (unsigned) step->idx[step->remain],
				 step->raw.pte);

	step->base.addr = step->raw.pte & ~PHYSADDR_MASK;
	step->base.as = step->meth->desc.target_as;

	if (step->remain >= 2 && step->remain <= 3 &&
	    (step->raw.pte & _PAGE_PSE)) {
		step->base.addr &= pgt->pgt_mask[step->remain - 1];
		return pgt_huge_page(step);
	}

	step->base.addr &= pgt->pgt_mask[0];
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}

/** Get Linux virtual memory layout by kernel version.
 * @param ver  Version code.
 * @returns    Layout definition, or @c NULL.
 */
static const struct sys_region *
linux_layout_by_ver(unsigned version_code)
{
#define LINUX_LAYOUT_BY_VER(a, b, c)			\
	if (version_code >= ADDRXLAT_VER_LINUX(a, b, c))	\
		return linux_layout_ ## a ## _ ## b ## _ ## c

	LINUX_LAYOUT_BY_VER(2, 6, 31);
	LINUX_LAYOUT_BY_VER(2, 6, 27);
	LINUX_LAYOUT_BY_VER(2, 6, 11);
	LINUX_LAYOUT_BY_VER(2, 6, 0);

	return NULL;
}

/** Check whether a virtual address is mapped to a physical address.
 * @param sys    Translation system object.
 * @param ctx    Address translation context.
 * @param addr   Address to be checked.
 * @returns      Non-zero if the address can be translated.
 */
static int
is_mapped(addrxlat_sys_t *sys, addrxlat_ctx_t *ctx,
	  addrxlat_addr_t addr)
{
	addrxlat_step_t step;
	addrxlat_status status;

	step.ctx = ctx;
	step.sys = sys;
	step.meth = sys->meth[ADDRXLAT_SYS_METH_PGT];
	status = internal_launch(&step, addr);

	if (status == ADDRXLAT_OK)
		status = internal_walk(&step);

	clear_error(ctx);
	return status == ADDRXLAT_OK;
}

/** Check whether an address looks like start of direct mapping.
 * @param sys    Translation system.
 * @param ctx    Address translation context.
 * @param addr   Address to be checked.
 * @returns      Non-zero if the address maps to physical address 0.
 */
static int
is_directmap(addrxlat_sys_t *sys, addrxlat_ctx_t *ctx,
	     addrxlat_addr_t addr)
{
	addrxlat_fulladdr_t faddr;
	addrxlat_status status;

	faddr.addr = addr;
	faddr.as = ADDRXLAT_KVADDR;
	status = internal_fulladdr_conv(&faddr, ADDRXLAT_KPHYSADDR, ctx, sys);
	clear_error(ctx);
	return status == ADDRXLAT_OK && faddr.addr == 0;
}

/** Get virtual memory layout by walking page tables.
 * @param sys    Translation system object.
 * @param ctx    Address translation context.
 * @returns      Memory layout, or @c NULL if undetermined.
 */
static const struct sys_region *
linux_layout_by_pgt(addrxlat_sys_t *sys, addrxlat_ctx_t *ctx)
{
	/* Only pre-2.6.11 kernels had this direct mapping */
	if (is_directmap(sys, ctx, 0x0000010000000000))
		return linux_layout_2_6_0;

	/* Only kernels between 2.6.11 and 2.6.27 had this direct mapping */
	if (is_directmap(sys, ctx, 0xffff810000000000))
		return linux_layout_2_6_11;

	/* Only 2.6.31+ kernels map VMEMMAP at this address */
	if (is_mapped(sys, ctx, 0xffffea0000000000))
		return linux_layout_2_6_31;

	/* Sanity check for 2.6.27+ direct mapping */
	if (is_directmap(sys, ctx, 0xffff880000000000))
		return linux_layout_2_6_27;

	return NULL;
}

/** Set Linux kernel text mapping offset.
 * @param sys    Translation system object.
 * @param ctx    Address translation object.
 * @param vaddr  Any valid kernel text virtual address.
 * @returns      Error status.
 */
static addrxlat_status
set_ktext_offset(addrxlat_sys_t *sys, addrxlat_ctx_t *ctx,
		 addrxlat_addr_t vaddr)
{
	addrxlat_step_t step;
	addrxlat_desc_t desc;
	addrxlat_status status;

	step.ctx = ctx;
	step.sys = sys;
	status = internal_launch_map(&step, vaddr,
				     sys->map[ADDRXLAT_SYS_MAP_HW]);
	if (status != ADDRXLAT_OK)
		return status;

	status = internal_walk(&step);
	if (status != ADDRXLAT_OK)
		return status;

	status = internal_fulladdr_conv(&step.base, ADDRXLAT_KPHYSADDR,
					ctx, sys);
	if (status != ADDRXLAT_OK)
		return status;

	desc.kind = ADDRXLAT_LINEAR;
	desc.target_as = ADDRXLAT_KPHYSADDR;
	desc.param.linear.off = step.base.addr - vaddr;
	return internal_meth_set_desc(
		sys->meth[ADDRXLAT_SYS_METH_KTEXT], &desc);
}

/** Fall back to page table mapping if needed.
 * @param sys    Translation system object.
 * @param idx    Translation method index.
 *
 * If the corresponding translation method is undefined, fall back
 * to hardware page table mapping.
 */
static void
set_pgt_fallback(addrxlat_sys_t *sys, addrxlat_sys_meth_t idx)
{
	addrxlat_meth_t *meth = sys->meth[idx];

	if (meth->desc.kind == ADDRXLAT_NOMETH) {
		addrxlat_meth_t *fallback = sys->meth[ADDRXLAT_SYS_METH_PGT];
		internal_meth_set_desc(meth, &fallback->desc);
	}
}

/** The beginning of the kernel text virtual mapping may not be mapped
 * for various reasons. Let's use an offset of 16M to be safe.
 */
#define LINUX_KTEXT_SKIP		(16ULL << 20)

/** Xen kernels are loaded low in memory. The ktext mapping may not go up
 * to 16M then. Let's use 1M, because Xen kernel should take up at least
 * 1M of RAM, and this value also covers kernels loaded at 1M (so this code
 * may be potentially reused for ia32).
 */
#define LINUX_KTEXT_SKIP_alt		(1ULL << 20)

/** Set up Linux kernel text translation method.
 * @param ctl     Initialization data.
 * @param region  Associated region definition.
 */
static addrxlat_status
linux_ktext_meth(struct os_init_data *ctl)
{
	addrxlat_status status;

	if (ctl->popt.val[OPT_physbase].set) {
		addrxlat_desc_t desc;

		desc.kind = ADDRXLAT_LINEAR;
		desc.target_as = ADDRXLAT_KPHYSADDR;
		desc.param.linear.off = ctl->popt.val[OPT_physbase].num -
			__START_KERNEL_map;
		return internal_meth_set_desc(
			ctl->sys->meth[ADDRXLAT_SYS_METH_KTEXT], &desc);
	}

	status = set_ktext_offset(ctl->sys, ctl->ctx,
				  __START_KERNEL_map + LINUX_KTEXT_SKIP);
	if (status == ADDRXLAT_ERR_NOTPRESENT || status == ADDRXLAT_ERR_NODATA) {
		clear_error(ctl->ctx);
		status = set_ktext_offset(ctl->sys, ctl->ctx,
					  __START_KERNEL_map +
					  LINUX_KTEXT_SKIP_alt);
	}
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status, "Cannot translate ktext");
	return status;
}

/** Set up Linux kernel text mapping on x86_64.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
linux_ktext_map(struct os_init_data *ctl)
{
	addrxlat_range_t range;
	addrxlat_status status;

	status = sys_ensure_meth(ctl, ADDRXLAT_SYS_METH_KTEXT);
	if (status != ADDRXLAT_OK)
		return status;

	status = linux_ktext_meth(ctl);
	if (status != ADDRXLAT_OK &&
	    status != ADDRXLAT_ERR_NOMETH &&
	    status != ADDRXLAT_ERR_NODATA &&
	    status != ADDRXLAT_ERR_NOTPRESENT)
		return status;
	clear_error(ctl->ctx);

	range.endoff = __END_KERNEL_map - __START_KERNEL_map;
	range.meth = ctl->sys->meth[ADDRXLAT_SYS_METH_KTEXT];
	status = internal_map_set(ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS],
				  __START_KERNEL_map, &range);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot set up Linux kernel text mapping");
	return ADDRXLAT_OK;
}

/** Initialize a translation map for Linux on x86_64.
 * @param ctl  Initialization data.
 * @param m2p  Virtual address of the machine-to-physical array.
 * @returns    Error status.
 */
static addrxlat_status
set_xen_mach2phys(struct os_init_data *ctl, addrxlat_addr_t m2p)
{
	addrxlat_meth_t *meth;
	addrxlat_desc_t desc;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_MACHPHYS_KPHYS];
	desc.kind = ADDRXLAT_MEMARR;
	desc.target_as = ADDRXLAT_KPHYSADDR;
	desc.param.memarr.base.as = ADDRXLAT_KVADDR;
	desc.param.memarr.base.addr = m2p;
	desc.param.memarr.shift = PAGE_SHIFT;
	desc.param.memarr.elemsz = sizeof(uint64_t);
	desc.param.memarr.valsz = sizeof(uint64_t);
	return internal_meth_set_desc(meth, &desc);
}

/** Initialize Xen p2m translation.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
set_xen_p2m(struct os_init_data *ctl)
{
	static const addrxlat_paging_form_t xen_p2m_pf = {
		.pte_format = ADDRXLAT_PTE_PFN64,
		.nfields = 4,
		.fieldsz = { 12, 9, 9, 9 }
	};

	addrxlat_addr_t p2m_maddr;
	addrxlat_map_t *map;
	addrxlat_meth_t *meth;
	addrxlat_desc_t desc;
	addrxlat_range_t range;
	addrxlat_status status;

	map = ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS];
	internal_map_clear(map);
	if (!ctl->popt.val[OPT_xen_p2m_mfn].set)
		return ADDRXLAT_OK; /* leave undefined */
	p2m_maddr = ctl->popt.val[OPT_xen_p2m_mfn].num << PAGE_SHIFT;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_KPHYS_MACHPHYS];
	desc.kind = ADDRXLAT_PGT;
	desc.target_as = ADDRXLAT_MACHPHYSADDR;
	desc.param.pgt.root.addr = p2m_maddr;
	desc.param.pgt.root.as = ADDRXLAT_MACHPHYSADDR;
	desc.param.pgt.pf = xen_p2m_pf;
	internal_meth_set_desc(meth, &desc);

	range.endoff = paging_max_index(&xen_p2m_pf);
	range.meth = meth;
	status = internal_map_set(map, 0, &range);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot allocate Xen p2m map");

	return ADDRXLAT_OK;
}

/** Initialize a translation map for Linux on x86_64.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
map_linux_x86_64(struct os_init_data *ctl)
{
	const struct sys_region *layout;
	addrxlat_status status;

	sys_sym_pgtroot(ctl, "cr3", "init_level4_pgt");

	if (ctl->popt.val[OPT_xen_xlat].set &&
	    ctl->popt.val[OPT_xen_xlat].num) {
		status = set_xen_p2m(ctl);
		if (status != ADDRXLAT_OK)
			return status;

		status = set_xen_mach2phys(ctl, XEN_MACH2PHYS_ADDR);
		if (status != ADDRXLAT_OK)
			return status;
	}

	status = linux_ktext_map(ctl);
	if (status != ADDRXLAT_OK)
		return status;

	layout = linux_layout_by_pgt(ctl->sys, ctl->ctx);

	if (!layout && ctl->osdesc->ver)
		layout = linux_layout_by_ver(ctl->osdesc->ver);
	if (!layout)
		return ADDRXLAT_OK;

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, layout);
	if (status != ADDRXLAT_OK)
		return status;

	set_pgt_fallback(ctl->sys, ADDRXLAT_SYS_METH_KTEXT);

	return ADDRXLAT_OK;
}

/** Xen direct mapping virtual address. */
#define XEN_DIRECTMAP	0xffff830000000000

/** Xen direct mapping virtual address with Xen 4.6+ BIGMEM. */
#define XEN_DIRECTMAP_BIGMEM	0xffff848000000000

/** Xen 1TB directmap size. */
#define XEN_DIRECTMAP_SIZE_1T	(1ULL << 40)

/** Xen 3.5TB directmap size (BIGMEM). */
#define XEN_DIRECTMAP_SIZE_3_5T	(3584ULL << 30)

/** Xen 5TB directmap size. */
#define XEN_DIRECTMAP_SIZE_5T	(5ULL << 40)

/** Xen 3.2-4.0 text virtual address. */
#define XEN_TEXT_3_2	0xffff828c80000000

/** Xen text virtual address (only during 4.0 development). */
#define XEN_TEXT_4_0dev	0xffff828880000000

/** Xen 4.0-4.3 text virtual address. */
#define XEN_TEXT_4_0	0xffff82c480000000

/** Xen 4.3-4.4 text virtual address. */
#define XEN_TEXT_4_3	0xffff82c4c0000000

/** Xen 4.4+ text virtual address. */
#define XEN_TEXT_4_4	0xffff82d080000000

/** Xen text mapping size. Always 1GB. */
#define XEN_TEXT_SIZE	(1ULL << 30)

/** Check whether an address looks like Xen text mapping.
 * @param ctl    Initialization data.
 * @param addr   Address to be checked.
 * @returns      Non-zero if the address maps to a 2M page.
 */
static int
is_xen_ktext(struct os_init_data *ctl, addrxlat_addr_t addr)
{
	addrxlat_step_t step;
	addrxlat_status status;
	unsigned steps = 0;

	step.ctx = ctl->ctx;
	step.sys = ctl->sys;
	step.meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	status = internal_launch(&step, addr);
	while (status == ADDRXLAT_OK && step.remain) {
		++steps;
		status = internal_step(&step);
	}

	clear_error(ctl->ctx);

	return status == ADDRXLAT_OK && steps == 4;
}

/** Initialize temporary mapping to make the page table usable.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
setup_xen_pgt(struct os_init_data *ctl)
{
	struct sys_region layout[2];
	addrxlat_meth_t *meth;
	addrxlat_desc_t desc;
	addrxlat_addr_t pgt;
	addrxlat_status status;

	status = sys_sym_pgtroot(ctl, "cr3", "pgd_l4");
	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	if (meth->desc.param.pgt.root.as != ADDRXLAT_KVADDR)
		return status;	/* either unset or physical */

	desc.kind = ADDRXLAT_LINEAR;
	desc.target_as = ADDRXLAT_KPHYSADDR;

	pgt = meth->desc.param.pgt.root.addr;
	if (pgt >= XEN_DIRECTMAP) {
		desc.param.linear.off = -XEN_DIRECTMAP;
	} else if (ctl->popt.val[OPT_physbase].set) {
		addrxlat_addr_t xen_virt_start = pgt & ~(XEN_TEXT_SIZE - 1);
		desc.param.linear.off = ctl->popt.val[OPT_physbase].num -
			xen_virt_start;
	} else
		return ADDRXLAT_ERR_NODATA;

	/* Temporary linear mapping just for the page table */
	layout[0].first = pgt;
	layout[0].last = pgt + (1ULL << PAGE_SHIFT) - 1;
	layout[0].meth = ADDRXLAT_SYS_METH_KTEXT;
	layout[0].act = SYS_ACT_NONE;

	layout[1].meth = ADDRXLAT_SYS_METH_NUM;

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, layout);
	if (status != ADDRXLAT_OK)
		return status;

	return internal_meth_set_desc(
		ctl->sys->meth[ADDRXLAT_SYS_METH_KTEXT], &desc);
}

/** Initialize a translation map for Xen on x86_64.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
map_xen_x86_64(struct os_init_data *ctl)
{
	struct sys_region layout[4];
	addrxlat_status status;

	layout[0].first = XEN_DIRECTMAP;
	layout[0].last = XEN_DIRECTMAP + XEN_DIRECTMAP_SIZE_5T - 1;
	layout[0].meth = ADDRXLAT_SYS_METH_DIRECT;
	layout[0].act = SYS_ACT_DIRECT;

	layout[1].meth = ADDRXLAT_SYS_METH_KTEXT;
	layout[1].act = SYS_ACT_NONE;

	layout[2].meth = ADDRXLAT_SYS_METH_NUM;

	setup_xen_pgt(ctl);

	if (is_directmap(ctl->sys, ctl->ctx, XEN_DIRECTMAP)) {
		if (is_xen_ktext(ctl, XEN_TEXT_4_4))
			layout[1].first = XEN_TEXT_4_4;
		else if (is_xen_ktext(ctl, XEN_TEXT_4_3))
			layout[1].first = XEN_TEXT_4_3;
		else if (is_xen_ktext(ctl, XEN_TEXT_4_0))
			layout[1].first = XEN_TEXT_4_0;
		else if (is_xen_ktext(ctl, XEN_TEXT_3_2)) {
			layout[0].last =
				XEN_DIRECTMAP + XEN_DIRECTMAP_SIZE_1T - 1;
			layout[1].first = XEN_TEXT_3_2;
		} else if (is_xen_ktext(ctl, XEN_TEXT_4_0dev))
			layout[1].first = XEN_TEXT_4_0dev;
		else {
			layout[0].last =
				XEN_DIRECTMAP + XEN_DIRECTMAP_SIZE_1T - 1;
			layout[1].meth = ADDRXLAT_SYS_METH_NUM;
		}
	} else if (is_directmap(ctl->sys, ctl->ctx, XEN_DIRECTMAP_BIGMEM)) {
		layout[0].first = XEN_DIRECTMAP_BIGMEM;
		layout[0].last =
			XEN_DIRECTMAP_BIGMEM + XEN_DIRECTMAP_SIZE_3_5T - 1;
		layout[1].first = XEN_TEXT_4_4;
	} else if (ctl->osdesc->ver >= ADDRXLAT_VER_XEN(4, 0)) {
		/* !BIGMEM is assumed for Xen 4.6+. Can we do better? */

		if (ctl->osdesc->ver >= ADDRXLAT_VER_XEN(4, 4))
			layout[1].first = XEN_TEXT_4_4;
		else if (ctl->osdesc->ver >= ADDRXLAT_VER_XEN(4, 3))
			layout[1].first = XEN_TEXT_4_3;
		else
			layout[1].first = XEN_TEXT_4_0;
	} else if (ctl->osdesc->ver) {
		layout[0].last =
			XEN_DIRECTMAP + XEN_DIRECTMAP_SIZE_1T - 1;

		if (ctl->osdesc->ver >= ADDRXLAT_VER_XEN(3, 2))
			layout[1].first = XEN_TEXT_3_2;
		else
			/* Prior to Xen 3.2, text was in direct mapping. */
			layout[1].meth = ADDRXLAT_SYS_METH_NUM;
	} else
		return ADDRXLAT_OK;

	layout[1].last = layout[1].first + XEN_TEXT_SIZE - 1;

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, layout);
	if (status != ADDRXLAT_OK)
		return status;

	if (layout[1].meth == ADDRXLAT_SYS_METH_KTEXT) {
		set_ktext_offset(ctl->sys, ctl->ctx, layout[1].first);
		clear_error(ctl->ctx);
		set_pgt_fallback(ctl->sys, ADDRXLAT_SYS_METH_KTEXT);
	}

	return ADDRXLAT_OK;
}

/** Generic x86_64 layout */
static const struct sys_region layout_generic[] = {
	{  0,  NONCANONICAL_START - 1,		/* lower half       */
	   ADDRXLAT_SYS_METH_PGT },
	/* NONCANONICAL_START - NONCANONICAL_END   non-canonical    */
	{  NONCANONICAL_END + 1,  VIRTADDR_MAX,	/* higher half      */
	   ADDRXLAT_SYS_METH_PGT },
	SYS_REGION_END
};

/** Initialize a translation map for an x86_64 OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_x86_64(struct os_init_data *ctl)
{
	static const addrxlat_paging_form_t x86_64_pf = {
		.pte_format = ADDRXLAT_PTE_X86_64,
		.nfields = 5,
		.fieldsz = { 12, 9, 9, 9, 9 }
	};
	addrxlat_map_t *map;
	addrxlat_meth_t *meth;
	addrxlat_desc_t desc;
	addrxlat_status status;

	status = sys_ensure_meth(ctl, ADDRXLAT_SYS_METH_PGT);
	if (status != ADDRXLAT_OK)
		return status;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	desc.kind = ADDRXLAT_PGT;
	desc.target_as = ADDRXLAT_MACHPHYSADDR;
	if (ctl->popt.val[OPT_rootpgt].set)
		desc.param.pgt.root = ctl->popt.val[OPT_rootpgt].fulladdr;
	else
		desc.param.pgt.root.as = ADDRXLAT_NOADDR;
	desc.param.pgt.pf = x86_64_pf;
	internal_meth_set_desc(meth, &desc);

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_HW, layout_generic);
	if (status != ADDRXLAT_OK)
		return status;

	map = internal_map_copy(ctl->sys->map[ADDRXLAT_SYS_MAP_HW]);
	if (!map)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
				 "Cannot duplicate hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = map;

	status = sys_set_physmaps(ctl, PHYSADDR_SIZE - 1);
	if (status != ADDRXLAT_OK)
		return status;

	switch (ctl->osdesc->type) {
	case ADDRXLAT_OS_LINUX:
		return map_linux_x86_64(ctl);

	case ADDRXLAT_OS_XEN:
		return map_xen_x86_64(ctl);

	default:
		return ADDRXLAT_OK;
	}
}
