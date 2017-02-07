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
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
pgt_x86_64(addrxlat_walk_t *state)
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
	const struct pgt_extra_def *pgt = &state->meth->extra.pgt;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(state->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.addr = state->raw_pte & ~PHYSADDR_MASK;
	if (state->level >= 2 && state->level <= 3 &&
	    (state->raw_pte & _PAGE_PSE)) {
		state->base.addr &= pgt->pgt_mask[state->level - 1];
		return pgt_huge_page(state);
	}

	state->base.addr &= pgt->pgt_mask[0];
	return addrxlat_continue;
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

/** Check whether the PGT translation method is usable.
 * @param sys    Translation system object.
 * @returns      Non-zero if PGT can be used, zero otherwise.
 */
static addrxlat_status
is_pgt_usable(addrxlat_sys_t *sys)
{
	const addrxlat_meth_t *meth, *pgtmeth;

	pgtmeth = sys->meth[ADDRXLAT_SYS_METH_PGT];
	switch (pgtmeth->def.param.pgt.root.as) {
	case ADDRXLAT_MACHPHYSADDR:
	case ADDRXLAT_KPHYSADDR:
		return 1;

	case ADDRXLAT_KVADDR:
		meth = internal_map_search(sys->map[ADDRXLAT_SYS_MAP_KV_PHYS],
					   pgtmeth->def.param.pgt.root.addr);
		return meth != pgtmeth;

	default:
		return 0;
	}
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
	addrxlat_status status =
		internal_walk(ctx, sys->meth[ADDRXLAT_SYS_METH_PGT], &addr);
	return status == addrxlat_ok;
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
	addrxlat_status status =
		internal_walk(ctx, sys->meth[ADDRXLAT_SYS_METH_PGT], &addr);
	return status == addrxlat_ok && addr == 0;
}

/** Get virtual memory layout by walking page tables.
 * @param sys    Translation system object.
 * @param ctx    Address translation context.
 * @returns      Memory layout, or @c NULL if undetermined.
 */
static const struct sys_region *
linux_layout_by_pgt(addrxlat_sys_t *sys, addrxlat_ctx_t *ctx)
{
	if (!is_pgt_usable(sys))
		return NULL;

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
	addrxlat_addr_t addr;
	addrxlat_status status;

	if (!is_pgt_usable(sys))
		return addrxlat_nodata;

	addr = vaddr;
	status = internal_walk(ctx, sys->meth[ADDRXLAT_SYS_METH_PGT], &addr);
	if (status == addrxlat_ok) {
		addrxlat_def_t def;
		def.kind = ADDRXLAT_LINEAR;
		def.target_as = ADDRXLAT_KPHYSADDR;
		def.param.linear.off = vaddr - addr;
		status = internal_meth_set_def(
			sys->meth[ADDRXLAT_SYS_METH_KTEXT], &def);
	}
	return status;
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

	if (meth->def.kind == ADDRXLAT_NONE) {
		addrxlat_meth_t *fallback = sys->meth[ADDRXLAT_SYS_METH_PGT];
		internal_meth_set_def(meth, &fallback->def);
	}
}

/* The beginning of the kernel text virtual mapping may not be mapped
 * for various reasons. Let's use an offset of 16M to be safe.
 */
#define LINUX_KTEXT_SKIP		(16ULL << 20)

/** Set up Linux kernel text translation method.
 * @param ctl     Initialization data.
 * @param region  Associated region definition.
 */
static addrxlat_status
linux_ktext_meth(struct sys_init_data *ctl)
{
	if (ctl->popt.val[OPT_physbase].set) {
		addrxlat_def_t def;

		def.kind = ADDRXLAT_LINEAR;
		def.target_as = ADDRXLAT_KPHYSADDR;
		def.param.linear.off = __START_KERNEL_map -
			ctl->popt.val[OPT_physbase].num;
		return internal_meth_set_def(
			ctl->sys->meth[ADDRXLAT_SYS_METH_KTEXT], &def);
	}

	return set_ktext_offset(ctl->sys, ctl->ctx,
				  __START_KERNEL_map + LINUX_KTEXT_SKIP);
}

/** Set up Linux kernel text mapping on x86_64.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
linux_ktext_map(struct sys_init_data *ctl)
{
	addrxlat_range_t range;
	addrxlat_map_t *newmap;
	addrxlat_status status;

	status = sys_ensure_meth(ctl, ADDRXLAT_SYS_METH_KTEXT);
	if (status != addrxlat_ok)
		return status;

	range.meth = ctl->sys->meth[ADDRXLAT_SYS_METH_KTEXT];
	if (range.meth->def.kind == ADDRXLAT_NONE) {
		status = linux_ktext_meth(ctl);
		if (status != addrxlat_ok && status != addrxlat_nodata)
			return status;
	}

	range.endoff = __END_KERNEL_map - __START_KERNEL_map;
	newmap = internal_map_set(ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS],
				  __START_KERNEL_map, &range);
	if (!newmap)
		return set_error(ctl->ctx, addrxlat_nomem,
				 "Cannot set up Linux kernel text mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = newmap;
	return addrxlat_ok;
}

/** Get Linux page table root address using symbolic information.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
get_linux_pgtroot(struct sys_init_data *ctl)
{
	addrxlat_meth_t *meth;
	addrxlat_addr_t addr;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	if (meth->def.param.pgt.root.as != ADDRXLAT_NOADDR)
		return addrxlat_ok;

	if (get_reg(ctl->ctx, "cr3", &addr) == addrxlat_ok) {
		meth->def.param.pgt.root.as = ADDRXLAT_MACHPHYSADDR;
		meth->def.param.pgt.root.addr = addr;
		return addrxlat_ok;
	}

	if (get_symval(ctl->ctx, "init_level4_pgt", &addr) == addrxlat_ok) {
		meth->def.param.pgt.root.as = ADDRXLAT_KVADDR;
		meth->def.param.pgt.root.addr = addr;
		return addrxlat_ok;
	}

	return addrxlat_nodata;
}

/** Initialize a translation map for Linux on x86_64.
 * @param ctl  Initialization data.
 * @param m2p  Virtual address of the machine-to-physical array.
 * @returns    Error status.
 */
static addrxlat_status
set_xen_mach2phys(struct sys_init_data *ctl, addrxlat_addr_t m2p)
{
	addrxlat_meth_t *meth;
	addrxlat_def_t def;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_MACHPHYS_KPHYS];
	def.kind = ADDRXLAT_MEMARR;
	def.target_as = ADDRXLAT_KPHYSADDR;
	def.param.memarr.base.as = ADDRXLAT_KVADDR;
	def.param.memarr.base.addr = m2p;
	def.param.memarr.shift = PAGE_SHIFT;
	def.param.memarr.elemsz = sizeof(uint64_t);
	def.param.memarr.valsz = sizeof(uint64_t);
	return addrxlat_meth_set_def(meth, &def);
}

/** Initialize Xen p2m translation.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
 addrxlat_status
set_xen_p2m(struct sys_init_data *ctl)
{
	static const addrxlat_paging_form_t xen_p2m_pf = {
		.pte_format = addrxlat_pte_pfn64,
		.levels = 4,
		.bits = { 12, 9, 9, 9 }
	};

	addrxlat_addr_t p2m_maddr;
	addrxlat_map_t *map;
	addrxlat_meth_t *meth;
	addrxlat_def_t def;
	addrxlat_range_t range;

	map = ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS];
	internal_map_clear(map);
	if (!ctl->popt.val[OPT_xen_p2m_mfn].set)
		return addrxlat_ok; /* leave undefined */
	p2m_maddr = ctl->popt.val[OPT_xen_p2m_mfn].num << PAGE_SHIFT;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_KPHYS_MACHPHYS];
	def.kind = ADDRXLAT_PGT;
	def.target_as = ADDRXLAT_MACHPHYSADDR;
	def.param.pgt.root.addr = p2m_maddr;
	def.param.pgt.root.as = ADDRXLAT_MACHPHYSADDR;
	def.param.pgt.pf = xen_p2m_pf;
	internal_meth_set_def(meth, &def);

	range.endoff = paging_max_index(&xen_p2m_pf);
	range.meth = meth;
	map = addrxlat_map_set(map, 0, &range);
	if (!map)
		return set_error(ctl->ctx, addrxlat_nomem,
				 "Cannot allocate Xen p2m map");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS] = map;

	return addrxlat_ok;
}

/** Initialize a translation map for Linux on x86_64.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
map_linux_x86_64(struct sys_init_data *ctl)
{
	const struct sys_region *layout;
	addrxlat_status status;

	get_linux_pgtroot(ctl);

	status = linux_ktext_map(ctl);
	if (status != addrxlat_ok)
		return status;

	if (ctl->popt.val[OPT_xen_xlat].set &&
	    ctl->popt.val[OPT_xen_xlat].num) {
		status = set_xen_p2m(ctl);
		if (status != addrxlat_ok)
			return status;

		status = set_xen_mach2phys(ctl, XEN_MACH2PHYS_ADDR);
		if (status != addrxlat_ok)
			return status;
	}

	layout = linux_layout_by_pgt(ctl->sys, ctl->ctx);

	if (!layout && ctl->osdesc->ver)
		layout = linux_layout_by_ver(ctl->osdesc->ver);
	if (!layout)
		return addrxlat_ok;

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, layout);
	if (status != addrxlat_ok)
		return status;

	set_pgt_fallback(ctl->sys, ADDRXLAT_SYS_METH_KTEXT);

	return addrxlat_ok;
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
is_xen_ktext(struct sys_init_data *ctl, addrxlat_addr_t addr)
{
	addrxlat_walk_t walk;
	addrxlat_status status;
	unsigned steps;

	status = internal_walk_init(&walk, ctl->ctx,
				    ctl->sys->meth[ADDRXLAT_SYS_METH_PGT],
				    addr);
	for (steps = 0; status == addrxlat_continue; ++steps)
		status = internal_walk_next(&walk);

	return status == addrxlat_ok && steps == 4;
}

/** Initialize a translation map for Xen on x86_64.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
map_xen_x86_64(struct sys_init_data *ctl)
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
		return addrxlat_ok;

	layout[1].last = layout[1].first + XEN_TEXT_SIZE - 1;

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, layout);
	if (status != addrxlat_ok)
		return status;

	if (layout[1].meth == ADDRXLAT_SYS_METH_KTEXT) {
		set_ktext_offset(ctl->sys, ctl->ctx, layout[1].first);
		set_pgt_fallback(ctl->sys, ADDRXLAT_SYS_METH_KTEXT);
	}

	return addrxlat_ok;
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
sys_x86_64(struct sys_init_data *ctl)
{
	static const addrxlat_paging_form_t x86_64_pf = {
		.pte_format = addrxlat_pte_x86_64,
		.levels = 5,
		.bits = { 12, 9, 9, 9, 9 }
	};
	addrxlat_map_t *map;
	addrxlat_meth_t *meth;
	addrxlat_def_t def;
	addrxlat_status status;

	status = sys_ensure_meth(ctl, ADDRXLAT_SYS_METH_PGT);
	if (status != addrxlat_ok)
		return status;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	def.kind = ADDRXLAT_PGT;
	def.target_as = ADDRXLAT_MACHPHYSADDR;
	if (ctl->popt.val[OPT_rootpgt].set)
		def.param.pgt.root = ctl->popt.val[OPT_rootpgt].fulladdr;
	else
		def.param.pgt.root.as = ADDRXLAT_NOADDR;
	def.param.pgt.pf = x86_64_pf;
	internal_meth_set_def(meth, &def);

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_HW, layout_generic);
	if (status != addrxlat_ok)
		return status;

	map = addrxlat_map_dup(ctl->sys->map[ADDRXLAT_SYS_MAP_HW]);
	if (!map)
		return set_error(ctl->ctx, addrxlat_nomem,
				 "Cannot duplicate hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = map;

	status = sys_set_physmaps(ctl, PHYSADDR_SIZE - 1);
	if (status != addrxlat_ok)
		return status;

	switch (ctl->osdesc->type) {
	case addrxlat_os_linux:
		return map_linux_x86_64(ctl);

	case addrxlat_os_xen:
		return map_xen_x86_64(ctl);

	default:
		return addrxlat_ok;
	}
}
