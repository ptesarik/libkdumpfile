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

#define NONCANONICAL_START	((uint64_t)1<<(VIRTADDR_BITS_MAX-1))
#define NONCANONICAL_END	(~NONCANONICAL_START)
#define VIRTADDR_MAX		UINT64_MAX

struct layout_def {
	addrxlat_addr_t first, last;
	addrxlat_osmap_xlat_t xlat;
};

#define LAYOUT_END	{ 0, 0, ADDRXLAT_OSMAP_NUM }

/* Original Linux layout (before 2.6.11) */
static const struct layout_def linux_layout_2_6_0[] = {
	{  0x0000000000000000,  0x0000007fffffffff, /* user space       */
	   ADDRXLAT_OSMAP_PGT },
	/* 0x0000008000000000 - 0x000000ffffffffff     guard hole       */
	{  0x0000010000000000,  0x000001ffffffffff, /* direct mapping   */
	   ADDRXLAT_OSMAP_DIRECT },
	/* 0x0000020000000000 - 0x00007fffffffffff     unused hole      */
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xfffffeffffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_OSMAP_PGT },
	/* 0xffffff8000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   ADDRXLAT_OSMAP_KTEXT },
	/* 0xffffffff82800000 - 0xffffffff9fffffff     unused hole      */
	{  0xffffffffa0000000,  0xffffffffafffffff, /* modules          */
	   ADDRXLAT_OSMAP_PGT },
	/* 0xffffffffb0000000 - 0xffffffffff5exxxx     unused hole      */
	{  0xffffffffff5ed000,  0xffffffffffdfffff, /* fixmap/vsyscalls */
	   ADDRXLAT_OSMAP_PGT },
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	LAYOUT_END
};

/* Linux layout introduced in 2.6.11 */
static const struct layout_def linux_layout_2_6_11[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   ADDRXLAT_OSMAP_PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	{  0xffff810000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   ADDRXLAT_OSMAP_DIRECT },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_OSMAP_PGT },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   ADDRXLAT_OSMAP_PGT },		    /*   (2.6.24+ only) */
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   ADDRXLAT_OSMAP_KTEXT },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   ADDRXLAT_OSMAP_PGT },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	LAYOUT_END
};

/** Linux layout with hypervisor area, introduced in 2.6.27 */
static const struct layout_def linux_layout_2_6_27[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   ADDRXLAT_OSMAP_PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   ADDRXLAT_OSMAP_DIRECT },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_OSMAP_PGT },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   ADDRXLAT_OSMAP_PGT },
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   ADDRXLAT_OSMAP_KTEXT },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   ADDRXLAT_OSMAP_PGT },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	LAYOUT_END
};

/** Linux layout with 64T direct mapping, introduced in 2.6.31 */
static const struct layout_def linux_layout_2_6_31[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   ADDRXLAT_OSMAP_PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc7ffffffffff, /* direct mapping   */
	   ADDRXLAT_OSMAP_DIRECT },
	/* 0xffffc80000000000 - 0xffffc8ffffffffff     guard hole       */
	{  0xffffc90000000000,  0xffffe8ffffffffff, /* vmalloc/ioremap  */
	   ADDRXLAT_OSMAP_PGT },
	/* 0xffffe90000000000 - 0xffffe9ffffffffff     guard hole       */
	{  0xffffea0000000000,  0xffffeaffffffffff, /* VMEMMAP          */
	   ADDRXLAT_OSMAP_PGT },
	/* 0xffffeb0000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* %esp fixup stack */
	   ADDRXLAT_OSMAP_PGT },
	/* 0xffffff8000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffffef00000000,  0xfffffffeffffffff, /* EFI runtime      */
	   ADDRXLAT_OSMAP_PGT },		    /*     (3.14+ only) */
	/* 0xffffffff00000000 - 0xffffffff7fffffff     guard hole       */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   ADDRXLAT_OSMAP_KTEXT },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   ADDRXLAT_OSMAP_PGT },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
	LAYOUT_END
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
	const struct pgt_xlat *pgt = &state->def->pgt;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(state->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = state->raw_pte & ~PHYSADDR_MASK;
	if (state->level >= 2 && state->level <= 3 &&
	    (state->raw_pte & _PAGE_PSE)) {
		state->base.addr &= pgt->pgt_mask[state->level - 1];
		return pgt_huge_page(state);
	}

	state->base.addr &= pgt->pgt_mask[0];
	return addrxlat_continue;
}

/** Create a page table address map for x86_64 canonical regions.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns           New translation map, or @c NULL on error.
 */
static addrxlat_status
canonical_pgt_map(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
		  const addrxlat_osdesc_t *osdesc)
{
	addrxlat_range_t range;
	addrxlat_map_t *newmap;

	range.def = osmap->def[ADDRXLAT_OSMAP_PGT];

	range.endoff = NONCANONICAL_START - 1;
	newmap = internal_map_set(osmap->map, 0, &range);
	if (!newmap)
		goto err;
	osmap->map = newmap;

	range.endoff = VIRTADDR_MAX - NONCANONICAL_END - 1;
	newmap = internal_map_set(osmap->map, NONCANONICAL_END + 1, &range);
	if (!newmap)
		goto err;
	osmap->map = newmap;

	return addrxlat_ok;

 err:
	return set_error(ctx, addrxlat_nomem,
			 "Cannot set up default mapping");
}

/** Get Linux virtual memory layout by kernel version.
 * @param ver  Version code.
 * @returns    Layout definition, or @c NULL.
 */
static const struct layout_def*
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
 * @param osmap  OS map object.
 * @param ctx    Address translation context.
 * @param addr   Address to be checked.
 * @returns      Non-zero if the address can be translated.
 */
static int
is_mapped(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
	  addrxlat_addr_t addr)
{
	addrxlat_status status =
		internal_walk(ctx, osmap->def[ADDRXLAT_OSMAP_PGT], &addr);
	return status == addrxlat_ok;
}

/** Check whether an address looks like start of direct mapping.
 * @param osmap  OS map object.
 * @param ctx    Address translation context.
 * @param addr   Address to be checked.
 * @returns      Non-zero if the address maps to physical address 0.
 */
static int
is_directmap(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
	     addrxlat_addr_t addr)
{
	addrxlat_status status =
		internal_walk(ctx, osmap->def[ADDRXLAT_OSMAP_PGT], &addr);
	return status == addrxlat_ok && addr == 0;
}

/** Get virtual memory layout by walking page tables.
 * @param osmap  OS map object.
 * @param ctx    Address translation context.
 * @returns      Memory layout, or @c NULL if undetermined.
 */
static const struct layout_def*
linux_layout_by_pgt(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx)
{
	/* Only pre-2.6.11 kernels had this direct mapping */
	if (is_directmap(osmap, ctx, 0x0000010000000000))
		return linux_layout_2_6_0;

	/* Only kernels between 2.6.11 and 2.6.27 had this direct mapping */
	if (is_directmap(osmap, ctx, 0xffff810000000000))
		return linux_layout_2_6_11;

	/* Only 2.6.31+ kernels map VMEMMAP at this address */
	if (is_mapped(osmap, ctx, 0xffffea0000000000))
		return linux_layout_2_6_31;

	/* Sanity check for 2.6.27+ direct mapping */
	if (is_directmap(osmap, ctx, 0xffff880000000000))
		return linux_layout_2_6_27;

	return NULL;
}

/** Set Linux kernel text mapping offset.
 * @param osmap  OS map object.
 * @param ctx    Address translation object.
 * @param vaddr  Any valid kernel text virtual address.
 */
static void
set_ktext_offset(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
		 addrxlat_addr_t vaddr)
{
	addrxlat_addr_t addr;
	addrxlat_status status;

	addr = vaddr;
	status = internal_walk(ctx, osmap->def[ADDRXLAT_OSMAP_PGT], &addr);
	if (status == addrxlat_ok)
		internal_def_set_offset(osmap->def[ADDRXLAT_OSMAP_KTEXT],
					vaddr - addr);
}

/** Fall back to page table mapping if needed.
 * @param osmap  OS map object.
 * @param xlat   Translation definition index.
 *
 * If the corresponding translation definition is undefined, fall back
 * to hardware page table mapping.
 */
static void
set_pgt_fallback(addrxlat_osmap_t *osmap, addrxlat_osmap_xlat_t xlat)
{
	addrxlat_def_t *def = osmap->def[xlat];

	if (def->kind == ADDRXLAT_NONE) {
		addrxlat_def_t *fallback = osmap->def[ADDRXLAT_OSMAP_PGT];
		internal_def_set_form(def, &fallback->pgt.pf);
	}
}

/* The beginning of the kernel text virtual mapping may not be mapped
 * for various reasons. Let's use an offset of 16M to be safe.
 */
#define LINUX_KTEXT_SKIP		(16ULL << 20)

/** Initialize a translation map for Linux on x86_64.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 */
static addrxlat_status
map_linux_x86_64(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
		 const addrxlat_osdesc_t *osdesc)
{
	const struct layout_def *layout = NULL;
	addrxlat_map_t *newmap;

	if (!osmap->def[ADDRXLAT_OSMAP_DIRECT])
		osmap->def[ADDRXLAT_OSMAP_DIRECT] = internal_def_new();
	if (!osmap->def[ADDRXLAT_OSMAP_DIRECT])
		return addrxlat_nomem;

	if (!osmap->def[ADDRXLAT_OSMAP_KTEXT])
		osmap->def[ADDRXLAT_OSMAP_KTEXT] = internal_def_new();
	if (!osmap->def[ADDRXLAT_OSMAP_KTEXT])
		return addrxlat_nomem;

	layout = linux_layout_by_pgt(osmap, ctx);

	if (!layout && osdesc->ver)
		layout = linux_layout_by_ver(osdesc->ver);
	if (!layout)
		return addrxlat_ok;

	while (layout->xlat != ADDRXLAT_OSMAP_NUM) {
		addrxlat_range_t range;

		range.endoff = layout->last - layout->first;
		range.def = osmap->def[layout->xlat];

		if (layout->xlat == ADDRXLAT_OSMAP_DIRECT)
			internal_def_set_offset(range.def, layout->first);
		if (layout->xlat == ADDRXLAT_OSMAP_KTEXT)
			set_ktext_offset(osmap, ctx,
					 layout->first + LINUX_KTEXT_SKIP);

		newmap = internal_map_set(osmap->map, layout->first, &range);
		if (!newmap)
			return set_error(ctx, addrxlat_nomem,
					 "Cannot set up mapping for"
					 " 0x%"ADDRXLAT_PRIxADDR
					 "-0x%"ADDRXLAT_PRIxADDR,
					 layout->first, layout->last);
		osmap->map = newmap;

		++layout;
	}

	set_pgt_fallback(osmap, ADDRXLAT_OSMAP_DIRECT);
	set_pgt_fallback(osmap, ADDRXLAT_OSMAP_KTEXT);

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
 * @param osmap  OS map object.
 * @param ctx    Address translation context.
 * @param addr   Address to be checked.
 * @returns      Non-zero if the address maps to a 2M page.
 */
static int
is_xen_ktext(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
	     addrxlat_addr_t addr)
{
	addrxlat_walk_t walk;
	addrxlat_status status;
	unsigned steps;

	status = internal_walk_init(&walk, ctx,
				    osmap->def[ADDRXLAT_OSMAP_PGT], addr);
	for (steps = 0; status == addrxlat_continue; ++steps)
		status = internal_walk_next(&walk);

	return status == addrxlat_ok && steps == 4;
}

/** Initialize a translation map for Xen on x86_64.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 */
static addrxlat_status
map_xen_x86_64(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
	       const addrxlat_osdesc_t *osdesc)
{
	addrxlat_range_t range_direct, range_ktext;
	addrxlat_addr_t addr_direct, addr_ktext;
	addrxlat_map_t *newmap;

	if (!osmap->def[ADDRXLAT_OSMAP_DIRECT])
		osmap->def[ADDRXLAT_OSMAP_DIRECT] = internal_def_new();
	if (!osmap->def[ADDRXLAT_OSMAP_DIRECT])
		return addrxlat_nomem;

	range_direct.def = osmap->def[ADDRXLAT_OSMAP_DIRECT];
	range_direct.endoff = XEN_DIRECTMAP_SIZE_5T - 1;

	if (!osmap->def[ADDRXLAT_OSMAP_KTEXT])
		osmap->def[ADDRXLAT_OSMAP_KTEXT] = internal_def_new();
	if (!osmap->def[ADDRXLAT_OSMAP_KTEXT])
		return addrxlat_nomem;

	range_ktext.def = osmap->def[ADDRXLAT_OSMAP_KTEXT];
	range_ktext.endoff = XEN_TEXT_SIZE - 1;

	addr_direct = XEN_DIRECTMAP;
	if (is_directmap(osmap, ctx, XEN_DIRECTMAP)) {
		if (is_xen_ktext(osmap, ctx, XEN_TEXT_4_4))
			addr_ktext = XEN_TEXT_4_4;
		else if (is_xen_ktext(osmap, ctx, XEN_TEXT_4_3))
			addr_ktext = XEN_TEXT_4_3;
		else if (is_xen_ktext(osmap, ctx, XEN_TEXT_4_0))
			addr_ktext = XEN_TEXT_4_0;
		else if (is_xen_ktext(osmap, ctx, XEN_TEXT_3_2)) {
			range_direct.endoff = XEN_DIRECTMAP_SIZE_1T - 1;
			addr_ktext = XEN_TEXT_3_2;
		} else if (is_xen_ktext(osmap, ctx, XEN_TEXT_4_0dev))
			addr_ktext = XEN_TEXT_4_0dev;
		else {
			range_direct.endoff = XEN_DIRECTMAP_SIZE_1T - 1;
			addr_ktext = 0;
		}
	} else if (is_directmap(osmap, ctx, XEN_DIRECTMAP_BIGMEM)) {
		addr_direct = XEN_DIRECTMAP_BIGMEM;
		range_direct.endoff = XEN_DIRECTMAP_SIZE_3_5T - 1;
		addr_ktext = XEN_TEXT_4_4;
	} else if (osdesc->ver >= ADDRXLAT_VER_XEN(4, 0)) {
		/* !BIGMEM is assumed for Xen 4.6+. Can we do better? */

		if (osdesc->ver >= ADDRXLAT_VER_XEN(4, 4))
			addr_ktext = XEN_TEXT_4_4;
		else if (osdesc->ver >= ADDRXLAT_VER_XEN(4, 3))
			addr_ktext = XEN_TEXT_4_3;
		else
			addr_ktext = XEN_TEXT_4_0;
	} else if (osdesc->ver) {
		range_direct.endoff = XEN_DIRECTMAP_SIZE_1T - 1;

		if (osdesc->ver >= ADDRXLAT_VER_XEN(3, 2))
			addr_ktext = XEN_TEXT_3_2;
		else
			/* Prior to Xen 3.2, text was in direct mapping. */
			addr_ktext = 0;
	} else
		return addrxlat_ok;

	internal_def_set_offset(range_direct.def, addr_direct);
	newmap = internal_map_set(osmap->map, addr_direct, &range_direct);
	if (!newmap)
		return set_error(ctx, addrxlat_nomem,
				 "Cannot set up Xen direct mapping");
	osmap->map = newmap;

	if (addr_ktext) {
		set_ktext_offset(osmap, ctx, addr_ktext);
		newmap = internal_map_set(osmap->map, addr_ktext, &range_ktext);
		if (!newmap)
			return set_error(ctx, addrxlat_nomem,
					 "Cannot set up Xen text mapping");
		osmap->map = newmap;
	}

	set_pgt_fallback(osmap, ADDRXLAT_OSMAP_DIRECT);
	set_pgt_fallback(osmap, ADDRXLAT_OSMAP_KTEXT);

	return addrxlat_ok;
}

/** Initialize a translation map for an x86_64 OS.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 */
addrxlat_status
osmap_x86_64(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
	     const addrxlat_osdesc_t *osdesc)
{
	static const addrxlat_paging_form_t x86_64_pf = {
		.pte_format = addrxlat_pte_x86_64,
		.levels = 5,
		.bits = { 12, 9, 9, 9, 9 }
	};
	addrxlat_status status;

	if (!osmap->def[ADDRXLAT_OSMAP_PGT])
		osmap->def[ADDRXLAT_OSMAP_PGT] = internal_def_new();
	if (!osmap->def[ADDRXLAT_OSMAP_PGT])
		return addrxlat_nomem;

	internal_def_set_form(osmap->def[ADDRXLAT_OSMAP_PGT], &x86_64_pf);
	status = canonical_pgt_map(osmap, ctx, osdesc);
	if (status != addrxlat_ok)
		return status;

	switch (osdesc->type) {
	case addrxlat_os_linux:
		return map_linux_x86_64(osmap, ctx, osdesc);

	case addrxlat_os_xen:
		return map_xen_x86_64(osmap, ctx, osdesc);

	default:
		return addrxlat_ok;
	}
}
