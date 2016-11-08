/** @internal @file src/x86_64.c
 * @brief Functions for the x86-64 architecture.
 */
/* Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#define _GNU_SOURCE

#include "kdumpfile-priv.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/version.h>

#define ELF_NGREG 27

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	48

#define NONCANONICAL_START	((uint64_t)1<<(VIRTADDR_BITS_MAX-1))
#define NONCANONICAL_END	(~NONCANONICAL_START)
#define VIRTADDR_MAX		UINT64_MAX

#define PAGE_SHIFT	12
#define PAGE_SIZE	((uint64_t)1 << PAGE_SHIFT)

#define PTRS_PER_PAGE	(PAGE_SIZE/sizeof(uint64_t))

#define __START_KERNEL_map	0xffffffff80000000ULL

/* The beginning of kernel text virtual mapping may not be mapped
 * for various reasons. Let's use an offset of 1M to be safe.
 */
#define KERNEL_map_skip		(1ULL << 20)

/* This constant is not the maximum physical load offset. This is the
 * maximum expected value of the PHYSICAL_START config option, which
 * defaults to 0x1000000. A relocatable kernel can be loaded anywhere
 * regardless of this config option. It is useful only for non-relocatable
 * kernels, and it moves the kernel text both in physical and virtual
 * address spaces. That means, the kernel must never overlap with the
 * following area in virtual address space (kernel modules). The virtual
 * memory layout has changed several times, but the minimum distance from
 * kernel modules has been 128M (the following constants). On kernel
 * versions where the distance is 512M, PHYSICAL_START can be higher than
 * this value. The check in process_load() will fail in such configurations.
 *
 * In other words, this constant is a safe value that will prevent
 * mistaking a kernel module LOAD for kernel text even on kernels
 * where the gap is only 128M.
 */
#define MAX_PHYSICAL_START	0x0000000008000000ULL

/**  Private data for the x86_64 arch-specific methods.
 */
struct x86_64_data {
	/** Overridden methods for linux.phys_base attribute. */
	struct attr_override phys_base_override;

	/** Directmap translation. */
	addrxlat_meth_t *directmap;

	/** Kernel text translation. */
	addrxlat_meth_t *ktext;

	/** Xen directmap translation. */
	addrxlat_meth_t *xen_directmap;
};

enum xlat_type {
	PGT,
	DIRECTMAP,
	KTEXT,
};

struct region_def {
	kdump_vaddr_t first, last;
	enum xlat_type xlat;
};

/* Original layout (before 2.6.11) */
static const struct region_def mm_layout_2_6_0[] = {
	{  0x0000000000000000,  0x0000007fffffffff, /* user space       */
	   PGT },
	/* 0x0000008000000000 - 0x000000ffffffffff     guard hole       */
	{  0x0000010000000000,  0x000001ffffffffff, /* direct mapping   */
	   DIRECTMAP },
	/* 0x0000020000000000 - 0x00007fffffffffff     unused hole      */
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xfffffeffffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* vmalloc/ioremap  */
	   PGT },
	/* 0xffffff8000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KTEXT },
	/* 0xffffffff82800000 - 0xffffffff9fffffff     unused hole      */
	{  0xffffffffa0000000,  0xffffffffafffffff, /* modules          */
	   PGT },
	/* 0xffffffffb0000000 - 0xffffffffff5exxxx     unused hole      */
	{  0xffffffffff5ed000,  0xffffffffffdfffff, /* fixmap/vsyscalls */
	   PGT },
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

/* New layout introduced in 2.6.11 */
static const struct region_def mm_layout_2_6_11[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	{  0xffff810000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   DIRECTMAP },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   PGT },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   PGT },				    /*   (2.6.24+ only) */
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KTEXT },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   PGT },				    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

static const struct region_def mm_layout_2_6_27[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   DIRECTMAP },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   PGT },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   PGT },
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KTEXT },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   PGT },				    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

static const struct region_def mm_layout_2_6_31[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   PGT },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc7ffffffffff, /* direct mapping   */
	   DIRECTMAP },
	/* 0xffffc80000000000 - 0xffffc8ffffffffff     guard hole       */
	{  0xffffc90000000000,  0xffffe8ffffffffff, /* vmalloc/ioremap  */
	   PGT },
	/* 0xffffe90000000000 - 0xffffe9ffffffffff     guard hole       */
	{  0xffffea0000000000,  0xffffeaffffffffff, /* VMEMMAP          */
	   PGT },
	/* 0xffffeb0000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* %esp fixup stack */
	   PGT },
	/* 0xffffff8000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffffef00000000,  0xfffffffeffffffff, /* EFI runtime      */
	   PGT },				    /*     (3.14+ only) */
	/* 0xffffffff00000000 - 0xffffffff7fffffff     guard hole       */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KTEXT },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   PGT },				    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

#define LAYOUT_NAME(a, b, c)	mm_layout_ ## a ## _ ## b ## _ ## c
#define DEF_LAYOUT(a, b, c) \
	{ KERNEL_VERSION(a, b, c), LAYOUT_NAME(a, b, c),	\
			ARRAY_SIZE(LAYOUT_NAME(a, b, c)) }

static const struct layout_def {
	unsigned ver;
	const struct region_def *regions;
	unsigned nregions;
} mm_layouts[] = {
	DEF_LAYOUT(2, 6, 0),
	DEF_LAYOUT(2, 6, 11),
	DEF_LAYOUT(2, 6, 27),
	DEF_LAYOUT(2, 6, 31),
};

#define XEN_DIRECTMAP_START	0xffff830000000000ULL
#define XEN_DIRECTMAP_END_OLD	0xffff83ffffffffffULL
#define XEN_DIRECTMAP_END_4_0_0	0xffff87ffffffffffULL
#define XEN_VIRT_SIZE		(1ULL<<30)
#define MACH2PHYS_VIRT_START	0xffff828000000000ULL

/** @cond TARGET_ABI */

struct elf_siginfo
{
	int32_t si_signo;	/* signal number */
	int32_t si_code;	/* extra code */
	int32_t si_errno;	/* errno */
} __attribute__((packed));

struct elf_prstatus
{
	struct elf_siginfo pr_info;	/* UNUSED in kernel cores */
	int16_t	pr_cursig;		/* UNUSED in kernel cores */
	char	_pad1[2];		/* alignment */
	uint64_t pr_sigpend;		/* UNUSED in kernel cores */
	uint64_t pr_sighold;		/* UNUSED in kernel cores */
	int32_t	pr_pid;			/* PID of crashing task */
	int32_t	pr_ppid;		/* UNUSED in kernel cores */
	int32_t	pr_pgrp;		/* UNUSED in kernel cores */
	int32_t	pr_sid;			/* UNUSED in kernel cores */
	struct timeval_64 pr_utime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_stime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_cutime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_cstime;	/* UNUSED in kernel cores */
	uint64_t pr_reg[ELF_NGREG];	/* GP registers */
	/* optional UNUSED fields may follow */
} __attribute__((packed));

struct xen_cpu_user_regs {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint32_t error_code;    /* private */
	uint32_t entry_vector;  /* private */
	uint64_t rip;
	uint16_t cs, _pad0[1];
	uint8_t  saved_upcall_mask;
	uint8_t  _pad1[3];
	uint64_t rflags;	/* rflags.IF == !saved_upcall_mask */
	uint64_t rsp;
	uint16_t ss, _pad2[3];
	uint16_t es, _pad3[3];
	uint16_t ds, _pad4[3];
	uint16_t fs, _pad5[3];
	uint16_t gs, _pad6[3];
} __attribute__((packed));

struct xen_trap_info {
	uint8_t  vector;
	uint8_t  flags;	   /* 0-3: privilege level; 4: clear event enable? */
	uint16_t cs;
	uint32_t _pad1;
	uint64_t address;
} __attribute__((packed));

struct xen_vcpu_guest_context {
	struct { char x[512]; } fpu_ctxt;   /* User-level FPU registers     */
	uint64_t flags;			    /* VGCF_* flags                 */
	struct xen_cpu_user_regs user_regs; /* User-level CPU registers     */
	struct xen_trap_info trap_ctxt[256]; /* Virtual IDT                  */
	uint64_t ldt_base, ldt_ents;	    /* LDT (linear address, # ents) */
	uint64_t gdt_frames[16], gdt_ents;  /* GDT (machine frames, # ents) */
	uint64_t kernel_ss, kernel_sp;	    /* Virtual TSS (only SS1/SP1)   */
	uint64_t ctrlreg[8];		    /* CR0-CR7 (control registers)  */
	uint64_t debugreg[8];		    /* DB0-DB7 (debug registers)    */
	uint64_t event_callback_eip;
	uint64_t failsafe_callback_eip;
	uint64_t syscall_callback_eip;
	uint64_t vm_assist;		    /* VMASST_TYPE_* bitmap */
	/* Segment base addresses. */
	uint64_t fs_base;
	uint64_t gs_base_kernel;
	uint64_t gs_base_user;
} __attribute__ ((packed));

/** @endcond */

static const struct attr_template reg_names[] = {
#define REG(name)	{ #name, NULL, kdump_number }
	REG(r15),		/*  0 */
	REG(r14),		/*  1 */
	REG(r13),		/*  2 */
	REG(r12),		/*  3 */
	REG(rbp),		/*  4 */
	REG(rbx),		/*  5 */
	REG(r11),		/*  6 */
	REG(r10),		/*  7 */
	REG(r9),		/*  8 */
	REG(r8),		/*  9 */
	REG(rax),		/* 10 */
	REG(rcx),		/* 11 */
	REG(rdx),		/* 12 */
	REG(rsi),		/* 13 */
	REG(rdi),		/* 14 */
	REG(orig_rax),		/* 15 */
	REG(rip),		/* 16 */
	REG(cs),		/* 17 */
	REG(rflags),		/* 18 */
	REG(rsp),		/* 19 */
	REG(ss),		/* 20 */
	REG(fs_base),		/* 21 */
	REG(gs_base),		/* 22 */
	REG(ds),		/* 23 */
	REG(es),		/* 24 */
	REG(fs),		/* 25 */
	REG(gs),		/* 26 */
	REG(cr0),		/* 27 */
	REG(cr1),		/* 28 */
	REG(cr2),		/* 29 */
	REG(cr3),		/* 30 */
	REG(cr4),		/* 31 */
	REG(cr5),		/* 32 */
	REG(cr6),		/* 33 */
	REG(cr7),		/* 34 */
	REG(dr0),		/* 35 */
	REG(dr1),		/* 36 */
	REG(dr2),		/* 37 */
	REG(dr3),		/* 38 */
	REG(dr4),		/* 39 */
	REG(dr5),		/* 40 */
	REG(dr6),		/* 41 */
	REG(dr7),		/* 42 */
};

static const struct attr_template tmpl_pid =
	{ "pid", NULL, kdump_number };

static kdump_status
add_canonical_regions(kdump_ctx *ctx, struct vtop_map *map)
{
	kdump_status res;

	res = set_vtop_xlat_pgt(map, 0, NONCANONICAL_START - 1);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot set up default  mapping");

	res = set_vtop_xlat_pgt(map, NONCANONICAL_END + 1, VIRTADDR_MAX);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot set up default  mapping");

	return res;
}

/** Set the kernel text virtual to physical offset.
 * @param archdata   x86-64 arch-specific data.
 * @param phys_base  Kernel physical base address.
 */
static void
set_ktext_off(struct x86_64_data *archdata, kdump_addr_t phys_base)
{
	addrxlat_meth_set_offset(archdata->ktext,
				 __START_KERNEL_map - phys_base);
}

/** Update the physical base offfset.
 * @param ctx   Dump file object.
 * @param attr  "linux.phys_base" attribute.
 * @returns     Error status.
 *
 * This function is used as a post-set handler for @c linux.phys_base
 * to update the total kernel text offset.
 */
static kdump_status
update_phys_base(kdump_ctx *ctx, struct attr_data *attr)
{
	struct x86_64_data *archdata = ctx->shared->archdata;
	const struct attr_ops *parent_ops;

	set_ktext_off(archdata, attr_value(attr)->address);

	parent_ops = archdata->phys_base_override.template.parent->ops;
	return (parent_ops && parent_ops->post_set)
		? parent_ops->post_set(ctx, attr)
		: kdump_ok;
}

static const addrxlat_paging_form_t x86_64_pf = {
	.pte_format = addrxlat_pte_x86_64,
	.levels = 5,
	.bits = { 12, 9, 9, 9, 9 }
};

static kdump_status
x86_64_init(kdump_ctx *ctx)
{
	struct x86_64_data *archdata;
	addrxlat_status axres;
	kdump_status ret;

	axres = addrxlat_meth_set_form(ctx->shared->vtop_map.pgt, &x86_64_pf);
	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	archdata = calloc(1, sizeof(struct x86_64_data));
	if (!archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate x86_64 private data");
	ctx->shared->archdata = archdata;

	archdata->ktext = addrxlat_meth_new();
	if (!archdata->ktext) {
		ret = set_error(ctx, kdump_syserr,
				"Cannot allocate kernel text mapping");
		goto err_arch;
	}
	set_ktext_off(archdata, get_phys_base(ctx));

	ret = set_vtop_xlat(&ctx->shared->vtop_map,
			    __START_KERNEL_map, VIRTADDR_MAX,
			    archdata->ktext);
	if (ret != kdump_ok) {
		set_error(ctx, ret,
			  "Cannot set up initial kernel mapping");
		goto err_ktext;
	}

	attr_add_override(gattr(ctx, GKI_phys_base),
			  &archdata->phys_base_override);
	archdata->phys_base_override.ops.post_set = update_phys_base;

	return kdump_ok;

 err_ktext:
	addrxlat_meth_decref(archdata->ktext);

 err_arch:
	free(archdata);
	ctx->shared->archdata = NULL;
	return ret;
}

static kdump_status
get_pml4(kdump_ctx *ctx)
{
	addrxlat_fulladdr_t pgtroot;
	kdump_status ret;

	rwlock_unlock(&ctx->shared->lock);
	ret = get_symbol_val(ctx, "init_level4_pgt", &pgtroot.addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (ret == kdump_ok) {
		if (pgtroot.addr < __START_KERNEL_map)
			return set_error(ctx, kdump_dataerr,
					 "Wrong page directory address:"
					 " 0x%"ADDRXLAT_PRIXADDR,
					 pgtroot.addr);

		pgtroot.as = ADDRXLAT_KPHYSADDR;
		pgtroot.addr -= __START_KERNEL_map - get_phys_base(ctx);
	} else if (ret == kdump_nodata) {
		struct attr_data *attr;
		clear_error(ctx);
		attr = lookup_attr(ctx->shared, "cpu.0.reg.cr3");
		if (!attr || validate_attr(ctx, attr) != kdump_ok)
			return set_error(ctx, kdump_nodata,
					 "Cannot find top-level page table");
		pgtroot.as = ADDRXLAT_MACHPHYSADDR;
		pgtroot.addr = attr_value(attr)->number;
	} else
		return ret;

	addrxlat_meth_set_root(ctx->shared->vtop_map.pgt, &pgtroot);
	return kdump_ok;
}

static const struct layout_def*
layout_by_version(unsigned version_code)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(mm_layouts); ++i)
		if (mm_layouts[i].ver > version_code)
			break;
	if (!i)
		return NULL;
	return &mm_layouts[i-1];
}

static const struct layout_def*
layout_by_pgt(kdump_ctx *ctx)
{
	kdump_paddr_t paddr;
	kdump_status ret;

	/* Only pre-2.6.11 kernels had this direct mapping */
	ret = vtop_pgt(ctx, 0x0000010000000000, &paddr);
	if (ret == kdump_ok && paddr == 0)
		return layout_by_version(KERNEL_VERSION(2, 6, 0));
	if (ret != kdump_addrxlat)
		return NULL;

	/* Only kernels between 2.6.11 and 2.6.27 had this direct mapping */
	ret = vtop_pgt(ctx, 0xffff810000000000, &paddr);
	if (ret == kdump_ok && paddr == 0)
		return layout_by_version(KERNEL_VERSION(2, 6, 11));
	if (ret != kdump_addrxlat)
		return NULL;

	/* Only 2.6.31+ kernels map VMEMMAP at this address */
	ret = vtop_pgt(ctx, 0xffffea0000000000, &paddr);
	if (ret == kdump_ok)
		return layout_by_version(KERNEL_VERSION(2, 6, 31));
	if (ret != kdump_addrxlat)
		return NULL;

	/* Sanity check for 2.6.27+ direct mapping */
	ret = vtop_pgt(ctx, 0xffff880000000000, &paddr);
	if (ret == kdump_ok && paddr == 0)
		return layout_by_version(KERNEL_VERSION(2, 6, 27));
	if (ret != kdump_addrxlat)
		return NULL;

	return NULL;
}

static void
remove_ktext_xlat(kdump_ctx *ctx, struct vtop_map *map)
{
	struct x86_64_data *archdata = ctx->shared->archdata;
	addrxlat_range_t *rng;
	for (rng = map->map->ranges;
	     rng < &map->map->ranges[map->map->n]; ++rng)
		if (rng->meth == archdata->ktext)
			rng->meth = map->pgt;
}

static kdump_status
x86_64_vtop_init(kdump_ctx *ctx)
{
	struct x86_64_data *archdata = ctx->shared->archdata;
	const struct layout_def *layout = NULL;
	unsigned i;
	kdump_status ret;

	ret = get_pml4(ctx);
	if (ret == kdump_ok)
		layout = layout_by_pgt(ctx);
	else if (ret != kdump_nodata)
		return ret;

	if (!layout)
		layout = layout_by_version(get_version_code(ctx));
	if (!layout)
		return set_error(ctx, kdump_nodata,
				 "Cannot determine virtual memory layout");

	if (!archdata->directmap)
		archdata->directmap = addrxlat_meth_new();
	if (!archdata->directmap)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate directmap");

	flush_vtop_map(&ctx->shared->vtop_map);
	ret = add_canonical_regions(ctx, &ctx->shared->vtop_map);
	if (ret != kdump_ok)
		return ret;

	for (i = 0; i < layout->nregions; ++i) {
		const struct region_def *def = &layout->regions[i];
		addrxlat_meth_t *xlat = NULL;

		switch (def->xlat) {
		case PGT:
			xlat = ctx->shared->vtop_map.pgt;
			break;
		case DIRECTMAP:
			xlat = archdata->directmap;
			addrxlat_meth_set_offset(archdata->directmap,
						 def->first);
			break;
		case KTEXT:
			xlat = archdata->ktext;
			break;
		}

		ret = set_vtop_xlat(&ctx->shared->vtop_map,
				    def->first, def->last, xlat);
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot set up mapping #%d", i);
	}

	if (!isset_phys_base(ctx)) {
		kdump_paddr_t phys_base;
		ret = vtop_pgt(ctx, __START_KERNEL_map + KERNEL_map_skip,
			       &phys_base);
		if (ret == kdump_nodata) {
			clear_error(ctx);
			remove_ktext_xlat(ctx, &ctx->shared->vtop_map);
		} else if (ret == kdump_ok)
			set_phys_base(ctx, phys_base - KERNEL_map_skip);
		else
			return set_error(ctx, ret,
					 "Error getting phys_base");
	}

	return kdump_ok;
}

static kdump_status
x86_64_vtop_init_xen(kdump_ctx *ctx)
{
	struct x86_64_data *archdata = ctx->shared->archdata;
	addrxlat_fulladdr_t pgtroot;
	addrxlat_status axres;
	kdump_status res;

	axres = addrxlat_meth_set_form(
		ctx->shared->vtop_map_xen.pgt, &x86_64_pf);
	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	res = add_canonical_regions(ctx, &ctx->shared->vtop_map_xen);
	if (res != kdump_ok)
		return res;

	rwlock_unlock(&ctx->shared->lock);
	res = get_symbol_val_xen(ctx, "pgd_l4", &pgtroot.addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (res != kdump_ok)
		return res;

	if (!archdata->xen_directmap)
		archdata->xen_directmap = addrxlat_meth_new();
	if (!archdata->xen_directmap)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate Xen directmap");

	if (pgtroot.addr >= XEN_DIRECTMAP_START) {
		/* Xen versions before 3.2.0 */
		addrxlat_meth_set_offset(archdata->xen_directmap,
					 XEN_DIRECTMAP_START);
		res = set_vtop_xlat(
			&ctx->shared->vtop_map_xen,
			XEN_DIRECTMAP_START, XEN_DIRECTMAP_END_OLD,
			archdata->xen_directmap);
	} else {
		kdump_vaddr_t xen_virt_start;
		xen_virt_start = pgtroot.addr & ~((1ULL<<30) - 1);
		addrxlat_meth_set_offset(archdata->xen_directmap,
					 xen_virt_start);
		res = set_vtop_xlat(
			&ctx->shared->vtop_map_xen,
			xen_virt_start,	xen_virt_start + XEN_VIRT_SIZE - 1,
			archdata->xen_directmap);
	}
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot set up initial kernel mapping");

	pgtroot.as = ADDRXLAT_XENVADDR;
	addrxlat_meth_set_root(ctx->shared->vtop_map_xen.pgt, &pgtroot);
	return kdump_ok;
}

static kdump_status
process_x86_64_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	char cpukey[sizeof("cpu.") + 20];
	struct attr_data *dir, *attr;
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, kdump_dataerr,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs64(ctx, get_num_cpus(ctx), reg_names,
			     status->pr_reg, ELF_NGREG);
	if (res != kdump_ok)
		return res;

	sprintf(cpukey, "cpu.%u", get_num_cpus(ctx));
	dir = lookup_attr(ctx->shared, cpukey);
	if (!dir)
		return set_error(ctx, kdump_nokey,
				 "'%s': %s", cpukey, "No such key");
	attr = new_attr(ctx->shared, dir, &tmpl_pid);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate '%s'", cpukey);
	res = set_attr_number(ctx, attr, ATTR_DEFAULT,
			      dump32toh(ctx, status->pr_pid));
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot set '%s'", cpukey);

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);
	return kdump_ok;
}

#define xen_reg_idx(field) \
	(offsetof(struct xen_cpu_user_regs, field) / sizeof(uint64_t))
#define xen_reg_cnt(start, end) \
	(xen_reg_idx(end) - xen_reg_idx(start) + 1)

static kdump_status
process_x86_64_xen_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	unsigned cpu = 0;
	kdump_status res;

	while (size >= sizeof(struct xen_vcpu_guest_context)) {
		struct xen_vcpu_guest_context *vgc = data;
		struct xen_cpu_user_regs *regs = &vgc->user_regs;
		uint16_t *p;

		/* zero out padding */
		for (p = &regs->cs; p <= &regs->gs; p += 4)
			p[1] = p[2] = p[3] = 0;

		res = set_cpu_regs64(ctx, cpu, &reg_names[0], &regs->r15,
				     xen_reg_cnt(r15, rdi));
		if (res != kdump_ok)
			return res;

		res = set_cpu_regs64(ctx, cpu, &reg_names[16], &regs->rip,
				     xen_reg_cnt(cs, gs));
		if (res != kdump_ok)
			return res;

		res = set_cpu_regs64(ctx, cpu, &reg_names[27],
				     vgc->ctrlreg, 16);
		if (res != kdump_ok)
			return res;

		++cpu;
		data += sizeof(struct xen_vcpu_guest_context);
		size -= sizeof(struct xen_vcpu_guest_context);
	}

	if (!isset_num_cpus(ctx) || cpu > get_num_cpus(ctx))
		set_num_cpus(ctx, cpu);

	return kdump_ok;
}

static kdump_status
x86_64_process_load(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t paddr)
{
	if (!isset_phys_base(ctx) &&
	    vaddr >= __START_KERNEL_map &&
	    vaddr < __START_KERNEL_map + MAX_PHYSICAL_START)
		set_phys_base(ctx, paddr - (vaddr - __START_KERNEL_map));
	return kdump_ok;
}

static void
x86_64_cleanup(struct kdump_shared *shared)
{
	struct x86_64_data *archdata = shared->archdata;

	if (!archdata)
		return;

	attr_remove_override(sgattr(shared, GKI_phys_base),
			     &archdata->phys_base_override);
	if (archdata->directmap)
		addrxlat_meth_decref(archdata->directmap);
	if (archdata->ktext)
		addrxlat_meth_decref(archdata->ktext);
	if (archdata->xen_directmap)
		addrxlat_meth_decref(archdata->xen_directmap);
	free(archdata);
	shared->archdata = NULL;
}

static kdump_status
read_pfn(kdump_ctx *ctx, kdump_maddr_t maddr, kdump_pfn_t *pval)
{
	uint64_t val;
	size_t sz;
	kdump_status res;

	sz = sizeof val;
	res = readp_locked(ctx, KDUMP_MACHPHYSADDR, maddr, &val, &sz);
	if (res == kdump_ok)
		*pval = dump64toh(ctx, val);
	return res;
}

static kdump_status
x86_64_pfn_to_mfn(kdump_ctx *ctx, kdump_pfn_t pfn, kdump_pfn_t *mfn)
{
	const struct attr_data *attr;
	kdump_pfn_t mfn_tbl;
	kdump_maddr_t maddr;
	uint64_t idx, l2_idx, l3_idx;
	kdump_status res;

	attr = gattr(ctx, GKI_xen_p2m_mfn);
	if (!attr_isset(attr))
		return kdump_nodata;
	mfn_tbl = attr_value(attr)->address;

	idx = pfn;
	l3_idx = idx % PTRS_PER_PAGE;
	idx /= PTRS_PER_PAGE;
	l2_idx = idx % PTRS_PER_PAGE;
	idx /= PTRS_PER_PAGE;
	if (idx >= PTRS_PER_PAGE)
		return set_error(ctx, kdump_invalid, "Out-of-bounds PFN");

	maddr = (mfn_tbl << get_page_shift(ctx)) + idx * sizeof(uint64_t);
	res = read_pfn(ctx, maddr, &mfn_tbl);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot read p2m L1 table at 0x%llx",
				 (unsigned long long) maddr);

	maddr = (mfn_tbl << get_page_shift(ctx)) + l2_idx * sizeof(uint64_t);
	res = read_pfn(ctx, maddr, &mfn_tbl);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot read p2m L2 table at 0x%llx",
				 (unsigned long long) maddr);

	maddr = (mfn_tbl << get_page_shift(ctx)) + l3_idx * sizeof(uint64_t);
	res = read_pfn(ctx, maddr, mfn);
	return set_error(ctx, res,
			 "Cannot read p2m L3 table at 0x%llx",
			 (unsigned long long) maddr);
}

static kdump_status
x86_64_mfn_to_pfn(kdump_ctx *ctx, kdump_pfn_t mfn, kdump_pfn_t *pfn)
{
	kdump_vaddr_t addr;
	uint64_t tmp;
	size_t sz;
	kdump_status ret;

	addr = MACH2PHYS_VIRT_START + sizeof(uint64_t) * mfn;
	sz = sizeof tmp;
	ret = readp_locked(ctx, KDUMP_KVADDR, addr, &tmp, &sz);
	if (ret == kdump_ok)
		*pfn = tmp;

	return ret;
}

const struct arch_ops x86_64_ops = {
	.init = x86_64_init,
	.vtop_init = x86_64_vtop_init,
	.vtop_init_xen = x86_64_vtop_init_xen,
	.process_prstatus = process_x86_64_prstatus,
	.process_load = x86_64_process_load,
	.process_xen_prstatus = process_x86_64_xen_prstatus,
	.pfn_to_mfn = x86_64_pfn_to_mfn,
	.mfn_to_pfn = x86_64_mfn_to_pfn,
	.cleanup = x86_64_cleanup,
};
