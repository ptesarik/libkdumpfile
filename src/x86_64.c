/* Functions for the x86-64 architecture.
   Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

/* Maximum physical addrss bits (architectural limit) */
#define PHYSADDR_BITS_MAX	52
#define PHYSADDR_SIZE		((uint64_t)1 << PHYSADDR_BITS_MAX)
#define PHYSADDR_MASK		(~(PHYSADDR_SIZE-1))

#define PGDIR_SHIFT	39

#define PUD_SHIFT	30
#define PUD_PSE_SIZE	((uint64_t)1 << PUD_SHIFT)
#define PUD_PSE_MASK	(~(PUD_PSE_SIZE-1))

#define PMD_SHIFT	21
#define PMD_PSE_SIZE	((uint64_t)1 << PMD_SHIFT)
#define PMD_PSE_MASK	(~(PMD_PSE_SIZE-1))

#define PAGE_SHIFT	12
#define PAGE_SIZE	((uint64_t)1 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

#define PTRS_PER_PAGE	(PAGE_SIZE/sizeof(uint64_t))

#define pgd_index(addr)	(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PAGE - 1))
#define pud_index(addr)	(((addr) >> PUD_SHIFT) & (PTRS_PER_PAGE - 1))
#define pmd_index(addr)	(((addr) >> PMD_SHIFT) & (PTRS_PER_PAGE - 1))
#define pte_index(addr)	(((addr) >> PAGE_SHIFT) & (PTRS_PER_PAGE - 1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

#define __START_KERNEL_map	0xffffffff80000000ULL

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

struct region_def {
	kdump_vaddr_t first, last;
	kdump_xlat_t xlat;
	kdump_vaddr_t phys_off;
};

/* Original layout (before 2.6.11) */
static const struct region_def mm_layout_2_6_0[] = {
	{  0x0000000000000000,  0x0000007fffffffff, /* user space       */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0x0000008000000000 - 0x000000ffffffffff     guard hole       */
	{  0x0000010000000000,  0x000001ffffffffff, /* direct mapping   */
	   KDUMP_XLAT_DIRECT,   0x0000010000000000 },
	/* 0x0000020000000000 - 0x00007fffffffffff     unused hole      */
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xfffffeffffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* vmalloc/ioremap  */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0xffffff8000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KDUMP_XLAT_KTEXT,    0xffffffff80000000 },
	/* 0xffffffff82800000 - 0xffffffff9fffffff     unused hole      */
	{  0xffffffffa0000000,  0xffffffffafffffff, /* modules          */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0xffffffffb0000000 - 0xffffffffff5exxxx     unused hole      */
	{  0xffffffffff5ed000,  0xffffffffffdfffff, /* fixmap/vsyscalls */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

/* New layout introduced in 2.6.11 */
static const struct region_def mm_layout_2_6_11[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	{  0xffff810000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   KDUMP_XLAT_DIRECT,   0xffff810000000000 },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   KDUMP_XLAT_VTOP,     0 },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   KDUMP_XLAT_VTOP,     0 },		    /*   (2.6.24+ only) */
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KDUMP_XLAT_KTEXT,    0xffffffff80000000 },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   KDUMP_XLAT_VTOP,     0 },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

static const struct region_def mm_layout_2_6_27[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc0ffffffffff, /* direct mapping   */
	   KDUMP_XLAT_DIRECT,   0xffff880000000000 },
	/* 0xffffc10000000000 - 0xffffc1ffffffffff     guard hole       */
	{  0xffffc20000000000,  0xffffe1ffffffffff, /* vmalloc/ioremap  */
	   KDUMP_XLAT_VTOP,     0 },
	{  0xffffe20000000000,  0xffffe2ffffffffff, /* VMEMMAP          */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0xffffe30000000000 - 0xffffffff7fffffff     unused hole      */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KDUMP_XLAT_KTEXT,    0xffffffff80000000 },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   KDUMP_XLAT_VTOP,     0 },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

static const struct region_def mm_layout_2_6_31[] = {
	{  0x0000000000000000,  0x00007fffffffffff, /* user space       */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0x0000800000000000 - 0xffff7fffffffffff     non-canonical    */
	/* 0xffff800000000000 - 0xffff80ffffffffff     guard hole       */
	/* 0xffff810000000000 - 0xffff87ffffffffff     hypervisor area  */
	{  0xffff880000000000,  0xffffc7ffffffffff, /* direct mapping   */
	   KDUMP_XLAT_DIRECT,   0xffff880000000000 },
	/* 0xffffc80000000000 - 0xffffc8ffffffffff     guard hole       */
	{  0xffffc90000000000,  0xffffe8ffffffffff, /* vmalloc/ioremap  */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0xffffe90000000000 - 0xffffe9ffffffffff     guard hole       */
	{  0xffffea0000000000,  0xffffeaffffffffff, /* VMEMMAP          */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0xffffeb0000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffff0000000000,  0xffffff7fffffffff, /* %esp fixup stack */
	   KDUMP_XLAT_VTOP,     0 },
	/* 0xffffff8000000000 - 0xffffffeeffffffff     unused hole      */
	{  0xffffffef00000000,  0xfffffffeffffffff, /* EFI runtime      */
	   KDUMP_XLAT_VTOP,     0 },		    /*     (3.14+ only) */
	/* 0xffffffff00000000 - 0xffffffff7fffffff     guard hole       */
	{  0xffffffff80000000,  0xffffffff827fffff, /* kernel text      */
	   KDUMP_XLAT_KTEXT,    0xffffffff80000000 },
	/* 0xffffffff82800000 - 0xffffffff87ffffff     unused hole      */
	{  0xffffffff88000000,  0xffffffffffdfffff, /* modules and      */
	   KDUMP_XLAT_VTOP,     0 },		    /*  fixmap/vsyscall */
	/* 0xffffffffffe00000 - 0xffffffffffffffff     guard hole       */
};

#define LAYOUT_NAME(a, b, c)	mm_layout_ ## a ## _ ## b ## _ ## c
#define DEF_LAYOUT(a, b, c) \
	{ KERNEL_VERSION(a, b, c), LAYOUT_NAME(a, b, c),	\
			ARRAY_SIZE(LAYOUT_NAME(a, b, c)) }

static struct layout_def {
	unsigned ver;
	const struct region_def *regions;
	unsigned nregions;
} mm_layouts[] = {
	DEF_LAYOUT(2, 6, 0),
	DEF_LAYOUT(2, 6, 11),
	DEF_LAYOUT(2, 6, 27),
	DEF_LAYOUT(2, 6, 31),
};

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

struct x86_64_data {
	uint64_t *pgt;
};

static kdump_status x86_64_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr,
				kdump_paddr_t *paddr);

static kdump_status
add_noncanonical_region(kdump_ctx *ctx)
{
	return set_region(ctx, NONCANONICAL_START, NONCANONICAL_END,
			  KDUMP_XLAT_INVALID, 0);
}

static kdump_status
x86_64_init(kdump_ctx *ctx)
{
	kdump_status ret;

	ctx->archdata = calloc(1, sizeof(struct x86_64_data));
	if (!ctx->archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate x86_64 private data");

	ret = add_noncanonical_region(ctx);
	if (ret != kdump_ok)
		return ret;

	ret = set_region(ctx, __START_KERNEL_map, VIRTADDR_MAX,
			 KDUMP_XLAT_KTEXT, __START_KERNEL_map);
	if (ret != kdump_ok)
		return ret;

	return kdump_ok;
}

static kdump_status
read_pgt(kdump_ctx *ctx)
{
	struct x86_64_data *archdata = ctx->archdata;
	kdump_vaddr_t pgtaddr;
	uint64_t *pgt;
	long rdflags;
	kdump_status ret;
	size_t sz;

	ret = get_symbol_val(ctx, "init_level4_pgt", &pgtaddr);
	if (ret == kdump_ok) {
		if (pgtaddr < __START_KERNEL_map)
			return set_error(ctx, kdump_dataerr,
					 "Wrong page directory address: 0x%llx",
					 (unsigned long long) pgtaddr);

		pgtaddr -= __START_KERNEL_map - get_attr_phys_base(ctx);
		rdflags = KDUMP_PHYSADDR;
	} else if (ret == kdump_nodata) {
		const struct attr_data *attr;
		attr = lookup_attr(ctx, "cpu.0.reg.cr3");
		if (!attr)
			return set_error(ctx, kdump_nodata,
					 "Cannot get CR3 value");
		pgtaddr = attr->val.number;
		rdflags = (get_attr_xen_type(ctx) == kdump_xen_pv)
			? KDUMP_XENMACHADDR
			: KDUMP_PHYSADDR;
	} else
		return ret;


	pgt = ctx_malloc(PAGE_SIZE, ctx, "page table");
	if (!pgt)
		return kdump_syserr;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, pgtaddr, pgt, &sz, rdflags);
	if (ret == kdump_ok)
		archdata->pgt = pgt;
	else
		free(pgt);

	return ret;
}

static struct layout_def*
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

static struct layout_def*
layout_by_pgt(kdump_ctx *ctx)
{
	kdump_paddr_t paddr;
	kdump_status ret;

	/* Only pre-2.6.11 kernels had this direct mapping */
	ret = x86_64_vtop(ctx, 0x0000010000000000, &paddr);
	if (ret == kdump_ok && paddr == 0)
		return layout_by_version(KERNEL_VERSION(2, 6, 0));
	if (ret != kdump_nodata)
		return NULL;

	/* Only kernels between 2.6.11 and 2.6.27 had this direct mapping */
	ret = x86_64_vtop(ctx, 0xffff810000000000, &paddr);
	if (ret == kdump_ok && paddr == 0)
		return layout_by_version(KERNEL_VERSION(2, 6, 11));
	if (ret != kdump_nodata)
		return NULL;

	/* Only 2.6.31+ kernels map VMEMMAP at this address */
	ret = x86_64_vtop(ctx, 0xffffea0000000000, &paddr);
	if (ret == kdump_ok)
		return layout_by_version(KERNEL_VERSION(2, 6, 31));
	if (ret != kdump_nodata)
		return NULL;

	/* Sanity check for 2.6.27+ direct mapping */
	ret = x86_64_vtop(ctx, 0xffff880000000000, &paddr);
	if (ret == kdump_ok && paddr == 0)
		return layout_by_version(KERNEL_VERSION(2, 6, 27));
	if (ret != kdump_nodata)
		return NULL;

	return NULL;
}

static kdump_status
x86_64_vtop_init(kdump_ctx *ctx)
{
	struct layout_def *layout = NULL;
	unsigned i;
	kdump_status ret;

	ret = read_pgt(ctx);
	if (ret == kdump_ok)
		layout = layout_by_pgt(ctx);
	else if (ret != kdump_nodata)
		return ret;

	if (!layout)
		layout = layout_by_version(get_attr_version_code(ctx));
	if (!layout)
		return set_error(ctx, kdump_nodata,
				 "Cannot determine virtual memory layout");

	flush_regions(ctx);
	ret = add_noncanonical_region(ctx);
	if (ret != kdump_ok)
		return ret;

	for (i = 0; i < layout->nregions; ++i) {
		const struct region_def *def = &layout->regions[i];
		ret = set_region(ctx, def->first, def->last,
				 def->xlat, def->phys_off);
		if (ret != kdump_ok)
			return ret;
	}

	return kdump_ok;
}

static kdump_status
process_x86_64_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	char cpukey[sizeof("cpu.") + 20 + sizeof(".reg")];
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, kdump_dataerr,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs64(ctx, get_attr_num_cpus(ctx), reg_names,
			     status->pr_reg, ELF_NGREG);
	if (res != kdump_ok)
		return res;

	sprintf(cpukey, "cpu.%u", get_attr_num_cpus(ctx));
	res = add_attr_number(ctx, cpukey, &tmpl_pid,
			      dump32toh(ctx, status->pr_pid));
	if (res != kdump_ok)
		return res;

	set_attr_num_cpus(ctx, get_attr_num_cpus(ctx) + 1);
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

	if (!static_attr_isset(&ctx->num_cpus) || cpu > get_attr_num_cpus(ctx))
		set_attr_num_cpus(ctx, cpu);

	return kdump_ok;
}

static const char *
x86_64_reg_name(unsigned index)
{
	return index < ARRAY_SIZE(reg_names)
		? reg_names[index].key
		: NULL;
}

static kdump_status
x86_64_process_load(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t paddr)
{
	if (!static_attr_isset(&ctx->phys_base) &&
	    vaddr >= __START_KERNEL_map &&
	    vaddr < __START_KERNEL_map + MAX_PHYSICAL_START)
		set_attr_phys_base(ctx, paddr - (vaddr - __START_KERNEL_map));
	return kdump_ok;
}

static void
x86_64_cleanup(kdump_ctx *ctx)
{
	struct x86_64_data *archdata = ctx->archdata;

	if (archdata->pgt)
		free(archdata->pgt);

	free(archdata);
	ctx->archdata = NULL;
}

static kdump_status
x86_64_pt_walk(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr,
	       int rdflags)
{
	struct x86_64_data *archdata = ctx->archdata;
	uint64_t tbl[PTRS_PER_PAGE];
	uint64_t pgd, pud, pmd, pte;
	kdump_paddr_t base;
	size_t sz;
	kdump_status ret;

	if (!archdata->pgt)
		return set_error(ctx, kdump_invalid,
				 "VTOP translation not initialized");

	pgd = archdata->pgt[pgd_index(vaddr)];
	if (!(pgd & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page directory pointer not present:"
				 " pgd[%u] = 0x%llx",
				 (unsigned) pgd_index(vaddr),
				 (unsigned long long) pgd);
	base = pgd & ~PHYSADDR_MASK & PAGE_MASK;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, rdflags);
	if (ret != kdump_ok)
		return ret;

	pud = tbl[pud_index(vaddr)];
	if (!(pud & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page directory not present:"
				 " pud[%u] = 0x%llx",
				 (unsigned) pud_index(vaddr),
				 (unsigned long long) pud);
	if (pud & _PAGE_PSE) {
		base = pud & ~PHYSADDR_MASK & PUD_PSE_MASK;
		*paddr = base + (vaddr & ~PUD_PSE_MASK);
		return kdump_ok;
	}
	base = pud & ~PHYSADDR_MASK & PAGE_MASK;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, rdflags);
	if (ret != kdump_ok)
		return ret;

	pmd = tbl[pmd_index(vaddr)];
	if (!(pmd & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page table not present: pmd[%u] = 0x%llx",
				 (unsigned) pmd_index(vaddr),
				 (unsigned long long) pmd);
	if (pmd & _PAGE_PSE) {
		base = pmd & ~PHYSADDR_MASK & PMD_PSE_MASK;
		*paddr = base + (vaddr & ~PMD_PSE_MASK);
		return kdump_ok;
	}
	base = pmd & ~PHYSADDR_MASK & PAGE_MASK;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, rdflags);
	if (ret != kdump_ok)
		return ret;

	pte = tbl[pte_index(vaddr)];
	if (!(pte & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page not present: pte[%u] = 0x%llx",
				 (unsigned) pte_index(vaddr),
				 (unsigned long long) pte);
	base = pte & ~PHYSADDR_MASK & PAGE_MASK;
	*paddr = base + (vaddr & ~PAGE_MASK);

	return kdump_ok;
}

static kdump_status
x86_64_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	kdump_status ret;

	if (get_attr_xen_type(ctx) == kdump_xen_pv) {
		kdump_addr_t maddr;
		kdump_pfn_t mfn, pfn;

		if (!ctx->ops->mfn_to_pfn)
			return set_error(ctx, kdump_nodata,
					 "No MFN-to-PFN translation method");

		ret = x86_64_pt_walk(ctx, vaddr, &maddr, KDUMP_XENMACHADDR);
		if (ret != kdump_ok)
			return ret;

		mfn = maddr >> get_attr_page_shift(ctx);
		ret = ctx->ops->mfn_to_pfn(ctx, mfn, &pfn);
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot translate MFN 0x%llx",
					 (unsigned long long) mfn);

		*paddr = (pfn << get_attr_page_shift(ctx)) |
			(maddr & (get_attr_page_size(ctx) - 1));
		return kdump_ok;
	}

	return x86_64_pt_walk(ctx, vaddr, paddr, KDUMP_PHYSADDR);
}

const struct arch_ops x86_64_ops = {
	.init = x86_64_init,
	.vtop_init = x86_64_vtop_init,
	.process_prstatus = process_x86_64_prstatus,
	.reg_name = x86_64_reg_name,
	.process_load = x86_64_process_load,
	.process_xen_prstatus = process_x86_64_xen_prstatus,
	.vtop = x86_64_vtop,
	.cleanup = x86_64_cleanup,
};
