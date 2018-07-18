/** @internal @file src/kdumpfile/x86_64.c
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

#define __START_KERNEL_map	0xffffffff80000000ULL

/** Minimum Linux kernel text alignment. */
#define LINUX_TEXT_ALIGN	0x200000ULL

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
#define REG(name)	{ #name, NULL, KDUMP_NUMBER }
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

	REG(pid),		/* 43 */
};

static kdump_status
calc_linux_phys_base(kdump_ctx_t *ctx, kdump_paddr_t paddr)
{
	kdump_addr_t stext;
	kdump_status status;

	rwlock_unlock(&ctx->shared->lock);
	status = get_symbol_val(ctx, "_stext", &stext);
	if (status == KDUMP_ERR_NODATA) {
		clear_error(ctx);
		status = get_symbol_val(ctx, "_text", &stext);
	}
	rwlock_rdlock(&ctx->shared->lock);

	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot get kernel text start address");
	stext &= -(kdump_addr_t)LINUX_TEXT_ALIGN;
	set_phys_base(ctx, paddr - (stext - __START_KERNEL_map));
	return KDUMP_OK;
}

static kdump_status
set_linux_phys_base(kdump_ctx_t *ctx)
{
	kdump_paddr_t paddr;

	if (ctx->shared->ops == &devmem_ops) {
		kdump_status status = linux_iomem_kcode(ctx, &paddr);
		if (status == KDUMP_OK)
			status = calc_linux_phys_base(ctx, paddr);
		if (status != KDUMP_ERR_NODATA)
			return status;
		clear_error(ctx);
	}

	if (isset_xen_type(ctx) &&
	    get_xen_type(ctx) != KDUMP_XEN_NONE)
		return set_phys_base(ctx, 0);

	return KDUMP_ERR_NODATA;
}

static kdump_status
init_linux_phys_base(kdump_ctx_t *ctx)
{
	const addrxlat_meth_t *meth;
	kdump_status status;

	status = revalidate_xlat(ctx);
	if (status != KDUMP_OK)
		return status;

	meth = addrxlat_sys_get_meth(
		ctx->xlat->xlatsys, ADDRXLAT_SYS_METH_KTEXT);
	if (meth->kind == ADDRXLAT_LINEAR) {
		set_phys_base(ctx, meth->param.linear.off + __START_KERNEL_map);
		return KDUMP_OK;
	}

	status = set_linux_phys_base(ctx);
	if (status == KDUMP_ERR_NODATA) {
		/* ignore missing data */
		clear_error(ctx);
		return KDUMP_OK;
	}

	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot initialize address translation");

	return KDUMP_OK;
}

static kdump_status
x86_64_late_init(kdump_ctx_t *ctx)
{
	kdump_status status;

	if (ctx->xlat->ostype == ADDRXLAT_OS_LINUX &&
	    !isset_phys_base(ctx)) {
		status = init_linux_phys_base(ctx);
		if (status != KDUMP_OK)
			return status;
	}

	return KDUMP_OK;
}

#define REG_CNT(start, end)				\
	((offsetof(struct elf_prstatus, end)		\
	  - offsetof(struct elf_prstatus, start))	\
	 / sizeof(((struct elf_prstatus*)0)->start)	\
	 + 1)

#define REG_DEF(bits, firstreg, lastreg, regnum)			\
	{ offsetof(struct elf_prstatus, firstreg),		\
	  (regnum), REG_CNT(firstreg, lastreg), (bits) }

static kdump_status
process_x86_64_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
{
	static const struct reg_def def[] = {
		REG_DEF(64, pr_reg[0], pr_reg[ELF_NGREG - 1], 0),
		REG_DEF(32, pr_pid, pr_pid, 43),
		REG_DEF_END
	};

	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs(ctx, get_num_cpus(ctx), reg_names, data, def);
	if (res != KDUMP_OK)
		return res;

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);
	return KDUMP_OK;
}

#define XEN_REG_CNT(start, end)					\
	  ((offsetof(struct xen_vcpu_guest_context, end)	\
	    - offsetof(struct xen_vcpu_guest_context, start))	\
	   / sizeof(((struct xen_vcpu_guest_context*)0)->start)	\
	   + 1)

#define XEN_REG_DEF(bits, firstreg, lastreg, regnum)		\
	   { offsetof(struct xen_vcpu_guest_context, firstreg),	\
	     (regnum), XEN_REG_CNT(firstreg, lastreg), (bits) }

#define XEN_UREG_CNT(start, end)				\
	   ((offsetof(struct xen_cpu_user_regs, end)		\
	     - offsetof(struct xen_cpu_user_regs, start))	\
	    / sizeof(((struct xen_cpu_user_regs*)0)->start)	\
	    + 1)

#define XEN_UREG_DEF(bits, firstreg, lastreg, regnum)			\
	{ offsetof(struct xen_vcpu_guest_context, user_regs.firstreg),	\
	  (regnum), XEN_UREG_CNT(firstreg, lastreg), (bits) }

static kdump_status
process_x86_64_xen_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
{
	static const struct reg_def def[] = {
		XEN_UREG_DEF(64, r15, rdi, 0),
		XEN_UREG_DEF(64, rip, rip, 16),
		XEN_UREG_DEF(16, cs, cs, 17),
		XEN_UREG_DEF(64, rflags, rsp, 18),
		XEN_UREG_DEF(16, ss, ss, 20),
		XEN_UREG_DEF(16, es, es, 24),
		XEN_UREG_DEF(16, ds, ds, 23),
		XEN_UREG_DEF(16, fs, fs, 25),
		XEN_UREG_DEF(16, gs, gs, 26),
		XEN_REG_DEF(64, ctrlreg[0], debugreg[7], 27),
		REG_DEF_END
	};

	unsigned cpu = 0;
	kdump_status res;

	while (size >= sizeof(struct xen_vcpu_guest_context)) {
		res = set_cpu_regs(ctx, cpu, reg_names, data, def);
		if (res != KDUMP_OK)
			return res;

		++cpu;
		data += sizeof(struct xen_vcpu_guest_context);
		size -= sizeof(struct xen_vcpu_guest_context);
	}

	if (!isset_num_cpus(ctx) || cpu > get_num_cpus(ctx))
		set_num_cpus(ctx, cpu);

	return KDUMP_OK;
}

const struct arch_ops x86_64_ops = {
	.late_init = x86_64_late_init,
	.process_prstatus = process_x86_64_prstatus,
	.process_xen_prstatus = process_x86_64_xen_prstatus,
};
