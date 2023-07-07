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
x86_64_post_addrxlat(kdump_ctx_t *ctx)
{
	const addrxlat_meth_t *meth;
	kdump_status status;

	if (isset_phys_base(ctx) ||
	    ctx->xlat->osdir != GKI_dir_linux)
		return KDUMP_OK;

	meth = addrxlat_sys_get_meth(ctx->xlat->xlatsys,
				     ADDRXLAT_SYS_METH_KTEXT);
	if (meth->kind == ADDRXLAT_LINEAR) {
		set_phys_base(ctx, (meth->param.linear.off +
				    __START_KERNEL_map));
		ctx->xlat->dirty = false;
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

	return revalidate_xlat(ctx);
}

#define REG(name, field) \
	DERIVED_NUMBER(#name, 1, struct elf_prstatus, field)

static struct derived_attr_def x86_64_reg_attrs[] = {
	REG(r15, pr_reg[0]),
	REG(r14, pr_reg[1]),
	REG(r13, pr_reg[2]),
	REG(r12, pr_reg[3]),
	REG(rbp, pr_reg[4]),
	REG(rbx, pr_reg[5]),
	REG(r11, pr_reg[6]),
	REG(r10, pr_reg[7]),
	REG(r9,  pr_reg[8]),
	REG(r8,  pr_reg[9]),
	REG(rax, pr_reg[10]),
	REG(rcx, pr_reg[11]),
	REG(rdx, pr_reg[12]),
	REG(rsi, pr_reg[13]),
	REG(rdi, pr_reg[14]),
	REG(orig_rax, pr_reg[15]),
	REG(rip, pr_reg[16]),
	REG(cs,  pr_reg[17]),
	REG(rflags, pr_reg[18]),
	REG(rsp, pr_reg[19]),
	REG(ss,  pr_reg[20]),
	REG(fs_base, pr_reg[21]),
	REG(gs_base, pr_reg[22]),
	REG(ds, pr_reg[23]),
	REG(es, pr_reg[24]),
	REG(fs, pr_reg[25]),
	REG(gs, pr_reg[26]),
	DERIVED_NUMBER("pid", 0, struct elf_prstatus, pr_pid),
};

static kdump_status
process_x86_64_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
{
	unsigned cpu;
	kdump_status status;

	cpu = get_num_cpus(ctx);
	set_num_cpus(ctx, get_num_cpus(ctx) + 1);

	status = init_cpu_prstatus(ctx, cpu, data, size);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot set CPU %u %s",
				 cpu, "PRSTATUS");

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong PRSTATUS size: %zu", size);

	status = create_cpu_regs(
		ctx, cpu, x86_64_reg_attrs, ARRAY_SIZE(x86_64_reg_attrs));

	return status;
}

#define XEN_REG(name, field, bits) \
	{ { #name, { .depth = 1 }, KDUMP_NUMBER },	  \
	  offsetof(struct xen_vcpu_guest_context, field), \
	  (bits) / BITS_PER_BYTE }

#define XEN_UREG(name, bits)	 \
	{ { #name, { .depth = 1 }, KDUMP_NUMBER },		   \
	  offsetof(struct xen_vcpu_guest_context, user_regs.name), \
	  (bits) / BITS_PER_BYTE }

static struct derived_attr_def x86_64_xen_reg_attrs[] = {
	XEN_UREG(r15, 64),
	XEN_UREG(r14, 64),
	XEN_UREG(r13, 64),
	XEN_UREG(r12, 64),
	XEN_UREG(rbp, 64),
	XEN_UREG(rbx, 64),
	XEN_UREG(r11, 64),
	XEN_UREG(r10, 64),
	XEN_UREG(r9, 64),
	XEN_UREG(r8, 64),
	XEN_UREG(rax, 64),
	XEN_UREG(rcx, 64),
	XEN_UREG(rdx, 64),
	XEN_UREG(rsi, 64),
	XEN_UREG(rdi, 64),
	XEN_UREG(rip, 64),
	XEN_UREG(cs, 16),
	XEN_UREG(rflags, 64),
	XEN_UREG(rsp, 64),
	XEN_UREG(ss, 16),
	XEN_UREG(es, 16),
	XEN_UREG(ds, 16),
	XEN_UREG(fs, 16),
	XEN_UREG(gs, 16),
	XEN_REG(cr0, ctrlreg[0], 64),
	XEN_REG(cr1, ctrlreg[1], 64),
	XEN_REG(cr2, ctrlreg[2], 64),
	XEN_REG(cr3, ctrlreg[3], 64),
	XEN_REG(cr4, ctrlreg[4], 64),
	XEN_REG(cr5, ctrlreg[5], 64),
	XEN_REG(cr6, ctrlreg[6], 64),
	XEN_REG(cr7, ctrlreg[7], 64),
	XEN_REG(dr0, debugreg[0], 64),
	XEN_REG(dr1, debugreg[1], 64),
	XEN_REG(dr2, debugreg[2], 64),
	XEN_REG(dr3, debugreg[3], 64),
	XEN_REG(dr4, debugreg[4], 64),
	XEN_REG(dr5, debugreg[5], 64),
	XEN_REG(dr6, debugreg[6], 64),
	XEN_REG(dr7, debugreg[7], 64),
};

static kdump_status
process_x86_64_xen_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
{
	unsigned cpu = 0;
	kdump_status status;

	while (size >= sizeof(struct xen_vcpu_guest_context)) {
		status = init_xen_cpu_prstatus(
			ctx, cpu, data, sizeof(struct xen_vcpu_guest_context));
		if (status != KDUMP_OK)
			return set_error(ctx, status, "Cannot set CPU %u %s",
					 cpu, "XEN_PRSTATUS");

		status = create_xen_cpu_regs(ctx, cpu, x86_64_xen_reg_attrs,
					     ARRAY_SIZE(x86_64_xen_reg_attrs));
		if (status != KDUMP_OK)
			return status;

		++cpu;
		data += sizeof(struct xen_vcpu_guest_context);
		size -= sizeof(struct xen_vcpu_guest_context);
	}

	if (!isset_num_cpus(ctx) || cpu > get_num_cpus(ctx))
		set_num_cpus(ctx, cpu);

	return KDUMP_OK;
}

const struct arch_ops x86_64_ops = {
	.post_addrxlat = x86_64_post_addrxlat,
	.process_prstatus = process_x86_64_prstatus,
	.process_xen_prstatus = process_x86_64_xen_prstatus,
};
