/** @internal @file src/kdumpfile/ia32.c
 * @brief Functions for the Intel 32-bit (x86) architecture.
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

#define ELF_NGREG 17

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
	uint32_t pr_sigpend;		/* UNUSED in kernel cores */
	uint32_t pr_sighold;		/* UNUSED in kernel cores */
	int32_t	pr_pid;			/* PID of crashing task */
	int32_t	pr_ppid;		/* UNUSED in kernel cores */
	int32_t	pr_pgrp;		/* UNUSED in kernel cores */
	int32_t	pr_sid;			/* UNUSED in kernel cores */
	struct timeval_32 pr_utime;	/* UNUSED in kernel cores */
	struct timeval_32 pr_stime;	/* UNUSED in kernel cores */
	struct timeval_32 pr_cutime;	/* UNUSED in kernel cores */
	struct timeval_32 pr_cstime;	/* UNUSED in kernel cores */
	uint32_t pr_reg[ELF_NGREG];	/* GP registers */
	/* optional UNUSED fields may follow */
} __attribute__((packed));

/** @endcond */

#define REG(name, field, bits) \
	{ { #name, { .depth = 1 }, KDUMP_NUMBER },	\
	  offsetof(struct elf_prstatus, field), \
	  (bits) / BITS_PER_BYTE }

static struct derived_attr_def ia32_reg_attrs[] = {
	REG(ebx, pr_reg[0], 32),
	REG(ecx, pr_reg[1], 32),
	REG(edx, pr_reg[2], 32),
	REG(esi, pr_reg[3], 32),
	REG(edi, pr_reg[4], 32),
	REG(ebp, pr_reg[5], 32),
	REG(eax, pr_reg[6], 32),
	REG(ds,  pr_reg[7], 32),
	REG(es,  pr_reg[8], 32),
	REG(fs,  pr_reg[9], 32),
	REG(gs,  pr_reg[10], 32),
	REG(orig_eax, pr_reg[11], 32),
	REG(eip, pr_reg[12], 32),
	REG(cs,  pr_reg[13], 32),
	REG(eflags, pr_reg[14], 32),
	REG(esp, pr_reg[15], 32),
	REG(ss,  pr_reg[16], 32),
	DERIVED_NUMBER("pid", 0, struct elf_prstatus, pr_pid),
};

static kdump_status
process_ia32_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
{
	unsigned cpu;
	kdump_status status;

	cpu = get_num_cpus(ctx);
	set_num_cpus(ctx, get_num_cpus(ctx) + 1);

	status = init_cpu_prstatus(ctx, cpu, data, size);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot set CPU %u PRSTATUS", cpu);

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong PRSTATUS size: %zu", size);

	status = create_cpu_regs(
		ctx, cpu, ia32_reg_attrs, ARRAY_SIZE(ia32_reg_attrs));

	return status;
}

static kdump_status
ia32_init(kdump_ctx_t *ctx)
{
	clear_attr(ctx, gattr(ctx, GKI_pteval_size));

	return KDUMP_OK;
}

const struct arch_ops ia32_ops = {
	.init = ia32_init,
	.process_prstatus = process_ia32_prstatus,
};
