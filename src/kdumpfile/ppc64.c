/** @internal @file src/kdumpfile/ppc64.c
 * @brief Functions for the ppc64 architecture.
 */
/* Copyright (C) 2015 Free Software Foundation, Inc.

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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

/** @cond TARGET_ABI */

#define ELF_NGREG 48

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
	int32_t pr_fpvalid;		/* UNUSED in kernel cores */
	/* optional UNUSED fields may follow */
} __attribute__((packed));

/** @endcond */

#define PRINFO(name, field, bits) \
	{ { #name, { .depth = 0 }, KDUMP_NUMBER },	\
	  offsetof(struct elf_prstatus, field), \
	  (bits) / BITS_PER_BYTE }

#define REG(name, field, bits) \
	{ { #name, { .depth = 1 }, KDUMP_NUMBER },	\
	  offsetof(struct elf_prstatus, field), \
	  (bits) / BITS_PER_BYTE }

static struct derived_attr_def ppc64_reg_attrs[] = {
	REG(r0,  pr_reg[0], 64),
	REG(r1,  pr_reg[1], 64),
	REG(r2,  pr_reg[2], 64),
	REG(r3,  pr_reg[3], 64),
	REG(r4,  pr_reg[4], 64),
	REG(r5,  pr_reg[5], 64),
	REG(r6,  pr_reg[6], 64),
	REG(r7,  pr_reg[7], 64),
	REG(r8,  pr_reg[8], 64),
	REG(r9,  pr_reg[9], 64),
	REG(r10, pr_reg[10], 64),
	REG(r11, pr_reg[11], 64),
	REG(r12, pr_reg[12], 64),
	REG(r13, pr_reg[13], 64),
	REG(r14, pr_reg[14], 64),
	REG(r15, pr_reg[15], 64),
	REG(r16, pr_reg[16], 64),
	REG(r17, pr_reg[17], 64),
	REG(r18, pr_reg[18], 64),
	REG(r19, pr_reg[19], 64),
	REG(r20, pr_reg[20], 64),
	REG(r21, pr_reg[21], 64),
	REG(r22, pr_reg[22], 64),
	REG(r23, pr_reg[23], 64),
	REG(r24, pr_reg[24], 64),
	REG(r25, pr_reg[25], 64),
	REG(r26, pr_reg[26], 64),
	REG(r27, pr_reg[27], 64),
	REG(r28, pr_reg[28], 64),
	REG(r29, pr_reg[29], 64),
	REG(r30, pr_reg[30], 64),
	REG(r31, pr_reg[31], 64),
	REG(pc,  pr_reg[32], 64),
	REG(msr, pr_reg[33], 64),
	REG(or3, pr_reg[34], 64),
	REG(ctr, pr_reg[35], 64),
	REG(lr,  pr_reg[36], 64),
	REG(xer, pr_reg[37], 64),
	REG(ccr, pr_reg[38], 64),
	REG(softe, pr_reg[39], 64),
	REG(trap, pr_reg[40], 64),
	REG(dar,  pr_reg[41], 64),
	REG(dsisr, pr_reg[42], 64),
	REG(res, pr_reg[43], 64),
	PRINFO(pid, pr_pid, 32),
};

static kdump_status
process_ppc64_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
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
		ctx, cpu, ppc64_reg_attrs, ARRAY_SIZE(ppc64_reg_attrs));

	return status;
}

const struct arch_ops ppc64_ops = {
	.process_prstatus = process_ppc64_prstatus,
};
