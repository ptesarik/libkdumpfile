/** @internal @file src/kdumpfile/ppc64.c
 * @brief Functions for the ppc64 architecture.
 */
/* Copyright (C) 2015 Ales Novak <alnovak@suse.com>
   Copyright (C) 2015-2022 Petr Tesarik <ptesarik@suse.com>

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

#define REG(name, field) \
	DERIVED_NUMBER(#name, 1, struct elf_prstatus, field)

static struct derived_attr_def ppc64_reg_attrs[] = {
	REG(r0,  pr_reg[0]),
	REG(r1,  pr_reg[1]),
	REG(r2,  pr_reg[2]),
	REG(r3,  pr_reg[3]),
	REG(r4,  pr_reg[4]),
	REG(r5,  pr_reg[5]),
	REG(r6,  pr_reg[6]),
	REG(r7,  pr_reg[7]),
	REG(r8,  pr_reg[8]),
	REG(r9,  pr_reg[9]),
	REG(r10, pr_reg[10]),
	REG(r11, pr_reg[11]),
	REG(r12, pr_reg[12]),
	REG(r13, pr_reg[13]),
	REG(r14, pr_reg[14]),
	REG(r15, pr_reg[15]),
	REG(r16, pr_reg[16]),
	REG(r17, pr_reg[17]),
	REG(r18, pr_reg[18]),
	REG(r19, pr_reg[19]),
	REG(r20, pr_reg[20]),
	REG(r21, pr_reg[21]),
	REG(r22, pr_reg[22]),
	REG(r23, pr_reg[23]),
	REG(r24, pr_reg[24]),
	REG(r25, pr_reg[25]),
	REG(r26, pr_reg[26]),
	REG(r27, pr_reg[27]),
	REG(r28, pr_reg[28]),
	REG(r29, pr_reg[29]),
	REG(r30, pr_reg[30]),
	REG(r31, pr_reg[31]),
	REG(pc,  pr_reg[32]),
	REG(msr, pr_reg[33]),
	REG(or3, pr_reg[34]),
	REG(ctr, pr_reg[35]),
	REG(lr,  pr_reg[36]),
	REG(xer, pr_reg[37]),
	REG(ccr, pr_reg[38]),
	REG(softe, pr_reg[39]),
	REG(trap, pr_reg[40]),
	REG(dar,  pr_reg[41]),
	REG(dsisr, pr_reg[42]),
	REG(res, pr_reg[43]),
	DERIVED_NUMBER("pid", 0, struct elf_prstatus, pr_pid),
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
