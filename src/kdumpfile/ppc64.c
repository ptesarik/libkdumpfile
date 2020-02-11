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

static const struct attr_template reg_names[] = {
#define REG(name)	{ #name, NULL, KDUMP_NUMBER }
	REG(r0),
	REG(r1),
	REG(r2),
	REG(r3),
	REG(r4),
	REG(r5),
	REG(r6),
	REG(r7),
	REG(r8),
	REG(r9),
	REG(r10),
	REG(r11),
	REG(r12),
	REG(r13),
	REG(r14),
	REG(r15),
	REG(r16),
	REG(r17),
	REG(r18),
	REG(r19),
	REG(r20),
	REG(r21),
	REG(r22),
	REG(r23),
	REG(r24),
	REG(r25),
	REG(r26),
	REG(r27),
	REG(r28),
	REG(r29),
	REG(r30),
	REG(r31),
	REG(pc),
	REG(msr),
	REG(or3),
	REG(ctr),
	REG(lr),
	REG(xer),
	REG(ccr),
	REG(softe),
	REG(trap),
	REG(dar),
	REG(dsisr),
	REG(res),
};

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

/**  Number of registers in struct pt_regs.
 *
 * This is the number of registers that are actually saved in a kernel crash
 * dump. Rest of the structure is always filled with zeroes.
 */
#define ELF_NGREG_PTREGS	44

static kdump_status
process_ppc64_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
{
	const struct elf_prstatus *status = data;
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs64(ctx, get_num_cpus(ctx), reg_names,
			     status->pr_reg, ELF_NGREG_PTREGS);

	if (res != KDUMP_OK)
		return res;

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);

	return KDUMP_OK;
}

const struct arch_ops ppc64_ops = {
	.process_prstatus = process_ppc64_prstatus,
};
