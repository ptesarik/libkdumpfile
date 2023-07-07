/** @internal @file src/kdumpfile/aarch64.c
 * @brief Functions for the Aarch64 architecture.
 */
/* Copyright (C) 2020 Petr Tesarik <ptesarik@suse.cz>

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

#define ELF_NGREG 34

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

/** @endcond */

#define REG(name, field, bits) \
	{ { #name, { .depth = 1 }, KDUMP_NUMBER },	\
	  offsetof(struct elf_prstatus, field), \
	  (bits) / BITS_PER_BYTE }

static struct derived_attr_def aarch64_reg_attrs[] = {
	REG(x0, pr_reg[0], 64),
	REG(x1, pr_reg[1], 64),
	REG(x2, pr_reg[2], 64),
	REG(x3, pr_reg[3], 64),
	REG(x4, pr_reg[4], 64),
	REG(x5, pr_reg[5], 64),
	REG(x6, pr_reg[6], 64),
	REG(x7, pr_reg[7], 64),
	REG(x8, pr_reg[8], 64),
	REG(x9, pr_reg[9], 64),
	REG(x10, pr_reg[10], 64),
	REG(x11, pr_reg[11], 64),
	REG(x12, pr_reg[12], 64),
	REG(x13, pr_reg[13], 64),
	REG(x14, pr_reg[14], 64),
	REG(x15, pr_reg[15], 64),
	REG(x16, pr_reg[16], 64),
	REG(x17, pr_reg[17], 64),
	REG(x18, pr_reg[18], 64),
	REG(x19, pr_reg[19], 64),
	REG(x20, pr_reg[20], 64),
	REG(x21, pr_reg[21], 64),
	REG(x22, pr_reg[22], 64),
	REG(x23, pr_reg[23], 64),
	REG(x24, pr_reg[24], 64),
	REG(x25, pr_reg[25], 64),
	REG(x26, pr_reg[26], 64),
	REG(x27, pr_reg[27], 64),
	REG(x28, pr_reg[28], 64),
	REG(x29, pr_reg[29], 64),
	REG(lr,  pr_reg[30], 64),
	REG(sp,  pr_reg[31], 64),
	REG(pc,  pr_reg[32], 64),
	REG(pstate, pr_reg[33], 64),
	DERIVED_NUMBER("pid", 0, struct elf_prstatus, pr_pid),
};

static kdump_status
process_aarch64_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
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
		ctx, cpu, aarch64_reg_attrs, ARRAY_SIZE(aarch64_reg_attrs));

	return status;
}

const struct arch_ops aarch64_ops = {
	.process_prstatus = process_aarch64_prstatus,
};
