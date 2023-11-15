/** @internal @file src/kdumpfile/riscv64.c
 * @brief Functions for the RISC-V architecture (64-bit).
 */
/* Copyright (C) 2023 Petr Tesarik <petr@tesarici.cz>

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

#define ELF_NGREG 33

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

#define REG(name, field) \
	DERIVED_NUMBER(#name, 1, struct elf_prstatus, field)

static struct derived_attr_def riscv64_reg_attrs[] = {
	REG(pc, pr_reg[0]),
	REG(ra, pr_reg[1]),
	REG(sp, pr_reg[2]),
	REG(gp, pr_reg[3]),
	REG(tp, pr_reg[4]),
	REG(t0, pr_reg[5]),
	REG(t1, pr_reg[6]),
	REG(t2, pr_reg[7]),
	REG(s0, pr_reg[8]),
	REG(s1, pr_reg[9]),
	REG(a0, pr_reg[10]),
	REG(a1, pr_reg[11]),
	REG(a2, pr_reg[12]),
	REG(a3, pr_reg[13]),
	REG(a4, pr_reg[14]),
	REG(a5, pr_reg[15]),
	REG(a6, pr_reg[16]),
	REG(a7, pr_reg[17]),
	REG(s2, pr_reg[18]),
	REG(s3, pr_reg[19]),
	REG(s4, pr_reg[20]),
	REG(s5, pr_reg[21]),
	REG(s6, pr_reg[22]),
	REG(s7, pr_reg[23]),
	REG(s8, pr_reg[24]),
	REG(s9, pr_reg[25]),
	REG(s10, pr_reg[26]),
	REG(s11, pr_reg[27]),
	REG(t3, pr_reg[28]),
	REG(t4, pr_reg[29]),
	REG(t5,  pr_reg[30]),
	REG(t6,  pr_reg[31]),
	DERIVED_NUMBER("pid", 0, struct elf_prstatus, pr_pid),
};

static kdump_status
process_riscv64_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
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
		ctx, cpu, riscv64_reg_attrs, ARRAY_SIZE(riscv64_reg_attrs));

	return status;
}

const struct arch_ops riscv64_ops = {
	.process_prstatus = process_riscv64_prstatus,
};
