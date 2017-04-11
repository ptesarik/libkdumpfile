/** @internal @file src/ia32.c
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

static const struct attr_template reg_names[] = {
#define REG(name)	{ #name, NULL, KDUMP_NUMBER }
	REG(ebx),
	REG(ecx),
	REG(edx),
	REG(esi),
	REG(edi),
	REG(ebp),
	REG(eax),
	REG(ds),
	REG(es),
	REG(fs),
	REG(gs),
	REG(orig_eax),
	REG(eip),
	REG(cs),
	REG(eflags),
	REG(esp),
	REG(ss),
};

static const struct attr_template tmpl_pid =
	{ "pid", NULL, KDUMP_NUMBER };

static kdump_status
process_ia32_prstatus(kdump_ctx_t *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	char cpukey[sizeof("cpu.") + 20];
	struct attr_data *dir, *attr;
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs32(ctx, get_num_cpus(ctx),
			     reg_names, status->pr_reg, ELF_NGREG);
	if (res != KDUMP_OK)
		return res;

	sprintf(cpukey, "cpu.%u", get_num_cpus(ctx));
	dir = lookup_attr(ctx->shared, cpukey);
	if (!dir)
		return set_error(ctx, KDUMP_ERR_NOKEY,
				 "'%s': %s", cpukey, "No such key");
	attr = new_attr(ctx->shared, dir, &tmpl_pid);
	if (!attr)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate '%s'", cpukey);
	res = set_attr_number(ctx, attr, ATTR_DEFAULT,
			      dump32toh(ctx, status->pr_pid));
	if (res != KDUMP_OK)
		return set_error(ctx, res,
				 "Cannot set '%s'", cpukey);

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);
	return KDUMP_OK;
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
