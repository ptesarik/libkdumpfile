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

#include <stdint.h>
#include <stdlib.h>

#include "kdumpfile-priv.h"

#define ELF_NGREG 27

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

/* Internal CPU state, as seen by libkdumpfile */
struct cpu_state {
	int32_t pid;
	uint64_t reg[ELF_NGREG];
	struct cpu_state *next;
};

static kdump_status
process_x86_64_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	struct cpu_state *cs;
	int i;

	if (size < sizeof(struct elf_prstatus))
		return kdump_dataerr;

	++ctx->num_cpus;

	cs = malloc(sizeof *cs);
	if (!cs)
		return kdump_syserr;

	cs->pid = dump32toh(ctx, status->pr_pid);
	for (i = 0; i < ELF_NGREG; ++i)
		cs->reg[i] = dump64toh(ctx, status->pr_reg[i]);

	cs->next = ctx->archdata;
	ctx->archdata = cs;

	return kdump_ok;
}

static kdump_status
x86_64_read_reg(kdump_ctx *ctx, unsigned cpu, unsigned index,
		kdump_reg_t *value)
{
	struct cpu_state *cs;
	int i;

	if (index >= ELF_NGREG)
		return kdump_nodata;

	for (i = 0, cs = ctx->archdata; i < cpu && cs; ++i)
		cs = cs->next;
	if (!cs)
		return kdump_nodata;

	*value = cs->reg[index];
	return kdump_ok;
}

static kdump_status
x86_64_process_load(kdump_ctx *ctx, kdump_paddr_t vaddr, kdump_paddr_t paddr)
{
	if (!(ctx->flags & DIF_PHYS_BASE) &&
	    vaddr >= __START_KERNEL_map &&
	    vaddr < __START_KERNEL_map + MAX_PHYSICAL_START)
		kdump_set_phys_base(ctx, paddr - (vaddr - __START_KERNEL_map));
	return kdump_ok;
}

static void
x86_64_cleanup(kdump_ctx *ctx)
{
	struct cpu_state *cs, *oldcs;

	cs = ctx->archdata;
	while (cs) {
		oldcs = cs;
		cs = cs->next;
		free(oldcs);
	}

	ctx->archdata = NULL;
}

const struct arch_ops kdump_x86_64_ops = {
	.process_prstatus = process_x86_64_prstatus,
	.read_reg = x86_64_read_reg,
	.process_load = x86_64_process_load,
	.cleanup = x86_64_cleanup,
};
