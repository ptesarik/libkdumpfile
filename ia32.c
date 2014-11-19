/* Functions for the Intel 32-bit (x86) architecture.
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

#include "kdumpfile-priv.h"

#include <stdint.h>
#include <stdlib.h>
#include <linux/version.h>

#define ELF_NGREG 17

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	32
#define VIRTADDR_MAX		UINT32_MAX

/* Maximum physical addrss bits (architectural limit) */
#define PHYSADDR_BITS_MAX_PAE	36
#define PHYSADDR_SIZE_PAE	((uint64_t)1 << PHYSADDR_BITS_MAX_PAE)
#define PHYSADDR_MASK_PAE	(~(PHYSADDR_SIZE_PAE-1))

#define PGDIR_SHIFT_PAE		30
#define PTRS_PER_PGD_PAE	4

#define PMD_SHIFT_PAE		21
#define PMD_PSE_SIZE_PAE	((uint64_t)1 << PMD_SHIFT_PAE)
#define PMD_PSE_MASK_PAE	(~(PMD_PSE_SIZE_PAE-1))
#define PTRS_PER_PMD_PAE	512

#define PAGE_SHIFT		12
#define PAGE_SIZE		((uint64_t)1 << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))
#define PTRS_PER_PTE_PAE	512

#define PTRS_PER_PAGE_PAE	(PAGE_SIZE/sizeof(uint64_t))

#define pgd_index_pae(addr)	\
	(((addr) >> PGDIR_SHIFT_PAE) & (PTRS_PER_PGD_PAE - 1))
#define pmd_index_pae(addr)	\
	(((addr) >> PMD_SHIFT_PAE) & (PTRS_PER_PMD_PAE - 1))
#define pte_index_pae(addr)	\
	(((addr) >> PAGE_SHIFT) & (PTRS_PER_PAGE_PAE - 1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

#define __START_KERNEL_map	0xc0000000UL

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

/* Internal CPU state, as seen by libkdumpfile */
struct cpu_state {
	int32_t pid;
	uint64_t reg[ELF_NGREG];
	struct cpu_state *next;
};

struct ia32_data {
	struct cpu_state *cpu_state;
	uint64_t *pgt;
};

static kdump_status
ia32_init(kdump_ctx *ctx)
{
	kdump_status ret;

	ctx->archdata = calloc(1, sizeof(struct ia32_data));
	if (!ctx->archdata)
		return kdump_syserr;

	ret = kdump_set_region(ctx, __START_KERNEL_map, VIRTADDR_MAX,
			       KDUMP_XLAT_DIRECT, __START_KERNEL_map);
	if (ret != kdump_ok)
		return ret;

	return kdump_ok;
}

static kdump_status
process_ia32_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct ia32_data *archdata = ctx->archdata;
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
		cs->reg[i] = dump32toh(ctx, status->pr_reg[i]);

	cs->next = archdata->cpu_state;
	archdata->cpu_state = cs;

	return kdump_ok;
}

static kdump_status
ia32_read_reg(kdump_ctx *ctx, unsigned cpu, unsigned index,
	      kdump_reg_t *value)
{
	struct ia32_data *archdata = ctx->archdata;
	struct cpu_state *cs;
	int i;

	if (index >= ELF_NGREG)
		return kdump_nodata;

	for (i = 0, cs = archdata->cpu_state; i < cpu && cs; ++i)
		cs = cs->next;
	if (!cs)
		return kdump_nodata;

	*value = cs->reg[index];
	return kdump_ok;
}

static kdump_status
read_pgt(kdump_ctx *ctx)
{
	struct ia32_data *archdata = ctx->archdata;
	kdump_vaddr_t pgtaddr;
	uint64_t *pgt;
	kdump_status ret;
	size_t sz;

	ret = kdump_vmcoreinfo_symbol(ctx, "swapper_pg_dir", &pgtaddr);
	if (ret != kdump_ok)
		return ret;

	if (pgtaddr < __START_KERNEL_map)
		return kdump_unsupported;

	pgt = malloc(PAGE_SIZE);
	if (!pgt)
		return kdump_syserr;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, pgtaddr - __START_KERNEL_map,
			  pgt, &sz, KDUMP_PHYSADDR);
	if (ret == kdump_ok)
		archdata->pgt = pgt;
	else
		free(pgt);

	return ret;
}

static kdump_status
ia32_vtop_init(kdump_ctx *ctx)
{
	kdump_status ret;

	ret = read_pgt(ctx);
	if (ret != kdump_ok)
		return ret;

	kdump_flush_regions(ctx);
	ret = kdump_set_region(ctx, 0, VIRTADDR_MAX, KDUMP_XLAT_VTOP, 0);
	if (ret != kdump_ok)
		return ret;

	return kdump_ok;
}

static void
ia32_cleanup(kdump_ctx *ctx)
{
	struct ia32_data *archdata = ctx->archdata;
	struct cpu_state *cs, *oldcs;

	cs = archdata->cpu_state;
	while (cs) {
		oldcs = cs;
		cs = cs->next;
		free(oldcs);
	}

	if (archdata->pgt)
		free(archdata->pgt);

	free(archdata);
	ctx->archdata = NULL;
}

static kdump_status
ia32_vtop_pae(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct ia32_data *archdata = ctx->archdata;
	uint64_t tbl[PTRS_PER_PAGE_PAE];
	uint64_t pgd, pmd, pte;
	kdump_paddr_t base;
	size_t sz;
	kdump_status ret;

	pgd = archdata->pgt[pgd_index_pae(vaddr)];
	if (!(pgd & _PAGE_PRESENT))
		return kdump_nodata;
	base = pgd & ~PHYSADDR_MASK_PAE & PAGE_MASK;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok)
		return ret;

	pmd = tbl[pmd_index_pae(vaddr)];
	if (!(pmd & _PAGE_PRESENT))
		return kdump_nodata;
	base = pmd & ~PHYSADDR_MASK_PAE & PAGE_MASK;
	if (pmd & _PAGE_PSE) {
		*paddr = base + (vaddr & ~PMD_PSE_MASK_PAE);
		return kdump_ok;
	}

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok)
		return ret;

	pte = tbl[pte_index_pae(vaddr)];
	if (!(pte & _PAGE_PRESENT))
		return kdump_nodata;
	base = pte & ~PHYSADDR_MASK_PAE & PAGE_MASK;
	*paddr = base + (vaddr & ~PAGE_MASK);

	return kdump_ok;
}

static kdump_status
ia32_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct ia32_data *archdata = ctx->archdata;

	if (!archdata->pgt)
		return kdump_unsupported;

	return ia32_vtop_pae(ctx, vaddr, paddr);
}

const struct arch_ops kdump_ia32_ops = {
	.init = ia32_init,
	.vtop_init = ia32_vtop_init,
	.process_prstatus = process_ia32_prstatus,
	.read_reg = ia32_read_reg,
	.vtop = ia32_vtop,
	.cleanup = ia32_cleanup,
};
