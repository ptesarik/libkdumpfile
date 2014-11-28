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
#include <string.h>
#include <errno.h>
#include <linux/version.h>

#define ELF_NGREG 17

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	32
#define VIRTADDR_MAX		UINT32_MAX

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX_PAE	52
#define PHYSADDR_SIZE_PAE	((uint64_t)1 << PHYSADDR_BITS_MAX_PAE)
#define PHYSADDR_MASK_PAE	(~(PHYSADDR_SIZE_PAE-1))

#define PGDIR_SHIFT_NONPAE	22
#define PGD_PSE_SIZE_NONPAE	((uint64_t)1 << PGDIR_SHIFT_NONPAE)
#define PGD_PSE_MASK_NONPAE	(~(PGD_PSE_SIZE_NONPAE-1))

#define PGD_PSE_HIGH_SHIFT	13
#define PGD_PSE_HIGH_BITS	8
#define PGD_PSE_HIGH_MASK	(((uint64_t)1 << PGD_PSE_HIGH_BITS)-1)
#define pgd_pse_high(pgd)	\
	((((pgd) >> PGD_PSE_HIGH_SHIFT) & PGD_PSE_HIGH_MASK) << 32)

#define PGDIR_SHIFT_PAE		30
#define PTRS_PER_PGD_PAE	4

#define PMD_SHIFT_PAE		21
#define PMD_PSE_SIZE_PAE	((uint64_t)1 << PMD_SHIFT_PAE)
#define PMD_PSE_MASK_PAE	(~(PMD_PSE_SIZE_PAE-1))

#define PAGE_SHIFT		12
#define PAGE_SIZE		((uint64_t)1 << PAGE_SHIFT)
#define PAGE_MASK		(~(PAGE_SIZE-1))

#define PTRS_PER_PAGE_NONPAE	(PAGE_SIZE/sizeof(uint32_t))
#define PTRS_PER_PAGE_PAE	(PAGE_SIZE/sizeof(uint64_t))

#define pgd_index_nonpae(addr)	\
	(((addr) >> PGDIR_SHIFT_NONPAE) & (PTRS_PER_PAGE_NONPAE - 1))
#define pte_index_nonpae(addr)	\
	(((addr) >> PAGE_SHIFT) & (PTRS_PER_PAGE_NONPAE - 1))

#define pgd_index_pae(addr)	\
	(((addr) >> PGDIR_SHIFT_PAE) & (PTRS_PER_PGD_PAE - 1))
#define pmd_index_pae(addr)	\
	(((addr) >> PMD_SHIFT_PAE) & (PTRS_PER_PAGE_PAE - 1))
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
	union {
		void *pgt;
		uint32_t *pgt_nonpae;
		uint64_t *pgt_pae;
	};
	int pae_state;		/* <0 .. no, >0 .. yes, 0 .. undetermined */
};

static kdump_status
ia32_init(kdump_ctx *ctx)
{
	kdump_status ret;

	ctx->archdata = calloc(1, sizeof(struct ia32_data));
	if (!ctx->archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate ia32 private data: %s",
				 strerror(errno));

	ret = set_region(ctx, __START_KERNEL_map, VIRTADDR_MAX,
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
		return set_error(ctx, kdump_dataerr,
				 "Wrong PRSTATUS size: %zu", size);

	++ctx->num_cpus;

	cs = ctx_malloc(sizeof *cs, ctx, "ia32 registers");
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
		return set_error(ctx, kdump_nodata,
				 "Out-of-bounds register number: %u (max %u)",
				 index, ELF_NGREG);

	for (i = 0, cs = archdata->cpu_state; i < cpu && cs; ++i)
		cs = cs->next;
	if (!cs)
		return set_error(ctx, kdump_nodata,
				 "Out-of-bounds CPU number: %u (max %u)",
				 cpu, ctx->num_cpus);

	*value = cs->reg[index];
	return kdump_ok;
}

static kdump_status
read_pgt(kdump_ctx *ctx)
{
	struct ia32_data *archdata = ctx->archdata;
	kdump_vaddr_t pgtaddr;
	void *pgt;
	kdump_status ret;
	size_t sz;

	ret = kdump_vmcoreinfo_symbol(ctx, "swapper_pg_dir", &pgtaddr);
	if (ret != kdump_ok)
		return ret;

	if (pgtaddr < __START_KERNEL_map)
		return set_error(ctx, kdump_unsupported,
				 "Wrong page directory address: 0x%llx",
				 (unsigned long long) pgtaddr);

	if (!archdata->pae_state) {
		kdump_vaddr_t addr = pgtaddr + 3 * sizeof(uint64_t);
		uint64_t entry;

		sz = sizeof addr;
		ret = kdump_readp(ctx, addr - __START_KERNEL_map,
				  &entry, &sz, KDUMP_PHYSADDR);
		if (ret != kdump_ok)
			return ret;
		archdata->pae_state = entry ? 1 : -1;
	}

	sz = archdata->pae_state > 0
		? PTRS_PER_PGD_PAE * sizeof(uint64_t)
		: PAGE_SIZE;

	pgt = ctx_malloc(sz, ctx, "page table");
	if (!pgt)
		return kdump_syserr;

	ret = kdump_readp(ctx, pgtaddr - __START_KERNEL_map,
			  pgt, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok) {
		free(pgt);
		return set_error(ctx, ret, "Cannot read page table");
	}

	archdata->pgt = pgt;
	return kdump_ok;
}

static kdump_status
ia32_vtop_init(kdump_ctx *ctx)
{
	struct ia32_data *archdata = ctx->archdata;
	const char *cfg;
	kdump_status ret;

	cfg = kdump_vmcoreinfo_row(ctx, "CONFIG_X86_PAE");
	if (cfg && !strcmp(cfg, "y"))
		archdata->pae_state = 1;

	ret = read_pgt(ctx);
	if (ret != kdump_ok)
		return ret;

	flush_regions(ctx);
	ret = set_region(ctx, 0, VIRTADDR_MAX, KDUMP_XLAT_VTOP, 0);
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
ia32_vtop_nonpae(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct ia32_data *archdata = ctx->archdata;
	uint32_t tbl[PTRS_PER_PAGE_NONPAE];
	uint32_t pgd, pte;
	kdump_paddr_t base;
	size_t sz;
	kdump_status ret;

	pgd = archdata->pgt_nonpae[pgd_index_nonpae(vaddr)];
	if (!(pgd & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page table not present: pgd[%u] = 0x%llx",
				 (unsigned) pgd_index_nonpae(vaddr),
				 (unsigned long long) pgd);
	if (pgd & _PAGE_PSE) {
		base = (pgd & PGD_PSE_MASK_NONPAE) | pgd_pse_high(pgd);
		*paddr = base + (vaddr & ~PGD_PSE_MASK_NONPAE);
		return kdump_ok;
	}
	base = pgd & PAGE_MASK;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok)
		return ret;

	pte = tbl[pte_index_nonpae(vaddr)];
	if (!(pte & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page not present: pte[%u] = 0x%llx",
				 (unsigned) pte_index_nonpae(vaddr),
				 (unsigned long long) pte);
	base = pte & PAGE_MASK;
	*paddr = base + (vaddr & ~PAGE_MASK);

	return kdump_ok;
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

	pgd = archdata->pgt_pae[pgd_index_pae(vaddr)];
	if (!(pgd & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page directory not present:"
				 " pgd[%u] = 0x%llx",
				 (unsigned) pgd_index_pae(vaddr),
				 (unsigned long long) pgd);
	base = pgd & ~PHYSADDR_MASK_PAE & PAGE_MASK;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok)
		return ret;

	pmd = tbl[pmd_index_pae(vaddr)];
	if (!(pmd & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page table not present: pmd[%u] = 0x%llx",
				 (unsigned) pmd_index_pae(vaddr),
				 (unsigned long long) pmd);
	if (pmd & _PAGE_PSE) {
		base = pmd & ~PHYSADDR_MASK_PAE & PMD_PSE_MASK_PAE;
		*paddr = base + (vaddr & ~PMD_PSE_MASK_PAE);
		return kdump_ok;
	}
	base = pmd & ~PHYSADDR_MASK_PAE & PAGE_MASK;

	sz = PAGE_SIZE;
	ret = kdump_readp(ctx, base, tbl, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok)
		return ret;

	pte = tbl[pte_index_pae(vaddr)];
	if (!(pte & _PAGE_PRESENT))
		return set_error(ctx, kdump_nodata,
				 "Page not present: pte[%u] = 0x%llx",
				 (unsigned) pte_index_pae(vaddr),
				 (unsigned long long) pte);
	base = pte & ~PHYSADDR_MASK_PAE & PAGE_MASK;
	*paddr = base + (vaddr & ~PAGE_MASK);

	return kdump_ok;
}

static kdump_status
ia32_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct ia32_data *archdata = ctx->archdata;

	if (!archdata->pgt)
		return set_error(ctx, kdump_unsupported,
				 "VTOP translation not initialized");

	return archdata->pae_state > 0
		? ia32_vtop_pae(ctx, vaddr, paddr)
		: ia32_vtop_nonpae(ctx, vaddr, paddr);
}

const struct arch_ops ia32_ops = {
	.init = ia32_init,
	.vtop_init = ia32_vtop_init,
	.process_prstatus = process_ia32_prstatus,
	.read_reg = ia32_read_reg,
	.vtop = ia32_vtop,
	.cleanup = ia32_cleanup,
};
