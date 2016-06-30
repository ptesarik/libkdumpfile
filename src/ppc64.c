/** @internal @file src/ppc64.c
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

#define VIRTADDR_BITS_MAX	64
#define VIRTADDR_MAX		UINT64_MAX

/** Definition of a paging form.
 */
struct paging_form {
	unsigned page_bits;
	unsigned pte_bits;
	unsigned pmd_bits;
	unsigned pud_bits;
	unsigned pgd_bits;
};

struct ppc64_data {
	struct paging_form pgform;
	struct {
		kdump_vaddr_t pmd_mask;
		kdump_vaddr_t pud_mask;
		kdump_vaddr_t pgd_mask;

		unsigned pte_shift;
		unsigned pmd_shift;
		unsigned pud_shift;
		unsigned pgd_shift;

		int rpn_shift;	/**< Real Page Number shift. */

		kdump_vaddr_t pg;
	} pg;
};

static const struct attr_template reg_names[] = {
#define REG(name)	{ #name, NULL, kdump_number }
	REG(gpr00),
	REG(gpr01),
	REG(gpr02),
	REG(gpr03),
	REG(gpr04),
	REG(gpr05),
	REG(gpr06),
	REG(gpr07),
	REG(gpr08),
	REG(gpr09),
	REG(gpr10),
	REG(gpr11),
	REG(gpr12),
	REG(gpr13),
	REG(gpr14),
	REG(gpr15),
	REG(gpr16),
	REG(gpr17),
	REG(gpr18),
	REG(gpr19),
	REG(gpr20),
	REG(gpr21),
	REG(gpr22),
	REG(gpr23),
	REG(gpr24),
	REG(gpr25),
	REG(gpr26),
	REG(gpr27),
	REG(gpr28),
	REG(gpr29),
	REG(gpr30),
	REG(gpr31),
	REG(nip),
	REG(msr),
	REG(or3),
	REG(ctr),
	REG(lr),
	REG(xer),
	REG(ccr),
	REG(mq),
	REG(dar),
	REG(dsisr),
	REG(rx1),
	REG(rx2),
	REG(rx3),
	REG(rx4),
	REG(rx5),
	REG(rx6),
	REG(rx7),
	REG(rx8),
	REG(rx9),
};

#define _64K (1<<16)

/**  A page table entry is huge if the bottom two bits != 00.
 */
#define HUGE_PTE_MASK     0x03

/**  Page entry flag for a huge page directory.
 * The corresponding entry is huge if the most significant bit is zero.
 */
#define PD_HUGE           ((uint64_t)1 << 63)

/**  Page shift of a huge page directory.
 * If PD_HUGE is zero, the huge page shift is stored in the least
 * significant bits of the entry.
 */
#define HUGEPD_SHIFT_MASK 0x3f

/**  Individual parts of a virtual address.
 */
struct vaddr_parts {
	unsigned off;		/**< Offset inside page */
	unsigned pte;		/**< PTE index */
	unsigned pmd;		/**< PMD index */
	unsigned pud;		/**< PUD index */
	unsigned pgd;		/**< PGD index */
};

/**  Split a virtual addres into individual parts.
 * @param[in]  pgform  Paging form definition.
 * @param[in]  addr    Virtual address to be split.
 * @param[out] parts   Parts of the address.
 */
static void
vaddr_split(const struct paging_form *pgform, kdump_vaddr_t addr,
	    struct vaddr_parts *parts)
{
	parts->off = addr & (((kdump_vaddr_t)1 << pgform->page_bits) - 1);
	addr >>= pgform->page_bits;
	parts->pte = addr & (((kdump_vaddr_t)1 << pgform->pte_bits) - 1);
	addr >>= pgform->pte_bits;
	parts->pmd = addr & (((kdump_vaddr_t)1 << pgform->pmd_bits) - 1);
	addr >>= pgform->pmd_bits;
	parts->pud = addr & (((kdump_vaddr_t)1 << pgform->pud_bits) - 1);
	addr >>= pgform->pud_bits;
	parts->pgd = addr & (((kdump_vaddr_t)1 << pgform->pgd_bits) - 1);
}

/**  Get the translated address using its PTE and page shift.
 * @param vaddr       Virtual address to be translated.
 * @param pte         Last-level page table entry.
 * @param rpn_shift   Real Page Number shift.
 * @param page_shift  Page shift.
 *
 * On PowerPC, the PFN in the page table entry is shifted left by
 * @ref rpn_shift bits (allowing to store more flags in the lower bits).
 */
static inline kdump_addr_t
vtop_final(kdump_vaddr_t vaddr, uint64_t pte,
	   unsigned rpn_shift, unsigned page_shift)
{
	kdump_addr_t mask = ((kdump_addr_t)1 << page_shift) - 1;
	return ((pte >> rpn_shift) << page_shift) + (vaddr & mask);
}

/**  Check whether a page table entry is huge.
 * @param pte  Page table entry (value).
 * @returns    Non-zero if this is a huge page entry.
 */
static inline int
is_hugepte(uint64_t pte)
{
	return (pte & HUGE_PTE_MASK) != 0x0;
}

/**  Check whether a page directory is huge.
 * @param pte  Page table entry (value).
 * @returns    Non-zero if this is a huge page directory entry.
 */
static inline int
is_hugepd(uint64_t pte)
{
	return !(pte & PD_HUGE);
}

/**  Get the huge page directory shift.
 * @param entry  Huge page directory entry.
 * @returns      Huge page bit shift.
 */
static inline unsigned
hugepd_shift(uint64_t hpde)
{
	return hpde & HUGEPD_SHIFT_MASK;
}

/**  Translate a huge page using its directory entry.
 */
static kdump_status
ppc64_vtop_hugepd(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr,
		  uint64_t hpde, unsigned pdshift)
{
	struct ppc64_data *archdata = ctx->shared->archdata;
	kdump_vaddr_t mask, ptep;
	unsigned long idx;
	uint64_t pte;
	kdump_status res;

	mask = ((kdump_vaddr_t)1 << pdshift) - 1;
	idx = (vaddr & mask) >> hugepd_shift(hpde);
	ptep = ((hpde & ~HUGEPD_SHIFT_MASK) | PD_HUGE) +
		idx * sizeof(uint64_t);

	res = read_u64(ctx, KDUMP_KVADDR, ptep, 0, "huge PTE", &pte);
	if (res != kdump_ok)
		return res;
	if (!pte)
		return set_error(ctx, kdump_nodata, "huge_pte[%lu] is none",
				 idx);

	*paddr = vtop_final(vaddr, pte, archdata->pg.rpn_shift,
			    hugepd_shift(hpde));
	return kdump_ok;
}

static kdump_status
ppc64_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct ppc64_data *archdata = ctx->shared->archdata;
	struct vaddr_parts split;
	kdump_vaddr_t pgdp, pudp, pmdp, ptep;
	uint64_t pgd, pud, pmd, pte;
	kdump_paddr_t base;
	kdump_status res;

	vaddr_split(&archdata->pgform, vaddr, &split);

	vtop_hook(ctx, 3, KDUMP_KVADDR, archdata->pg.pg, split.pgd);
	pgdp = archdata->pg.pg + split.pgd * sizeof(uint64_t);
	res = read_u64(ctx, KDUMP_KVADDR, pgdp, 1, "PGD entry", &pgd);
	if (res != kdump_ok)
		return res;
	if (!pgd)
		return set_error(ctx, kdump_nodata, "pgd[%u] is none",
				 split.pgd);

	if (is_hugepte(pgd)) {
		*paddr = vtop_final(vaddr, pgd, archdata->pg.rpn_shift,
				    archdata->pg.pgd_shift);
		return kdump_ok;
	}
	if (is_hugepd(pgd))
		return ppc64_vtop_hugepd(ctx, vaddr, paddr,
					 pgd, archdata->pg.pgd_shift);

	base = (pgd & (~archdata->pg.pgd_mask));
	if (archdata->pgform.pud_bits != 0) {
		vtop_hook(ctx, 2, KDUMP_KVADDR, base, split.pud);
		pudp = base + split.pud * sizeof(uint64_t);
		res = read_u64(ctx, KDUMP_KVADDR, pudp, 1, "PUD entry", &pud);
		if (res != kdump_ok)
			return res;

		if (!pud)
			return set_error(ctx, kdump_nodata, "pud[%u] is none",
					 split.pud);

		if (is_hugepte(pud)) {
			*paddr = vtop_final(vaddr, pud, archdata->pg.rpn_shift,
					    archdata->pg.pud_shift);
			return kdump_ok;
		}
		if (is_hugepd(pud))
			return ppc64_vtop_hugepd(ctx, vaddr, paddr,
						 pud, archdata->pg.pud_shift);

		base = pud & (~archdata->pg.pud_mask);
	}

	vtop_hook(ctx, 1, KDUMP_KVADDR, base, split.pmd);
	pmdp = base + split.pmd * sizeof(uint64_t);
	res = read_u64(ctx, KDUMP_KVADDR, pmdp, 0, "PMD entry", &pmd);
	if (res != kdump_ok)
		return res;
	if (!pmd)
		return set_error(ctx, kdump_nodata, "pmd[%u] is none",
				 split.pmd);

	if (is_hugepte(pmd)) {
		*paddr = vtop_final(vaddr, pmd, archdata->pg.rpn_shift,
				    archdata->pg.pmd_shift);
		return kdump_ok;
	}
	if (is_hugepd(pmd))
		return ppc64_vtop_hugepd(ctx, vaddr, paddr,
					 pmd, archdata->pg.pmd_shift);

	base = pmd & (~archdata->pg.pmd_mask);
	vtop_hook(ctx, 0, KDUMP_KVADDR, base, split.pte);
	ptep = base + split.pte * sizeof(uint64_t);
	res = read_u64(ctx, KDUMP_KVADDR, ptep, 0, "PTE entry", &pte);
	if (res != kdump_ok)
		return res;
	if (!pte)
		return set_error(ctx, kdump_nodata, "pte[%u] is none",
				 split.pte);

	*paddr = vtop_final(vaddr, pte, archdata->pg.rpn_shift,
			    archdata->pg.pte_shift);
	return kdump_ok;
}


static kdump_status
ppc64_vtop_init(kdump_ctx *ctx)
{
	struct ppc64_data *archdata = ctx->shared->archdata;
	kdump_vaddr_t addr, vmal;
	struct attr_data *base, *attr;
	char *endp;
	unsigned long off_vm_struct_addr;
	size_t sz = get_ptr_size(ctx);
	kdump_status res;

	rwlock_unlock(&ctx->shared->lock);
	res = get_symbol_val(ctx, "swapper_pg_dir", &addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot resolve %s",
				 "swapper_pg_dir");
	archdata->pg.pg = addr;

	rwlock_unlock(&ctx->shared->lock);
	res = get_symbol_val(ctx, "_stext", &addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot resolve %s",
				 "_stext");
	set_phys_base(ctx, addr);

	flush_vtop_map(&ctx->shared->vtop_map);
	res = set_vtop_xlat(&ctx->shared->vtop_map,
			    addr, addr + 0x1000000000000000,
			    KDUMP_XLAT_DIRECT, addr);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot set up directmap");

	rwlock_unlock(&ctx->shared->lock);
	res = get_symbol_val(ctx, "vmlist", &addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot resolve %s",
				 "vmlist");

	base = gattr(ctx, GKI_linux_vmcoreinfo_lines);
	attr = lookup_dir_attr(ctx->shared, base,
			       "OFFSET(vm_struct.addr)",
			       sizeof("OFFSET(vm_struct.addr)") - 1);
	if (!attr || validate_attr(ctx, attr) != kdump_ok)
		return set_error(ctx, kdump_nodata,
				 "No OFFSET(vm_struct.addr) in VMCOREINFO");
	off_vm_struct_addr = strtoul(attr_value(attr)->string, &endp, 10);
	if (*endp)
		return set_error(ctx, kdump_dataerr,
				 "Invalid value of OFFSET(vm_struct.addr)");

	res = readp_locked(ctx, KDUMP_KVADDR, addr, &addr, &sz);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read vmlist.addr");

	addr = dump64toh(ctx, addr);
	addr += off_vm_struct_addr;

	res = readp_locked(ctx, KDUMP_KVADDR, addr, &vmal, &sz);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read vmlist.addr");

	vmal = dump64toh(ctx, vmal);

	res = set_vtop_xlat(&ctx->shared->vtop_map,
			    vmal, VIRTADDR_MAX,
			    KDUMP_XLAT_VTOP, addr);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot set up pagetable mapping");

	return kdump_ok;
}

static kdump_status
ppc64_init(kdump_ctx *ctx)
{
	struct ppc64_data *archdata;
	unsigned shift;
	int pagesize;

	archdata = calloc(1, sizeof(struct ppc64_data));
	if (!archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate ppc64 private data");

	ctx->shared->archdata = archdata;

	pagesize = get_page_size(ctx);

	if (pagesize == _64K) {
		archdata->pgform.page_bits = 16;
		archdata->pgform.pte_bits = 12;
		archdata->pgform.pmd_bits = 12;
		archdata->pgform.pud_bits = 0;
		archdata->pgform.pgd_bits = 4;
		archdata->pg.pmd_mask = 0x1ff;
		archdata->pg.pud_mask = 0x1ff;
		archdata->pg.pgd_mask = 0x1ff;
		archdata->pg.rpn_shift = 30;

	} else
		return set_error(ctx, kdump_nodata, "PAGESIZE == %d", pagesize);

	shift = get_page_shift(ctx);
	archdata->pg.pte_shift = shift;
	shift += archdata->pgform.pte_bits;
	archdata->pg.pmd_shift = shift;
	shift += archdata->pgform.pmd_bits;
	archdata->pg.pud_shift = shift;
	shift += archdata->pgform.pgd_bits;
	archdata->pg.pgd_shift = shift;

	return kdump_ok;
}

static void
ppc64_cleanup(struct kdump_shared *shared)
{
	struct ppc64_data *archdata = shared->archdata;

	free(archdata);
	shared->archdata = NULL;
}

/** @cond TARGET_ABI */

#define ELF_NGREG 49

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

static kdump_status
process_ppc64_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, kdump_dataerr,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs64(ctx, get_num_cpus(ctx), reg_names,
			     status->pr_reg, ELF_NGREG);

	if (res != kdump_ok)
		return res;

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);

	return kdump_ok;
}

const struct arch_ops ppc64_ops = {
	.init = ppc64_init,
	.vtop_init = ppc64_vtop_init,
	.process_prstatus = process_ppc64_prstatus,
	.vtop = ppc64_vtop,
	.cleanup = ppc64_cleanup,
};
