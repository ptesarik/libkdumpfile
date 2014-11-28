/* Functions for the s390x architecture.
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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <elf.h>

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	64
#define VIRTADDR_MAX		UINT64_MAX

/* As of Linux 3.17, region-first tables are not used, but since the
 * architecture limits are already defined, why not prepare in advance?
 * Assume that the maximum table length will be used then...
 */
#define REG1_SHIFT	53
#define PTRS_PER_REG1	2048

#define PGDIR_SHIFT	42
#define PTRS_PER_PGD	2048

#define PUD_SHIFT	31
#define PUD_PSE_SIZE	((uint64_t)1 << PUD_SHIFT)
#define PUD_PSE_MASK	(~(PUD_PSE_SIZE-1))
#define PTRS_PER_PUD	2048

#define PMD_SHIFT	20
#define PMD_PSE_SIZE	((uint64_t)1 << PMD_SHIFT)
#define PMD_PSE_MASK	(~(PMD_PSE_SIZE-1))
#define PTRS_PER_PMD	2048

#define PAGE_SHIFT	12
#define PAGE_SIZE	((uint64_t)1 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))
#define PTRS_PER_PTE	256

#define PTRS_PER_PAGE	512

/* Maximum size of a translation table */
#define PTRS_PER_XLAT_MAX	2048

#define reg1_index(addr) (((addr) >> REG1_SHIFT) & (PTRS_PER_REG1 - 1))
#define pgd_index(addr)	(((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pud_index(addr)	(((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
#define pmd_index(addr)	(((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr)	(((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

/* Bah, use IBM's official bit numbering... */
#define PTE_MASK(bits)		(((uint64_t)1<<bits) - 1)
#define PTE_VAL(x, shift, bits)	(((x) >> (64-(shift)-(bits))) & PTE_MASK(bits))

#define PTE_FC(x)	PTE_VAL(x, 53, 1)
#define PTE_I(x)	PTE_VAL(x, 58, 1)
#define PTE_TF(x)	PTE_VAL(x, 56, 2)
#define PTE_TT(x)	PTE_VAL(x, 60, 2)
#define PTE_TL(x)	PTE_VAL(x, 62, 2)

/* Page-Table Origin has 2K granularity in hardware */
#define PTO_MASK	(~(((uint64_t)1 << 11) - 1))

/* Well-known lowcore addresses */
#define LC_VMCORE_INFO	0x0e0c
#define LC_OS_INFO	0x0e18

struct s390x_data {
	uint64_t *pgt;
	int pgttype;
};

struct vtop_control {
	kdump_vaddr_t vaddr;
	kdump_paddr_t paddr;

	uint64_t *tbl;
	int tbltype;
	unsigned len, off;
	uint64_t tmp[PTRS_PER_XLAT_MAX];
};

static kdump_status
xlat(kdump_ctx *ctx, struct vtop_control *ctl)
{
	unsigned idx;
	uint64_t entry;
	size_t sz;

	switch(ctl->tbltype) {
	case 3: idx = reg1_index(ctl->vaddr); break;
	case 2: idx = pgd_index(ctl->vaddr); break;
	case 1: idx = pud_index(ctl->vaddr); break;
	case 0: idx = pmd_index(ctl->vaddr); break;
	default:
		return set_error(ctx, kdump_unsupported,
				 "Unknown translation table type: %d",
				 ctl->tbltype);
	}

	if (idx < ctl->off || idx >= ctl->len)
		return set_error(ctx, kdump_nodata,
				 "Page table index %u not within %u and %u",
				 idx, ctl->off, ctl->len);

	entry = dump64toh(ctx, ctl->tbl[idx]);
	if (PTE_I(entry))
		return set_error(ctx, kdump_nodata,
				 "Page table not present: tbl%u[%u] = 0x%llx",
				 ctl->tbltype, idx,
				 (unsigned long long) entry);
	if (PTE_TT(entry) != ctl->tbltype)
		return set_error(ctx, kdump_dataerr,
				 "Table type field %d in table %d",
				 (int) PTE_TT(entry), ctl->tbltype);

	if (ctl->tbltype <= 1 && PTE_FC(entry)) {
		uint64_t mask = ctl->tbltype
			? PUD_PSE_MASK
			: PMD_PSE_MASK;

		ctl->paddr = (entry & mask) | (ctl->vaddr & ~mask);
		ctl->off = ctl->len = 0;
		return kdump_ok;
	}

	if (ctl->tbltype >= 1) {
		ctl->paddr = entry & PAGE_MASK;
		ctl->off = PTE_TF(entry) * PTRS_PER_PAGE;
		ctl->len = (PTE_TL(entry) + 1) * PTRS_PER_PAGE;
	} else {
		ctl->paddr = entry & PTO_MASK;
		ctl->off = 0;
		ctl->len = PTRS_PER_PTE;
	}
	ctl->tbl = ctl->tmp;
	--ctl->tbltype;

	sz = (ctl->len - ctl->off) * sizeof(uint64_t);
	return kdump_readp(ctx, ctl->paddr + ctl->off * sizeof(uint64_t),
			   ctl->tbl + ctl->off, &sz, KDUMP_PHYSADDR);
}

static kdump_status
s390x_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct s390x_data *archdata = ctx->archdata;
	struct vtop_control ctl;
	uint64_t entry;
	kdump_status ret;

	if (!archdata->pgt)
		return set_error(ctx, kdump_unsupported,
				 "VTOP translation not initialized");

	/* TODO: This should be initialised from kernel_asce, but for
	 * now, just assume that the top-level table is always maximum size.
	 */
	ctl.tbl = archdata->pgt;
	ctl.tbltype = archdata->pgttype;
	ctl.len = (3 + 1) * PTRS_PER_PAGE;
	ctl.off = 0 * PTRS_PER_PAGE;
	ctl.vaddr = vaddr;

	if ((ctl.tbltype < 3 && reg1_index(vaddr)) ||
	    (ctl.tbltype < 2 && pgd_index(vaddr)) ||
	    (ctl.tbltype < 1 && pud_index(vaddr)))
		return set_error(ctx, kdump_nodata,
				 "Out-of-bounds virtual address");

	while (ctl.tbltype >= 0) {
		ret = xlat(ctx, &ctl);
		if (ret != kdump_ok)
			return ret;

		if (!ctl.len) {
			*paddr = ctl.paddr;
			return kdump_ok;
		}
	}

	entry = dump64toh(ctx, ctl.tbl[pte_index(vaddr)]);
	if (PTE_I(entry))
		return set_error(ctx, kdump_nodata,
				 "Page not present: pte[%u] = 0x%llx",
				 (unsigned) pte_index(vaddr),
				 (unsigned long long) entry);

	*paddr = (entry & PAGE_MASK) | (vaddr & ~PAGE_MASK);
	return kdump_ok;
}

/* TODO: This value should come from kernel_asce, but its lowcore
 *       address is variable and not exported through VMCOREINFO...
 */
static int
determine_pgttype(kdump_ctx *ctx)
{
	struct s390x_data *archdata = ctx->archdata;
	unsigned i;

	for (i = 0; i < PTRS_PER_PGD; ++i) {
		uint64_t entry = dump64toh(ctx, archdata->pgt[i]);
		if (!PTE_I(entry))
			return PTE_TT(entry);
	}

	/* If there are no valid entries, the pgt cannot be used
	 * for translation anyway, and this number does not matter.
	 */
	return 0;
}

static kdump_status
s390x_vtop_init(kdump_ctx *ctx)
{
	struct s390x_data *archdata = ctx->archdata;
	kdump_vaddr_t addr;
	kdump_status ret;

	if (archdata->pgt) {
		archdata->pgttype = determine_pgttype(ctx);
		ret = set_region(ctx, 0, VIRTADDR_MAX, KDUMP_XLAT_VTOP, 0);
		if (ret != kdump_ok)
			return ret;
	}

	ret = kdump_vmcoreinfo_symbol(ctx, "high_memory", &addr);
	if (ret == kdump_ok) {
		uint64_t highmem;
		size_t sz = sizeof(highmem);
		/* In identity mapping virtual == physical */
		ret = kdump_readp(ctx, addr, &highmem, &sz, KDUMP_PHYSADDR);
		if (ret != kdump_ok)
			return ret;
		highmem = dump64toh(ctx, highmem);

		ret = set_region(ctx, 0, highmem, KDUMP_XLAT_DIRECT, 0);
		if (ret != kdump_ok)
			return ret;
	} else if (!archdata->pgt)
		return set_error(ctx, kdump_nodata,
				 "Cannot determine size of direct mapping");

	return kdump_ok;
}

static kdump_status
read_pgt(kdump_ctx *ctx, kdump_vaddr_t pgtaddr)
{
	struct s390x_data *archdata = ctx->archdata;
	uint64_t *pgt;
	size_t sz;
	kdump_status ret;

	pgt = ctx_malloc(sizeof(uint64_t) * PTRS_PER_PGD, ctx, "page table");
	if (!pgt)
		return kdump_syserr;

	sz = sizeof(uint64_t) * PTRS_PER_PGD;
	ret = kdump_readp(ctx, pgtaddr, pgt, &sz, KDUMP_PHYSADDR);
	if (ret == kdump_ok)
		archdata->pgt = pgt;
	else
		free(pgt);

	return ret;
}

static kdump_status
get_vmcoreinfo_from_lowcore(kdump_ctx *ctx)
{
	uint64_t addr;
	Elf64_Nhdr hdr;
	void *note;
	size_t sz, notesz, descoff;
	kdump_status ret;

	sz = sizeof(addr);
	ret = kdump_readp(ctx, LC_VMCORE_INFO, &addr, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok)
		return ret;
	addr = dump64toh(ctx, addr);
	if (!addr)
		return set_error(ctx, kdump_nodata,
				 "NULL VMCOREINFO pointer");

	sz = sizeof(hdr);
	ret = kdump_readp(ctx, addr, &hdr, &sz, KDUMP_PHYSADDR);
	if (ret != kdump_ok)
		return ret;
	hdr.n_namesz = dump32toh(ctx, hdr.n_namesz);
	hdr.n_descsz = dump32toh(ctx, hdr.n_descsz);
	hdr.n_type = dump32toh(ctx, hdr.n_type);

	descoff = sizeof(Elf64_Nhdr) + ((hdr.n_namesz + 3) & ~3);
	notesz = descoff + hdr.n_descsz;
	note = ctx_malloc(notesz, ctx, "VMCOREINFO buffer");
	if (!note)
		return kdump_syserr;

	sz = notesz;
	ret = kdump_readp(ctx, addr, note, &sz, KDUMP_PHYSADDR);
	if (ret == kdump_ok &&
	    !memcmp(note + sizeof(Elf64_Nhdr), "VMCOREINFO", hdr.n_namesz))
		ret = process_notes(ctx, note, notesz);

	free(note);
	return ret;
}

static kdump_status
s390x_init(kdump_ctx *ctx)
{
	kdump_vaddr_t pgtaddr;
	kdump_status ret;

	ctx->archdata = calloc(1, sizeof(struct s390x_data));
	if (!ctx->archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate s390x private data: %s",
				 strerror(errno));

	get_vmcoreinfo_from_lowcore(ctx);
	clear_error(ctx);

	ret = kdump_vmcoreinfo_symbol(ctx, "swapper_pg_dir", &pgtaddr);
	if (ret == kdump_ok) {
		ret = read_pgt(ctx, pgtaddr);
		if (ret != kdump_ok)
			return ret;
	}

	ret = set_region(ctx, 0, VIRTADDR_MAX, KDUMP_XLAT_DIRECT, 0);
	if (ret != kdump_ok)
		return ret;

	return kdump_ok;
}

static void
s390x_cleanup(kdump_ctx *ctx)
{
	struct s390x_data *archdata = ctx->archdata;

	if (archdata->pgt)
		free(archdata->pgt);

	free(archdata);
	ctx->archdata = NULL;
}

const struct arch_ops s390x_ops = {
	.init = s390x_init,
	.vtop_init = s390x_vtop_init,
	.vtop = s390x_vtop,
	.cleanup = s390x_cleanup,
};
