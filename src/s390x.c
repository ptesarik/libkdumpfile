/** @internal @file src/s390x.c
 * @brief Functions for the s390x architecture.
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

#include <string.h>
#include <stdlib.h>
#include <elf.h>

/** @cond TARGET_ABI */

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

#define OS_INFO_MAGIC	0x4f53494e464f535aULL

#define OS_INFO_VMCOREINFO	0
#define OS_INFO_REIPL_BLOCK	1

struct os_info_entry {
        uint64_t addr;
	uint64_t size;
        uint32_t csum;
} __attribute__ ((packed));

struct os_info {
	uint64_t magic;
	uint32_t csum;
	uint16_t version_major;
	uint16_t version_minor;
	uint64_t crashkernel_addr;
	uint64_t crashkernel_size;
	struct os_info_entry entry[2];
	/* possibly more fields up to PAGE_SIZE */
} __attribute__ ((packed));

/** @endcond */

/**  Private data for the s390x arch-specific methods.
 */
struct s390x_data {
	kdump_paddr_t pgdir;	/**< Top-level page directory address */
	int pgttype;
};

struct vtop_control {
	kdump_vaddr_t vaddr;
	kdump_paddr_t paddr;

	int tbltype;
	unsigned len, off;
};

static kdump_status
read_pte(kdump_ctx *ctx, struct vtop_control *ctl, unsigned idx,
	 uint64_t *pentry)
{
	kdump_paddr_t addr;

	addr = ctl->paddr + idx * sizeof(uint64_t);
	return read_u64(ctx, KDUMP_KPHYSADDR, addr,
			(ctl->tbltype > 0), "page table entry", pentry);
}

static kdump_status
xlat(kdump_ctx *ctx, struct vtop_control *ctl)
{
	unsigned idx;
	uint64_t entry;
	kdump_status res;

	switch(ctl->tbltype) {
	case 3: idx = reg1_index(ctl->vaddr); break;
	case 2: idx = pgd_index(ctl->vaddr); break;
	case 1: idx = pud_index(ctl->vaddr); break;
	case 0: idx = pmd_index(ctl->vaddr); break;
	default:
		return set_error(ctx, kdump_dataerr,
				 "Unknown translation table type: %d",
				 ctl->tbltype);
	}

	if (idx < ctl->off || idx >= ctl->len)
		return set_error(ctx, kdump_nodata,
				 "Page table index %u not within %u and %u",
				 idx, ctl->off, ctl->len);

	res = read_pte(ctx, ctl, idx, &entry);
	if (res != kdump_ok)
		return res;

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
	--ctl->tbltype;

	return kdump_ok;
}

static kdump_status
s390x_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct s390x_data *archdata = ctx->shared->archdata;
	struct vtop_control ctl;
	uint64_t entry;
	kdump_status ret;

	if (archdata->pgdir == ~(kdump_addr_t)0)
		return set_error(ctx, kdump_invalid,
				 "VTOP translation not initialized");

	/* TODO: This should be initialised from kernel_asce, but for
	 * now, just assume that the top-level table is always maximum size.
	 */
	ctl.paddr = archdata->pgdir;
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

	ret = read_pte(ctx, &ctl, pte_index(ctl.vaddr), &entry);
	if (ret != kdump_ok)
		return ret;

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
	struct s390x_data *archdata = ctx->shared->archdata;
	struct page_io pio;
	uint64_t entry, *p, *endp;
	unsigned i;
	kdump_status res;

	p = endp = NULL;
	for (i = 0; i < PTRS_PER_PGD; ++i) {
		if (p >= endp) {
			kdump_paddr_t addr;

			if (p)
				unref_page(ctx, &pio);

			addr = archdata->pgdir + i * sizeof(uint64_t);
			pio.pfn = addr >> PAGE_SHIFT;
			pio.precious = 0;
			res = raw_read_page(ctx, KDUMP_KPHYSADDR, &pio);
			if (res != kdump_ok)
				return set_error(ctx, res,
						 "Page table at %016llx",
						 (unsigned long long)addr);
			p = pio.ce->data + (addr & ~PAGE_MASK);
			endp = pio.ce->data + PAGE_SIZE;
		}
		entry = dump64toh(ctx, *p++);
		if (!PTE_I(entry)) {
			unref_page(ctx, &pio);
			archdata->pgttype = PTE_TT(entry);
			return kdump_ok;
		}
	}

	if (p)
		unref_page(ctx, &pio);

	return set_error(ctx, kdump_nodata, "Empty top-level page table");
}

static kdump_status
s390x_vtop_init(kdump_ctx *ctx)
{
	struct s390x_data *archdata = ctx->shared->archdata;
	kdump_vaddr_t addr;
	kdump_status ret;

	rwlock_unlock(&ctx->shared->lock);
	ret = get_symbol_val(ctx, "swapper_pg_dir", &addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (ret == kdump_ok) {
		archdata->pgdir = addr;
		ret = determine_pgttype(ctx);
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot determine paging type");
		ret = set_vtop_xlat(&ctx->shared->vtop_map,
				    0, VIRTADDR_MAX,
				    KDUMP_XLAT_VTOP, 0);
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot set up pagetable mapping");
	}

	rwlock_unlock(&ctx->shared->lock);
	ret = get_symbol_val(ctx, "high_memory", &addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (ret == kdump_ok) {
		uint64_t highmem;
		size_t sz = sizeof(highmem);
		/* In identity mapping virtual == physical */
		ret = readp_locked(ctx, KDUMP_KPHYSADDR, addr, &highmem, &sz);
		if (ret != kdump_ok)
			return ret;
		highmem = dump64toh(ctx, highmem);

		ret = set_vtop_xlat(&ctx->shared->vtop_map,
				    0, highmem,
				    KDUMP_XLAT_DIRECT, 0);
		if (ret != kdump_ok)
			return set_error(ctx, ret, "Cannot set up directmap");
	} else if (archdata->pgdir == ~(kdump_addr_t)0)
		return set_error(ctx, kdump_nodata,
				 "Cannot determine size of direct mapping");

	return kdump_ok;
}

static kdump_status
read_os_info_from_lowcore(kdump_ctx *ctx)
{
	unsigned char os_info_buf[PAGE_SIZE];
	struct os_info *os_info;
	size_t sz;
	uint64_t addr;
	uint64_t magic;
	uint32_t csum, csum_expect;
	void *vmcoreinfo;
	kdump_status ret;

	sz = sizeof(addr);
	ret = readp_locked(ctx, KDUMP_KPHYSADDR, LC_OS_INFO, &addr, &sz);
	if (ret != kdump_ok)
		return set_error(ctx, ret, "Cannot read LC_OS_INFO pointer");
	addr = dump64toh(ctx, addr);
	if (!addr)
		return set_error(ctx, kdump_nodata,
				 "NULL os_info pointer");
	if (addr % PAGE_SIZE != 0)
		return set_error(ctx, kdump_dataerr,
				 "Invalid os_info pointer: 0x%llx",
				 (unsigned long long) addr);

	sz = PAGE_SIZE;
	ret = readp_locked(ctx, KDUMP_KPHYSADDR, addr, os_info_buf, &sz);
	if (ret != kdump_ok)
		return set_error(ctx, ret, "Cannot read os_info");
	os_info = (struct os_info*) os_info_buf;

	magic = dump64toh(ctx, os_info->magic);
	if (magic != OS_INFO_MAGIC)
		return set_error(ctx, kdump_nodata,
				 "Invalid os_info magic: 0x%llx",
				 (unsigned long long) magic);

	sz = PAGE_SIZE - offsetof(struct os_info, version_major);
	csum = cksum32(&os_info->version_major, sz, 0);
	csum_expect = dump32toh(ctx, os_info->csum);
	if (csum != csum_expect)
		return set_error(ctx, kdump_dataerr,
				 "Invalid os_info checksum: 0x%lx != 0x%lx",
				 (unsigned long) csum,
				 (unsigned long) csum_expect);

	sz = dump64toh(ctx, os_info->entry[OS_INFO_VMCOREINFO].size);
	addr = dump64toh(ctx, os_info->entry[OS_INFO_VMCOREINFO].addr);
	if (!sz || !addr)
		return set_error(ctx, kdump_nodata,
				 "No VMCOREINFO found in os_info");

	vmcoreinfo = ctx_malloc(sz, ctx, "VMCOREINFO buffer");
	if (!vmcoreinfo)
		return kdump_syserr;

	ret = readp_locked(ctx, KDUMP_KPHYSADDR, addr, vmcoreinfo, &sz);
	if (ret != kdump_ok) {
		free(vmcoreinfo);
		return set_error(ctx, ret, "Cannot read VMCOREINFO");
	}

	csum = cksum32(vmcoreinfo, sz, 0);
	csum_expect = dump32toh(ctx, os_info->entry[OS_INFO_VMCOREINFO].csum);
	if (csum != csum_expect) {
		free(vmcoreinfo);
		return set_error(ctx, kdump_dataerr,
				 "Invalid VMCOREINFO checksum: 0x%lx != 0x%lx",
				 (unsigned long) csum,
				 (unsigned long) csum_expect);
	}

	ret = set_attr_sized_string(ctx, gattr(ctx, GKI_linux_vmcoreinfo_raw),
				    ATTR_DEFAULT, vmcoreinfo, sz);
	free(vmcoreinfo);
	if (ret != kdump_ok)
		return set_error(ctx, ret, "Cannot set VMCOREINFO");

	return kdump_ok;
}

static kdump_status
read_vmcoreinfo_from_lowcore(kdump_ctx *ctx)
{
	uint64_t addr;
	Elf64_Nhdr hdr;
	void *note;
	size_t sz, notesz, descoff;
	kdump_status ret;

	sz = sizeof(addr);
	ret = readp_locked(ctx, KDUMP_KPHYSADDR, LC_VMCORE_INFO, &addr, &sz);
	if (ret != kdump_ok)
		return ret;
	addr = dump64toh(ctx, addr);
	if (!addr)
		return set_error(ctx, kdump_nodata,
				 "NULL VMCOREINFO pointer");

	sz = sizeof(hdr);
	ret = readp_locked(ctx, KDUMP_KPHYSADDR, addr, &hdr, &sz);
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
	ret = readp_locked(ctx, KDUMP_KPHYSADDR, addr, note, &sz);
	if (ret == kdump_ok &&
	    !memcmp(note + sizeof(Elf64_Nhdr), "VMCOREINFO", hdr.n_namesz))
		ret = process_notes(ctx, note, notesz);

	free(note);
	return ret;
}

static kdump_status
process_lowcore_info(kdump_ctx *ctx)
{
	kdump_status ret;

	ret = read_os_info_from_lowcore(ctx);
	if (ret == kdump_nodata) {
		clear_error(ctx);
		ret = read_vmcoreinfo_from_lowcore(ctx);
	}
	return ret;
}

static kdump_status
s390x_init(kdump_ctx *ctx)
{
	struct s390x_data *archdata;
	kdump_status ret;

	archdata = calloc(1, sizeof(struct s390x_data));
	if (!archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate s390x private data");
	ctx->shared->archdata = archdata;

	archdata->pgdir = ~(kdump_addr_t)0;

	process_lowcore_info(ctx);
	clear_error(ctx);

	ret = set_vtop_xlat(&ctx->shared->vtop_map,
			    0, VIRTADDR_MAX,
			    KDUMP_XLAT_DIRECT, 0);
	if (ret != kdump_ok)
		return set_error(ctx, ret, "Cannot set up initial directmap");

	return kdump_ok;
}

static void
s390x_cleanup(struct kdump_shared *shared)
{
	struct s390x_data *archdata = shared->archdata;

	free(archdata);
	shared->archdata = NULL;
}

const struct arch_ops s390x_ops = {
	.init = s390x_init,
	.vtop_init = s390x_vtop_init,
	.vtop = s390x_vtop,
	.cleanup = s390x_cleanup,
};
