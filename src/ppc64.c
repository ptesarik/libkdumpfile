/* Functions for the ppc64 architecture.
   Copyright (C) 2015

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
#include <errno.h>
#include <elf.h>

#define TRAC {fprintf(stderr, __FILE__"::%d: TRACEUR\n", __LINE__);}

#define VIRTADDR_BITS_MAX	64
#define VIRTADDR_MAX		UINT64_MAX

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

struct ppc64_data {
	struct {
		size_t size;
		char *l4;
		char *l3;
		char *l2;
		char *l1;

		kdump_vaddr_t l4_mask;
		kdump_vaddr_t l2_mask;

		int l1_size;
		int l2_size;
		int l3_size;
		int l4_size;

		int l1_shift;
		int l2_shift;
		int l3_shift;
		int l4_shift;

		int pte_shift;

		kdump_vaddr_t pg;
	} pg;
	int pgttype;
};

#define _64K (1<<16)

#define PAGE_SIZE (kdump_pagesize(a))
#define PAGE_OFFSET(a) (PAGE_SIZE(a)-1)
#define PAGE_MASK(a) (~PAGE_OFFSET(a))
#define PAGE_BASE(a,x) ((x) & PAGE_MASK(a))

#define PD_HUGE           0x8000000000000000
#define HUGE_PTE_MASK     0x03
#define HUGEPD_SHIFT_MASK 0x3f

static int vtoplog = 0;
#define L(format, ...) vtoplog && fprintf (stderr, __FILE__":%d: " format, __LINE__, ##__VA_ARGS__)

enum {
	NORMAL = 0,
	HUGEPG,
	HUGEPD
};

static int ishuge(kdump_vaddr_t pte)
{
	if (pte & HUGE_PTE_MASK)
		return HUGEPG;
	else if ((pte & PD_HUGE) == 0)
		return HUGEPD;
	else
		return NORMAL;
}

static void vaddr_split (struct ppc64_data *archdata, kdump_vaddr_t addr, int *l4, int *l3, int *l2, int *l1, kdump_vaddr_t *off)
{
	*l4 = (addr >> archdata->pg.l4_shift) & archdata->pg.l4_mask;
	*l3 = (addr >> archdata->pg.l3_shift) & ((1 << archdata->pg.l3_size) - 1);
	*l2 = (addr >> archdata->pg.l2_shift) & ((1 << archdata->pg.l2_size) - 1);
	*l1 = (addr >> archdata->pg.l1_shift) & ((1 << archdata->pg.l1_size) - 1);
	*off = addr & ((1 << archdata->pg.l1_size) - 1);
}

static kdump_status
ppc64_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct ppc64_data *archdata = ctx->archdata;
	uint64_t entry = 0;
	int l1, l2, l3, l4;
	kdump_vaddr_t l1e, l2e, l3e, l4e, e, pt;
	kdump_vaddr_t addr, pg, pagemask;
	kdump_status ret;
	size_t ps = kdump_ptr_size(ctx);
	int huge;

	vaddr_split (archdata, vaddr, &l4, &l3, &l2, &l1, &addr);

	pagemask = archdata->pg.size-1;

	L("reading l4 %p\n", archdata->pg.pg + l4*ps);

	if (kdump_readp(ctx, archdata->pg.pg + l4*ps, &l4e, &ps, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read L4");

	l4e = dump64toh(ctx, l4e);
	huge = ishuge(l4e);
	if (huge) {
		e = l4e;
		goto gohuge;
	}

	L("l4 => %p\n", l4e);

	if (archdata->pg.l3_size != 0) {
		/* TODO: DO ! e = ?*/

		return set_error(ctx, kdump_unsupported, "L3 != 0 not yet supported");

	} else
		e = l4e;

	if (kdump_readp(ctx, e + l2*ps, &l2e, &ps, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read L2");

	l2e = dump64toh(ctx, l2e);

	huge = ishuge(l2e);
	if (huge) {
		e = l2e;
		goto gohuge;
	}

	e = (l2e & (~archdata->pg.l2_mask)) +
		ps*((vaddr>>archdata->pg.l1_shift) & ((1<<archdata->pg.l1_size)-1));

	L("l2 => %p (ps=%d) %p ==> %p\n", l2e, ps, (l2e & (~archdata->pg.l2_mask)), e);

	if (kdump_readp(ctx, (l2e&~(pagemask)) + (e&(pagemask)), &e, &ps, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read L1");

	e = dump64toh(ctx, e);
	L("l1 => %p\n", e);
	L("   => %p\n",
		(((e>>archdata->pg.pte_shift)<<archdata->pg.l1_shift)&~(pagemask))
		+((pagemask)&vaddr));

	*paddr = (((e>>archdata->pg.pte_shift)<<archdata->pg.l1_shift)&~(pagemask))
		+((pagemask)&vaddr);

	return kdump_ok;

gohuge:
	if (kdump_readp(ctx, (e & ~HUGEPD_SHIFT_MASK) | PD_HUGE, &pt, &ps,
		KDUMP_KVADDR) != kdump_ok)

		return set_error(ctx, kdump_unsupported, "Cannot read hugepage");

	*paddr = (((pt>>archdata->pg.pte_shift)<<archdata->pg.l1_shift)&~(pagemask));
}


static kdump_status
ppc64_vtop_init(kdump_ctx *ctx)
{
	struct ppc64_data *archdata = ctx->archdata;
	kdump_vaddr_t addr, vmal;
	kdump_status ret;
	const char *val;
	size_t sz = kdump_ptr_size(ctx);

	val = kdump_vmcoreinfo_row(ctx, "SYMBOL(_stext)");
	if (!val)
		return set_error(ctx, kdump_nodata, "No _stext in VMCOREINFO");

	addr = strtoull(val, NULL, 16);

	set_attr_phys_base(ctx, addr);

	flush_regions(ctx);
	ret = set_region(ctx, addr, addr + 0x1000000000000000, KDUMP_XLAT_DIRECT, addr);
	if (ret != kdump_ok)
		return ret;

	val = kdump_vmcoreinfo_row(ctx, "SYMBOL(vmlist)");
	if (!val)
		return set_error(ctx, kdump_nodata, "No SYMBOL(vmlist) in VMCOREINFO");

	addr = strtoull(val, NULL, 16);

	val = kdump_vmcoreinfo_row(ctx, "OFFSET(vm_struct.addr)");
	if (!val)
		return set_error(ctx, kdump_nodata, "No OFFSET(vm_struct.addr) in VMCOREINFO");

	if (kdump_readp(ctx, addr, &addr, &sz, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read vmlist.addr");

	addr = dump64toh(ctx, addr);
	addr += strtoull(val, NULL, 16);

	if (kdump_readp(ctx, addr, &vmal, &sz, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read vmlist.addr");

	vmal = dump64toh(ctx, vmal);

	ret = set_region(ctx, vmal, VIRTADDR_MAX, KDUMP_XLAT_VTOP, addr);
	if (ret != kdump_ok)
		return ret;

	{
		kdump_paddr_t paddr = 0L;
		ppc64_vtop(ctx, 0xc000000001070000, &paddr);
		L("ppc64_vtop->%p\n", paddr);
		ppc64_vtop(ctx, 0xd000000004d0cde0, &paddr);
		L("ppc64_vtop->%p\n", paddr);
	}

	return kdump_ok;
}

static kdump_status
ppc64_init(kdump_ctx *ctx)
{
	struct ppc64_data *archdata;
	kdump_vaddr_t pgtaddr;
	const char *val;
	kdump_status ret;
	int pagesize;
	const char *pg;

	TRAC


	archdata = calloc(1, sizeof(struct ppc64_data));
	if (!archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate ppc64 private data: %s",
				 strerror(errno));

	ctx->archdata = archdata;

	pagesize = kdump_pagesize(ctx);

	if (pagesize == _64K) {
		archdata->pg.l1_size = 12;
		archdata->pg.l2_size = 12;
		archdata->pg.l3_size = 0;
		archdata->pg.l4_size = 4;
		archdata->pg.l2_mask = 0x1ff;
		archdata->pg.pte_shift = 30;

	} else
		return set_error(ctx, kdump_nodata, "PAGESIZE == %d", pagesize);

	archdata->pg.size = pagesize;

	archdata->pg.l1_shift = kdump_pageshift(ctx);
	archdata->pg.l2_shift = archdata->pg.l1_size + archdata->pg.l1_shift;
	archdata->pg.l3_shift = archdata->pg.l2_size + archdata->pg.l2_shift;
	archdata->pg.l4_shift = archdata->pg.l3_size + archdata->pg.l3_shift;

	archdata->pg.l4 = calloc(1, pagesize);
	archdata->pg.l3 = calloc(1, pagesize);
	archdata->pg.l2 = calloc(1, pagesize);
	archdata->pg.l1 = calloc(1, pagesize);

	L("pagesize=%d,pageshift=%d,pbase=%p\n", kdump_pagesize(ctx), kdump_pageshift(ctx), kdump_phys_base(ctx));

	ret = get_symbol_val(ctx, "swapper_pg_dir", &pgtaddr);
	if (ret == kdump_ok) {
	//	ret = read_pgt(ctx, pgtaddr);
		if (ret != kdump_ok)
			return ret;
	}
	archdata->pg.pg = pgtaddr;
	return kdump_ok;
}

static void
ppc64_cleanup(kdump_ctx *ctx)
{
	struct ppc64_data *archdata = ctx->archdata;

#define FREE(x) if((x)){free(x);(x)=NULL;}
	FREE (archdata->pg.l1)
	FREE (archdata->pg.l2)
	FREE (archdata->pg.l3)
	FREE (archdata->pg.l4)

	free(archdata);
	ctx->archdata = NULL;
}

const struct arch_ops ppc64_ops = {
	.init = ppc64_init,
	.vtop_init = ppc64_vtop_init,
	.vtop = ppc64_vtop,
	.cleanup = ppc64_cleanup,
};
