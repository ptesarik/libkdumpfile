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
#include <elf.h>

#define VIRTADDR_BITS_MAX	64
#define VIRTADDR_MAX		UINT64_MAX

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

#define PAGE_SIZE (kdump_pagesize(a))
#define PAGE_OFFSET(a) (PAGE_SIZE(a)-1)
#define PAGE_MASK(a) (~PAGE_OFFSET(a))
#define PAGE_BASE(a,x) ((x) & PAGE_MASK(a))

#define PD_HUGE           0x8000000000000000
#define HUGE_PTE_MASK     0x03
#define HUGEPD_SHIFT_MASK 0x3f

static int vtoplog = 0;
#define L(format, ...) if (vtoplog) fprintf (stderr, __FILE__":%d: " format, __LINE__, ##__VA_ARGS__)

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

static void vaddr_split (struct ppc64_data *archdata, kdump_vaddr_t addr,
	int *l4, int *l3, int *l2, int *l1, kdump_vaddr_t *off)
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
	int l1, l2, l3, l4;
	kdump_vaddr_t l1e, l2e, l3e, l4e, e, pt;
	kdump_vaddr_t addr, pagemask;
	size_t ps = kdump_ptr_size(ctx);
	int huge;

	vaddr_split (archdata, vaddr, &l4, &l3, &l2, &l1, &addr);

	pagemask = archdata->pg.size-1;

	L("reading l4 %lx\n", archdata->pg.pg + l4*ps);

	if (kdump_readp(ctx, archdata->pg.pg + l4*ps, &l4e, &ps, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read L4");

	l4e = dump64toh(ctx, l4e);

	if (!l4e) goto notfound;

	huge = ishuge(l4e);
	if (huge) {
		e = l4e;
		goto gohuge;
	}

	L("l4 => %lx\n", l4e);

	if (archdata->pg.l3_size != 0) {
		/* TODO: DO ! e = ?*/
		l3e = 0;
		return set_error(ctx, kdump_unsupported, "L3 %lx != 0 not yet supported", l3e);
	} else
		e = l4e;

	if (kdump_readp(ctx, e + l2*ps, &l2e, &ps, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read L2");

	l2e = dump64toh(ctx, l2e);

	if (!l2e) goto notfound;

	huge = ishuge(l2e);
	if (huge) {
		e = l2e;
		goto gohuge;
	}

	e = (l2e & (~archdata->pg.l2_mask)) +
		ps*((vaddr>>archdata->pg.l1_shift) & ((1<<archdata->pg.l1_size)-1));

	L("l2 => %lx %lx ==> %lx\n", l2e, (l2e & (~archdata->pg.l2_mask)), e);

	if (kdump_readp(ctx, (l2e&~(pagemask)) + (e&(pagemask)), &l1e, &ps, KDUMP_KVADDR) != kdump_ok)
		return set_error(ctx, kdump_unsupported, "Cannot read L1");

	l1e = dump64toh(ctx, l1e);

	if (!l1e) goto notfound;

	L("l1 %lx => %lx\n", l1e,
		(((l1e>>archdata->pg.pte_shift)<<archdata->pg.l1_shift)&~(pagemask))
		+((pagemask)&vaddr));

	*paddr = (((l1e>>archdata->pg.pte_shift)<<archdata->pg.l1_shift)&~(pagemask))
		+((pagemask)&vaddr);

	return kdump_ok;

gohuge:
	if (kdump_readp(ctx, (e & ~HUGEPD_SHIFT_MASK) | PD_HUGE, &pt, &ps,
		KDUMP_KVADDR) != kdump_ok)

		return set_error(ctx, kdump_unsupported, "Cannot read hugepage");

	pt = dump64toh(ctx, e);

	if (!pt) goto notfound;

	*paddr = (((pt>>archdata->pg.pte_shift)<<archdata->pg.l1_shift)&~(pagemask));

	return kdump_ok;
notfound:
	return kdump_nodata;
}


static kdump_status
ppc64_vtop_init(kdump_ctx *ctx)
{
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

	return kdump_ok;
}

static kdump_status
ppc64_init(kdump_ctx *ctx)
{
	struct ppc64_data *archdata;
	kdump_vaddr_t pgtaddr;
	kdump_status ret;
	int pagesize;

	archdata = calloc(1, sizeof(struct ppc64_data));
	if (!archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate ppc64 private data");

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

	ret = get_symbol_val(ctx, "swapper_pg_dir", &pgtaddr);
	if (ret == kdump_ok) {
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


static kdump_status
process_ppc64_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, kdump_dataerr,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs64(ctx, get_attr_num_cpus(ctx), reg_names,
			     status->pr_reg, ELF_NGREG);

	if (res != kdump_ok)
		return res;

	set_attr_num_cpus(ctx, get_attr_num_cpus(ctx) + 1);

	return kdump_ok;
}

static const char *
ppc64_reg_name(unsigned index)
{
	return index < ARRAY_SIZE(reg_names)
		? reg_names[index].key
		: NULL;
}


const struct arch_ops ppc64_ops = {
	.init = ppc64_init,
	.vtop_init = ppc64_vtop_init,
	.process_prstatus = process_ppc64_prstatus,
	.reg_name = ppc64_reg_name,
	.vtop = ppc64_vtop,
	.cleanup = ppc64_cleanup,
};
