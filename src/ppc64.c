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
	unsigned l1_bits;
	unsigned l2_bits;
	unsigned l3_bits;
	unsigned l4_bits;
};

struct ppc64_data {
	struct paging_form pgform;
	struct {
		kdump_vaddr_t l2_mask;

		unsigned l1_shift;
		unsigned l2_shift;
		unsigned l3_shift;
		unsigned l4_shift;

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

static int vtoplog = 0;
#define L(format, ...) if (vtoplog) fprintf (stderr, __FILE__":%d: " format, __LINE__, ##__VA_ARGS__)

/**  Individual parts of a virtual address.
 */
struct vaddr_parts {
	unsigned off;		/**< Offset inside page */
	unsigned l1;		/**< Level-1 page table index */
	unsigned l2;		/**< Level-2 page table index */
	unsigned l3;		/**< Level-3 page table index */
	unsigned l4;		/**< Level-4 page table index */
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
	parts->l1 = addr & (((kdump_vaddr_t)1 << pgform->l1_bits) - 1);
	addr >>= pgform->l1_bits;
	parts->l2 = addr & (((kdump_vaddr_t)1 << pgform->l2_bits) - 1);
	addr >>= pgform->l2_bits;
	parts->l3 = addr & (((kdump_vaddr_t)1 << pgform->l3_bits) - 1);
	addr >>= pgform->l3_bits;
	parts->l4 = addr & (((kdump_vaddr_t)1 << pgform->l4_bits) - 1);
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
	struct ppc64_data *archdata = ctx->archdata;
	kdump_vaddr_t mask, base;
	unsigned long idx;
	uint64_t pte;
	size_t sz;
	kdump_status res;

	base = (hpde & ~HUGEPD_SHIFT_MASK) | PD_HUGE;
	mask = ((kdump_vaddr_t)1 << pdshift) - 1;
	idx = (vaddr & mask) >> hugepd_shift(hpde);

	sz = sizeof(uint64_t);
	res = kdump_readp(ctx,
			  KDUMP_KVADDR, base + idx * sizeof(uint64_t),
			  &pte, &sz);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read hugepage");

	pte = dump64toh(ctx, pte);
	if (!pte)
		return set_error(ctx, kdump_nodata,
				 "Page not present: pte[%lu] = 0x%llx",
				 idx, (unsigned long long) pte);

	*paddr = vtop_final(vaddr, pte, archdata->pg.rpn_shift,
			    hugepd_shift(hpde));
	return kdump_ok;
}

static kdump_status
ppc64_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	struct ppc64_data *archdata = ctx->archdata;
	struct vaddr_parts split;
	kdump_vaddr_t l1e, l2e, l3e, l4e, e;
	kdump_vaddr_t pagemask;
	size_t ps = kdump_ptr_size(ctx);
	kdump_status res;

	vaddr_split(&archdata->pgform, vaddr, &split);

	pagemask = get_page_size(ctx) - 1;

	L("reading l4 %lx\n", archdata->pg.pg + split.l4*ps);

	res = kdump_readp(ctx, KDUMP_KVADDR, archdata->pg.pg + split.l4*ps,
			  &l4e, &ps);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read L4");

	l4e = dump64toh(ctx, l4e);

	if (!l4e) goto notfound;

	if (is_hugepte(l4e)) {
		*paddr = vtop_final(vaddr, l4e, archdata->pg.rpn_shift,
				    archdata->pg.l4_shift);
		return kdump_ok;
	}
	if (is_hugepd(l4e))
		return ppc64_vtop_hugepd(ctx, vaddr, paddr,
					 l4e, archdata->pg.l4_shift);

	L("l4 => %lx\n", l4e);

	if (archdata->pgform.l3_bits != 0) {
		/* TODO: DO ! e = ?*/
		l3e = 0;
		return set_error(ctx, kdump_unsupported, "L3 %lx != 0 not yet supported", l3e);
	} else
		e = l4e;

	res = kdump_readp(ctx, KDUMP_KVADDR, e + split.l2*ps, &l2e, &ps);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read L2");

	l2e = dump64toh(ctx, l2e);

	if (!l2e) goto notfound;

	if (is_hugepte(l2e)) {
		*paddr = vtop_final(vaddr, l2e, archdata->pg.rpn_shift,
				    archdata->pg.l2_shift);
		return kdump_ok;
	}
	if (is_hugepd(l2e))
		return ppc64_vtop_hugepd(ctx, vaddr, paddr,
					 l2e, archdata->pg.l2_shift);

	e = (l2e & (~archdata->pg.l2_mask)) +
		ps*((vaddr>>archdata->pg.l1_shift) & ((1<<archdata->pgform.l1_bits)-1));

	L("l2 => %lx %lx ==> %lx\n", l2e, (l2e & (~archdata->pg.l2_mask)), e);

	res = kdump_readp(ctx,
			  KDUMP_KVADDR, (l2e&~(pagemask)) + (e&(pagemask)),
			  &l1e, &ps);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read L1");

	l1e = dump64toh(ctx, l1e);

	if (!l1e) goto notfound;

	L("l1 %lx => %lx\n", l1e,
		(((l1e>>archdata->pg.rpn_shift)<<archdata->pg.l1_shift)&~(pagemask))
		+((pagemask)&vaddr));

	*paddr = vtop_final(vaddr, l1e,
			    archdata->pg.rpn_shift, archdata->pg.l1_shift);

	return kdump_ok;

notfound:
	return kdump_nodata;
}


static kdump_status
ppc64_vtop_init(kdump_ctx *ctx)
{
	kdump_vaddr_t addr, vmal;
	const char *val;
	size_t sz = kdump_ptr_size(ctx);
	kdump_status res;

	res = get_symbol_val(ctx, "_stext", &addr);
	if (res != kdump_ok)
		return set_error(ctx, kdump_nodata,
				 "Cannot resolve _stext");
	set_phys_base(ctx, addr);

	flush_vtop_map(&ctx->vtop_map);
	res = set_vtop_xlat(&ctx->vtop_map,
			    addr, addr + 0x1000000000000000,
			    KDUMP_XLAT_DIRECT, addr);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot set up directmap");

	res = get_symbol_val(ctx, "vmlist", &addr);
	if (res != kdump_ok)
		return set_error(ctx, kdump_nodata,
				 "Cannot resolve vmlist");

	val = kdump_vmcoreinfo_row(ctx, "OFFSET(vm_struct.addr)");
	if (!val)
		return set_error(ctx, kdump_nodata,
				 "No OFFSET(vm_struct.addr) in VMCOREINFO");

	res = kdump_readp(ctx, KDUMP_KVADDR, addr, &addr, &sz);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read vmlist.addr");

	addr = dump64toh(ctx, addr);
	addr += strtoull(val, NULL, 10);

	res = kdump_readp(ctx, KDUMP_KVADDR, addr, &vmal, &sz);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read vmlist.addr");

	vmal = dump64toh(ctx, vmal);

	res = set_vtop_xlat(&ctx->vtop_map,
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
	kdump_vaddr_t pgtaddr;
	unsigned shift;
	kdump_status ret;
	int pagesize;

	archdata = calloc(1, sizeof(struct ppc64_data));
	if (!archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate ppc64 private data");

	ctx->archdata = archdata;

	pagesize = get_page_size(ctx);

	if (pagesize == _64K) {
		archdata->pgform.page_bits = 16;
		archdata->pgform.l1_bits = 12;
		archdata->pgform.l2_bits = 12;
		archdata->pgform.l3_bits = 0;
		archdata->pgform.l4_bits = 4;
		archdata->pg.l2_mask = 0x1ff;
		archdata->pg.rpn_shift = 30;

	} else
		return set_error(ctx, kdump_nodata, "PAGESIZE == %d", pagesize);

	shift = get_page_shift(ctx);
	archdata->pg.l1_shift = shift;
	shift += archdata->pgform.l1_bits;
	archdata->pg.l2_shift = shift;
	shift += archdata->pgform.l2_bits;
	archdata->pg.l3_shift = shift;
	shift += archdata->pgform.l3_bits;
	archdata->pg.l4_shift = shift;

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

	res = set_cpu_regs64(ctx, get_num_cpus(ctx), reg_names,
			     status->pr_reg, ELF_NGREG);

	if (res != kdump_ok)
		return res;

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);

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
