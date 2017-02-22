/** @internal @file src/addrxlat/ppc64.c
 * @brief Routines specific to IBM POWER.
 */
/* Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

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

#include "addrxlat-priv.h"

#include <stdlib.h>

/**  Page entry flag for a huge page directory.
 * The corresponding entry is huge if the most significant bit is zero.
 */
#define PD_HUGE           ((addrxlat_pte_t)1 << 63)

/**  Page shift of a huge page directory.
 * If PD_HUGE is zero, the huge page shift is stored in the least
 * significant bits of the entry.
 */
#define HUGEPD_SHIFT_MASK 0x3f

/**  A page table entry is huge if the bottom two bits != 00.
 */
#define HUGE_PTE_MASK     ((addrxlat_pte_t)0x03)

#define MMU_PAGE_4K	0
#define MMU_PAGE_16K	1
#define MMU_PAGE_64K	2
#define MMU_PAGE_64K_AP 3	/* "Admixed pages" (hash64 only) */
#define MMU_PAGE_256K	4
#define MMU_PAGE_1M	5
#define MMU_PAGE_4M	6
#define MMU_PAGE_8M	7
#define MMU_PAGE_16M	8
#define MMU_PAGE_64M	9
#define MMU_PAGE_256M	10
#define MMU_PAGE_1G	11
#define MMU_PAGE_16G	12
#define MMU_PAGE_64G	13

#define MMU_PAGE_COUNT	14

/** Map from MMU page size to page shift. */
static unsigned mmu_pshift[MMU_PAGE_COUNT] = {
	[MMU_PAGE_4K] = 12,
	[MMU_PAGE_16K] = 14,
	[MMU_PAGE_64K] = 16,
	[MMU_PAGE_64K_AP] = 16,
	[MMU_PAGE_256K] = 18,
	[MMU_PAGE_1M] = 20,
	[MMU_PAGE_4M] = 22,
	[MMU_PAGE_8M] = 23,
	[MMU_PAGE_16M] = 24,
	[MMU_PAGE_64M] = 26,
	[MMU_PAGE_256M] = 28,
	[MMU_PAGE_1G] = 30,
	[MMU_PAGE_16G] = 34,
	[MMU_PAGE_64G] = 36,
};

/** Symbolic constant to be used for 64KB (to avoid typos). */
#define _64K (1<<16)

/**  Check whether a Linux page directory is huge.
 * @param pte  Page table entry (value).
 * @returns    Non-zero if this is a huge page directory entry.
 */
static inline int
is_hugepd_linux(addrxlat_pte_t pte)
{
	return !(pte & PD_HUGE);
}

/**  Get the huge page directory shift.
 * @param hpde  Huge page directory entry.
 * @returns     Huge page bit shift.
 */
static inline unsigned
hugepd_shift(addrxlat_pte_t hpde)
{
	unsigned mmu_psize = (hpde & HUGEPD_SHIFT_MASK) >> 2;
	return mmu_psize < MMU_PAGE_COUNT
		? mmu_pshift[mmu_psize]
		: 0U;
}

/**  Translate a Linux huge page using its directory entry.
 * @param step  Current step state.
 * @returns     Always @c addrxlat_continue.
 */
static addrxlat_status
huge_pd_linux(addrxlat_step_t *step)
{
	const addrxlat_paging_form_t *pf = &step->meth->def.param.pgt.pf;
	addrxlat_addr_t off;
	unsigned pdshift;
	unsigned short i;

	pdshift = hugepd_shift(step->raw_pte);
	if (!pdshift)
		return set_error(step->ctx, addrxlat_invalid,
				 "Invalid hugepd shift");

	step->base.addr = (step->raw_pte & ~HUGEPD_SHIFT_MASK) | PD_HUGE;
	step->base.as = ADDRXLAT_KVADDR;

	/* Calculate the total byte offset below current table. */
	off = 0;
	i = step->remain;
	while (--i) {
		off |= step->idx[i];
		off <<= pf->bits[i - 1];
	}

	/* Calculate the index in the huge page table. */
	step->idx[1] = off >> pdshift;

	/* Update the page byte offset. */
	off &= ((addrxlat_addr_t)1 << pdshift) - 1;
	step->idx[0] |= off;

	step->remain = 2;
	return addrxlat_continue;
}

/**  Check whether a Linux page table entry is huge.
 * @param pte  Page table entry (value).
 * @returns    Non-zero if this is a huge page entry.
 */
static inline int
is_hugepte_linux(addrxlat_pte_t pte)
{
	return (pte & HUGE_PTE_MASK) != 0x0;
}

/** Update current step state for Linux huge page.
 * @param state      Current step state.
 * @param rpn_shift  RPN shift.
 * @returns          Always @c addrxlat_continue.
 *
 * This function skips all lower paging levels and updates the state
 * so that the next page table translation step adds the correct page
 * offset and terminates.
 */
static addrxlat_status
huge_page_linux(addrxlat_step_t *step, unsigned rpn_shift)
{
	const addrxlat_paging_form_t *pf = &step->meth->def.param.pgt.pf;

	step->base.addr = (step->raw_pte >> rpn_shift) << pf->bits[0];
	step->base.as = step->meth->def.target_as;
	return pgt_huge_page(step);
}

/** 64-bit IBM POWER Linux page table step function for RPN shift 30.
 * @param step       Current step state.
 * @param rpn_shift  RPN shift.
 * @returns          Error status.
 */
static addrxlat_status
pgt_ppc64_linux(addrxlat_step_t *step, unsigned rpn_shift)
{
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
	};
	const addrxlat_paging_form_t *pf = &step->meth->def.param.pgt.pf;
	const struct pgt_extra_def *pgt = &step->meth->extra.pgt;
	addrxlat_status status;

	status = read_pte(step);
	if (status != addrxlat_ok)
		return status;

	if (!step->raw_pte)
		return set_error(step->ctx, addrxlat_notpresent,
				 "%s[%u] is none",
				 pte_name[step->remain - 1],
				 (unsigned) step->idx[step->remain]);

	if (step->remain > 1) {
		addrxlat_addr_t table_size;

		if (is_hugepte_linux(step->raw_pte))
			return huge_page_linux(step, rpn_shift);

		if (is_hugepd_linux(step->raw_pte))
			return huge_pd_linux(step);

		table_size = ((addrxlat_addr_t)1 << pgt->pte_shift <<
			      pf->bits[step->remain - 1]);
		step->base.addr = step->raw_pte & ~(table_size - 1);
		step->base.as = ADDRXLAT_KVADDR;
	} else {
		step->base.addr =
			(step->raw_pte >> rpn_shift) << pf->bits[0];
		step->base.as = step->meth->def.target_as;
	}

	return addrxlat_continue;
}

/** 64-bit IBM POWER Linux page table step function with RPN shift 30.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_ppc64_linux_rpn30(addrxlat_step_t *step)
{
	return pgt_ppc64_linux(step, 30);
}

/* Linux virtual memory layout */
static const struct sys_region linux_layout[] = {
	{  0x0000000000000000,  0x00000fffffffffff, /* userspace        */
	   ADDRXLAT_SYS_METH_UPGT },
	/* 0x0000100000000000 - 0xbfffffffffffffff     invalid          */
	{  0xc000000000000000,  0xcfffffffffffffff, /* direct mapping   */
	   ADDRXLAT_SYS_METH_DIRECT, SYS_ACT_DIRECT },
	{  0xd000000000000000,  0xd00007ffffffffff, /* vmalloc          */
	   ADDRXLAT_SYS_METH_PGT },
	{  0xd000080000000000,  0xd0000fffffffffff, /* IO mappings      */
	   ADDRXLAT_SYS_METH_PGT },
	/* 0xd000100000000000 - 0xefffffffffffffff     reserved         */
	{  0xf000000000000000,  0xffffffffffffffff, /* vmemmap          */
	   ADDRXLAT_SYS_METH_VMEMMAP },
	SYS_REGION_END
};

/** Get VMEMMAP translation definition.
 * @param ctl  Initialization data.
 * @param def  Translation definition.
 * @returns    Error status.
 */
static addrxlat_status
get_vmemmap_def(struct sys_init_data *ctl, addrxlat_def_t *def)
{
	addrxlat_step_t step =	/* step state surrogate */
		{ .ctx = ctl->ctx, .sys = ctl->sys };
	addrxlat_addr_t vmemmap_list, elem, first_elem;
	addrxlat_fulladdr_t readptr;
	uint64_t data;
	addrxlat_addr_t off_list, off_phys, off_virt;
	unsigned cnt;
	addrxlat_lookup_elem_t *tblp;
	addrxlat_status status;

	status = get_symval(ctl->ctx, "vmemmap_list", &vmemmap_list);
	if (status != addrxlat_ok)
		return status;

	status = get_offsetof(ctl->ctx, "vmemmap_backing", "list", &off_list);
	if (status != addrxlat_ok)
		return status;

	status = get_offsetof(ctl->ctx, "vmemmap_backing", "phys", &off_phys);
	if (status != addrxlat_ok)
		return status;

	status = get_offsetof(ctl->ctx, "vmemmap_backing", "virt_addr",
			      &off_virt);
	if (status != addrxlat_ok)
		return status;

	readptr.as = ADDRXLAT_KVADDR;
	readptr.addr = vmemmap_list;
	status = read64(&step, &readptr, &data, "vmemmap_list");
	if (status != addrxlat_ok)
		return status;
	first_elem = data;

	for (cnt = 0, elem = first_elem; elem != 0; ++cnt) {
		readptr.addr = elem + off_list;
		status = read64(&step, &readptr, &data, "vmemmap list");
		if (status != addrxlat_ok)
			return status;
		elem = data;
	}

	def->param.lookup.nelem = cnt;
	tblp = malloc(cnt * sizeof(addrxlat_lookup_elem_t));
	if (!tblp)
		return set_error(ctl->ctx, addrxlat_nomem,
				 "Cannot allocate VMEMMAP translation");
	def->param.lookup.tbl = tblp;

	for (elem = first_elem; elem != 0; ++tblp) {
		readptr.addr = elem + off_phys;
		status = read64(&step, &readptr, &data, "vmemmap phys");
		if (status != addrxlat_ok)
			goto err_free;
		tblp->orig = data;

		readptr.addr = elem + off_virt;
		status = read64(&step, &readptr, &data, "vmemmap virt");
		if (status != addrxlat_ok)
			goto err_free;
		tblp->dest = data;

		readptr.addr = elem + off_list;
		status = read64(&step, &readptr, &data, "vmemmap list");
		if (status != addrxlat_ok)
			goto err_free;
		elem = data;
	}

	return addrxlat_ok;

 err_free:
	free((void*)def->param.lookup.tbl);
	return status;
}

/** Initialize a translation map for Linux/ppc64.
 * @param ctl  Initialization data.
 * @returns       Error status.
 */
static addrxlat_status
map_linux_ppc64(struct sys_init_data *ctl)
{
	static const addrxlat_paging_form_t ppc64_pf_64k = {
		.pte_format = addrxlat_pte_ppc64_linux_rpn30,
		.levels = 4,
		.bits = { 16, 12, 12, 4 }
	};

	long pagesize;
	addrxlat_meth_t *meth;
	addrxlat_def_t def;
	addrxlat_status status;

	pagesize = ctl->popt.val[OPT_pagesize].set
		? ctl->popt.val[OPT_pagesize].num
		: _64K;		/* default 64k */

	if (pagesize != _64K)
		return set_error(ctl->ctx, addrxlat_notimpl,
				 "Unsupported page size: %ld", pagesize);

	status = sys_set_physmaps(ctl, (1ULL << (64 - 30 + 16)) - 1);
	if (status != addrxlat_ok)
		return status;

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, linux_layout);
	if (status != addrxlat_ok)
		return status;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	def.kind = ADDRXLAT_PGT;
	def.target_as = ADDRXLAT_MACHPHYSADDR;
	def.param.pgt.root.as = ADDRXLAT_NOADDR;
	def.param.pgt.pf = ppc64_pf_64k;
	internal_meth_set_def(meth, &def);

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_UPGT];
	internal_meth_set_def(meth, &def);

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_VMEMMAP];
	if (meth->def.kind == ADDRXLAT_NONE) {
		status = get_vmemmap_def(ctl, &def);
		if (status != addrxlat_ok)
			return status;
		def.kind = ADDRXLAT_LOOKUP;
		def.target_as = ADDRXLAT_KPHYSADDR;
		def.param.lookup.endoff = pagesize - 1;
		internal_meth_set_def(meth, &def);
	}

	return addrxlat_ok;
}

/** Initialize a translation map for a 64-bit IBM POWER OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_ppc64(struct sys_init_data *ctl)
{
	switch (ctl->osdesc->type) {
	case addrxlat_os_linux:
		return map_linux_ppc64(ctl);

	default:
		return set_error(ctl->ctx, addrxlat_notimpl,
				 "OS type not implemented");
	}
}
