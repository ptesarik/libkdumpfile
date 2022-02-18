/** @internal @file src/addrxlat/s390x.c
 * @brief Routines specific to IBM z/Architecture.
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

/* Use IBM's official bit numbering to match spec... */
#define PTE_MASK(bits)		(((uint64_t)1<<bits) - 1)
#define PTE_VAL(x, shift, bits)	(((x) >> (64-(shift)-(bits))) & PTE_MASK(bits))

#define PTE_FC(x)	PTE_VAL(x, 53, 1)
#define PTE_I(x)	PTE_VAL(x, 58, 1)
#define PTE_TF(x)	PTE_VAL(x, 56, 2)
#define PTE_TT(x)	PTE_VAL(x, 60, 2)
#define PTE_TL(x)	PTE_VAL(x, 62, 2)

/** Page shift (log2 4K). */
#define PAGE_SHIFT		12

/** Page mask. */
#define PAGE_MASK		ADDR_MASK(PAGE_SHIFT)

/** Page-Table Origin mask. */
#define PTO_MASK	ADDR_MASK(11)

/** Segment-Frame Absolute Address mask when FC=0 */
#define SFAA_MASK	ADDR_MASK(20)

/** Region-Frame Absolute Address mask when FC=0 */
#define RFAA_MASK	ADDR_MASK(31)

/* Maximum pointers in the root page table */
#define ROOT_PGT_LEN	2048

/** IBM z/Architecture page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_s390x(addrxlat_step_t *step)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Segment table",
		"Region 3 table",
		"Region 2 table",
		"Region 1 table"
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
		"rg1",		/* Invented; does not exist in the wild. */
	};
	const addrxlat_paging_form_t *pf = &step->meth->param.pgt.pf;
	addrxlat_pte_t pte;
	addrxlat_status status;

	status = read_pte64(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	if (PTE_I(pte))
		return !step->ctx->noerr.notpresent
			? set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
				    "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				    pgt_full_name[step->remain - 1],
				    pte_name[step->remain - 1],
				    (unsigned) step->idx[step->remain],
				    step->raw.pte)
			: ADDRXLAT_ERR_NOTPRESENT;

	if (step->remain >= 2 && PTE_TT(pte) != step->remain - 2)
		return set_error(step->ctx, ADDRXLAT_ERR_INVALID,
				 "Table type field %u in %s",
				 (unsigned) PTE_TT(pte),
				 pgt_full_name[step->remain]);

	step->base.addr = pte;
	step->base.as = step->meth->target_as;

	if (step->remain == 3 && PTE_FC(pte)) {
		step->base.addr &= ~RFAA_MASK;
		return pgt_huge_page(step);
	}

	if (step->remain == 2 && PTE_FC(pte)) {
		step->base.addr &= ~SFAA_MASK;
		return pgt_huge_page(step);
	}

	if (step->remain >= 3) {
		unsigned pgidx = step->idx[step->remain - 1] >>
			(pf->fieldsz[step->remain - 1] - pf->fieldsz[0]);
		if (pgidx < PTE_TF(pte) || pgidx > PTE_TL(pte))
			return !step->ctx->noerr.notpresent
				? set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
					    "%s index %u not within %u and %u",
					    pgt_full_name[step->remain-1],
					    (unsigned) step->idx[step->remain-1],
					    (unsigned) PTE_TF(pte),
					    (unsigned) PTE_TL(pte))
				: ADDRXLAT_ERR_NOTPRESENT;
	}

	step->base.addr &= (step->remain == 2 ? ~PTO_MASK : ~PAGE_MASK);
	if (step->remain == 1)
		step->elemsz = 1;

	return ADDRXLAT_OK;
}

/** Determine OS-specific page table root.
 * @param ctl        Initialization data.
 * @param[out] root  Page table root address (set on successful return).
 * @returns          Error status.
 */
static addrxlat_status
get_pgtroot(struct os_init_data *ctl, addrxlat_fulladdr_t *root)
{
	addrxlat_status status;

	if (opt_isset(ctl->popt, rootpgt))
		*root = ctl->popt.rootpgt;
	else
		root->as = ADDRXLAT_NOADDR;

	if (root->as != ADDRXLAT_NOADDR)
		return ADDRXLAT_OK;

	if (!opt_isset(ctl->popt, os_type))
		status = ADDRXLAT_ERR_NODATA;
	else if (ctl->popt.os_type == ADDRXLAT_OS_LINUX) {
		status = get_symval(ctl->ctx, "swapper_pg_dir", &root->addr);
		if (status == ADDRXLAT_OK) {
			root->as = ADDRXLAT_KPHYSADDR;
			return ADDRXLAT_OK;
		}
	} else
		status = ADDRXLAT_ERR_NOTIMPL;

	return set_error(ctl->ctx, status,
			 "Cannot determine page table root address");
}

/* Use the content of the root page table to determine paging levels.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
get_levels_from_pgt(struct os_init_data *ctl)
{
	addrxlat_step_t step =	/* step state surrogate */
		{ .ctx = ctl->ctx, .sys = ctl->sys };
	addrxlat_fulladdr_t ptr;
	uint64_t entry;
	unsigned i;
	addrxlat_status status;

	ptr = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT].param.pgt.root;
	for (i = 0; i < ROOT_PGT_LEN; ++i) {
		status = read64(&step, &ptr, &entry, "page table");
		if (status != ADDRXLAT_OK)
			return status;
		if (!PTE_I(entry)) {
			ctl->popt.levels = PTE_TT(entry) + 2;
			return ADDRXLAT_OK;
		}
		ptr.addr += sizeof(uint64_t);
	}

	return set_error(ctl->ctx, ADDRXLAT_ERR_NOTPRESENT,
			 "Empty top-level page table");
}

/* Initialize paging form.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
init_paging_form(struct os_init_data *ctl)
{
	static const addrxlat_paging_form_t pf = {
		.pte_format = ADDRXLAT_PTE_S390X,
		.fieldsz = { 12, 8, 11, 11, 11, 11 }
	};

	addrxlat_meth_t *meth;
	long levels;
	addrxlat_status status;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];

	status = get_pgtroot(ctl, &meth->param.pgt.root);
	if (status == ADDRXLAT_OK && !opt_isset(ctl->popt, levels))
		status = get_levels_from_pgt(ctl);
	if (status != ADDRXLAT_OK)
		return status;

	levels = ctl->popt.levels;
	if (levels < 2 || levels > 5)
		return bad_paging_levels(ctl->ctx, levels);

	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;
	meth->param.pgt.pte_mask = 0;
	meth->param.pgt.pf = pf;
	meth->param.pgt.pf.nfields = levels + 1;
	return ADDRXLAT_OK;
}

/** Initialize a translation map for a s390x OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_s390x(struct os_init_data *ctl)
{
	addrxlat_map_t *newmap;
	addrxlat_range_t range;
	addrxlat_status status;

	status = sys_set_physmaps(ctl, ~(uint64_t)0);
	if (status != ADDRXLAT_OK)
		return status;

	status = init_paging_form(ctl);
	if (status == ADDRXLAT_ERR_NODATA) {
		clear_error(ctl->ctx);
		return ADDRXLAT_OK;
	} else if (status != ADDRXLAT_OK)
		return status;

	range.meth = ADDRXLAT_SYS_METH_PGT;
	range.endoff = paging_max_index(&ctl->sys->meth[range.meth].param.pgt.pf);
	newmap = internal_map_new();
	if (!newmap)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
				 "Cannot set up hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_HW] = newmap;
	status = internal_map_set(newmap, 0, &range);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot set up hardware mapping");

	newmap = internal_map_copy(ctl->sys->map[ADDRXLAT_SYS_MAP_HW]);
	if (!newmap)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
				 "Cannot duplicate hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = newmap;

	return ADDRXLAT_OK;
}
