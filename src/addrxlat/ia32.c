/** @internal @file src/addrxlat/ia32.c
 * @brief Routines specific to Intel IA32.
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

#include <stdint.h>
#include <string.h>

#include "addrxlat-priv.h"

#define PGD_PSE_HIGH_SHIFT	13
#define PGD_PSE_HIGH_BITS	8
#define PGD_PSE_HIGH_MASK	(((uint64_t)1 << PGD_PSE_HIGH_BITS)-1)
#define pgd_pse_high(pgd)	\
	((((pgd) >> PGD_PSE_HIGH_SHIFT) & PGD_PSE_HIGH_MASK) << 32)

/* Non-PAE maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX_NONPAE	32
#define PHYSADDR_SIZE_NONPAE	((uint64_t)1 << PHYSADDR_BITS_MAX_NONPAE)
#define PHYSADDR_MASK_NONPAE	(~(PHYSADDR_SIZE_NONPAE-1))

/* PAE maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX_PAE	52
#define PHYSADDR_SIZE_PAE	((uint64_t)1 << PHYSADDR_BITS_MAX_PAE)
#define PHYSADDR_MASK_PAE	(~(PHYSADDR_SIZE_PAE-1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

/* Maximum virtual address (architecture limit) */
#define VIRTADDR_MAX		UINT32_MAX

/** IA32 page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_ia32(addrxlat_step_t *step)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table"
	};
	static const char pte_name[][4] = {
		"pte",
		"pgd",
	};
	const addrxlat_paging_form_t *pf = &step->meth->def.param.pgt.pf;
	const struct pgt_extra_def *pgt = &step->meth->extra.pgt;
	addrxlat_status status;

	status = read_pte(step);
	if (status != addrxlat_ok)
		return status;

	if (!(step->raw_pte & _PAGE_PRESENT))
		return set_error(step->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[step->remain - 1],
				 pte_name[step->remain - 1],
				 (unsigned) step->idx[step->remain],
				 step->raw_pte);

	if (step->remain == 2 && (step->raw_pte & _PAGE_PSE)) {
		--step->remain;
		step->base.addr = (step->raw_pte & pgt->pgt_mask[1]) |
			pgd_pse_high(step->raw_pte);
		step->idx[0] |= step->idx[1] << pf->bits[0];
	} else
		step->base.addr = step->raw_pte & pgt->pgt_mask[0];
	step->base.as = step->meth->def.target_as;

	return addrxlat_continue;
}

/** IA32 PAE page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_ia32_pae(addrxlat_step_t *step)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Page directory",
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pgd",
	};
	const addrxlat_paging_form_t *pf = &step->meth->def.param.pgt.pf;
	const struct pgt_extra_def *pgt = &step->meth->extra.pgt;
	addrxlat_status status;

	status = read_pte(step);
	if (status != addrxlat_ok)
		return status;

	if (!(step->raw_pte & _PAGE_PRESENT))
		return set_error(step->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[step->remain - 1],
				 pte_name[step->remain - 1],
				 (unsigned) step->idx[step->remain],
				 step->raw_pte);

	step->base.addr = step->raw_pte & ~PHYSADDR_MASK_PAE;
	if (step->remain == 2 && (step->raw_pte & _PAGE_PSE)) {
		--step->remain;
		step->base.addr &= pgt->pgt_mask[1];
		step->idx[0] |= step->idx[1] << pf->bits[0];
	} else
		step->base.addr &= pgt->pgt_mask[0];
	step->base.as = step->meth->def.target_as;

	return addrxlat_continue;
}

/** Starting virtual address of Linux direct mapping */
#define LINUX_DIRECTMAP	0xc0000000

/** Starting virtual address of Xen direct mapping */
#define XEN_DIRECTMAP	0xff000000

static const addrxlat_paging_form_t ia32_pf = {
	.pte_format = addrxlat_pte_ia32,
	.levels = 3,
	.bits = { 12, 10, 10 }
};

static const addrxlat_paging_form_t ia32_pf_pae = {
	.pte_format = addrxlat_pte_ia32_pae,
	.levels = 4,
	.bits = { 12, 9, 9, 2 }
};

/** Check whether a page table hierarchy looks like PAE.
 * @param ctl     Initialization data.
 * @param root    Root page table address
 * @param direct  Starting virtual address of direct mapping
 * @returns       Non-zero if PAE, zero if non-PAE, negative on error.
 */
static int
is_pae(struct sys_init_data *ctl, const addrxlat_fulladdr_t *root,
       addrxlat_addr_t direct)
{
	addrxlat_step_t step;
	addrxlat_meth_t meth;
	addrxlat_def_t def;
	addrxlat_status status;

	def.kind = ADDRXLAT_PGT;
	def.target_as = ADDRXLAT_MACHPHYSADDR;
	def.param.pgt.root = *root;

	def.param.pgt.pf = ia32_pf_pae;
	internal_meth_set_def(&meth, &def);
	step.ctx = ctl->ctx;
	step.sys = ctl->sys;
	step.meth = &meth;
	status = internal_launch(&step, direct);
	if (status != addrxlat_ok)
		return -1;
	status = sys_set_physmaps(ctl, PHYSADDR_SIZE_PAE - 1);
	if (status != addrxlat_ok)
		return status;
	status = internal_walk(&step);
	if (status == addrxlat_ok && step.base.addr == 0)
		return 1;

	clear_error(ctl->ctx);
	internal_map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS]);
	internal_map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS]);

	def.param.pgt.pf = ia32_pf;
	internal_meth_set_def(&meth, &def);
	step.ctx = ctl->ctx;
	step.sys = ctl->sys;
	step.meth = &meth;
	status = internal_launch(&step, direct);
	if (status != addrxlat_ok)
		return -1;
	status = sys_set_physmaps(ctl, PHYSADDR_SIZE_NONPAE - 1);
	if (status != addrxlat_ok)
		return status;
	status = internal_walk(&step);
	if (status == addrxlat_ok && step.base.addr == 0)
		return 0;

	clear_error(ctl->ctx);
	internal_map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS]);
	internal_map_clear(ctl->sys->map[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS]);

	return -1;
}

/** Direct mapping, used temporarily to translate swapper_pg_dir */
static const struct sys_region linux_directmap[] = {
	{ LINUX_DIRECTMAP, VIRTADDR_MAX,
	   ADDRXLAT_SYS_METH_DIRECT, SYS_ACT_DIRECT },
	SYS_REGION_END
};

/** Determine PAE status resolving root pgt from symbols.
 * @param ctl  Initialization data.
 * @returns    PAE status, see @ref is_pae.
 */
static addrxlat_status
is_pae_sym(struct sys_init_data *ctl)
{
	addrxlat_fulladdr_t rootpgt;
	addrxlat_status status;

	if (ctl->osdesc->type != addrxlat_os_linux)
		return -1;

	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS,
				linux_directmap);
	if (status != addrxlat_ok)
		return status;

	if (get_symval(ctl->ctx, "swapper_pg_dir",
		       &rootpgt.addr) == addrxlat_ok) {
		rootpgt.as = ADDRXLAT_KVADDR;
		return is_pae(ctl, &rootpgt, LINUX_DIRECTMAP);
	}

	clear_error(ctl->ctx);

	return -1;
}

/** Initialize a translation map for an Intel IA32 (non-pae) OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
sys_ia32_nonpae(struct sys_init_data *ctl)
{
	addrxlat_meth_t *meth;
	addrxlat_def_t def;
	addrxlat_status status;

	status = sys_set_physmaps(ctl, PHYSADDR_SIZE_NONPAE - 1);
	if (status != addrxlat_ok)
		return status;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	def.kind = ADDRXLAT_PGT;
	def.target_as = ADDRXLAT_MACHPHYSADDR;
	if (ctl->popt.val[OPT_rootpgt].set)
		def.param.pgt.root = ctl->popt.val[OPT_rootpgt].fulladdr;
	else
		def.param.pgt.root.as = ADDRXLAT_NOADDR;
	def.param.pgt.pf = ia32_pf;
	internal_meth_set_def(meth, &def);
	return addrxlat_ok;
}

/** Initialize a translation map for an Intel IA32 (pae) OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
static addrxlat_status
sys_ia32_pae(struct sys_init_data *ctl)
{
	addrxlat_meth_t *meth;
	addrxlat_def_t def;
	addrxlat_status status;

	status = sys_set_physmaps(ctl, PHYSADDR_SIZE_PAE - 1);
	if (status != addrxlat_ok)
		return status;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	def.kind = ADDRXLAT_PGT;
	def.target_as = ADDRXLAT_MACHPHYSADDR;
	if (ctl->popt.val[OPT_rootpgt].set)
		def.param.pgt.root = ctl->popt.val[OPT_rootpgt].fulladdr;
	else
		def.param.pgt.root.as = ADDRXLAT_NOADDR;
	def.param.pgt.pf = ia32_pf_pae;
	internal_meth_set_def(meth, &def);
	return addrxlat_ok;
}

/** Initialize a translation map for an Intel IA32 OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_ia32(struct sys_init_data *ctl)
{
	addrxlat_range_t range;
	addrxlat_map_t *newmap;
	long pae;
	struct optval *rootpgtopt;
	addrxlat_status status;

	rootpgtopt = &ctl->popt.val[OPT_rootpgt];

	if (ctl->popt.val[OPT_pae].set)
		pae = ctl->popt.val[OPT_pae].num;
	else if (!rootpgtopt->set)
		pae = is_pae_sym(ctl);
	else if (ctl->osdesc->type == addrxlat_os_linux)
		pae = is_pae(ctl, &rootpgtopt->fulladdr,
			     LINUX_DIRECTMAP);
	else if (ctl->osdesc->type == addrxlat_os_xen)
		pae = is_pae(ctl, &rootpgtopt->fulladdr,
			     XEN_DIRECTMAP);
	else
		pae = -1;

	if (pae < 0)
		return set_error(ctl->ctx, addrxlat_notimpl,
				 "Cannot determine PAE state");

	status = sys_ensure_meth(ctl, ADDRXLAT_SYS_METH_PGT);
	if (status != addrxlat_ok)
		return status;

	range.meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	range.endoff = VIRTADDR_MAX;
	newmap = internal_map_set(ctl->sys->map[ADDRXLAT_SYS_MAP_HW],
				  0, &range);
	if (!newmap)
		return set_error(ctl->ctx, addrxlat_nomem,
				 "Cannot set up hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_HW] = newmap;

	newmap = internal_map_dup(ctl->sys->map[ADDRXLAT_SYS_MAP_HW]);
	if (!newmap)
		return set_error(ctl->ctx, addrxlat_nomem,
				 "Cannot duplicate hardware mapping");
	ctl->sys->map[ADDRXLAT_SYS_MAP_KV_PHYS] = newmap;

	return pae
		? sys_ia32_pae(ctl)
		: sys_ia32_nonpae(ctl);
}
