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

/* Maximum physical address bits (architectural limit) */
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
 * @param state  Page table walk state.
 * @returns      Error status.
 */
addrxlat_status
pgt_ia32(addrxlat_walk_t *state)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table"
	};
	static const char pte_name[][4] = {
		"pte",
		"pgd",
	};
	const addrxlat_paging_form_t *pf = &state->meth->def.param.pgt.pf;
	const struct pgt_extra_def *pgt = &state->meth->extra.pgt;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(state->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	if (state->level == 2 && (state->raw_pte & _PAGE_PSE)) {
		--state->level;
		state->base.addr = (state->raw_pte & pgt->pgt_mask[1]) |
			pgd_pse_high(state->raw_pte);
		state->idx[0] |= state->idx[1] << pf->bits[0];
	} else
		state->base.addr = state->raw_pte & pgt->pgt_mask[0];

	return addrxlat_continue;
}

/** IA32 PAE page table step function.
 * @param state  Page table walk state.
 * @returns      Error status.
 */
addrxlat_status
pgt_ia32_pae(addrxlat_walk_t *state)
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
	const addrxlat_paging_form_t *pf = &state->meth->def.param.pgt.pf;
	const struct pgt_extra_def *pgt = &state->meth->extra.pgt;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(state->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = state->raw_pte & ~PHYSADDR_MASK_PAE;
	if (state->level == 2 && (state->raw_pte & _PAGE_PSE)) {
		--state->level;
		state->base.addr &= pgt->pgt_mask[1];
		state->idx[0] |= state->idx[1] << pf->bits[0];
	} else
		state->base.addr &= pgt->pgt_mask[0];

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
 * @param ctx     Translation context
 * @param root    Root page table address
 * @param direct  Starting virtual address of direct mapping
 * @returns       Non-zero if PAE, zero if non-PAE, negative on error.
 */
static int
is_pae(addrxlat_ctx_t *ctx, const addrxlat_fulladdr_t *root,
       addrxlat_addr_t direct)
{
	addrxlat_meth_t meth;
	addrxlat_def_t def;
	addrxlat_addr_t addr;
	addrxlat_status status;

	def.kind = ADDRXLAT_PGT;
	def.param.pgt.root = *root;

	def.param.pgt.pf = ia32_pf_pae;
	internal_meth_set_def(&meth, &def);
	addr = direct;
	status = internal_walk(ctx, &meth, &addr);
	if (status == addrxlat_ok && addr == 0)
		return 1;

	def.param.pgt.pf = ia32_pf;
	internal_meth_set_def(&meth, &def);
	addr = direct;
	status = internal_walk(ctx, &meth, &addr);
	if (status == addrxlat_ok && addr == 0)
		return 0;

	return -1;
}

/** Initialize a translation map for an Intel IA32 (non-pae) OS.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 */
static addrxlat_status
osmap_ia32_nonpae(addrxlat_osmap_t *osmap, addrxlat_ctx_t *ctx,
		  const addrxlat_osdesc_t *osdesc)
{
	addrxlat_meth_t *meth;
	addrxlat_def_t def;

	meth = osmap->meth[ADDRXLAT_OSMAP_PGT];
	def.kind = ADDRXLAT_PGT;
	def.param.pgt.pf = ia32_pf;
	def_choose_pgtroot(&def, meth);
	internal_meth_set_def(meth, &def);
	return addrxlat_ok;
}

/** Initialize a translation map for an Intel IA32 (pae) OS.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 */
static addrxlat_status
osmap_ia32_pae(addrxlat_osmap_t *osmap, addrxlat_ctx_t *ctx,
	       const addrxlat_osdesc_t *osdesc)
{
	addrxlat_meth_t *meth;
	addrxlat_def_t def;

	meth = osmap->meth[ADDRXLAT_OSMAP_PGT];
	def.kind = ADDRXLAT_PGT;
	def.param.pgt.pf = ia32_pf_pae;
	def_choose_pgtroot(&def, meth);
	internal_meth_set_def(meth, &def);
	return addrxlat_ok;
}

/** Initialize a translation map for an Intel IA32 OS.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 */
addrxlat_status
osmap_ia32(addrxlat_osmap_t *osmap, addrxlat_ctx_t *ctx,
	   const addrxlat_osdesc_t *osdesc)
{
	addrxlat_range_t range;
	addrxlat_map_t *newmap;
	int pae;

	if (!osdesc->archvar) {
		addrxlat_meth_t *pgtmeth = osmap->meth[ADDRXLAT_OSMAP_PGT];

		if (!pgtmeth)
			pae = -1;
		else if (osdesc->type == addrxlat_os_linux)
			pae = is_pae(ctx, &pgtmeth->def.param.pgt.root,
				     LINUX_DIRECTMAP);
		else if (osdesc->type == addrxlat_os_xen)
			pae = is_pae(ctx, &pgtmeth->def.param.pgt.root,
				     XEN_DIRECTMAP);
		else
			pae = -1;

		if (pae < 0)
			return set_error(ctx, addrxlat_notimpl,
					 "Cannot determine PAE state");
	} else if (!strcmp(osdesc->archvar, "pae"))
		pae = 1;
	else if (!strcmp(osdesc->archvar, "nonpae"))
		pae = 0;
	else
		return set_error(ctx, addrxlat_notimpl,
				 "Unimplemented architecture variant");

	if (!osmap->meth[ADDRXLAT_OSMAP_PGT])
		osmap->meth[ADDRXLAT_OSMAP_PGT] = internal_meth_new();
	if (!osmap->meth[ADDRXLAT_OSMAP_PGT])
		return addrxlat_nomem;

	range.meth = osmap->meth[ADDRXLAT_OSMAP_PGT];
	range.endoff = VIRTADDR_MAX;
	newmap = internal_map_set(osmap->map, 0, &range);
	if (!newmap)
		return set_error(ctx, addrxlat_nomem,
				 "Cannot set up default mapping");
	osmap->map = newmap;

	return pae
		? osmap_ia32_pae(osmap, ctx, osdesc)
		: osmap_ia32_nonpae(osmap, ctx, osdesc);
}
