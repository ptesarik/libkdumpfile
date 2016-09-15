/** @internal @file src/addrxlat/x86_64.c
 * @brief Routines specific to AMD64 and Intel 64.
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

#include <stdlib.h>

#include "addrxlat-priv.h"

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX	52
#define PHYSADDR_SIZE		((uint64_t)1 << PHYSADDR_BITS_MAX)
#define PHYSADDR_MASK		(~(PHYSADDR_SIZE-1))

#define _PAGE_BIT_PRESENT	0
#define _PAGE_BIT_PSE		7

#define _PAGE_PRESENT	(1UL << _PAGE_BIT_PRESENT)
#define _PAGE_PSE	(1UL << _PAGE_BIT_PSE)

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	48

#define NONCANONICAL_START	((uint64_t)1<<(VIRTADDR_BITS_MAX-1))
#define NONCANONICAL_END	(~NONCANONICAL_START)
#define VIRTADDR_MAX		UINT64_MAX

/** AMD64 (Intel 64) page table step function.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
pgt_x86_64(addrxlat_walk_t *state)
{
	static const char pgt_full_name[][16] = {
		"Page",
		"Page table",
		"Page directory",
		"PDPT table",
	};
	static const char pte_name[][4] = {
		"pte",
		"pmd",
		"pud",
		"pgd",
	};
	const struct pgt_xlat *pgt = &state->def->pgt;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(state->ctx, addrxlat_notpresent,
				 "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
				 pgt_full_name[state->level - 1],
				 pte_name[state->level - 1],
				 (unsigned) state->idx[state->level],
				 state->raw_pte);

	state->base.as = ADDRXLAT_MACHPHYSADDR;
	state->base.addr = state->raw_pte & ~PHYSADDR_MASK;
	if (state->level >= 2 && state->level <= 3 &&
	    (state->raw_pte & _PAGE_PSE)) {
		state->base.addr &= pgt->pgt_mask[state->level - 1];
		return pgt_huge_page(state);
	}

	state->base.addr &= pgt->pgt_mask[0];
	return addrxlat_continue;
}

/** Create a page table address map for x86_64 canonical regions.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns           New translation map, or @c NULL on error.
 */
static addrxlat_status
canonical_pgt_map(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
		  const addrxlat_osdesc_t *osdesc)
{
	addrxlat_range_t range;
	addrxlat_map_t *newmap;

	range.def = osmap->def[ADDRXLAT_OSMAP_PGT];

	range.endoff = NONCANONICAL_START - 1;
	newmap = internal_map_set(osmap->map, 0, &range);
	if (!newmap)
		goto err;
	osmap->map = newmap;

	range.endoff = VIRTADDR_MAX - NONCANONICAL_END - 1;
	newmap = internal_map_set(osmap->map, NONCANONICAL_END + 1, &range);
	if (!newmap)
		goto err;
	osmap->map = newmap;

	return addrxlat_ok;

 err:
	return set_error(ctx, addrxlat_nomem,
			 "Cannot set up default mapping");
}

/** Initialize a translation map for an x86_64 OS.
 * @param osmap   OS map object.
 * @param ctx     Address translation object.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 */
addrxlat_status
osmap_x86_64(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
	     const addrxlat_osdesc_t *osdesc)
{
	static const addrxlat_paging_form_t x86_64_pf = {
		.pte_format = addrxlat_pte_x86_64,
		.levels = 5,
		.bits = { 12, 9, 9, 9, 9 }
	};
	addrxlat_status status;

	osmap->def[ADDRXLAT_OSMAP_PGT] = internal_def_new();
	if (!osmap->def[ADDRXLAT_OSMAP_PGT])
		return addrxlat_nomem;

	internal_def_set_form(osmap->def[ADDRXLAT_OSMAP_PGT], &x86_64_pf);
	status = canonical_pgt_map(osmap, ctx, osdesc);
	if (status != addrxlat_ok)
		return status;

	return addrxlat_ok;
}
