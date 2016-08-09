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

/** Check whether an address is canonical.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Zero if @c state corresponds to a canonical address,
 *               non-zero otherwise.
 *
 * All bits above the virtual address space size must be copies of the
 * highest bit.
 */
static int
is_noncanonical(addrxlat_ctx *ctx, addrxlat_pgt_state_t *state)
{
	const addrxlat_pgt_t *pgt = ctx->pgt;
	unsigned short lvl = pgt->pf.levels;
	struct {
		int bit : 1;
	} s;
	addrxlat_addr_t signext;

	s.bit = state->idx[lvl - 1] >> (pgt->pf.bits[lvl - 1] - 1);
	signext = s.bit & (pgt->pgt_mask[lvl - 1] >> pgt->vaddr_bits);
	return state->idx[lvl] != signext;
}

/** AMD64 (Intel 64) page table step function.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
pgt_x86_64(addrxlat_ctx *ctx, addrxlat_pgt_state_t *state)
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
	const addrxlat_pgt_t *pgt = ctx->pgt;

	if (!state->level)
		return is_noncanonical(ctx, state)
			? set_error(ctx, addrxlat_invalid,
				    "Non-canonical address")
			: addrxlat_continue;

	if (!(state->raw_pte & _PAGE_PRESENT))
		return set_error(ctx, addrxlat_notpresent,
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
		return pgt_huge_page(ctx, state);
	}

	state->base.addr &= pgt->pgt_mask[0];
	return addrxlat_continue;
}

/** Create a page table address map for x86_64 canonical regions.
 * @param ctx         Address translation object.
 * @param[in] osdesc  Description of the operating system.
 * @returns           New translation map, or @c NULL on error.
 */
static addrxlat_map_t *
canonical_pgt_map(addrxlat_ctx *ctx, const addrxlat_osdesc_t *osdesc)
{
	addrxlat_range_t range;
	addrxlat_map_t *map, *newmap;

	range.xlat.method = ADDRXLAT_PGT_IND;
	range.xlat.ppgt = osdesc->pgtaddr;

	range.endoff = NONCANONICAL_START - 1;
	map = internal_map_set(NULL, 0, &range);
	if (!map)
		goto err;

	range.endoff = VIRTADDR_MAX - NONCANONICAL_END - 1;
	newmap = internal_map_set(map, NONCANONICAL_END + 1, &range);
	if (!newmap)
		goto err_free;

	return newmap;

 err_free:
	free(map);
 err:
	set_error(ctx, addrxlat_nomem, "Cannot set up default mapping");
	return NULL;
}

/** Initialize a translation map for an x86_64 OS.
 * @param ctx         Address translation object.
 * @param[in] osdesc  Description of the operating system.
 * @param pgt         Page table translation, updated on successful return.
 * @param[out] pmap   Translation map on successful return.
 * @returns           Error status.
 */
addrxlat_status
map_os_x86_64(addrxlat_ctx *ctx, const addrxlat_osdesc_t *osdesc,
	      addrxlat_pgt_t *pgt, addrxlat_map_t **pmap)
{
	static const addrxlat_paging_form_t x86_64_pf = {
		.pte_format = addrxlat_pte_x86_64,
		.levels = 5,
		.bits = { 12, 9, 9, 9, 9 }
	};
	addrxlat_map_t *map;

	internal_pgt_set_form(pgt, &x86_64_pf);
	map = canonical_pgt_map(ctx, osdesc);
	if (!map)
		return addrxlat_nomem;

	*pmap = map;
	return addrxlat_ok;
}
