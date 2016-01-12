/* Virtual-to-physical address translation.
   Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#define RGN_ALLOC_INC 32

kdump_status
set_vtop_xlat(struct vtop_map *map, kdump_vaddr_t first, kdump_vaddr_t last,
	      kdump_xlat_t xlat, kdump_vaddr_t phys_off)
{
	struct kdump_vaddr_region *rgn, *prevrgn;
	kdump_vaddr_t rfirst, rlast;
	unsigned left;
	int numinc;

	rgn = map->region;
	rfirst = 0;
	for (left = map->num_regions; left > 0; --left) {
		if (first <= rfirst + rgn->max_off)
			break;
		rfirst += rgn->max_off + 1;
		++rgn;
	}
	rlast = rfirst - 1;

	prevrgn = rgn;
	numinc = 3;
	if (first == rfirst)
		--numinc;
	if (rgn) {
		for ( ; left > 0; --left) {
			--numinc;
			rlast += rgn->max_off + 1;
			if (rlast > last)
				break;
			++rgn;
		}
	} else if (last == rlast)
		--numinc;

	if (numinc) {
		int idx = (map->num_regions - 1) % RGN_ALLOC_INC;
		if (idx + numinc >= RGN_ALLOC_INC) {
			struct kdump_vaddr_region *newrgn;
			unsigned newalloc = map->num_regions - idx +
				2 * RGN_ALLOC_INC;
			newrgn = realloc(map->region,
					 newalloc * sizeof(*newrgn));
			if (!newrgn)
				return kdump_syserr;

			if (!rgn) {
				rgn = prevrgn = newrgn;
				rgn->max_off = KDUMP_ADDR_MAX;
				rgn->xlat = KDUMP_XLAT_NONE;
				++map->num_regions;
				++left;
				--numinc;
			} else {
				rgn = newrgn + (rgn - map->region);
				prevrgn = newrgn + (prevrgn - map->region);
			}
			map->region = newrgn;
		}
		map->num_regions += numinc;

		memmove(rgn + numinc, rgn,
			left * sizeof(struct kdump_vaddr_region));
	}

	if (last != rlast)
		rgn[numinc].max_off = rlast - last - 1;
	if (first != rfirst) {
		prevrgn->max_off = first - rfirst - 1;
		++prevrgn;
	}

	prevrgn->max_off = last - first;
	prevrgn->phys_off = phys_off;
	prevrgn->xlat = xlat;
	return kdump_ok;
}

void
flush_vtop_map(struct vtop_map *map)
{
	if (map->region)
		free(map->region);
	map->region = NULL;
	map->num_regions = 0;
}

kdump_xlat_t
get_vtop_xlat(struct vtop_map *map, kdump_vaddr_t vaddr,
	      kdump_paddr_t *phys_off)
{
	struct kdump_vaddr_region *rgn;
	kdump_vaddr_t rfirst;
	unsigned left;

	rgn = map->region;
	rfirst = 0;
	for (left = map->num_regions; left > 0; --left) {
		if (vaddr <= rfirst + rgn->max_off)
			break;
		rfirst += rgn->max_off + 1;
		++rgn;
	}
	if (!rgn)
		return KDUMP_XLAT_NONE;

	*phys_off = rgn->phys_off;
	return rgn->xlat;
}

/**  Set default translation to VTOP (page table) translation
 */
static void
default_to_vtop(struct vtop_map *map)
{
	struct kdump_vaddr_region *rgn;
	for (rgn = map->region; rgn < &map->region[map->num_regions]; ++rgn)
		if (rgn->xlat == KDUMP_XLAT_NONE)
			rgn->xlat = KDUMP_XLAT_VTOP;
}

kdump_status
kdump_vtop_init(kdump_ctx *ctx)
{
	kdump_status res;

	clear_error(ctx);

	if (!ctx->arch_ops || !ctx->arch_ops->vtop_init)
		return kdump_unsupported;

	res = ctx->arch_ops->vtop_init(ctx);
	if (res != kdump_ok)
		return res;

	default_to_vtop(&ctx->vtop_map);
	return kdump_ok;
}

kdump_status
kdump_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	kdump_xlat_t xlat;
	kdump_paddr_t phys_off;

	clear_error(ctx);

	xlat = get_vtop_xlat(&ctx->vtop_map, vaddr, &phys_off);
	switch (xlat) {
	case KDUMP_XLAT_NONE:
		return set_error(ctx, kdump_nodata,
				 "Unhandled virtual address");

	case KDUMP_XLAT_INVALID:
		return set_error(ctx, kdump_invalid,
				 "Invalid virtual address");

	case KDUMP_XLAT_VTOP:
		if (!ctx->arch_ops || !ctx->arch_ops->vtop)
			return set_error(ctx, kdump_unsupported,
					 "VTOP translation not available");
		return ctx->arch_ops->vtop(ctx, vaddr, paddr);

	case KDUMP_XLAT_DIRECT:
		*paddr = vaddr - phys_off;
		return kdump_ok;

	case KDUMP_XLAT_KTEXT:
		*paddr = vaddr - phys_off + get_phys_base(ctx);
		return kdump_ok;
	};

	/* unknown translation method */
	return set_error(ctx, kdump_dataerr,
			 "Invalid translation method: %d", (int)xlat);
}
