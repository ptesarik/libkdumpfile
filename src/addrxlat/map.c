/** @internal @file src/addrxlat/map.c
 * @brief Address translation maps.
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
#include <string.h>

#include "addrxlat-priv.h"

DEFINE_INTERNAL(map_set)

addrxlat_map_t *
addrxlat_map_set(addrxlat_map_t *map, addrxlat_addr_t addr,
		 const addrxlat_range_t *range)
{
	addrxlat_range_t *first, *last;
	addrxlat_addr_t raddr, rend;
	addrxlat_addr_t end;
	addrxlat_addr_t extend;
	size_t left;
	int delta;
	int i;

	end = addr + range->endoff;

	extend = 0;
	raddr = 0;
	if (map) {
		delta = 2;
		left = map->n;

		/* find first affected region */
		first = map->ranges;
		while (left > 0) {
			if (raddr + first->endoff >= addr)
				break;
			raddr += first->endoff + 1;
			++first, --left;
		}
		/* include the previous region if it can be merged */
		if (raddr && raddr == addr && first[-1].meth == range->meth) {
			--first, ++left;
			raddr -= first->endoff + 1;
		}

		/* find last affected region */
		last = first;
		rend = raddr + first->endoff;
		while (left > 0) {
			if (rend >= end)
				break;
			--delta;
			++last, --left;
			rend += last->endoff + 1;
		}
		/* include the following region if it can be merged */
		if (left > 0 && rend == end && last[1].meth == range->meth) {
			--delta;
			++last, --left;
			rend += last->endoff + 1;
		}

		/* merge up and/or down */
		if (first->meth == range->meth) {
			extend += addr - raddr;
			raddr = addr;
		}
		if (last->meth == range->meth) {
			extend += rend - end;
			rend = end;
		}
	} else {
		delta = 3;
		left = 0;
		first = last = NULL;
		rend = ADDRXLAT_ADDR_MAX;
	}

	/* split begin and/or end */
	if (addr == raddr)
		--delta;
	if (rend == end)
		--delta;

	/* (re-)allocate if growing */
	if (delta > 0) {
		size_t newn = delta + (map ? map->n : 0);
		addrxlat_map_t *newmap =
			realloc(map, offsetof(addrxlat_map_t, ranges) +
				newn * sizeof(newmap->ranges[0]));
		if (!newmap)
			return newmap;

		if (!map) {
			newmap->n = 1;
			first = last = newmap->ranges;
			first->endoff = ADDRXLAT_ADDR_MAX;
			first->meth = NULL;
			++left;
			--delta;
		} else {
			first = &newmap->ranges[first - map->ranges];
			last = &newmap->ranges[last - map->ranges];
		}
		map = newmap;
	}

	/* drop references to overlapped regions */
	for (i = delta; i < 0; ++i)
		if (last[i].meth)
			internal_meth_decref(last[i].meth);
	if (delta) {
		/* if a region is split, take an extra reference  */
		if (delta > 1 && last->meth)
			internal_meth_incref(last->meth);

		memmove(last + delta, last, left * sizeof(*last));
		last += delta;
		map->n += delta;
	}

	/* resize adjacent regions if necessary */
	if (raddr != addr) {
		first->endoff = addr - raddr - 1;
		++first;
	}
	if (rend != end) {
		last->endoff = rend - end - 1;
		--last;
	}

	/* take an extra reference to the new region */
	internal_meth_incref(range->meth);

	/* drop reference to the previous value, unless an unitialized
	 * array entry is being inserted */
	if (delta <= 0 && first->meth)
		internal_meth_decref(first->meth);

	first->endoff = range->endoff + extend;
	first->meth = range->meth;
	return map;
}

DEFINE_INTERNAL(map_search)

const addrxlat_meth_t *
addrxlat_map_search(const addrxlat_map_t *map, addrxlat_addr_t addr)
{
	const addrxlat_range_t *r = map->ranges;
	addrxlat_addr_t raddr = 0;
	size_t left = map ? map->n : 0;

	while (left-- > 0) {
		if (addr <= raddr + r->endoff)
			return r->meth;
		raddr += r->endoff + 1;
		++r;
	}
	return NULL;
}

addrxlat_status
addrxlat_by_map(addrxlat_ctx *ctx, addrxlat_addr_t *paddr,
		const addrxlat_map_t *map)
{
	const addrxlat_meth_t *meth = internal_map_search(map, *paddr);
	return meth
		? internal_walk(ctx, meth, paddr)
		: set_error(ctx, addrxlat_invalid,
			    "No translation method defined");
}

DEFINE_INTERNAL(map_clear)

void
addrxlat_map_clear(addrxlat_map_t *map)
{
	const addrxlat_range_t *r = map->ranges;
	while(map->n--) {
		if (r->meth)
			internal_meth_decref(r->meth);
		++r;
	}
}
