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
	addrxlat_range_t *r = NULL;
	addrxlat_range_t *prev;
	addrxlat_addr_t raddr = 0;
	addrxlat_addr_t rend = ADDRXLAT_ADDR_MAX;
	size_t left = 0;
	int delta = 3;

	if (map)
		for (r = map->ranges, left = map->n; left > 0; ++r, --left) {
			if (addr <= raddr + r->endoff)
				break;
			raddr += r->endoff + 1;
		}
	prev = r;

	if (addr == raddr)
		--delta;
	rend = raddr - 1;
	while (left > 0) {
		--delta;
		rend += r->endoff + 1;
		if (rend > addr + range->endoff)
			break;
		++r;
		--left;
	}
	if (rend == addr + range->endoff)
		--delta;

	if (delta > 0) {
		size_t newn = delta + (map ? map->n : 0);
		addrxlat_map_t *newmap =
			realloc(map, offsetof(addrxlat_map_t, ranges) +
				newn * sizeof(newmap->ranges[0]));
		if (!newmap)
			return newmap;

		if (!map) {
			newmap->n = 1;
			r = prev = newmap->ranges;
			r->endoff = ADDRXLAT_ADDR_MAX;
			r->def = NULL;
			++left;
			--delta;
		} else {
			r = &newmap->ranges[r - map->ranges];
			prev = &newmap->ranges[prev - map->ranges];
		}
		map = newmap;
	}
	map->n += delta;

	memmove(r + delta, r, left * sizeof(*r));

	if (rend != addr + range->endoff)
		r[delta].endoff = rend - (addr + range->endoff) - 1;
	if (raddr != addr) {
		prev->endoff = addr - raddr - 1;
		++prev;
	}

	*prev = *range;
	return map;
}

DEFINE_INTERNAL(map_search)

const addrxlat_def_t *
addrxlat_map_search(const addrxlat_map_t *map, addrxlat_addr_t addr)
{
	const addrxlat_range_t *r = map->ranges;
	addrxlat_addr_t raddr = 0;
	size_t left = map ? map->n : 0;

	while (left-- > 0) {
		if (addr <= raddr + r->endoff)
			return r->def;
		raddr += r->endoff + 1;
		++r;
	}
	return NULL;
}

addrxlat_status
addrxlat_by_map(addrxlat_ctx *ctx, addrxlat_addr_t *paddr,
		const addrxlat_map_t *map)
{
	const addrxlat_def_t *def = internal_map_search(map, *paddr);
	return def
		? internal_walk(ctx, def, paddr)
		: set_error(ctx, addrxlat_invalid,
			    "No translation defined");
}
