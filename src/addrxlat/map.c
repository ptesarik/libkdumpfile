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

DEFINE_ALIAS(map_new);

addrxlat_map_t *
addrxlat_map_new(void)
{
	addrxlat_map_t *ret;

	ret = calloc(1, sizeof(addrxlat_map_t));
	if (ret)
		ret->refcnt = 1;
	return ret;
}

DEFINE_ALIAS(map_incref);

unsigned long
addrxlat_map_incref(addrxlat_map_t *map)
{
	return ++map->refcnt;
}

DEFINE_ALIAS(map_decref);

unsigned long
addrxlat_map_decref(addrxlat_map_t *map)
{
	unsigned long refcnt = --map->refcnt;
	if (!refcnt) {
		internal_map_clear(map);
		free(map);
	}
	return refcnt;
}

size_t
addrxlat_map_len(const addrxlat_map_t *map)
{
	return map->n;
}

const addrxlat_range_t *
addrxlat_map_ranges(const addrxlat_map_t *map)
{
	return map->ranges;
}

DEFINE_ALIAS(map_set);

addrxlat_status
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
	if (map->n) {
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
		if (left > 1 && rend == end && last[1].meth == range->meth) {
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
		if (!range->meth) {
			extend = ADDRXLAT_ADDR_MAX - (end - addr);
			raddr = addr;
			rend = end;
		} else
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
		addrxlat_range_t *newranges =
			realloc(map->ranges, newn * sizeof(newranges[0]));
		if (!newranges)
			return ADDRXLAT_ERR_NOMEM;

		if (!first) {
			map->n = 1;
			first = last = newranges;
			first->endoff = ADDRXLAT_ADDR_MAX;
			first->meth = NULL;
			++left;
			--delta;
		} else {
			first = &newranges[first - map->ranges];
			last = &newranges[last - map->ranges];
		}
		map->ranges = newranges;
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
	if (range->meth)
		internal_meth_incref(range->meth);

	/* drop reference to the previous value, unless an unitialized
	 * array entry is being inserted */
	if (delta <= 0 && first->meth)
		internal_meth_decref(first->meth);

	first->endoff = range->endoff + extend;
	first->meth = range->meth;
	return ADDRXLAT_OK;
}

DEFINE_ALIAS(map_search);

addrxlat_meth_t *
addrxlat_map_search(const addrxlat_map_t *map, addrxlat_addr_t addr)
{
	if (map) {
		const addrxlat_range_t *r = map->ranges;
		addrxlat_addr_t raddr = 0;
		size_t left = map->n;

		while (left-- > 0) {
			if (addr <= raddr + r->endoff)
				return r->meth;
			raddr += r->endoff + 1;
			++r;
		}
	}
	return NULL;
}

DEFINE_ALIAS(map_clear);

void
addrxlat_map_clear(addrxlat_map_t *map)
{
	const addrxlat_range_t *r = map->ranges;
	size_t n = map->n;
	while(n--) {
		if (r->meth)
			internal_meth_decref(r->meth);
		++r;
	}
	map->n = 0;
}

DEFINE_ALIAS(map_dup);

addrxlat_map_t *
addrxlat_map_dup(const addrxlat_map_t *map)
{
	const addrxlat_range_t *q;
	addrxlat_range_t *r;
	addrxlat_map_t *ret;
	size_t todo;

	ret = internal_map_new();
	if (!ret || !map)
		return ret;

	ret->ranges = malloc(map->n * sizeof(ret->ranges[0]));
	if (!ret->ranges) {
		internal_map_decref(ret);
		return NULL;
	}

	q = map->ranges;
	r = ret->ranges;
	todo = ret->n = map->n;
	while (todo--) {
		if (q->meth)
			internal_meth_incref(q->meth);
		*r++ = *q++;
	}

	return ret;
}
