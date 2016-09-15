/* Address map manipulation.
   Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

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

#include <stdio.h>
#include <stdlib.h>
#include <addrxlat.h>

#include "testutil.h"

static addrxlat_def_t **defs;
static unsigned ndef;

static unsigned
get_def_idx(const addrxlat_def_t *def)
{
	unsigned i;

	if (!def)
		return 0;

	for (i = 0; i < ndef; ++i)
		if (defs[i] == def)
			return i;
	return ~0U;
}

static void
printmap(const addrxlat_map_t *map)
{
	addrxlat_addr_t addr = 0;
	size_t i;

	for (i = 0; i < map->n; ++i) {
		printf("0x%"ADDRXLAT_PRIxADDR "-0x%"ADDRXLAT_PRIxADDR ":%u\n",
		       addr, addr + map->ranges[i].endoff,
		       get_def_idx(map->ranges[i].def));
		addr += map->ranges[i].endoff + 1;
	}
}

int
main(int argc, char **argv)
{
	addrxlat_map_t *map;
	addrxlat_range_t range;
	addrxlat_addr_t addr;
	unsigned long defidx;
	char *endp;
	int i;
	int ret;

	map = NULL;
	ndef = 0;
	for (i = 1; i < argc; ++i) {
		addr = strtoull(argv[i], &endp, 0);
		if (*endp != '-') {
			fprintf(stderr, "Invalid range spec: %s\n", argv[i]);
			return TEST_ERR;
		}

		range.endoff = strtoull(endp + 1, &endp, 0);
		if (*endp != ':') {
			fprintf(stderr, "Invalid range spec: %s\n", argv[i]);
			return TEST_ERR;
		}
		range.endoff -= addr;

		defidx = strtoul(endp + 1, &endp, 0);
		if (*endp) {
			fprintf(stderr, "Invalid range spec: %s\n", argv[i]);
			return TEST_ERR;
		}
		if (defidx >= ndef) {
			addrxlat_def_t **newdefs;
			newdefs = realloc(defs, ((defidx + 1) *
						 sizeof(addrxlat_def_t *)));
			if (!newdefs) {
				fprintf(stderr, "Cannot enlarge def array to"
					" %lu elements\n", defidx + 1);
				return TEST_ERR;
			}
			defs = newdefs;
			while (ndef <= defidx)
				defs[ndef++] = NULL;
		}
		if (!defs[defidx])
			defs[defidx] = addrxlat_def_new();
		if (!defs[defidx]) {
			fprintf(stderr, "Cannot allocate def %lu\n", defidx);
			return TEST_ERR;
		}

		range.def = defs[defidx];
		map = addrxlat_map_set(map, addr, &range);
		if (!map) {
			perror("Cannot add range");
			return TEST_ERR;
		}
	}

	if (map)
		printmap(map);

	addrxlat_map_clear(map);

	ret = TEST_OK;
	while (ndef-- > 0) {
		unsigned refcnt;

		if (!defs[ndef])
			continue;

		refcnt = addrxlat_def_decref(defs[ndef]);
		if (refcnt) {
			fprintf(stderr, "Leaked %u references to def %u\n",
				refcnt, ndef);
			ret = TEST_FAIL;
		}
	}

	return ret;
}
