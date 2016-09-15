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

static void
printmap(const addrxlat_map_t *map)
{
	addrxlat_addr_t addr = 0;
	size_t i;

	for (i = 0; i < map->n; ++i) {
		printf("0x%"ADDRXLAT_PRIxADDR "-0x%"ADDRXLAT_PRIxADDR ":%u\n",
		       addr, addr + map->ranges[i].endoff,
		       (unsigned)(intptr_t)map->ranges[i].def);
		addr += map->ranges[i].endoff + 1;
	}
}

int
main(int argc, char **argv)
{
	addrxlat_map_t *map;
	addrxlat_range_t range;
	addrxlat_addr_t addr;
	char *endp;
	int i;

	map = NULL;
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

		range.def = (addrxlat_def_t*)(intptr_t)
			strtoul(endp + 1, &endp, 0);
		if (*endp) {
			fprintf(stderr, "Invalid range spec: %s\n", argv[i]);
			return TEST_ERR;
		}

		map = addrxlat_map_set(map, addr, &range);
		if (!map) {
			perror("Cannot add range");
			return TEST_ERR;
		}
	}

	if (map)
		printmap(map);

	return TEST_OK;
}
