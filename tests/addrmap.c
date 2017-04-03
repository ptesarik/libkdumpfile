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

static addrxlat_meth_t **meths;
static unsigned nmeth;

static unsigned
get_meth_idx(const addrxlat_meth_t *meth)
{
	unsigned i;

	if (!meth)
		return 0;

	for (i = 0; i < nmeth; ++i)
		if (meths[i] == meth)
			return i;
	return ~0U;
}

static void
printmap(const addrxlat_map_t *map)
{
	addrxlat_addr_t addr;
	const addrxlat_range_t *range;
	size_t i, n;

	n = addrxlat_map_len(map);
	addr = 0;
	range = addrxlat_map_ranges(map);
	for (i = 0; i < n; ++i) {
		printf("0x%"ADDRXLAT_PRIxADDR "-0x%"ADDRXLAT_PRIxADDR ":%u\n",
		       addr, addr + range->endoff,
		       get_meth_idx(range->meth));
		addr += range->endoff + 1;
		++range;
	}
}

int
main(int argc, char **argv)
{
	addrxlat_map_t *map;
	addrxlat_range_t range;
	addrxlat_addr_t addr;
	addrxlat_status status;
	unsigned long methidx;
	char *endp;
	int i;
	int ret;

	map = addrxlat_map_new();
	if (!map) {
		perror("Cannot allocate map");
		return TEST_ERR;
	}
	nmeth = 0;
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

		methidx = strtoul(endp + 1, &endp, 0);
		if (*endp) {
			fprintf(stderr, "Invalid range spec: %s\n", argv[i]);
			return TEST_ERR;
		}
		if (methidx >= nmeth) {
			addrxlat_meth_t **newmeths;
			newmeths = realloc(meths, ((methidx + 1) *
						 sizeof(addrxlat_meth_t *)));
			if (!newmeths) {
				fprintf(stderr, "Cannot enlarge methods array"
					" to %lu elements\n", methidx + 1);
				return TEST_ERR;
			}
			meths = newmeths;
			while (nmeth <= methidx)
				meths[nmeth++] = NULL;
		}
		if (!meths[methidx])
			meths[methidx] = addrxlat_meth_new();
		if (!meths[methidx]) {
			fprintf(stderr, "Cannot allocate method %lu\n",
				methidx);
			return TEST_ERR;
		}

		range.meth = meths[methidx];
		status = addrxlat_map_set(map, addr, &range);
		if (status != ADDRXLAT_OK) {
			fprintf(stderr, "Cannot add range: %s\n",
				addrxlat_strerror(status));
			return TEST_ERR;
		}
	}

	if (map)
		printmap(map);

	addrxlat_map_clear(map);

	ret = TEST_OK;
	while (nmeth-- > 0) {
		unsigned refcnt;

		if (!meths[nmeth])
			continue;

		refcnt = addrxlat_meth_decref(meths[nmeth]);
		if (refcnt) {
			fprintf(stderr, "Leaked %u references to method %u\n",
				refcnt, nmeth);
			ret = TEST_FAIL;
		}
	}

	return ret;
}
