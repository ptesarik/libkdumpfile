/* Test translation map low-level handling.
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <addrxlat.h>

#include "testutil.h"

#define NMAPS 16
static addrxlat_map_t *map[NMAPS];

#define CANARY	-100

static int result;

/** Current address translation map. */
static void *curmap;

static void* (*orig_realloc)(void *ptr, size_t size);

/** Evil realloc.
 * @param ptr   Allocated memory block, or @c NULL.
 * @param size  New desired size.
 *
 * When reallocating the current translation map (as denoted by @c curmap),
 * inject a pointer to a canary translation definition, so if any code
 * accesses an (uninitialized) element beyond the original array boundaries,
 * it will hit this canary.
 */
void *
realloc(void *ptr, size_t size)
{
	addrxlat_range_t *oldranges, *newranges;
	size_t oldn, newn, i;

	if (ptr != addrxlat_map_ranges(curmap))
		return orig_realloc(ptr, size);

	oldranges = ptr;
	if (size) {
		newranges = malloc(size);
		if (!newranges)
			return newranges;

		oldn = addrxlat_map_len(curmap);
		newn = size / sizeof(*newranges);
		if (newn > oldn) {
			if (oldranges)
				memcpy(newranges, oldranges,
				       oldn * sizeof(*oldranges));
			for (i = oldn; i < newn; ++i)
				newranges[i].meth = CANARY;
		} else
			memcpy(newranges, oldranges, size);
	} else
		newranges = NULL;

	free(oldranges);
	return newranges;
}

static void
printmap(const addrxlat_map_t *map)
{
	size_t i, n;
	addrxlat_addr_t addr;
	const addrxlat_range_t *range;

	n = addrxlat_map_len(map);
	addr = 0;
	range = addrxlat_map_ranges(map);
	for (i = 0; i < n; ++i) {
		printf("%"ADDRXLAT_PRIxADDR"-%"ADDRXLAT_PRIxADDR": ",
		       addr, addr + range->endoff);
		if (range->meth == ADDRXLAT_SYS_METH_NONE)
			printf("NULL\n");
		else if (range->meth == CANARY)
			printf("CANARY\n");
		else
			printf("#%ld\n", (long)range->meth);

		addr += range->endoff + 1;
		++range;
	}
}

static void
map_set(addrxlat_map_t **pmap, addrxlat_addr_t addr,
	const addrxlat_range_t *range)
{
	addrxlat_status status;

	if (!*pmap) {
		addrxlat_map_t *newmap = addrxlat_map_new();
		if (!newmap) {
			perror("Cannot allocate map");
			exit(TEST_ERR);
		}
		*pmap =	newmap;
	}

	curmap = *pmap;
	status = addrxlat_map_set(curmap, addr, range);
	curmap = NULL;
	if (status != ADDRXLAT_OK) {
		fprintf(stderr, "Cannot update map: %s\n",
			addrxlat_strerror(status));
		exit(TEST_ERR);
	}
}

static void
split_middle(addrxlat_map_t **pmap)
{
	addrxlat_range_t range;

	range.endoff = ADDRXLAT_ADDR_MAX;
	range.meth = 0;
	map_set(pmap, 0, &range);
	range.endoff = 0xffff;
	range.meth = 1;
	map_set(pmap, 0x10000, &range);
}

int
main(int argc, char **argv)
{
	addrxlat_range_t range;
	unsigned i;

	result = TEST_OK;

	orig_realloc = dlsym(RTLD_NEXT, "realloc");
	if (!orig_realloc) {
		fprintf(stderr, "Cannot get original realloc() address: %s\n",
			dlerror());
		return TEST_ERR;
	}

	puts("empty -> single region:");
	range.endoff = ADDRXLAT_ADDR_MAX;
	range.meth = 0;
	map_set(&map[0], 0, &range);
	printmap(map[0]);

	puts("\nreplace single region:");
	range.endoff = ADDRXLAT_ADDR_MAX;
	range.meth = 1;
	map_set(&map[0], 0, &range);
	printmap(map[0]);

	puts("\nempty -> begin:");
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[1], 0, &range);
	printmap(map[1]);

	puts("\nempty -> end:");
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[2], ADDRXLAT_ADDR_MAX - range.endoff, &range);
	printmap(map[2]);

	puts("\nempty -> middle:");
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[3], 0x10000, &range);
	printmap(map[3]);

	puts("\nsplit begin:");
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[0], 0, &range);
	printmap(map[0]);

	puts("\nsplit end:");
	range.endoff = 0xffff;
	range.meth = 2;
	map_set(&map[0], ADDRXLAT_ADDR_MAX - range.endoff, &range);
	printmap(map[0]);

	puts("\nsplit middle:");
	split_middle(&map[4]);
	printmap(map[4]);

	puts("\nreplace middle:");
	range.endoff = 0xffff;
	range.meth = 2;
	map_set(&map[4], 0x10000, &range);
	printmap(map[4]);

	puts("\nmerge down:");
	range.endoff= 0xffff;
	range.meth = 2;
	map_set(&map[4], 0, &range);
	printmap(map[4]);

	puts("\nmerge up:");
	range.endoff = 0xffff;
	range.meth = 2;
	map_set(&map[4], 0x20000, &range);
	printmap(map[4]);

	puts("\nmerge both:");
	split_middle(&map[5]);
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[5], 0x10000, &range);
	printmap(map[5]);

	puts("\nmerge overlap down:");
	split_middle(&map[6]);
	range.endoff = 0x7fff;
	range.meth = 1;
	map_set(&map[6], 0xc000, &range);
	printmap(map[6]);

	puts("\nmerge overlap up:");
	range.endoff = 0x7fff;
	range.meth = 1;
	map_set(&map[6], 0x1c000, &range);
	printmap(map[6]);

	puts("\nmerge inner:");
	range.endoff = 0x7fff;
	range.meth = 1;
	map_set(&map[6], 0x14000, &range);
	printmap(map[6]);

	puts("\noverlap down:");
	split_middle(&map[7]);
	range.endoff = 0xffff;
	range.meth = 2;
	map_set(&map[7], 0x8000, &range);
	printmap(map[7]);

	puts("\noverlap up:");
	split_middle(&map[8]);
	range.endoff = 0xffff;
	range.meth = 2;
	map_set(&map[8], 0x18000, &range);
	printmap(map[8]);

	puts("\noverlap both:");
	split_middle(&map[9]);
	range.endoff = 0x1ffff;
	range.meth = 2;
	map_set(&map[9], 0x8000, &range);
	printmap(map[9]);

	puts("\noverlap multiple:");
	split_middle(&map[10]);
	range.endoff = 0xffff;
	range.meth = 2;
	map_set(&map[10], 0x20000, &range);
	range.endoff = 0x2ffff;
	range.meth = 3;
	map_set(&map[10], 0x8000, &range);
	printmap(map[10]);

	puts("\npunch hole:");
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[11], 0x10000, &range);
	range.endoff = 0xfff;
	range.meth = ADDRXLAT_SYS_METH_NONE;
	map_set(&map[11], 0x18000, &range);
	printmap(map[11]);

	puts("\nmerge hole:");
	range.endoff = 0xffff;
	range.meth = ADDRXLAT_SYS_METH_NONE;
	map_set(&map[12], 0x10000, &range);
	printmap(map[12]);

	puts("\nno merge beyond end of map:");
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[13], 0, &range);
	map_set(&map[13], 0x20000, &range);
	/* remove the last element, keeping a known value at [n+1] */
	range.endoff = ADDRXLAT_ADDR_MAX - 0x30000;
	map_set(&map[13], 0x30000, &range);
	range.endoff = 0xffff;
	range.meth = ADDRXLAT_SYS_METH_NONE;
	map_set(&map[13], ADDRXLAT_ADDR_MAX - range.endoff, &range);
	printmap(map[13]);

	puts("\nduplicate punch hole:");
	map[14] = addrxlat_map_copy(map[11]);
	printmap(map[14]);

	puts("\nno merge with stale data:");
	range.endoff = 0xffff;
	range.meth = 0;
	map_set(&map[15], 0, &range);
	addrxlat_map_clear(map[15]);
	range.endoff = 0x1ffff;
	map_set(&map[15], 0, &range);
	printmap(map[15]);

	/* Cleanup must not crash */
	for (i = 0; i < NMAPS; ++i) {
		addrxlat_map_clear(map[i]);
		free(map[i]);
	}

	return result;
}
