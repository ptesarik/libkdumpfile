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

#define NMAPS 11
static addrxlat_map_t *map[NMAPS];

#define NDEFS 4
static addrxlat_def_t *def[NDEFS];
static unsigned long ref[NDEFS];

#define CANARY_EXTRA_REF	100
static addrxlat_def_t *canary;
static unsigned long canaryref;

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
	addrxlat_map_t *oldmap, *newmap;
	size_t oldn, newn, i;

	if (ptr != curmap)
		return orig_realloc(ptr, size);

	oldmap = ptr;
	if (size) {
		newmap = malloc(size);
		if (!newmap)
			return newmap;

		oldn = oldmap ? oldmap->n : 0;
		newn = ((size - offsetof(addrxlat_map_t, ranges)) /
			sizeof(newmap->ranges[0]));
		if (newn > oldn) {
			if (oldmap)
				memcpy(newmap, oldmap,
				       offsetof(addrxlat_map_t, ranges) +
				       oldn * sizeof(oldmap->ranges[0]));
			for (i = oldn; i < newn; ++i)
				newmap->ranges[i].def = canary;
		} else
			memcpy(newmap, oldmap, size);
	} else
		newmap = NULL;

	free(oldmap);
	curmap = newmap;
	return newmap;
}

static void
printmap(const addrxlat_map_t *map)
{
	size_t i, j;
	addrxlat_addr_t addr = 0;
	for (i = 0; i < map->n; ++i) {
		printf("%"ADDRXLAT_PRIxADDR"-%"ADDRXLAT_PRIxADDR": ",
		       addr, addr + map->ranges[i].endoff);
		if (!map->ranges[i].def)
			printf("NULL\n");
		else if (map->ranges[i].def == canary)
			printf("CANARY\n");
		else {
			for (j = 0; j < NDEFS; ++j)
				if (map->ranges[i].def == def[j]) {
					printf("#%zu\n", j);
					break;
				}
			if (j >= NDEFS)
				printf("UNKNOWN: %p\n", map->ranges[i].def);
		}

		addr += map->ranges[i].endoff + 1;
	}
}

static void
check_def_ref(unsigned idx, unsigned long expect)
{
	addrxlat_def_incref(def[idx]);
	ref[idx] = addrxlat_def_decref(def[idx]);
	if (ref[idx] != expect) {
		printf("Wrong reference count for #%d: %lu != %lu\n",
		       idx, ref[idx], expect);
		result = TEST_FAIL;
	}
}

static void
check_canary(void)
{
	unsigned long ref;
	addrxlat_def_incref(canary);
	ref = addrxlat_def_decref(canary);
	if (ref != canaryref) {
		printf("Canary reference changed by %ld!\n", ref - canaryref);
		canaryref = ref;
		result = TEST_FAIL;
	}
}

static void
map_set(addrxlat_map_t **pmap, addrxlat_addr_t addr,
	const addrxlat_range_t *range)
{
	addrxlat_map_t *newmap;
	curmap = *pmap;
	newmap = addrxlat_map_set(curmap, addr, range);
	curmap = NULL;
	if (!newmap) {
		perror("Cannot reallocate map");
		exit(TEST_ERR);
	}
	*pmap = newmap;
	check_canary();
}

static void
split_middle(addrxlat_map_t **pmap)
{
	addrxlat_range_t range;

	range.endoff = ADDRXLAT_ADDR_MAX;
	range.def = def[0];
	map_set(pmap, 0, &range);
	check_def_ref(0, ++ref[0]);
	range.endoff = 0xffff;
	range.def = def[1];
	map_set(pmap, 0x10000, &range);
	check_def_ref(0, ++ref[0]);
	check_def_ref(1, ++ref[1]);
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

	canary = addrxlat_def_new();
	if (!canary) {
		perror("Cannot allocate canary");
		return TEST_ERR;
	}
	for (i = 0; i < CANARY_EXTRA_REF; ++i)
		canaryref = addrxlat_def_incref(canary);

	for (i = 0; i < NDEFS; ++i) {
		def[i] = addrxlat_def_new();
		if (!def[i]) {
			perror("Cannot allocate addrxlat definition");
			return TEST_ERR;
		}
		check_def_ref(i, ++ref[i]);
	}

	puts("empty -> single region:");
	range.endoff = ADDRXLAT_ADDR_MAX;
	range.def = def[0];
	map_set(&map[0], 0, &range);
	check_def_ref(0, ++ref[0]);
	printmap(map[0]);

	puts("\nreplace single region:");
	range.endoff = ADDRXLAT_ADDR_MAX;
	range.def = def[1];
	map_set(&map[0], 0, &range);
	check_def_ref(0, --ref[0]);
	check_def_ref(1, ++ref[1]);
	printmap(map[0]);

	puts("\nempty -> begin:");
	range.endoff = 0xffff;
	range.def = def[0];
	map_set(&map[1], 0, &range);
	check_def_ref(0, ++ref[0]);
	printmap(map[1]);

	puts("\nempty -> end:");
	range.endoff = 0xffff;
	range.def = def[0];
	map_set(&map[2], ADDRXLAT_ADDR_MAX - range.endoff, &range);
	check_def_ref(0, ++ref[0]);
	printmap(map[2]);

	puts("\nempty -> middle:");
	range.endoff = 0xffff;
	range.def = def[0];
	map_set(&map[3], 0x10000, &range);
	check_def_ref(0, ++ref[0]);
	printmap(map[3]);

	puts("\nsplit begin:");
	range.endoff = 0xffff;
	range.def = def[0];
	map_set(&map[0], 0, &range);
	check_def_ref(0, ++ref[0]);
	check_def_ref(1, ref[1]);
	printmap(map[0]);

	puts("\nsplit end:");
	range.endoff = 0xffff;
	range.def = def[2];
	map_set(&map[0], ADDRXLAT_ADDR_MAX - range.endoff, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, ref[1]);
	check_def_ref(2, ++ref[2]);
	printmap(map[0]);

	puts("\nsplit middle:");
	split_middle(&map[4]);
	printmap(map[4]);

	puts("\nreplace middle:");
	range.endoff = 0xffff;
	range.def = def[2];
	map_set(&map[4], 0x10000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, --ref[1]);
	check_def_ref(2, ++ref[2]);
	printmap(map[4]);

	puts("\nmerge down:");
	range.endoff= 0xffff;
	range.def = def[2];
	map_set(&map[4], 0, &range);
	check_def_ref(0, --ref[0]);
	check_def_ref(2, ref[2]);
	printmap(map[4]);

	puts("\nmerge up:");
	range.endoff = 0xffff;
	range.def = def[2];
	map_set(&map[4], 0x20000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(2, ref[2]);
	printmap(map[4]);

	puts("\nmerge both:");
	split_middle(&map[5]);
	range.endoff = 0xffff;
	range.def = def[0];
	map_set(&map[5], 0x10000, &range);
	check_def_ref(0, --ref[0]);
	check_def_ref(1, --ref[1]);
	printmap(map[5]);

	puts("\nmerge overlap down:");
	split_middle(&map[6]);
	range.endoff = 0x7fff;
	range.def = def[1];
	map_set(&map[6], 0xc000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, ref[1]);
	printmap(map[6]);

	puts("\nmerge overlap up:");
	range.endoff = 0x7fff;
	range.def = def[1];
	map_set(&map[6], 0x1c000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, ref[1]);
	printmap(map[6]);

	puts("\nmerge inner:");
	range.endoff = 0x7fff;
	range.def = def[1];
	map_set(&map[6], 0x14000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, ref[1]);
	printmap(map[6]);

	puts("\noverlap down:");
	split_middle(&map[7]);
	range.endoff = 0xffff;
	range.def = def[2];
	map_set(&map[7], 0x8000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, ref[1]);
	check_def_ref(2, ++ref[2]);
	printmap(map[7]);

	puts("\noverlap up:");
	split_middle(&map[8]);
	range.endoff = 0xffff;
	range.def = def[2];
	map_set(&map[8], 0x18000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, ref[1]);
	check_def_ref(2, ++ref[2]);
	printmap(map[8]);

	puts("\noverlap both:");
	split_middle(&map[9]);
	range.endoff = 0x1ffff;
	range.def = def[2];
	map_set(&map[9], 0x8000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, --ref[1]);
	check_def_ref(2, ++ref[2]);
	printmap(map[9]);

	puts("\noverlap multiple:");
	split_middle(&map[10]);
	range.endoff = 0xffff;
	range.def = def[2];
	map_set(&map[10], 0x20000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(2, ++ref[2]);
	range.endoff = 0x2ffff;
	range.def = def[3];
	map_set(&map[10], 0x8000, &range);
	check_def_ref(0, ref[0]);
	check_def_ref(1, --ref[1]);
	check_def_ref(2, --ref[2]);
	check_def_ref(3, ++ref[3]);
	printmap(map[10]);

	/* Cleanup must not crash */
	for (i = 0; i < NMAPS; ++i) {
		addrxlat_map_clear(map[i]);
		free(map[i]);
	}
	for (i = 0; i < NDEFS; ++i)
		if (addrxlat_def_decref(def[i])) {
			printf("Leaked reference to #%u\n", i);
			result = TEST_FAIL;
		}

	return result;
}
