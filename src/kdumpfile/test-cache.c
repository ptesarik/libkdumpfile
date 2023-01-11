/** @internal @file src/kdumpfile/test-cache.c
 * @brief Test the cache algorithm.
 */
/* Copyright (C) Petr Tesarik <petr@tesarici.cz>

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

#include <stdio.h>

#define TEST_OK     0
#define TEST_FAIL   1
#define TEST_ERR   99

#define CACHE_SIZE  8

static void
poison_stack(void)
{
	unsigned short largearray[2048];
	unsigned i;
	for (i = 0; i < ARRAY_SIZE(largearray); ++i)
		largearray[i] = 0xDEAD;
	/* Do not let the compiler optimize it out. */
	__asm__ volatile("" :: "g" (largearray) : "memory");
}

int
main(int argc, char **argv)
{
	struct cache *cache;
	struct cache_entry *entry;
	unsigned i;

	cache = cache_alloc(CACHE_SIZE, 0);
	if (!cache) {
		perror("Cannot allocate cache");
		return TEST_ERR;
	}

	/* Fill the cache, keeping a reference to each entry */
	for (i = 0; i < CACHE_SIZE; ++i) {
		entry = cache_get_entry(cache, i);
		if (!entry) {
			fprintf(stderr, "Cannot get cache entry %u\n", i);
			return TEST_FAIL;
		}
		if (!entry->data) {
			fprintf(stderr, "NULL data for entry %u\n", i);
			return TEST_FAIL;
		}
		cache_insert(cache, entry);
	}

	/* Make sure that a full cache returns NULL. */
	entry = cache_get_entry(cache, i);
	if (entry) {
		fprintf(stderr, "Cache allocated over capacity???\n");
		return TEST_FAIL;
	}

	/* Lookup each entry for a second time. */
	for (i = 0; i < CACHE_SIZE; ++i) {
		entry = cache_get_entry(cache, i);
		if (!entry) {
			fprintf(stderr, "Cannot find cached entry %u\n", i);
			return TEST_FAIL;
		}
		cache_put_entry(cache, entry);
	}
	/* Put the last entry once again (match the initial loop). */
	cache_put_entry(cache, entry);

	/* Evict last entry and move it into ghost probed. */
	entry = cache_get_entry(cache, CACHE_SIZE);
	if (!entry) {
		fprintf(stderr, "Cannot allocate after put\n");
		return TEST_FAIL;
	}
	if (!entry->data) {
		fprintf(stderr, "NULL data for entry %u\n", CACHE_SIZE);
		return TEST_FAIL;
	}
	/* Put the newly allocated entry into the unused partition. */
	cache_discard(cache, entry);
	poison_stack();

	/* Re-allocate the evicted entry. */
	entry = cache_get_entry(cache, CACHE_SIZE - 1);
	if (!entry) {
		fprintf(stderr, "Cannot allocate after discard\n");
		return TEST_FAIL;
	}
	if (!entry->data) {
		fprintf(stderr, "NULL data for entry after discard\n");
		return TEST_FAIL;
	}
	cache_insert(cache, entry);
	cache_put_entry(cache, entry);

	/* Evict the last entry again. */
	entry = cache_get_entry(cache, CACHE_SIZE);
	if (!entry || !entry->data) {
		fprintf(stderr, "Second eviction failed.\n");
		return TEST_FAIL;
	}
	cache_insert(cache, entry);
	cache_put_entry(cache, entry);
	poison_stack();

	/* Re-initialize from ghost list. */
	entry = cache_get_entry(cache, CACHE_SIZE - 1);
	if (!entry) {
		fprintf(stderr, "Cannot allocate after insert\n");
		return TEST_FAIL;
	}
	if (!entry->data) {
		fprintf(stderr, "NULL data for entry after insert\n");
		return TEST_FAIL;
	}
	cache_insert(cache, entry);
	cache_put_entry(cache, entry);

	cache_free(cache);
	return TEST_OK;
}
