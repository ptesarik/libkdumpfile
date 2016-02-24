/** @internal @file src/cache.c
 * @brief Data caching.
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

#define _GNU_SOURCE

#include "kdumpfile-priv.h"

#include <stdlib.h>
#include <limits.h>

/**  Simple cache.
 */
struct cache {
	void *data;		 /**< Actual cache data */
	size_t elemsize;	 /**< Element data size */
	unsigned split;		 /**< Split point between probed and precious
				  *   entries (index of MRU probed entry) */
	int dsplit;		 /**< Desired split point change */
	unsigned gprec;		 /**< Index of MRU precious ghost entry */
	unsigned eprec;		 /**< End of precious entries; this is the
				  *   index of the first unused entry */
	unsigned gprobe;	 /**< Index of MRU probed ghost elentry */
	unsigned eprobe;	 /**< End of probed entries; this is the
				  *   index of the first unused entry */
	unsigned nprobe;	 /**< Total number of probe list entries,
				  *   including ghost and in-flight entries */
	unsigned cap;		 /**< Total cache capacity */
	struct cache_entry ce[]; /**< Cache entries */
};

static struct cache_entry *get_ghost_entry(struct cache *, kdump_pfn_t);
static struct cache_entry *get_missed_entry(struct cache *, kdump_pfn_t);

/**  Check whether the probed cache is empty.
 *
 * @param cache  Cache object.
 *
 * Check if there are any cached entries on the probe list. It does not
 * count ghost entries.
 */
static inline int
probe_cache_empty(struct cache *cache)
{
	return cache->split == cache->gprobe;
}

/**  Check whether the precious cache is empty.
 *
 * @param cache  Cache object.
 *
 * Check if there are any cached entries on the probe list. It does not
 * count ghost entries.
 */
static inline int
prec_cache_empty(struct cache *cache)
{
	return cache->ce[cache->split].next == cache->gprec;
}

/**  Remove a cache entry from the list.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry to be removed.
 * @returns      Pointer to the cache entry (value of @ref entry).
 */
static struct cache_entry *
remove_entry(struct cache *cache, struct cache_entry *entry)
{
	struct cache_entry *prev, *next;
	unsigned idx;

	idx = entry - cache->ce;
	if (cache->eprec == idx)
		cache->eprec = entry->next;
	if (cache->eprobe == idx)
		cache->eprobe = entry->prev;

	next = &cache->ce[entry->next];
	next->prev = entry->prev;
	prev = &cache->ce[entry->prev];
	prev->next = entry->next;

	return entry;
}

/**  Move a cache entry to the MRU position of the precious list.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry to be moved.
 */
static void
use_precious(struct cache *cache, struct cache_entry *entry)
{
	struct cache_entry *prev, *next;
	unsigned idx = entry - cache->ce;

	if (cache->split != idx && cache->split != entry->prev) {
		remove_entry(cache, entry);

		prev = &cache->ce[cache->split];
		next = &cache->ce[prev->next];
		entry->next = prev->next;
		prev->next = idx;
		entry->prev = next->prev;
		next->prev = idx;

		if (cache->eprec == entry->next &&
		    cache->eprec != cache->gprec)
			cache->eprec = idx;
	}

	cache->split = entry->prev;
}

/**  Re-initialize an entry for a different page.
 *
 * @param cache  Cache object.
 * @param entry  Entry to be reinitialized.
 *
 * Evict an entry from the cache and use its data pointer for @ref entry.
 * The evicted entry is taken either from the probe list or from the
 * precious list, depending on the value of @c dsplit.
 * This function is used for pages that will be added to the probe list,
 * so it has bias towards the probe list.
 *
 * Note that @c dsplit is not updated when taking an entry from the
 * probe list. That's because the entry will be added back to the list
 * eventually, so there is no change in fact.
 *
 * @sa reuse_ghost_entry
 */
static void
reinit_entry(struct cache *cache, struct cache_entry *entry)
{
	unsigned evict;
	int delta = cache->dsplit;

	if (delta <= 0 && probe_cache_empty(cache))
		delta = 1;
	else if (delta > 0 && prec_cache_empty(cache))
		delta = 0;

	if (delta <= 0) {
		evict = cache->ce[cache->gprobe].next;
		cache->gprobe = evict;
	} else {
		--cache->dsplit;
		evict = cache->ce[cache->gprec].prev;
		cache->gprec = evict;
	}
	entry->data = cache->ce[evict].data;
	cache->ce[evict].data = NULL;
}

/**  Reuse a ghost entry.
 *
 * @param cache  Cache object.
 * @param entry  Ghost entry to be reused.
 *
 * Same as @ref reinit_entry, but designed for ghost entries.
 * This function is used for pages that will be added to the precious list,
 * so it has bias towards the precious list.
 *
 * @sa reinit_entry
 */
static void
reuse_ghost_entry(struct cache *cache, struct cache_entry *entry)
{
	unsigned idx, evict;
	int delta = cache->dsplit;

	if (delta < 0 && probe_cache_empty(cache))
		delta = 0;
	else if (delta >= 0 && prec_cache_empty(cache))
		delta = -1;

	idx = entry - cache->ce;
	if (delta < 0) {
		if (cache->gprec == idx)
			cache->gprec = entry->next;
		++cache->dsplit;
		evict = cache->ce[cache->gprobe].next;
		cache->gprobe = evict;
	} else {
		if (cache->gprobe == idx)
			cache->gprobe = entry->prev;
		evict = cache->ce[cache->gprec].prev;
		cache->gprec = evict;
	}
	entry->data = cache->ce[evict].data;
	cache->ce[evict].data = NULL;

	if (cache->split == idx)
		cache->split = entry->prev;

	remove_entry(cache, entry);
	entry->pfn |= CACHE_FLAGS_PFN(cf_precious);
}

/**  Get the cache entry for a given PFN.
 *
 * @param cache  Cache object.
 * @param pfn    PFN to be searched.
 * @returns      Pointer to a cache entry.
 *
 * On a cache hit (page data is found in the cache), the returned entry
 * denotes the cached page data.
 * On a cache miss, the returned entry can be used to load data into the
 * cache and store it for later use with @ref cache_set_entry.
 */
struct cache_entry *
cache_get_entry(struct cache *cache, kdump_pfn_t pfn)
{
	struct cache_entry *entry;
	unsigned idx;

	/* Search precious entries */
	idx = cache->ce[cache->split].next;
	while (idx != cache->gprec) {
		entry = &cache->ce[idx];
		if (entry->pfn == pfn) {
			use_precious(cache, entry);
			return entry;
		}
		idx = entry->next;
	}

	/* Search probed entries */
	idx = cache->split;
	while (idx != cache->gprobe) {
		entry = &cache->ce[idx];
		if (entry->pfn == pfn) {
			++cache->dsplit;
			--cache->nprobe;
			use_precious(cache, entry);
			return entry;
		}
		idx = entry->prev;
	}

	entry = get_ghost_entry(cache, pfn);
	if (!entry)
		entry = get_missed_entry(cache, pfn);

	return entry;
}

/**  Get the ghost entry for a given PFN.
 *
 * @param cache  Cache object.
 * @param pfn    PFN to be searched.
 * @returns      Ghost entry, or @c NULL if not found.
 */
static struct cache_entry *
get_ghost_entry(struct cache *cache, kdump_pfn_t pfn)
{
	struct cache_entry *entry;
	unsigned idx;

	/* Search precious ghost entries */
	idx = cache->gprec;
	while (idx != cache->eprec) {
		entry = &cache->ce[idx];
		if (entry->pfn == pfn) {
			if (!probe_cache_empty(cache))
				--cache->dsplit;
			reuse_ghost_entry(cache, entry);
			return entry;
		}
		idx = entry->next;
	}

	/* Search probed ghost entries */
	idx = cache->gprobe;
	while (idx != cache->eprobe) {
		entry = &cache->ce[idx];
		if (entry->pfn == pfn) {
			++cache->dsplit;
			--cache->nprobe;
			reuse_ghost_entry(cache, entry);
			return entry;
		}
		idx = entry->prev;
	}

	return NULL;
}

/**  Get a cache entry for a given missed PFN.
 *
 * @param cache  Cache object.
 * @param pfn    Requested PFN.
 * @returns      A new cache entry.
 */
static struct cache_entry *
get_missed_entry(struct cache *cache, kdump_pfn_t pfn)
{
	struct cache_entry *entry;
	unsigned idx;

	if (cache->nprobe == cache->cap) {
		idx = cache->ce[cache->eprobe].next;
		entry = &cache->ce[idx];
	} else {
		idx = cache->eprobe;
		entry = &cache->ce[idx];
		cache->eprobe = entry->prev;
		++cache->nprobe;
		if (entry->data)
			--cache->dsplit;
	}

	if (cache->split == idx)
		cache->split = entry->prev;
	if (cache->gprobe == idx)
		cache->gprobe = entry->prev;

	remove_entry(cache, entry);
	entry->pfn = pfn | CACHE_FLAGS_PFN(cf_probe);

	if (!entry->data)
		reinit_entry(cache, entry);

	return entry;
}

/**  Insert an entry into the cache.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry (with data).
 */
void
cache_insert(struct cache *cache, struct cache_entry *entry)
{
	struct cache_entry *prev, *next;
	unsigned idx = entry - cache->ce;

	prev = &cache->ce[cache->split];
	next = &cache->ce[prev->next];

	switch (CACHE_PFN_FLAGS(entry->pfn)) {
	case cf_probe:
		if (cache->eprec == prev->next &&
		    cache->eprec != cache->gprec)
			cache->eprec = next->prev;
		if (cache->eprobe == cache->split &&
		    cache->eprobe != cache->gprobe)
			cache->eprobe = idx;
		cache->split = idx;
		break;

	case cf_precious:
		if (cache->eprec == prev->next &&
		    cache->eprec != cache->gprec)
			cache->eprec = idx;
		if (cache->eprobe == cache->split &&
		    cache->eprobe != cache->gprobe)
			cache->eprobe = prev->next;
		break;
	}
	entry->pfn &= ~CACHE_FLAGS_PFN(CF_MASK);

	entry->next = prev->next;
	prev->next = idx;
	entry->prev = next->prev;
	next->prev = idx;
}

/**  Discard an entry.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry.
 *
 * Use this function to return an entry back into the cache without
 * providing any data. This can be used for error handling.
 */
void
cache_discard(struct cache *cache, struct cache_entry *entry)
{
	cache_insert(cache, entry);
	entry->pfn |= CACHE_FLAGS_PFN(cf_error);
}

/**  Flush all cache entries.
 *
 * @param cache  Cache object.
 */
void
cache_flush(struct cache *cache)
{
	unsigned i, n;

	n = 2 * cache->cap;
	for (i = 0; i < n; ++i) {
		struct cache_entry *entry = &cache->ce[i];
		entry->next = (i + 1) % n;
		entry->prev = (i - 1) % n;
		entry->data = i < cache->cap
			? cache->data + i * cache->elemsize
			: NULL;
	}

	cache->split = cache->cap - 1;
	cache->dsplit = 0;
	cache->gprec = cache->cap;
	cache->eprec = cache->cap;
	cache->gprobe = cache->cap - 1;
	cache->eprobe = cache->cap - 1;
	cache->nprobe = 0;
}

/**  Allocate a cache object.
 *
 * @param n     Number of elements in the cache.
 * @param size  Data size for each element.
 * @returns     Newly allocated cache object, or @c NULL on failure.
 *
 * The cache object must be eventually freed with a call to @ref cache_free.
 */
struct cache *
cache_alloc(unsigned n, size_t size)
{
	struct cache *cache;

	cache = malloc(sizeof(struct cache) +
		       2 * n * sizeof(struct cache_entry));
	if (!cache)
		return cache;
	cache->elemsize = size;
	cache->cap = n;

	cache->data = malloc(cache->cap * cache->elemsize);
	if (!cache->data) {
		free(cache);
		return NULL;
	}

	cache_flush(cache);
	return cache;
}

/**  Free a cache object.
 *
 * @param cache  Cache object.
 */
void
cache_free(struct cache *cache)
{
	free(cache->data);
	free(cache);
}

/**  Allocate a cache with default parameters.
 * @param ctx  Dump file object.
 * @returns    The allocated cache, or @c NULL on failure.
 *
 * This is a shorthand for allocating a cache with @c cache.size
 * elements of @c arch.page_size bytes each.
 */
struct cache *
def_cache_alloc(kdump_ctx *ctx)
{
	const struct attr_data *attr;
	unsigned cache_size;
	struct cache *cache;

	attr = lookup_attr(ctx, GATTR(GKI_cache_size));
	cache_size = attr
		? attr_value(attr)->number
		: DEFAULT_CACHE_SIZE;
	cache = cache_alloc(cache_size, get_page_size(ctx));
	if (!cache)
		set_error(ctx, kdump_syserr,
			  "Cannot allocate cache (%u * %zu bytes)",
			  cache_size, get_page_size(ctx));
	return cache;
}
