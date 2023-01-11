/** @internal @file src/kdumpfile/cache.c
 * @brief Data caching.
 */
/* Copyright (C) Petr Tesarik <ptesarik@suse.com>

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
 *
 * The cache is divided into five partitions:
 *   1. probed: cached entries that have been hit only once
 *   2. precious: cached entries that have been hit more than once
 *   3. ghost probe: evicted entries from the probed list
 *   4. ghost precious: evicted entries from the precious list
 *   5. unused: entries that haven't been used yet
 *
 * Cached entries have a non-NULL data pointer. Ghost entries do not have
 * any data, so their data pointer is NULL.
 *
 * The cache is implemented as a circular list. This allows to move around
 * entries without copying much data even if the cache is large.
 * The list is organized as follows:
 *
 *               <-- ngprobe --> <- nprobe -> <- nprec -> <--- ngprec --->
 *     +--------+---------------+------------+-----------+----------------+
 *     | unused | ghost probed  |   probed   | precious  | ghost precious |
 *     +--------+---------------+------------+-----------+----------------+
 *             ^               ^            ^             ^                ^
 *             eprobe          gprobe     split       gprec            eprec
 *
 *
 * Only the @ref split index and the four sizes are stored in the data
 * structure. The remaining pointers are found as a side effect of searching
 * the cache, and they are stored in @ref cache_search.
 *
 * Any partition may be empty; some pointers will share the same value in
 * that case.
 *
 * Note that since the list is circular, the unused partition is between
 * the ghost probed and ghost precious partitions. This part of the cache is
 * usually empty after it has been used for some time.
 *
 * Entries that have been allocated for I/O but not yet committed back,
 * are removed from the main list and added to an in-flight list.
 * They are returned back to the list later when the user calls
 * @ref cache_insert or @ref cache_discard on the in-flight entry.
 */
struct cache {
	unsigned split;		 /**< Split point between probed and precious
				  *   entries (index of MRU probed entry) */
	unsigned nprec;		 /**< Number of cached precious entries */
	unsigned ngprec;	 /**< Number of ghost precious entries */
	unsigned nprobe;	 /**< Number of cached probe entries */
	unsigned ngprobe;	 /**< Number of ghost probe entries */
	unsigned dprobe;	 /**< Desired number of cached probe entries */
	unsigned cap;		 /**< Total cache capacity */
	unsigned inflight;	 /**< Index of first in-flight entry */
	unsigned ninflight;	 /**< Number of in-flight entries */

	kdump_attr_value_t hits;   /**< Cache hits */
	kdump_attr_value_t misses; /**< Cache misses */

	size_t elemsize;	 /**< Element data size */
	void *data;		 /**< Actual cache data */

	/** Cache entry destructor. */
	cache_entry_cleanup_fn *entry_cleanup;
	void *cleanup_data;	 /**< User-supplied data for the destructor. */

	struct cache_entry ce[]; /**< Cache entries */
};

/**  Temporary information needed during a cache search.
 * This is grouped in a structure to avoid passing an inordinate number
 * of parameters among the various helper functions.
 */
struct cache_search {
	unsigned gprec;		/**< Index of MRU precious ghost entry */
	unsigned eprec;		/**< End of precious entries; this is the
				 *   index of the first unused entry. */
	unsigned uprec;		/**< Index of LRU unused precious entry. */
	unsigned nuprec;	/**< Number of unused precious entries. */
	unsigned gprobe;	/**< Index of MRU probed ghost entry */
	unsigned eprobe;	/**< End of probed entries; this is the
				 *   index of the first unused entry. */
	unsigned uprobe;	/**< Index of LRU unused probed entry. */
	unsigned nuprobe;	/**< Number of unused probed entries. */
};

/**  Insert an entry to the list after a given position.
 * @param cache   Cache object.
 * @param entry   Cache entry to be added.
 * @param idx     Index of @p entry.
 * @param insidx  Insertion point.
 *
 * The entry is added just after @p insidx.
 */
static void
add_entry_after(struct cache *cache, struct cache_entry *entry, unsigned idx,
		unsigned insidx)
{
	struct cache_entry *prev = &cache->ce[insidx];
	struct cache_entry *next = &cache->ce[prev->next];
	entry->next = prev->next;
	prev->next = idx;
	entry->prev = next->prev;
	next->prev = idx;
}

/**  Insert an entry to the list before a given poisition.
 * @param cache   Cache object.
 * @param entry   Cache entry to be added.
 * @param idx     Index of @p entry.
 * @param insidx  Insertion point.
 *
 * The entry is added just before @p insidx.
 */
static void
add_entry_before(struct cache *cache, struct cache_entry *entry, unsigned idx,
		 unsigned insidx)
{
	struct cache_entry *next = &cache->ce[insidx];
	struct cache_entry *prev = &cache->ce[next->prev];
	entry->next = prev->next;
	prev->next = idx;
	entry->prev = next->prev;
	next->prev = idx;
}

/**  Remove a cache entry from a list.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry to be removed.
 */
static void
remove_entry(struct cache *cache, struct cache_entry *entry)
{
	struct cache_entry *prev, *next;

	next = &cache->ce[entry->next];
	next->prev = entry->prev;
	prev = &cache->ce[entry->prev];
	prev->next = entry->next;
}

/**  Add an entry to the inflight list.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry to be removed.
 * @param idx    Cache entry index.
 */
static void
add_inflight(struct cache *cache, struct cache_entry *entry, unsigned idx)
{
	if (cache->ninflight++)
		add_entry_before(cache, entry, idx, cache->inflight);
	else
		cache->inflight = entry->next = entry->prev = idx;
}

/**  Reuse a cached entry.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry to be moved.
 * @param idx    Index of @p entry.
 * @returns      The value of @p entry.
 *
 * Move a cache entry to the MRU position of the precious list.
 */
static struct cache_entry *
reuse_cached_entry(struct cache *cache, struct cache_entry *entry,
		   unsigned idx)
{
	if (cache->split != idx && cache->split != entry->prev) {
		remove_entry(cache, entry);
		add_entry_after(cache, entry, idx, cache->split);
	}

	cache->split = entry->prev;

	++cache->hits.number;
	return entry;
}

/**  Evict an entry from the probe partition.
 * @param cache  Cache object.
 * @param cs     Cache search info.
 * @returns      The evicted entry.
 */
static struct cache_entry *
evict_probe(struct cache *cache, struct cache_search *cs)
{
	struct cache_entry *entry = &cache->ce[cs->uprobe];
	if (entry->prev != cs->gprobe) {
		if (cs->uprobe == cache->split)
			cache->split = entry->prev;
		remove_entry(cache, entry);
		add_entry_after(cache, entry, cs->uprobe, cs->gprobe);
	}
	--cache->nprobe;
	++cache->ngprobe;
	return entry;
}

/**  Evict an entry from the precious partition.
 * @param cache  Cache object.
 * @param cs     Cache search info.
 * @returns      The evicted entry.
 */
static struct cache_entry *
evict_prec(struct cache *cache, struct cache_search *cs)
{
	struct cache_entry *entry = &cache->ce[cs->uprec];
	if (entry->next != cs->gprec) {
		remove_entry(cache, entry);
		add_entry_before(cache, entry, cs->uprec, cs->gprec);
	}
	--cache->nprec;
	++cache->ngprec;
	return entry;
}

/**  Re-initialize an entry for different data.
 *
 * @param cache  Cache object.
 * @param entry  Entry to be reinitialized.
 * @param cs     Cache search info.
 * @param bias   Bias towards the probed partition.
 *
 * Evict an entry from the cache and use its data pointer for @p entry.
 * The evicted entry is taken either from the probe partition or from the
 * precious partition, depending on the value of @c dprobe.
 */
static void
reinit_entry(struct cache *cache, struct cache_entry *entry,
	     struct cache_search *cs, unsigned bias)
{
	struct cache_entry *evict;

	if (cache->nprec + cache->nprobe + cache->ninflight < cache->cap) {
		/* Get an entry from the unused partition. */
		evict = &cache->ce[cs->eprobe];
	} else {
		/* Get an unused cached entry. */
		if (cs->nuprobe != 0 &&
		    (cs->nuprec == 0 || cache->nprobe + bias > cache->dprobe))
			evict = evict_probe(cache, cs);
		else
			evict = evict_prec(cache, cs);
		if (cache->entry_cleanup)
			cache->entry_cleanup(cache->cleanup_data, evict);
	}
	entry->data = evict->data;
	evict->data = NULL;
}

/**  Get a cache entry for a given missed key.
 *
 * @param cache  Cache object.
 * @param key    Requested key.
 * @param cs     Cache search info.
 * @returns      A new cache entry.
 */
static struct cache_entry *
get_missed_entry(struct cache *cache, cache_key_t key,
		 struct cache_search *cs)
{
	struct cache_entry *entry;
	unsigned idx;

	idx = cs->eprobe;
	entry = &cache->ce[idx];
	if (entry->next == cs->eprec) {
		if (cache->ngprobe) {
			/* Full and non-empty ghost probe partition.
			 * Use an entry from that partition instead.
			 */
			idx = entry->next;
			entry = &cache->ce[idx];
			--cache->ngprobe;
		} else if (cache->ngprec) {
			/* Full and empty ghost probe partition.
			 * Entry is from the ghost precious partition,
			 * so its size must be adjusted.
			 */
			--cache->ngprec;
		}
		/* Else empty cache. Entry is from the unused partition. */
	}
	/* Else ghost probe and ghost precious partitions do not touch,
	 * so entry must be from the unused partition in between.
	 */

	if (!entry->data)
		reinit_entry(cache, entry, cs, 1);

	if (cache->split == idx)
		cache->split = entry->prev;

	remove_entry(cache, entry);
	add_inflight(cache, entry, idx);
	entry->key = key;
	entry->state = cs_probe;

	return entry;
}

/**  Reuse a ghost entry.
 *
 * @param cache  Cache object.
 * @param entry  Ghost entry to be reused.
 * @param idx    Index of @p entry.
 * @param cs     Cache search info.
 * @returns      The value of @p entry.
 */
static struct cache_entry *
reuse_ghost_entry(struct cache *cache, struct cache_entry *entry,
		  unsigned idx, struct cache_search *cs)
{
	reinit_entry(cache, entry, cs, 0);

	if (cache->split == idx)
		cache->split = entry->prev;

	remove_entry(cache, entry);
	add_inflight(cache, entry, idx);
	entry->state = cs_precious;
	return entry;
}

/**  Get an entry for a given non-cached key.
 *
 * @param cache  Cache object.
 * @param key    Key to be searched.
 * @param cs     Cache search info.
 * @returns      An in-flight entry.
 */
static struct cache_entry *
get_ghost_or_missed_entry(struct cache *cache, cache_key_t key,
			  struct cache_search *cs)
{
	struct cache_entry *entry;
	unsigned n, idx;

	/* Search precious ghost entries */
	n = cache->ngprec;
	idx = cs->gprec;
	while (n--) {
		entry = &cache->ce[idx];
		if (entry->key == key) {
			int delta = cache->ngprobe > cache->ngprec
				? cache->ngprobe / cache->ngprec
				: 1;
			if (cache->dprobe > delta)
				cache->dprobe -= delta;
			else
				cache->dprobe = 0;
			--cache->ngprec;
			return reuse_ghost_entry(cache, entry, idx, cs);
		}
		idx = entry->next;
	}
	cs->eprec = idx;

	/* Search probed ghost entries */
	n = cache->ngprobe;
	idx = cs->gprobe;
	while (n--) {
		entry = &cache->ce[idx];
		if (entry->key == key) {
			int delta = cache->ngprec > cache->ngprobe
				? cache->ngprec / cache->ngprobe
				: 1;
			if (cache->dprobe + delta < cache->cap)
				cache->dprobe += delta;
			else
				cache->dprobe = cache->cap;
			--cache->ngprobe;
			return reuse_ghost_entry(cache, entry, idx, cs);
		}
		idx = entry->prev;
	}
	cs->eprobe = idx;

	return get_missed_entry(cache, key, cs);
}

/**  Get the in-flight entry for a given key.
 *
 * @param cache  Cache object.
 * @param key    Key to be searched.
 * @returns      In-flight entry, or @c NULL if there is none.
 */
static struct cache_entry *
get_inflight_entry(struct cache *cache, cache_key_t key)
{
	struct cache_entry *entry;
	unsigned idx, n;

	idx = cache->inflight;
	for (n = cache->ninflight; n; --n) {
		entry = &cache->ce[idx];
		if (entry->key == key) {
			entry->state = cs_precious;
			return entry;
		}
		idx = entry->next;
	}

	return NULL;
}

/**  Search the cache for an entry.
 *
 * @param cache  Cache object.
 * @param key    Key to be searched.
 * @returns      Pointer to a cache entry, or @c NULL if cache is full.
 */
static struct cache_entry *
cache_get_entry_noref(struct cache *cache, cache_key_t key)
{
	struct cache_search cs;
	struct cache_entry *entry;
	unsigned n, idx;

	cs.nuprec = 0;
	cs.nuprobe = 0;

	/* Search precious entries */
	n = cache->nprec;
	idx = cache->ce[cache->split].next;
	while (n--) {
		entry = &cache->ce[idx];
		if (entry->key == key)
			return reuse_cached_entry(cache, entry, idx);
		if (entry->refcnt == 0) {
			cs.uprec = idx;
			++cs.nuprec;
		}
		idx = entry->next;
	}
	cs.gprec = idx;

	/* Search probed entries */
	n = cache->nprobe;
	idx = cache->split;
	while (n--) {
		entry = &cache->ce[idx];
		if (entry->key == key) {
			--cache->nprobe;
			++cache->nprec;
			return reuse_cached_entry(cache, entry, idx);
		}
		if (entry->refcnt == 0) {
			cs.uprobe = idx;
			++cs.nuprobe;
		}
		idx = entry->prev;
	}
	cs.gprobe = idx;

	entry = get_inflight_entry(cache, key);

	if (!entry) {
		unsigned inuse = (cache->nprec - cs.nuprec) +
			(cache->nprobe - cs.nuprobe) +
			cache->ninflight;
		if (inuse >= cache->cap)
			return NULL;

		entry = get_ghost_or_missed_entry(cache, key, &cs);
	}

	++cache->misses.number;

	return entry;
}

/**  Get the cache entry for a given key.
 *
 * @param cache  Cache object.
 * @param key    Key to be searched.
 * @returns      Pointer to a cache entry, or @c NULL if cache is full.
 *
 * On a cache hit (corresponding entry is found in the cache), the returned
 * entry denotes the cached data.
 * On a cache miss, the returned entry can be used to load data into the
 * cache and store it for later use with @ref cache_insert.
 *
 * The reference count of the returned entry is incremented.
 */
struct cache_entry *
cache_get_entry(struct cache *cache, cache_key_t key)
{
	struct cache_entry *entry;

	entry = cache_get_entry_noref(cache, key);
	if (entry)
		++entry->refcnt;

	return entry;
}

/**  Insert an entry into the cache.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry (with data).
 *
 * Note that this function does **NOT** drop the reference to @p entry.
 * This is necessary to allow callers inserting an entry to the cache as
 * soon as possible, while using the data afterwards.
 */
void
cache_insert(struct cache *cache, struct cache_entry *entry)
{
	unsigned idx;

	if (cache_entry_valid(entry))
		return;

	idx = entry - cache->ce;
	if (cache->ninflight--) {
		if (cache->inflight == idx)
			cache->inflight = entry->next;
		remove_entry(cache, entry);
	}
	add_entry_after(cache, entry, idx, cache->split);

	switch (entry->state) {
	case cs_probe:
		++cache->nprobe;
		cache->split = idx;
		break;

	case cs_precious:
		++cache->nprec;
		break;

	default:		/* Make -Wswitch happy. */
		break;
	}
	entry->state = cs_valid;
}

/**  Drop a reference to a cache entry.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry.
 */
void
cache_put_entry(struct cache *cache, struct cache_entry *entry)
{
	--entry->refcnt;
}

/**  Discard an entry.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry.
 *
 * Use this function to return an entry back into the cache without
 * providing any data. This can be used for error handling.
 *
 * This function first drops the reference to @p entry and does
 * nothing unless this was the last reference. This means that a caller
 * who has a reference to @p entry may still insert it to the cache after
 * another caller discarded it.
 */
void
cache_discard(struct cache *cache, struct cache_entry *entry)
{
	unsigned n, idx, eprobe;

	if (--entry->refcnt)
		return;
	if (cache_entry_valid(entry))
		return;
	--cache->ninflight;

	idx = entry - cache->ce;
	if (cache->inflight == idx)
		cache->inflight = entry->next;
	remove_entry(cache, entry);

	eprobe = cache->split;
	n = cache->nprobe + cache->ngprobe;
	if (!n)
		cache->split = idx;
	else while (n--)
		eprobe = cache->ce[eprobe].prev;

	add_entry_after(cache, entry, idx, eprobe);
}

/**  Clean up all cache entries.
 *
 * @param cache  Cache object.
 *
 * Call the entry destructor on all active entries in the cache.
 */
static void
cleanup_entries(struct cache *cache)
{
	unsigned n, idx;
	struct cache_entry *entry;

	if (!cache->entry_cleanup)
		return;

	/* Clean up precious entries */
	n = cache->nprec;
	idx = cache->ce[cache->split].next;
	while (n--) {
		entry = &cache->ce[idx];
		cache->entry_cleanup(cache->cleanup_data, entry);
		idx = entry->next;
	}

	/* Clean up probed entries */
	n = cache->nprobe;
	idx = cache->split;
	while (n--) {
		entry = &cache->ce[idx];
		cache->entry_cleanup(cache->cleanup_data, entry);
		idx = entry->prev;
	}
}

/**  Flush all cache entries.
 *
 * @param cache  Cache object.
 */
void
cache_flush(struct cache *cache)
{
	unsigned i, n;

	cleanup_entries(cache);

	n = 2 * cache->cap;
	for (i = 0; i < n; ++i) {
		struct cache_entry *entry = &cache->ce[i];
		entry->next = (i > 0) ? (i - 1) : (n - 1);
		entry->prev = (i < n - 1) ? (i + 1) : 0;
		entry->refcnt = 0;
		entry->data = i < cache->cap
			? cache->data + i * cache->elemsize
			: NULL;
	}

	cache->split = 0;
	cache->nprec = 0;
	cache->ngprec = 0;
	cache->nprobe = 0;
	cache->ngprobe = 0;
	cache->dprobe = 0;
	cache->ninflight = 0;
}

/**  Allocate a cache object.
 *
 * @param n     Number of elements in the cache.
 * @param size  Data size for each element.
 * @returns     Newly allocated cache object, or @c NULL on failure.
 *
 * The reference count of the new cache object is set to 1.
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
	cache->hits.number = 0;
	cache->misses.number = 0;
	cache->entry_cleanup = NULL;

	if (cache->elemsize) {
		cache->data = malloc(cache->cap * cache->elemsize);
		if (!cache->data) {
			free(cache);
			return NULL;
		}
	} else
		cache->data = cache; /* Any non-NULL pointer */

	cache_flush(cache);
	return cache;
}

/** Set cache entry destructor.
 * @param cache  Cache object.
 * @param fn     Entry destructor, or @c NULL.
 * @param data   User-supplied data, passed as an argument to the destructor.
 *
 * The destructor is called whenever a cache entry is invalidated, that is
 * either when the entry is evicted, or when the whole cache is freed.
 * It should free any resources associated with the data pointer of the
 * respective entry.
 */
void
set_cache_entry_cleanup(struct cache *cache, cache_entry_cleanup_fn *fn,
			void *data)
{
	cache->entry_cleanup = fn;
	cache->cleanup_data = data;
}

/**  Free a cache object.
 * @param cache  Cache object.
 *
 * All resources used by the cache object are freed. Any cache entry
 * pointers into the cache and returned by @c cache_get_entry are invalid
 * and must not be used after calling this function.
 */
void
cache_free(struct cache *cache)
{
	cleanup_entries(cache);
	if (cache->data != cache)
		free(cache->data);
	free(cache);
}

/**  Get the configured cache size.
 * @param ctx  Dump file object.
 * @returns    Cache size.
 *
 * Get the cache size from "cache.size" attribute. If not set, return
 * @ref DEFAULT_CACHE_SIZE.
 */
unsigned
get_cache_size(kdump_ctx_t *ctx)
{
	struct attr_data *attr = gattr(ctx, GKI_cache_size);
	return attr_isset(attr) && attr_revalidate(ctx, attr) == KDUMP_OK
		? attr_value(attr)->number
		: DEFAULT_CACHE_SIZE;
}

/**  Set up cache statistics attributes.
 * @param cache   Cache object.
 * @param ctx     Dump file object containing the attributes.
 * @param hits    Attribute for cache hits.
 * @param misses  Attribute for cache misses.
 * @returns       Error status.
 */
kdump_status
cache_set_attrs(struct cache *cache, kdump_ctx_t *ctx,
		struct attr_data *hits, struct attr_data *misses)
{
	kdump_status status;

	status = set_attr(ctx, hits, ATTR_PERSIST_INDIRECT, &cache->hits);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot set up cache '%s' attribute",
				 "hits");

	status = set_attr(ctx, misses, ATTR_PERSIST_INDIRECT, &cache->misses);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot set up cache '%s' attribute",
				 "misses");

	return KDUMP_OK;
}
