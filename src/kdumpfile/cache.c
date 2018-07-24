/** @internal @file src/kdumpfile/cache.c
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
 *
 * The cache is divided into five sections:
 *   1. probed list: cached entries that have been hit only once
 *   2. precious list: cached entries that have been hit more than once
 *   3. ghost probe list: evicted entries from the probed list
 *   4. ghost precious list: evicted entries from the precious list
 *   5. unused pool: entries that haven't been used yet
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
 * Only the @ref split index and the four sizes are stored in the structure.
 * During a search, the remaining pointers are found as a side effect, and
 * they are stored in @ref cache_search.
 *
 * Note that any section may be empty; some pointers will share the same
 * value in such case.
 *
 * Also note that since the list is circular, unused entries are in fact
 * between ghost probed and ghost precious lists. This part of the cache
 * is usually empty; it's used only after a flush or when an entry is
 * discarded.
 */
struct cache {
	mutex_t mutex;		 /**< Lock for changes to struct cache. */

	unsigned split;		 /**< Split point between probed and precious
				  *   entries (index of MRU probed entry) */
	unsigned nprec;		 /**< Number of cached precious entries */
	unsigned ngprec;	 /**< Number of ghost precious entries */
	unsigned nprobe;	 /**< Number of cached probe entries */
	unsigned ngprobe;	 /**< Number of ghost probe entries */
	unsigned dprobe;	 /**< Desired nubmer of cached probe entries */
	unsigned nprobetotal;	 /**< Total number of probe list entries,
				  *   including ghost and in-flight entries */
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

static struct cache_entry *get_ghost_entry(
	struct cache *cache, cache_key_t key,
	struct cache_search *cs);
static struct cache_entry *get_inflight_entry(
	struct cache *cache, cache_key_t key);
static struct cache_entry *get_missed_entry(
	struct cache *cache, cache_key_t key,
	struct cache_search *cs);

/**  Add an entry to the list after a given point.
 * @param cache   Cache object.
 * @param entry   Cache entry to be added.
 * @param idx     Index of @ref entry.
 * @param insidx  Insertion point.
 *
 * The entry is added just after @ref insidx.
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

/**  Add an entry to the list before a given point.
 * @param cache   Cache object.
 * @param entry   Cache entry to be added.
 * @param idx     Index of @ref entry.
 * @param insidx  Insertion point.
 *
 * The entry is added just before @ref insidx.
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

/**  Ensure that a locked in-flight entry goes to the precious list.
 *
 * @param cache  Cache object (locked).
 * @param entry  Cache entry.
 *
 * This function must be called with the cache mutex held.
 */
static void
make_precious(struct cache *cache, struct cache_entry *entry)
{
	if (entry->state == cs_probe) {
		--cache->nprobetotal;
		entry->state = cs_precious;
	}
}

/**  Reuse a cached entry.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry to be moved.
 * @param idx    Index of @ref entry.
 *
 * Move a cache entry to the MRU position of the precious list.
 */
static void
reuse_cached_entry(struct cache *cache, struct cache_entry *entry,
		   unsigned idx)
{
	if (cache->split != idx && cache->split != entry->prev) {
		remove_entry(cache, entry);
		add_entry_after(cache, entry, idx, cache->split);
	}

	cache->split = entry->prev;

	++cache->hits.number;
}

/**  Evict an entry from the probe list.
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

/**  Evict an entry from the precious list.
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
 *
 * Evict an entry from the cache and use its data pointer for @ref entry.
 * The evicted entry is taken either from the probe list or from the
 * precious list, depending on the value of @c dprobe.
 * This function is used for pages that will be added to the probe list,
 * so it has bias towards the probe list.
 *
 * @sa reuse_ghost_entry
 */
static void
reinit_entry(struct cache *cache, struct cache_entry *entry,
	     struct cache_search *cs)
{
	struct cache_entry *evict;
	int delta = cache->dprobe - cache->nprobe;

	if (delta <= 0 && cs->nuprobe == 0)
		delta = 1;
	else if (delta > 0 && cs->nuprec == 0)
		delta = 0;

	if (delta <= 0)
		evict = evict_probe(cache, cs);
	else
		evict = evict_prec(cache, cs);
	if (cache->entry_cleanup)
		cache->entry_cleanup(cache->cleanup_data, evict);

	entry->data = evict->data;
	evict->data = NULL;
}

/**  Reuse a ghost entry.
 *
 * @param cache  Cache object.
 * @param entry  Ghost entry to be reused.
 * @param idx    Index of @ref entry.
 * @param cs     Cache search info.
 *
 * Same as @ref reinit_entry, but designed for ghost entries.
 * This function is used for pages that will be added to the precious list,
 * so it has bias towards the precious list.
 *
 * @sa reinit_entry
 */
static void
reuse_ghost_entry(struct cache *cache, struct cache_entry *entry,
		  unsigned idx, struct cache_search *cs)
{
	struct cache_entry *evict;
	int delta = cache->dprobe - cache->nprobe;

	if (delta < 0 && cs->nuprobe == 0)
		delta = 0;
	else if (delta >= 0 && cs->nuprec == 0)
		delta = -1;

	if (delta < 0)
		evict = evict_probe(cache, cs);
	else
		evict = evict_prec(cache, cs);
	if (cache->entry_cleanup)
		cache->entry_cleanup(cache->cleanup_data, evict);

	entry->data = evict->data;
	evict->data = NULL;

	if (cache->split == idx)
		cache->split = entry->prev;

	remove_entry(cache, entry);
	add_inflight(cache, entry, idx);
	entry->state = cs_precious;
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
		if (entry->key == key) {
			reuse_cached_entry(cache, entry, idx);
			return entry;
		}
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
			--cache->nprobetotal;
			reuse_cached_entry(cache, entry, idx);
			return entry;
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
	}

	if (!entry)
		entry = get_ghost_entry(cache, key, &cs);
	if (!entry)
		entry = get_missed_entry(cache, key, &cs);

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

	mutex_lock(&cache->mutex);
	entry = cache_get_entry_noref(cache, key);
	if (entry)
		++entry->refcnt;
	mutex_unlock(&cache->mutex);

	return entry;
}

/**  Get the ghost entry for a given key.
 *
 * @param cache  Cache object.
 * @param key    Key to be searched.
 * @param cs     Cache search info.
 * @returns      Ghost entry, or @c NULL if not found.
 *
 * If no entry is found (function returns @c NULL), the @c epreca and
 * @c eprobe fields in @ref cs are updated. Otherwise (if an entry is
 * found), their values are undefined.
 */
static struct cache_entry *
get_ghost_entry(struct cache *cache, cache_key_t key,
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
			reuse_ghost_entry(cache, entry, idx, cs);
			return entry;
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
			--cache->nprobetotal;
			reuse_ghost_entry(cache, entry, idx, cs);
			return entry;
		}
		idx = entry->prev;
	}
	cs->eprobe = idx;

	return NULL;
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
			make_precious(cache, entry);
			return entry;
		}
		idx = entry->next;
	}

	return NULL;
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

	++cache->nprobetotal;
	idx = cs->eprobe;
	entry = &cache->ce[idx];
	if (entry->next == cs->eprec) {
		if (cache->nprobetotal > cache->cap) {
			idx = entry->next;
			entry = &cache->ce[idx];
			if (cache->ngprobe)
				--cache->ngprobe;
			else
				--cache->nprobe;
			--cache->nprobetotal;
		} else if (cache->ngprec)
			   --cache->ngprec;
	}

	if (!entry->data)
		reinit_entry(cache, entry, cs);

	if (cache->split == idx)
		cache->split = entry->prev;

	remove_entry(cache, entry);
	add_inflight(cache, entry, idx);
	entry->key = key;
	entry->state = cs_probe;

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

	mutex_lock(&cache->mutex);
	if (cache_entry_valid(entry))
		goto unlock;

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

 unlock:
	mutex_unlock(&cache->mutex);
}

/**  Drop a reference to a cache entry.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry.
 */
void
cache_put_entry(struct cache *cache, struct cache_entry *entry)
{
	mutex_lock(&cache->mutex);
	--entry->refcnt;
	mutex_unlock(&cache->mutex);
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

	mutex_lock(&cache->mutex);
	if (--entry->refcnt)
		goto unlock;
	if (cache_entry_valid(entry))
		goto unlock;
	if (entry->state == cs_probe)
		--cache->nprobetotal;

	idx = entry - cache->ce;
	if (cache->ninflight--) {
		if (cache->inflight == idx)
			cache->inflight = entry->next;
		remove_entry(cache, entry);
	}

	n = cache->nprobe + cache->ngprobe;
	eprobe = cache->split;
	while (n--)
		eprobe = cache->ce[eprobe].prev;

	if (eprobe == cache->split)
		cache->split = idx;

	add_entry_after(cache, entry, idx, eprobe);

 unlock:
	mutex_unlock(&cache->mutex);
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
	cache->nprobetotal = 0;
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

	if (mutex_init(&cache->mutex, NULL)) {
		free(cache);
		return NULL;
	}

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
	mutex_lock(&cache->mutex);
	cache->entry_cleanup = fn;
	cache->cleanup_data = data;
	mutex_unlock(&cache->mutex);
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
	mutex_destroy(&cache->mutex);
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

/**  Re-allocate a cache with default parameters.
 * @param ctx  Dump file object.
 * @returns    Error status.
 *
 * This function can be used as the @c realloc_caches method if
 * the cache is organized as @c cache.size elements of @c arch.page_size
 * bytes each.
 */
kdump_status
def_realloc_caches(kdump_ctx_t *ctx)
{
	unsigned cache_size = get_cache_size(ctx);
	struct cache *cache;

	cache = cache_alloc(cache_size, get_page_size(ctx));
	if (!cache)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate cache (%u * %zu bytes)",
				 cache_size, get_page_size(ctx));

	set_attr(ctx, gattr(ctx, GKI_cache_hits),
		 ATTR_INDIRECT, &cache->hits);
	set_attr(ctx, gattr(ctx, GKI_cache_misses),
		 ATTR_INDIRECT, &cache->misses);

	if (ctx->shared->cache)
		cache_free(ctx->shared->cache);
	ctx->shared->cache = cache;

	return KDUMP_OK;
}

static kdump_status
cache_size_pre_hook(kdump_ctx_t *ctx, struct attr_data *attr,
		    kdump_attr_value_t *val)
{
	if (val->number > UINT_MAX)
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "Cache size too big (max %u)", UINT_MAX);
	return KDUMP_OK;
}

static kdump_status
cache_size_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return ctx->shared->ops && ctx->shared->ops->realloc_caches
		? ctx->shared->ops->realloc_caches(ctx)
		: KDUMP_OK;
}

const struct attr_ops cache_size_ops = {
	.pre_set = cache_size_pre_hook,
	.post_set = cache_size_post_hook,
};
