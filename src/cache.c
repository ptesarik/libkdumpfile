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
	unsigned split;		 /**< Split point between probed and precious
				  *   entries (index of MRU probed entry) */
	int dsplit;		 /**< Desired split point change */
	unsigned nprec;		 /**< Number of cached precious entries */
	unsigned ngprec;	 /**< Number of ghost precious entries */
	unsigned nprobe;	 /**< Number of cached probe entries */
	unsigned ngprobe;	 /**< Number of ghost probe entries */
	unsigned nprobetotal;	 /**< Total number of probe list entries,
				  *   including ghost and in-flight entries */
	unsigned cap;		 /**< Total cache capacity */
	unsigned inflight;	 /**< Index of first in-flight entry */
	unsigned ninflight;	 /**< Number of in-flight entries */

	union kdump_attr_value hits;   /**< Cache hits */
	union kdump_attr_value misses; /**< Cache misses */

	size_t elemsize;	 /**< Element data size */
	void *data;		 /**< Actual cache data */
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
	unsigned gprobe;	/**< Index of MRU probed ghost entry */
	unsigned eprobe;	/**< End of probed entries; this is the
				 *   index of the first unused entry. */
};

static struct cache_entry *get_ghost_entry(
	struct cache *cache, kdump_pfn_t pfn,
	struct cache_search *cs);
static struct cache_entry *get_inflight_entry(
	struct cache *cache, kdump_pfn_t pfn);
static struct cache_entry *get_missed_entry(
	struct cache *cache, kdump_pfn_t pfn,
	struct cache_search *cs);

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
	return cache->nprobe == 0;
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
	return cache->nprec == 0;
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

/**  Remove an active cache entry from the list.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry to be removed.
 * @param idx    Cache entry index.
 */
static void
remove_active(struct cache *cache, struct cache_entry *entry, unsigned idx)
{
	remove_entry(cache, entry);
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
	if (cache->ninflight++) {
		entry->next = cache->inflight;
		entry->prev = cache->ce[cache->inflight].prev;
	} else
		entry->next = entry->prev = idx;
	cache->inflight = idx;
}

/**  Ensure that an in-flight entry goes to the precious list, eventually.
 *
 * @param cache  Cache object.
 * @param entry  Cache entry.
 */
void
cache_make_precious(struct cache *cache, struct cache_entry *entry)
{
	if (CACHE_PFN_FLAGS(entry->pfn) == cf_probe) {
		++cache->dsplit;
		--cache->nprobetotal;
		entry->pfn = CACHE_PFN(entry->pfn) |
			CACHE_FLAGS_PFN(cf_precious);
	}
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
		remove_active(cache, entry, idx);

		prev = &cache->ce[cache->split];
		next = &cache->ce[prev->next];
		entry->next = prev->next;
		prev->next = idx;
		entry->prev = next->prev;
		next->prev = idx;
	}

	cache->split = entry->prev;
}

/**  Re-initialize an entry for a different page.
 *
 * @param cache  Cache object.
 * @param entry  Entry to be reinitialized.
 * @param cs     Cache search info.
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
reinit_entry(struct cache *cache, struct cache_entry *entry,
	     struct cache_search *cs)
{
	unsigned evict;
	int delta = cache->dsplit;

	if (delta <= 0 && probe_cache_empty(cache))
		delta = 1;
	else if (delta > 0 && prec_cache_empty(cache))
		delta = 0;

	if (delta <= 0) {
		evict = cache->ce[cs->gprobe].next;
		--cache->nprobe;
		++cache->ngprobe;
	} else {
		--cache->dsplit;
		evict = cache->ce[cs->gprec].prev;
		--cache->nprec;
		++cache->ngprec;
	}
	entry->data = cache->ce[evict].data;
	cache->ce[evict].data = NULL;
}

/**  Reuse a ghost entry.
 *
 * @param cache  Cache object.
 * @param entry  Ghost entry to be reused.
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
		  struct cache_search *cs)
{
	unsigned idx, evict;
	int delta = cache->dsplit;

	if (delta < 0 && probe_cache_empty(cache))
		delta = 0;
	else if (delta >= 0 && prec_cache_empty(cache))
		delta = -1;

	idx = entry - cache->ce;
	if (delta < 0) {
		++cache->dsplit;
		evict = cache->ce[cs->gprobe].next;
		--cache->nprobe;
		++cache->ngprobe;
	} else {
		evict = cache->ce[cs->gprec].prev;
		--cache->nprec;
		++cache->ngprec;
	}
	entry->data = cache->ce[evict].data;
	cache->ce[evict].data = NULL;

	if (cache->split == idx)
		cache->split = entry->prev;

	remove_active(cache, entry, idx);
	add_inflight(cache, entry, idx);
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
	struct cache_search cs;
	struct cache_entry *entry;
	unsigned n, idx;

	/* Search precious entries */
	n = cache->nprec;
	idx = cache->ce[cache->split].next;
	while (n--) {
		entry = &cache->ce[idx];
		if (entry->pfn == pfn) {
			use_precious(cache, entry);
			++cache->hits.number;
			return entry;
		}
		idx = entry->next;
	}
	cs.gprec = idx;

	/* Search probed entries */
	n = cache->nprobe;
	idx = cache->split;
	while (n--) {
		entry = &cache->ce[idx];
		if (entry->pfn == pfn) {
			++cache->dsplit;
			--cache->nprobe;
			++cache->nprec;
			--cache->nprobetotal;
			use_precious(cache, entry);
			++cache->hits.number;
			return entry;
		}
		idx = entry->prev;
	}
	cs.gprobe = idx;

	++cache->misses.number;

	entry = get_ghost_entry(cache, pfn, &cs);
	if (!entry)
		entry = get_inflight_entry(cache, pfn);
	if (!entry)
		entry = get_missed_entry(cache, pfn, &cs);

	return entry;
}

/**  Get the ghost entry for a given PFN.
 *
 * @param cache  Cache object.
 * @param pfn    PFN to be searched.
 * @param cs     Cache search info.
 * @returns      Ghost entry, or @c NULL if not found.
 *
 * If no entry is found (function returns @c NULL), the @c epreca and
 * @c eprobe fields in @ref cs are updated. Otherwise (if an entry is
 * found), their values are undefined.
 */
static struct cache_entry *
get_ghost_entry(struct cache *cache, kdump_pfn_t pfn,
		struct cache_search *cs)
{
	struct cache_entry *entry;
	unsigned n, idx;

	/* Search precious ghost entries */
	n = cache->ngprec;
	idx = cs->gprec;
	while (n--) {
		entry = &cache->ce[idx];
		if (entry->pfn == pfn) {
			if (!probe_cache_empty(cache))
				--cache->dsplit;
			--cache->ngprec;
			reuse_ghost_entry(cache, entry, cs);
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
		if (entry->pfn == pfn) {
			++cache->dsplit;
			--cache->ngprobe;
			--cache->nprobetotal;
			reuse_ghost_entry(cache, entry, cs);
			return entry;
		}
		idx = entry->prev;
	}
	cs->eprobe = idx;

	return NULL;
}

/**  Get the in-flight entry for a given PFN.
 *
 * @param cache  Cache object.
 * @param pfn    PFN to be searched.
 * @returns      In-flight entry, or @c NULL if not found.
 */
static struct cache_entry *
get_inflight_entry(struct cache *cache, kdump_pfn_t pfn)
{
	struct cache_entry *entry;
	unsigned idx, n;

	idx = cache->inflight;
	for (n = cache->ninflight; n; --n) {
		entry = &cache->ce[idx];
		if (CACHE_PFN(entry->pfn) == pfn) {
			cache_make_precious(cache, entry);
			return entry;
		}
		idx = entry->next;
	}

	return NULL;
}

/**  Get a cache entry for a given missed PFN.
 *
 * @param cache  Cache object.
 * @param pfn    Requested PFN.
 * @param cs     Cache search info.
 * @returns      A new cache entry.
 */
static struct cache_entry *
get_missed_entry(struct cache *cache, kdump_pfn_t pfn,
		 struct cache_search *cs)
{
	struct cache_entry *entry;
	unsigned idx;

	if (cache->nprobetotal == cache->cap) {
		idx = cache->ce[cs->eprobe].next;
		entry = &cache->ce[idx];
		if (cache->ngprobe)
			--cache->ngprobe;
		else
			--cache->nprobe;
	} else {
		idx = cs->eprobe;
		entry = &cache->ce[idx];
		if (entry->next == cs->eprec && cache->ngprec)
			--cache->ngprec;
		++cache->nprobetotal;
		if (entry->data)
			--cache->dsplit;
	}

	if (!entry->data)
		reinit_entry(cache, entry, cs);

	if (cache->split == idx)
		cache->split = entry->prev;

	remove_active(cache, entry, idx);
	add_inflight(cache, entry, idx);
	entry->pfn = pfn | CACHE_FLAGS_PFN(cf_probe);

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
	unsigned idx;

	if (cache_entry_valid(entry))
		return;
	if (cache->ninflight--)
		remove_entry(cache, entry);

	idx = entry - cache->ce;
	prev = &cache->ce[cache->split];
	next = &cache->ce[prev->next];

	switch (CACHE_PFN_FLAGS(entry->pfn)) {
	case cf_probe:
		++cache->nprobe;
		cache->split = idx;
		break;

	case cf_precious:
		++cache->nprec;
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
		entry->next = (i < n - 1) ? (i + 1) : 0;
		entry->prev = (i > 0) ? (i - 1) : (n - 1);
		entry->data = i < cache->cap
			? cache->data + i * cache->elemsize
			: NULL;
	}

	cache->split = cache->cap - 1;
	cache->dsplit = 0;
	cache->nprec = 0;
	cache->ngprec = 0;
	cache->nprobe = 0;
	cache->ngprobe = 0;
	cache->nprobetotal = 0;
	cache->ninflight = 0;
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
	cache->hits.number = 0;
	cache->misses.number = 0;

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

/**  Default way to handle cached reads.
 *
 * @param ctx  Dump file object.
 * @param pio  Page I/O control.
 * @param fn   Read function.
 * @param idx  Page index passed to @ref fn (usually PFN).
 * @returns    Error status.
 */
kdump_status
def_read_cache(kdump_ctx *ctx, struct page_io *pio,
	       read_cache_fn *fn, kdump_pfn_t idx)
{
	struct cache_entry *entry;
	kdump_status ret;

	entry = cache_get_entry(ctx->cache, idx);
	pio->buf = entry->data;
	if (cache_entry_valid(entry))
		return kdump_ok;

	ret = fn(ctx, idx, entry);
	if (ret == kdump_ok) {
		if (pio->precious)
			cache_make_precious(ctx->cache, entry);
		cache_insert(ctx->cache, entry);
	} else
		cache_discard(ctx->cache, entry);
	return ret;
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
def_realloc_caches(kdump_ctx *ctx)
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
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate cache (%u * %zu bytes)",
				 cache_size, get_page_size(ctx));

	if (ctx->cache)
		cache_free(ctx->cache);
	ctx->cache = cache;
	set_attr_indirect(ctx, GATTR(GKI_cache_hits), &cache->hits);
	set_attr_indirect(ctx, GATTR(GKI_cache_misses), &cache->misses);

	return kdump_ok;
}

static kdump_status
cache_size_pre_hook(kdump_ctx *ctx, struct attr_data *attr,
		    union kdump_attr_value *val)
{
	if (val->number > UINT_MAX)
		return set_error(ctx, kdump_invalid,
				 "Cache size too big (max %u)", UINT_MAX);
	return kdump_ok;
}

static kdump_status
cache_size_post_hook(kdump_ctx *ctx, struct attr_data *attr)
{
	return ctx->ops && ctx->ops->realloc_caches
		? ctx->ops->realloc_caches(ctx)
		: kdump_ok;
}

const struct attr_ops cache_size_ops = {
	.pre_set = cache_size_pre_hook,
	.post_set = cache_size_post_hook,
};
