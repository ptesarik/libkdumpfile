/** @internal @file src/fcache.c
 * @brief File caching.
 */
/* Copyright (C) 2017 Petr Tesarik <ptesarik@suse.com>

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
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/** Destructor for mmapped cache entries.
 * @param ce  Cache entry.
 */
static void
unmap_entry(void *data, struct cache_entry *ce)
{
	struct fcache *fc = data;
	if (ce->data != MAP_FAILED)
		munmap(ce->data, fc->mmapsz);
}

/** Allocate and initialize a new file cache.
 * @param fd     File descriptor.
 * @param n      Number of elements in the cache.
 * @param order  Page order of mmap regions.
 * @returns      File cache object, or @c NULL on allocation failure.
 */
struct fcache *
fcache_new(int fd, unsigned n, unsigned order)
{
	struct fcache *fc;

	fc = malloc(sizeof *fc);
	if (!fc)
		return fc;

	fc->fd = fd;
	fc->pgsz = sysconf(_SC_PAGESIZE);
	fc->mmapsz = fc->pgsz << order;

	fc->cache = cache_alloc(1 << order, 0);
	if (!fc->cache)
		goto err;
	set_cache_entry_cleanup(fc->cache, unmap_entry, fc);

	fc->fbcache = cache_alloc(1 << order, fc->pgsz);
	if (!fc->fbcache)
		goto err_cache;
	return fc;

 err_cache:
	cache_free(fc->cache);
 err:
	free(fc);
	return NULL;
}

/** Free a file cache.
 * @param fc  File cache object.
 */
void
fcache_free(struct fcache *fc)
{
	cache_free(fc->fbcache);
	cache_free(fc->cache);
	free(fc);
}

/** Get file cache content.
 * @param fc   File cache object.
 * @param fce  File cache entry, updated on success.
 * @param pos  File position.
 * @returns    Error status.
 */
kdump_status
fcache_get(struct fcache *fc, struct fcache_entry *fce, off_t pos)
{
	off_t blkpos;
	size_t off;
	struct cache_entry *ce;

	blkpos = pos & ~(fc->mmapsz - 1);
	ce = cache_get_entry(fc->cache, blkpos);
	if (!ce)
		return KDUMP_ERR_BUSY;

	if (!cache_entry_valid(ce)) {
		ce->data = mmap(NULL, fc->mmapsz, PROT_READ, MAP_SHARED,
				fc->fd, blkpos);
		cache_insert(fc->cache, ce);
	}

	if (ce->data != MAP_FAILED) {
		fce->ce = ce;
		off = pos & (fc->mmapsz - 1);
		fce->len = fc->mmapsz - off;
		fce->data = ce->data + off;
		fce->cache = fc->cache;
		return KDUMP_OK;
	}

	blkpos = pos & ~(fc->pgsz - 1);
	ce = cache_get_entry(fc->fbcache, blkpos);
	if (!ce)
		return KDUMP_ERR_BUSY;

	if (!cache_entry_valid(ce)) {
		ssize_t rd = pread(fc->fd, ce->data, fc->pgsz, blkpos);
		if (rd < 0) {
			cache_discard(fc->fbcache, ce);
			return KDUMP_ERR_SYSTEM;
		}
		if (rd < fc->pgsz)
			memset(ce->data + rd, 0, fc->pgsz - rd);
		cache_insert(fc->fbcache, ce);
	}

	fce->ce = ce;
	off = pos & (fc->pgsz - 1);
	fce->len = fc->pgsz - off;
	fce->data = ce->data + off;
	fce->cache = fc->fbcache;
	return KDUMP_OK;
}
