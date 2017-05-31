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

/** Free an array of file cache entries.
 * @param fces  Array of file cache entries.
 * @param n     Number of entries in the array.
 */
static void
free_fces(struct fcache_entry *fces, size_t n)
{
	if (fces) {
		while (n--)
			fcache_put(&fces[n]);
		free(fces);
	}
}

/** Copy data out of an array of file cache entries.
 * @param data  Pre-allocated buffer.
 * @param fces  Array of file cache entries.
 * @param n     Number of entries in the array.
 * @returns     Pointer past end of buffer.
 */
static void *
copy_data(void *data, struct fcache_entry *fces, size_t n)
{
	size_t i;
	for (i = 0; i < n; ++i) {
		memcpy(data, fces[i].data, fces[i].len);
		data += fces[i].len;
	}
	return data;
}

/** Get a contiguous data chunk using a file cache.
 * @param fc   File cache.
 * @param fch  File cache chunk, updated on success.
 * @param pos  File position.
 * @param len  Length of data.
 * @returns    Error status.
 */
kdump_status
fcache_get_chunk(struct fcache *fc, struct fcache_chunk *fch,
		 off_t pos, size_t len)
{
	off_t first, last;
	struct fcache_entry fce;
	struct fcache_entry *fces, *curfce;
	void *data, *curdata;
	size_t remain;
	size_t nent;
	kdump_status status;

	first = pos & ~(fc->pgsz - 1);
	last = (pos + len - 1) & ~(fc->pgsz - 1);
	if (last != first) {
		fces = malloc(((last - first) / fc->pgsz + 1) * sizeof(*fces));
		if (!fces)
			return KDUMP_ERR_SYSTEM;
		curfce = fces;
	} else {
		fces = NULL;
		curfce = &fce;
	}

	nent = 0;
	data = NULL;
	remain = len;
	while (remain) {
		status = fcache_get(fc, curfce, pos);
		if (status != KDUMP_OK) {
			free_fces(fces, nent);
			return status;
		}

		if (curfce->len > remain)
			curfce->len = remain;

		if (!nent)
			curdata = curfce->data;
		else if (curfce->data != curdata) {
			if (!data) {
				data = malloc(len);
				if (!data) {
					free_fces(fces, nent + 1);
					return KDUMP_ERR_SYSTEM;
				}
				curdata = copy_data(data, fces, nent);

				fce = *curfce;
				curfce = &fce;
				free_fces(fces, nent);
			}
			memcpy(curdata, curfce->data, curfce->len);
		}

		curdata += curfce->len;
		pos += curfce->len;
		remain -= curfce->len;

		if (data)
			fcache_put(curfce);
		else
			++curfce;
		++nent;
	}

	fch->nent = nent;
	if (nent > 1) {
		if (data) {
			fch->data = data;
			fch->nent = 0;
		} else {
			fch->data = fces->data;
			fch->fces = fces;
		}
	} else if (nent) {
		--curfce;
		fch->data = curfce->data;
		fch->fce = *curfce;
		if (fces)
			free(fces);
	}

	return KDUMP_OK;
}

/** Return a no longer needed file cache chunk.
 * @param fch  File cache chunk.
 */
void
fcache_put_chunk(struct fcache_chunk *fch)
{
	if (fch->nent > 1)
		free_fces(fch->fces, fch->nent);
	else if (fch->nent)
		fcache_put(&fch->fce);
	else
		free(fch->data);
}
