/** @internal @file src/kdumpfile/fcache.c
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
#include <sys/types.h>
#include <sys/stat.h>
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
	struct stat st;

	fc = malloc(sizeof *fc);
	if (!fc)
		return fc;

	fc->refcnt = 1;
	fc->fd = fd;
	fc->mmap_policy.number = KDUMP_MMAP_TRY;
	fc->pgsz = sysconf(_SC_PAGESIZE);
	fc->mmapsz = fc->pgsz << order;

	fc->cache = cache_alloc(1 << order, 0);
	if (!fc->cache)
		goto err;
	set_cache_entry_cleanup(fc->cache, unmap_entry, fc);

	fc->fbcache = cache_alloc(1 << order, fc->pgsz);
	if (!fc->fbcache)
		goto err_cache;

	fc->filesz = (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)
		      ? st.st_size
		      : ((unsigned long long) ~(off_t)0) >> 1);

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

/** Get file cache content using mmap(2).
 * @param fc   File cache object.
 * @param fce  File cache entry, updated on success.
 * @param pos  File position.
 * @returns    Error status.
 */
kdump_status
fcache_get_mmap(struct fcache *fc, struct fcache_entry *fce, off_t pos)
{
	struct cache_entry *ce;
	off_t blkpos;
	size_t off;

	blkpos = pos & ~(off_t)(fc->pgsz - 1);
	if (blkpos >= fc->filesz)
		return KDUMP_ERR_NODATA;

	blkpos = pos & ~(off_t)(fc->mmapsz - 1);
	ce = cache_get_entry(fc->cache, blkpos);
	if (!ce)
		return KDUMP_ERR_BUSY;

	if (!cache_entry_valid(ce)) {
		ce->data = mmap(NULL, fc->mmapsz, PROT_READ,
				MAP_SHARED, fc->fd, blkpos);
		cache_insert(fc->cache, ce);
	}

	if (ce->data == MAP_FAILED)
		return KDUMP_ERR_SYSTEM;

	fce->ce = ce;
	off = pos & (fc->mmapsz - 1);
	fce->len = fc->mmapsz - off;
	fce->data = ce->data + off;
	fce->cache = fc->cache;
	return KDUMP_OK;
}

/** Get file cache content using read(2).
 * @param fc   File cache object.
 * @param fce  File cache entry, updated on success.
 * @param pos  File position.
 * @returns    Error status.
 */
kdump_status
fcache_get_read(struct fcache *fc, struct fcache_entry *fce, off_t pos)
{
	struct cache_entry *ce;
	off_t blkpos;
	size_t off;

	blkpos = pos & ~(off_t)(fc->pgsz - 1);
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

/** Get file cache content.
 * @param fc   File cache object.
 * @param fce  File cache entry, updated on success.
 * @param pos  File position.
 * @returns    Error status.
 */
kdump_status
fcache_get(struct fcache *fc, struct fcache_entry *fce, off_t pos)
{
	kdump_mmap_policy_t policy = fc->mmap_policy.number;
	kdump_status status;

	if (policy != KDUMP_MMAP_NEVER) {
		status = fcache_get_mmap(fc, fce, pos);

		if (policy == KDUMP_MMAP_TRY_ONCE)
			fc->mmap_policy.number =
				(status == KDUMP_OK
				 ? KDUMP_MMAP_ALWAYS
				 : KDUMP_MMAP_NEVER);

		if (status == KDUMP_OK ||
		    policy == KDUMP_MMAP_ALWAYS)
			return status;
	}

	return fcache_get_read(fc, fce, pos);
}

/** Get file cache content with a fallback buffer.
 * @param fc   File cache object.
 * @param fce  File cache entry, updated on success.
 * @param pos  File position.
 * @param fb   Fallback buffer.
 * @param sz   Minimum buffer size.
 * @returns    Error status.
 *
 * On a successful return, @c fce->data points to at least @sz bytes of data
 * at file position @c pos. This is normally a pointer directly into a cache
 * entry, but if the corresponding file chunk crosses a cache entry boundary,
 * data is read into the fallback buffer instead. In that case, @c fce->cache
 * is set to @c NULL.
 */
kdump_status
fcache_get_fb(struct fcache *fc, struct fcache_entry *fce, off_t pos,
	      void *fb, size_t sz)
{
	kdump_status ret;

	ret = fcache_get(fc, fce, pos);
	if (ret != KDUMP_OK)
		return ret;
	if (fce->len < sz) {
		fcache_put(fce);
		fce->data = fb;
		fce->len = sz;
		fce->cache = NULL;
		ret = fcache_pread(fc, fb, sz, pos);
	}
	return ret;
}

/** Read file cache content into a pre-allocated buffer.
 * @param fc   File cache object.
 * @param buf  Target buffer.
 * @param pos  File position.
 * @param len  Length of data.
 * @returns    Error status.
 */
kdump_status
fcache_pread(struct fcache *fc, void *buf, size_t len, off_t pos)
{
	struct fcache_entry fce;
	kdump_status ret;

	while (len) {
		size_t partlen;

		ret = fcache_get(fc, &fce, pos);
		if (ret != KDUMP_OK)
			return ret;

		partlen = (fce.len < len) ? fce.len : len;
		memcpy(buf, fce.data, partlen);
		fcache_put(&fce);

		buf += partlen;
		pos += partlen;
		len -= partlen;
	}

	return KDUMP_OK;
}

/** Put an array of file cache entries.
 * @param fces  Array of file cache entries.
 * @param n     Number of entries in the array.
 */
static void
put_fces(struct fcache_entry *fces, size_t n)
{
	while (n--)
		fcache_put(&fces[n]);
}

/** Free an array of file cache entries.
 * @param fces  Array of file cache entries.
 * @param n     Number of entries in the array.
 */
static void
free_fces(struct fcache_entry *fces, size_t n)
{
	if (fces) {
		put_fces(fces, n);
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
 * @param len  Length of data.
 * @param pos  File position.
 * @returns    Error status.
 */
kdump_status
fcache_get_chunk(struct fcache *fc, struct fcache_chunk *fch,
		 size_t len, off_t pos)
{
	off_t first, last;
	struct fcache_entry fce;
	struct fcache_entry *fces, *curfce;
	void *data, *curdata;
	size_t remain;
	size_t nent;
	kdump_status status;

	if (!len) {
		fch->data = NULL;
		fch->nent = 0;
		return KDUMP_OK;
	}

	first = pos & ~(off_t)(fc->pgsz - 1);
	last = (pos + len - 1) & ~(off_t)(fc->pgsz - 1);
	nent = (last - first) / fc->pgsz + 1;
	if (nent > MAX_EMBED_FCES) {
		fces = malloc(nent * sizeof(*fces));
		if (!fces)
			return KDUMP_ERR_SYSTEM;
		curfce = fces;
	} else {
		fces = NULL;
		curfce = fch->embed_fces;
	}

	nent = 0;
	data = NULL;
	remain = len;
	while (remain) {
		status = fcache_get(fc, curfce, pos);
		if (status != KDUMP_OK) {
			put_fces(curfce - nent, nent);
			if (fces)
				free(fces);
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
					put_fces(curfce - nent, nent + 1);
					if (fces)
						free(fces);
					return KDUMP_ERR_SYSTEM;
				}
				curdata = copy_data(data, curfce - nent, nent);
				put_fces(curfce - nent, nent);
				fce = *curfce;
				curfce = &fce;
				if (fces)
					free(fces);
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
	if (data) {
		fch->data = data;
		fch->nent = 0;
	} else if (nent > MAX_EMBED_FCES) {
		fch->data = fces->data;
		fch->fces = fces;
	} else {
		if (fces) {
			memcpy(fch->embed_fces, fces, nent * sizeof(*fces));
			free(fces);
		}
		fch->data = fch->embed_fces->data;
	}

	return KDUMP_OK;
}

/** Return a no longer needed file cache chunk.
 * @param fch  File cache chunk.
 */
void
fcache_put_chunk(struct fcache_chunk *fch)
{
	if (fch->nent > MAX_EMBED_FCES)
		free_fces(fch->fces, fch->nent);
	else if (fch->nent)
		put_fces(fch->embed_fces, fch->nent);
	else
		free(fch->data);
}
