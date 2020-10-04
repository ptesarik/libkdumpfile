/** @internal @file src/kdumpfile/context.c
 * @brief Functions that provide access to kdump_ctx_t contents.
 */
/* Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

/** Maximum length of the static error message. */
#define ERRBUF	160

static kdump_ctx_t *
alloc_ctx(void)
{
	kdump_ctx_t *ctx;
	unsigned i;

	ctx = calloc(1, sizeof (kdump_ctx_t) + ERRBUF);
	if (!ctx)
		return ctx;

	err_init(&ctx->err, ERRBUF);

	ctx->xlatctx = init_addrxlat(ctx);
	if (!ctx->xlatctx)
		goto err;

	return ctx;

 err:
	err_cleanup(&ctx->err);
	free(ctx);
	return NULL;
}

static struct kdump_shared *
alloc_shared(void)
{
	struct kdump_shared *shared;

	shared = calloc(1, sizeof *shared);
	if (!shared)
		return shared;
	list_init(&shared->ctx);

	if (rwlock_init(&shared->lock, NULL))
		goto err1;

	if (mutex_init(&shared->cache_lock, NULL))
		goto err2;

	shared->refcnt = 1;
	return shared;

 err2:	rwlock_destroy(&shared->lock);
 err1:	free(shared);
	return NULL;
}

/** Clean up and free shared info.
 * @param shared  Shared info.
 *
 * The shared info must be locked by the caller.
 */
void
shared_free(struct kdump_shared *shared)
{
	rwlock_unlock(&shared->lock);

	if (shared->ops && shared->ops->cleanup)
		shared->ops->cleanup(shared);
	if (shared->arch_ops && shared->arch_ops->cleanup)
		shared->arch_ops->cleanup(shared);
	if (shared->cache)
		cache_free(shared->cache);
	if (shared->fcache)
		fcache_decref(shared->fcache);
	mutex_destroy(&shared->cache_lock);
	rwlock_destroy(&shared->lock);
	free(shared);
}

/** Increment shared info reference counter.
 * @param shared  Shared info.
 * @returns       New reference count.
 */
unsigned long
shared_incref(struct kdump_shared *shared)
{
	unsigned long refcnt;

	rwlock_wrlock(&shared->lock);
	refcnt = shared_incref_locked(shared);
	rwlock_unlock(&shared->lock);
	return refcnt;
}

/** Decrement shared info reference counter.
 * @param shared  Shared info.
 * @returns       New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
unsigned long
shared_decref(struct kdump_shared *shared)
{
	unsigned long refcnt;

	rwlock_wrlock(&shared->lock);
	refcnt = shared_decref_locked(shared);
	if (refcnt)
		rwlock_unlock(&shared->lock);
	return refcnt;
}

kdump_ctx_t *
kdump_new(void)
{
	kdump_ctx_t *ctx;

	ctx = alloc_ctx();
	if (!ctx)
		return NULL;

	ctx->shared = alloc_shared();
	if (!ctx->shared)
		goto err;
	list_add(&ctx->list, &ctx->shared->ctx);

	ctx->dict = attr_dict_new(ctx->shared);
	if (!ctx->dict)
		goto err_dict;

	ctx->xlat = xlat_new();
	if (!ctx->xlat)
		goto err_xlat;
	list_add(&ctx->xlat_list, &ctx->xlat->ctx);

	set_attr_number(ctx, gattr(ctx, GKI_cache_size),
			ATTR_PERSIST, DEFAULT_CACHE_SIZE);
	set_attr_number(ctx, gattr(ctx, GKI_cache_hits),
			ATTR_PERSIST, 0);
	set_attr_number(ctx, gattr(ctx, GKI_cache_misses),
			ATTR_PERSIST, 0);
	set_attr_number(ctx, gattr(ctx, GKI_file_mmap_policy),
			ATTR_PERSIST, KDUMP_MMAP_TRY);

	return ctx;

 err_xlat:
	attr_dict_decref(ctx->dict);
 err_dict:
	shared_decref(ctx->shared);
 err:
	addrxlat_ctx_decref(ctx->xlatctx);
	free(ctx);
	return NULL;
}

static bool
clone_xlat_attrs(kdump_ctx_t *dest, const kdump_ctx_t *orig)
{
	static const enum global_keyidx globals[] = {
		GKI_xlat_opts_pre,
		GKI_xlat_opts_post,
		GKI_ostype,
	};

	int i;
	for (i = 0; i < ARRAY_SIZE(globals); ++i) {
		struct attr_data *attr = dgattr(orig->dict, globals[i]);
		if (! clone_attr_path(dest->dict, attr))
			return false;
	}
	return true;
}

kdump_ctx_t *
kdump_clone(const kdump_ctx_t *orig, unsigned long flags)
{
	kdump_ctx_t *ctx;
	int slot;

	ctx = alloc_ctx();
	if (!ctx)
		return ctx;

	rwlock_rdlock(&orig->shared->lock);
	for (slot = 0; slot < PER_CTX_SLOTS; ++slot) {
		size_t sz = orig->shared->per_ctx_size[slot];
		if (!sz)
			continue;
		if (! (ctx->data[slot] = malloc(sz)) ) {
			while (slot-- > 0)
				if (orig->shared->per_ctx_size[slot])
					free(ctx->data[slot]);
			addrxlat_ctx_decref(ctx->xlatctx);
			free(ctx);
			return NULL;
		}
	}
	rwlock_unlock(&orig->shared->lock);

	rwlock_wrlock(&orig->shared->lock);
	ctx->shared = orig->shared;
	shared_incref_locked(ctx->shared);
	list_add(&ctx->list, &orig->shared->ctx);

	if (flags) {
		ctx->dict = attr_dict_clone(orig->dict);
		if (!ctx->dict)
			goto err_shared;
	} else {
		ctx->dict = orig->dict;
		attr_dict_incref(ctx->dict);
	}

	if (flags & KDUMP_CLONE_XLAT) {
		ctx->xlat = xlat_clone(orig->xlat);
		if (!ctx->xlat)
			goto err_dict;
		if (!clone_xlat_attrs(ctx, orig))
			goto err_xlat;
	} else {
		ctx->xlat = orig->xlat;
		xlat_incref(ctx->xlat);
	}
	list_add(&ctx->xlat_list, &ctx->xlat->ctx);

	rwlock_unlock(&orig->shared->lock);

	return ctx;

 err_xlat:
	xlat_decref(ctx->xlat);
 err_dict:
	attr_dict_decref(ctx->dict);
 err_shared:
	list_del(&ctx->list);
	shared_decref_locked(ctx->shared);
	rwlock_unlock(&orig->shared->lock);
	free(ctx);
	return NULL;
}

const char *
kdump_get_err(kdump_ctx_t *ctx)
{
	return err_str(&ctx->err);
}

kdump_errmsg_t *
kdump_get_errmsg(kdump_ctx_t *ctx)
{
	return &ctx->err;
}

kdump_status
kdump_get_addrxlat(kdump_ctx_t *ctx,
		   addrxlat_ctx_t **axctx, addrxlat_sys_t **axsys)
{
	kdump_status status;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	status = revalidate_xlat(ctx);
	if (status == KDUMP_OK) {
		if (axctx) {
			*axctx = ctx->xlatctx;
			addrxlat_ctx_incref(*axctx);
		}

		if (axsys) {
			*axsys = ctx->xlat->xlatsys;
			addrxlat_sys_incref(*axsys);
		}
	}

	rwlock_unlock(&ctx->shared->lock);
	return status;
}

/**  Allocate per-context data.
 * @param shared  Dump file shared data.
 * @param sz      Size of per-context data.
 * @returns       Per-context slot number, or -1 on error.
 *
 * On error, @c errno is set to:
 * - @c EAGAIN  All slots are already in use.
 * - @c ENOMEM  Memory allocation failure.
 */
int
per_ctx_alloc(struct kdump_shared *shared, size_t sz)
{
	kdump_ctx_t *ctx;
	int slot;

	/* Allocate a slot. */
	for (slot = 0; slot < PER_CTX_SLOTS; ++slot)
		if (!shared->per_ctx_size[slot])
			break;
	if (slot >= PER_CTX_SLOTS) {
		errno = EAGAIN;
		return -1;
	}
	shared->per_ctx_size[slot] = sz;

	/* Allocate memory. */
	list_for_each_entry(ctx, &shared->ctx, list)
		if (! (ctx->data[slot] = malloc(sz)) ) {
			while (ctx->list.prev != &shared->ctx) {
				ctx = list_entry(ctx->list.prev,
						 kdump_ctx_t, list);
				free(ctx->data[slot]);
			}
			shared->per_ctx_size[slot] = 0;
			return -1;
		}

	return slot;
}

/**  Free per-context data.
 * @param shared  Dump file shared data.
 * @param slot    Per-context slot number.
 */
void
per_ctx_free(struct kdump_shared *shared, int slot)
{
	kdump_ctx_t *ctx;

	list_for_each_entry(ctx, &shared->ctx, list)
		free(ctx->data[slot]);
	shared->per_ctx_size[slot] = 0;
}

const char *
kdump_strerror(kdump_status status)
{
	switch (status) {
	case KDUMP_OK:
		return "Success";
	case KDUMP_ERR_SYSTEM:
		return "OS error";
	case KDUMP_ERR_NOTIMPL:
		return "Unimplemented feature";
	case KDUMP_ERR_NODATA:
		return "Data is not stored in the dump file";
	case KDUMP_ERR_CORRUPT:
		return "Corrupted file data";
	case KDUMP_ERR_INVALID:
		return "Invalid value";
	case KDUMP_ERR_NOKEY:
		return "No such attribute key";
	case KDUMP_ERR_EOF:
		return "Unexpected EOF";
	case KDUMP_ERR_BUSY:
		return "Too many pending requests";
	case KDUMP_ERR_ADDRXLAT:
		return "Address translation error";
	default:
		return "Unknown error";
	}
}

uint_fast16_t
kdump_d16toh(kdump_ctx_t *ctx, uint_fast16_t val)
{
	return dump16toh(ctx, val);
}

uint_fast32_t
kdump_d32toh(kdump_ctx_t *ctx, uint_fast32_t val)
{
	return dump32toh(ctx, val);
}

uint_fast64_t
kdump_d64toh(kdump_ctx_t *ctx, uint_fast64_t val)
{
	return dump64toh(ctx, val);
}
