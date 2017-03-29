/** @internal @file src/context.c
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

static kdump_ctx_t *
alloc_ctx(void)
{
	kdump_ctx_t *ctx;

	ctx = calloc(1, sizeof (kdump_ctx_t));
	if (!ctx)
		return ctx;
	ctx->cb_get_symbol_val = kdump_vmcoreinfo_symbol;

	ctx->xlatctx = init_addrxlat(ctx);
	if (!ctx->xlatctx) {
		free(ctx);
		return NULL;
	}

	return ctx;
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

	shared->xlatsys = addrxlat_sys_new();
	if (!shared->xlatsys)
		goto err2;

	if (!init_attrs(shared))
		goto err3;

	return shared;

 err3:	addrxlat_sys_decref(shared->xlatsys);
 err2:	rwlock_destroy(&shared->lock);
 err1:	free(shared);
	return NULL;
}

kdump_ctx_t *
kdump_new(void)
{
	kdump_ctx_t *ctx;

	ctx = alloc_ctx();
	if (!ctx)
		return NULL;

	ctx->shared = alloc_shared();
	if (!ctx->shared) {
		addrxlat_ctx_decref(ctx->xlatctx);
		free(ctx);
		return NULL;
	}
	list_add(&ctx->list, &ctx->shared->ctx);

	set_attr_number(ctx, gattr(ctx, GKI_cache_size),
			ATTR_PERSIST, DEFAULT_CACHE_SIZE);

	return ctx;
}

kdump_ctx_t *
kdump_clone(const kdump_ctx_t *orig)
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
	list_add(&ctx->list, &orig->shared->ctx);
	rwlock_unlock(&orig->shared->lock);

	ctx->priv = orig->priv;
	ctx->cb_get_symbol_val = orig->cb_get_symbol_val;
	return ctx;
}

const char *
kdump_err_str(kdump_ctx_t *ctx)
{
	return ctx->err_str;
}

addrxlat_ctx_t *
kdump_get_addrxlat_ctx(const kdump_ctx_t *ctx)
{
	addrxlat_ctx_t *ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = ctx->xlatctx;
	addrxlat_ctx_incref(ret);
	rwlock_unlock(&ctx->shared->lock);

	return ret;
}

addrxlat_sys_t *
kdump_get_addrxlat_sys(const kdump_ctx_t *ctx)
{
	addrxlat_sys_t *ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = ctx->shared->xlatsys;
	addrxlat_sys_incref(ret);
	rwlock_unlock(&ctx->shared->lock);

	return ret;
}

kdump_byte_order_t
kdump_byte_order(kdump_ctx_t *ctx)
{
	kdump_byte_order_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_byte_order(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

size_t
kdump_ptr_size(kdump_ctx_t *ctx)
{
	size_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_ptr_size(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

const char *
kdump_arch_name(kdump_ctx_t *ctx)
{
	const char *ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_arch_name(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_xen_type_t
kdump_xen_type(kdump_ctx_t *ctx)
{
	kdump_xen_type_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_xen_type(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

size_t
kdump_pagesize(kdump_ctx_t *ctx)
{
	size_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_page_size(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

unsigned
kdump_pageshift(kdump_ctx_t *ctx)
{
	unsigned ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_page_shift(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

static const char *
get_string_attr(kdump_ctx_t *ctx, struct attr_data *attr)
{
	const char *ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = (validate_attr(ctx, attr) == kdump_ok &&
	       attr->template->type == kdump_string)
		? attr_value(attr)->string
		: NULL;
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

const char *
kdump_get_string_attr(kdump_ctx_t *ctx, const char *key)
{
	struct attr_data *attr;
	const char *ret = NULL;

	rwlock_rdlock(&ctx->shared->lock);
	attr = lookup_attr(ctx->shared, key);
	if (attr && validate_attr(ctx, attr) == kdump_ok &&
	    attr->template->type == kdump_string)
		ret = attr_value(attr)->string;
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

const char *
kdump_format(kdump_ctx_t *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_file_format));
}

unsigned
kdump_num_cpus(kdump_ctx_t *ctx)
{
	unsigned ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_num_cpus(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_get_symbol_val_fn *
kdump_cb_get_symbol_val(kdump_ctx_t *ctx, kdump_get_symbol_val_fn *cb)
{
	kdump_get_symbol_val_fn *ret = ctx->cb_get_symbol_val;
	ctx->cb_get_symbol_val = cb ?: kdump_vmcoreinfo_symbol;
	return ret;
}

void
kdump_set_priv(kdump_ctx_t *ctx, void *data)
{
	ctx->priv = data;
}

void *
kdump_get_priv(kdump_ctx_t *ctx)
{
	return ctx->priv;
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
