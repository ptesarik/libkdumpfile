/** @internal @file src/context.c
 * @brief Functions that provide access to kdump_ctx contents.
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

const char *
kdump_err_str(kdump_ctx *ctx)
{
	return ctx->err_str;
}

kdump_byte_order_t
kdump_byte_order(kdump_ctx *ctx)
{
	kdump_byte_order_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_byte_order(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

size_t
kdump_ptr_size(kdump_ctx *ctx)
{
	size_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_ptr_size(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

const char *
kdump_arch_name(kdump_ctx *ctx)
{
	const char *ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_arch_name(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_xen_type_t
kdump_xen_type(kdump_ctx *ctx)
{
	kdump_xen_type_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_xen_type(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

size_t
kdump_pagesize(kdump_ctx *ctx)
{
	size_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_page_size(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

unsigned
kdump_pageshift(kdump_ctx *ctx)
{
	unsigned ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_page_shift(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_paddr_t
kdump_phys_base(kdump_ctx *ctx)
{
	kdump_paddr_t ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_phys_base(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

static const char *
get_string_attr(kdump_ctx *ctx, struct attr_data *attr)
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
kdump_get_string_attr(kdump_ctx *ctx, const char *key)
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
kdump_format(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_format_name));
}

const char *
kdump_sysname(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_linux_uts_sysname));
}

const char *
kdump_nodename(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_linux_uts_nodename));
}

const char *
kdump_release(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_linux_uts_release));
}

const char *
kdump_version(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_linux_uts_version));
}

const char *
kdump_machine(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_linux_uts_machine));
}

const char *
kdump_domainname(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_linux_uts_domainname));
}

unsigned
kdump_version_code(kdump_ctx *ctx)
{
	unsigned ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_version_code(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

unsigned
kdump_num_cpus(kdump_ctx *ctx)
{
	unsigned ret;
	rwlock_rdlock(&ctx->shared->lock);
	ret = get_num_cpus(ctx);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

const char *
kdump_vmcoreinfo(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_linux_vmcoreinfo_raw));
}

const char *
kdump_vmcoreinfo_xen(kdump_ctx *ctx)
{
	return get_string_attr(ctx, gattr(ctx, GKI_xen_vmcoreinfo_raw));
}

kdump_get_symbol_val_fn *
kdump_cb_get_symbol_val(kdump_ctx *ctx, kdump_get_symbol_val_fn *cb)
{
	kdump_get_symbol_val_fn *ret = ctx->cb_get_symbol_val;
	ctx->cb_get_symbol_val = cb ?: kdump_vmcoreinfo_symbol;
	return ret;
}

void
kdump_set_priv(kdump_ctx *ctx, void *data)
{
	ctx->priv = data;
}

void *
kdump_get_priv(kdump_ctx *ctx)
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
	kdump_ctx *ctx;
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
						 kdump_ctx, list);
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
	kdump_ctx *ctx;

	list_for_each_entry(ctx, &shared->ctx, list)
		free(ctx->data[slot]);
	shared->per_ctx_size[slot] = 0;
}
