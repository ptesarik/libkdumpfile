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

kdump_status
kdump_get_attr(kdump_ctx *ctx, const char *key, kdump_attr_t *valp)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	d = lookup_attr(ctx->shared, key);
	if (!d) {
		ret = set_error(ctx, kdump_nokey, "No such key");
		goto out;
	}
	if (validate_attr(ctx, d) != kdump_ok) {
		ret = set_error(ctx, kdump_nodata, "Key has no value");
		goto out;
	}

	valp->type = d->template->type;
	valp->val = *attr_value(d);
	ret = kdump_ok;

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Set an attribute value with type check.
 * @param ctx   Dump file object.
 * @param attr  Attribute to be modified.
 * @param valp  New value for the attribute.
 */
static kdump_status
check_set_attr(kdump_ctx *ctx, struct attr_data *attr,
	       const kdump_attr_t *valp)
{
	if (valp->type == kdump_nil) {
		clear_attr(attr);
		return kdump_ok;
	}

	if (valp->type != attr->template->type)
		return set_error(ctx, kdump_invalid, "Type mismatch");

	if (valp->type == kdump_string)
		return set_attr_string(ctx, attr, valp->val.string);

	return set_attr(ctx, attr, valp->val);
}

kdump_status
kdump_set_attr(kdump_ctx *ctx, const char *key,
	       const kdump_attr_t *valp)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_wrlock(&ctx->shared->lock);

	d = lookup_attr(ctx->shared, key);
	if (!d) {
		ret = set_error(ctx, kdump_nodata, "No such key");
		goto out;
	}

	ret = check_set_attr(ctx, d, valp);

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Convert attribute data to an attribute reference.
 * @param[out] ref   Attribute reference.
 * @param[in]  attr  Attribute data.
 */
static inline void
mkref(kdump_attr_ref_t *ref, struct attr_data *attr)
{
	ref->_ptr = attr;
}

/**  Convert an attribute reference to attribute data.
 * @param ref  Attribute reference.
 * @returns    Attribute data.
 */
static inline struct attr_data *
ref_attr(const kdump_attr_ref_t *ref)
{
	return ref->_ptr;
}

kdump_status
kdump_attr_ref(kdump_ctx *ctx, const char *key, kdump_attr_ref_t *ref)
{
	struct attr_data *d;

	clear_error(ctx);

	rwlock_rdlock(&ctx->shared->lock);
	d = lookup_attr(ctx->shared, key);
	rwlock_unlock(&ctx->shared->lock);
	if (!d)
		return set_error(ctx, kdump_nokey, "No such key");

	mkref(ref, d);
	return kdump_ok;
}

kdump_status
kdump_sub_attr_ref(kdump_ctx *ctx, const kdump_attr_ref_t *base,
		   const char *subkey, kdump_attr_ref_t *ref)
{
	struct attr_data *dir, *attr;

	clear_error(ctx);

	dir = ref_attr(base);
	rwlock_rdlock(&ctx->shared->lock);
	attr = lookup_dir_attr(ctx->shared, dir, subkey, strlen(subkey));
	rwlock_unlock(&ctx->shared->lock);
	if (!attr)
		return set_error(ctx, kdump_nokey, "No such key");

	mkref(ref, attr);
	return kdump_ok;
}

void
kdump_attr_unref(kdump_ctx *ctx, kdump_attr_ref_t *ref)
{
	clear_error(ctx);
}

kdump_attr_type_t
kdump_attr_ref_type(kdump_attr_ref_t *ref)
{
	return ref_attr(ref)->template->type;
}

kdump_status
kdump_attr_ref_get(kdump_ctx *ctx, const kdump_attr_ref_t *ref,
		   kdump_attr_t *valp)
{
	struct attr_data *d = ref_attr(ref);
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	if (validate_attr(ctx, d) != kdump_ok) {
		ret = set_error(ctx, kdump_nodata, "Key has no value");
		goto out;
	}

	valp->type = d->template->type;
	valp->val = *attr_value(d);
	ret = kdump_ok;

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_attr_ref_set(kdump_ctx *ctx, kdump_attr_ref_t *ref,
		   const kdump_attr_t *valp)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_wrlock(&ctx->shared->lock);

	ret = check_set_attr(ctx, ref_attr(ref), valp);

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

static kdump_status
set_iter_pos(kdump_attr_iter_t *iter, struct attr_data *attr)
{
	while (attr && !attr_isset(attr))
		attr = attr->next;

	iter->key = attr ? attr->template->key : NULL;
	mkref(&iter->pos, attr);
	return kdump_ok;
}

/**  Get an attribute iterator by attribute data.
 * @param      ctx   Dump file object.
 * @param[in]  attr  Attribute directory data.
 * @param[out] iter  Attribute iterator.
 * @returns          Error status.
 *
 * This is the common implementation of @ref kdump_attr_iter_start
 * and @ref kdump_attr_ref_iter_start, which takes an attribute data
 * pointer as argument.
 */
static kdump_status
attr_iter_start(kdump_ctx *ctx, const struct attr_data *attr,
		kdump_attr_iter_t *iter)
{
	if (!attr_isset(attr))
		return set_error(ctx, kdump_nodata, "Key has no value");
	if (attr->template->type != kdump_directory)
		return set_error(ctx, kdump_invalid,
				 "Path is a leaf attribute");

	return set_iter_pos(iter, attr->dir);
}

kdump_status
kdump_attr_iter_start(kdump_ctx *ctx, const char *path,
		      kdump_attr_iter_t *iter)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	d = lookup_attr(ctx->shared, path);
	if (d)
		ret = attr_iter_start(ctx, d, iter);
	else
		ret = set_error(ctx, kdump_nokey, "No such path");

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_attr_ref_iter_start(kdump_ctx *ctx, const kdump_attr_ref_t *ref,
			  kdump_attr_iter_t *iter)
{
	kdump_status ret;
	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);
	ret = attr_iter_start(ctx, ref_attr(ref), iter);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_attr_iter_next(kdump_ctx *ctx, kdump_attr_iter_t *iter)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	d = ref_attr(&iter->pos);
	if (d)
		ret = set_iter_pos(iter, d->next);
	else
		ret = set_error(ctx, kdump_invalid, "End of iteration");

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

void
kdump_attr_iter_end(kdump_ctx *ctx, kdump_attr_iter_t *iter)
{
	clear_error(ctx);
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

	rwlock_wrlock(&shared->lock);

	/* Allocate a slot. */
	for (slot = 0; slot < PER_CTX_SLOTS; ++slot)
		if (!shared->per_ctx_size[slot])
			break;
	if (slot >= PER_CTX_SLOTS) {
		errno = EAGAIN;
		slot = -1;
		goto out;
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
			slot = -1;
			goto out;
		}

 out:
	rwlock_unlock(&shared->lock);
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

	rwlock_wrlock(&shared->lock);
	list_for_each_entry(ctx, &shared->ctx, list)
		free(ctx->data[slot]);
	shared->per_ctx_size[slot] = 0;
	rwlock_unlock(&shared->lock);
}
