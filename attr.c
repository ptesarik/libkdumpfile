/* Attribute handling.
   Copyright (C) 2015 Petr Tesarik <ptesarik@suse.cz>

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
#include <errno.h>

static const struct attr_template global_keys[] = {
	{ "arch.name", kdump_string },
	{ "arch.ptr_size", kdump_number },
};

#define NR_GLOBAL	ARRAY_SIZE(global_keys)

/**  Look up a template by name.
 * @param key  Key name.
 * @returns    Attribute template, or @c NULL if not found.
 */
static const struct attr_template*
lookup_template(const char *key)
{
	const struct attr_template *t;
	unsigned i;
	for (t = global_keys, i = 0; i < NR_GLOBAL; ++i, ++t)
		if (!strcmp(key, t->key))
			return t;
	return NULL;
}

/**  Lookup attribute value by template.
 * @param ctx   Dump file object.
 * @param tmpl  Attribute template.
 * @returns     Stored attribute or @c NULL if not found.
 */
static struct attr_data*
lookup_data(const kdump_ctx *ctx, const struct attr_template *tmpl)
{
	struct attr_data *d;
	for (d = ctx->attrs; d; d = d->next)
		if (d->template == tmpl)
			return d;
	return NULL;
}

/**  Check if a given attribute is set.
 * @param ctx  Dump file object.
 * @param key  Key name.
 * @returns    Non-zero if the key is known and has a value.
 */
int
attr_isset(const kdump_ctx *ctx, const char *key)
{
	const struct attr_template *t = lookup_template(key);
	return t && !!lookup_data(ctx, t);
}

kdump_status
kdump_get_attr(kdump_ctx *ctx, const char *key,
	       struct kdump_attr *valp)
{
	const struct attr_template *t;
	struct attr_data *d;

	clear_error(ctx);
	t = lookup_template(key);
	if (!t)
		return set_error(ctx, kdump_unsupported, "No such key");

	d = lookup_data(ctx, t);
	if (d) {
		valp->type = t->type;
		valp->val = d->val;
		return kdump_ok;
	}

	return set_error(ctx, kdump_nodata, "Key has no value");
}

/**  Allocate a new attribute.
 * @param tmpl   Attribute template.
 * @param extra  Extra size to be allocated.
 */
static struct attr_data*
alloc_attr(const struct attr_template *tmpl, size_t extra)
{
	struct attr_data *ret;

	ret = malloc(sizeof(struct attr_data) + extra);
	if (!ret)
		return NULL;

	ret->template = tmpl;
	return ret;
}

/**  Allocate new attribute object by key name.
 * @param ctx         Dump file object.
 * @param[out] pattr  To be filled with the allocated attribute.
 * @param key         Key name.
 * @param extra       Extra size to be allocated.
 * @returns           Error status.
 */
static kdump_status
alloc_attr_by_key(kdump_ctx *ctx, struct attr_data **pattr,
		  const char *key, size_t extra)
{
	const struct attr_template *t;
	struct attr_data *attr;

	t = lookup_template(key);
	if (!t)
		return set_error(ctx, kdump_unsupported, "No such key");

	attr = alloc_attr(t, extra);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate attribute: %s",
				 strerror(errno));

	*pattr = attr;
	return kdump_ok;
}

/**  Free all memory associated with an attribute.
 * @param attr  The attribute to be freed (detached).
 */
static void
free_attr(struct attr_data *attr)
{
	free(attr);
}

/**  Add new attribute to a dump file object.
 * @param ctx   Dump file object.
 * @param attr  Complete initialized attribute.
 *
 * This function merely adds the attribute to the dump file object.
 * It does not check for duplicates.
 */
static void
add_attr(kdump_ctx *ctx, struct attr_data *attr)
{
	/* Link the new node */
	attr->next = ctx->attrs;
	if (attr->next)
		attr->next->pprev = &attr->next;
	ctx->attrs = attr;
	attr->pprev = &ctx->attrs;
}

/**  Delete an attribute.
 * @param attr  Attribute to be deleted.
 *
 * Remove an attribute from its dump file object and free it.
 */
static void
delete_attr(struct attr_data *attr)
{
	*attr->pprev = attr->next;
	if (attr->next)
		attr->next->pprev = attr->pprev;
	free_attr(attr);
}

/**  Cleanup all attributes from a dump file object.
 * @param ctx   Dump file object.
 */
void
cleanup_attr(kdump_ctx *ctx)
{
	struct attr_data *attr = ctx->attrs;

	while (attr) {
		struct attr_data *next = attr->next;
		free_attr(attr);
		attr = next;
	}
	ctx->attrs = NULL;
}

/**  Set an attribute of a dump file object.
 * @param ctx   Dump file object.
 * @param attr  Attribute (detached).
 */
static void
set_attr(kdump_ctx *ctx, struct attr_data *attr)
{
	struct attr_data *old = lookup_data(ctx, attr->template);

	if (old)
		delete_attr(old);
	add_attr(ctx, attr);
}

/**  Set a numeric attribute of a dump file object.
 * @param ctx  Dump file object.
 * @param key  Key name.
 * @param num  Key value (numeric).
 * @returns    Error status.
 */
kdump_status
set_attr_number(kdump_ctx *ctx, const char *key, kdump_num_t num)
{
	struct attr_data *attr;
	kdump_status res;

	res = alloc_attr_by_key(ctx, &attr, key, 0);
	if (res != kdump_ok)
		return res;

	attr->val.number = num;
	set_attr(ctx, attr);
	return kdump_ok;
}

/**  Set an address attribute of a dump file object.
 * @param ctx   Dump file object.
 * @param key   Key name.
 * @param addr  Key value (address).
 * @returns     Error status.
 */
kdump_status
set_attr_address(kdump_ctx *ctx, const char *key, kdump_addr_t addr)
{
	struct attr_data *attr;
	kdump_status res;

	res = alloc_attr_by_key(ctx, &attr, key, 0);
	if (res != kdump_ok)
		return res;

	attr->val.address = addr;
	set_attr(ctx, attr);
	return kdump_ok;
}

/**  Set a string attribute of a dump file object.
 * @param ctx  Dump file object.
 * @param key  Key name.
 * @param str  Key value (string).
 * @returns    Error status.
 */
kdump_status
set_attr_string(kdump_ctx *ctx, const char *key, const char *str)
{
	struct attr_data *attr;
	size_t len = strlen(str);
	char *dynstr;
	kdump_status res;

	res = alloc_attr_by_key(ctx, &attr, key, len + 1);
	if (res != kdump_ok)
		return res;

	dynstr = (char*)(attr + 1);
	memcpy(dynstr, str, len + 1);
	attr->val.string = dynstr;
	set_attr(ctx, attr);
	return kdump_ok;
}

/**  Set a static string attribute of a dump file object.
 * @param ctx  Dump file object.
 * @param key  Key name.
 * @param str  Key value (static string).
 * @returns    Error status.
 */
kdump_status
set_attr_static_string(kdump_ctx *ctx, const char *key, const char *str)
{
	struct attr_data *attr;
	kdump_status res;

	res = alloc_attr_by_key(ctx, &attr, key, 0);
	if (res != kdump_ok)
		return res;

	attr->val.string = str;
	set_attr(ctx, attr);
	return kdump_ok;
}
