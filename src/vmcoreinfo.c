/** @internal @file src/vmcoreinfo.c
 * @brief Handling of VMCOREINFO.
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

#include <string.h>
#include <stdlib.h>

/**  De-allocate parsed VMCOREINFO.
 * @param dir  Base attribute directory.
 */
static void
dealloc_vmcoreinfo(struct attr_data *dir)
{
	struct attr_data *child, *child2;

	if (dir->template->type != kdump_directory)
		return;

	for (child = dir->dir; child; child = child->next) {
		if (child->template->type != kdump_directory)
			continue;

		for (child2 = child->dir; child2; child2 = child2->next)
			dealloc_attr(child2);
		child->dir = NULL;
	}
}

static kdump_status
add_parsed_row(kdump_ctx *ctx, struct attr_data *dir,
	       char *key, char *val)
{
	char *type, *sym, *p;
	unsigned long long num;
	kdump_attr_type_t attr_type;
	struct attr_data *attr;
	kdump_status res;

	attr = lookup_dir_attr(ctx->shared, dir, "lines", 5);
	if (!attr)
		return set_error(ctx, kdump_nokey,
				 "Cannot set VMCOREINFO '%s'", key);
	attr = create_attr_path(ctx->shared, attr, key, kdump_string);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot set VMCOREINFO '%s'", key);
	res = set_attr_string(ctx, attr, 0, val);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot set VMCOREINFO '%s'", key);

	type = key;
	sym = strchr(key, '(');
	if (!sym)
		return kdump_ok;
	*sym++ = '\0';
	p = strchr(sym, ')');
	if (!p || p[1])
		return kdump_ok;
	*p = '\0';

	if (!strcmp(type, "SYMBOL")) {
		num = strtoull(val, &p, 16);
		if (*p)
			/* invalid format -> ignore */
			return kdump_ok;
		attr_type = kdump_address;
	} else if (!strcmp(type, "LENGTH") ||
		   !strcmp(type, "NUMBER") ||
		   !strcmp(type, "OFFSET") ||
		   !strcmp(type, "SIZE")) {
		num = strtoull(val, &p, 10);
		if (*p)
			/* invalid format -> ignore */
			return kdump_ok;
		attr_type = kdump_number;
	} else
		return kdump_ok;

	sym[-1] = '.';
	attr = create_attr_path(ctx->shared, dir, key, attr_type);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot set VMCOREINFO '%s'", key);
	return set_error(ctx,
			 (attr_type == kdump_number)
			 ? set_attr_number(ctx, attr, 0, num)
			 : set_attr_address(ctx, attr, 0, num),
			 "Cannot set VMCOREINFO '%s'", key);
}

#define str_lines_PAGESIZE	"lines.PAGESIZE"
#define len_lines_PAGESIZE	(sizeof(str_lines_PAGESIZE) - 1)
#define str_lines_OSRELEASE	"lines.OSRELEASE"
#define len_lines_OSRELEASE	(sizeof(str_lines_OSRELEASE) - 1)

/**  Process information from Linux VMCOREINFO.
 * @param ctx  Dump file object.
 *
 * This function should be called after Linux VMCOREINFO has changed
 * to update any values that may need updating.
 */
static kdump_status
process_linux_vmcoreinfo(kdump_ctx *ctx, const struct attr_data *dir)
{
	const struct attr_data *attr;
	kdump_status res;

	attr = lookup_dir_attr(ctx->shared, dir,
			       str_lines_PAGESIZE, len_lines_PAGESIZE);
	if (attr && attr_isset(attr)) {
		char *endp;
		unsigned long page_size =
			strtoul(attr_value(attr)->string, &endp, 10);
		if (!*endp &&
		    (res = set_page_size(ctx, page_size)) != kdump_ok)
			return set_error(ctx, res, "Cannot set page size");
	}

	attr = lookup_dir_attr(ctx->shared, dir,
			       str_lines_OSRELEASE, len_lines_OSRELEASE);
	if (attr && attr_isset(attr)) {
		res = set_attr_string(ctx, gattr(ctx, GKI_linux_uts_release),
				      0, attr_value(attr)->string);
		if (res != kdump_ok)
			return set_error(ctx, res,
					 "Cannot set UTS release");
	}

	return kdump_ok;
}

static kdump_status
vmcoreinfo_raw_post_hook(kdump_ctx *ctx, struct attr_data *rawattr)
{
	char *raw, *p, *endp, *val;
	struct attr_data *dir;
	kdump_status res;

	raw = strdup(attr_value(rawattr)->string);
	if (!raw)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate VMCOREINFO copy");

	dir = rawattr->parent;
	dealloc_vmcoreinfo(dir);

	for (p = raw; *p; p = endp) {
		endp = strchrnul(p, '\n');
		if (*endp)
			*endp++ = '\0';

		val = strchr(p, '=');
		if (val)
			*val++ = '\0';

		res = add_parsed_row(ctx, dir, p, val);
		if (res != kdump_ok)
			break;
	}

	free(raw);

	if (dir->parent == gattr(ctx, GKI_dir_linux))
		res = process_linux_vmcoreinfo(ctx, dir);

	return res;
}

const struct attr_ops vmcoreinfo_raw_ops = {
	.post_set = vmcoreinfo_raw_post_hook,
};

static const char*
vmcoreinfo_row(kdump_ctx *ctx, const char *key, const struct attr_data *base)
{
	struct attr_data *attr;
	const char *ret = NULL;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	attr = lookup_dir_attr(ctx->shared, base, key, strlen(key));
	if (attr && validate_attr(ctx, attr) == kdump_ok)
		ret = attr_value(attr)->string;

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

const char *
kdump_vmcoreinfo_row(kdump_ctx *ctx, const char *key)
{
	return vmcoreinfo_row(ctx, key,
			      gattr(ctx, GKI_linux_vmcoreinfo_lines));
}

const char *
kdump_vmcoreinfo_row_xen(kdump_ctx *ctx, const char *key)
{
	return vmcoreinfo_row(ctx, key,
			      gattr(ctx, GKI_xen_vmcoreinfo_lines));
}

static kdump_status
vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname, kdump_addr_t *symvalue,
		  const struct attr_data *base)
{
	struct attr_data *attr;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	attr = lookup_dir_attr(ctx->shared, base, symname, strlen(symname));
	if (!attr) {
		ret = set_error(ctx, kdump_nodata, "Symbol not found");
		goto out;
	}
	if (validate_attr(ctx, attr) != kdump_ok) {
		ret = set_error(ctx, kdump_nodata, "Symbol has no value");
		goto out;
	}

	*symvalue = attr_value(attr)->address;
	ret = kdump_ok;

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname,
			kdump_addr_t *symvalue)
{
	return vmcoreinfo_symbol(ctx, symname, symvalue,
				 gattr(ctx, GKI_linux_symbol));
}

kdump_status
kdump_vmcoreinfo_symbol_xen(kdump_ctx *ctx, const char *symname,
			    kdump_addr_t *symvalue)
{
	return vmcoreinfo_symbol(ctx, symname, symvalue,
				 gattr(ctx, GKI_xen_symbol));
}
