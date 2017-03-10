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

static const struct attr_ops vmcoreinfo_lines_ops;

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
	       const char *key, size_t keylen,
	       const char *val, size_t vallen)
{
	static const struct attr_template lines_tmpl = {
		.type = kdump_string,
		.ops = &vmcoreinfo_lines_ops,
	};

	struct attr_data *attr;
	kdump_status res;

	attr = lookup_dir_attr(ctx->shared, dir, "lines", 5);
	if (!attr)
		return set_error(ctx, kdump_nokey,
				 "Cannot set VMCOREINFO '%.*s'",
				 (int) keylen, key);
	attr = create_attr_path(ctx->shared, attr, key, keylen, &lines_tmpl);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot set VMCOREINFO '%.*s'",
				 (int) keylen, key);
	res = set_attr_sized_string(ctx, attr, ATTR_DEFAULT, val, vallen);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot set VMCOREINFO '%.*s'",
				 (int) keylen, key);

	return kdump_ok;
}

static kdump_status
lines_post_hook(kdump_ctx *ctx, struct attr_data *lineattr)
{
	char *key, *type, *sym, *p;
	size_t keylen;
	unsigned long long num;
	struct attr_template tmpl;
	struct attr_data *dir, *attr;
	kdump_status res;

	keylen = 0;
	attr = lineattr;
	while (attr != gattr(ctx, GKI_linux_vmcoreinfo_lines) &&
	       attr != gattr(ctx, GKI_xen_vmcoreinfo_lines)) {
		keylen += strlen(attr->template->key) + 1;
		attr = attr->parent;
	}

	key = alloca(keylen);
	attr = lineattr;
	p = key + keylen - 1;
	*p = '\0';
	while (p > key) {
		keylen = strlen(attr->template->key);
		p -= keylen;
		memcpy(p, attr->template->key, keylen);
		attr = attr->parent;
		if (p > key)
			*--p = '.';
	}
	dir = attr->parent;

	if (dir == gattr(ctx, GKI_dir_linux_vmcoreinfo)) {
		if (!strcmp(key, "PAGESIZE")) {
			unsigned long page_size;
			page_size = strtoul(attr_value(lineattr)->string,
					    &p, 10);
			if (*p)
				/* invalid format -> ignore */
				return kdump_ok;

			res = set_page_size(ctx, page_size);
			if (res != kdump_ok)
				return set_error(ctx, res,
						 "Cannot set page size");
		} else if (!strcmp(key, "OSRELEASE")) {
			attr = gattr(ctx, GKI_linux_uts_release);
			res = set_attr_string(ctx, attr,
					      ATTR_DEFAULT,
					      attr_value(lineattr)->string);
			if (res != kdump_ok)
				return set_error(ctx, res,
						 "Cannot set UTS release");
		}
	}

	type = key;
	sym = strchr(key, '(');
	if (!sym)
		return kdump_ok;
	*sym++ = '\0';
	p = strchr(sym, ')');
	if (!p || p[1])
		return kdump_ok;
	*p = '\0';

	memset(&tmpl, 0, sizeof tmpl);

	if (!strcmp(type, "SYMBOL")) {
		num = strtoull(attr_value(lineattr)->string, &p, 16);
		if (*p)
			/* invalid format -> ignore */
			return kdump_ok;
		tmpl.type = kdump_address;
	} else if (!strcmp(type, "LENGTH") ||
		   !strcmp(type, "NUMBER") ||
		   !strcmp(type, "OFFSET") ||
		   !strcmp(type, "SIZE")) {
		num = strtoull(attr_value(lineattr)->string, &p, 10);
		if (*p)
			/* invalid format -> ignore */
			return kdump_ok;
		tmpl.type = kdump_number;
	} else
		return kdump_ok;

	sym[-1] = '.';
	attr = create_attr_path(ctx->shared, dir, key, strlen(key), &tmpl);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot set VMCOREINFO '%s'", key);
	return set_error(ctx,
			 (tmpl.type == kdump_number)
			 ? set_attr_number(ctx, attr, ATTR_DEFAULT, num)
			 : set_attr_address(ctx, attr, ATTR_DEFAULT, num),
			 "Cannot set VMCOREINFO '%s'", key);
}

static const struct attr_ops vmcoreinfo_lines_ops = {
	.post_set = lines_post_hook,
};

static kdump_status
vmcoreinfo_raw_post_hook(kdump_ctx *ctx, struct attr_data *rawattr)
{
	const char *p, *endp, *val;
	size_t len;
	struct attr_data *dir;
	kdump_status res;

	dir = rawattr->parent;
	dealloc_vmcoreinfo(dir);

	for (p = attr_value(rawattr)->string; *p; p = endp) {
		endp = strchrnul(p, '\n');
		val = memchr(p, '=', endp - p);
		if (val) {
			len = val - p;
			++val;
		} else {
			val = endp;
			len = val - p;
		}

		res = add_parsed_row(ctx, dir, p, len, val, endp - val);
		if (res != kdump_ok)
			break;

		if (*endp)
			++endp;
	}

	return res;
}

static void
vmcoreinfo_raw_clear_hook(kdump_ctx *ctx, struct attr_data *rawattr)
{
	dealloc_vmcoreinfo(rawattr->parent);
}

const struct attr_ops vmcoreinfo_raw_ops = {
	.post_set = vmcoreinfo_raw_post_hook,
	.pre_clear = vmcoreinfo_raw_clear_hook,
};

const char *
kdump_vmcoreinfo(kdump_ctx *ctx)
{
	static const struct ostype_attr_map raw_map[] = {
		{ addrxlat_os_linux, GKI_linux_vmcoreinfo_raw },
		{ addrxlat_os_xen, GKI_xen_vmcoreinfo_raw },
		{ addrxlat_os_unknown }
	};

	struct attr_data *attr;
	const char *ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	attr = ostype_attr(ctx->shared, raw_map);
	ret = (attr && validate_attr(ctx, attr) == kdump_ok &&
	       attr->template->type == kdump_string)
		? attr_value(attr)->string
		: NULL;

	rwlock_rdlock(&ctx->shared->lock);
	return ret;
}

const char *
kdump_vmcoreinfo_row(kdump_ctx *ctx, const char *key)
{
	static const struct ostype_attr_map lines_map[] = {
		{ addrxlat_os_linux, GKI_linux_vmcoreinfo_lines },
		{ addrxlat_os_xen, GKI_xen_vmcoreinfo_lines },
		{ addrxlat_os_unknown }
	};

	const struct attr_data *base;
	struct attr_data *attr;
	const char *ret = NULL;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	base = ostype_attr(ctx->shared, lines_map);
	if (base) {
		attr = lookup_dir_attr(ctx->shared, base, key, strlen(key));
		if (attr && validate_attr(ctx, attr) == kdump_ok)
			ret = attr_value(attr)->string;
	}

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname,
			kdump_addr_t *symvalue)
{
	static const struct ostype_attr_map symbol_map[] = {
		{ addrxlat_os_linux, GKI_linux_symbol },
		{ addrxlat_os_xen, GKI_xen_symbol },
		{ addrxlat_os_unknown }
	};

	const struct attr_data *base;
	struct attr_data *attr;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	base = ostype_attr(ctx->shared, symbol_map);
	if (!base) {
		ret = set_error(ctx, kdump_unsupported, "Unsupported OS");
		goto out;
	}

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
