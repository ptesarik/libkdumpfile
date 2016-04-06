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
	res = set_attr_string(ctx, attr, val);
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
			 ? set_attr_number(ctx, attr, num)
			 : set_attr_address(ctx, attr, num),
			 "Cannot set VMCOREINFO '%s'", key);
}

kdump_status
store_vmcoreinfo(kdump_ctx *ctx, struct attr_data *dir, void *data, size_t len)
{
	char *raw, *p, *endp, *val;
	struct attr_data *attr;
	kdump_status res;

	raw = ctx_malloc(len + 1, ctx, "VMCOREINFO");
	if (!raw)
		return kdump_syserr;
	memcpy(raw, data, len);
	raw[len] = '\0';

	attr = lookup_dir_attr(ctx->shared, dir, "raw", 3);
	if (!attr) {
		free(raw);
		return set_error(ctx, kdump_nokey,
				 "Cannot set raw VMCOREINFO");
	}
	res = set_attr_string(ctx, attr, raw);
	if (res != kdump_ok) {
		free(raw);
		return set_error(ctx, res, "Cannot set raw VMCOREINFO");
	}

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
	return res;
}

kdump_status
process_vmcoreinfo(kdump_ctx *ctx, void *desc, size_t descsz)
{
	kdump_status ret;
	const char *val;

	ret = store_vmcoreinfo(ctx, gattr(ctx, GKI_dir_linux_vmcoreinfo),
			       desc, descsz);
	if (ret != kdump_ok)
		return ret;

	val = kdump_vmcoreinfo_row(ctx, "PAGESIZE");
	if (val) {
		char *endp;
		unsigned long page_size = strtoul(val, &endp, 10);
		if (*endp)
			return set_error(ctx, kdump_dataerr,
					 "Invalid PAGESIZE: %s", val);

		ret = set_page_size(ctx, page_size);
		if (ret != kdump_ok)
			return ret;
	}

	val = kdump_vmcoreinfo_row(ctx, "OSRELEASE");
	if (val) {
		ret = set_attr_string(ctx, gattr(ctx, GKI_linux_uts_release),
				      val);
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot set UTS release");
	}

	return kdump_ok;
}

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
