/* Functions that provide access to kdump_ctx contents.
   Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

const char *
kdump_err_str(kdump_ctx *ctx)
{
	return ctx->err_str;
}

const char *
kdump_format(kdump_ctx *ctx)
{
	return ctx->format;
}

kdump_byte_order_t
kdump_byte_order(kdump_ctx *ctx)
{
	return get_attr_byte_order(ctx);
}

size_t
kdump_ptr_size(kdump_ctx *ctx)
{
	return get_attr_ptr_size(ctx);
}

const char *
kdump_arch_name(kdump_ctx *ctx)
{
	return get_attr_arch_name(ctx);
}

int
kdump_is_xen(kdump_ctx *ctx)
{
	return !!(ctx->flags & DIF_XEN);
}

size_t
kdump_pagesize(kdump_ctx *ctx)
{
	return get_attr_page_size(ctx);
}

unsigned
kdump_pageshift(kdump_ctx *ctx)
{
	return get_attr_page_shift(ctx);
}

kdump_paddr_t
kdump_phys_base(kdump_ctx *ctx)
{
	return get_attr_phys_base(ctx);
}

/** Get a string attribute.
 *
 * @param ctx  Dump file object.
 * @param key  Attribut key.
 * @returns    The attribute value, @c NULL if not found or if the
 *             attribute is not a string.
 */
static const char *
kdump_get_string_attr(kdump_ctx *ctx, const char *key)
{
	struct kdump_attr attr;

	return (kdump_get_attr(ctx, key, &attr) == kdump_ok &&
		attr.type == kdump_string)
		? attr.val.string
		: NULL;
}

const char *
kdump_sysname(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_linux_uts_sysname));
}

const char *
kdump_nodename(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_linux_uts_nodename));
}

const char *
kdump_release(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_linux_uts_release));
}

const char *
kdump_version(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_linux_uts_version));
}

const char *
kdump_machine(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_linux_uts_machine));
}

const char *
kdump_domainname(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_linux_uts_domainname));
}

unsigned
kdump_version_code(kdump_ctx *ctx)
{
	return get_attr_version_code(ctx);
}

unsigned
kdump_num_cpus(kdump_ctx *ctx)
{
	return get_attr_num_cpus(ctx);
}

kdump_status
kdump_read_reg(kdump_ctx *ctx, unsigned cpu, unsigned index,
	       kdump_reg_t *value)
{
	clear_error(ctx);

	if (!ctx->arch_ops || !ctx->arch_ops->read_reg)
		return set_error(ctx, kdump_nodata, "Registers not available");

	return ctx->arch_ops->read_reg(ctx, cpu, index, value);
}

const char *
kdump_vmcoreinfo(kdump_ctx *ctx)
{
	return ctx->vmcoreinfo ? ctx->vmcoreinfo->raw : NULL;
}

const char *
kdump_vmcoreinfo_xen(kdump_ctx *ctx)
{
	return ctx->vmcoreinfo_xen ? ctx->vmcoreinfo_xen->raw : NULL;
}

static const char*
vmcoreinfo_row(struct vmcoreinfo *info, const char *key)
{
	unsigned i;
	if (!info)
		return NULL;
	for (i = 0; i < info->n; ++i)
		if (!strcmp(key, info->row[i].template.key))
			return info->row[i].val;
	return NULL;
}

const char *
kdump_vmcoreinfo_row(kdump_ctx *ctx, const char *key)
{
	return vmcoreinfo_row(ctx->vmcoreinfo, key);
}

const char *
kdump_vmcoreinfo_row_xen(kdump_ctx *ctx, const char *key)
{
	return vmcoreinfo_row(ctx->vmcoreinfo_xen, key);
}

void
kdump_xen_version(kdump_ctx *ctx, kdump_xen_version_t *version)
{
	struct kdump_attr attr;
	kdump_status res;

	res = kdump_get_attr(ctx, GATTR(GKI_xen_ver_major), &attr);
	version->major = res == kdump_ok ? attr.val.number : 0;

	res = kdump_get_attr(ctx, GATTR(GKI_xen_ver_minor), &attr);
	version->minor = res == kdump_ok ? attr.val.number : 0;

	version->extra = kdump_get_string_attr(ctx, GATTR(GKI_xen_ver_extra));
}

static kdump_status
vmcoreinfo_symbol(kdump_ctx *ctx, struct vmcoreinfo *info,
		  const char *symname, kdump_addr_t *symvalue)
{
	char key[sizeof("SYMBOL()") + strlen(symname)];
	const char *valstr;
	unsigned long long val;
	char *p;

	sprintf(key, "SYMBOL(%s)", symname);
	valstr = vmcoreinfo_row(info, key);
	if (!valstr || !*valstr)
		return set_error(ctx, kdump_nodata, "Symbol not found");

	val = strtoull(valstr, &p, 16);
	if (*p)
		return set_error(ctx, kdump_dataerr,
				 "Invalid number: %s", valstr);

	*symvalue = val;
	return kdump_ok;
}

kdump_status
kdump_vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname,
			kdump_addr_t *symvalue)
{
	clear_error(ctx);

	return vmcoreinfo_symbol(ctx, ctx->vmcoreinfo, symname, symvalue);
}

kdump_status
kdump_vmcoreinfo_symbol_xen(kdump_ctx *ctx, const char *symname,
			    kdump_addr_t *symvalue)
{
	clear_error(ctx);

	return vmcoreinfo_symbol(ctx, ctx->vmcoreinfo_xen, symname, symvalue);
}

kdump_get_symbol_val_fn *
kdump_cb_get_symbol_val(kdump_ctx *ctx, kdump_get_symbol_val_fn *cb)
{
	kdump_get_symbol_val_fn *ret = ctx->cb_get_symbol_val;
	ctx->cb_get_symbol_val = cb ?: kdump_vmcoreinfo_symbol;
	return ret;
}
