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

kdump_status
kdump_get_attr(kdump_ctx *ctx, const char *key,
	       struct kdump_attr *valp)
{
	const struct attr_data *d;

	clear_error(ctx);

	d = lookup_attr(ctx, key);
	if (d) {
		valp->type = d->template->type;
		valp->val = d->val;
		return kdump_ok;
	}

	return set_error(ctx, kdump_nodata, "Key has no value");
}

kdump_status
kdump_enum_attr(kdump_ctx *ctx, const char *path,
		kdump_enum_attr_fn *cb, void *cb_data)
{
	const struct attr_data *parent, *d;

	clear_error(ctx);

	parent = lookup_attr(ctx, path);
	if (!parent)
		return set_error(ctx, kdump_nodata, "No such path");
	if (parent->template->type != kdump_directory)
		return set_error(ctx, kdump_invalid,
				 "Path is a leaf attribute");

	for (d = (struct attr_data*)parent->val.directory; d; d = d->next) {
		struct kdump_attr attr;

		attr.type = d->template->type;
		attr.val = d->val;
		if (cb(cb_data, d->template->key, &attr))
			break;
	}
	return kdump_ok;
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

kdump_xen_type_t
kdump_xen_type(kdump_ctx *ctx)
{
	return get_attr_xen_type(ctx);
}

int
kdump_is_xen(kdump_ctx *ctx)
{
	return get_attr_xen_type(ctx) != kdump_xen_none;
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

const char *
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
	char *key;
	const char *regname;
	struct kdump_attr attr;
	kdump_status res;

	clear_error(ctx);

	if (!ctx->arch_ops || !ctx->arch_ops->reg_name)
		return set_error(ctx, kdump_nodata, "Registers not available");

	regname = ctx->arch_ops->reg_name(index);
	if (!regname)
		return set_error(ctx, kdump_nodata,
				 "Out-of-bounds register number");

	key = alloca(sizeof("cpu.") + 20 + sizeof(".reg.") + strlen(regname));
	sprintf(key, "cpu.%u.reg.%s", cpu, regname);
	res = kdump_get_attr(ctx, key, &attr);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot read '%s'", key);

	*value = attr.val.number;
	return kdump_ok;
}

const char *
kdump_vmcoreinfo(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_linux_vmcoreinfo_raw));
}

const char *
kdump_vmcoreinfo_xen(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_xen_vmcoreinfo_raw));
}

static const char*
vmcoreinfo_row(kdump_ctx *ctx, const char *key, const char *base)
{
	char attrkey[strlen(base) + sizeof(".vmcoreinfo.lines.")
		     + strlen(key)];

	clear_error(ctx);

	sprintf(attrkey, "%s.vmcoreinfo.lines.%s", base, key);
	return kdump_get_string_attr(ctx, attrkey);
}

const char *
kdump_vmcoreinfo_row(kdump_ctx *ctx, const char *key)
{
	return vmcoreinfo_row(ctx, key, "linux");
}

const char *
kdump_vmcoreinfo_row_xen(kdump_ctx *ctx, const char *key)
{
	return vmcoreinfo_row(ctx, key, "xen");
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
vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname, kdump_addr_t *symvalue,
		  const char *base)
{
	char attrkey[strlen(base) + sizeof(".vmcoreinfo.SYMBOL.") +
		     strlen(symname)];
	struct kdump_attr attr;
	kdump_status ret;

	clear_error(ctx);

	sprintf(attrkey, "%s.vmcoreinfo.SYMBOL.%s", base, symname);
	ret = kdump_get_attr(ctx, attrkey, &attr);
	if (ret == kdump_ok)
		*symvalue = attr.val.address;
	return ret;
}

kdump_status
kdump_vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname,
			kdump_addr_t *symvalue)
{
	return vmcoreinfo_symbol(ctx, symname, symvalue, "linux");
}

kdump_status
kdump_vmcoreinfo_symbol_xen(kdump_ctx *ctx, const char *symname,
			    kdump_addr_t *symvalue)
{
	return vmcoreinfo_symbol(ctx, symname, symvalue, "xen");
}

kdump_get_symbol_val_fn *
kdump_cb_get_symbol_val(kdump_ctx *ctx, kdump_get_symbol_val_fn *cb)
{
	kdump_get_symbol_val_fn *ret = ctx->cb_get_symbol_val;
	ctx->cb_get_symbol_val = cb ?: kdump_vmcoreinfo_symbol;
	return ret;
}
