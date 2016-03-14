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

const char *
kdump_err_str(kdump_ctx *ctx)
{
	return ctx->err_str;
}

kdump_status
kdump_set_attr(kdump_ctx *ctx, const char *key,
	       const struct kdump_attr *valp)
{
	struct attr_data *d;

	clear_error(ctx);

	d = lookup_attr_raw(ctx, key);
	if (!d)
		return set_error(ctx, kdump_nodata, "No such key");

	if (valp->type != d->template->type)
		return set_error(ctx, kdump_invalid, "Type mismatch");

	return set_attr(ctx, d, valp->val);
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
		valp->val = *attr_value(d);
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

	for (d = parent->dir; d; d = d->next) {
		struct kdump_attr attr;

		if (!attr_isset(d))
			continue;

		attr.type = d->template->type;
		attr.val = *attr_value(d);
		if (cb(cb_data, d->template->key, &attr))
			break;
	}
	return kdump_ok;
}

kdump_status
kdump_enum_attr_val(kdump_ctx *ctx, const struct kdump_attr *parent,
		    kdump_enum_attr_fn *cb, void *cb_data)
{
	const struct attr_data *d;

	if (parent->type != kdump_directory)
		return set_error(ctx, kdump_invalid,
				 "Path is a leaf attribute");

	for (d = (struct attr_data*)parent->val.string; d; d = d->next) {
		struct kdump_attr attr;

		if (!attr_isset(d))
			continue;

		attr.type = d->template->type;
		attr.val = *attr_value(d);
		if (cb(cb_data, d->template->key, &attr))
			break;
	}
	return kdump_ok;
}

static kdump_status
set_iter_pos(kdump_attr_iter_t *iter, const struct attr_data *attr)
{
	iter->key = attr ? attr->template->key : NULL;
	iter->_pos = attr;
	return kdump_ok;
}

kdump_status
kdump_attr_iter_start(kdump_ctx *ctx, const char *path,
		      kdump_attr_iter_t *iter)
{
	const struct attr_data *d;

	clear_error(ctx);

	d = lookup_attr_raw(ctx, path);
	if (!d)
		return set_error(ctx, kdump_nokey, "No such path");
	if (!attr_isset(d))
		return set_error(ctx, kdump_nodata, "Key has no value");
	if (d->template->type != kdump_directory)
		return set_error(ctx, kdump_invalid,
				 "Path is a leaf attribute");

	return set_iter_pos(iter, d->dir);
}

kdump_status
kdump_attr_iter_next(kdump_ctx *ctx, kdump_attr_iter_t *iter)
{
	const struct attr_data *d;

	clear_error(ctx);

	if (!iter->_pos)
		return set_error(ctx, kdump_invalid, "End of iteration");

	do {
		d = (const struct attr_data*)iter->_pos;
		d = d->next;
	} while (d && !attr_isset(d));

	return set_iter_pos(iter, d);
}

void
kdump_attr_iter_end(kdump_ctx *ctx, kdump_attr_iter_t *iter)
{
	clear_error(ctx);
}

kdump_status
kdump_attr_iter_data(kdump_ctx *ctx, const kdump_attr_iter_t *iter,
		     struct kdump_attr *valp)
{
	const struct attr_data *d;

	clear_error(ctx);

	if (!iter->key)
		return set_error(ctx, kdump_invalid, "Invalid iterator");

	d = (const struct attr_data*) iter->_pos;
	valp->type = d->template->type;
	valp->val = *attr_value(d);

	return kdump_ok;
}

kdump_byte_order_t
kdump_byte_order(kdump_ctx *ctx)
{
	return get_byte_order(ctx);
}

size_t
kdump_ptr_size(kdump_ctx *ctx)
{
	return get_ptr_size(ctx);
}

const char *
kdump_arch_name(kdump_ctx *ctx)
{
	return get_arch_name(ctx);
}

kdump_xen_type_t
kdump_xen_type(kdump_ctx *ctx)
{
	return get_xen_type(ctx);
}

size_t
kdump_pagesize(kdump_ctx *ctx)
{
	return get_page_size(ctx);
}

unsigned
kdump_pageshift(kdump_ctx *ctx)
{
	return get_page_shift(ctx);
}

kdump_paddr_t
kdump_phys_base(kdump_ctx *ctx)
{
	return get_phys_base(ctx);
}

const char *
kdump_get_string_attr(kdump_ctx *ctx, const char *key)
{
	const struct attr_data *attr = lookup_attr(ctx, key);
	return (attr && attr->template->type == kdump_string)
		? attr_value(attr)->string
		: NULL;
}

const char *
kdump_format(kdump_ctx *ctx)
{
	return kdump_get_string_attr(ctx, GATTR(GKI_format_name));
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
	return get_version_code(ctx);
}

unsigned
kdump_num_cpus(kdump_ctx *ctx)
{
	return get_num_cpus(ctx);
}

kdump_status
kdump_read_reg(kdump_ctx *ctx, unsigned cpu, unsigned index,
	       kdump_reg_t *value)
{
	char *key;
	const char *regname;
	const struct attr_data *attr;

	clear_error(ctx);

	if (!ctx->arch_ops || !ctx->arch_ops->reg_name)
		return set_error(ctx, kdump_nodata, "Registers not available");

	regname = ctx->arch_ops->reg_name(index);
	if (!regname)
		return set_error(ctx, kdump_nodata,
				 "Out-of-bounds register number");

	key = alloca(sizeof("cpu.") + 20 + sizeof(".reg.") + strlen(regname));
	sprintf(key, "cpu.%u.reg.%s", cpu, regname);
	attr = lookup_attr(ctx, key);
	if (!attr)
		return set_error(ctx, kdump_nodata, "Cannot read '%s'", key);

	*value = attr_value(attr)->number;
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

static kdump_status
vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname, kdump_addr_t *symvalue,
		  const char *base)
{
	char attrkey[strlen(base) + sizeof(".vmcoreinfo.SYMBOL.") +
		     strlen(symname)];
	const struct attr_data *attr;

	clear_error(ctx);

	sprintf(attrkey, "%s.vmcoreinfo.SYMBOL.%s", base, symname);
	attr = lookup_attr(ctx, attrkey);
	if (!attr)
		return set_error(ctx, kdump_nodata, "Key has no value");

	*symvalue = attr_value(attr)->address;
	return kdump_ok;
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
