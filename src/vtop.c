/** @internal @file src/vtop.c
 * @brief Virtual-to-physical address translation.
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

#define RGN_ALLOC_INC 32

static void
set_pteval_size(kdump_ctx *ctx)
{
	addrxlat_meth_t *meth;
	const addrxlat_def_t *def;

	meth = addrxlat_sys_get_meth(ctx->shared->xlat,
				     ADDRXLAT_SYS_METH_PGT);
	if (!meth)
		return;

	def = addrxlat_meth_get_def(meth);
	if (def->kind == ADDRXLAT_PGT) {
		int shift = addrxlat_pteval_shift(
			def->param.pgt.pf.pte_format);
		if (shift >= 0) {
			struct attr_data *attr = gattr(ctx, GKI_pteval_size);
			set_attr_number(ctx, attr, ATTR_DEFAULT, 1UL << shift);
		}
	}
	addrxlat_meth_decref(meth);
}

static unsigned long
get_version_code(kdump_ctx *ctx)
{
	static const char attrname[] = "version_code";
	struct attr_data *attr;
	const char *ostype;
	kdump_status status;

	/* Get OS type name */
	attr = gattr(ctx, GKI_ostype);
	status = validate_attr(ctx, attr);
	if (status == kdump_nodata)
		return 0UL;
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot get OS type");
	ostype = attr_value(attr)->string;

	/* Get OS directory attribute */
	attr = lookup_attr(ctx->shared, ostype);
	if (!attr || attr->template->type != kdump_directory)
		return set_error(ctx, kdump_unsupported,
				 "Unknown operating system type: %s", ostype);
	status = validate_attr(ctx, attr);
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot get %s.%s",
				 ostype, attrname);

	/* Get version_code in the OS directory. */
	attr = lookup_dir_attr(
		ctx->shared, attr, attrname, sizeof(attrname) - 1);
	if (!attr)
		return 0UL;
	status = validate_attr(ctx, attr);
	if (status == kdump_nodata)
		return 0UL;
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot get %s.%s",
				 ostype, attrname);

	if (attr->template->type != kdump_number)
		status = set_error(ctx, kdump_invalid,
				   "Attribute %s.%s is not a number",
				   ostype, attrname);

	return attr_value(attr)->number;
}

static void
set_linux_opts(kdump_ctx *ctx, char *opts)
{
	struct attr_data *attr;

	if (isset_phys_base(ctx))
		sprintf(opts, "physbase=0x%"ADDRXLAT_PRIxADDR,
			get_phys_base(ctx));

	if ((isset_xen_xlat(ctx) && get_xen_xlat(ctx) != kdump_xen_auto) ||
	    (isset_xen_type(ctx) && get_xen_type(ctx) == kdump_xen_system))
		strcat(opts, " xen_xlat=1");

	attr = gattr(ctx, GKI_xen_p2m_mfn);
	if (validate_attr(ctx, attr) == kdump_ok)
		sprintf(opts + strlen(opts),
			" xen_p2m_mfn=0x%"ADDRXLAT_PRIxADDR,
			attr_value(attr)->number);
}

static void
set_xen_opts(kdump_ctx *ctx, char *opts)
{
	struct attr_data *attr;

	attr = gattr(ctx, GKI_xen_phys_start);
	if (validate_attr(ctx, attr) == kdump_ok)
		sprintf(opts, "physbase=0x%"ADDRXLAT_PRIxADDR,
			attr_value(attr)->address);
}

kdump_status
kdump_vtop_init(kdump_ctx *ctx)
{
	addrxlat_osdesc_t osdesc;
	addrxlat_status axres;
	char opts[80];

	clear_error(ctx);

	if (!isset_arch_name(ctx))
		return set_error(ctx, kdump_nodata, "Unknown architecture");

	osdesc.type = ctx->shared->ostype;
	osdesc.ver = get_version_code(ctx);
	osdesc.arch = get_arch_name(ctx);

	opts[0] = '\0';
	if (ctx->shared->ostype == addrxlat_os_linux)
		set_linux_opts(ctx, opts);
	else if (ctx->shared->ostype == addrxlat_os_xen)
		set_xen_opts(ctx, opts);
	osdesc.opts = opts;

	axres = addrxlat_sys_init(ctx->shared->xlat,
				  ctx->addrxlat, &osdesc);

	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	if (!attr_isset(gattr(ctx, GKI_pteval_size)))
		set_pteval_size(ctx);
	return kdump_ok;
}

static kdump_status
locked_xlat(kdump_ctx *ctx, addrxlat_sys_t **psys,
	    addrxlat_addr_t src, addrxlat_addrspace_t as,
	    addrxlat_addr_t *dst, addrxlat_addrspace_t goal)
{
	addrxlat_fulladdr_t faddr;
	addrxlat_status axres;

	if (!*psys)
		return set_error(ctx, kdump_invalid,
				 "VTOP translation not initialized");

	faddr.addr = src;
	faddr.as = as;
	axres = addrxlat_by_sys(ctx->addrxlat, &faddr, goal, *psys);
	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	*dst = faddr.addr;
	return kdump_ok;
}

static kdump_status
do_xlat(kdump_ctx *ctx, addrxlat_sys_t **psys,
	addrxlat_addr_t src, addrxlat_addrspace_t as,
	addrxlat_addr_t *dst, addrxlat_addrspace_t goal)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);
	ret = locked_xlat(ctx, psys, src, as, dst, goal);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	return do_xlat(ctx, &ctx->shared->xlat,
		       vaddr, ADDRXLAT_KVADDR,
		       paddr, ADDRXLAT_KPHYSADDR);
}

kdump_status
kdump_vtom(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_maddr_t *maddr)
{
	return do_xlat(ctx, &ctx->shared->xlat,
		       vaddr, ADDRXLAT_KVADDR,
		       maddr, ADDRXLAT_MACHPHYSADDR);
}

kdump_status
kdump_ptom(kdump_ctx *ctx, kdump_paddr_t paddr, kdump_maddr_t *maddr)
{
	return do_xlat(ctx, &ctx->shared->xlat,
		       paddr, ADDRXLAT_KPHYSADDR,
		       maddr, ADDRXLAT_MACHPHYSADDR);
}

kdump_status
kdump_mtop(kdump_ctx *ctx, kdump_maddr_t maddr, kdump_paddr_t *paddr)
{
	return do_xlat(ctx, &ctx->shared->xlat,
		       maddr, ADDRXLAT_MACHPHYSADDR,
		       paddr, ADDRXLAT_KPHYSADDR);
}

/** Translate kdump status to addrxlat status.
 * @param ctx     Dump file object.
 * @param status  libkdumpfile status.
 */
static addrxlat_status
kdump2addrxlat(kdump_ctx *ctx, kdump_status status)
{
	addrxlat_status ret;

	if (status == kdump_ok)
		return addrxlat_ok;

	if (status == kdump_nodata)
		ret = addrxlat_nodata;
	else
		ret = -status;

	addrxlat_ctx_err(ctx->addrxlat, ret, "%s", ctx->err_str);
	clear_error(ctx);
	return ret;
}

static addrxlat_status
addrxlat_read32(void *data, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	kdump_ctx *ctx = (kdump_ctx*) data;
	kdump_status status;

	status = read_u32(ctx, addr->as, addr->addr, 0, NULL, val);
	return kdump2addrxlat(ctx, status);
}

static addrxlat_status
addrxlat_read64(void *data, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	kdump_ctx *ctx = (kdump_ctx*) data;
	kdump_status status;

	status = read_u64(ctx, addr->as, addr->addr, 0, NULL, val);
	return kdump2addrxlat(ctx, status);
}

static addrxlat_status
addrxlat_sym(void *data, addrxlat_sym_t *sym)
{
	static const struct ostype_attr_map sizeof_map[] = {
		{ addrxlat_os_linux, GKI_linux_size },
		{ addrxlat_os_xen, GKI_xen_size },
		{ addrxlat_os_unknown }
	};
	static const struct ostype_attr_map offsetof_map[] = {
		{ addrxlat_os_linux, GKI_linux_offset },
		{ addrxlat_os_xen, GKI_xen_offset },
		{ addrxlat_os_unknown }
	};

	kdump_ctx *ctx = (kdump_ctx*) data;
	const struct attr_data *base;
	struct attr_data *attr;
	kdump_status status;
	addrxlat_status ret;

	switch (sym->type) {
	case ADDRXLAT_SYM_VALUE:
		status = get_symbol_val(ctx, sym->args[0], &sym->val);
		return status == kdump_nodata
			? addrxlat_nodata
			: (addrxlat_status) -(int)status;

	case ADDRXLAT_SYM_SIZEOF:
		base = ostype_attr(ctx->shared, sizeof_map);
		if (!base)
			return addrxlat_ctx_err(
				ctx->addrxlat, addrxlat_notimpl,
				"Unsupported OS");
		break;

	case ADDRXLAT_SYM_OFFSETOF:
		base = ostype_attr(ctx->shared, offsetof_map);
		if (!base)
			return addrxlat_ctx_err(
				ctx->addrxlat, addrxlat_notimpl,
				"Unsupported OS");
		break;

	case ADDRXLAT_SYM_REG:
		rwlock_rdlock(&ctx->shared->lock);
		base = lookup_attr(ctx->shared, "cpu.0.reg");
		rwlock_unlock(&ctx->shared->lock);
		if (!base)
			return addrxlat_ctx_err(ctx->addrxlat, addrxlat_nodata,
						"No registers");
		break;

	default:
		return addrxlat_ctx_err(ctx->addrxlat, addrxlat_notimpl,
					"Unhandled symbolic type");
	}

	rwlock_rdlock(&ctx->shared->lock);

	attr = lookup_dir_attr(ctx->shared, base,
			       sym->args[0], strlen(sym->args[0]));
	if (!attr) {
		ret = addrxlat_ctx_err(ctx->addrxlat, addrxlat_nodata,
				       "Symbol not found");
		goto out;
	}
	if (validate_attr(ctx, attr) != kdump_ok) {
		ret = addrxlat_ctx_err(ctx->addrxlat, addrxlat_nodata,
				       "Symbol has no value");
		goto out;
	}

	if (sym->type == ADDRXLAT_SYM_OFFSETOF) {
		attr = lookup_dir_attr(ctx->shared, base,
				       sym->args[0], strlen(sym->args[1]));
		if (!attr) {
			ret = addrxlat_ctx_err(ctx->addrxlat, addrxlat_nodata,
					       "Field not found");
			goto out;
		}
		if (validate_attr(ctx, attr) != kdump_ok) {
			ret = addrxlat_ctx_err(ctx->addrxlat, addrxlat_nodata,
					       "Field has no value");
			goto out;
		}
	}

	ret = addrxlat_ok;
	switch (attr->template->type) {
	case kdump_number:
		sym->val = attr_value(attr)->number;
		break;

	case kdump_address:
		sym->val = attr_value(attr)->address;
		break;

	default:
		ret = addrxlat_ctx_err(ctx->addrxlat, addrxlat_notimpl,
				       "Unhandled attribute type");
	}

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

addrxlat_ctx_t *
init_addrxlat(kdump_ctx *ctx)
{
	addrxlat_ctx_t *addrxlat;
	addrxlat_cb_t cb = {
		.data = ctx,
		.read32 = addrxlat_read32,
		.read64 = addrxlat_read64,
		.read_caps = (ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR) |
			      ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR) |
			      ADDRXLAT_CAPS(ADDRXLAT_KVADDR)),
		.sym = addrxlat_sym
	};

	addrxlat = addrxlat_ctx_new();
	if (!addrxlat)
		return addrxlat;

	addrxlat_ctx_set_cb(addrxlat, &cb);

	return addrxlat;
}
