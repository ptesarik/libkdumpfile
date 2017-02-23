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

	meth = addrxlat_sys_get_meth(ctx->shared->xlat_linux,
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

kdump_status
kdump_vtop_init(kdump_ctx *ctx)
{
	addrxlat_osdesc_t osdesc;
	addrxlat_status axres;
	char opts[32];

	clear_error(ctx);

	osdesc.type = addrxlat_os_linux;
	osdesc.ver = get_version_code(ctx);
	osdesc.arch = get_arch_name(ctx);

	opts[0] = '\0';
	if (isset_phys_base(ctx))
		sprintf(opts, "physbase=0x%"ADDRXLAT_PRIxADDR,
			get_phys_base(ctx));
	osdesc.opts = opts;

	axres = addrxlat_sys_init(ctx->shared->xlat_linux,
				  ctx->addrxlat, &osdesc);

	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	if (!attr_isset(gattr(ctx, GKI_pteval_size)))
		set_pteval_size(ctx);
	return kdump_ok;
}

static unsigned long
xen_version_code(kdump_ctx *ctx)
{
	struct attr_data *verdir, *ver;
	unsigned long major, minor;

	verdir = lookup_attr(ctx->shared, "xen.version");
	if (!verdir || validate_attr(ctx, verdir) != kdump_ok)
		return 0UL;

	ver = lookup_dir_attr(ctx->shared, verdir, "major", 5);
	if (!ver || validate_attr(ctx, ver) != kdump_ok)
		return 0UL;
	major = attr_value(ver)->number;

	ver = lookup_dir_attr(ctx->shared, verdir, "minor", 5);
	if (!ver || validate_attr(ctx, ver) != kdump_ok)
		return 0UL;
	minor = attr_value(ver)->number;

	return ADDRXLAT_VER_XEN(major, minor);
}

kdump_status
kdump_vtop_init_xen(kdump_ctx *ctx)
{
	addrxlat_osdesc_t osdesc;
	addrxlat_status axres;

	clear_error(ctx);

	osdesc.type = addrxlat_os_xen;
	rwlock_rdlock(&ctx->shared->lock);
	osdesc.ver = xen_version_code(ctx);
	rwlock_unlock(&ctx->shared->lock);
	osdesc.arch = get_arch_name(ctx);
	osdesc.opts = NULL;
	axres = addrxlat_sys_init(ctx->shared->xlat_xen,
				  ctx->addrxlat, &osdesc);

	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);
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
	return do_xlat(ctx, &ctx->shared->xlat_linux,
		       vaddr, ADDRXLAT_KVADDR,
		       paddr, ADDRXLAT_KPHYSADDR);
}

kdump_status
kdump_vtom(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_maddr_t *maddr)
{
	return do_xlat(ctx, &ctx->shared->xlat_linux,
		       vaddr, ADDRXLAT_KVADDR,
		       maddr, ADDRXLAT_MACHPHYSADDR);
}

kdump_status
kdump_vtop_xen(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	return do_xlat(ctx, &ctx->shared->xlat_xen,
		       vaddr, ADDRXLAT_KVADDR,
		       paddr, ADDRXLAT_MACHPHYSADDR);
}

kdump_status
kdump_ptom(kdump_ctx *ctx, kdump_paddr_t paddr, kdump_maddr_t *maddr)
{
	return do_xlat(ctx, &ctx->shared->xlat_linux,
		       paddr, ADDRXLAT_KPHYSADDR,
		       maddr, ADDRXLAT_MACHPHYSADDR);
}

kdump_status
kdump_mtop(kdump_ctx *ctx, kdump_maddr_t maddr, kdump_paddr_t *paddr)
{
	return do_xlat(ctx, &ctx->shared->xlat_linux,
		       maddr, ADDRXLAT_MACHPHYSADDR,
		       paddr, ADDRXLAT_KPHYSADDR);
}

static addrxlat_status
addrxlat_read32(void *data, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	kdump_ctx *ctx = (kdump_ctx*) data;
	return -read_u32(ctx, addr->as, addr->addr, 0,
			 "page table entry", val);
}

static addrxlat_status
addrxlat_read64(void *data, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	kdump_ctx *ctx = (kdump_ctx*) data;
	return -read_u64(ctx, addr->as, addr->addr, 0,
			 "page table entry", val);
}

static addrxlat_status
addrxlat_sym(void *data, addrxlat_sym_t *sym)
{
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
		base = gattr(ctx, GKI_linux_size);
		break;

	case ADDRXLAT_SYM_OFFSETOF:
		base = gattr(ctx, GKI_linux_offset);
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

kdump_status
init_vtop_maps(kdump_ctx *ctx)
{
	struct kdump_shared *shared = ctx->shared;
	addrxlat_sys_t *xlatsys;

	xlatsys = addrxlat_sys_new();
	if (!xlatsys)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate %s translation system",
				 "Linux");

	if (shared->xlat_linux)
		addrxlat_sys_decref(shared->xlat_linux);
	shared->xlat_linux = xlatsys;

	xlatsys = addrxlat_sys_new();
	if (!xlatsys)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate %s translation system",
				 "Xen");

	if (shared->xlat_xen)
		addrxlat_sys_decref(shared->xlat_xen);
	shared->xlat_xen = xlatsys;

	return kdump_ok;
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
