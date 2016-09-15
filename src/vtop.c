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

#define RGN_ALLOC_INC 32

kdump_status
set_vtop_xlat(struct vtop_map *map, kdump_vaddr_t first, kdump_vaddr_t last,
	      addrxlat_def_t *xlat)
{
	const addrxlat_range_t range = {
		.endoff = last - first,
		.def = xlat,
	};
	addrxlat_map_t *newmap;

	newmap = addrxlat_map_set(map->map, first, &range);
	if (!newmap)
		return kdump_syserr;

	map->map = newmap;
	return kdump_ok;
}

kdump_status
set_vtop_xlat_pgt(struct vtop_map *map,
		  kdump_vaddr_t first, kdump_vaddr_t last)
{
	return set_vtop_xlat(map, first, last, map->pgt);
}

void
flush_vtop_map(struct vtop_map *map)
{
	if (map->map) {
		addrxlat_map_clear(map->map);
		free(map->map);
		map->map = NULL;
	}
}

kdump_status
vtop_init(kdump_ctx *ctx, struct vtop_map *map, size_t init_ops_off)
{
	kdump_status (*arch_init)(kdump_ctx *);
	kdump_status ret;

	clear_error(ctx);
	rwlock_wrlock(&ctx->shared->lock);

	if (!ctx->shared->arch_ops) {
		ret = set_error(ctx, kdump_unsupported,
				"Unsupported architecture");
		goto out;
	}

	arch_init = *(kdump_status (*const *)(kdump_ctx*))
		((char*)ctx->shared->arch_ops + init_ops_off);
	if (!arch_init) {
		ret = set_error(ctx, kdump_unsupported,
				"No vtop support for this architecture");
		goto out;
	}

	ret = arch_init(ctx);
	if (ret != kdump_ok)
		goto out;

	ret = kdump_ok;

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_vtop_init(kdump_ctx *ctx)
{
	return vtop_init(ctx, &ctx->shared->vtop_map,
			 offsetof(struct arch_ops, vtop_init));
}

kdump_status
kdump_vtop_init_xen(kdump_ctx *ctx)
{
	return vtop_init(ctx, &ctx->shared->vtop_map,
			 offsetof(struct arch_ops, vtop_init_xen));
}

static inline kdump_status
set_error_no_vtop(kdump_ctx *ctx)
{
	return set_error(ctx, kdump_unsupported,
			 "VTOP translation not available");
}

/**  Virtual-to-physical translation using pagetables.
 * @param ctx         Dump file object.
 * @param[in] vaddr   Virtual address.
 * @param[out] paddr  Physical address.
 * @returns           Error status.
 *
 * Unlike @ref kdump_vtop, this function always uses page tables to
 * do the translation.
 */
kdump_status
vtop_pgt(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	addrxlat_addr_t addr = vaddr;
	addrxlat_status axres;
	kdump_status res;

	axres = addrxlat_walk(ctx->addrxlat, ctx->shared->vtop_map.pgt,
			      &addr);
	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	res = mtop(ctx, addr, paddr);
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot translate machine address"
				 " 0x%"ADDRXLAT_PRIxADDR, addr);

	return kdump_ok;
}

/**  Xen Virtual-to-physical translation using pagetables.
 * @param ctx         Dump file object.
 * @param[in] vaddr   Xen virtual address.
 * @param[out] paddr  Physical address.
 * @returns           Error status.
 *
 * Same as @ref vtop_pgt, but for Xen hypervisor virtual addresses.
 */
kdump_status
vtop_pgt_xen(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	addrxlat_addr_t addr = vaddr;
	addrxlat_status axres;

	axres = addrxlat_walk(ctx->addrxlat, ctx->shared->vtop_map_xen.pgt,
			      &addr);
	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	*paddr = addr;
	return kdump_ok;
}

/**  Perform virtual -> physical address translation using a given mapping.
 * @param      ctx    Dump file object.
 * @param[in]  vaddr  Virtual address.
 * @param[out] paddr  On success, set to translated physical address.
 * @param      map    Translation mapping to be used.
 * @returns           Error status.
 */
kdump_status
map_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr,
	 const struct vtop_map *map)
{
	addrxlat_status status;

	status = addrxlat_by_map(ctx->addrxlat, &vaddr, map->map);
	if (status == addrxlat_ok)
		*paddr = vaddr;
	return set_error_addrxlat(ctx, status);
}

kdump_status
kdump_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	ret = vtop(ctx, vaddr, paddr);

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Internal version of @ref kdump_vtom
 * @param ctx         Dump file object.
 * @param[in] vaddr   Virtual address.
 * @param[out] maddr  Machine address.
 * @returns           Error status.
 *
 * Use this function internally if the shared lock is already held
 * (for reading or writing).
 */
kdump_status
vtom(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_maddr_t *maddr)
{
	addrxlat_addr_t addr;
	addrxlat_status axres;

	if (kphys_is_machphys(ctx))
		return vtop(ctx, vaddr, maddr);

	addr = vaddr;
	axres = addrxlat_walk(ctx->addrxlat, ctx->shared->vtop_map.pgt,
			      &addr);
	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	*maddr = addr;
	return kdump_ok;
}

kdump_status
kdump_vtom(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_maddr_t *maddr)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);
	ret = vtom(ctx, vaddr, maddr);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_vtop_xen(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	if (get_xen_type(ctx) != kdump_xen_system) {
		ret = set_error(ctx, kdump_nodata,
				"Not a Xen system dump");
		goto out;
	}

	ret = vtop_xen(ctx, vaddr, paddr);

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_ptom(kdump_ctx *ctx, kdump_paddr_t paddr, kdump_maddr_t *maddr)
{
	kdump_pfn_t mfn, pfn;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	if (kphys_is_machphys(ctx)) {
		*maddr = paddr;
		ret = kdump_ok;
		goto out;
	}

	if (!ctx->shared->arch_ops || !ctx->shared->arch_ops->pfn_to_mfn) {
		ret = set_error(ctx, kdump_unsupported, "Not implemented");
		goto out;
	}

	pfn = paddr >> get_page_shift(ctx);
	ret = ctx->shared->arch_ops->pfn_to_mfn(ctx, pfn, &mfn);
	if (ret == kdump_ok)
		*maddr = (mfn << get_page_shift(ctx)) |
			(paddr & (get_page_size(ctx) - 1));

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Internal version of @ref kdump_mtop
 * @param      ctx    Dump file object.
 * @param[in]  maddr  Machine address.
 * @param[out] paddr  Physical address.
 * @returns           Error status.
 *
 * Use this function internally if the shared lock is already held
 * (for reading or writing).
 */
kdump_status
mtop(kdump_ctx *ctx, kdump_maddr_t maddr, kdump_paddr_t *paddr)
{
	kdump_pfn_t mfn, pfn;
	kdump_status ret;

	switch (get_xen_type(ctx)) {
	case kdump_xen_system:
		if (!ctx->shared->arch_ops ||
		    !ctx->shared->arch_ops->mfn_to_pfn)
			return set_error(ctx, kdump_unsupported,
					 "Not implemented");
		mfn = maddr >> get_page_shift(ctx);
		ret = ctx->shared->arch_ops->mfn_to_pfn(ctx, mfn, &pfn);
		break;

	case kdump_xen_domain:
		if (get_xen_xlat(ctx) == kdump_xen_nonauto) {
			if (!ctx->shared->ops->mfn_to_pfn)
				return set_error(ctx, kdump_unsupported,
						 "Not implemented");
			mfn = maddr >> get_page_shift(ctx);
			ret = ctx->shared->ops->mfn_to_pfn(ctx, mfn, &pfn);
			break;
		}
		/* else fall-through */

	default:
		*paddr = maddr;
		return kdump_ok;
	}

	if (ret == kdump_ok)
		*paddr = (pfn << get_page_shift(ctx)) |
			(maddr & (get_page_size(ctx) - 1));
	return ret;
}

kdump_status
kdump_mtop(kdump_ctx *ctx, kdump_maddr_t maddr, kdump_paddr_t *paddr)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);
	ret = mtop(ctx, maddr, paddr);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
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

kdump_status
init_vtop_maps(kdump_ctx *ctx)
{
	struct kdump_shared *shared = ctx->shared;

	shared->vtop_map.pgt = addrxlat_def_new();
	if (!shared->vtop_map.pgt)
		return set_error(ctx, kdump_syserr,
				 "Cannot initialize %s page table translation",
				 "Linux");

	shared->vtop_map_xen.pgt = addrxlat_def_new();
	if (!shared->vtop_map_xen.pgt)
		return set_error(ctx, kdump_syserr,
				 "Cannot initialize %s page table translation",
				 "Xen");

	return kdump_ok;
}

addrxlat_ctx *
init_addrxlat(kdump_ctx *ctx)
{
	addrxlat_ctx *addrxlat;

	addrxlat = addrxlat_new();
	if (!addrxlat)
		return addrxlat;

	addrxlat_set_priv(addrxlat, ctx);
	addrxlat_cb_read32(addrxlat, addrxlat_read32);
	addrxlat_cb_read64(addrxlat, addrxlat_read64);

	return addrxlat;
}
