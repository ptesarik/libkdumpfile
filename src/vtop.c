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
	      kdump_xlat_method_t method, kdump_vaddr_t phys_off)
{
	struct kdump_vaddr_region *rgn, *prevrgn;
	kdump_vaddr_t rfirst, rlast;
	unsigned left;
	int numinc;

	rgn = map->region;
	rfirst = 0;
	for (left = map->num_regions; left > 0; --left) {
		if (first <= rfirst + rgn->max_off)
			break;
		rfirst += rgn->max_off + 1;
		++rgn;
	}
	rlast = rfirst - 1;

	prevrgn = rgn;
	numinc = 3;
	if (first == rfirst)
		--numinc;
	if (rgn) {
		for ( ; left > 0; --left) {
			--numinc;
			rlast += rgn->max_off + 1;
			if (rlast > last)
				break;
			++rgn;
		}
	} else if (last == rlast)
		--numinc;

	if (numinc) {
		int idx = (map->num_regions - 1) % RGN_ALLOC_INC;
		if (idx + numinc >= RGN_ALLOC_INC) {
			struct kdump_vaddr_region *newrgn;
			unsigned newalloc = map->num_regions - idx +
				2 * RGN_ALLOC_INC;
			newrgn = realloc(map->region,
					 newalloc * sizeof(*newrgn));
			if (!newrgn)
				return kdump_syserr;

			if (!rgn) {
				rgn = prevrgn = newrgn;
				rgn->max_off = KDUMP_ADDR_MAX;
				rgn->xlat.method = KDUMP_XLAT_NONE;
				++map->num_regions;
				++left;
				--numinc;
			} else {
				rgn = newrgn + (rgn - map->region);
				prevrgn = newrgn + (prevrgn - map->region);
			}
			map->region = newrgn;
		}
		map->num_regions += numinc;

		memmove(rgn + numinc, rgn,
			left * sizeof(struct kdump_vaddr_region));
	}

	if (last != rlast)
		rgn[numinc].max_off = rlast - last - 1;
	if (first != rfirst) {
		prevrgn->max_off = first - rfirst - 1;
		++prevrgn;
	}

	prevrgn->max_off = last - first;
	prevrgn->xlat.phys_off = phys_off;
	prevrgn->xlat.method = method;
	return kdump_ok;
}

void
flush_vtop_map(struct vtop_map *map)
{
	if (map->region)
		free(map->region);
	map->region = NULL;
	map->num_regions = 0;
}

const struct kdump_xlat *
get_vtop_xlat(const struct vtop_map *map, kdump_vaddr_t vaddr)
{
	static const struct kdump_xlat xlat_none = {
		.method = KDUMP_XLAT_NONE,
	};

	struct kdump_vaddr_region *rgn;
	kdump_vaddr_t rfirst;

	rgn = map->region;
	if (!rgn)
		return &xlat_none;
	rfirst = 0;
	while (vaddr > rfirst + rgn->max_off) {
		rfirst += rgn->max_off + 1;
		++rgn;
	}
	return &rgn->xlat;
}

/**  Set default translation to VTOP (page table) translation
 */
static void
default_to_vtop(struct vtop_map *map)
{
	struct kdump_vaddr_region *rgn;
	for (rgn = map->region; rgn < &map->region[map->num_regions]; ++rgn)
		if (rgn->xlat.method == KDUMP_XLAT_NONE)
			rgn->xlat.method = KDUMP_XLAT_VTOP;
}

static kdump_status
vtop_init(kdump_ctx *ctx, struct vtop_map *map, size_t init_ops_off)
{
	kdump_status res;
	kdump_status (*arch_init)(kdump_ctx *);

	clear_error(ctx);

	if (!ctx->shared->arch_ops)
		return set_error(ctx, kdump_unsupported,
				 "Unsupported architecture");

	arch_init = *(kdump_status (*const *)(kdump_ctx*))
		((char*)ctx->shared->arch_ops + init_ops_off);
	if (!arch_init)
		return set_error(ctx, kdump_unsupported,
				 "No vtop support for this architecture");

	res = arch_init(ctx);
	if (res != kdump_ok)
		return res;

	default_to_vtop(map);
	return kdump_ok;
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
	return vtop_init(ctx, &ctx->shared->vtop_map_xen,
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
	kdump_addr_t maddr;
	kdump_status res;

	if (!ctx->shared->arch_ops || !ctx->shared->arch_ops->vtop)
		return set_error_no_vtop(ctx);

	if (kphys_is_machphys(ctx))
		return ctx->shared->arch_ops->vtop(ctx, vaddr, paddr);

	res = ctx->shared->arch_ops->vtop(ctx, vaddr, &maddr);
	if (res != kdump_ok)
		return res;

	return set_error(ctx, kdump_mtop(ctx, maddr, paddr),
			 "Cannot translate machine address 0x%llx",
			 (unsigned long long) maddr);
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
	if (ctx->shared->arch_ops && ctx->shared->arch_ops->vtop_xen)
		return ctx->shared->arch_ops->vtop_xen(ctx, vaddr, paddr);
	else
		return set_error_no_vtop(ctx);
}

static kdump_status
map_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr,
	 const struct vtop_map *map)
{
	const struct kdump_xlat *xlat;
	struct attr_data *attr;

	xlat = get_vtop_xlat(map, vaddr);
	switch (xlat->method) {
	case KDUMP_XLAT_NONE:
		return set_error(ctx, kdump_nodata,
				 "Unhandled virtual address");

	case KDUMP_XLAT_INVALID:
		return set_error(ctx, kdump_invalid,
				 "Invalid virtual address");

	case KDUMP_XLAT_VTOP:
		return map->vtop_pgt_fn(ctx, vaddr, paddr);

	case KDUMP_XLAT_DIRECT:
		*paddr = vaddr - xlat->phys_off;
		return kdump_ok;

	case KDUMP_XLAT_KTEXT:
		attr = gattr(ctx, map->phys_base);
		if (validate_attr(ctx, attr) != kdump_ok)
			return set_error(ctx, kdump_nodata,
					 "Unknown kernel physical base");
		*paddr = vaddr - xlat->phys_off + attr_value(attr)->address;
		return kdump_ok;
	};

	/* unknown translation method */
	return set_error(ctx, kdump_dataerr,
			 "Invalid translation method: %d", (int)xlat->method);
}

kdump_status
kdump_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	clear_error(ctx);

	return map_vtop(ctx, vaddr, paddr, &ctx->shared->vtop_map);
}

kdump_status
kdump_vtom(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_maddr_t *maddr)
{
	clear_error(ctx);

	if (kphys_is_machphys(ctx))
		return map_vtop(ctx, vaddr, maddr, &ctx->shared->vtop_map);

	if (!ctx->shared->arch_ops || !ctx->shared->arch_ops->vtop)
		return set_error_no_vtop(ctx);

	return ctx->shared->arch_ops->vtop(ctx, vaddr, maddr);
}

kdump_status
kdump_vtop_xen(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	clear_error(ctx);

	if (get_xen_type(ctx) != kdump_xen_system)
		return set_error(ctx, kdump_nodata,
				 "Not a Xen system dump");

	return map_vtop(ctx, vaddr, paddr, &ctx->shared->vtop_map_xen);
}

kdump_status
kdump_ptom(kdump_ctx *ctx, kdump_paddr_t paddr, kdump_maddr_t *maddr)
{
	kdump_pfn_t mfn, pfn;
	kdump_status ret;

	if (kphys_is_machphys(ctx)) {
		*maddr = paddr;
		return kdump_ok;
	}

	if (!ctx->shared->arch_ops || !ctx->shared->arch_ops->pfn_to_mfn)
		return set_error(ctx, kdump_unsupported,
				 "Not implemented");

	pfn = paddr >> get_page_shift(ctx);
	ret = ctx->shared->arch_ops->pfn_to_mfn(ctx, pfn, &mfn);
	if (ret == kdump_ok)
		*maddr = (mfn << get_page_shift(ctx)) |
			(paddr & (get_page_size(ctx) - 1));

	return ret;
}

kdump_status
kdump_mtop(kdump_ctx *ctx, kdump_maddr_t maddr, kdump_paddr_t *paddr)
{
	kdump_pfn_t mfn, pfn;
	kdump_status ret;

	switch (get_xen_type(ctx)) {
	case kdump_xen_system:
		if (!ctx->shared->arch_ops || !ctx->shared->arch_ops->mfn_to_pfn)
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

void
init_vtop_maps(kdump_ctx *ctx)
{
	ctx->shared->vtop_map.phys_base = GKI_phys_base;
	ctx->shared->vtop_map.vtop_pgt_fn = vtop_pgt;

	ctx->shared->vtop_map_xen.phys_base = GKI_xen_phys_start;
	ctx->shared->vtop_map_xen.vtop_pgt_fn = vtop_pgt_xen;
}
