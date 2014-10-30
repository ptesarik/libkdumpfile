/* Virtual-to-physical address translation.
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

#define RGN_ALLOC_INC 32

kdump_status
kdump_set_region(kdump_ctx *ctx, kdump_vaddr_t first, kdump_vaddr_t last,
		 kdump_xlat_t xlat, kdump_vaddr_t phys_off)
{
	struct kdump_vaddr_region *rgn, *prevrgn;
	kdump_vaddr_t rfirst, rlast;
	unsigned left;
	int numinc;

	rgn = ctx->region;
	rfirst = 0;
	for (left = ctx->num_regions; left > 0; --left) {
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
		int idx = (ctx->num_regions - 1) % RGN_ALLOC_INC;
		if (idx + numinc >= RGN_ALLOC_INC) {
			struct kdump_vaddr_region *newrgn;
			unsigned newalloc = ctx->num_regions - idx +
				2 * RGN_ALLOC_INC;
			newrgn = realloc(ctx->region,
					 newalloc * sizeof(*newrgn));
			if (!newrgn)
				return kdump_syserr;

			if (!rgn) {
				rgn = prevrgn = newrgn;
				rgn->max_off = KDUMP_ADDR_MAX;
				rgn->xlat = KDUMP_XLAT_NONE;
				++ctx->num_regions;
				++left;
				--numinc;
			} else {
				rgn = newrgn + (rgn - ctx->region);
				prevrgn = newrgn + (prevrgn - ctx->region);
			}
			ctx->region = newrgn;
		}
		ctx->num_regions += numinc;

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
	prevrgn->phys_off = phys_off;
	prevrgn->xlat = xlat;
	return kdump_ok;
}

void
kdump_flush_regions(kdump_ctx *ctx)
{
	if (ctx->region)
		free(ctx->region);
	ctx->region = NULL;
	ctx->num_regions = 0;
}

kdump_xlat_t
kdump_get_xlat(kdump_ctx *ctx, kdump_vaddr_t vaddr,
	       kdump_paddr_t *phys_off)
{
	struct kdump_vaddr_region *rgn;
	kdump_vaddr_t rfirst;
	unsigned left;

	rgn = ctx->region;
	rfirst = 0;
	for (left = ctx->num_regions; left > 0; --left) {
		if (vaddr <= rfirst + rgn->max_off)
			break;
		rfirst += rgn->max_off + 1;
		++rgn;
	}
	if (!rgn)
		return KDUMP_XLAT_NONE;

	*phys_off = rgn->phys_off;
	return rgn->xlat;
}

kdump_status
kdump_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	kdump_xlat_t xlat;
	kdump_paddr_t phys_off;

	xlat = kdump_get_xlat(ctx, vaddr, &phys_off);
	switch (xlat) {
	case KDUMP_XLAT_NONE:
		return kdump_unsupported;

	case KDUMP_XLAT_INVALID:
		return kdump_nodata;

	case KDUMP_XLAT_VTOP:
		if (!ctx->arch_ops || !ctx->arch_ops->vtop)
			return kdump_unsupported;
		return ctx->arch_ops->vtop(ctx, vaddr, paddr);

		/* fall through */
	case KDUMP_XLAT_DIRECT:
		*paddr = vaddr - phys_off;
		return kdump_ok;

	case KDUMP_XLAT_KTEXT:
		*paddr = vaddr - ctx->phys_base - phys_off;
		return kdump_ok;
	};

	/* unknown translation method */
	return kdump_dataerr;
}
