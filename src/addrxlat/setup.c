/** @internal @file src/addrxlat/setup.c
 * @brief Address translation setup routines.
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

#include <stdlib.h>

#include "addrxlat-priv.h"

static const addrxlat_paging_form_t null_paging;

addrxlat_ctx *
addrxlat_new(void)
{
	addrxlat_ctx *ctx = calloc(1, sizeof(addrxlat_ctx));
	if (ctx) {
		ctx->pf = &null_paging;
		ctx->vtop_step = vtop_none;
	}
	return ctx;
}

void
addrxlat_free(addrxlat_ctx *ctx)
{
	free(ctx);
}

addrxlat_status
addrxlat_set_arch(addrxlat_ctx *ctx, const char *name)
{
	return addrxlat_notimplemented;
}

addrxlat_status
addrxlat_set_paging_form(addrxlat_ctx *ctx, const addrxlat_paging_form_t *pf)
{
	addrxlat_vtop_step_fn *fn;
	addrxlat_addr_t mask;
	unsigned short i;

	switch (pf->pte_format) {
	case addrxlat_pte_none:		fn = vtop_none;	break;
	case addrxlat_pte_ia32:		fn = vtop_ia32; break;
	case addrxlat_pte_ia32_pae:	fn = vtop_ia32_pae; break;
	case addrxlat_pte_x86_64:	fn = vtop_x86_64; break;
	case addrxlat_pte_s390x:	fn = vtop_s390x; break;
	case addrxlat_pte_ppc64:	fn = vtop_ppc64; break;
	default:
		return set_error(ctx, addrxlat_notimplemented,
				 "Unknown PTE format");
	}

	ctx->vtop_step = fn;
	ctx->pf = pf;

	mask = 1;
	for (i = 0; i < pf->levels; ++i) {
		mask <<= pf->bits[i];
		ctx->pgt_mask[i] = ~(mask - 1);
	}

	return addrxlat_ok;
}

const addrxlat_paging_form_t *
addrxlat_get_paging_form(addrxlat_ctx *ctx)
{
	return ctx->pf;
}
