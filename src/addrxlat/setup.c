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
	if (ctx)
		ctx->pf = &null_paging;
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

void
addrxlat_set_paging_form(addrxlat_ctx *ctx, const addrxlat_paging_form_t *pf)
{
	ctx->pf = pf;
	ctx->page_mask = ~(((addrxlat_addr_t)1 << ctx->pf->bits[0]) - 1);
}

const addrxlat_paging_form_t *
addrxlat_get_paging_form(addrxlat_ctx *ctx)
{
	return ctx->pf;
}
