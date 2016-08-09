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
#include <string.h>

#include "addrxlat-priv.h"

addrxlat_ctx *
addrxlat_new(void)
{
	addrxlat_ctx *ctx = calloc(1, sizeof(addrxlat_ctx));
	if (ctx) {
		ctx->refcnt = 1;
	}
	return ctx;
}

unsigned long
addrxlat_incref(addrxlat_ctx *ctx)
{
	return ++ctx->refcnt;
}

unsigned long
addrxlat_decref(addrxlat_ctx *ctx)
{
	unsigned long refcnt = --ctx->refcnt;
	if (!refcnt) {
		if (ctx->pgt)
			internal_pgt_decref(ctx->pgt);
		free(ctx);
	}
	return refcnt;
}

addrxlat_status
addrxlat_init_os(addrxlat_ctx *ctx, const addrxlat_osdesc_t *osdesc,
		 addrxlat_pgt_t **ppgt, addrxlat_map_t **pmap)
{
	addrxlat_pgt_t *pgt;
	addrxlat_status ret;

	pgt = internal_pgt_new();
	if (!pgt)
		return set_error(ctx, addrxlat_nomem,
				 "Cannot allocate pgt");

	if (!strcmp(osdesc->arch, "x86_64"))
		ret = map_os_x86_64(ctx, osdesc, pgt, pmap);
	else
		ret = set_error(ctx, addrxlat_notimpl,
				"Unsupported architecture");

	if (ret != addrxlat_ok)
		internal_pgt_decref(pgt);
	else
		*ppgt = pgt;

	return ret;
}

void
addrxlat_set_priv(addrxlat_ctx *ctx, void *data)
{
	ctx->priv = data;
}

void *
addrxlat_get_priv(addrxlat_ctx *ctx)
{
	return ctx->priv;
}
