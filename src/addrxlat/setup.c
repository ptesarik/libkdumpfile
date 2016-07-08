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

struct pte_def {
	addrxlat_vtop_step_fn *fn;
};

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
	static const struct pte_def formats[] = {
		[addrxlat_pte_none] = { vtop_none },
		[addrxlat_pte_ia32] = { vtop_ia32 },
		[addrxlat_pte_ia32_pae] = { vtop_ia32_pae },
		[addrxlat_pte_x86_64] = { vtop_x86_64 },
		[addrxlat_pte_s390x] = { vtop_s390x },
		[addrxlat_pte_ppc64] = { vtop_ppc64 },
	};

	const struct pte_def *fmt;
	addrxlat_addr_t mask;
	unsigned short i;

	fmt = pf->pte_format < ARRAY_SIZE(formats)
		? &formats[pf->pte_format]
		: NULL;
	if (!fmt || !fmt->fn)
		return set_error(ctx, addrxlat_notimplemented,
				 "Unknown PTE format");

	ctx->vtop_step = fmt->fn;
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
