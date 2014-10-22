/* Routines for reading dumps.
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

#include <string.h>

#include "kdumpfile-priv.h"

static kdump_status
read_page(kdump_ctx *ctx, kdump_paddr_t pfn)
{
	if (pfn == ctx->last_pfn)
		return kdump_ok;
	ctx->last_pfn = pfn;
	return ctx->ops->read_page(ctx, pfn);
}

ssize_t
kdump_read(kdump_ctx *ctx, kdump_paddr_t paddr,
	   unsigned char *buffer, size_t length)
{
	size_t remain;
	kdump_status ret;

	if (!ctx->ops || !ctx->ops->read_page)
		return kdump_unsupported;

	ret = kdump_ok;
	remain = length;
	while (remain) {
		size_t off, partlen;

		ret = read_page(ctx, paddr / ctx->page_size);
		if (ret != kdump_ok)
			break;

		off = paddr % ctx->page_size;
		partlen = ctx->page_size - off;
		if (partlen > remain)
			partlen = remain;
		memcpy(buffer, ctx->page + off, partlen);
		paddr += partlen;
		buffer += partlen;
		remain -= partlen;
	}

	if (ret == kdump_syserr)
		return -1;

	return length - remain;
}
