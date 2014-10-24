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
#include <stdlib.h>

#include "kdumpfile-priv.h"

typedef kdump_status (*read_page_fn)(kdump_ctx *, kdump_paddr_t);

static kdump_status
read_kvpage(kdump_ctx *ctx, kdump_paddr_t pfn)
{
	kdump_paddr_t vaddr, paddr;
	kdump_status ret;

	vaddr = pfn * ctx->page_size;
	ret = ctx->arch_ops->vtop(ctx, vaddr, &paddr);
	if (ret != kdump_ok)
		return ret;
	return ctx->ops->read_page(ctx, paddr / ctx->page_size);
}

static kdump_status
read_page(kdump_ctx *ctx, kdump_paddr_t pfn, read_page_fn fn)
{
	if (pfn == ctx->last_pfn)
		return kdump_ok;
	ctx->last_pfn = pfn;
	return fn(ctx, pfn);
}

static kdump_status
setup_readfn(kdump_ctx *ctx, long flags, read_page_fn *fn)
{
	if (!ctx->ops)
		return kdump_unsupported;

	if (flags & KDUMP_PHYSADDR)
		*fn = ctx->ops->read_page;
	else if (flags & KDUMP_XENMACHADDR)
		*fn = ctx->ops->read_xenmach_page;
	else if (flags & KDUMP_KVADDR && ctx->ops->read_page &&
		ctx->arch_ops && ctx->arch_ops->vtop)
		*fn = read_kvpage;
	else
		return kdump_unsupported;

	if (!*fn)
		return kdump_unsupported;

	return kdump_ok;
}

kdump_status
kdump_readp(kdump_ctx *ctx, kdump_paddr_t paddr,
	    unsigned char *buffer, size_t *plength,
	    long flags)
{
	read_page_fn readfn;
	size_t remain;
	kdump_status ret;

	ret = setup_readfn(ctx, flags, &readfn);
	if (ret != kdump_ok)
		return ret;

	remain = *plength;
	while (remain) {
		size_t off, partlen;

		ret = read_page(ctx, paddr / ctx->page_size, readfn);
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

	*plength -= remain;
	return ret;
}

ssize_t
kdump_read(kdump_ctx *ctx, kdump_paddr_t paddr,
	   unsigned char *buffer, size_t length,
	   long flags)
{
	size_t sz;
	kdump_status ret;

	sz = length;
	ret = kdump_readp(ctx, paddr, buffer, &sz, flags);
	if (!sz && ret == kdump_syserr)
		return -1;
	return sz;
}

kdump_status
kdump_read_string(kdump_ctx *ctx, kdump_paddr_t paddr,
		  char **pstr, long flags)
{
	read_page_fn readfn;
	char *str = NULL, *newstr, *endp;
	size_t length = 0, newlength;
	kdump_status ret;

	ret = setup_readfn(ctx, flags, &readfn);
	if (ret != kdump_ok)
		return ret;

	do {
		size_t off, partlen;

		ret = read_page(ctx, paddr / ctx->page_size, readfn);
		if (ret != kdump_ok)
			break;

		off = paddr % ctx->page_size;
		partlen = ctx->page_size - off;
		endp = memchr(ctx->page + off, 0, partlen);
		if (endp)
			partlen = endp - ((char*)ctx->page + off);

		newlength = length + partlen;
		newstr = realloc(str, newlength + 1);
		if (!newstr) {
			if (str)
				free(str);
			return kdump_syserr;
		}
		memcpy(newstr + length, ctx->page + off, partlen);
		length = newlength;
		str = newstr;

		paddr += partlen;
	} while (!endp);

	if (ret == kdump_ok) {
		str[length] = 0;
		*pstr = str;
	}

	return ret;
}
