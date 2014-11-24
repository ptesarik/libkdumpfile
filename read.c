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

#include "kdumpfile-priv.h"

#include <string.h>
#include <stdlib.h>

typedef kdump_status (*read_page_fn)(kdump_ctx *, kdump_pfn_t);

static kdump_status
read_kvpage(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	kdump_vaddr_t vaddr;
	kdump_paddr_t paddr;
	kdump_status ret;

	vaddr = pfn * ctx->page_size;
	ret = kdump_vtop(ctx, vaddr, &paddr);
	if (ret != kdump_ok)
		return ret;
	return ctx->ops->read_page(ctx, paddr / ctx->page_size);
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
kdump_readp(kdump_ctx *ctx, kdump_addr_t addr,
	    void *buffer, size_t *plength, long flags)
{
	read_page_fn readfn;
	size_t remain;
	kdump_status ret;

	clear_error(ctx);

	ret = setup_readfn(ctx, flags, &readfn);
	if (ret != kdump_ok)
		return ret;

	remain = *plength;
	while (remain) {
		size_t off, partlen;

		ret = readfn(ctx, addr / ctx->page_size);
		if (ret != kdump_ok)
			break;

		off = addr % ctx->page_size;
		partlen = ctx->page_size - off;
		if (partlen > remain)
			partlen = remain;
		memcpy(buffer, ctx->page + off, partlen);
		addr += partlen;
		buffer += partlen;
		remain -= partlen;
	}

	*plength -= remain;
	return ret;
}

ssize_t
kdump_read(kdump_ctx *ctx, kdump_addr_t addr,
	   void *buffer, size_t length, long flags)
{
	size_t sz;
	kdump_status ret;

	sz = length;
	ret = kdump_readp(ctx, addr, buffer, &sz, flags);
	if (!sz && ret == kdump_syserr)
		return -1;
	return sz;
}

kdump_status
kdump_read_string(kdump_ctx *ctx, kdump_addr_t addr,
		  char **pstr, long flags)
{
	read_page_fn readfn;
	char *str = NULL, *newstr, *endp;
	size_t length = 0, newlength;
	kdump_status ret;

	clear_error(ctx);

	ret = setup_readfn(ctx, flags, &readfn);
	if (ret != kdump_ok)
		return ret;

	do {
		size_t off, partlen;

		ret = readfn(ctx, addr / ctx->page_size);
		if (ret != kdump_ok)
			break;

		off = addr % ctx->page_size;
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

		addr += partlen;
	} while (!endp);

	if (ret == kdump_ok) {
		str[length] = 0;
		*pstr = str;
	}

	return ret;
}
