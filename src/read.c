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
#include <errno.h>

typedef kdump_status (*read_page_fn)(kdump_ctx *, kdump_pfn_t);

static kdump_status
read_dom0_page(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	size_t ptr_size;
	unsigned fpp;
	uint64_t mfn_idx, frame_idx;
	kdump_status ret;

	ptr_size = get_attr_ptr_size(ctx);
	fpp = get_attr_page_size(ctx) / ptr_size;
	mfn_idx = pfn / fpp;
	frame_idx = pfn % fpp;
	if (mfn_idx >= ctx->xen_map_size)
		return set_error(ctx, kdump_nodata, "Out-of-bounds PFN");

	pfn = (ptr_size == 8)
		? ((uint64_t*)ctx->xen_map)[mfn_idx]
		: ((uint32_t*)ctx->xen_map)[mfn_idx];
	ret = ctx->ops->read_page(ctx, pfn);
	if (ret != kdump_ok)
		return set_error(ctx, ret, "Cannot read MFN %llx",
				 (unsigned long long) pfn);

	pfn = (ptr_size == 8)
		? ((uint64_t*)ctx->page)[frame_idx]
		: ((uint32_t*)ctx->page)[frame_idx];
	ret = ctx->ops->read_page(ctx, pfn);
	return set_error(ctx, ret, "Cannot read MFN %llx",
			 (unsigned long long) pfn);
}

static inline read_page_fn
read_phys_page_fn(kdump_ctx *ctx)
{
	return ctx->flags & DIF_XEN ? read_dom0_page : ctx->ops->read_page;
}

static inline read_page_fn
read_xenmach_page_fn(kdump_ctx *ctx)
{
	return ctx->flags & DIF_XEN ? ctx->ops->read_page : NULL;
}

static kdump_status
read_kvpage(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	kdump_vaddr_t vaddr;
	kdump_paddr_t paddr;
	read_page_fn read_page;
	kdump_status ret;

	vaddr = pfn << get_attr_page_shift(ctx);
	ret = kdump_vtop(ctx, vaddr, &paddr);
	if (ret != kdump_ok)
		return ret;

	read_page = read_phys_page_fn(ctx);
	return read_page(ctx, paddr >> get_attr_page_shift(ctx));
}

static kdump_status
setup_readfn(kdump_ctx *ctx, long flags, read_page_fn *fn)
{
	if (!ctx->ops)
		return set_error(ctx, kdump_unsupported,
				 "File format not initialized");

	if (flags & KDUMP_PHYSADDR)
		*fn = read_phys_page_fn(ctx);
	else if (flags & KDUMP_XENMACHADDR)
		*fn = read_xenmach_page_fn(ctx);
	else if (flags & KDUMP_KVADDR && ctx->ops->read_page &&
		ctx->arch_ops && ctx->arch_ops->vtop)
		*fn = read_kvpage;
	else
		return set_error(ctx, kdump_unsupported,
				 "Invalid address type flags");

	if (!*fn)
		return set_error(ctx, kdump_unsupported,
				 "Read function not available");

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

		ret = readfn(ctx, addr / get_attr_page_size(ctx));
		if (ret != kdump_ok)
			break;

		off = addr % get_attr_page_size(ctx);
		partlen = get_attr_page_size(ctx) - off;
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

		ret = readfn(ctx, addr / get_attr_page_size(ctx));
		if (ret != kdump_ok)
			break;

		off = addr % get_attr_page_size(ctx);
		partlen = get_attr_page_size(ctx) - off;
		endp = memchr(ctx->page + off, 0, partlen);
		if (endp)
			partlen = endp - ((char*)ctx->page + off);

		newlength = length + partlen;
		newstr = realloc(str, newlength + 1);
		if (!newstr) {
			if (str)
				free(str);
			return set_error(ctx, kdump_syserr,
					 "Cannot enlarge string to"
					 " %zu bytes: %s",
					 newlength + 1, strerror(errno));
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

static kdump_status
init_xen_p2m64(kdump_ctx *ctx, void *dir)
{
	size_t ptr_size;
	unsigned fpp;
	uint64_t *dirp, *p, *map;
	uint64_t pfn;
	unsigned long mfns;
	kdump_status ret;

	ptr_size = get_attr_ptr_size(ctx);
	fpp = get_attr_page_size(ctx) / ptr_size;
	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < ctx->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		ret = ctx->ops->read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page;
		     (void*)p < ctx->page + get_attr_page_size(ctx);
		     ++p)
			if (*p)
				++mfns;
	}

	map = ctx_malloc(mfns * sizeof(uint64_t), ctx, "Xen P2M map");
	if (!map)
		return kdump_syserr;
	ctx->xen_map = map;
	ctx->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		ret = ctx->ops->read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page;
		     (void*)p < ctx->page + get_attr_page_size(ctx);
		     ++p)
			if (*p) {
				*map++ = dump64toh(ctx, *p);
				--mfns;
			}
	}

	return kdump_ok;
}

static kdump_status
init_xen_p2m32(kdump_ctx *ctx, void *dir)
{
	size_t ptr_size;
	unsigned fpp;
	uint32_t *dirp, *p, *map;
	uint32_t pfn;
	unsigned long mfns;
	kdump_status ret;

	ptr_size = get_attr_ptr_size(ctx);
	fpp = get_attr_page_size(ctx) / ptr_size;
	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < ctx->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		ret = ctx->ops->read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page;
		     (void*)p < ctx->page + get_attr_page_size(ctx);
		     ++p)
			if (*p)
				++mfns;
	}

	map = ctx_malloc(mfns * sizeof(uint32_t), ctx, "Xen P2M map");
	if (!map)
		return kdump_syserr;
	ctx->xen_map = map;
	ctx->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		ret = ctx->ops->read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page;
		     (void*)p < ctx->page + get_attr_page_size(ctx);
		     ++p)
			if (*p) {
				*map++ = dump32toh(ctx, *p);
				--mfns;
			}
	}

	return kdump_ok;
}

kdump_status
init_xen_dom0(kdump_ctx *ctx)
{
	void *dir, *page;
	kdump_pfn_t xen_p2m_mfn;
	struct kdump_attr attr;
	kdump_status ret;

	ret = kdump_get_attr(ctx, GATTR(GKI_xen_p2m_mfn), &attr);
	if (ret == kdump_nodata)
		/* not a Xen Dom0 dump */
		return kdump_ok;
	else if (ret != kdump_ok)
		return set_error(ctx, ret,
				 "Cannot get xen_p2m_mfn");
	xen_p2m_mfn = attr.val.address;

	ret = ctx->ops->read_page(ctx, xen_p2m_mfn);
	if (ret != kdump_ok)
		return set_error(ctx, ret,
				 "Cannot read Xen P2M directory MFN 0x%llx",
				 (unsigned long long) xen_p2m_mfn);

	dir = ctx->page;
	page = ctx_malloc(get_attr_page_size(ctx), ctx, "page buffer");
	if (page == NULL)
		return kdump_syserr;
	ctx->page = page;

	ret = (get_attr_ptr_size(ctx) == 8)
		? init_xen_p2m64(ctx, dir)
		: init_xen_p2m32(ctx, dir);

	free(dir);
	return ret;
}
