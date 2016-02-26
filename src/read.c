/** @internal @file src/read.c
 * @brief Routines for reading dumps.
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

typedef kdump_status (*read_page_fn)(kdump_ctx *, struct page_io *);

static kdump_status
read_kpage_generic(kdump_ctx *ctx, struct page_io *pio)
{
	kdump_status res;

	res = ctx->arch_ops->pfn_to_mfn(ctx, pio->pfn, &pio->pfn);
	if (res != kdump_ok)
		return res;

	res = ctx->ops->read_page(ctx, pio);
	return set_error(ctx, res, "Cannot read MFN %llx",
			 (unsigned long long) pio->pfn);
}

static inline read_page_fn
read_kphys_page_fn(kdump_ctx *ctx)
{
	if (kphys_is_machphys(ctx))
		return ctx->ops->read_page;

	if (ctx->ops->read_kpage)
		return ctx->ops->read_kpage;

	if (ctx->ops->read_page &&
	    ctx->arch_ops && ctx->arch_ops->pfn_to_mfn)
		return read_kpage_generic;

	return NULL;
}

static kdump_status
read_kvpage_machphys(kdump_ctx *ctx, struct page_io *pio)
{
	kdump_vaddr_t vaddr;
	kdump_maddr_t maddr;
	kdump_status ret;

	vaddr = pio->pfn << get_page_shift(ctx);
	ret = kdump_vtom(ctx, vaddr, &maddr);
	if (ret != kdump_ok)
		return ret;

	pio->pfn = maddr >> get_page_shift(ctx);
	return ctx->ops->read_page(ctx, pio);
}

static kdump_status
read_kvpage_kphys(kdump_ctx *ctx, struct page_io *pio)
{
	kdump_vaddr_t vaddr;
	kdump_paddr_t paddr;
	kdump_status ret;

	vaddr = pio->pfn << get_page_shift(ctx);
	ret = kdump_vtop(ctx, vaddr, &paddr);
	if (ret != kdump_ok)
		return ret;

	pio->pfn = paddr >> get_page_shift(ctx);
	return ctx->ops->read_kpage(ctx, pio);
}

static kdump_status
read_kvpage_choose(kdump_ctx *ctx, struct page_io *pio)
{
	kdump_vaddr_t vaddr;
	const struct kdump_xlat *xlat;

	vaddr = pio->pfn << get_page_shift(ctx);
	xlat = get_vtop_xlat(&ctx->vtop_map, vaddr);
	if (xlat->method != KDUMP_XLAT_VTOP)
		return read_kvpage_kphys(ctx, pio);
	else
		return read_kvpage_machphys(ctx, pio);
}

static kdump_status
read_xenvpage(kdump_ctx *ctx, struct page_io *pio)
{
	kdump_vaddr_t vaddr;
	kdump_paddr_t paddr;
	kdump_status ret;

	vaddr = pio->pfn << get_page_shift(ctx);
	ret = kdump_vtop_xen(ctx, vaddr, &paddr);
	if (ret != kdump_ok)
		return ret;

	pio->pfn = paddr >> get_page_shift(ctx);
	return ctx->ops->read_page(ctx, pio);
}

static kdump_status
setup_readfn(kdump_ctx *ctx, kdump_addrspace_t as, read_page_fn *pfn)
{
	read_page_fn fn;

	if (!ctx->ops)
		return set_error(ctx, kdump_invalid,
				 "File format not initialized");

	fn = NULL;
	switch (as) {
	case KDUMP_KPHYSADDR:
		fn = read_kphys_page_fn(ctx);
		break;

	case KDUMP_MACHPHYSADDR:
		fn = ctx->ops->read_page;
		break;

	case KDUMP_KVADDR:
		if (ctx->ops->read_page) {
			if (ctx->ops->read_kpage)
				fn = read_kvpage_choose;
			else
				fn = read_kvpage_machphys;
		} else if (ctx->ops->read_kpage)
			fn = read_kvpage_kphys;
		break;

	case KDUMP_XENVADDR:
		if (ctx->ops->read_page)
			fn = read_xenvpage;
		break;

	default:
		return set_error(ctx, kdump_invalid,
				 "Invalid address space");
	}

	if (!fn)
		return set_error(ctx, kdump_invalid,
				 "Read function not available");

	*pfn = fn;
	return kdump_ok;
}

/**  Raw interface to read_page().
 * @param ctx  Dump file object.
 * @param as   Address space.
 * @param pio  Page I/O control.
 */
kdump_status
raw_read_page(kdump_ctx *ctx, kdump_addrspace_t as, struct page_io *pio)
{
	read_page_fn readfn;
	kdump_status ret;

	ret = setup_readfn(ctx, as, &readfn);
	if (ret != kdump_ok)
		return ret;

	return readfn(ctx, pio);
}

kdump_status
kdump_readp(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	    void *buffer, size_t *plength)
{
	read_page_fn readfn;
	struct page_io pio;
	size_t remain;
	kdump_status ret;

	clear_error(ctx);

	ret = setup_readfn(ctx, as, &readfn);
	if (ret != kdump_ok)
		return ret;

	pio.precious = 0;
	remain = *plength;
	while (remain) {
		size_t off, partlen;

		pio.pfn = addr >> get_page_shift(ctx);
		ret = readfn(ctx, &pio);
		if (ret != kdump_ok)
			break;

		off = addr % get_page_size(ctx);
		partlen = get_page_size(ctx) - off;
		if (partlen > remain)
			partlen = remain;
		memcpy(buffer, pio.buf + off, partlen);
		addr += partlen;
		buffer += partlen;
		remain -= partlen;
	}

	*plength -= remain;
	return ret;
}

ssize_t
kdump_read(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	   void *buffer, size_t length)
{
	size_t sz;
	kdump_status ret;

	sz = length;
	ret = kdump_readp(ctx, as, addr, buffer, &sz);
	if (!sz && ret == kdump_syserr)
		return -1;
	return sz;
}

kdump_status
kdump_read_string(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
		  char **pstr)
{
	read_page_fn readfn;
	struct page_io pio;
	char *str = NULL, *newstr, *endp;
	size_t length = 0, newlength;
	kdump_status ret;

	clear_error(ctx);

	ret = setup_readfn(ctx, as, &readfn);
	if (ret != kdump_ok)
		return ret;

	pio.precious = 0;
	do {
		size_t off, partlen;

		pio.pfn = addr >> get_page_shift(ctx);
		ret = readfn(ctx, &pio);
		if (ret != kdump_ok)
			break;

		off = addr % get_page_size(ctx);
		partlen = get_page_size(ctx) - off;
		endp = memchr(pio.buf + off, 0, partlen);
		if (endp)
			partlen = endp - ((char*)pio.buf + off);

		newlength = length + partlen;
		newstr = realloc(str, newlength + 1);
		if (!newstr) {
			if (str)
				free(str);
			return set_error(ctx, kdump_syserr,
					 "Cannot enlarge string to %zu bytes",
					 newlength + 1);
		}
		memcpy(newstr + length, pio.buf + off, partlen);
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

/**  Get an aligned uint64_t value in host-byte order.
 * @param ctx     Dump file object.
 * @param as      Address space.
 * @param addr    Value address.
 * @param what    Human-readable description of the read.
 * @param result  Pointer to resulting variable.
 *
 * This function fails if data crosses a page boundary.
 */
kdump_status
read_u64(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	 char *what, uint64_t *result)
{
	struct page_io pio;
	uint64_t *p;
	kdump_status ret;

	pio.pfn = addr >> get_page_shift(ctx);
	pio.precious = 0;
	ret = raw_read_page(ctx, as, &pio);
	if (ret != kdump_ok)
		return set_error(ctx, ret,
				 "Reading %s failed at %llx",
				 what, (unsigned long long) addr);

	p = pio.buf + (addr & (get_page_size(ctx) - 1));
	*result = dump64toh(ctx, *p);
	return kdump_ok;
}
