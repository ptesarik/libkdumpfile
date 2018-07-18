/** @internal @file src/kdumpfile/read.c
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

/** Get a page from the default cache.
 *
 * @param ctx  Dump file object.
 * @param pio  Page I/O control.
 * @param fn   Read function.
 * @returns    Error status.
 *
 * If the page is not currently found in the cache, read it using
 * the read function.
 */
kdump_status
cache_get_page(kdump_ctx_t *ctx, struct page_io *pio, read_page_fn *fn)
{
	struct cache_entry *entry;
	kdump_status ret;

	pio->chunk.nent = 1;
	pio->chunk.fce.cache = ctx->shared->cache;
	entry = cache_get_entry(pio->chunk.fce.cache,
				pio->addr.addr | pio->addr.as);
	if (!entry)
		return set_error(ctx, KDUMP_ERR_BUSY,
				 "Cache is fully utilized");

	pio->chunk.data = entry->data;
	pio->chunk.fce.ce = entry;
	if (cache_entry_valid(entry))
		return KDUMP_OK;

	ret = fn(ctx, pio);
	if (ret == KDUMP_OK) {
		if (pio->precious)
			cache_make_precious(pio->chunk.fce.cache, entry);
		cache_insert(pio->chunk.fce.cache, entry);
	} else
		cache_discard(pio->chunk.fce.cache, entry);
	return ret;
}

/**  Drop a reference to an I/O page from the default cache.
 * @param ctx  Dump file object.
 * @param pio  Page I/O control.
 */
void
cache_put_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	fcache_put_chunk(&pio->chunk);
}

static addrxlat_status
xlat_pio_op(void *data, const addrxlat_fulladdr_t *addr)
{
	struct page_io *pio = data;
	pio->addr = *addr;
	return ADDRXLAT_OK;
}

/**  Tranlate the address for page I/O.
 * @param ctx  Dump file object.
 * @param pio  Page I/O control.
 *
 * This function translates the page I/O address to an address space that
 * is included in @c xlat_caps. The resulting page I/O object can be
 * directly passed to a @c get_page method.
 */
static kdump_status
xlat_pio(kdump_ctx_t *ctx, struct page_io *pio)
{
	addrxlat_op_ctl_t ctl;
	kdump_status status;

	if (ctx->xlat->xlat_caps & ADDRXLAT_CAPS(pio->addr.as))
		return KDUMP_OK;

	status = revalidate_xlat(ctx);
	if (status != KDUMP_OK)
		return status;

	ctl.ctx = ctx->xlatctx;
	ctl.sys = ctx->xlat->xlatsys;
	ctl.op = xlat_pio_op;
	ctl.data = pio;
	ctl.caps = ctx->xlat->xlat_caps;
	return addrxlat2kdump(ctx, addrxlat_op(&ctl, &pio->addr));
}

/**  Raw interface to get_page().
 * @param ctx  Dump file object.
 * @param pio  Page I/O control.
 */
static kdump_status
get_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	kdump_status status;

	status = xlat_pio(ctx, pio);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot get page I/O address");

	return ctx->shared->ops->get_page(ctx, pio);
}

/**  Internal version of @ref kdump_read
 * @param         ctx      Dump file object.
 * @param[in]     as       Address space of @p addr.
 * @param[in]     addr     Any type of address.
 * @param[out]    buffer   Buffer to receive data.
 * @param[in,out] plength  Length of the buffer.
 * @returns                Error status.
 *
 * Use this function internally if the shared lock is already held
 * (for reading or writing).
 *
 * @sa kdump_read
 */
kdump_status
read_locked(kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	    void *buffer, size_t *plength)
{
	struct page_io pio;
	size_t remain;
	kdump_status ret;

	ret = KDUMP_OK;
	pio.precious = 0;
	remain = *plength;
	while (remain) {
		size_t off, partlen;

		pio.addr.as = as;
		pio.addr.addr = page_align(ctx, addr);
		ret = get_page(ctx, &pio);
		if (ret != KDUMP_OK)
			break;

		off = addr % get_page_size(ctx);
		partlen = get_page_size(ctx) - off;
		if (partlen > remain)
			partlen = remain;
		memcpy(buffer, pio.chunk.data + off, partlen);
		put_page(ctx, &pio);
		addr += partlen;
		buffer += partlen;
		remain -= partlen;
	}

	*plength -= remain;
	return ret;
}

kdump_status
kdump_read(kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	    void *buffer, size_t *plength)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);
	ret = read_locked(ctx, as, addr, buffer, plength);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Internal version of @ref kdump_read_string.
 * @param      ctx   Dump file object.
 * @param[in]  as    Address space of @c addr.
 * @param[in]  addr  Any type of address.
 * @param[out] pstr  String to be read.
 * @returns          Error status.
 *
 * Use this function internally if the shared lock is already held
 * (for reading or writing).
 *
 * @sa kdump_read_string
 */
kdump_status
read_string_locked(kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
		   char **pstr)
{
	struct page_io pio;
	char *str = NULL, *newstr, *endp;
	size_t length = 0, newlength;
	kdump_status ret;

	pio.precious = 0;
	do {
		size_t off, partlen;

		pio.addr.as = as;
		pio.addr.addr = page_align(ctx, addr);
		ret = get_page(ctx, &pio);
		if (ret != KDUMP_OK)
			return ret;

		off = addr % get_page_size(ctx);
		partlen = get_page_size(ctx) - off;
		endp = memchr(pio.chunk.data + off, 0, partlen);
		if (endp)
			partlen = endp - ((char*)pio.chunk.data + off);

		newlength = length + partlen;
		newstr = realloc(str, newlength + 1);
		if (!newstr) {
			put_page(ctx, &pio);
			if (str)
				free(str);
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot enlarge string to %zu bytes",
					 newlength + 1);
		}
		memcpy(newstr + length, pio.chunk.data + off, partlen);
		put_page(ctx, &pio);
		length = newlength;
		str = newstr;

		addr += partlen;
	} while (!endp);

	str[length] = 0;
	*pstr = str;
	return KDUMP_OK;
}

kdump_status
kdump_read_string(kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
		  char **pstr)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);
	ret = read_string_locked(ctx, as, addr, pstr);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Get an aligned uint32_t value in host-byte order.
 * @param ctx       Dump file object.
 * @param as        Address space.
 * @param addr      Value address.
 * @param precious  Non-zero if this read should be regarded as precious.
 * @param what      Human-readable description of the read,
 *                  or @c NULL to turn off error reporting.
 * @param result    Pointer to resulting variable.
 *
 * This function fails if data crosses a page boundary.
 */
kdump_status
read_u32(kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	 int precious, char *what, uint32_t *result)
{
	struct page_io pio;
	uint32_t *p;
	kdump_status ret;

	pio.addr.addr = page_align(ctx, addr);
	pio.addr.as = as;
	pio.precious = precious;
	ret = get_page(ctx, &pio);
	if (ret != KDUMP_OK)
		return what
			? set_error(ctx, ret,
				    "Reading %s failed at %llx",
				    what, (unsigned long long) addr)
			: ret;

	p = pio.chunk.data + (addr & (get_page_size(ctx) - 1));
	*result = dump32toh(ctx, *p);
	put_page(ctx, &pio);
	return KDUMP_OK;
}

/**  Get an aligned uint64_t value in host-byte order.
 * @param ctx       Dump file object.
 * @param as        Address space.
 * @param addr      Value address.
 * @param precious  Non-zero if this read should be regarded as precious.
 * @param what      Human-readable description of the read,
 *                  or @c NULL to turn off error reporting.
 * @param result    Pointer to resulting variable.
 *
 * This function fails if data crosses a page boundary.
 */
kdump_status
read_u64(kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	 int precious, char *what, uint64_t *result)
{
	struct page_io pio;
	uint64_t *p;
	kdump_status ret;

	pio.addr.addr = page_align(ctx, addr);
	pio.addr.as = as;
	pio.precious = precious;
	ret = get_page(ctx, &pio);
	if (ret != KDUMP_OK)
		return what
			? set_error(ctx, ret,
				    "Reading %s failed at %llx",
				    what, (unsigned long long) addr)
			: ret;

	p = pio.chunk.data + (addr & (get_page_size(ctx) - 1));
	*result = dump64toh(ctx, *p);
	put_page(ctx, &pio);
	return KDUMP_OK;
}

/**  Set read address spaces.
 * @param xlat    Address translation.
 * @param caps    Addrxlat capabilities.
 */
void
set_addrspace_caps(struct kdump_xlat *xlat, unsigned long caps)
{
	kdump_ctx_t *ctx;

	xlat->xlat_caps = caps;
	list_for_each_entry(ctx, &xlat->ctx, xlat_list) {
		addrxlat_ctx_t *xlatctx = ctx->xlatctx;
		addrxlat_cb_t cb = *addrxlat_ctx_get_cb(xlatctx);
		cb.read_caps = caps;
		addrxlat_ctx_set_cb(xlatctx, &cb);
	}
}
