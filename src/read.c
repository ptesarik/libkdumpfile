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
	addrxlat_fulladdr_t faddr;
	addrxlat_status axres;

	faddr.addr = pio->addr;
	faddr.as = ADDRXLAT_KPHYSADDR;
	axres = addrxlat_by_sys(ctx->addrxlat, &faddr, ADDRXLAT_MACHPHYSADDR,
				ctx->shared->xlat);
	if (axres != addrxlat_ok)
		return addrxlat2kdump(ctx, axres);

	pio->addr = faddr.addr;
	return ctx->shared->ops->read_page(ctx, pio);
}

static inline read_page_fn
read_kphys_page_fn(kdump_ctx *ctx)
{
	if (kphys_is_machphys(ctx))
		return ctx->shared->ops->read_page;

	if (ctx->shared->ops->read_kpage)
		return ctx->shared->ops->read_kpage;

	if (ctx->shared->ops->read_page)
		return read_kpage_generic;

	return NULL;
}

static kdump_status
read_kvpage_machphys(kdump_ctx *ctx, struct page_io *pio)
{
	addrxlat_fulladdr_t faddr;
	addrxlat_status axres;

	faddr.addr = pio->addr;
	faddr.as = ADDRXLAT_KVADDR;
	axres = addrxlat_by_sys(ctx->addrxlat, &faddr, ADDRXLAT_MACHPHYSADDR,
				ctx->shared->xlat);
	if (axres != addrxlat_ok)
		return addrxlat2kdump(ctx, axres);

	pio->addr = faddr.addr;
	return ctx->shared->ops->read_page(ctx, pio);
}

static kdump_status
read_kvpage_kphys(kdump_ctx *ctx, struct page_io *pio)
{
	addrxlat_fulladdr_t faddr;
	addrxlat_status axres;

	faddr.addr = pio->addr;
	faddr.as = ADDRXLAT_KVADDR;
	axres = addrxlat_by_sys(ctx->addrxlat, &faddr, ADDRXLAT_KPHYSADDR,
				ctx->shared->xlat);
	if (axres != addrxlat_ok)
		return addrxlat2kdump(ctx, axres);

	pio->addr = faddr.addr;
	return ctx->shared->ops->read_kpage(ctx, pio);
}

static kdump_status
read_kvpage_choose(kdump_ctx *ctx, struct page_io *pio)
{
	kdump_vaddr_t vaddr;
	const addrxlat_map_t *map;

	vaddr = pio->addr;
	map = addrxlat_sys_get_map(ctx->shared->xlat,
				   ADDRXLAT_SYS_MAP_KV_PHYS);
	if (map) {
		const addrxlat_meth_t *meth = addrxlat_map_search(map, vaddr);
		if (meth && addrxlat_meth_get_def(meth)->kind != ADDRXLAT_PGT)
			return read_kvpage_kphys(ctx, pio);
	}

	return read_kvpage_machphys(ctx, pio);
}

static kdump_status
setup_readfn(kdump_ctx *ctx, kdump_addrspace_t as, read_page_fn *pfn)
{
	read_page_fn fn;

	if (!ctx->shared->ops)
		return set_error(ctx, kdump_invalid,
				 "File format not initialized");

	fn = NULL;
	switch (as) {
	case KDUMP_KPHYSADDR:
		fn = read_kphys_page_fn(ctx);
		break;

	case KDUMP_MACHPHYSADDR:
		fn = ctx->shared->ops->read_page;
		break;

	case KDUMP_KVADDR:
		if (ctx->shared->ops->read_page) {
			if (ctx->shared->ops->read_kpage)
				fn = read_kvpage_choose;
			else
				fn = read_kvpage_machphys;
		} else if (ctx->shared->ops->read_kpage)
			fn = read_kvpage_kphys;
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
static kdump_status
raw_read_page(kdump_ctx *ctx, kdump_addrspace_t as, struct page_io *pio)
{
	read_page_fn readfn;
	kdump_status ret;

	ret = setup_readfn(ctx, as, &readfn);
	if (ret != kdump_ok)
		return ret;

	return readfn(ctx, pio);
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
read_locked(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	    void *buffer, size_t *plength)
{
	read_page_fn readfn;
	struct page_io pio;
	size_t remain;
	kdump_status ret;

	ret = setup_readfn(ctx, as, &readfn);
	if (ret != kdump_ok)
		return ret;

	pio.precious = 0;
	remain = *plength;
	while (remain) {
		size_t off, partlen;

		pio.addr = page_align(ctx, addr);
		ret = readfn(ctx, &pio);
		if (ret != kdump_ok)
			break;

		off = addr % get_page_size(ctx);
		partlen = get_page_size(ctx) - off;
		if (partlen > remain)
			partlen = remain;
		memcpy(buffer, pio.ce->data + off, partlen);
		unref_page(ctx, &pio);
		addr += partlen;
		buffer += partlen;
		remain -= partlen;
	}

	*plength -= remain;
	return ret;
}

kdump_status
kdump_read(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
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
read_string_locked(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
		   char **pstr)
{
	read_page_fn readfn;
	struct page_io pio;
	char *str = NULL, *newstr, *endp;
	size_t length = 0, newlength;
	kdump_status ret;

	ret = setup_readfn(ctx, as, &readfn);
	if (ret != kdump_ok)
		return ret;

	pio.precious = 0;
	do {
		size_t off, partlen;

		pio.addr = page_align(ctx, addr);
		ret = readfn(ctx, &pio);
		if (ret != kdump_ok)
			return ret;

		off = addr % get_page_size(ctx);
		partlen = get_page_size(ctx) - off;
		endp = memchr(pio.ce->data + off, 0, partlen);
		if (endp)
			partlen = endp - ((char*)pio.ce->data + off);

		newlength = length + partlen;
		newstr = realloc(str, newlength + 1);
		if (!newstr) {
			unref_page(ctx, &pio);
			if (str)
				free(str);
			return set_error(ctx, kdump_syserr,
					 "Cannot enlarge string to %zu bytes",
					 newlength + 1);
		}
		memcpy(newstr + length, pio.ce->data + off, partlen);
		unref_page(ctx, &pio);
		length = newlength;
		str = newstr;

		addr += partlen;
	} while (!endp);

	str[length] = 0;
	*pstr = str;
	return kdump_ok;
}

kdump_status
kdump_read_string(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
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
read_u32(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	 int precious, char *what, uint32_t *result)
{
	struct page_io pio;
	uint32_t *p;
	kdump_status ret;

	pio.addr = page_align(ctx, addr);
	pio.precious = precious;
	ret = raw_read_page(ctx, as, &pio);
	if (ret != kdump_ok)
		return what
			? set_error(ctx, ret,
				    "Reading %s failed at %llx",
				    what, (unsigned long long) addr)
			: ret;

	p = pio.ce->data + (addr & (get_page_size(ctx) - 1));
	*result = dump32toh(ctx, *p);
	unref_page(ctx, &pio);
	return kdump_ok;
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
read_u64(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	 int precious, char *what, uint64_t *result)
{
	struct page_io pio;
	uint64_t *p;
	kdump_status ret;

	pio.addr = page_align(ctx, addr);
	pio.precious = precious;
	ret = raw_read_page(ctx, as, &pio);
	if (ret != kdump_ok)
		return what
			? set_error(ctx, ret,
				    "Reading %s failed at %llx",
				    what, (unsigned long long) addr)
			: ret;

	p = pio.ce->data + (addr & (get_page_size(ctx) - 1));
	*result = dump64toh(ctx, *p);
	unref_page(ctx, &pio);
	return kdump_ok;
}

/**  Set read address spaces.
 * @param shared  Dump file shared data.
 * @param caps    Addrxlat capabilities.
 */
void
set_addrspace_caps(struct kdump_shared *shared, unsigned long caps)
{
	kdump_ctx *ctx;

	shared->xlat_caps = caps;
	list_for_each_entry(ctx, &shared->ctx, list) {
		addrxlat_ctx_t *addrxlat = ctx->addrxlat;
		addrxlat_cb_t cb = *addrxlat_ctx_get_cb(addrxlat);
		cb.read_caps = caps;
		addrxlat_ctx_set_cb(addrxlat, &cb);
	}
}
