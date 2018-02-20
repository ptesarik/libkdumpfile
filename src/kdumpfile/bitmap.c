/** @internal @file src/kdumpfile/fcache.c
 * @brief File caching.
 */
/* Copyright (C) 2017 Petr Tesarik <ptesarik@suse.com>

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

/** Maximum length of the static error message. */
#define ERRBUF	80

/** Set a range of bits in a raw bitmap.
 * @param buf    Pointer to raw bitmap.
 * @param start  First bit to set.
 * @param end    Last bit to set.
 */
void
set_bits(unsigned char *buf, size_t start, size_t end)
{
	size_t startbyte, endbyte;
	char startmask, endmask;

	startbyte = start >> 3;
	startmask = (1 << (start & 7)) - 1;
	endbyte = end >> 3;
	endmask = (1 << ((end & 7) + 1)) - 1;

	if (startbyte < endbyte) {
		buf[startbyte++] |= ~startmask;
		memset(buf + startbyte, 0xff, endbyte - startbyte);
		buf[endbyte] |= endmask;
	} else
		buf[startbyte] |= ~startmask & endmask;
}

/** Clear a range of bits in a raw bitmap.
 * @param buf    Pointer to raw bitmap.
 * @param start  First bit to clear.
 * @param end    Last bit to clear.
 */
void
clear_bits(unsigned char *buf, size_t start, size_t end)
{
	size_t startbyte, endbyte;
	char startmask, endmask;

	startbyte = start >> 3;
	startmask = (1 << (start & 7)) - 1;
	endbyte = end >> 3;
	endmask = (1 << ((end & 7) + 1)) - 1;

	if (startbyte < endbyte) {
		buf[startbyte++] &= startmask;
		memset(buf + startbyte, 0x00, endbyte - startbyte);
		buf[endbyte] &= ~endmask;
	} else
		buf[startbyte] &= startmask | ~endmask;
}

/** Allocate a new bitmap object.
 * @param ops  Bitmap operations.
 * @returns    New bitmap, or @c NULL on allocation error.
 *
 * The new object's reference count is initialized to 1.
 */
kdump_bmp_t *
kdump_bmp_new(const struct kdump_bmp_ops *ops)
{
	kdump_bmp_t *bmp;
	bmp = malloc(sizeof(kdump_bmp_t) + ERRBUF);
	if (bmp) {
		bmp->refcnt = 1;
		bmp->ops = ops;
		err_init(&bmp->err, ERRBUF);
	}
	return bmp;
}

unsigned long
kdump_bmp_incref(kdump_bmp_t *bmp)
{
	return ++bmp->refcnt;
}

unsigned long
kdump_bmp_decref(kdump_bmp_t *bmp)
{
	unsigned long refcnt = --bmp->refcnt;
	if (!refcnt) {
		if (bmp->ops->cleanup)
			bmp->ops->cleanup(bmp);
		err_cleanup(&bmp->err);
		free(bmp);
	}
	return refcnt;
}

const char *
kdump_bmp_get_err(const kdump_bmp_t *bmp)
{
	return err_str(&bmp->err);
}

kdump_status
kdump_bmp_get_bits(kdump_bmp_t *bmp,
		   kdump_addr_t first, kdump_addr_t last, unsigned char *raw)
{
	err_clear(&bmp->err);
	if (!bmp->ops->get_bits)
		return status_err(&bmp->err, KDUMP_ERR_NOTIMPL,
				  "Function not implemented");
	return bmp->ops->get_bits(&bmp->err, bmp, first, last, raw);
}

kdump_status
kdump_bmp_find_set(kdump_bmp_t *bmp, kdump_addr_t *idx)
{
	err_clear(&bmp->err);
	if (!bmp->ops->find_set)
		return status_err(&bmp->err, KDUMP_ERR_NOTIMPL,
				  "Function not implemented");
	return bmp->ops->find_set(&bmp->err, bmp, idx);
}

kdump_status
kdump_bmp_find_clear(kdump_bmp_t *bmp, kdump_addr_t *idx)
{
	err_clear(&bmp->err);
	if (!bmp->ops->find_clear)
		return status_err(&bmp->err, KDUMP_ERR_NOTIMPL,
				  "Function not implemented");
	return bmp->ops->find_clear(&bmp->err, bmp, idx);
}
