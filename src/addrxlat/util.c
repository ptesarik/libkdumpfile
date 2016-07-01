/** @internal @file src/addrxlat/util.c
 * @brief Utility functions.
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

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "addrxlat-priv.h"

addrxlat_status
set_error(addrxlat_ctx *ctx, addrxlat_status status, const char *msgfmt, ...)
{
	va_list ap;
	int msglen;

	if (status == addrxlat_ok)
		return status;

	va_start(ap, msgfmt);
	msglen = vsnprintf(ctx->err_buf, sizeof(ctx->err_buf), msgfmt, ap);
	va_end(ap);

	if (msglen < 0)
		strcpy(ctx->err_buf, "(set_error failed)");

	return status;
}

const char *
addrxlat_err_str(addrxlat_ctx *ctx)
{
	return ctx->err_buf;
}

addrxlat_read32_fn *
addrxlat_cb_read32(addrxlat_ctx *ctx, addrxlat_read32_fn *cb)
{
	addrxlat_read32_fn *oldval = ctx->cb_read32;
	ctx->cb_read32 = cb;
	return oldval;
}

addrxlat_read64_fn *
addrxlat_cb_read64(addrxlat_ctx *ctx, addrxlat_read64_fn *cb)
{
	addrxlat_read64_fn *oldval = ctx->cb_read64;
	ctx->cb_read64 = cb;
	return oldval;
}
