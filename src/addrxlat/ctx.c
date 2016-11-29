/** @internal @file src/addrxlat/ctx.c
 * @brief Address translation context routines.
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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "addrxlat-priv.h"

addrxlat_ctx_t *
addrxlat_ctx_new(void)
{
	addrxlat_ctx_t *ctx = calloc(1, sizeof(addrxlat_ctx_t));
	if (ctx) {
		ctx->refcnt = 1;
	}
	return ctx;
}

unsigned long
addrxlat_ctx_incref(addrxlat_ctx_t *ctx)
{
	return ++ctx->refcnt;
}

unsigned long
addrxlat_ctx_decref(addrxlat_ctx_t *ctx)
{
	unsigned long refcnt = --ctx->refcnt;
	if (!refcnt)
		free(ctx);
	return refcnt;
}

const char *
addrxlat_ctx_err(addrxlat_ctx_t *ctx)
{
	return ctx->err_buf;
}

void
addrxlat_ctx_set_cbdata(addrxlat_ctx_t *ctx, void *data)
{
	ctx->priv = data;
}

void *
addrxlat_ctx_get_cbdata(addrxlat_ctx_t *ctx)
{
	return ctx->priv;
}

addrxlat_sym_fn *
addrxlat_ctx_cb_sym(addrxlat_ctx_t *ctx, addrxlat_sym_fn *cb)
{
	addrxlat_sym_fn *oldval = ctx->cb_sym;
	ctx->cb_sym = cb;
	return oldval;
}

addrxlat_read32_fn *
addrxlat_ctx_cb_read32(addrxlat_ctx_t *ctx, addrxlat_read32_fn *cb)
{
	addrxlat_read32_fn *oldval = ctx->cb_read32;
	ctx->cb_read32 = cb;
	return oldval;
}

addrxlat_read64_fn *
addrxlat_ctx_cb_read64(addrxlat_ctx_t *ctx, addrxlat_read64_fn *cb)
{
	addrxlat_read64_fn *oldval = ctx->cb_read64;
	ctx->cb_read64 = cb;
	return oldval;
}

/** Resolve a symbol value.
 * @param      ctx   Address translation context.
 * @param      name  Symbol name.
 * @param[out] val   Symbol value, returned on sucess.
 * @returns          Error status.
 *
 * The symbol is resolved using a user-supplied callback.
 */
addrxlat_status
get_symval(addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *val)
{
	struct {
		addrxlat_sym_t sym;
		const char *name;
	} info;
	addrxlat_status status;

	if (!ctx->cb_sym)
		return set_error(ctx, addrxlat_notimpl,
				 "No symbolic information callback");

	info.sym.type = ADDRXLAT_SYM_VALUE;
	info.name = name;
	status = ctx->cb_sym(ctx->priv, (addrxlat_sym_t*)&info);
	if (status != addrxlat_ok)
		return set_error(ctx, status,
				 "Cannot resolve \"%s\"", info.name);

	*val = info.sym.val;
	return status;
}

/** Get the size of a symbol or type.
 * @param      ctx   Address translation context.
 * @param      name  Symbol name or type name.
 * @param[out] sz    Size in bytes, returned on sucess.
 * @returns          Error status.
 *
 * The size is determined using a user-supplied callback.
 */
addrxlat_status
get_sizeof(addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *sz)
{
	struct {
		addrxlat_sym_t sym;
		const char *name;
	} info;
	addrxlat_status status;

	if (!ctx->cb_sym)
		return set_error(ctx, addrxlat_notimpl,
				 "No symbolic information callback");

	info.sym.type = ADDRXLAT_SYM_SIZEOF;
	info.name = name;
	status = ctx->cb_sym(ctx->priv, (addrxlat_sym_t*)&info);
	if (status != addrxlat_ok)
		return set_error(ctx, status, "Cannot get sizeof(%s)",
				 info.name);

	*sz = info.sym.val;
	return status;
}

/** Get the relative offset of a member inside a type.
 * @param      ctx   Address translation context.
 * @param      type  Container type name.
 * @param      memb  Member name.
 * @param[out] val   Symbol value, returned on sucess.
 * @returns          Error status.
 *
 * The symbol is resolved using a user-supplied callback.
 */
addrxlat_status
get_offsetof(addrxlat_ctx_t *ctx, const char *type, const char *memb,
	     addrxlat_addr_t *off)
{
	struct {
		addrxlat_sym_t sym;
		const char *type;
		const char *memb;
	} info;
	addrxlat_status status;

	if (!ctx->cb_sym)
		return set_error(ctx, addrxlat_notimpl,
				 "No symbolic information callback");

	info.sym.type = ADDRXLAT_SYM_VALUE;
	info.type = type;
	info.memb = memb;
	status = ctx->cb_sym(ctx->priv, (addrxlat_sym_t*)&info);
	if (status != addrxlat_ok)
		return set_error(ctx, status, "Cannot get offsetof(%s, %s)",
				 info.type, info.memb);

	*off = info.sym.val;
	return status;
}

addrxlat_status
set_error(addrxlat_ctx_t *ctx, addrxlat_status status, const char *msgfmt, ...)
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
