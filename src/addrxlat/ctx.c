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
	if (!refcnt) {
		if (ctx->err_dyn)
			free(ctx->err_dyn);
		free(ctx);
	}
	return refcnt;
}

void addrxlat_ctx_clear_err(addrxlat_ctx_t *ctx)
{
	clear_error(ctx);
}

const char *
addrxlat_ctx_get_err(addrxlat_ctx_t *ctx)
{
	return ctx->err_str;
}

void
addrxlat_ctx_set_cb(addrxlat_ctx_t *ctx, const addrxlat_cb_t *cb)
{
	ctx->cb = *cb;
}

const addrxlat_cb_t *
addrxlat_ctx_get_cb(const addrxlat_ctx_t *ctx)
{
	return &ctx->cb;
}

/** Read a 32-bit value, making an error message if needed.
 * @param     step  Current step state.
 * @param[in] addr  Full address of the data.
 * @param[out] val  32-bit data (on successful return).
 * @param     what  Descriptive object name.
 * @returns         Error status.
 */
addrxlat_status
read32(addrxlat_step_t *step, const addrxlat_fulladdr_t *addr, uint32_t *val,
       const char *what)
{
	addrxlat_ctx_t *ctx = step->ctx;
	addrxlat_status status = ctx->cb.read32(ctx->cb.data, addr, val);
	if (status != addrxlat_ok)
		return set_error(ctx, status,
				 "Cannot read the %s value of %s at 0x%"ADDRXLAT_PRIxADDR,
				 "32-bit", what, addr->addr);
	return addrxlat_ok;
}

/** Read a 64-bit value, making an error message if needed.
 * @param     step  Current step state.
 * @param[in] addr  Full address of the data.
 * @param[out] val  64-bit data (on successful return).
 * @param     what  Descriptive object name.
 * @returns         Error status.
 */
addrxlat_status
read64(addrxlat_step_t *step, const addrxlat_fulladdr_t *addr, uint64_t *val,
       const char *what)
{
	addrxlat_ctx_t *ctx = step->ctx;
	addrxlat_status status = ctx->cb.read64(ctx->cb.data, addr, val);
	if (status != addrxlat_ok)
		return set_error(ctx, status,
				 "Cannot read the %s value of %s at 0x%"ADDRXLAT_PRIxADDR,
				 "64-bit", what, addr->addr);
	return addrxlat_ok;
}

/** Get register value.
 * @param      ctx   Address translation context.
 * @param      name  Register name.
 * @param[out] val   Register value, returned on sucess.
 * @returns          Error status.
 *
 * The register value is obtained using a user-supplied callback.
 */
addrxlat_status
get_reg(addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *val)
{
	struct {
		addrxlat_sym_t sym;
		const char *name;
	} info;
	addrxlat_status status;

	if (!ctx->cb.sym)
		return set_error(ctx, addrxlat_notimpl,
				 "No symbolic information callback");

	info.sym.type = ADDRXLAT_SYM_REG;
	info.name = name;
	status = ctx->cb.sym(ctx->cb.data, (addrxlat_sym_t*)&info);
	if (status != addrxlat_ok)
		return set_error(ctx, status,
				 "Cannot read register \"%s\"", info.name);

	*val = info.sym.val;
	return status;
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

	if (!ctx->cb.sym)
		return set_error(ctx, addrxlat_notimpl,
				 "No symbolic information callback");

	info.sym.type = ADDRXLAT_SYM_VALUE;
	info.name = name;
	status = ctx->cb.sym(ctx->cb.data, (addrxlat_sym_t*)&info);
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

	if (!ctx->cb.sym)
		return set_error(ctx, addrxlat_notimpl,
				 "No symbolic information callback");

	info.sym.type = ADDRXLAT_SYM_SIZEOF;
	info.name = name;
	status = ctx->cb.sym(ctx->cb.data, (addrxlat_sym_t*)&info);
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

	if (!ctx->cb.sym)
		return set_error(ctx, addrxlat_notimpl,
				 "No symbolic information callback");

	info.sym.type = ADDRXLAT_SYM_OFFSETOF;
	info.type = type;
	info.memb = memb;
	status = ctx->cb.sym(ctx->cb.data, (addrxlat_sym_t*)&info);
	if (status != addrxlat_ok)
		return set_error(ctx, status, "Cannot get offsetof(%s, %s)",
				 info.type, info.memb);

	*off = info.sym.val;
	return status;
}

DEFINE_INTERNAL(ctx_err);

addrxlat_status
addrxlat_ctx_err(addrxlat_ctx_t *ctx, addrxlat_status status,
		 const char *msgfmt, ...)
{
	static const char failure[] = "(bad format string)";
	static const char delim[] = { ':', ' ' };

	va_list ap;
	char *msg, *newbuf;
	int msglen, dlen;
	size_t remain;

	if (status == addrxlat_ok)
		return status;

	/* Get length of formatted message. */
	va_start(ap, msgfmt);
	msglen = vsnprintf(NULL, 0, msgfmt, ap);
	va_end(ap);

	/* Cope with invalid format string.  */
	if (msglen < 0) {
		msgfmt = failure;
		msglen = sizeof(failure) - 1;
	}

	/* Calculate required and already allocated space. */
	msg = ctx->err_str;
	if (!msg || !*msg) {
		msg = ctx->err_buf + sizeof(ctx->err_buf) - 1;
		*msg = '\0';
		remain = sizeof(ctx->err_buf) - 1;
		dlen = 0;
	} else {
		remain = msg - ctx->err_buf;
		if (remain >= sizeof(ctx->err_buf))
			remain = msg - ctx->err_dyn;
		dlen = sizeof(delim);
	}

	va_start(ap, msgfmt);
	msglen += dlen;
	if (remain < msglen) {
		size_t curlen = strlen(msg);
		newbuf = realloc(ctx->err_dyn, 1 + curlen + msglen + 1);
		if (newbuf) {
			if (ctx->err_dyn <= msg && msg <= ctx->err_dyn + 1)
				msg += newbuf - ctx->err_dyn;
			ctx->err_dyn = newbuf;
			memmove(newbuf + msglen + 1, msg, curlen + 1);
			vsnprintf(newbuf + 1, msglen + 1, msgfmt, ap);
			msg = newbuf + msglen + 1;
			remain = msglen;
		} else if (remain) {
			char lbuf[ERRBUF];
			vsnprintf(lbuf, sizeof lbuf, msgfmt, ap);
			if (msglen - dlen >= sizeof(lbuf)) {
				lbuf[sizeof(lbuf) - 2] = '>';
				msglen = sizeof(lbuf) - 1 + dlen;
			}
			memcpy(msg - remain, lbuf + msglen - remain, remain);
			msglen = remain;
			*(msg - remain) = '<';
			--remain;
		} else {
			msglen = 0;
			*msg = '<';
		}
	} else
		vsnprintf(msg - msglen, msglen + 1, msgfmt, ap);
	va_end(ap);

	/* Add delimiter (or its part) if needed. */
	if (dlen) {
		if (remain > dlen)
			remain = dlen;
		memcpy(msg - remain, delim + sizeof(delim) - remain, remain);
	}

	ctx->err_str = msg - msglen;
	return status;
}
