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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "addrxlat-priv.h"

/** Maximum length of the static error message. */
#define ERRBUF	64

/**  Initialize the read cache.
 * @param cache  Read cache.
 */
static void
init_cache(struct read_cache *cache)
{
	struct read_cache_slot *slot, *end;

	slot = &cache->slot[0];
	end  = &cache->slot[READ_CACHE_SLOTS];
	cache->mru = slot;
	do {
		slot->next = slot + 1 < end ? slot + 1 : &cache->slot[0];
		slot->next->prev = slot;
	} while (++slot < end);
}

/**  Clean up the read cache.
 * @param cache  Read cache.
 *
 * Release all cached pages.
 */
static void
cleanup_cache(struct read_cache *cache)
{
	struct read_cache_slot *slot;

	slot = &cache->slot[0];
	do {
		addrxlat_buffer_t *buf = &slot->buffer;
		if (buf->size)
			buf->put_page(buf);
	} while (++slot < &cache->slot[READ_CACHE_SLOTS]);
}

/** Mark a slot as most recently used.
 * @param cache  Read cache.
 * @param slot   Cache slot.
 */
static inline void
touch_cache_slot(struct read_cache *cache, struct read_cache_slot *slot)
{
	/* If already marked, do nothing. */
	if (slot == cache->mru)
		return;

	/* Reorder the MRU chain if needed */
	if (slot->next != cache->mru) {
		slot->prev->next = slot->next;
		slot->next->prev = slot->prev;
		slot->next = cache->mru;
		slot->prev = cache->mru->prev;
		slot->prev->next = slot->next->prev = slot;
	}

	/* Move the MRU pointer. */
	cache->mru = slot;
}

/** Default put-page callback.
 * @param buf  Read buffer metadata (unused).
 */
static void
def_put_page_cb(const addrxlat_buffer_t *buf)
{
}

/** Get a cache slot for a given address.
 * @param      ctx   Address translation context.
 * @param      addr  Desired address.
 * @param[out] pbuf  Buffer (updated on success).
 * @returns          Error status.
 */
addrxlat_status
get_cache_buf(addrxlat_ctx_t *ctx, const addrxlat_fulladdr_t *addr,
	      addrxlat_buffer_t **pbuf)
{
	addrxlat_status status;
	struct read_cache_slot *slot;

	/* Try to reuse a cache slot */
	slot = &ctx->cache.slot[0];
	do {
		addrxlat_buffer_t *buf = &slot->buffer;
		if (buf->size > addr->addr - buf->addr.addr &&
		    buf->addr.as == addr->as)
			goto out;
	} while (++slot < &ctx->cache.slot[READ_CACHE_SLOTS]);

	/* Not found - use the LRU slot */
	slot = ctx->cache.mru->prev;

	/* Free up the slot if necessary */
	if (slot->buffer.size)
		slot->buffer.put_page(&slot->buffer);

	/* Get the new page */
	slot->buffer.addr = *addr;
	slot->buffer.ptr = NULL;
	slot->buffer.put_page = def_put_page_cb;
	status = ctx->cb->get_page(ctx->cb, &slot->buffer);
	if (status != ADDRXLAT_OK) {
		slot->buffer.size = 0;
		return status;
	}

 out:
	if (!slot->buffer.ptr)
		return set_error(ctx, ADDRXLAT_ERR_NODATA,
				 "Infinite read recursion");

	*pbuf = &slot->buffer;
	touch_cache_slot(&ctx->cache, slot);
	return ADDRXLAT_OK;
}

/** Mark a buffer as no longer needed.
 * @param cache  Read cache.
 * @param addr   Address inside a buffer to be buried.
 *
 * This function moves the cache slot corresponding to the given address
 * to the end of the MRU chain. It does not release the associated page,
 * but the slot will be evicted first (unless it is meanwhile reused, of
 * course).
 */
void
bury_cache_buffer(struct read_cache *cache, const addrxlat_fulladdr_t *addr)
{
	struct read_cache_slot *slot;

	/* Find the corresponding cache slot */
	slot = &cache->slot[0];
	do {
		addrxlat_buffer_t *buf = &slot->buffer;
		if (buf->size > addr->addr - buf->addr.addr &&
		    buf->addr.as == addr->as) {
			/* FOUND */

			/* If already marked, do nothing. */
			if (slot->next == cache->mru)
				break;

			/* Reorder the MRU chain if needed */
			if (slot != cache->mru) {
				slot->prev->next = slot->next;
				slot->next->prev = slot->prev;
				slot->next = cache->mru;
				slot->prev = cache->mru->prev;
				slot->prev->next = slot->next->prev = slot;
			} else
				/* Move the MRU pointer. */
				cache->mru = slot->next;
			break;
		}
	} while (++slot < &cache->slot[READ_CACHE_SLOTS]);
}

/** Missing callback handler.
 * @param cb    Default callback definition.
 * @param name  Name of the callback.
 * @returns     Error status.
 */
static addrxlat_status
no_callback(const addrxlat_cb_t *cb, const char *name)
{
	addrxlat_ctx_t *ctx = cb->priv;
	return set_error(ctx, ADDRXLAT_ERR_NODATA,
			 "No %s callback", name);
}

/** Default get-page callback.
 * @param cb    This callback definition.
 * @param buf   Read buffer metadata (unused).
 * @returns     Error status.
 */
static addrxlat_status
def_get_page_cb(const addrxlat_cb_t *cb, addrxlat_buffer_t *buf)
{
	return no_callback(cb, "get_page");
}

/** Default read capabilities callback.
 * @param cb    This callback definition.
 * @returns     Read capabilities.
 */
static unsigned long
def_read_caps_cb(const addrxlat_cb_t *cb)
{
	return 0;
}

/** Default register value callback.
 * @param cb        This callback definition.
 * @param name[in]  Register name.
 * @param val[out]  Register value.
 * @returns         Error status.
 */
static addrxlat_status
def_reg_value_cb(const addrxlat_cb_t *cb, const char *name,
		 addrxlat_addr_t *val)
{
	return no_callback(cb, "reg_value");
}

/** Default symbol value callback.
 * @param cb        This callback definition.
 * @param name[in]  Symbol name.
 * @param val[out]  Symbol value (e.g. address of a variable).
 * @returns         Error status.
 */
static addrxlat_status
def_sym_value_cb(const addrxlat_cb_t *cb, const char *name,
		 addrxlat_addr_t *val)
{
	return no_callback(cb, "sym_value");
}

/** Default symbol size callback.
 * @param cb        This callback definition.
 * @param name[in]  Name of a symbol or data type.
 * @param val[out]  Symbol size, @c sizeof(name).
 * @returns         Error status.
 */
static addrxlat_status
def_sym_sizeof_cb(const addrxlat_cb_t *cb, const char *name,
		  addrxlat_addr_t *val)
{
	return no_callback(cb, "sym_sizeof");
}

/** Default element offset callback.
 * @param cb        This callback definition.
 * @param obj[in]   Name of the container object (e.g. of a @c struct).
 * @param elem[in]  Name of the element (e.g. a structure field).
 * @param val[out]  Offset of @p elem within @p obj, @c offsetof(obj, elem).
 * @returns         Error status.
 */
static addrxlat_status
def_sym_offsetof_cb(const addrxlat_cb_t *cb, const char *obj,
		    const char *elem, addrxlat_addr_t *val)
{
	return no_callback(cb, "sym_offsetof");
}

/** Default number value callback.
 * @param cb        This callback definition.
 * @param name[in]  Name of the numeric parameter.
 * @param val[out]  Parameter value.
 * @returns         Error status.
 */
static addrxlat_status
def_num_value_cb(const addrxlat_cb_t *cb, const char *name,
		 addrxlat_addr_t *val)
{
	return no_callback(cb, "sym_offsetof");
}

addrxlat_ctx_t *
addrxlat_ctx_new(void)
{
	addrxlat_ctx_t *ctx = calloc(1, sizeof(addrxlat_ctx_t) + ERRBUF);
	if (ctx) {
		ctx->refcnt = 1;
		ctx->cb = &ctx->def_cb;
		ctx->def_cb.priv = ctx;
		ctx->def_cb.get_page = def_get_page_cb;
		ctx->def_cb.read_caps = def_read_caps_cb;
		ctx->def_cb.reg_value = def_reg_value_cb;
		ctx->def_cb.sym_value = def_sym_value_cb;
		ctx->def_cb.sym_sizeof = def_sym_sizeof_cb;
		ctx->def_cb.sym_offsetof = def_sym_offsetof_cb;
		ctx->def_cb.num_value = def_num_value_cb;
		init_cache(&ctx->cache);
		err_init(&ctx->err, ERRBUF);
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
		cleanup_cache(&ctx->cache);
		addrxlat_cb_t *p = (addrxlat_cb_t *)ctx->cb;
		while (p != &ctx->def_cb) {
			const addrxlat_cb_t *next = p->next;
			free(p);
			p = (addrxlat_cb_t *)next;
		}
		err_cleanup(&ctx->err);
		free(ctx);
	}
	return refcnt;
}

void addrxlat_ctx_clear_err(addrxlat_ctx_t *ctx)
{
	clear_error(ctx);
}

const char *
addrxlat_ctx_get_err(const addrxlat_ctx_t *ctx)
{
	return err_str(&ctx->err);
}

kdump_errmsg_t *
addrxlat_ctx_get_errmsg(addrxlat_ctx_t *ctx)
{
	return &ctx->err;
}

/** Call the next get-page callback.
 * @param cb    This callback definition.
 * @param buf   Read buffer metadata.
 * @returns     Error status.
 */
static addrxlat_status
next_get_page_cb(const addrxlat_cb_t *cb, addrxlat_buffer_t *buf)
{
	return cb->next->get_page(cb->next, buf);
}

/** Call the next read capabilities callback.
 * @param cb    This callback definition.
 * @returns     Read capabilities.
 */
static unsigned long
next_read_caps_cb(const addrxlat_cb_t *cb)
{
	return cb->next->read_caps(cb->next);
}

/** Call the next register value callback.
 * @param cb        This callback definition.
 * @param name[in]  Register name.
 * @param val[out]  Register value.
 * @returns         Error status.
 */
static addrxlat_status
next_reg_value_cb(const addrxlat_cb_t *cb, const char *name,
		  addrxlat_addr_t *val)
{
	return cb->next->reg_value(cb, name, val);
}

/** Call the next symbol value callback.
 * @param cb        This callback definition.
 * @param name[in]  Symbol name.
 * @param val[out]  Symbol value (e.g. address of a variable).
 * @returns         Error status.
 */
static addrxlat_status
next_sym_value_cb(const addrxlat_cb_t *cb, const char *name,
		  addrxlat_addr_t *val)
{
	return cb->next->sym_value(cb, name, val);
}

/** Call the next symbol size callback.
 * @param cb        This callback definition.
 * @param name[in]  Name of a symbol or data type.
 * @param val[out]  Symbol size, @c sizeof(name).
 * @returns         Error status.
 */
static addrxlat_status
next_sym_sizeof_cb(const addrxlat_cb_t *cb, const char *name,
		   addrxlat_addr_t *val)
{
	return cb->next->sym_sizeof(cb, name, val);
}

/** Call the next element offset callback.
 * @param cb        This callback definition.
 * @param obj[in]   Name of the container object (e.g. of a @c struct).
 * @param elem[in]  Name of the element (e.g. a structure field).
 * @param val[out]  Offset of @p elem within @p obj, @c offsetof(obj, elem).
 * @returns         Error status.
 */
static addrxlat_status
next_sym_offsetof_cb(const addrxlat_cb_t *cb, const char *obj,
		     const char *elem, addrxlat_addr_t *val)
{
	return cb->next->sym_offsetof(cb, obj, elem, val);
}

/** Call the next number value callback.
 * @param cb        This callback definition.
 * @param name[in]  Name of the numeric parameter.
 * @param val[out]  Parameter value.
 * @returns         Error status.
 */
static addrxlat_status
next_num_value_cb(const addrxlat_cb_t *cb, const char *name,
		  addrxlat_addr_t *val)
{
	return cb->next->num_value(cb, name, val);
}

addrxlat_cb_t *
addrxlat_ctx_add_cb(addrxlat_ctx_t *ctx)
{
	addrxlat_cb_t *cb;

	cb = malloc(sizeof *cb);
	if (!cb)
		return cb;

	cb->next = ctx->cb;
	cb->priv = NULL;
	cb->get_page = next_get_page_cb;
	cb->read_caps = next_read_caps_cb;
	cb->reg_value = next_reg_value_cb;
	cb->sym_value = next_sym_value_cb;
	cb->sym_sizeof = next_sym_sizeof_cb;
	cb->sym_offsetof = next_sym_offsetof_cb;
	cb->num_value = next_num_value_cb;

	ctx->cb = cb;

	return cb;
}

void
addrxlat_ctx_del_cb(addrxlat_ctx_t *ctx, addrxlat_cb_t *cb)
{
	const addrxlat_cb_t **pprev = &ctx->cb;
	const addrxlat_cb_t *p = ctx->cb;

	while (p && p != cb) {
		pprev = (const addrxlat_cb_t **) &p->next;
		p = p->next;
	}
	if (p) {
		*pprev = cb->next;
		free(cb);
	}
}

const addrxlat_cb_t *
addrxlat_ctx_get_cb(const addrxlat_ctx_t *ctx)
{
	return ctx->cb;
}

DEFINE_ALIAS(addrspace_name);

const char *
addrxlat_addrspace_name(addrxlat_addrspace_t as)
{
	switch (as) {
	case ADDRXLAT_KPHYSADDR:	return "KPHYSADDR";
	case ADDRXLAT_MACHPHYSADDR:	return "MACHPHYSADDR";
	case ADDRXLAT_KVADDR:		return "KVADDR";
	case ADDRXLAT_NOADDR:		return "NOADDR";
	default:			return "invalid addrspace_t";
	}
}

/** Common format string for read callback failures. */
static const char read_err_fmt[] =
	"Cannot read %d-bit %s at %s:0x%"ADDRXLAT_PRIxADDR;

struct read_param {
	addrxlat_ctx_t *ctx;
	void *val;
};

/** Read a 32-bit entity using the get-page callback. */
addrxlat_status
do_read32(addrxlat_ctx_t *ctx, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	addrxlat_status status;
	addrxlat_buffer_t *buf;
	const uint32_t *ptr;

	status = get_cache_buf(ctx, addr, &buf);
	if (status != ADDRXLAT_OK)
		return status;

	ptr = buf->ptr + (addr->addr - buf->addr.addr);
	switch (buf->byte_order) {
	case ADDRXLAT_BIG_ENDIAN:
		*val = be32toh(*ptr);
		break;
	case ADDRXLAT_LITTLE_ENDIAN:
		*val = le32toh(*ptr);
		break;
	case ADDRXLAT_HOST_ENDIAN:
		*val = *ptr;
	}
	return ADDRXLAT_OK;
}

static addrxlat_status
read32_op(void *data, const addrxlat_fulladdr_t *addr)
{
	const struct read_param *param = data;
	return do_read32(param->ctx, addr, param->val);
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
	unsigned long read_caps;
	addrxlat_status status;

	read_caps = ctx->cb->read_caps(ctx->cb);
	if (read_caps & ADDRXLAT_CAPS(addr->as)) {
		status = do_read32(ctx, addr, val);
	} else {
		addrxlat_op_ctl_t ctl;
		struct read_param param = { ctx, val };

		ctl.ctx = ctx;
		ctl.sys = step->sys;
		ctl.op = read32_op;
		ctl.data = &param;
		ctl.caps = read_caps;
		status = internal_op(&ctl, addr);
	}

	if (status != ADDRXLAT_OK)
		return set_error(ctx, status, read_err_fmt, 32, what,
				 internal_addrspace_name(addr->as), addr->addr);

	return ADDRXLAT_OK;
}

/** Read a 64-bit entity using the get-page callback. */
addrxlat_status
do_read64(addrxlat_ctx_t *ctx, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	addrxlat_status status;
	addrxlat_buffer_t *buf;
	const uint64_t *ptr;

	status = get_cache_buf(ctx, addr, &buf);
	if (status != ADDRXLAT_OK)
		return status;

	ptr = buf->ptr + (addr->addr - buf->addr.addr);
	switch (buf->byte_order) {
	case ADDRXLAT_BIG_ENDIAN:
		*val = be64toh(*ptr);
		break;
	case ADDRXLAT_LITTLE_ENDIAN:
		*val = le64toh(*ptr);
		break;
	case ADDRXLAT_HOST_ENDIAN:
		*val = *ptr;
	}
	return ADDRXLAT_OK;
}

static addrxlat_status
read64_op(void *data, const addrxlat_fulladdr_t *addr)
{
	const struct read_param *param = data;
	return do_read64(param->ctx, addr, param->val);
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
	unsigned long read_caps;
	addrxlat_status status;

	read_caps = ctx->cb->read_caps(ctx->cb);
	if (read_caps & ADDRXLAT_CAPS(addr->as)) {
		status = do_read64(ctx, addr, val);
	} else {
		addrxlat_op_ctl_t ctl;
		struct read_param param = { ctx, val };

		ctl.ctx = ctx;
		ctl.sys = step->sys;
		ctl.op = read64_op;
		ctl.data = &param;
		ctl.caps = read_caps;
		status = internal_op(&ctl, addr);
	}

	if (status != ADDRXLAT_OK)
		return set_error(ctx, status, read_err_fmt, 64, what,
				 internal_addrspace_name(addr->as), addr->addr);

	return ADDRXLAT_OK;
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
	addrxlat_status status =
		ctx->cb->reg_value(ctx->cb, name, val);
	return status != ADDRXLAT_OK
		? set_error(ctx, status,
			    "Cannot read register \"%s\"", name)
		: status;
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
	addrxlat_status status =
		ctx->cb->sym_value(ctx->cb, name, val);
	return status != ADDRXLAT_OK
		? set_error(ctx, status,
			    "Cannot resolve \"%s\"", name)
		: status;
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
	addrxlat_status status =
		ctx->cb->sym_sizeof(ctx->cb, name, sz);
	return status != ADDRXLAT_OK
		? set_error(ctx, status, "Cannot get sizeof(%s)", name)
		: status;
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
	addrxlat_status status =
		ctx->cb->sym_offsetof(ctx->cb, type, memb, off);
	return status != ADDRXLAT_OK
		? set_error(ctx, status, "Cannot get offsetof(%s, %s)",
			    type, memb)
		: status;
}

/** Resolve a number value.
 * @param      ctx   Address translation context.
 * @param      name  Number name.
 * @param[out] num   Number value returned on success.
 * @returns	     Error status.
 *
 * The size is determined using a user-supplied callback.
 */
addrxlat_status
get_number(addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *num)
{
	addrxlat_status status =
		ctx->cb->num_value(ctx->cb, name, num);
	return status != ADDRXLAT_OK
		? set_error(ctx, status, "Cannot get number(%s)", name)
		: status;
}

DEFINE_ALIAS(ctx_err);

addrxlat_status
addrxlat_ctx_err(addrxlat_ctx_t *ctx, addrxlat_status status,
		 const char *msgfmt, ...)
{
	if (status != ADDRXLAT_OK) {
		va_list ap;

		va_start(ap, msgfmt);
		err_vadd(&ctx->err, msgfmt, ap);
		va_end(ap);
	}

	return status;
}

const char *
addrxlat_strerror(addrxlat_status status)
{
	switch (status) {
	case ADDRXLAT_OK:		return "Success";
	case ADDRXLAT_ERR_NOTIMPL:	return "Unimplemented feature";
	case ADDRXLAT_ERR_NOTPRESENT:	return "Page not present";
	case ADDRXLAT_ERR_INVALID:	return "Invalid address";
	case ADDRXLAT_ERR_NOMEM:	return "Memory allocation failure";
	case ADDRXLAT_ERR_NODATA:	return "Data not available";
	case ADDRXLAT_ERR_NOMETH:	return "No translation method";
	default:			return "Unknown error";
	}
}
