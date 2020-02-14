/** @internal @file src/kdumpfile/vtop.c
 * @brief Virtual-to-physical address translation.
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
#include <stdio.h>

#define RGN_ALLOC_INC 32

static void
set_pteval_size(kdump_ctx_t *ctx)
{
	const addrxlat_meth_t *meth;

	meth = addrxlat_sys_get_meth(ctx->xlat->xlatsys,
				     ADDRXLAT_SYS_METH_PGT);
	if (meth->kind == ADDRXLAT_PGT) {
		int shift = addrxlat_pteval_shift(
			meth->param.pgt.pf.pte_format);
		if (shift >= 0) {
			struct attr_data *attr = gattr(ctx, GKI_pteval_size);
			set_attr_number(ctx, attr, ATTR_DEFAULT, 1UL << shift);
		}
	}
}

static kdump_status
get_version_code(kdump_ctx_t *ctx, unsigned long *pver)
{
	static const char attrname[] = "version_code";
	struct attr_data *attr;
	const char *ostype;
	kdump_status status;

	/* Default to unknown version */
	*pver = 0UL;

	/* Get OS type name */
	attr = gattr(ctx, GKI_ostype);
	if (!attr_isset(attr))
		return KDUMP_OK;
	status = attr_revalidate(ctx, attr);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot get OS type");
	ostype = attr_value(attr)->string;

	/* Get OS directory attribute */
	attr = lookup_attr(ctx->dict, ostype);
	if (!attr || attr->template->type != KDUMP_DIRECTORY)
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unknown operating system type: %s", ostype);
	if (!attr_isset(attr))
		return KDUMP_OK;
	status = attr_revalidate(ctx, attr);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot get %s.%s",
				 ostype, attrname);

	/* Get version_code in the OS directory. */
	attr = lookup_dir_attr(
		ctx->dict, attr, attrname, sizeof(attrname) - 1);
	if (!attr || !attr_isset(attr))
		return KDUMP_OK;
	status = attr_revalidate(ctx, attr);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot get %s.%s",
				 ostype, attrname);

	if (attr->template->type != KDUMP_NUMBER)
		status = set_error(ctx, KDUMP_ERR_INVALID,
				   "Attribute %s.%s is not a number",
				   ostype, attrname);

	 *pver = attr_value(attr)->number;
	 return KDUMP_OK;
}

#define MAX_OPTS	8
struct opts {
	unsigned n;
	char *str[MAX_OPTS];
};

static char *
join_opts(const struct opts *opts)
{
	size_t len;
	unsigned i;
	char *ret, *p;

	for (len = 0, i = 0; i < opts->n; ++i)
		len += strlen(opts->str[i]) + 1;
	ret = malloc(len);
	if (!ret)
		return ret;
	for (p = ret, i = 0; i < opts->n; ++i) {
		p = stpcpy(p, opts->str[i]);
		*p++ = ' ';
	}
	p[-1] = '\0';
	return ret;
}

static void
free_opts(struct opts *opts)
{
	while (opts->n)
		free(opts->str[--opts->n]);
}

static kdump_status
add_attr_opt(kdump_ctx_t *ctx, struct opts *opts, enum global_keyidx key)
{
	struct attr_data *attr;
	char *opt;
	kdump_status status;

	attr = gattr(ctx, key);
	if (!attr_isset(attr))
		return KDUMP_OK;
	status = attr_revalidate(ctx, attr);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot get the value of addrxlat %s option",
				 attr->template->key);

	opt = strdup(attr_value(attr)->string);
	if (!opt)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate addrxlat %s option",
				 attr->template->key);

	opts->str[opts->n++] = opt;
	return KDUMP_OK;
}
static kdump_status
set_x86_pae_opt(kdump_ctx_t *ctx, struct opts *opts)
{
	static const char config_pae[] = "CONFIG_X86_PAE";
	struct attr_data *attr;
	const char *pae_state;
	int len;

	pae_state = NULL;
	attr = gattr(ctx, GKI_linux_vmcoreinfo_lines);
	if (attr_isset(attr))
		pae_state = "no";
	attr = lookup_dir_attr(ctx->dict, attr,
			       config_pae, sizeof(config_pae) - 1);
	if (attr && attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot get %s from vmcoreinfo",
					 config_pae);
		if (!strcmp(attr_value(attr)->string, "y"))
			pae_state = "yes";
	}
	if (pae_state) {
		len = asprintf(&opts->str[opts->n], "pae=%s", pae_state);
		if (len < 0)
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot make %s option", "pae");
		++opts->n;
	}

	return KDUMP_OK;
}

static kdump_status
set_linux_opts(kdump_ctx_t *ctx, struct opts *opts)
{
	struct attr_data *attr;
	int len;

	if (ctx->shared->arch == ARCH_IA32) {
		kdump_status status = set_x86_pae_opt(ctx, opts);
		if (status != KDUMP_OK)
			return status;
	}

	if (isset_phys_base(ctx)) {
		len = asprintf(&opts->str[opts->n],
			       "phys_base=0x%"ADDRXLAT_PRIxADDR,
			       get_phys_base(ctx));
		if (len < 0)
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot make %s option", "phys_base");
		++opts->n;
	}

	if ((isset_xen_xlat(ctx) && get_xen_xlat(ctx) != KDUMP_XEN_AUTO) ||
	    (isset_xen_type(ctx) && get_xen_type(ctx) == KDUMP_XEN_SYSTEM)) {
		if (! (opts->str[opts->n] = strdup("xen_xlat=1")) )
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot make %s option", "xen_xlat");
		++opts->n;
	}

	attr = gattr(ctx, GKI_xen_p2m_mfn);
	if (attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot get %s from vmcoreinfo",
					 "p2m_mfn");
		len = asprintf(&opts->str[opts->n],
			"xen_p2m_mfn=0x%"ADDRXLAT_PRIxADDR,
			attr_value(attr)->number);
		if (len < 0)
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot make %s option",
					 "xen_p2m_mfn");
		++opts->n;
	}

	return KDUMP_OK;
}

static kdump_status
set_xen_opts(kdump_ctx_t *ctx, struct opts *opts)
{
	struct attr_data *attr;
	int len;

	attr = gattr(ctx, GKI_xen_phys_start);
	if (attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status, "Cannot get %s.%s",
					 "xen", "phys_start");
		len = asprintf(&opts->str[opts->n],
			       "phys_base=0x%"ADDRXLAT_PRIxADDR,
			       attr_value(attr)->address);
		if (len < 0)
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot make %s option", "phys_base");
		++opts->n;
	}

	return KDUMP_OK;
}

kdump_status
vtop_init(kdump_ctx_t *ctx)
{
	kdump_status status;
	addrxlat_osdesc_t osdesc;
	addrxlat_status axres;
	struct opts opts;

	if (!isset_arch_name(ctx))
		return KDUMP_OK;

	osdesc.type = ctx->xlat->ostype;
	osdesc.arch = get_arch_name(ctx);

	status = get_version_code(ctx, &osdesc.ver);
	if (status != KDUMP_OK)
		return status;
	clear_error(ctx);

	opts.n = 0;
	status = add_attr_opt(ctx, &opts, GKI_xlat_opts_pre);
	if (status == KDUMP_OK) {
		if (ctx->xlat->ostype == ADDRXLAT_OS_LINUX)
			status = set_linux_opts(ctx, &opts);
		else if (ctx->xlat->ostype == ADDRXLAT_OS_XEN)
			status = set_xen_opts(ctx, &opts);
	}
	if (status == KDUMP_OK)
		status = add_attr_opt(ctx, &opts, GKI_xlat_opts_post);
	if (status != KDUMP_OK) {
		free_opts(&opts);
		return status;
	}
	if (opts.n) {
		osdesc.opts = join_opts(&opts);
		free_opts(&opts);
		if (!osdesc.opts)
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot allocate addrxlat options");
	} else
		osdesc.opts = NULL;

	ctx->xlat->dirty = false;

	rwlock_unlock(&ctx->shared->lock);

	axres = addrxlat_sys_os_init(ctx->xlat->xlatsys,
				     ctx->xlatctx, &osdesc);
	if (osdesc.opts)
		free((void*)osdesc.opts);

	rwlock_rdlock(&ctx->shared->lock);
	if (axres != ADDRXLAT_OK)
		return addrxlat2kdump(ctx, axres);

	if (!attr_isset(gattr(ctx, GKI_pteval_size)))
		set_pteval_size(ctx);

	if (ctx->shared->arch_ops->post_addrxlat &&
	    (status = ctx->shared->arch_ops->post_addrxlat(ctx)) != KDUMP_OK)
		return set_error(ctx, status,
				 "Arch late init failed");

	if (ctx->shared->ops->post_addrxlat &&
	    (status = ctx->shared->ops->post_addrxlat(ctx)) != KDUMP_OK)
		return set_error(ctx, status,
				 "Format late init failed");

	return KDUMP_OK;
}

static kdump_status
dirty_xlat_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	ctx->xlat->dirty = true;
	return KDUMP_OK;
}

const struct attr_ops dirty_xlat_ops = {
	.post_set = dirty_xlat_hook,
	.pre_clear = (attr_pre_clear_fn*)dirty_xlat_hook,
};

static kdump_status
linux_dirty_xlat_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	if (ctx->xlat->ostype == ADDRXLAT_OS_LINUX)
		ctx->xlat->dirty = true;
	return KDUMP_OK;
}

const struct attr_ops linux_dirty_xlat_ops = {
	.post_set = linux_dirty_xlat_hook,
	.pre_clear = (attr_pre_clear_fn*)linux_dirty_xlat_hook,
};

static kdump_status
xen_dirty_xlat_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	if (ctx->xlat->ostype == ADDRXLAT_OS_XEN)
		ctx->xlat->dirty = true;
	return KDUMP_OK;
}

const struct attr_ops xen_dirty_xlat_ops = {
	.post_set = xen_dirty_xlat_hook,
	.pre_clear = (attr_pre_clear_fn*)xen_dirty_xlat_hook,
};

/**  Addrxlat get_page callback.
 * @param data  Dump file object.
 * @param buf   Page buffer metadata.
 * @returns     Error status.
 */
static addrxlat_status
addrxlat_get_page(void *data, addrxlat_buffer_t *buf)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) data;
	struct page_io *pio;
	kdump_status status;

	pio = malloc(sizeof *pio);
	if (!pio)
		return addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NOMEM,
					"Cannot allocate pio structure");

	/* init all fields here except ptr */
	buf->addr.addr = page_align(ctx, buf->addr.addr);
	buf->size = get_page_size(ctx);
	buf->byte_order = get_byte_order(ctx);
	buf->priv = pio;

	pio->addr.addr = buf->addr.addr;
	pio->addr.as = buf->addr.as;
	status = get_page(ctx, pio);
	if (status != KDUMP_OK)
		return kdump2addrxlat(ctx, status);

	buf->ptr = pio->chunk.data;
	return ADDRXLAT_OK;
}

/**  Addrxlat put_page callback.
 * @param data  Dump file object.
 * @param buf   Page buffer metadata.
 * @returns     Error status.
 */
static void
addrxlat_put_page(void *data, const addrxlat_buffer_t *buf)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) data;
	struct page_io *pio = buf->priv;
	put_page(ctx, pio);
	free(pio);
}

static addrxlat_status
addrxlat_sym(void *data, addrxlat_sym_t *sym)
{
	static const struct ostype_attr_map value_map[] = {
		{ ADDRXLAT_OS_LINUX, GKI_linux_symbol },
		{ ADDRXLAT_OS_XEN, GKI_xen_symbol },
		{ ADDRXLAT_OS_UNKNOWN }
	};
	static const struct ostype_attr_map sizeof_map[] = {
		{ ADDRXLAT_OS_LINUX, GKI_linux_size },
		{ ADDRXLAT_OS_XEN, GKI_xen_size },
		{ ADDRXLAT_OS_UNKNOWN }
	};
	static const struct ostype_attr_map offsetof_map[] = {
		{ ADDRXLAT_OS_LINUX, GKI_linux_offset },
		{ ADDRXLAT_OS_XEN, GKI_xen_offset },
		{ ADDRXLAT_OS_UNKNOWN }
	};

	kdump_ctx_t *ctx = (kdump_ctx_t*) data;
	const struct attr_data *base;
	struct attr_data *attr;
	addrxlat_status ret;

	switch (sym->type) {
	case ADDRXLAT_SYM_VALUE:
		base = ostype_attr(ctx, value_map);
		if (!base)
			return addrxlat_ctx_err(
				ctx->xlatctx, ADDRXLAT_ERR_NOTIMPL,
				"Unsupported OS");
		break;

	case ADDRXLAT_SYM_SIZEOF:
		base = ostype_attr(ctx, sizeof_map);
		if (!base)
			return addrxlat_ctx_err(
				ctx->xlatctx, ADDRXLAT_ERR_NOTIMPL,
				"Unsupported OS");
		break;

	case ADDRXLAT_SYM_OFFSETOF:
		base = ostype_attr(ctx, offsetof_map);
		if (!base)
			return addrxlat_ctx_err(
				ctx->xlatctx, ADDRXLAT_ERR_NOTIMPL,
				"Unsupported OS");
		break;

	case ADDRXLAT_SYM_REG:
		rwlock_rdlock(&ctx->shared->lock);
		base = lookup_attr(ctx->dict, "cpu.0.reg");
		rwlock_unlock(&ctx->shared->lock);
		if (!base)
			return addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
						"No registers");
		break;

	default:
		return addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NOTIMPL,
					"Unhandled symbolic type");
	}

	rwlock_rdlock(&ctx->shared->lock);

	attr = lookup_dir_attr(ctx->dict, base,
			       sym->args[0], strlen(sym->args[0]));
	if (!attr) {
		ret = addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
				       "Symbol not found");
		goto out;
	}
	if (!attr_isset(attr)) {
		ret = addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
				       "Symbol has no value");
		goto out;
	}
	if (attr_revalidate(ctx, attr) != KDUMP_OK) {
		ret = addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
				       "Symbol value cannot be revalidated");
		goto out;
	}

	if (sym->type == ADDRXLAT_SYM_OFFSETOF) {
		attr = lookup_dir_attr(ctx->dict, attr,
				       sym->args[1], strlen(sym->args[1]));
		if (!attr) {
			ret = addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
					       "Field not found");
			goto out;
		}
		if (!attr_isset(attr)) {
			ret = addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
					       "Field has no value");
			goto out;
		}
		if (attr_revalidate(ctx, attr) != KDUMP_OK) {
			ret = addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
					       "Field cannot be revalidated");
			goto out;
		}
	}

	ret = ADDRXLAT_OK;
	switch (attr->template->type) {
	case KDUMP_NUMBER:
		sym->val = attr_value(attr)->number;
		break;

	case KDUMP_ADDRESS:
		sym->val = attr_value(attr)->address;
		break;

	default:
		ret = addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NOTIMPL,
				       "Unhandled attribute type");
	}

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

addrxlat_ctx_t *
init_addrxlat(kdump_ctx_t *ctx)
{
	addrxlat_ctx_t *addrxlat;
	addrxlat_cb_t cb = {
		.data = ctx,
		.get_page = addrxlat_get_page,
		.put_page = addrxlat_put_page,
		.read_caps = (ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR) |
			      ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR) |
			      ADDRXLAT_CAPS(ADDRXLAT_KVADDR)),
		.sym = addrxlat_sym
	};

	addrxlat = addrxlat_ctx_new();
	if (!addrxlat)
		return addrxlat;

	addrxlat_ctx_set_cb(addrxlat, &cb);

	return addrxlat;
}

/**  Allocate a new translation definition.
 * @returns       Address translation, or @c NULL on allocation failure.
 */
struct kdump_xlat *
xlat_new(void)
{
	struct kdump_xlat *xlat;

	xlat = calloc(1, sizeof(struct kdump_xlat));
	if (!xlat)
		return NULL;
	xlat->refcnt = 1;
	list_init(&xlat->ctx);

	xlat->xlatsys = addrxlat_sys_new();
	if (!xlat->xlatsys)
		goto err;

	return xlat;

err:
	free(xlat);
	return NULL;
}

/**  Clone a translation definition.
 * @param xlat  Original address translation.
 * @returns     Cloned address translation, or @c NULL on allocation failure.
 */
struct kdump_xlat *
xlat_clone(const struct kdump_xlat *orig)
{
	struct kdump_xlat *xlat;

	xlat = xlat_new();
	if (xlat)
		set_addrspace_caps(xlat, orig->xlat_caps);
	xlat->dirty = true;
	return xlat;
}

/**  Free a translation definition.
 * @param xlat  Address translation.
 */
void
xlat_free(struct kdump_xlat *xlat)
{
	addrxlat_sys_decref(xlat->xlatsys);
	free(xlat);
}
