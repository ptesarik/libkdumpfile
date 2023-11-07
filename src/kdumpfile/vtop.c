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

#define DEFOPT(k, t) {			\
		.key = (#k),		\
		.type = (t),		\
		.ops = &dirty_xlat_ops,	\
		.optidx = ADDRXLAT_OPT_ ## k,	\
	}

static const struct attr_template options[] = {
	DEFOPT(arch, KDUMP_STRING),
	DEFOPT(os_type, KDUMP_STRING),
	DEFOPT(version_code, KDUMP_NUMBER),
	DEFOPT(phys_bits, KDUMP_NUMBER),
	DEFOPT(virt_bits, KDUMP_NUMBER),
	DEFOPT(page_shift, KDUMP_NUMBER),
	DEFOPT(phys_base, KDUMP_ADDRESS),
	DEFOPT(rootpgt, KDUMP_DIRECTORY),
	DEFOPT(xen_p2m_mfn, KDUMP_NUMBER),
	DEFOPT(xen_xlat, KDUMP_NUMBER),
};

static const struct attr_template fulladdr_as = {
	.key = "as",
	.type = KDUMP_NUMBER,
	/* .ops = &dirty_xlat_ops, */
};

static const struct attr_template fulladdr_addr = {
	.key = "addr",
	.type = KDUMP_ADDRESS,
	/* .ops = &dirty_xlat_ops, */
};

/** Create addrxlat attributes under a given directory.
 * @param dict    Target attribute dictionary.
 * @param dirkey  Global directory key index.
 * @returns       New directory attribute, or @c NULL on allocation error.
 */
static struct attr_data *
create_addrxlat_dir(struct attr_dict *dict, enum global_keyidx dirkey)
{
	const struct attr_template *tmpl;
	struct attr_data *dir, *attr;

	dir = dgattr(dict, dirkey);
	dir->flags.isset = 1;

	for (tmpl = options; tmpl < &options[ARRAY_SIZE(options)]; ++tmpl) {
		attr = new_attr(dict, dir, tmpl);
		if (!attr)
			return NULL;
		if (tmpl->type == KDUMP_DIRECTORY &&
		    (!new_attr(dict, attr, &fulladdr_as) ||
		     !new_attr(dict, attr, &fulladdr_addr)))
			return NULL;
	}

	return dir;
}

/** Create and populate addrxlat attribute directories.
 * @param dict  Target attribute dictionary.
 * @returns     Error status.
 *
 * Create the standard addrxlat.default and addrxlat.force attribute
 * directories.
 */
kdump_status
create_addrxlat_attrs(struct attr_dict *dict)
{
	static const enum global_keyidx dirkeys[] = {
		GKI_dir_xlat_default,
		GKI_dir_xlat_force,
	};

	unsigned i;

	for (i = 0; i < ARRAY_SIZE(dirkeys); ++i)
		if (!create_addrxlat_dir(dict, dirkeys[i]))
			return KDUMP_ERR_SYSTEM;

	return KDUMP_OK;
}

/** Add one addrxlat option.
 * @param ctx   Dump file object.
 * @param opts  Options.
 * @param dir   Attribute directory (addrxlat.default or addrxlat.force).
 * @param tmpl  Template of the wanted child attribute.
 * @returns     Error status.
 *
 * Take one option attribute and add the corresponding option to @p opts.
 * If the attribute is not set, return @c KDUMP_OK and do nothing.
 */
static kdump_status
add_addrxlat_opt(kdump_ctx_t *ctx, addrxlat_opt_t *opts,
		 const struct attr_data *dir,
		 const struct attr_template *tmpl)
{
	struct attr_data *attr, *sub;
	addrxlat_opt_t *opt;
	kdump_status status;

	attr = lookup_attr_child(dir, tmpl);
	if (!attr || !attr_isset(attr))
		return KDUMP_OK;
	status = attr_revalidate(ctx, attr);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot get %s addrxlat option",
				 tmpl->key);

	opt = &opts[tmpl->optidx];
	switch (tmpl->type) {
	case KDUMP_NUMBER:
		opt->val.num = attr_value(attr)->number;
		break;

	case KDUMP_ADDRESS:
		opt->val.addr = attr_value(attr)->address;
		break;

	case KDUMP_STRING:
		opt->val.str = attr_value(attr)->string;
		break;

	case KDUMP_DIRECTORY:
		sub = lookup_attr_child(attr, &fulladdr_as);
		if (!sub || !attr_isset(sub))
			return KDUMP_OK;
		status = attr_revalidate(ctx, sub);
		if (status != KDUMP_OK)
			return set_error(ctx, status, "Cannot get %s %s",
					 tmpl->key, "address space");
		opt->val.fulladdr.as = attr_value(sub)->number;

		sub = lookup_attr_child(attr, &fulladdr_addr);
		if (!sub || !attr_isset(sub))
			return KDUMP_OK;
		status = attr_revalidate(ctx, sub);
		if (status != KDUMP_OK)
			return set_error(ctx, status, "Cannot get %s %s",
					 tmpl->key, "address");
		opt->val.fulladdr.addr = attr_value(sub)->address;
		break;

	default:
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unimplemented addrxlat option type: %u",
				 (unsigned) tmpl->type);
	}
	opt->idx = tmpl->optidx;

	return KDUMP_OK;
}

/** Add all addrxlat options under a given directory.
 * @param ctx     Dump file object.
 * @param opts    Options.
 * @param dirkey  Global directory key index
 *                (addrxlat.default, or addrxlat.force).
 * @returns       Error status.
 */
static kdump_status
add_addrxlat_opts(kdump_ctx_t *ctx, addrxlat_opt_t *opts,
		  enum global_keyidx dirkey)
{
	const struct attr_template *tmpl;
	struct attr_data *dir;
	kdump_status status;

	dir = gattr(ctx, dirkey);
	if (!attr_isset(dir))
		return KDUMP_OK;

	for (tmpl = options; tmpl < &options[ARRAY_SIZE(options)]; ++tmpl) {
		status = add_addrxlat_opt(ctx, opts, dir, tmpl);
		if (status != KDUMP_OK)
			return status;
	}

	return KDUMP_OK;
}

/** Add an ADDRXLAT_OPT_arch option if set.
 * @param ctx   Dump file object.
 * @param opts  Options.
 * @returns     Error status.
 *
 * If the architecture is unknown, nothing is added, and this function
 * returns success.
 */
static kdump_status
set_arch_opt(kdump_ctx_t *ctx, addrxlat_opt_t *opts)
{
	if (isset_arch_name(ctx))
		addrxlat_opt_arch(&opts[ADDRXLAT_OPT_arch],
				  get_arch_name(ctx));
	return KDUMP_OK;
}

/** Add an ADDRXLAT_OPT_os_type option.
 * @param ctx   Dump file object.
 * @param opts  Options.
 * @returns     Error status.
 *
 * If the OS type is unknown, nothing is added, and this function
 * returns success.
 */
static kdump_status
set_os_type_opt(kdump_ctx_t *ctx, addrxlat_opt_t *opts)
{
	struct attr_data *attr;
	kdump_status status;

	attr = gattr(ctx, GKI_ostype);
	if (!attr_isset(attr))
		return KDUMP_OK;
	status = attr_revalidate(ctx, attr);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot get OS type");

	addrxlat_opt_os_type(&opts[ADDRXLAT_OPT_os_type],
			     attr_value(attr)->string);
	return KDUMP_OK;
}

/** Add an ADDRXLAT_OPT_version_code option.
 * @param ctx   Dump file object.
 * @param opts  Options.
 * @returns     Error status.
 *
 * If the version is unknown, nothing is added, and this function
 * returns success.
 */
static kdump_status
set_version_code(kdump_ctx_t *ctx, addrxlat_opt_t *opts)
{
	struct attr_data *attr;
	kdump_status status;

	status = ostype_attr(ctx, "version_code", &attr);
	if (status == KDUMP_ERR_NODATA) {
		clear_error(ctx);
		return KDUMP_OK;
	} else if (status != KDUMP_OK)
		return status;

	if (attr->template->type != KDUMP_NUMBER)
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "Version code is not a number");

	addrxlat_opt_version_code(&opts[ADDRXLAT_OPT_version_code],
				  attr_value(attr)->number);
	return KDUMP_OK;
}

/** Add an ADDRXLAT_OPT_page_shift option.
 * @param ctx   Dump file object.
 * @param opts  Options.
 * @returns     Error status.
 *
 * If page size is unknown, nothing is added and this function
 * returns success.
 */
static kdump_status
set_page_shift_opt(kdump_ctx_t *ctx, addrxlat_opt_t *opts)
{
	if (isset_page_shift(ctx))
		addrxlat_opt_page_shift(&opts[ADDRXLAT_OPT_page_shift],
					get_page_shift(ctx));
	return KDUMP_OK;
}

/**  Determine number of physical address bits for x86 Linux OS.
 * @param ctx     Dump file object.
 * @param bits    Set to number of physical address bits on success.
 * @returns       Error status.
 *
 * If PAE status is unknown, @p bits is unchanged, and this function
 * returns success.
 */
static kdump_status
get_linux_x86_phys_bits(kdump_ctx_t *ctx, int *bits)
{
	static const char config_pae[] = "CONFIG_X86_PAE";
	struct attr_data *attr;

	attr = gattr(ctx, GKI_linux_vmcoreinfo_lines);
	if (attr_isset(attr))
		*bits = 32;
	attr = lookup_dir_attr(ctx->dict, attr,
			       config_pae, sizeof(config_pae) - 1);
	if (attr && attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot get %s from vmcoreinfo",
					 config_pae);
		if (!strcmp(attr_value(attr)->string, "y"))
			*bits = 52;
	}
	return KDUMP_OK;
}

/** Add an ADDRXLAT_OPT_phys_bits option.
 * @param ctx   Dump file object.
 * @param opts  Options.
 * @returns     Error status.
 *
 * If the number of physical address bits cannot be determined,
 * nothing is added and this function returns success.
 */
static kdump_status
set_linux_phys_bits_opt(kdump_ctx_t *ctx, addrxlat_opt_t *opts)
{
	int bits;
	kdump_status status;

	switch (ctx->shared->arch) {
	case ARCH_IA32:
		status = get_linux_x86_phys_bits(ctx, &bits);
		break;

	default:
		return KDUMP_OK;
	}
	if (status != KDUMP_OK)
		return status;

	if (bits != 0)
		addrxlat_opt_phys_bits(&opts[ADDRXLAT_OPT_phys_bits], bits);

	return KDUMP_OK;
}

static kdump_status
set_linux_opts(kdump_ctx_t *ctx, addrxlat_opt_t *opts)
{
	struct attr_data *attr;
	kdump_status status;

	status = set_linux_phys_bits_opt(ctx, opts);
	if (status != KDUMP_OK)
		return status;

	if (isset_phys_base(ctx))
		addrxlat_opt_phys_base(&opts[ADDRXLAT_OPT_phys_base],
				       get_phys_base(ctx));

	if ((isset_xen_xlat(ctx) && get_xen_xlat(ctx) != KDUMP_XEN_AUTO) ||
	    (isset_xen_type(ctx) && get_xen_type(ctx) == KDUMP_XEN_SYSTEM))
		addrxlat_opt_xen_xlat(&opts[ADDRXLAT_OPT_xen_xlat], 1);

	attr = gattr(ctx, GKI_xen_p2m_mfn);
	if (attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot get %s from vmcoreinfo",
					 "p2m_mfn");
		addrxlat_opt_xen_p2m_mfn(&opts[ADDRXLAT_OPT_xen_p2m_mfn],
					 attr_value(attr)->number);
	}

	return KDUMP_OK;
}

static kdump_status
set_xen_opts(kdump_ctx_t *ctx, addrxlat_opt_t *opts)
{
	struct attr_data *attr;

	attr = gattr(ctx, GKI_xen_phys_start);
	if (attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status, "Cannot get %s.%s",
					 "xen", "phys_start");
		addrxlat_opt_phys_base(&opts[ADDRXLAT_OPT_phys_base],
				       attr_value(attr)->address);
	}

	return KDUMP_OK;
}

kdump_status
vtop_init(kdump_ctx_t *ctx)
{
	kdump_status status;
	addrxlat_status axres;
	addrxlat_opt_t opts[ADDRXLAT_OPT_NUM];
	unsigned i;

	if (!isset_arch_name(ctx))
		return KDUMP_OK;

	for (i = 0; i < ARRAY_SIZE(opts); ++i)
		opts[i].idx = ADDRXLAT_OPT_NULL;

	status = add_addrxlat_opts(ctx, opts, GKI_dir_xlat_default);
	if (status == KDUMP_OK)
		status = set_arch_opt(ctx, opts);
	if (status == KDUMP_OK)
		status = set_os_type_opt(ctx, opts);
	if (status == KDUMP_OK)
		status = set_version_code(ctx, opts);
	if (status == KDUMP_OK)
		status = set_page_shift_opt(ctx, opts);
	if (status == KDUMP_OK) {
		if (ctx->xlat->osdir == GKI_dir_linux)
			status = set_linux_opts(ctx, opts);
		else if (ctx->xlat->osdir == GKI_dir_xen)
			status = set_xen_opts(ctx, opts);
	}
	if (status == KDUMP_OK)
		status = add_addrxlat_opts(ctx, opts, GKI_dir_xlat_force);
	if (status != KDUMP_OK)
		return status;

	ctx->xlat->dirty = false;

	rwlock_unlock(&ctx->shared->lock);

	axres = addrxlat_sys_os_init(ctx->xlat->xlatsys, ctx->xlatctx,
				     ARRAY_SIZE(opts), opts);

	rwlock_rdlock(&ctx->shared->lock);
	if (axres != ADDRXLAT_OK)
		return addrxlat2kdump(ctx, axres);

	if (!attr_isset(gattr(ctx, GKI_pteval_size)))
		set_pteval_size(ctx);

	if (ctx->shared->arch_ops &&
	    ctx->shared->arch_ops->post_addrxlat &&
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
	if (ctx->xlat->osdir == GKI_dir_linux)
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
	if (ctx->xlat->osdir == GKI_dir_xen)
		ctx->xlat->dirty = true;
	return KDUMP_OK;
}

const struct attr_ops xen_dirty_xlat_ops = {
	.post_set = xen_dirty_xlat_hook,
	.pre_clear = (attr_pre_clear_fn*)xen_dirty_xlat_hook,
};

/**  Addrxlat put_page callback.
 * @param buf   Page buffer metadata.
 * @returns     Error status.
 */
static void
addrxlat_put_page(const addrxlat_buffer_t *buf)
{
	struct page_io *pio = buf->priv;
	put_page(pio);
	free(pio);
}

/**  Addrxlat read_caps callback.
 * @param cb    This callback definition.
 * @returns     Address spaces supported by @ref addrxlat_get_page.
 */
static unsigned long
addrxlat_read_caps(const addrxlat_cb_t *cb)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	return ctx->xlat->xlat_caps;
}

/**  Addrxlat get_page callback.
 * @param cb    This callback definition.
 * @param buf   Page buffer metadata.
 * @returns     Error status.
 */
static addrxlat_status
addrxlat_get_page(const addrxlat_cb_t *cb, addrxlat_buffer_t *buf)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
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
	buf->put_page = addrxlat_put_page;
	buf->priv = pio;

	pio->ctx = ctx;
	pio->addr.addr = buf->addr.addr;
	pio->addr.as = buf->addr.as;
	status = get_page(pio);
	if (status != KDUMP_OK)
		return kdump2addrxlat(ctx, status);

	buf->ptr = pio->chunk.data;
	return ADDRXLAT_OK;
}

/** Get a sub-attribute, using the addrxlat context for error reporting.
 * @param ctx   Dump file object.
 * @param base  Base attribute.
 * @param name  Name of the sub-attribute under @p base.
 * @param what  Human-readable description of the object
 *              (used in error messages).
 * @returns     Attribute data, or @c NULL on error.
 */
static struct attr_data *
sub_attr_xlat(kdump_ctx_t *ctx, struct attr_data *base, const char *name,
		  const char *what)
{
	struct attr_data *attr;

	attr = lookup_dir_attr(ctx->dict, base, name, strlen(name));
	if (!attr) {
		addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
				 "%s attribute not found", what);
		return NULL;
	}
	if (!attr_isset(attr)) {
		addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
				 "%s attribute is unset", what);
		return NULL;
	}
	if (attr_revalidate(ctx, attr) != KDUMP_OK) {
		addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
				 "%s attribute cannot be revalidated", what);
		return NULL;
	}
	return attr;
}

/** Get register value from attributes (with locks held). */
static addrxlat_status
reg_value_locked(const addrxlat_cb_t *cb, const char *name,
		 addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	struct attr_data *attr;

	attr = lookup_attr(ctx->dict, "cpu.0.reg");
	if (!attr)
		return addrxlat_ctx_err(ctx->xlatctx, ADDRXLAT_ERR_NODATA,
					"No registers");

	attr = sub_attr_xlat(ctx, attr, name, "Register");
	if (!attr)
		return ADDRXLAT_ERR_NODATA;

	*val = attr_value(attr)->number;
	return ADDRXLAT_OK;
}

/** Register value callback. */
static addrxlat_status
reg_value(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	addrxlat_status ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = reg_value_locked(cb, name, val);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/** Get symbol value from attributes (with locks held). */
static addrxlat_status
sym_value_locked(const addrxlat_cb_t *cb, const char *name,
		 addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	struct attr_data *attr;
	kdump_status status;

	status = ostype_attr(ctx, "vmcoreinfo.SYMBOL", &attr);
	if (status != KDUMP_OK)
		return kdump2addrxlat(ctx, status);

	attr = sub_attr_xlat(ctx, attr, name, "Symbol value");
	if (!attr)
		return ADDRXLAT_ERR_NODATA;

	*val = attr_value(attr)->address;
	return ADDRXLAT_OK;
}

/** Symbol value callback. */
static addrxlat_status
sym_value(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	addrxlat_status ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = sym_value_locked(cb, name, val);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/** Get symbol size from attributes (with locks held). */
static addrxlat_status
sym_sizeof_locked(const addrxlat_cb_t *cb, const char *name,
		  addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	struct attr_data *attr;
	kdump_status status;

	status = ostype_attr(ctx, "vmcoreinfo.SIZE", &attr);
	if (status != KDUMP_OK)
		return kdump2addrxlat(ctx, status);

	attr = sub_attr_xlat(ctx, attr, name, "Symbol size");
	if (!attr)
		return ADDRXLAT_ERR_NODATA;

	*val = attr_value(attr)->number;
	return ADDRXLAT_OK;
}

/** Symbol size callback. */
static addrxlat_status
sym_sizeof(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	addrxlat_status ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = sym_sizeof_locked(cb, name, val);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/** Get element offset within an object from attributes (with locks held). */
static addrxlat_status
sym_offsetof_locked(const addrxlat_cb_t *cb, const char *obj, const char *elem,
		    addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	struct attr_data *attr;
	kdump_status status;

	status = ostype_attr(ctx, "vmcoreinfo.OFFSET", &attr);
	if (status != KDUMP_OK)
		return kdump2addrxlat(ctx, status);

	attr = sub_attr_xlat(ctx, attr, obj, "Container object");
	if (!attr)
		return ADDRXLAT_ERR_NODATA;

	attr = sub_attr_xlat(ctx, attr, elem, "Field");
	if (!attr)
		return ADDRXLAT_ERR_NODATA;

	*val = attr_value(attr)->number;
	return ADDRXLAT_OK;
}

/** Element offset callback. */
static addrxlat_status
sym_offsetof(const addrxlat_cb_t *cb, const char *obj, const char *elem,
	     addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	addrxlat_status ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = sym_offsetof_locked(cb, obj, elem, val);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/** Get number value from attributes (with locks held). */
static addrxlat_status
num_value_locked(const addrxlat_cb_t *cb, const char *name,
		 addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	struct attr_data *attr;
	kdump_status status;

	status = ostype_attr(ctx, "vmcoreinfo.NUMBER", &attr);
	if (status != KDUMP_OK)
		return kdump2addrxlat(ctx, status);

	attr = sub_attr_xlat(ctx, attr, name, "Number");
	if (!attr)
		return ADDRXLAT_ERR_NODATA;

	*val = attr_value(attr)->number;
	return ADDRXLAT_OK;
}

/** Number value callback. */
static addrxlat_status
num_value(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	kdump_ctx_t *ctx = (kdump_ctx_t*) cb->priv;
	addrxlat_status ret;

	rwlock_rdlock(&ctx->shared->lock);
	ret = num_value_locked(cb, name, val);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
init_addrxlat(kdump_ctx_t *ctx)
{
	addrxlat_ctx_t *addrxlat;
	addrxlat_cb_t *cb;

	addrxlat = addrxlat_ctx_new();
	if (!addrxlat)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s",
				 "address translation context");

	cb = addrxlat_ctx_add_cb(addrxlat);
	if (!cb) {
		addrxlat_ctx_decref(addrxlat);
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s",
				 "address translation callbacks");
	}

	cb->priv = ctx;
	cb->get_page = addrxlat_get_page;
	cb->read_caps = addrxlat_read_caps;
	cb->reg_value = reg_value;
	cb->sym_value = sym_value;
	cb->sym_sizeof = sym_sizeof;
	cb->sym_offsetof = sym_offsetof;
	cb->num_value = num_value;

	ctx->xlatctx = addrxlat;
	ctx->xlatcb = cb;
	return KDUMP_OK;
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

	xlat->osdir = NR_GLOBAL_ATTRS;

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
