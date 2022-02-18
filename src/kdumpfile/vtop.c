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
	DEFOPT(os_type, KDUMP_NUMBER),
	DEFOPT(version_code, KDUMP_NUMBER),
	DEFOPT(levels, KDUMP_NUMBER),
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

#define MAX_OPTS	(11 + 2*ARRAY_SIZE(options))
struct opts {
	unsigned n;
	addrxlat_opt_t opts[MAX_OPTS];
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
add_addrxlat_opt(kdump_ctx_t *ctx, struct opts *opts,
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

	opt = &opts->opts[opts->n];
	opt->idx = tmpl->optidx;
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

	++opts->n;
	return KDUMP_OK;
}

/** Add all addrxlat options under a given directory.
 * @param ctx     Dump file object.
 * @param opts    Options.
 * @param dirkey  Global directory key index
 *                (addrxlat.default, or addrxlat.force).
 */
static kdump_status
add_addrxlat_opts(kdump_ctx_t *ctx, struct opts *opts,
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
set_arch_opt(kdump_ctx_t *ctx, struct opts *opts)
{
	if (isset_arch_name(ctx)) {
		addrxlat_opt_arch(&opts->opts[opts->n],
				  get_arch_name(ctx));
		++opts->n;
	}
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
set_os_type_opt(kdump_ctx_t *ctx, struct opts *opts)
{
	if (ctx->xlat->ostype != ADDRXLAT_OS_UNKNOWN) {
		addrxlat_opt_os_type(&opts->opts[opts->n],
				     ctx->xlat->ostype);
		++opts->n;
	}
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
set_version_code(kdump_ctx_t *ctx, struct opts *opts)
{
	static const char attrname[] = "version_code";
	struct attr_data *attr;
	const char *ostype;
	kdump_status status;

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

	addrxlat_opt_version_code(&opts->opts[opts->n],
				  attr_value(attr)->number);
	++opts->n;
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
set_page_shift_opt(kdump_ctx_t *ctx, struct opts *opts)
{
	if (isset_page_shift(ctx)) {
		addrxlat_opt_page_shift(&opts->opts[opts->n],
					get_page_shift(ctx));
		++opts->n;
	}
	return KDUMP_OK;
}

/**  Determine number of paging levels for x86 Linux OS.
 * @param ctx     Dump file object.
 * @param levels  Set to number of levels on success.
 * @returns       Error status.
 *
 * If PAE status is unknown, @c levels is unchanged, and this function
 * returns success.
 */
static kdump_status
get_linux_x86_levels(kdump_ctx_t *ctx, int *levels)
{
	static const char config_pae[] = "CONFIG_X86_PAE";
	struct attr_data *attr;

	attr = gattr(ctx, GKI_linux_vmcoreinfo_lines);
	if (attr_isset(attr))
		*levels = 2;
	attr = lookup_dir_attr(ctx->dict, attr,
			       config_pae, sizeof(config_pae) - 1);
	if (attr && attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot get %s from vmcoreinfo",
					 config_pae);
		if (!strcmp(attr_value(attr)->string, "y"))
			*levels = 3;
	}
	return KDUMP_OK;
}

/**  Add "levels=" addrxlat option if possible.
 * @param ctx   Dump file object.
 * @param opts  Options.
 * @returns     Error status.
 *
 * If paging levels cannot be determined, nothing is added and this
 * function returns success.
 */
static kdump_status
set_linux_levels_opt(kdump_ctx_t *ctx, struct opts *opts)
{
	int levels;
	kdump_status status;

	levels = 0;
	switch (ctx->shared->arch) {
	case ARCH_IA32:
		status = get_linux_x86_levels(ctx, &levels);
		break;

	default:
		status = KDUMP_OK;
		break;
	}
	if (status != KDUMP_OK)
		return status;

	if (levels != 0) {
		addrxlat_opt_levels(&opts->opts[opts->n], levels);
		++opts->n;
	}

	return KDUMP_OK;
}

static kdump_status
set_linux_opts(kdump_ctx_t *ctx, struct opts *opts)
{
	struct attr_data *attr;
	kdump_status status;

	status = set_linux_levels_opt(ctx, opts);
	if (status != KDUMP_OK)
		return status;

	if (isset_phys_base(ctx)) {
		addrxlat_opt_phys_base(&opts->opts[opts->n],
				       get_phys_base(ctx));
		++opts->n;
	}

	if ((isset_xen_xlat(ctx) && get_xen_xlat(ctx) != KDUMP_XEN_AUTO) ||
	    (isset_xen_type(ctx) && get_xen_type(ctx) == KDUMP_XEN_SYSTEM)) {
		addrxlat_opt_xen_xlat(&opts->opts[opts->n], 1);
		++opts->n;
	}

	attr = gattr(ctx, GKI_xen_p2m_mfn);
	if (attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot get %s from vmcoreinfo",
					 "p2m_mfn");
		addrxlat_opt_xen_p2m_mfn(&opts->opts[opts->n],
					 attr_value(attr)->number);
		++opts->n;
	}

	return KDUMP_OK;
}

static kdump_status
set_xen_opts(kdump_ctx_t *ctx, struct opts *opts)
{
	struct attr_data *attr;

	attr = gattr(ctx, GKI_xen_phys_start);
	if (attr_isset(attr)) {
		kdump_status status = attr_revalidate(ctx, attr);
		if (status != KDUMP_OK)
			return set_error(ctx, status, "Cannot get %s.%s",
					 "xen", "phys_start");
		addrxlat_opt_phys_base(&opts->opts[opts->n],
				       attr_value(attr)->address);
		++opts->n;
	}

	return KDUMP_OK;
}

kdump_status
vtop_init(kdump_ctx_t *ctx)
{
	kdump_status status;
	addrxlat_status axres;
	struct opts opts;

	if (!isset_arch_name(ctx))
		return KDUMP_OK;

	opts.n = 0;
	status = add_addrxlat_opts(ctx, &opts, GKI_dir_xlat_default);
	if (status == KDUMP_OK)
		status = set_arch_opt(ctx, &opts);
	if (status == KDUMP_OK)
		status = set_os_type_opt(ctx, &opts);
	if (status == KDUMP_OK)
		status = set_version_code(ctx, &opts);
	if (status == KDUMP_OK)
		status = set_page_shift_opt(ctx, &opts);
	if (status == KDUMP_OK) {
		if (ctx->xlat->ostype == ADDRXLAT_OS_LINUX)
			status = set_linux_opts(ctx, &opts);
		else if (ctx->xlat->ostype == ADDRXLAT_OS_XEN)
			status = set_xen_opts(ctx, &opts);
	}
	if (status == KDUMP_OK)
		status = add_addrxlat_opts(ctx, &opts, GKI_dir_xlat_force);
	if (status != KDUMP_OK)
		return status;

	ctx->xlat->dirty = false;

	rwlock_unlock(&ctx->shared->lock);

	axres = addrxlat_sys_os_init(ctx->xlat->xlatsys, ctx->xlatctx,
				     opts.n, opts.opts);

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

	static const struct ostype_attr_map number_map[] = {
		{ ADDRXLAT_OS_LINUX, GKI_linux_number },
		{ ADDRXLAT_OS_XEN, GKI_xen_number },
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

        case ADDRXLAT_SYM_NUMBER:
		base = ostype_attr(ctx, number_map);
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
