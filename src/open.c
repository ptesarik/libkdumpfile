/** @internal @file src/open.c
 * @brief Routines for opening dumps.
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/version.h>

static kdump_status kdump_open_known(kdump_ctx *pctx);
static kdump_status use_kernel_utsname(kdump_ctx *ctx);
static kdump_status setup_version_code(kdump_ctx *ctx);

static const struct format_ops *formats[] = {
	&elfdump_ops,
	&qemu_ops,
	&libvirt_ops,
	&xc_save_ops,
	&xc_core_ops,
	&diskdump_ops,
	&lkcd_ops,
	&mclxcd_ops,
	&s390dump_ops,
	&devmem_ops
};

kdump_ctx *
kdump_alloc_ctx(void)
{
	return calloc(1, sizeof (kdump_ctx));
}

kdump_status
kdump_init_ctx(kdump_ctx *ctx)
{
	struct kdump_shared *shared;
	kdump_status status;

	shared = calloc(1, sizeof *shared);
	if (!shared)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate shared info");
	list_init(&shared->ctx);

	ctx->shared = shared;
	list_add(&ctx->list, &shared->ctx);

	status = init_attrs(ctx);
	if (status != kdump_ok) {
		free(ctx->shared);
		return status;
	}

	set_attr_number(ctx, gattr(ctx, GKI_cache_size), DEFAULT_CACHE_SIZE);

	ctx->cb_get_symbol_val = kdump_vmcoreinfo_symbol;
	ctx->cb_get_symbol_val_xen = kdump_vmcoreinfo_symbol_xen;

	init_vtop_maps(ctx);

	return kdump_ok;
}

kdump_status
kdump_init_clone(kdump_ctx *ctx, const kdump_ctx *orig)
{
	int slot;

	for (slot = 0; slot < PER_CTX_SLOTS; ++slot) {
		size_t sz = orig->shared->per_ctx_size[slot];
		if (!sz)
			continue;
		if (! (ctx->data[slot] = malloc(sz)) ) {
			while (slot-- > 0)
				if (orig->shared->per_ctx_size[slot])
					free(ctx->data[slot]);
			return set_error(ctx, kdump_syserr,
					 "Cannot allocate per-ctx data");
		}
	}

	ctx->shared = orig->shared;
	list_add(&ctx->list, &orig->shared->ctx);

	ctx->priv = orig->priv;
	ctx->cb_get_symbol_val = orig->cb_get_symbol_val;
	ctx->cb_get_symbol_val_xen = orig->cb_get_symbol_val_xen;
	return kdump_ok;
}

kdump_ctx *
kdump_init(void)
{
	kdump_ctx *ctx;
	kdump_status status;

	ctx = kdump_alloc_ctx();
	if (!ctx)
		return NULL;

	status = kdump_init_ctx(ctx);
	if (status != kdump_ok) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

kdump_status
kdump_fdopen(kdump_ctx **pctx, int fd)
{
	kdump_ctx *ctx;
	kdump_status ret;

	/* Initialize context */
	ctx = kdump_init();
	if (!ctx)
		return kdump_syserr;

	ret = kdump_set_fd(ctx, fd);
	if (ret != kdump_ok) {
		kdump_free(ctx);
		return ret;
	}

	*pctx = ctx;
	return kdump_ok;
}

/**  Set dump file descriptor.
 * @param ctx   Dump file object.
 * @param fd    File descriptor.
 * @param buf   Temporary buffer.
 * @returns     Error status.
 *
 * Probe the given file for known file formats and initialize it for use.
 */
static kdump_status
set_fd(kdump_ctx *ctx, int fd, void *buf)
{
	struct attr_data *d;
	ssize_t rd;
	kdump_status ret;
	int i;

	ctx->shared->fd = fd;

	rd = paged_read(ctx->shared->fd, buf, MAX_PAGE_SIZE);
	if (rd < 0)
		return set_error(ctx, kdump_syserr, "Cannot read file header");
	memset(buf + rd, 0, MAX_PAGE_SIZE - rd);

	for (i = 0; i < ARRAY_SIZE(formats); ++i) {
		ctx->shared->ops = formats[i];
		ret = ctx->shared->ops->probe(ctx, buf);
		if (ret == kdump_ok)
			return kdump_open_known(ctx);
		if (ret != kdump_noprobe)
			return ret;

		ctx->shared->ops = NULL;
		if (ctx->shared->cache)
			cache_free(ctx->shared->cache);
		clear_attrs(ctx);
		d = gattr(ctx, GKI_cache_size);
		set_attr(ctx, d, *attr_value(d));
		clear_error(ctx);
	}

	return set_error(ctx, kdump_unsupported, "Unknown file format");
}

static kdump_status
kdump_open_known(kdump_ctx *ctx)
{
	const struct attr_data *attr;
	kdump_status res;

	set_attr_static_string(ctx, gattr(ctx, GKI_format_name),
			       ctx->shared->ops->name);

	if (!attr_isset(gattr(ctx, GKI_linux_uts_sysname)))
		/* If this fails, it is not fatal. */
		use_kernel_utsname(ctx);

	/* If this fails, it is not fatal. */
	attr = gattr(ctx, GKI_xen_ver_extra_addr);
	if (attr_isset(attr)) {
		char *extra;
		res = kdump_read_string(ctx, KDUMP_MACHPHYSADDR,
					attr_value(attr)->address, &extra);
		if (res == kdump_ok) {
			set_attr_string(ctx, gattr(ctx, GKI_xen_ver_extra),
					extra);
			free(extra);
		}
	}

	setup_version_code(ctx);

	flush_vtop_map(&ctx->shared->vtop_map);
	flush_vtop_map(&ctx->shared->vtop_map_xen);

	clear_error(ctx);
	return kdump_ok;
}

kdump_status
kdump_set_fd(kdump_ctx *ctx, int fd)
{
	void *buffer;
	kdump_status ret;

	clear_error(ctx);

	buffer = ctx_malloc(MAX_PAGE_SIZE, ctx, "file header buffer");
	if (!buffer)
		return kdump_syserr;

	ret = set_fd(ctx, fd, buffer);

	free(buffer);
	return ret;
}

/* struct new_utsname is inside struct uts_namespace, preceded by a struct
 * kref, but the offset is not stored in VMCOREINFO. So, search some sane
 * amount of memory for UTS_SYSNAME, which can be used as kind of a magic
 * signature.
 */
static kdump_status
uts_name_from_init_uts_ns(kdump_ctx *ctx, kdump_vaddr_t *uts_name)
{
	kdump_vaddr_t init_uts_ns;
	char buf[2 * NEW_UTS_LEN + sizeof(UTS_SYSNAME)];
	char *p;
	size_t rd;
	kdump_status ret;

	ret = get_symbol_val(ctx, "init_uts_ns", &init_uts_ns);
	if (ret != kdump_ok)
		return ret;

	rd = sizeof buf;
	ret = kdump_readp(ctx, KDUMP_KVADDR, init_uts_ns, buf, &rd);
	if (ret != kdump_ok)
		return ret;

	for (p = buf; p <= &buf[2 * NEW_UTS_LEN]; ++p)
		if (!memcmp(p, UTS_SYSNAME, sizeof(UTS_SYSNAME)))
			break;
	if (p > &buf[2 * NEW_UTS_LEN])
		return set_error(ctx, kdump_dataerr, "UTS_SYSNAME not found");

	*uts_name = init_uts_ns + p - buf;
	return kdump_ok;
}

static kdump_status
use_kernel_utsname(kdump_ctx *ctx)
{
	kdump_vaddr_t uts_name;
	struct new_utsname uts;
	size_t rd;
	kdump_status ret;

	ret = get_symbol_val(ctx, "system_utsname", &uts_name);
	if (ret == kdump_nodata) {
		clear_error(ctx);
		ret = uts_name_from_init_uts_ns(ctx, &uts_name);
	}
	if (ret != kdump_ok)
		return ret;

	rd = sizeof uts;
	ret = kdump_readp(ctx, KDUMP_KVADDR, uts_name,
			  (unsigned char*)&uts, &rd);
	if (ret != kdump_ok)
		return ret;

	if (!uts_looks_sane(&uts))
		return set_error(ctx, kdump_dataerr,
				 "Wrong utsname content");

	set_uts(ctx, &uts);

	return kdump_ok;
}

static kdump_status
setup_version_code(kdump_ctx *ctx)
{
	const struct attr_data *rel;
	const char *p;
	char *endp;
	long a, b, c;

	rel = gattr(ctx, GKI_linux_uts_release);
	if (!attr_isset(rel))
		return set_error(ctx, kdump_nodata,
				 "Cannot get kernel release");

	p = attr_value(rel)->string;
	a = strtoul(p, &endp, 10);
	if (endp == p || *endp != '.')
		return set_error(ctx, kdump_dataerr,
				 "Invalid kernel version: %s",
				 attr_value(rel)->string);

	b = c = 0L;
	if (*endp) {
		p = endp + 1;
		b = strtoul(p, &endp, 10);
		if (endp == p || *endp != '.')
			return set_error(ctx, kdump_dataerr,
					 "Invalid kernel version: %s",
					 attr_value(rel)->string);

		if (*endp) {
			p = endp + 1;
			c = strtoul(p, &endp, 10);
			if (endp == p)
				return set_error(ctx, kdump_dataerr,
						 "Invalid kernel version: %s",
						 attr_value(rel)->string);
		}
	}

	set_version_code(ctx, KERNEL_VERSION(a, b, c));
	return kdump_ok;
}

void
kdump_free(kdump_ctx *ctx)
{
	struct kdump_shared *shared = ctx->shared;

	list_del(&ctx->list);
	if (list_empty(&shared->ctx)) {
		if (shared->ops && shared->ops->cleanup)
			shared->ops->cleanup(shared);
		if (shared->arch_ops && shared->arch_ops->cleanup)
			shared->arch_ops->cleanup(shared);
		if (shared->cache)
			cache_free(shared->cache);
		if (shared->xen_map)
			free(shared->xen_map);
		flush_vtop_map(&shared->vtop_map);
		flush_vtop_map(&shared->vtop_map_xen);
		cleanup_attr(shared);
		free(shared);
	}
	free(ctx);
}
