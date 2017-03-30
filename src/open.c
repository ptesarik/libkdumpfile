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

static kdump_status kdump_open_known(kdump_ctx_t *pctx);

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

/**  Set dump file descriptor.
 * @param ctx   Dump file object.
 * @param buf   Temporary buffer.
 * @returns     Error status.
 *
 * Probe the given file for known file formats and initialize it for use.
 */
static kdump_status
set_fd(kdump_ctx_t *ctx, void *buf)
{
	ssize_t rd;
	kdump_status ret;
	int i;

	rd = paged_read(get_file_fd(ctx), buf, MAX_PAGE_SIZE);
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
		if (ctx->shared->cache) {
			cache_unref(ctx->shared->cache);
			ctx->shared->cache = NULL;
		}
		clear_volatile_attrs(ctx);
		clear_error(ctx);
	}

	return set_error(ctx, kdump_unsupported, "Unknown file format");
}

static kdump_status
kdump_open_known(kdump_ctx_t *ctx)
{
	set_attr_static_string(ctx, gattr(ctx, GKI_file_format),
			       ATTR_DEFAULT, ctx->shared->ops->name);

	if (isset_arch_name(ctx)) {
		vtop_init(ctx);
		clear_error(ctx);
	}

	return kdump_ok;
}

static kdump_status
file_fd_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	void *buffer;
	kdump_status ret;

	buffer = ctx_malloc(MAX_PAGE_SIZE, ctx, "file header buffer");
	if (!buffer)
		return kdump_syserr;

	ret = set_fd(ctx, buffer);

	free(buffer);
	return ret;
}

const struct attr_ops file_fd_ops = {
	.post_set = file_fd_post_hook,
};

kdump_status
kdump_set_fd(kdump_ctx_t *ctx, int fd)
{
	kdump_attr_value_t val;
	kdump_status ret;

	clear_error(ctx);
	rwlock_wrlock(&ctx->shared->lock);
	val.number = fd;
	ret = set_attr(ctx, gattr(ctx, GKI_file_fd), ATTR_PERSIST, &val);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/* struct new_utsname is inside struct uts_namespace, preceded by a struct
 * kref, but the offset is not stored in VMCOREINFO. So, search some sane
 * amount of memory for UTS_SYSNAME, which can be used as kind of a magic
 * signature.
 */
static kdump_status
uts_name_from_init_uts_ns(kdump_ctx_t *ctx, kdump_vaddr_t *uts_name)
{
	kdump_vaddr_t init_uts_ns;
	char buf[2 * NEW_UTS_LEN + sizeof(UTS_SYSNAME)];
	char *p;
	size_t rd;
	kdump_status ret;

	rwlock_unlock(&ctx->shared->lock);
	ret = get_symbol_val(ctx, "init_uts_ns", &init_uts_ns);
	rwlock_wrlock(&ctx->shared->lock);
	if (ret != kdump_ok)
		return ret;

	rd = sizeof buf;
	ret = read_locked(ctx, KDUMP_KVADDR, init_uts_ns, buf, &rd);
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
update_linux_utsname(kdump_ctx_t *ctx)
{
	kdump_vaddr_t uts_name;
	struct new_utsname uts;
	size_t rd;
	kdump_status ret;

	if (attr_isset(gattr(ctx, GKI_linux_uts_sysname)))
		return kdump_ok;

	rwlock_unlock(&ctx->shared->lock);
	ret = get_symbol_val(ctx, "system_utsname", &uts_name);
	rwlock_wrlock(&ctx->shared->lock);
	if (ret == kdump_nodata) {
		clear_error(ctx);
		ret = uts_name_from_init_uts_ns(ctx, &uts_name);
	}
	if (ret == kdump_nodata || ret == kdump_addrxlat) {
		clear_error(ctx);
		return kdump_ok;
	}
	if (ret != kdump_ok)
		return ret;

	rd = sizeof uts;
	ret = read_locked(ctx, KDUMP_KVADDR, uts_name,
			   (unsigned char*)&uts, &rd);
	if (ret != kdump_ok)
		return ret;

	if (!uts_looks_sane(&uts))
		return set_error(ctx, kdump_dataerr,
				 "Wrong utsname content");

	set_uts(ctx, &uts);

	return kdump_ok;
}

/** Initialize Linux version code from kernel release string.
 * @param ctx      Dump file object.
 * @returns        Error status.
 *
 * If the release string is not set, version code is left unchanged,
 * and this function succeeds. This behaviour may have to change if
 * the function is used from other contexts than the ostype post hook.
 */
static kdump_status
linux_version_code(kdump_ctx_t *ctx)
{
	struct attr_data *rel;
	const char *p;
	char *endp;
	long a, b, c;
	kdump_attr_value_t val;
	kdump_status status;

	rel = gattr(ctx, GKI_linux_uts_release);
	status = validate_attr(ctx, rel);
	if (status == kdump_nodata)
		return kdump_ok; /* Missing data => ignore */
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot get Linux release");

	p = attr_value(rel)->string;
	a = strtoul(p, &endp, 10);
	if (endp == p || *endp != '.')
		goto err;

	b = c = 0L;
	if (*endp) {
		p = endp + 1;
		b = strtoul(p, &endp, 10);
		if (endp == p || *endp != '.')
			goto err;

		if (*endp) {
			p = endp + 1;
			c = strtoul(p, &endp, 10);
			if (endp == p)
				goto err;
		}
	}

	val.number = KERNEL_VERSION(a, b, c);
	return set_attr(ctx, gattr(ctx, GKI_linux_version_code),
			ATTR_DEFAULT, &val);

 err:
	return set_error(ctx, kdump_dataerr, "Invalid kernel version: %s",
			 attr_value(rel)->string);
}

/** Read the Xen extra version string.
 * @param ctx      Dump file object.
 * @returns        Error status.
 */
static kdump_status
update_xen_extra_ver(kdump_ctx_t *ctx)
{
	static const char desc[] = "Xen extra version";
	struct attr_data *attr;
	char *extra;
	kdump_status status;

	attr = gattr(ctx, GKI_xen_ver_extra_addr);
	status = validate_attr(ctx, attr);
	if (status == kdump_nodata)
		return kdump_ok;
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot locate %s", desc);

	status = read_string_locked(ctx, KDUMP_MACHPHYSADDR,
				    attr_value(attr)->address, &extra);
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot read %s", desc);

	status = set_attr_string(ctx, gattr(ctx, GKI_xen_ver_extra),
				 ATTR_DEFAULT, extra);
	free(extra);
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot set %s", desc);

	return kdump_ok;
}

/** Initialize Xen version code from Xen major/minor strings.
 * @param ctx      Dump file object.
 * @returns        Error status.
 *
 * If the version strings are not set, version code is left unchanged,
 * and this function succeeds. This behaviour may have to change if
 * the function is used from other contexts than the ostype post hook.
 */
static kdump_status
xen_version_code(kdump_ctx_t *ctx)
{
	struct attr_data *ver;
	unsigned long major, minor;
	kdump_attr_value_t val;
	kdump_status status;

	ver = gattr(ctx, GKI_xen_ver_major);
	status = validate_attr(ctx, ver);
	if (status == kdump_nodata)
		return kdump_ok; /* Missing data => ignore */
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot get Xen major");
	major = attr_value(ver)->number;

	ver = gattr(ctx, GKI_xen_ver_minor);
	status = validate_attr(ctx, ver);
	if (status == kdump_nodata)
		return kdump_ok; /* Missing data => ignore */
	if (status != kdump_ok)
		return set_error(ctx, status, "Cannot get Xen minor");
	minor = attr_value(ver)->number;

	val.number = ADDRXLAT_VER_XEN(major, minor);
	return set_attr(ctx, gattr(ctx, GKI_xen_version_code),
			ATTR_DEFAULT, &val);
}

static kdump_status
ostype_pre_hook(kdump_ctx_t *ctx, struct attr_data *attr,
		kdump_attr_value_t *val)
{
	if (!(strcmp(val->string, "linux")))
		ctx->shared->ostype = addrxlat_os_linux;
	else if (!strcmp(val->string, "xen"))
		ctx->shared->ostype = addrxlat_os_xen;
	else
		return set_error(ctx, kdump_unsupported,
				 "Unsupported OS type");

	return kdump_ok;
}

static kdump_status
ostype_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	kdump_status status;

	if (isset_arch_name(ctx)) {
		status = vtop_init(ctx);
		if (status != kdump_ok)
			return set_error(ctx, status,
					 "Cannot initialize address translation");
	}

	if (ctx->shared->arch_ops && ctx->shared->arch_ops->late_init &&
	    (status = ctx->shared->arch_ops->late_init(ctx)) != kdump_ok)
		return set_error(ctx, status,
				 "Architecture late init failed");

	switch (ctx->shared->ostype) {
	case addrxlat_os_linux:
		status = update_linux_utsname(ctx);
		if (status != kdump_ok)
			return status;
		status = linux_version_code(ctx);
		if (status != kdump_ok)
			return status;
		break;

	case addrxlat_os_xen:
		status = update_xen_extra_ver(ctx);
		if (status != kdump_ok)
			return status;
		status = xen_version_code(ctx);
		if (status != kdump_ok)
			return status;
		break;

	default:
		break;
	}

	return kdump_ok;
}

static void
ostype_clear_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	ctx->shared->ostype = addrxlat_os_unknown;
	if (isset_arch_name(ctx)) {
		vtop_init(ctx);
		clear_error(ctx);
	}
}

const struct attr_ops ostype_ops = {
	.pre_set = ostype_pre_hook,
	.post_set = ostype_post_hook,
	.pre_clear = ostype_clear_hook,
};

void
kdump_free(kdump_ctx_t *ctx)
{
	struct kdump_shared *shared = ctx->shared;
	int slot;
	int isempty;

	rwlock_wrlock(&shared->lock);

	for (slot = 0; slot < PER_CTX_SLOTS; ++slot)
		if (shared->per_ctx_size[slot])
			free(ctx->data[slot]);

	addrxlat_ctx_decref(ctx->xlatctx);

	list_del(&ctx->list);
	isempty = list_empty(&shared->ctx);

	rwlock_unlock(&shared->lock);

	if (isempty) {
		if (shared->ops && shared->ops->cleanup)
			shared->ops->cleanup(shared);
		if (shared->arch_ops && shared->arch_ops->cleanup)
			shared->arch_ops->cleanup(shared);
		if (shared->cache)
			cache_unref(shared->cache);
		if (shared->xen_map)
			free(shared->xen_map);
		if (shared->xlatsys)
			addrxlat_sys_decref(shared->xlatsys);
		cleanup_attr(shared);
		rwlock_destroy(&shared->lock);
		free(shared);
	}

	if (ctx->err_dyn)
		free(ctx->err_dyn);
	free(ctx);
}
