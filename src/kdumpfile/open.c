/** @internal @file src/kdumpfile/open.c
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

/** File cache size.
 * This number should be big enough to cover page table lookups with a
 * scattered page table hierarchy, including a possible Xen mtop lookup
 * in a separate hierarchy. The worst case seems to be 4-level paging with
 * a subsequent lookup (4-level paging again, plus the lookup page) and
 * a data page. That is 4 + 1 + 4 + 1 = 10. Let's add some reserve and use
 * a beautirul power of two.
 */
#define FCACHE_SIZE	16

/** File cache page order.
 * This number should be high enough to leverage transparent huge pages in
 * the kernel (if possible), but small enough not to exhaust the virtual
 * address space (especially on 32-bit platforms).
 * Choosing 10 here results in 4M blocks on architectures with 4K pages
 * and 64M blocks on architectures with 64K pages. In the latter case,
 * virtual address space may a bit tight on a 32-bit platform.
 */
#define FCACHE_ORDER	10

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
 * @returns     Error status.
 *
 * Probe the given file for known file formats and initialize it for use.
 */
static kdump_status
file_fd_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	/* Attributes that point into ctx->shared->fcache */
	static const enum global_keyidx fcache_attrs[] = {
		GKI_file_mmap_policy,
		GKI_mmap_cache_hits,
		GKI_mmap_cache_misses,
		GKI_read_cache_hits,
		GKI_read_cache_misses,
	};

	struct attr_data *mmap_attr;
	kdump_status ret;
	int i;

	if (ctx->shared->fcache) {
		for (i = 0; i < ARRAY_SIZE(fcache_attrs); ++i)
			attr_embed_value(gattr(ctx, fcache_attrs[i]));
		fcache_decref(ctx->shared->fcache);
	}
	ctx->shared->fcache = fcache_new(get_file_fd(ctx),
					 FCACHE_SIZE, FCACHE_ORDER);
	if (!ctx->shared->fcache)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate file cache");

	mmap_attr = gattr(ctx, GKI_file_mmap_policy);
	ctx->shared->fcache->mmap_policy = *attr_value(mmap_attr);
	set_attr(ctx, mmap_attr, ATTR_PERSIST_INDIRECT,
		 &ctx->shared->fcache->mmap_policy);

	cache_set_attrs(ctx->shared->fcache->cache, ctx,
			gattr(ctx, GKI_mmap_cache_hits),
			gattr(ctx, GKI_mmap_cache_misses));
	cache_set_attrs(ctx->shared->fcache->fbcache, ctx,
			gattr(ctx, GKI_read_cache_hits),
			gattr(ctx, GKI_read_cache_misses));

	ctx->xlat->dirty = true;

	for (i = 0; i < ARRAY_SIZE(formats); ++i) {
		ctx->shared->ops = formats[i];
		ret = ctx->shared->ops->probe(ctx);
		if (ret == KDUMP_OK)
			return kdump_open_known(ctx);
		if (ret != KDUMP_NOPROBE)
			return ret;

		ctx->shared->ops = NULL;
		if (ctx->shared->cache) {
			cache_free(ctx->shared->cache);
			ctx->shared->cache = NULL;
		}
		clear_volatile_attrs(ctx);
		clear_error(ctx);
	}

	return set_error(ctx, KDUMP_ERR_NOTIMPL, "Unknown file format");
}

static kdump_status
kdump_open_known(kdump_ctx_t *ctx)
{
	set_attr_static_string(ctx, gattr(ctx, GKI_file_format),
			       ATTR_DEFAULT, ctx->shared->ops->name);

	return KDUMP_OK;
}

const struct attr_ops file_fd_ops = {
	.post_set = file_fd_post_hook,
};

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
	if (ret != KDUMP_OK)
		return ret;

	rd = sizeof buf;
	ret = read_locked(ctx, KDUMP_KVADDR, init_uts_ns, buf, &rd);
	if (ret != KDUMP_OK)
		return ret;

	for (p = buf; p <= &buf[2 * NEW_UTS_LEN]; ++p)
		if (!memcmp(p, UTS_SYSNAME, sizeof(UTS_SYSNAME)))
			break;
	if (p > &buf[2 * NEW_UTS_LEN])
		return set_error(ctx, KDUMP_ERR_CORRUPT, "UTS_SYSNAME not found");

	*uts_name = init_uts_ns + p - buf;
	return KDUMP_OK;
}

static kdump_status
update_linux_utsname(kdump_ctx_t *ctx)
{
	kdump_vaddr_t uts_name;
	struct new_utsname uts;
	size_t rd;
	kdump_status ret;

	if (attr_isset(gattr(ctx, GKI_linux_uts_sysname)))
		return KDUMP_OK;

	rwlock_unlock(&ctx->shared->lock);
	ret = get_symbol_val(ctx, "system_utsname", &uts_name);
	rwlock_wrlock(&ctx->shared->lock);
	if (ret == KDUMP_ERR_NODATA) {
		clear_error(ctx);
		ret = uts_name_from_init_uts_ns(ctx, &uts_name);
	}
	if (ret == KDUMP_ERR_NODATA || ret == KDUMP_ERR_ADDRXLAT) {
		clear_error(ctx);
		return KDUMP_OK;
	}
	if (ret != KDUMP_OK)
		return ret;

	rd = sizeof uts;
	ret = read_locked(ctx, KDUMP_KVADDR, uts_name,
			   (unsigned char*)&uts, &rd);
	if (ret != KDUMP_OK)
		return ret;

	if (!uts_looks_sane(&uts))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong utsname content");

	set_uts(ctx, &uts);

	return KDUMP_OK;
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
	if (!attr_isset(attr))
		return KDUMP_OK;
	status = attr_revalidate(ctx, attr);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot locate %s", desc);

	status = read_string_locked(ctx, KDUMP_MACHPHYSADDR,
				    attr_value(attr)->address, &extra);
	if (status == KDUMP_ERR_NODATA) {
		/* Missing data is not fatal here. */
		clear_error(ctx);
		return KDUMP_OK;
	}
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot read %s", desc);

	status = set_attr_string(ctx, gattr(ctx, GKI_xen_ver_extra),
				 ATTR_DEFAULT, extra);
	free(extra);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot set %s", desc);

	return KDUMP_OK;
}

static kdump_status
ostype_pre_hook(kdump_ctx_t *ctx, struct attr_data *attr,
		kdump_attr_value_t *val)
{
	if (!(strcmp(val->string, "linux"))) {
		ctx->xlat->ostype = ADDRXLAT_OS_LINUX;
		ctx->xlat->osdir = GKI_dir_linux;
	} else if (!strcmp(val->string, "xen")) {
		ctx->xlat->ostype = ADDRXLAT_OS_XEN;
		ctx->xlat->osdir = GKI_dir_linux;
	} else
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unsupported OS type");

	return KDUMP_OK;
}

static kdump_status
ostype_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	kdump_status status;

	ctx->xlat->dirty = true;

	if (ctx->shared->arch_ops && ctx->shared->arch_ops->post_ostype) {
		status = ctx->shared->arch_ops->post_ostype(ctx);
		if (status != KDUMP_OK)
			return status;
	}

	switch (ctx->xlat->ostype) {
	case ADDRXLAT_OS_LINUX:
		status = update_linux_utsname(ctx);
		if (status != KDUMP_OK)
			return status;
		/* fall through */
	case ADDRXLAT_OS_XEN:
		status = update_xen_extra_ver(ctx);
		if (status != KDUMP_OK)
			return status;
		break;

	default:
		break;
	}

	return KDUMP_OK;
}

static void
ostype_clear_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	ctx->xlat->ostype = ADDRXLAT_OS_UNKNOWN;
	ctx->xlat->osdir = NR_GLOBAL_ATTRS;
	ctx->xlat->dirty = true;
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

	rwlock_wrlock(&shared->lock);

	for (slot = 0; slot < PER_CTX_SLOTS; ++slot)
		if (shared->per_ctx_size[slot])
			free(ctx->data[slot]);

	addrxlat_ctx_decref(ctx->xlatctx);

	list_del(&ctx->xlat_list);
	xlat_decref(ctx->xlat);

	attr_dict_decref(ctx->dict);

	list_del(&ctx->list);
	if (shared_decref_locked(shared))
		rwlock_unlock(&shared->lock);

	err_cleanup(&ctx->err);
	free(ctx);
}
