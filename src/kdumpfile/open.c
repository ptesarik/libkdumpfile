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

#include <stdio.h>
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

static kdump_status open_dump(kdump_ctx_t *ctx);
static kdump_status finish_open_dump(kdump_ctx_t *ctx);

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
	&sadump_ops,
	&devmem_ops
};

/**  Open the dump if all file descriptors have been specified.
 * @param ctx  Dump file object.
 */
static inline kdump_status
maybe_open_dump(kdump_ctx_t *ctx)
{
	return get_num_files(ctx) && !ctx->shared->pendfiles
		? open_dump(ctx)
		: KDUMP_OK;
}

/**  Set a file descriptor.
 * @param ctx   Dump file object.
 * @param attr  File descriptor attribute data.
 * @param val   New attribute value.
 * @returns     Error status.
 *
 * Adjust number of pending dump files if appropriate.
 */
static kdump_status
fdset_pre_hook(kdump_ctx_t *ctx, struct attr_data *attr,
	       kdump_attr_value_t *val)
{
	if (!attr_isset(attr))
		--ctx->shared->pendfiles;
	return KDUMP_OK;
}

/**  Unset a file descriptor.
 * @param ctx   Dump file object.
 * @param attr  File descriptor attribute data.
 */
static void
fdset_clear_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	if (attr_isset(attr))
		++ctx->shared->pendfiles;

	if (attr->parent->template->fidx == 0)
		clear_attr(ctx, gattr(ctx, GKI_file_fd));
}

/**  Maybe open the dump after setting a file descriptor.
 * @param ctx   Dump file object.
 * @param attr  File descriptor attribute data.
 * @returns     Error status.
 *
 * If no more files are pending, open the dump.
 */
static kdump_status
fdset_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return maybe_open_dump(ctx);
}

static const struct attr_ops fdset_ops = {
	.pre_set = fdset_pre_hook,
	.pre_clear = fdset_clear_hook,
	.post_set = fdset_post_hook,
};

/**  Set number of dump files.
 * @param ctx   Dump file object.
 * @param attr  Attribute data to be changed.
 * @param val   New attribute value.
 * @returns     Error status.
 *
 * Set up attributes for a set of dump files.
 */
static kdump_status
num_files_pre_hook(kdump_ctx_t *ctx, struct attr_data *attr,
		   kdump_attr_value_t *val)
{
	static const struct attr_template tmpl = {
		.key = "fd",
		.type = KDUMP_NUMBER,
		.ops = &fdset_ops,
	};
	static const struct attr_template name_tmpl = {
		.key = "name",
		.type = KDUMP_STRING,
	};

	struct attr_template dir_tmpl = {
		.type = KDUMP_DIRECTORY,
	};
	struct attr_data *parent = attr->parent;
	char fdkey[21];
	size_t keylen;
	size_t n, i;
	kdump_status ret;

	/* Check that the new value fits into a size_t. */
	n = val->number;
	if (n != val->number)
		return set_error(ctx, KDUMP_ERR_INVALID, "Number too big");

	/* Allocate new attributes */
	ret = KDUMP_OK;
	for (i = attr_value(attr)->number; i < n; ++i) {
		struct attr_data *dir, *fdattr, *nameattr;

		keylen = sprintf(fdkey, "%zd", i);
		dir_tmpl.fidx = i;
		dir = create_attr_path(ctx->dict, parent,
				       fdkey, keylen, &dir_tmpl);
		fdattr = dir
			? new_attr(ctx->dict, dir, &tmpl)
			: NULL;
		nameattr = fdattr
			? new_attr(ctx->dict, dir, &name_tmpl)
			: NULL;
		if (!nameattr) {
			ret = set_error(ctx, KDUMP_ERR_SYSTEM,
					"Cannot allocate file.set attributes");
			n = attr_value(attr)->number;
			break;
		}
		if (i == 0) {
			fdattr->flags.indirect = 1;
			fdattr->pval = attr_mut_value(gattr(ctx, GKI_file_fd));
		}
	}

	/* Delete superfluous attributes. */
	if (i > n) {
		struct attr_data **pprev = &parent->dir;
		while (*pprev) {
			struct attr_data *dir = *pprev;
			if (dir->template->type == KDUMP_DIRECTORY &&
			    dir->template->fidx >= n) {
				*pprev = dir->next;
				dealloc_attr(dir);
			} else
				pprev = &dir->next;
		}
	}

	return ret;
}

/**  Set number of dump files pending open.
 * @param ctx   Dump file object.
 * @param attr  Number of files attribute.
 * @returns     Error status.
 *
 * Set up the number of pending files.
 */
static kdump_status
num_files_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	if (attr_value(attr)->number != 1)
		clear_attr(ctx, gattr(ctx, GKI_file_fd));

	size_t pendfiles = 0;
	struct attr_data *dir;
	for (dir = attr->parent->dir; dir; dir = dir->next) {
		struct attr_data *child;
		if (dir->template->type != KDUMP_DIRECTORY ||
		    !(child = lookup_dir_attr(ctx->dict, dir, "fd", 2)))
			continue;
		if (!attr_isset(child))
			++pendfiles;
	}
	ctx->shared->pendfiles = pendfiles;

	return maybe_open_dump(ctx);
}

/** Attribute operations for file.set.number. */
const struct attr_ops num_files_ops = {
	.pre_set = num_files_pre_hook,
	.post_set = num_files_post_hook,
};

/**  Set dump file descriptor.
 * @param ctx   Dump file object.
 * @returns     Error status.
 */
static kdump_status
file_fd_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	int fd = attr_value(attr)->number;
	return internal_open_fdset(ctx, 1, &fd);
}

const struct attr_ops file_fd_ops = {
	.post_set = file_fd_post_hook,
};

/**  Open the dump.
 * @param ctx   Dump file object.
 * @returns     Error status.
 *
 * Probe a dump file for known file formats.
 * On success, initialize the dump file context for use.
 */
static kdump_status
open_dump(kdump_ctx_t *ctx)
{
	/* Attributes that point into ctx->shared->fcache */
	static const enum global_keyidx fcache_attrs[] = {
		GKI_file_mmap_policy,
		GKI_mmap_cache_hits,
		GKI_mmap_cache_misses,
		GKI_read_cache_hits,
		GKI_read_cache_misses,
	};

	size_t nfiles = get_num_files(ctx);
	struct attr_data *dir;
	struct attr_data *mmap_attr;
	kdump_status ret;
	int fdset[nfiles];
	int i;

	flatmap_free(ctx->shared->flatmap);
	if (ctx->shared->fcache) {
		for (i = 0; i < ARRAY_SIZE(fcache_attrs); ++i)
			attr_embed_value(gattr(ctx, fcache_attrs[i]));
		fcache_decref(ctx->shared->fcache);
	}

	for (dir = gattr(ctx, GKI_dir_file_set)->dir; dir; dir = dir->next) {
		struct attr_data *child;
		if (dir->template->type != KDUMP_DIRECTORY ||
		    !(child = lookup_dir_attr(ctx->dict, dir, "fd", 2)))
			continue;
		fdset[dir->template->fidx] = attr_value(child)->number;
	}
	ctx->shared->fcache = fcache_new(nfiles, fdset,
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

	ctx->shared->flatmap = flatmap_alloc(nfiles);
	if (!ctx->shared->flatmap)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s", "flattened dump maps");

	ret = flatmap_init(ctx->shared->flatmap, ctx);
	if (ret != KDUMP_OK)
		return ret;

	ctx->xlat->dirty = true;

	for (i = 0; i < ARRAY_SIZE(formats); ++i) {
		ctx->shared->ops = formats[i];
		ret = ctx->shared->ops->probe(ctx);
		if (ret == KDUMP_OK)
			return finish_open_dump(ctx);
		if (ctx->shared->ops->cleanup)
			ctx->shared->ops->cleanup(ctx->shared);
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

/** Finish opening a dump file of a known file format.
 * @param ctx   Dump file object.
 * @returns     Error status.
 */
static kdump_status
finish_open_dump(kdump_ctx_t *ctx)
{
	set_attr_static_string(ctx, gattr(ctx, GKI_file_format),
			       ATTR_DEFAULT, ctx->shared->ops->name);

	return KDUMP_OK;
}

/** Clear file.set.x.fd attributes
 * @param ctx   Dump file object.
 *
 * Clear all file descriptors. This is done before installing a new file
 * descriptor set to make sure that previously set file descriptor are not
 * used unexpectedly.
 */
static void
clear_all_fds(kdump_ctx_t *ctx)
{
	struct attr_data *dir = gattr(ctx, GKI_dir_file_set);

	for (dir = dir->dir; dir; dir = dir->next) {
		struct attr_data *child;
		if (dir->template->type == KDUMP_DIRECTORY &&
		    (child = lookup_dir_attr(ctx->dict, dir, "fd", 2)))
			clear_attr(ctx, child);
	}
}

kdump_status
kdump_set_filenames(kdump_ctx_t *ctx, unsigned n, const char *const *names)
{
	struct attr_data *dir;
	kdump_status status;

	clear_error(ctx);

	if (get_num_files(ctx) < n &&
	    (status = set_attr_number(ctx, gattr(ctx, GKI_num_files),
				      ATTR_PERSIST, n)) != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot initialize file set size");

	for (dir = gattr(ctx, GKI_dir_file_set)->dir; dir; dir = dir->next) {
		struct attr_data *child;
		unsigned fidx;

		if (dir->template->type != KDUMP_DIRECTORY)
			continue;
		fidx = dir->template->fidx;
		if (fidx >= n)
			continue;
		child = lookup_dir_attr(ctx->dict, dir, "name", 4);
		if (!child)
			continue;

		if (names[fidx]) {
			status = set_attr_string(ctx, child, ATTR_PERSIST,
						 names[fidx]);
			if (status != KDUMP_OK)
				return set_error(ctx, status, "%s",
						 err_filename(ctx, fidx));
		} else
			clear_attr(ctx, child);
	}

	return KDUMP_OK;
}

DEFINE_ALIAS(open_fdset);

kdump_status
kdump_open_fdset(kdump_ctx_t *ctx, unsigned nfds, const int *fds)
{
	struct attr_data *dir;
	kdump_status status;

	clear_error(ctx);

	/* Make sure we do not use a stale file descriptor value. */
	clear_all_fds(ctx);

	status = set_attr_number(ctx, gattr(ctx, GKI_num_files),
				 ATTR_PERSIST, nfds);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot initialize file set size");

	for (dir = gattr(ctx, GKI_dir_file_set)->dir; dir; dir = dir->next) {
		struct attr_data *child;
		if (dir->template->type != KDUMP_DIRECTORY ||
		    !(child = lookup_dir_attr(ctx->dict, dir, "fd", 2)))
			continue;

		status = set_attr_number(ctx, child, ATTR_PERSIST,
					 fds[dir->template->fidx]);
		if (status != KDUMP_OK)
			return set_error(ctx, status, "%s",
					 err_filename(ctx, dir->template->fidx));
	}

	return KDUMP_OK;
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
		ctx->xlat->osdir = GKI_dir_linux;
	} else if (!strcmp(val->string, "xen")) {
		ctx->xlat->osdir = GKI_dir_xen;
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

	switch (ctx->xlat->osdir) {
	case GKI_dir_linux:
		status = update_linux_utsname(ctx);
		if (status != KDUMP_OK)
			return status;
		/* fall through */
	case GKI_dir_xen:
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
	ctx->xlat->osdir = NR_GLOBAL_ATTRS;
	ctx->xlat->dirty = true;
}

const struct attr_ops ostype_ops = {
	.pre_set = ostype_pre_hook,
	.post_set = ostype_post_hook,
	.pre_clear = ostype_clear_hook,
};
