/** @internal @file src/devmem.c
 * @brief Routines to read from /dev/mem.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#define FN_VMCOREINFO	"/sys/kernel/vmcoreinfo"

struct devmem_priv {
	unsigned cache_size;
	struct cache_entry *ce;
};

static kdump_status
get_vmcoreinfo(kdump_ctx *ctx)
{
	FILE *f;
	unsigned long long addr;
	size_t length;
	void *info;
	kdump_status ret;

	f = fopen(FN_VMCOREINFO, "r");
	if (!f)
		return set_error(ctx, kdump_syserr,
				 "Cannot open %s", FN_VMCOREINFO);

	if (fscanf(f, "%llx %zx", &addr, &length) == 2)
		ret = kdump_ok;
	else if (ferror(f))
		ret = set_error(ctx, kdump_syserr,
				"Error reading %s", FN_VMCOREINFO);
	else
		ret = set_error(ctx, kdump_dataerr,
				"Error parsing %s: Wrong file format",
				FN_VMCOREINFO);
	fclose(f);
	if (ret != kdump_ok)
		return ret;

	info = ctx_malloc(length, ctx, "VMCOREINFO buffer");
	if (!info)
		return kdump_syserr;

	ret = kdump_readp(ctx, KDUMP_KPHYSADDR, addr, info, &length);
	if (ret == kdump_ok)
		ret = process_notes(ctx, info, length);

	free(info);
	return ret;
}

static kdump_status
devmem_read_page(kdump_ctx *ctx, struct page_io *pio)
{
	struct devmem_priv *dmp = ctx->fmtdata;
	struct cache_entry *ce;
	off_t pos = pio->pfn << get_page_shift(ctx);
	ssize_t rd;
	unsigned i;

	ce = NULL;
	for (i = 0; i < dmp->cache_size; ++i) {
		if (dmp->ce[i].pfn == pio->pfn) {
			ce = &dmp->ce[i];
			break;
		} else if (dmp->ce[i].refcnt == 0)
			ce = &dmp->ce[i];
	}
	if (!ce)
		return set_error(ctx, kdump_busy,
				 "Cache is fully utilized");
	++ce->refcnt;

	ce->pfn = pio->pfn;
	rd = pread(ctx->fd, ce->data, get_page_size(ctx), pos);
	if (rd != get_page_size(ctx)) {
		--ce->refcnt;
		return set_error(ctx, read_error(rd),
				 "Cannot read memory device");
	}

	pio->ce = ce;
	return kdump_ok;
}

static void
devmem_unref_page(kdump_ctx *ctx, struct page_io *pio)
{
	--pio->ce->refcnt;
}

kdump_status
devmem_realloc_caches(kdump_ctx *ctx)
{
	struct devmem_priv *dmp = ctx->fmtdata;
	unsigned cache_size = get_cache_size(ctx);
	struct cache_entry *ce;
	unsigned i;

	ce = calloc(cache_size, sizeof *ce);
	if (!ce)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate cache (%u * %zu bytes)",
				 cache_size, sizeof *ce);

	ce[0].data = ctx_malloc(cache_size * get_page_size(ctx),
				ctx, "cache data");
	if (!ce[0].data) {
		free(ce);
		return kdump_syserr;
	}

	ce[0].pfn = CACHE_FLAGS_PFN(-1);
	for (i = 1; i < cache_size; ++i) {
		ce[i].pfn = CACHE_FLAGS_PFN(-1);
		ce[i].data = ce[i-1].data + get_page_size(ctx);
	}

	dmp->cache_size = cache_size;
	if (dmp->ce) {
		free(dmp->ce[0].data);
		free(dmp->ce);
	}
	dmp->ce = ce;

	return kdump_ok;
}

static kdump_status
devmem_probe(kdump_ctx *ctx, void *hdr)
{
	struct devmem_priv *dmp;
	struct stat st;
	kdump_status ret;

	if (fstat(ctx->fd, &st))
		return set_error(ctx, kdump_syserr, "Cannot stat file");

	if (!S_ISCHR(st.st_mode) ||
	    (st.st_rdev != makedev(1, 1) &&
	    major(st.st_rdev) != 10))
		return set_error(ctx, kdump_noprobe,
				 "Not a memory dump character device");

	dmp = ctx_malloc(sizeof *dmp, ctx, "Live source private data");
	if (!dmp)
		return kdump_syserr;
	dmp->ce = NULL;
	ctx->fmtdata = dmp;

#if defined(__x86_64__)
	ret = set_arch_name(ctx, KDUMP_ARCH_X86_64);
#elif defined(__i386__)
	ret = set_arch_name(ctx, KDUMP_ARCH_IA32);
#elif defined(__powerpc64__)
	ret = set_arch_name(ctx, KDUMP_ARCH_PPC64);
#elif defined(__powerpc__)
	ret = set_arch_name(ctx, KDUMP_ARCH_PPC);
#elif defined(__s390x__)
	ret = set_arch_name(ctx, KDUMP_ARCH_S390X);
#elif defined(__s390__)
	ret = set_arch_name(ctx, KDUMP_ARCH_S390);
#elif defined(__ia64__)
	ret = set_arch_name(ctx, KDUMP_ARCH_IA64);
#elif defined(__aarch64__)
	ret = set_arch_name(ctx, KDUMP_ARCH_AARCH64);
#elif defined(__arm__)
	ret = set_arch_name(ctx, KDUMP_ARCH_ARM);
#elif defined(__alpha__)
	ret = set_arch_name(ctx, KDUMP_ARCH_ALPHA);
#endif
	if (ret != kdump_ok)
		return ret;

	set_format_longname(ctx, "Live memory source");
#if __BYTE_ORDER == __LITTLE_ENDIAN
	set_byte_order(ctx, kdump_little_endian);
#else
	set_byte_order(ctx, kdump_big_endian);
#endif

	ret = set_page_size(ctx, sysconf(_SC_PAGESIZE));
	if (ret != kdump_ok)
		return ret;

	get_vmcoreinfo(ctx);

	return kdump_ok;
}

static void
devmem_cleanup(kdump_ctx *ctx)
{
	struct devmem_priv *dmp = ctx->fmtdata;

	if (dmp->ce) {
		free(dmp->ce[0].data);
		free(dmp->ce);
	}

	free(ctx->priv);
	ctx->fmtdata = NULL;
}

const struct format_ops devmem_ops = {
	.name = "memory",
	.probe = devmem_probe,
	.read_page = devmem_read_page,
	.unref_page = devmem_unref_page,
	.realloc_caches = devmem_realloc_caches,
	.cleanup = devmem_cleanup,
};
