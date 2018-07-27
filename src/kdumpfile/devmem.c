/** @internal @file src/kdumpfile/devmem.c
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#define FN_VMCOREINFO	"/sys/kernel/vmcoreinfo"

struct devmem_priv {
	unsigned cache_size;
	struct cache_entry *ce;
};

static kdump_status
get_vmcoreinfo(kdump_ctx_t *ctx)
{
	FILE *f;
	unsigned long long addr;
	size_t length;
	void *info;
	kdump_status ret;

	f = fopen(FN_VMCOREINFO, "r");
	if (!f)
		return errno == ENOENT
			? KDUMP_OK
			: set_error(ctx, KDUMP_ERR_SYSTEM,
				    "Cannot open %s", FN_VMCOREINFO);

	if (fscanf(f, "%llx %zx", &addr, &length) == 2)
		ret = KDUMP_OK;
	else if (ferror(f))
		ret = set_error(ctx, KDUMP_ERR_SYSTEM,
				"Error reading %s", FN_VMCOREINFO);
	else
		ret = set_error(ctx, KDUMP_ERR_CORRUPT,
				"Error parsing %s: Wrong file format",
				FN_VMCOREINFO);
	fclose(f);
	if (ret != KDUMP_OK)
		return ret;

	info = ctx_malloc(length, ctx, "VMCOREINFO buffer");
	if (!info)
		return KDUMP_ERR_SYSTEM;

	ret = read_locked(ctx, KDUMP_MACHPHYSADDR, addr, info, &length);
	if (ret == KDUMP_OK)
		ret = process_notes(ctx, info, length);

	free(info);
	return ret;
}

#define FN_IOMEM	"/proc/iomem"

static kdump_status
check_kcode(kdump_ctx_t *ctx, char *line, kdump_paddr_t *paddr)
{
	unsigned long long start;
	char *p, *q;

	p = strchr(line, ':');
	if (!p)
		return KDUMP_ERR_NOKEY;
	++p;
	while (is_posix_space(*p))
		++p;

	q = line + strlen(line) - 1;
	while (is_posix_space(*q))
		*q-- = '\0';
	if (strcmp(p, "Kernel code"))
		return KDUMP_ERR_NOKEY;

	p = line;
	while (is_posix_space(*p))
		++p;
	start = strtoull(line, &p, 16);
	while (is_posix_space(*p))
		++p;
	if (p == line || *p != '-')
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid iomem format: %s", line);

	*paddr = start;
	return KDUMP_OK;
}

kdump_status
linux_iomem_kcode(kdump_ctx_t *ctx, kdump_paddr_t *paddr)
{
	FILE *f;
	char *line;
	size_t linealloc;
	kdump_status ret;

	f = fopen(FN_IOMEM, "r");
	if (!f)
		return errno == ENOENT
			? KDUMP_ERR_NODATA
			: set_error(ctx, KDUMP_ERR_SYSTEM,
				    "Cannot open %s", FN_VMCOREINFO);

	line = NULL;
	linealloc = 0;
	do {
		ssize_t linelen = getline(&line, &linealloc, f);
		if (linelen < 0)
			break;
	} while ((ret = check_kcode(ctx, line, paddr)) == KDUMP_ERR_NOKEY);

	if (ferror(f))
		ret = set_error(ctx, KDUMP_ERR_SYSTEM,
				"Error reading %s", FN_IOMEM);
	if (line)
		free(line);
	fclose(f);
	return ret;
}

static kdump_status
devmem_get_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	struct devmem_priv *dmp = ctx->shared->fmtdata;
	struct cache_entry *ce;
	unsigned i;
	kdump_status ret;

	ce = NULL;
	for (i = 0; i < dmp->cache_size; ++i) {
		if (dmp->ce[i].refcnt == 0) {
			ce = &dmp->ce[i];
		} else if (dmp->ce[i].key == pio->addr.addr) {
			ce = &dmp->ce[i];
			break;
		}
	}
	if (!ce)
		return set_error(ctx, KDUMP_ERR_BUSY,
				 "Cache is fully utilized");
	++ce->refcnt;

	ce->key = pio->addr.addr;
	mutex_lock(&ctx->shared->cache_lock);
	ret = fcache_get_chunk(ctx->shared->fcache, &pio->chunk,
			       get_page_size(ctx), pio->addr.addr);
	mutex_unlock(&ctx->shared->cache_lock);
	if (ret != KDUMP_OK) {
		--ce->refcnt;
		return set_error(ctx, ret,
				 "Cannot read memory device");
	}

	return KDUMP_OK;
}

static void
devmem_put_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	--pio->chunk.embed_fces->ce->refcnt;
}

static kdump_status
devmem_realloc_caches(kdump_ctx_t *ctx)
{
	struct devmem_priv *dmp = ctx->shared->fmtdata;
	unsigned cache_size = get_cache_size(ctx);
	struct cache_entry *ce;
	unsigned i;

	ce = calloc(cache_size, sizeof *ce);
	if (!ce)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate cache (%u * %zu bytes)",
				 cache_size, sizeof *ce);

	ce[0].data = ctx_malloc(cache_size * get_page_size(ctx),
				ctx, "cache data");
	if (!ce[0].data) {
		free(ce);
		return KDUMP_ERR_SYSTEM;
	}

	for (i = 1; i < cache_size; ++i)
		ce[i].data = ce[i-1].data + get_page_size(ctx);

	dmp->cache_size = cache_size;
	if (dmp->ce) {
		free(dmp->ce[0].data);
		free(dmp->ce);
	}
	dmp->ce = ce;

	return KDUMP_OK;
}

static kdump_status
devmem_probe(kdump_ctx_t *ctx)
{
	struct devmem_priv *dmp;
	struct stat st;
	kdump_status ret;

	if (fstat(get_file_fd(ctx), &st))
		return set_error(ctx, KDUMP_ERR_SYSTEM, "Cannot stat file");

	if (!S_ISCHR(st.st_mode) ||
	    (st.st_rdev != makedev(1, 1) &&
	    major(st.st_rdev) != 10))
		return set_error(ctx, KDUMP_NOPROBE,
				 "Not a memory dump character device");

	dmp = ctx_malloc(sizeof *dmp, ctx, "Live source private data");
	if (!dmp)
		return KDUMP_ERR_SYSTEM;
	dmp->ce = NULL;
	ctx->shared->fmtdata = dmp;

	set_file_description(ctx, "Live memory source");
#if __BYTE_ORDER == __LITTLE_ENDIAN
	set_byte_order(ctx, KDUMP_LITTLE_ENDIAN);
#else
	set_byte_order(ctx, KDUMP_BIG_ENDIAN);
#endif

	ret = set_page_size(ctx, sysconf(_SC_PAGESIZE));
	if (ret != KDUMP_OK)
		return ret;

	set_addrspace_caps(ctx->xlat, ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR));

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
	if (ret != KDUMP_OK)
		return ret;

	get_vmcoreinfo(ctx);

	return KDUMP_OK;
}

static void
devmem_cleanup(struct kdump_shared *shared)
{
	struct devmem_priv *dmp = shared->fmtdata;

	if (dmp->ce) {
		free(dmp->ce[0].data);
		free(dmp->ce);
	}

	free(dmp);
	shared->fmtdata = NULL;
}

const struct format_ops devmem_ops = {
	.name = "memory",
	.probe = devmem_probe,
	.get_page = devmem_get_page,
	.put_page = devmem_put_page,
	.realloc_caches = devmem_realloc_caches,
	.cleanup = devmem_cleanup,
};
