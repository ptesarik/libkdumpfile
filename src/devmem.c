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
	struct cache_entry ce;
};

static kdump_status
get_vmcoreinfo(kdump_ctx *ctx)
{
	FILE *f;
	unsigned long long addr, length;
	void *info;
	ssize_t rd;
	kdump_status ret;

	f = fopen(FN_VMCOREINFO, "r");
	if (!f)
		return set_error(ctx, kdump_syserr,
				 "Cannot open %s", FN_VMCOREINFO);

	if (fscanf(f, "%llx %llx", &addr, &length) == 2)
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

	if (lseek(ctx->fd, addr, SEEK_SET) == (off_t)-1) {
		ret = set_error(ctx, kdump_syserr,
				"Cannot seek to VMCOREINFO");
		goto out;
	}

	rd = paged_read(ctx->fd, info, length);
	if (rd != length) {
		ret = set_error(ctx, read_error(rd),
				"Cannot read VMCOREINFO");
		goto out;
	}

	ret = process_notes(ctx, info, length);

  out:
	free(info);
	return ret;
}

static kdump_status
devmem_read_page(kdump_ctx *ctx, struct page_io *pio)
{
	struct devmem_priv *dmp = ctx->fmtdata;
	off_t pos = pio->pfn << get_page_shift(ctx);
	ssize_t rd;

	dmp->ce.pfn = pio->pfn;
	dmp->ce.data = ctx->buffer;
	rd = pread(ctx->fd, dmp->ce.data, get_page_size(ctx), pos);
	if (rd != get_page_size(ctx))
		return set_error(ctx, read_error(rd),
				 "Cannot read memory device");
	pio->ce = &dmp->ce;
	return kdump_ok;
}

static kdump_status
devmem_probe(kdump_ctx *ctx)
{
	struct devmem_priv *dmp;
	struct stat st;
	kdump_status ret;

	if (fstat(ctx->fd, &st))
		return set_error(ctx, kdump_syserr, "Cannot stat file");

	if (!S_ISCHR(st.st_mode) ||
	    (st.st_rdev != makedev(1, 1) &&
	    major(st.st_rdev) != 10))
		return set_error(ctx, kdump_unsupported,
				 "Not a memory dump character device");

#if defined(__x86_64__)
	ret = set_arch(ctx, ARCH_X86_64);
#elif defined(__i386__)
	ret = set_arch(ctx, ARCH_X86);
#elif defined(__powerpc64__)
	ret = set_arch(ctx, ARCH_PPC64);
#elif defined(__powerpc__)
	ret = set_arch(ctx, ARCH_PPC);
#elif defined(__s390x__)
	ret = set_arch(ctx, ARCH_S390X);
#elif defined(__s390__)
	ret = set_arch(ctx, ARCH_S390);
#elif defined(__ia64__)
	ret = set_arch(ctx, ARCH_IA64);
#elif defined(__aarch64__)
	ret = set_arch(ctx, ARCH_AARCH64);
#elif defined(__arm__)
	ret = set_arch(ctx, ARCH_ARM);
#elif defined(__alpha__)
	ret = set_arch(ctx, ARCH_ALPHA);
#else
	ret = set_arch(ctx, ARCH_UNKNOWN);
#endif
	if (ret != kdump_ok)
		return ret;

	set_attr_static_string(ctx, GATTR(GKI_format_longname),
			       "Live memory source");
#if __BYTE_ORDER == __LITTLE_ENDIAN
	set_byte_order(ctx, kdump_little_endian);
#else
	set_byte_order(ctx, kdump_big_endian);
#endif

	ret = set_page_size(ctx, sysconf(_SC_PAGESIZE));
	if (ret != kdump_ok)
		return ret;

	dmp = ctx_malloc(sizeof *dmp, ctx, "Live source private data");
	if (!dmp)
		return kdump_syserr;
	ctx->fmtdata = dmp;

	get_vmcoreinfo(ctx);

	return kdump_ok;
}

static void
devmem_cleanup(kdump_ctx *ctx)
{
	free(ctx->priv);
	ctx->fmtdata = NULL;
}

const struct format_ops devmem_ops = {
	.name = "memory",
	.probe = devmem_probe,
	.read_page = devmem_read_page,
	.cleanup = devmem_cleanup,
};
