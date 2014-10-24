/* Routines for opening dumps.
   Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kdumpfile-priv.h"

static kdump_status kdump_open_known(kdump_ctx *pctx);
static kdump_status use_kernel_utsname(kdump_ctx *ctx);

static const struct format_ops *formats[] = {
	&kdump_elfdump_ops,
	&kdump_kvm_ops,
	&kdump_libvirt_ops,
	&kdump_xc_save_ops,
	&kdump_xc_core_ops,
	&kdump_diskdump_ops,
	&kdump_lkcd_ops,
	&kdump_mclxcd_ops,
	&kdump_s390_ops,
	&kdump_devmem_ops
};

#define NFORMATS	(sizeof formats / sizeof formats[0])

/* /dev/crash cannot handle reads larger than page size */
static int
paged_cpin(int fd, void *buffer, size_t size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	while (size) {
		size_t chunksize = (size > page_size)
			? page_size
			: size;
		if (read(fd, buffer, chunksize) != chunksize)
			return size;

		buffer += chunksize;
		size -= chunksize;
	}
	return 0;
}

kdump_status
kdump_fdopen(kdump_ctx **pctx, int fd)
{
	kdump_ctx *ctx;
	kdump_status ret;
	int i;

	ret = kdump_syserr;

	/* Initialize context */
	ctx = calloc(1, sizeof *ctx);
	if (!ctx)
		goto err;

	ctx->buffer = malloc(MAX_PAGE_SIZE);
	if (!ctx->buffer)
		goto err_ctx;

	ctx->fd = fd;

	if (paged_cpin(ctx->fd, ctx->buffer, MAX_PAGE_SIZE))
		goto err_ctx;

	for (i = 0; i < NFORMATS; ++i) {
		ctx->ops = formats[i];
		ret = ctx->ops->probe(ctx);
		if (ret == kdump_ok) {
			*pctx = ctx;
			return kdump_open_known(ctx);
		}
	}

  err_ctx:
	kdump_free(ctx);
  err:
	return ret;
}

static kdump_status
kdump_open_known(kdump_ctx *ctx)
{
	ctx->page = malloc(ctx->page_size);
	if (!ctx->page) {
		kdump_free(ctx);
		return kdump_syserr;
	}

	if (!(ctx->flags & DIF_UTSNAME))
		/* If this fails, it is not fatal. */
		use_kernel_utsname(ctx);

	if (ctx->xen_extra_ver)
		/* Return value ignored: if this fails, it is not fatal. */
		kdump_read_string(ctx, ctx->xen_extra_ver,
				  (char**)&ctx->xen_ver.extra,
				  KDUMP_XENMACHADDR);

	return kdump_ok;
}

static kdump_status
use_kernel_utsname(kdump_ctx *ctx)
{
	const char *sym_init_uts_ns;
	kdump_paddr_t init_uts_ns, uts_name;
	struct new_utsname uts;
	size_t rd;
	char *p;
	kdump_status ret;

	sym_init_uts_ns = kdump_vmcoreinfo_row(ctx, "SYMBOL(init_uts_ns)");
	if (!sym_init_uts_ns || !sym_init_uts_ns[0])
		return kdump_nodata;

	init_uts_ns = strtoull(sym_init_uts_ns, &p, 16);
	if (*p)
		return kdump_dataerr;

	rd = sizeof uts;
	ret = kdump_readp(ctx, init_uts_ns, (unsigned char*)&uts, &rd,
			  KDUMP_KVADDR);
	if (ret != kdump_ok)
		return ret;

	/* struct new_utsname is inside struct uts_namespace, preceded
	 * by a struct kref, but the offset is not stored in VMCOREINFO
	 * So, search some sane amount of memory for UTS_SYSNAME, which
	 * can be used as kind of a magic signature.
	 */
	for (p = uts.sysname; p <= uts.nodename; ++p)
		if (!memcmp(p, UTS_SYSNAME, sizeof(UTS_SYSNAME)))
			break;
	if (p > uts.nodename)
		return kdump_dataerr;

	uts_name = init_uts_ns + p - uts.sysname;
	rd = sizeof uts;
	ret = kdump_readp(ctx, uts_name, (unsigned char*)&uts, &rd,
			  KDUMP_KVADDR);
	if (ret != kdump_ok)
		return ret;

	if (!kdump_uts_looks_sane(&uts))
		return kdump_dataerr;

	kdump_set_uts(ctx, &uts);

	return kdump_ok;
}

void
kdump_free(kdump_ctx *ctx)
{
	if (ctx->ops && ctx->ops->free)
		ctx->ops->free(ctx);
	if (ctx->arch_ops && ctx->arch_ops->cleanup)
		ctx->arch_ops->cleanup(ctx);
	if (ctx->page)
		free(ctx->page);
	if (ctx->buffer)
		free(ctx->buffer);
	if (ctx->vmcoreinfo)
		free(ctx->vmcoreinfo);
	if (ctx->vmcoreinfo_xen)
		free(ctx->vmcoreinfo_xen);
	free(ctx);
}
