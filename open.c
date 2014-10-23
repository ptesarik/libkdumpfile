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

	if (ctx->xen_extra_ver)
		/* Return value ignored: if this fails, it is not fatal. */
		kdump_read_string(ctx, ctx->xen_extra_ver,
				  (char**)&ctx->xen_ver.extra,
				  KDUMP_XENMACHADDR);

	return kdump_ok;
}

void
kdump_free(kdump_ctx *ctx)
{
	if (ctx->ops && ctx->ops->free)
		ctx->ops->free(ctx);
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
