/* Routines to read from /dev/mem.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kdumpfile-priv.h"

static kdump_status
devmem_read_page(kdump_ctx *ctx, kdump_paddr_t pfn)
{
	off_t pos = pfn * ctx->page_size;
	if (pread(ctx->fd, ctx->page, ctx->page_size, pos) != ctx->page_size)
		return kdump_syserr;
	return kdump_ok;
}

static kdump_status
devmem_probe(kdump_ctx *ctx)
{
	struct stat st;

	if (fstat(ctx->fd, &st))
		return kdump_syserr;

	if (!S_ISCHR(st.st_mode) ||
	    (st.st_rdev != makedev(1, 1) &&
	    major(st.st_rdev) != 10))
		return kdump_unsupported;

	ctx->format = "live source";
	ctx->page_size = sysconf(_SC_PAGESIZE);

	return kdump_ok;
}

const struct kdump_ops kdump_devmem_ops = {
	.probe = devmem_probe,
	.read_page = devmem_read_page,
};
