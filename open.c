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

typedef kdump_status (*open_fn)(kdump_ctx *ctx);

struct crash_file {
	const char *magic;
	size_t magicsz;
	open_fn handler;
};

static const char magic_elfdump[] =
	{ '\177', 'E', 'L', 'F' };
static const char magic_kvm[] =
	{ 'Q', 'E', 'V', 'M' };
static const char magic_libvirt[] =
	{ 'L', 'i', 'b', 'v' };
static const char magic_xc_save[] =
	{ 'L', 'i', 'n', 'u', 'x', 'G', 'u', 'e',
	  's', 't', 'R', 'e', 'c', 'o', 'r', 'd' };
static const char magic_xc_core[] =
	{ 0xed, 0xeb, 0x0f, 0xf0 };
static const char magic_xc_core_hvm[] =
	{ 0xee, 0xeb, 0x0f, 0xf0 };
static const char magic_diskdump[] =
	{ 'D', 'I', 'S', 'K', 'D', 'U', 'M', 'P' };
static const char magic_kdump[] =
	{ 'K', 'D', 'U', 'M', 'P', ' ', ' ', ' ' };
static const char magic_lkcd_le[] =
	{ 0xed, 0x23, 0x8f, 0x61, 0x73, 0x01, 0x19, 0xa8 };
static const char magic_lkcd_be[] =
	{ 0xa8, 0x19, 0x01, 0x73, 0x61, 0x8f, 0x23, 0xed };
static const char magic_mclxcd[] =
	{ 0xdd, 0xcc, 0x8b, 0x9a };
static const char magic_s390[] =
	{ 0xa8, 0x19, 0x01, 0x73, 0x61, 0x8f, 0x23, 0xfd };
static const char magic_devmem[0];


static kdump_status
kdump_open_elfdump(kdump_ctx *ctx)
{
	/* ELF dump not yet implemented */
	ctx->format = "ELF dump";
	return kdump_unsupported;
}

static kdump_status
kdump_open_kvm(kdump_ctx *ctx)
{
	/* KVM dump not yet implemented */
	ctx->format = "KVM";
	return kdump_unsupported;
}

static kdump_status
kdump_open_libvirt(kdump_ctx *ctx)
{
	/* Libvirt dump not yet implemented */
	ctx->format = "Libvirt";
	return kdump_unsupported;
}

static kdump_status
kdump_open_xc_save(kdump_ctx *ctx)
{
	/* Xen xc_save not yet implemented */
	ctx->format = "Xen xc_save";
	return kdump_unsupported;
}

static kdump_status
kdump_open_xc_core(kdump_ctx *ctx)
{
	/* Xen xc_core not yet implemented */
	ctx->format = "Xen xc_core";
	return kdump_unsupported;
}

static kdump_status
kdump_open_xc_core_hvm(kdump_ctx *ctx)
{
	/* Xen xc_core HVM not yet implemented */
	ctx->format = "Xen xc_core hvm";
	return kdump_unsupported;
}

static kdump_status
kdump_open_diskdump(kdump_ctx *ctx)
{
	/* Diskdump not yet implemented */
	ctx->format = "diskdump";
	return kdump_unsupported;
}

static kdump_status
kdump_open_kdump(kdump_ctx *ctx)
{
	/* Compressed kdump not yet implemented */
	ctx->format = "compressed kdump";
	return kdump_unsupported;
}

static kdump_status
kdump_open_lkcd_le(kdump_ctx *ctx)
{
	/* LKCD not yet implemented */
	ctx->format = "LKCD";
	return kdump_unsupported;
}

static kdump_status
kdump_open_lkcd_be(kdump_ctx *ctx)
{
	/* LKCD not yet implemented */
	ctx->format = "LKCD";
	return kdump_unsupported;
}

static kdump_status
kdump_open_mclxcd(kdump_ctx *ctx)
{
	/* MCLXCD dump not yet implemented */
	ctx->format = "MCLXCD";
	return kdump_unsupported;
}

static kdump_status
kdump_open_s390(kdump_ctx *ctx)
{
	/* S/390 dump not yet implemented */
	ctx->format = "S390";
	return kdump_unsupported;
}

static kdump_status
kdump_open_devmem(kdump_ctx *ctx)
{
	/* Live source not yet implemented */
	ctx->format = "live source";
	return kdump_unsupported;
}

#define FORMAT(x)	\
	{ magic_ ## x, sizeof(magic_ ## x), kdump_open_ ## x }
static const struct crash_file formats[] = {
	FORMAT(elfdump),
	FORMAT(kvm),
	FORMAT(libvirt),
	FORMAT(xc_save),
	FORMAT(xc_core),
	FORMAT(xc_core_hvm),
	FORMAT(diskdump),
	FORMAT(kdump),
	FORMAT(lkcd_le),
	FORMAT(lkcd_be),
	FORMAT(mclxcd),
	FORMAT(s390),
	FORMAT(devmem),
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
		ret = kdump_unsupported;
		if (memcmp(ctx->buffer, formats[i].magic, formats[i].magicsz))
			continue;

		ret = formats[i].handler(ctx);
		if (ret == kdump_ok)
			break;
	}
	if (ret != kdump_ok)
		goto err_ctx;

	ctx->page = malloc(ctx->page_size);
	if (!ctx->page) {
		ret = kdump_syserr;
		goto err_ctx;
	}

	return kdump_ok;

  err_ctx:
	kdump_free(ctx);
  err:
	return ret;
}

void
kdump_free(kdump_ctx *ctx)
{
	if (ctx->page)
		free(ctx->page);
	if (ctx->buffer)
		free(ctx->buffer);
	free(ctx);
}
