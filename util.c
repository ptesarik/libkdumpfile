/* Utility functions.
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

#include <string.h>

#include "kdumpfile-priv.h"

const char *
kdump_format(kdump_ctx *ctx)
{
	return ctx->format;
}

size_t
kdump_pagesize(kdump_ctx *ctx)
{
	return ctx->page_size;
}

const char *
kdump_sysname(kdump_ctx *ctx)
{
	return ctx->utsname.sysname;
}

const char *
kdump_nodename(kdump_ctx *ctx)
{
	return ctx->utsname.nodename;
}

const char *
kdump_release(kdump_ctx *ctx)
{
	return ctx->utsname.release;
}

const char *
kdump_version(kdump_ctx *ctx)
{
	return ctx->utsname.version;
}

const char *
kdump_machine(kdump_ctx *ctx)
{
	return ctx->utsname.machine;
}

const char *
kdump_domainname(kdump_ctx *ctx)
{
	return ctx->utsname.domainname;
}

const char *
kdump_vmcoreinfo(kdump_ctx *ctx)
{
	return ctx->vmcoreinfo;
}

const char *
kdump_vmcoreinfo_xen(kdump_ctx *ctx)
{
	return ctx->vmcoreinfo_xen;
}

const size_t
kdump_arch_ptr_size(enum kdump_arch arch)
{
	switch (arch) {
	case ARCH_ALPHA:
	case ARCH_IA64:
	case ARCH_PPC64:
	case ARCH_PPC64LE:
	case ARCH_S390X:
	case ARCH_X86_64:
		return 8;	/* 64 bits */

	case ARCH_ARM:
	case ARCH_PPC:
	case ARCH_S390:
	case ARCH_X86:
	default:
		return 4;	/* 32 bits */
	}

}

/* Final NUL may be missing in the source (i.e. corrupted dump data),
 * but let's make sure that it is present in the destination.
 */
void
kdump_copy_uts_string(char *dest, const char *src)
{
	if (!*dest) {
		memcpy(dest, src, NEW_UTS_LEN);
		dest[NEW_UTS_LEN] = 0;
	}
}

void
kdump_copy_uts(struct new_utsname *dest, const struct new_utsname *src)
{
	kdump_copy_uts_string(dest->sysname, src->sysname);
	kdump_copy_uts_string(dest->nodename, src->nodename);
	kdump_copy_uts_string(dest->release, src->release);
	kdump_copy_uts_string(dest->version, src->version);
	kdump_copy_uts_string(dest->machine, src->machine);
	kdump_copy_uts_string(dest->domainname, src->domainname);
}

int
kdump_uts_looks_sane(struct new_utsname *uts)
{
	return uts->sysname[0] && uts->nodename[0] && uts->release[0] &&
		uts->version[0] && uts->machine[0];
}

int
kdump_uncompress_rle(unsigned char *dst, size_t *pdstlen,
		     const unsigned char *src, size_t srclen)
{
	const unsigned char *srcend = src + srclen;
	size_t remain = *pdstlen;

	while (src < srcend) {
		unsigned char byte, cnt;

		if (! (byte = *src++)) {
			if (src >= srcend)
				return -1;
			if ( (cnt = *src++) ) {
				if (remain < cnt)
					return -1;
				if (src >= srcend)
					return -1;
				memset(dst, *src++, cnt);
				dst += cnt;
				remain -= cnt;
				continue;
			}
		}

		if (!remain)
			return -1;
		*dst++ = byte;
		--remain;
	}

	*pdstlen -= remain;
	return 0;
}

kdump_status
kdump_store_vmcoreinfo(kdump_ctx *ctx, void *info, size_t len)
{
	ctx->vmcoreinfo = malloc(len + 1);
	if (!ctx->vmcoreinfo)
		return kdump_syserr;

	memcpy(ctx->vmcoreinfo, info, len);
	ctx->vmcoreinfo[len] = '\0';

	return kdump_ok;
}

kdump_status
kdump_store_vmcoreinfo_xen(kdump_ctx *ctx, void *info, size_t len)
{
	ctx->vmcoreinfo_xen = malloc(len + 1);
	if (!ctx->vmcoreinfo_xen)
		return kdump_syserr;

	memcpy(ctx->vmcoreinfo_xen, info, len);
	ctx->vmcoreinfo_xen[len] = '\0';

	return kdump_ok;
}
