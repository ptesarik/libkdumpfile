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

#include "kdumpfile-priv.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/version.h>

static kdump_status kdump_open_known(kdump_ctx *pctx);
static kdump_status use_kernel_utsname(kdump_ctx *ctx);
static kdump_status get_version_code(kdump_ctx *ctx);

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
	ctx->last_pfn = -(kdump_paddr_t)1;

	ctx->buffer = malloc(MAX_PAGE_SIZE);
	if (!ctx->buffer)
		goto err_ctx;

	ctx->fd = fd;

	if (kdump_paged_cpin(ctx->fd, ctx->buffer, MAX_PAGE_SIZE))
		goto err_ctx;

	for (i = 0; i < ARRAY_SIZE(formats); ++i) {
		ctx->ops = formats[i];
		ret = ctx->ops->probe(ctx);
		if (ret == kdump_ok) {
			*pctx = ctx;
			return kdump_open_known(ctx);
		}
	}
	ctx->ops = NULL;

  err_ctx:
	kdump_free(ctx);
  err:
	return ret;
}

static kdump_status
kdump_open_known(kdump_ctx *ctx)
{
	kdump_status ret;

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

	get_version_code(ctx);

	if (ctx->arch_ops && ctx->arch_ops->late_init) {
		ret = ctx->arch_ops->late_init(ctx);
		if (ret != kdump_ok)
			return ret;
	}

	return kdump_ok;
}

/* struct new_utsname is inside struct uts_namespace, preceded by a struct
 * kref, but the offset is not stored in VMCOREINFO. So, search some sane
 * amount of memory for UTS_SYSNAME, which can be used as kind of a magic
 * signature.
 */
static kdump_status
uts_name_from_init_uts_ns(kdump_ctx *ctx, kdump_vaddr_t *uts_name)
{
	kdump_vaddr_t init_uts_ns;
	char buf[2 * NEW_UTS_LEN + sizeof(UTS_SYSNAME)];
	char *p;
	size_t rd;
	kdump_status ret;

	ret = kdump_vmcoreinfo_symbol(ctx, "init_uts_ns", &init_uts_ns);
	if (ret != kdump_ok)
		return ret;

	rd = sizeof buf;
	ret = kdump_readp(ctx, init_uts_ns, buf, &rd, KDUMP_KVADDR);
	if (ret != kdump_ok)
		return ret;

	for (p = buf; p <= &buf[2 * NEW_UTS_LEN]; ++p)
		if (!memcmp(p, UTS_SYSNAME, sizeof(UTS_SYSNAME)))
			break;
	if (p > &buf[2 * NEW_UTS_LEN])
		return kdump_dataerr;

	*uts_name = init_uts_ns + p - buf;
	return kdump_ok;
}

static kdump_status
use_kernel_utsname(kdump_ctx *ctx)
{
	kdump_vaddr_t uts_name;
	struct new_utsname uts;
	size_t rd;
	kdump_status ret;

	ret = kdump_vmcoreinfo_symbol(ctx, "system_utsname", &uts_name);
	if (ret == kdump_nodata)
		ret = uts_name_from_init_uts_ns(ctx, &uts_name);
	if (ret != kdump_ok)
		return ret;

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

static kdump_status
get_version_code(kdump_ctx *ctx)
{
	const char *p;
	char *endp;
	long a, b, c;

	p = ctx->utsname.release;
	a = strtoul(p, &endp, 10);
	if (endp == p || *endp != '.')
		return kdump_dataerr;

	b = c = 0L;
	if (*endp) {
		p = endp + 1;
		b = strtoul(p, &endp, 10);
		if (endp == p || *endp != '.')
			return kdump_dataerr;

		if (*endp) {
			p = endp + 1;
			c = strtoul(p, &endp, 10);
			if (endp == p)
				return kdump_dataerr;
		}
	}

	ctx->version_code = KERNEL_VERSION(a, b, c);
	return kdump_ok;
}

void
kdump_free(kdump_ctx *ctx)
{
	if (ctx->ops && ctx->ops->cleanup)
		ctx->ops->cleanup(ctx);
	if (ctx->arch_ops && ctx->arch_ops->cleanup)
		ctx->arch_ops->cleanup(ctx);
	if (ctx->page)
		free(ctx->page);
	if (ctx->buffer)
		free(ctx->buffer);
	if (ctx->region)
		free(ctx->region);
	if (ctx->vmcoreinfo)
		free(ctx->vmcoreinfo);
	if (ctx->vmcoreinfo_xen)
		free(ctx->vmcoreinfo_xen);
	free(ctx);
}
