/* Functions for the s390x architecture.
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

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	64
#define VIRTADDR_MAX		UINT64_MAX

/* As of Linux 3.17, region-first tables are not used, but since the
 * architecture limits are already defined, why not prepare in advance?
 * Assume that the maximum table length will be used then...
 */
#define REG1_SHIFT	53
#define PTRS_PER_REG1	2048

#define PGDIR_SHIFT	42
#define PTRS_PER_PGD	2048

#define PUD_SHIFT	31
#define PUD_PSE_SIZE	((uint64_t)1 << PUD_SHIFT)
#define PUD_PSE_MASK	(~(PUD_PSE_SIZE-1))
#define PTRS_PER_PUD	2048

#define PMD_SHIFT	20
#define PMD_PSE_SIZE	((uint64_t)1 << PMD_SHIFT)
#define PMD_PSE_MASK	(~(PMD_PSE_SIZE-1))
#define PTRS_PER_PMD	2048

#define PAGE_SHIFT	12
#define PAGE_SIZE	((uint64_t)1 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))
#define PTRS_PER_PTE	256

struct s390x_data {
	uint64_t *pgt;
};

static kdump_status
s390x_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr)
{
	return kdump_unsupported;
}

static kdump_status
read_pgt(kdump_ctx *ctx, kdump_vaddr_t pgtaddr)
{
	struct s390x_data *archdata = ctx->archdata;
	uint64_t *pgt;
	size_t sz;
	kdump_status ret;

	pgt = malloc(sizeof(uint64_t) * PTRS_PER_PGD);
	if (!pgt)
		return kdump_syserr;

	sz = sizeof(uint64_t) * PTRS_PER_PGD;
	ret = kdump_readp(ctx, pgtaddr, pgt, &sz, KDUMP_PHYSADDR);
	if (ret == kdump_ok)
		archdata->pgt = pgt;
	else
		free(pgt);

	return ret;
}

static kdump_status
s390x_vtop_init(kdump_ctx *ctx)
{
	struct s390x_data *archdata = ctx->archdata;
	kdump_vaddr_t addr;
	kdump_status ret;

	if (!archdata->pgt && kdump_vmcoreinfo_symbol(ctx, "swapper_pg_dir",
						      &addr) == kdump_ok) {
		ret = read_pgt(ctx, addr);
		if (ret != kdump_ok)
			return ret;
	}

	if (archdata->pgt) {
		ret = kdump_set_region(ctx, 0, VIRTADDR_MAX,
				       KDUMP_XLAT_VTOP, 0);
		if (ret != kdump_ok)
			return ret;
	}

	ret = kdump_vmcoreinfo_symbol(ctx, "high_memory", &addr);
	if (ret == kdump_ok) {
		uint64_t highmem;
		size_t sz = sizeof(highmem);
		/* In identity mapping virtual == physical */
		ret = kdump_readp(ctx, addr, &highmem, &sz, KDUMP_PHYSADDR);
		if (ret != kdump_ok)
			return ret;
		highmem = dump64toh(ctx, highmem);

		ret = kdump_set_region(ctx, 0, highmem, KDUMP_XLAT_DIRECT, 0);
		if (ret != kdump_ok)
			return ret;
	} else if (!archdata->pgt)
		return kdump_nodata;

	return kdump_ok;
}

static kdump_status
s390x_init(kdump_ctx *ctx)
{
	ctx->archdata = calloc(1, sizeof(struct s390x_data));
	if (!ctx->archdata)
		return kdump_syserr;

	s390x_vtop_init(ctx);

	return kdump_ok;
}

static void
s390x_cleanup(kdump_ctx *ctx)
{
	struct s390x_data *archdata = ctx->archdata;

	if (archdata->pgt)
		free(archdata->pgt);

	free(archdata);
	ctx->archdata = NULL;
}

const struct arch_ops kdump_s390x_ops = {
	.init = s390x_init,
	.vtop_init = s390x_vtop_init,
	.vtop = s390x_vtop,
	.cleanup = s390x_cleanup,
};
