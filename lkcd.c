/* Routines to read LKCD dump files.
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

#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>

#define LKCD_DUMP_V1                  (0x1)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V2                  (0x2)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V3                  (0x3)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V5                  (0x5)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V6                  (0x6)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V7                  (0x7)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V8                  (0x8)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V9                  (0x9)  /* DUMP_VERSION_NUMBER */
#define LKCD_DUMP_V10                 (0xa)  /* DUMP_VERSION_NUMBER */

#define LKCD_DUMP_MCLX_V0            (0x80000000)   /* MCLX mod of LKCD */
#define LKCD_DUMP_MCLX_V1            (0x40000000)   /* Extra page header data */

#define LKCD_OFFSET_TO_FIRST_PAGE    (65536)

#define DUMP_PANIC_LEN 0x100

/* dump compression options */
#define DUMP_COMPRESS_NONE     0x0      /* don't compress this dump         */
#define DUMP_COMPRESS_RLE      0x1      /* use RLE compression              */
#define DUMP_COMPRESS_GZIP     0x2      /* use GZIP compression             */

/* common header fields for all versions */
struct dump_header_common {
	/* the dump magic number -- unique to verify dump is valid */
	uint64_t             dh_magic_number;

	/* the version number of this dump */
	uint32_t             dh_version;

	/* the size of this header (in case we can't read it) */
	uint32_t             dh_header_size;

	/* the level of this dump (just a header?) */
	uint32_t             dh_dump_level;

	/* the size of a Linux memory page (4K, 8K, 16K, etc.) */
	uint32_t             dh_page_size;

	/* the size of all physical memory */
	uint64_t             dh_memory_size;

	/* the start of physical memory */
	uint64_t             dh_memory_start;

	/* the end of physical memory */
	uint64_t             dh_memory_end;
} __attribute__((packed));

/* LKCDv1 32-bit variant */
struct dump_header_v1_32 {
	/* Known fields */
	struct dump_header_common common;

	/* the esp for i386 systems -- MOVE LATER */
	uint32_t             dh_esp;

	/* the eip for i386 systems -- MOVE LATER */
	uint32_t             dh_eip;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* the time of the system crash */
	struct timeval_32    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad2[2];

/* Other fields follow... */
} __attribute__((packed));

/* LKCDv1 64-bit variant */
struct dump_header_v1_64 {
	/* Known fields */
	struct dump_header_common common;

	/* the esp for i386 systems -- MOVE LATER */
	uint32_t             dh_esp;

	/* the eip for i386 systems -- MOVE LATER */
	uint32_t             dh_eip;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* alignment */
	char                 _pad1[4];

	/* the time of the system crash */
	struct timeval_64    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad2[2];

/* Other fields follow... */
} __attribute__((packed));

/* LKCDv2 .. LKCDv7 32-bit variant */
struct dump_header_v2_32 {
	/* Known fields */
	struct dump_header_common common;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* the time of the system crash */
	struct timeval_32    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad1[2];

	/* the address of current task */
	uint32_t             dh_current_task;

/* following fields only in LKCDv5+ */

	/* type of compression used in this dump */
	uint32_t             dh_dump_compress;

	/* any additional flags */
	uint32_t             dh_dump_flags;

	/* dump device */
	uint32_t             dh_dump_device;
} __attribute__((packed));

/* LKCDv2 .. LKCDv7 64-bit variant */
struct dump_header_v2_64 {
	/* Known fields */
	struct dump_header_common common;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* alignment */
	char                 _pad1[4];

	/* the time of the system crash */
	struct timeval_64    dh_time;

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* alignment */
	char                 _pad2[2];

	/* the address of current task */
	uint64_t             dh_current_task;

/* following fields only in LKCDv5+ */

	/* type of compression used in this dump */
	uint32_t             dh_dump_compress;

	/* any additional flags */
	uint32_t             dh_dump_flags;

	/* dump device */
	uint32_t             dh_dump_device;
} __attribute__((packed));

/* LKCDv8 unified variant */
struct dump_header_v8 {
	/* Known fields */
	struct dump_header_common common;

	/* the number of pages in this dump specifically */
	uint32_t             dh_num_pages;

	/* the panic string, if available */
	char                 dh_panic_string[DUMP_PANIC_LEN];

	/* timeval depends on architecture, two long values */
	struct {
		uint64_t tv_sec;
		uint64_t tv_usec;
	} dh_time; /* the time of the system crash */

	/* the utsname (uname) information */
	struct new_utsname   dh_utsname;

	/* the address of current task */
	uint64_t             dh_current_task;

	/* what type of compression we're using in this dump (if any) */
	uint32_t             dh_dump_compress;

	/* any additional flags */
	uint32_t             dh_dump_flags;

	/* any additional flags */
	uint32_t             dh_dump_device;

/* following fields only in LKCDv9+ */

	/* size of dump buffer */
	uint64_t             dh_dump_buffer_size;
} __attribute__((packed));

/* dump_page flags */
#define DUMP_RAW            0x1      /* raw page (no compression)        */
#define DUMP_COMPRESSED     0x2      /* page is compressed               */
#define DUMP_END            0x4      /* end marker on a full dump        */

struct dump_page {
	/* the address of this dump page */
        uint64_t             dp_address;

        /* the size of this dump page */
        uint32_t             dp_size;

        /* flags (currently DUMP_COMPRESSED, DUMP_RAW or DUMP_END) */
        uint32_t             dp_flags;
} __attribute__((packed));

/* Split the 32-bit PFN into 3 indices */
#define PFN_IDX1_BITS	10
#define PFN_IDX2_BITS	10
#define PFN_IDX3_BITS	12

#define PFN_IDX1_SIZE	((uint32_t)1 << PFN_IDX1_BITS)
#define PFN_IDX2_SIZE	((uint32_t)1 << PFN_IDX2_BITS)
#define PFN_IDX3_SIZE	((uint32_t)1 << PFN_IDX3_BITS)

#define pfn_idx1(pfn) \
	((uint32_t)(pfn) >> (PFN_IDX3_BITS + PFN_IDX2_BITS))
#define pfn_idx2(pfn) \
	(((uint32_t)(pfn) >> PFN_IDX3_BITS) & (PFN_IDX2_SIZE - 1))
#define pfn_idx3(pfn) \
	((uint32_t)(pfn) & (PFN_IDX3_SIZE - 1))

/* Level-3 tables contain only a 32-bit offset from the level-2 page
 * beginning, cutting their size by 50%. A 32-bit offset must be
 * enough, because max page shift is 18 and pfn_idx3 has 12 bits:
 * 18 + 12 = 30 and 30 < 32
 */

struct pfn_level2 {
	off_t off;
	uint32_t *pfn_level3;
};

/* Maximum size of the format name: the version field is a 32-bit integer,
 * so it cannot be longer than 10 decimal digits.
 */
#define LKCD_FORMAT_PFX	"LKCD v"
#define MAX_FORMAT_NAME	(sizeof(LKCD_FORMAT_PFX) + 10)

struct lkcd_priv {
	off_t data_offset;	/* offset to 1st page */
	unsigned version;
	unsigned compression;
	struct pfn_level2 **pfn_level1;
	char format[MAX_FORMAT_NAME];
};

static off_t
find_page(kdump_ctx *ctx, off_t off, unsigned pfn, struct dump_page *dp)
{
	uint64_t addr = pfn * ctx->page_size;

	for ( ;; ) {
		if (pread(ctx->fd, dp, sizeof *dp, off) != sizeof *dp)
			return -1;
		dp->dp_address = dump64toh(ctx, dp->dp_address);
		dp->dp_size = dump32toh(ctx, dp->dp_size);
		if (dp->dp_address >= addr)
			break;
		off += sizeof(struct dump_page) + dp->dp_size;
	}

	dp->dp_flags = dump32toh(ctx, dp->dp_flags);
	return off;
}

static kdump_status
fill_level1(kdump_ctx *ctx, unsigned endidx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	off_t off = lkcdp->data_offset;
	struct pfn_level2 **p;
	unsigned idx;

	for (p = lkcdp->pfn_level1, idx = 0; idx < endidx; ++p, ++idx) {
		if (!*p)
			break;
		off = (*p)->off;
	}

	for ( ; idx <= endidx; ++p, ++idx) {
		struct dump_page dp;
		uint32_t pfn;

		*p = calloc(PFN_IDX2_SIZE, sizeof(struct pfn_level2));
		if (!*p)
			return kdump_syserr;
		pfn = idx << (PFN_IDX3_BITS + PFN_IDX2_BITS);
		if ( (off = find_page(ctx, off, pfn, &dp)) < 0)
			return kdump_syserr;
		(*p)->off = off;
	}

	return kdump_ok;
}

static kdump_status
fill_level2(kdump_ctx *ctx, unsigned idx1, unsigned endidx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct pfn_level2 *p = lkcdp->pfn_level1[idx1];
	off_t off, baseoff;
	struct dump_page dp;
	uint32_t pfn;
	uint32_t *pp;
	unsigned idx;

	baseoff = p->off;
	for (idx = 0; idx <= endidx; ++p, ++idx) {
		if (!p->pfn_level3)
			break;
		baseoff = p->off;
	}

	pfn = ((idx1 << PFN_IDX2_BITS) + idx) << PFN_IDX3_BITS;
	for ( ; idx < endidx; ++p, ++idx) {
		if ( (baseoff = find_page(ctx, baseoff, pfn, &dp)) < 0)
			return kdump_syserr;
		p->off = baseoff;
		pfn += PFN_IDX3_SIZE;
	}
	if (idx) {
		if ( (baseoff = find_page(ctx, baseoff, pfn, &dp)) < 0)
			return kdump_syserr;
		p->off = baseoff;
	}

	pp = malloc(PFN_IDX3_SIZE * sizeof(uint32_t));
	if (!pp)
		return kdump_syserr;
	p->pfn_level3 = pp;
	memset(pp, -1, PFN_IDX3_SIZE * sizeof(uint32_t));

	off = baseoff;
	for (idx = 0; idx < PFN_IDX3_SIZE; ++idx, ++pp) {
		if ( (off = find_page(ctx, off, pfn, &dp)) < 0)
			break;
		if (dp.dp_address == pfn * ctx->page_size)
			*pp = off - baseoff;
		pfn++;
	}

	return kdump_ok;
}

static kdump_status
lkcd_read_page(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct pfn_level2 *pfn_level2;
	uint32_t *pfn_level3;
	unsigned idx1, idx2, idx3;
	struct dump_page dp;
	unsigned type;
	off_t off;
	void *buf;
	kdump_status ret;

	if (pfn == ctx->last_pfn)
		return kdump_ok;

	if (pfn >= ctx->max_pfn)
		return kdump_nodata;

	idx1 = pfn_idx1(pfn);
	if (!lkcdp->pfn_level1[idx1]) {
		ret = fill_level1(ctx, idx1);
		if (ret != kdump_ok)
			return ret;
	}
	pfn_level2 = lkcdp->pfn_level1[idx1];

	idx2 = pfn_idx2(pfn);
	if (!pfn_level2[idx2].pfn_level3) {
		ret = fill_level2(ctx, idx1, idx2);
		if (ret != kdump_ok)
			return ret;
	}
	off = pfn_level2[idx2].off;
	pfn_level3 = pfn_level2[idx2].pfn_level3;

	idx3 = pfn_idx3(pfn);
	if (pfn_level3[idx3] == (uint32_t)-1)
		return kdump_nodata;
	off += pfn_level3[idx3];

	if (find_page(ctx, off, pfn, &dp) < 0)
		return kdump_syserr;
	off += sizeof(struct dump_page);

	type = dp.dp_flags & (DUMP_COMPRESSED|DUMP_RAW);
	switch (type) {
	case DUMP_COMPRESSED:
		if (dp.dp_size > MAX_PAGE_SIZE)
			return kdump_dataerr;
		buf = ctx->buffer;
		break;
	case DUMP_RAW:
		if (dp.dp_size != ctx->page_size)
			return kdump_dataerr;
		buf = ctx->page;
		break;
	default:
		return kdump_unsupported;
	}

	/* read page data */
	if (pread(ctx->fd, buf, dp.dp_size, off) != dp.dp_size)
		return kdump_syserr;

	if (type == DUMP_RAW)
		goto out;

	if (lkcdp->compression == DUMP_COMPRESS_RLE) {
		size_t retlen = ctx->page_size;
		int ret = kdump_uncompress_rle(ctx->page, &retlen,
					       buf, dp.dp_size);
		if (ret)
			return kdump_dataerr;
	} else if (lkcdp->compression == DUMP_COMPRESS_GZIP) {
		uLongf retlen = ctx->page_size;
		int ret = uncompress(ctx->page, &retlen,
				     buf, dp.dp_size);
		if ((ret != Z_OK) || (retlen != ctx->page_size))
			return kdump_dataerr;
	} else
		return kdump_unsupported;

  out:
	ctx->last_pfn = pfn;
	return kdump_ok;
}

static inline unsigned long
base_version(uint32_t version)
{
	return version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1);
}

static kdump_status
init_v1(kdump_ctx *ctx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct dump_header_v1_32 *dh32 = ctx->buffer;
	struct dump_header_v1_64 *dh64 = ctx->buffer;

	if (!kdump_uts_looks_sane(&dh32->dh_utsname) &&
	    kdump_uts_looks_sane(&dh64->dh_utsname))
		kdump_set_uts(ctx, &dh64->dh_utsname);
	else
		kdump_set_uts(ctx, &dh32->dh_utsname);
	lkcdp->compression = DUMP_COMPRESS_RLE;

	return kdump_ok;
}

static kdump_status
init_v2(kdump_ctx *ctx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct dump_header_v2_32 *dh32 = ctx->buffer;
	struct dump_header_v2_64 *dh64 = ctx->buffer;

	if (!kdump_uts_looks_sane(&dh32->dh_utsname) &&
	    kdump_uts_looks_sane(&dh64->dh_utsname)) {
		kdump_set_uts(ctx, &dh64->dh_utsname);
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(ctx, dh64->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
	} else {
		kdump_set_uts(ctx, &dh32->dh_utsname);
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(ctx, dh32->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
	}

	return kdump_ok;
}

static int
init_v8(kdump_ctx *ctx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct dump_header_v8 *dh = ctx->buffer;

	kdump_set_uts(ctx, &dh->dh_utsname);
	lkcdp->compression = dump32toh(ctx, dh->dh_dump_compress);
	if (lkcdp->version >= LKCD_DUMP_V9)
		lkcdp->data_offset = dump64toh(ctx, dh->dh_dump_buffer_size);

	return 0;
}

static kdump_status
open_common(kdump_ctx *ctx)
{
	struct dump_header_common *dh = ctx->buffer;
	struct lkcd_priv *lkcdp;
	unsigned max_idx1;
	kdump_status ret;

	lkcdp = malloc(sizeof *lkcdp);
	if (!lkcdp)
		return kdump_syserr;

	lkcdp->version = base_version(dump32toh(ctx, dh->dh_version));
	snprintf(lkcdp->format, sizeof(lkcdp->format),
		 "LKCD v%u", lkcdp->version);

	lkcdp->data_offset = LKCD_OFFSET_TO_FIRST_PAGE;

	ctx->format = lkcdp->format;
	ctx->page_size = dump32toh(ctx, dh->dh_page_size);
	ctx->max_pfn = dump64toh(ctx, dh->dh_memory_size);
	ctx->fmtdata = lkcdp;

	switch(lkcdp->version) {
	case LKCD_DUMP_V1:
		ret = init_v1(ctx);
		break;

	case LKCD_DUMP_V2:
	case LKCD_DUMP_V3:
	case LKCD_DUMP_V5:
	case LKCD_DUMP_V6:
	case LKCD_DUMP_V7:
		ret = init_v2(ctx);
		break;

	case LKCD_DUMP_V8:
	case LKCD_DUMP_V9:
	case LKCD_DUMP_V10:
		ret = init_v8(ctx);
		break;

	default:
		ret = kdump_unsupported;
	}

	if (ret != kdump_ok)
		goto err_free;

	ret = kdump_set_arch(ctx, kdump_machine_arch(ctx->utsname.machine));
	if (ret != kdump_ok)
		goto err_free;

	ret = kdump_syserr;
	max_idx1 = pfn_idx1(ctx->max_pfn - 1) + 1;
	lkcdp->pfn_level1 = calloc(max_idx1, sizeof(struct pfn_level2*));
	if (!lkcdp->pfn_level1)
		goto err_free;

	return kdump_ok;

  err_free:
	free(lkcdp);
	return ret;
}

static kdump_status
lkcd_probe(kdump_ctx *ctx)
{
	static const char magic_le[] =
		{ 0xed, 0x23, 0x8f, 0x61, 0x73, 0x01, 0x19, 0xa8 };
	static const char magic_be[] =
		{ 0xa8, 0x19, 0x01, 0x73, 0x61, 0x8f, 0x23, 0xed };

	if (!memcmp(ctx->buffer, magic_le, sizeof magic_le))
		ctx->endian = __LITTLE_ENDIAN;
	else if (!memcmp(ctx->buffer, magic_be, sizeof magic_be))
		ctx->endian = __BIG_ENDIAN;
	else
		return kdump_unsupported;

	return open_common(ctx);
}

static void
free_level2(struct pfn_level2 *level2)
{
	if (level2) {
		unsigned i;
		for (i = 0; i < PFN_IDX2_SIZE; ++i)
			if (level2[i].pfn_level3)
				free(level2[i].pfn_level3);
		free(level2);
	}
}

static void
free_level1(struct pfn_level2 **level1, unsigned long n)
{
	if (level1) {
		unsigned long i;
		for (i = 0; i < n; ++i)
			free_level2(level1[i]);
		free(level1);
	}
}

static void
lkcd_cleanup(kdump_ctx *ctx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;

	free_level1(lkcdp->pfn_level1, pfn_idx1(ctx->max_pfn - 1) + 1);
	free(lkcdp);
	ctx->fmtdata = NULL;
}

const struct format_ops kdump_lkcd_ops = {
	.probe = lkcd_probe,
	.read_page = lkcd_read_page,
	.cleanup = lkcd_cleanup,
};
