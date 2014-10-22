/* Routines to read diskdump/compressed kdump files.
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

#include <unistd.h>
#include <string.h>
#include <zlib.h>
#include <lzo/lzo1x.h>
#include <snappy-c.h>

#include "kdumpfile-priv.h"

#define SIG_LEN	8

/* The header is architecture-dependent, unfortunately */
struct disk_dump_header_32 {
	char			signature[SIG_LEN];	/* = "DISKDUMP" */
	int32_t			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	char			_pad1[2];	/* alignment */
	struct timeval_32	timestamp;	/* Time stamp */
	uint32_t		status; 	/* Above flags */
	int32_t			block_size;	/* Size of a block in byte */
	int32_t			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	uint32_t		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	uint32_t		max_mapnr;	/* = max_mapnr */
	uint32_t		total_ram_blocks;/* Number of blocks should be
						   written */
	uint32_t		device_blocks;	/* Number of total blocks in
						 * the dump device */
	uint32_t		written_blocks; /* Number of written blocks */
	uint32_t		current_cpu;	/* CPU# which handles dump */
	int32_t			nr_cpus;	/* Number of CPUs */
	uint32_t		tasks[0];	/* "struct task_struct *" */
} __attribute__((packed));

/* The header is architecture-dependent, unfortunately */
struct disk_dump_header_64 {
	char			signature[SIG_LEN];	/* = "DISKDUMP" */
	int32_t			header_version; /* Dump header version */
	struct new_utsname	utsname;	/* copy of system_utsname */
	char			_pad1[6];	/* alignment */
	struct timeval_64	timestamp;	/* Time stamp */
	uint32_t		status; 	/* Above flags */
	int32_t			block_size;	/* Size of a block in byte */
	int32_t			sub_hdr_size;	/* Size of arch dependent
						   header in blocks */
	uint32_t		bitmap_blocks;	/* Size of Memory bitmap in
						   block */
	uint32_t		max_mapnr;	/* = max_mapnr */
	uint32_t		total_ram_blocks;/* Number of blocks should be
						   written */
	uint32_t		device_blocks;	/* Number of total blocks in
						 * the dump device */
	uint32_t		written_blocks; /* Number of written blocks */
	uint32_t		current_cpu;	/* CPU# which handles dump */
	int32_t			nr_cpus;	/* Number of CPUs */
	uint64_t		tasks[0];	/* "struct task_struct *" */
} __attribute__((packed));

/* descriptor of each page for vmcore */
struct page_desc {
	uint64_t	offset;		/* the offset of the page data*/
	uint32_t	size;		/* the size of this dump page */
	uint32_t	flags;		/* flags */
	uint64_t	page_flags;	/* page flags */
};

struct disk_dump_priv {
	unsigned char *bitmap;	/* for compressed dumps */
	off_t descoff;		/* position of page descriptor table */
};

/* flags */
#define DUMP_DH_COMPRESSED_ZLIB	0x1	/* page is compressed with zlib */
#define DUMP_DH_COMPRESSED_LZO	0x2	/* page is compressed with lzo */
#define DUMP_DH_COMPRESSED_SNAPPY 0x4	/* page is compressed with snappy */

/* Any compression flag */
#define DUMP_DH_COMPRESSED	( 0	\
	| DUMP_DH_COMPRESSED_ZLIB	\
	| DUMP_DH_COMPRESSED_LZO	\
	| DUMP_DH_COMPRESSED_SNAPPY	\
		)

static inline int
page_is_dumpable(kdump_ctx *ctx, unsigned int nr)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;
	return ddp->bitmap[nr>>3] & (1 << (nr & 7));
}

static off_t
pfn_to_pdpos(kdump_ctx *ctx, unsigned long pfn)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;
	unsigned i, n;

	n = 0;
	for (i = 0; i < pfn >> 3; ++i)
		n += bitcount(ddp->bitmap[i]);
	for (i = 0; i < (pfn & 0x7); ++i)
		if (page_is_dumpable(ctx, pfn - i))
		    ++n;

	return ddp->descoff + n * sizeof(struct page_desc);
}

static kdump_status
diskdump_read_page(kdump_ctx *ctx, kdump_paddr_t pfn)
{
	struct page_desc pd;
	off_t pd_pos;
	void *buf;

	if (!page_is_dumpable(ctx, pfn)) {
		memset(ctx->page, 0, ctx->page_size);
		return 0;
	}

	pd_pos = pfn_to_pdpos(ctx, pfn);
	if (pread(ctx->fd, &pd, sizeof pd, pd_pos) != sizeof pd)
		return -1;

	pd.offset = dump64toh(ctx, pd.offset);
	pd.size = dump32toh(ctx, pd.size);
	pd.flags = dump32toh(ctx, pd.flags);
	pd.page_flags = dump64toh(ctx, pd.page_flags);

	if (pd.flags & DUMP_DH_COMPRESSED) {
		if (pd.size > MAX_PAGE_SIZE)
			return -1;
		buf = ctx->buffer;
	} else {
		if (pd.size != ctx->page_size)
			return -1;
		buf = ctx->page;
	}

	/* read page data */
	if (pread(ctx->fd, buf, pd.size, pd.offset) != pd.size)
		return -1;

	if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
		uLongf retlen = ctx->page_size;
		int ret = uncompress(ctx->page, &retlen,
				     buf, pd.size);
		if ((ret != Z_OK) || (retlen != ctx->page_size))
			return -1;
	} else if (pd.flags & DUMP_DH_COMPRESSED_LZO) {
		lzo_uint retlen = ctx->page_size;
		int ret = lzo1x_decompress_safe((lzo_bytep)buf, pd.size,
						(lzo_bytep)ctx->page, &retlen,
						LZO1X_MEM_DECOMPRESS);
		if ((ret != LZO_E_OK) || (retlen != ctx->page_size))
			return -1;
	} else if (pd.flags & DUMP_DH_COMPRESSED_SNAPPY) {
		size_t retlen = ctx->page_size;
		snappy_status ret;
		ret = snappy_uncompress((char *)buf, pd.size,
					(char *)ctx->page, &retlen);
		if ((ret != SNAPPY_OK) || (retlen != ctx->page_size))
			return -1;
	}

	return 0;
}

static int
sane_header_values(int32_t block_size, uint32_t bitmap_blocks,
		   uint32_t max_mapnr)
{
	unsigned maxcovered;

	/* Page size must be reasonable */
	if (block_size < MIN_PAGE_SIZE || block_size > MAX_PAGE_SIZE)
		return 0;

	/* It must be a power of 2 */
	if (block_size != (block_size & ~(block_size - 1)))
		return 0;

	/* Number of bitmap blocks should cover all pages in the system */
	maxcovered = 8 * bitmap_blocks * block_size;
	if (maxcovered < max_mapnr)
		return 0;

	/* basic sanity checks passed, return true: */
	return 1;
}

static int
header_looks_sane_32(struct disk_dump_header_32 *dh)
{
	if (sane_header_values(le32toh(dh->block_size),
			       le32toh(dh->bitmap_blocks),
			       le32toh(dh->max_mapnr)))
		return __LITTLE_ENDIAN;

	if (sane_header_values(be32toh(dh->block_size),
			       be32toh(dh->bitmap_blocks),
			       be32toh(dh->max_mapnr)))
		return __BIG_ENDIAN;

	return 0;
}

static int
header_looks_sane_64(struct disk_dump_header_64 *dh)
{
	if (sane_header_values(le32toh(dh->block_size),
			       le32toh(dh->bitmap_blocks),
			       le32toh(dh->max_mapnr)))
		return __LITTLE_ENDIAN;

	if (sane_header_values(be32toh(dh->block_size),
			       be32toh(dh->bitmap_blocks),
			       be32toh(dh->max_mapnr)))
		return __BIG_ENDIAN;

	return 0;
}

static inline int
read_bitmap(kdump_ctx *ctx, int32_t sub_hdr_size,
	    int32_t bitmap_blocks, int32_t max_mapnr)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;
	off_t off = (1 + sub_hdr_size) * ctx->page_size;
	size_t bitmapsize;

	ddp->descoff = off + bitmap_blocks * ctx->page_size;

	if (8 * bitmap_blocks * ctx->page_size >= max_mapnr * 2) {
		/* partial dump */
		bitmap_blocks /= 2;
		off += bitmap_blocks * ctx->page_size;
	}

	bitmapsize = bitmap_blocks * ctx->page_size;
	if (! (ddp->bitmap = malloc(bitmapsize)) )
		return -1;

	ctx->max_pfn = bitmapsize * 8;

	if (pread(ctx->fd, ddp->bitmap, bitmapsize, off) != bitmapsize)
		return -1;

	return 0;
}

static kdump_status
open_common(kdump_ctx *ctx)
{
	struct disk_dump_header_32 *dh32 = ctx->buffer;
	struct disk_dump_header_64 *dh64 = ctx->buffer;
	struct disk_dump_priv *ddp;

	ddp = malloc(sizeof *ddp);
	if (!ddp)
		return kdump_syserr;

	ctx->fmtdata = ddp;

	if (kdump_uts_looks_sane(&dh32->utsname))
		kdump_copy_uts(&ctx->utsname, &dh32->utsname);
	else if (kdump_uts_looks_sane(&dh64->utsname))
		kdump_copy_uts(&ctx->utsname, &dh64->utsname);

	if ( (ctx->endian = header_looks_sane_32(dh32)) ) {
		ctx->page_size = dump32toh(ctx, dh32->block_size);
		if (read_bitmap(ctx,
				dump32toh(ctx, dh32->sub_hdr_size),
				dump32toh(ctx, dh32->bitmap_blocks),
				dump32toh(ctx, dh32->max_mapnr)) ) {
			return kdump_syserr;
		}
	} else if ( (ctx->endian = header_looks_sane_64(dh64)) ) {
		ctx->page_size = dump32toh(ctx, dh64->block_size);
		if (read_bitmap(ctx,
				dump32toh(ctx, dh64->sub_hdr_size),
				dump32toh(ctx, dh64->bitmap_blocks),
				dump32toh(ctx, dh64->max_mapnr)) ) {
			return kdump_syserr;
		}
	} else
		return kdump_unsupported;

	return kdump_ok;
}

static kdump_status
diskdump_probe(kdump_ctx *ctx)
{
	static const char magic_diskdump[] =
		{ 'D', 'I', 'S', 'K', 'D', 'U', 'M', 'P' };
	static const char magic_kdump[] =
		{ 'K', 'D', 'U', 'M', 'P', ' ', ' ', ' ' };

	if (!memcmp(ctx->buffer, magic_diskdump, sizeof magic_diskdump))
		ctx->format = "diskdump";
	else if (!memcmp(ctx->buffer, magic_kdump, sizeof magic_kdump))
		ctx->format = "compressed kdump";
	else
		return kdump_unsupported;

	return open_common(ctx);
}

const struct kdump_ops kdump_diskdump_ops = {
	.probe = diskdump_probe,
	.read_page = diskdump_read_page,
};
