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

#include "kdumpfile-priv.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#if USE_ZLIB
# include <zlib.h>
#endif
#if USE_LZO
# include <lzo/lzo1x.h>
#endif
#if USE_SNAPPY
# include <snappy-c.h>
#endif

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

/* Sub header for KDUMP */
struct kdump_sub_header_32 {
	uint32_t	phys_base;
	int32_t		dump_level;	   /* header_version 1 and later */
	int32_t		split;		   /* header_version 2 and later */
	uint32_t	start_pfn;	   /* header_version 2 and later,
					      OBSOLETE! 32bit only, full
					      64bit in start_pfn_64. */
	uint32_t	end_pfn;	   /* header_version 2 and later,
					      OBSOLETE! 32bit only, full
					      64bit in end_pfn_64. */
	uint64_t	offset_vmcoreinfo; /* header_version 3 and later */
	uint32_t	size_vmcoreinfo;   /* header_version 3 and later */
	uint64_t	offset_note;	   /* header_version 4 and later */
	uint32_t	size_note;	   /* header_version 4 and later */
	uint64_t	offset_eraseinfo;  /* header_version 5 and later */
	uint32_t	size_eraseinfo;	   /* header_version 5 and later */
	uint64_t	start_pfn_64;	   /* header_version 6 and later */
	uint64_t	end_pfn_64;	   /* header_version 6 and later */
	uint64_t	max_mapnr_64;	   /* header_version 6 and later */
} __attribute__((packed));

/* Sub header for KDUMP */
struct kdump_sub_header_64 {
	uint64_t	phys_base;
	int32_t		dump_level;	   /* header_version 1 and later */
	int32_t		split;		   /* header_version 2 and later */
	uint64_t	start_pfn;	   /* header_version 2 and later,
					      OBSOLETE! 32bit only, full
					      64bit in start_pfn_64. */
	uint64_t	end_pfn;	   /* header_version 2 and later,
					      OBSOLETE! 32bit only, full
					      64bit in end_pfn_64. */
	uint64_t	offset_vmcoreinfo; /* header_version 3 and later */
	uint64_t	size_vmcoreinfo;   /* header_version 3 and later */
	uint64_t	offset_note;	   /* header_version 4 and later */
	uint64_t	size_note;	   /* header_version 4 and later */
	uint64_t	offset_eraseinfo;  /* header_version 5 and later */
	uint64_t	size_eraseinfo;	   /* header_version 5 and later */
	uint64_t	start_pfn_64;	   /* header_version 6 and later */
	uint64_t	end_pfn_64;	   /* header_version 6 and later */
	uint64_t	max_mapnr_64;	   /* header_version 6 and later */
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
	n += bitcount(ddp->bitmap[i] & (((1 << (pfn & 0x7)) - 1)));

	return ddp->descoff + n * sizeof(struct page_desc);
}

static kdump_status
diskdump_read_page(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	struct page_desc pd;
	off_t pd_pos;
	void *buf;

	if (pfn == ctx->last_pfn)
		return kdump_ok;

	if (pfn >= ctx->max_pfn)
		return kdump_nodata;

	if (!page_is_dumpable(ctx, pfn)) {
		memset(ctx->page, 0, ctx->page_size);
		return kdump_ok;
	}

	pd_pos = pfn_to_pdpos(ctx, pfn);
	if (pread(ctx->fd, &pd, sizeof pd, pd_pos) != sizeof pd)
		return kdump_syserr;

	pd.offset = dump64toh(ctx, pd.offset);
	pd.size = dump32toh(ctx, pd.size);
	pd.flags = dump32toh(ctx, pd.flags);
	pd.page_flags = dump64toh(ctx, pd.page_flags);

	if (pd.flags & DUMP_DH_COMPRESSED) {
		if (pd.size > MAX_PAGE_SIZE)
			return kdump_dataerr;
		buf = ctx->buffer;
	} else {
		if (pd.size != ctx->page_size)
			return kdump_dataerr;
		buf = ctx->page;
	}

	/* read page data */
	if (pread(ctx->fd, buf, pd.size, pd.offset) != pd.size)
		return kdump_syserr;

	if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
#if USE_ZLIB
		uLongf retlen = ctx->page_size;
		int ret = uncompress(ctx->page, &retlen,
				     buf, pd.size);
		if ((ret != Z_OK) || (retlen != ctx->page_size))
			return kdump_dataerr;
#else
		return kdump_unsupported;
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_LZO) {
#if USE_LZO
		lzo_uint retlen = ctx->page_size;
		int ret = lzo1x_decompress_safe((lzo_bytep)buf, pd.size,
						(lzo_bytep)ctx->page, &retlen,
						LZO1X_MEM_DECOMPRESS);
		if ((ret != LZO_E_OK) || (retlen != ctx->page_size))
			return kdump_dataerr;
#else
		return kdump_unsupported;
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_SNAPPY) {
#if USE_SNAPPY
		size_t retlen = ctx->page_size;
		snappy_status ret;
		ret = snappy_uncompress((char *)buf, pd.size,
					(char *)ctx->page, &retlen);
		if ((ret != SNAPPY_OK) || (retlen != ctx->page_size))
			return kdump_dataerr;
#else
		return kdump_unsupported;
#endif
	}

	ctx->last_pfn = pfn;
	return kdump_ok;
}

static kdump_status
read_vmcoreinfo(kdump_ctx *ctx, off_t off, size_t size)
{
	void *info;
	kdump_status ret = kdump_ok;

	info = malloc(size);
	if (!info)
		return kdump_syserr;

	if (pread(ctx->fd, info, size, off) != size)
		ret = kdump_syserr;

	if (ret == kdump_ok)
		ret = kdump_process_vmcoreinfo(ctx, info, size);
	free(info);

	return ret;
}

/* This function also sets architecture */
static kdump_status
read_notes(kdump_ctx *ctx, off_t off, size_t size)
{
	void *notes;
	kdump_status ret = kdump_ok;

	notes = malloc(size);
	if (!notes)
		return kdump_syserr;

	if (pread(ctx->fd, notes, size, off) != size)
		ret = kdump_syserr;

	if (ret != kdump_ok)
		goto out;

	ret = kdump_process_noarch_notes(ctx, notes, size);
	if (ret != kdump_ok)
		goto out;

	ret = kdump_set_arch(ctx, kdump_machine_arch(ctx->utsname.machine));
	if (ret != kdump_ok)
		goto out;

	ret = kdump_process_arch_notes(ctx, notes, size);

 out:
	free(notes);

	return ret;
}

static kdump_status
read_bitmap(kdump_ctx *ctx, int32_t sub_hdr_size,
	    int32_t bitmap_blocks)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;
	off_t off = (1 + sub_hdr_size) * ctx->page_size;
	size_t bitmapsize;
	kdump_pfn_t max_bitmap_pfn;

	ddp->descoff = off + bitmap_blocks * ctx->page_size;

	bitmapsize = bitmap_blocks * ctx->page_size;
	max_bitmap_pfn = (kdump_pfn_t)bitmapsize * 8;
	if (ctx->max_pfn <= max_bitmap_pfn / 2) {
		/* partial dump */
		bitmap_blocks /= 2;
		bitmapsize = bitmap_blocks * ctx->page_size;
		off += bitmapsize;
		max_bitmap_pfn = (kdump_pfn_t)bitmapsize * 8;
	}

	if (ctx->max_pfn > max_bitmap_pfn)
		ctx->max_pfn = max_bitmap_pfn;

	if (! (ddp->bitmap = malloc(bitmapsize)) )
		return kdump_syserr;

	if (pread(ctx->fd, ddp->bitmap, bitmapsize, off) != bitmapsize)
		return kdump_syserr;

	return kdump_ok;
}

static kdump_status
try_header(kdump_ctx *ctx, int32_t block_size,
	   uint32_t bitmap_blocks, uint32_t max_mapnr)
{
	uint64_t maxcovered;
	kdump_status ret;

	/* Page size must be reasonable */
	if (block_size < MIN_PAGE_SIZE || block_size > MAX_PAGE_SIZE)
		return kdump_dataerr;

	/* Number of bitmap blocks should cover all pages in the system */
	maxcovered = (uint64_t)8 * bitmap_blocks * block_size;
	if (maxcovered < max_mapnr)
		return kdump_dataerr;

	/* basic sanity checks passed */
	ret = kdump_set_page_size(ctx, block_size);
	if (ret != kdump_ok)
		return ret;

	ctx->max_pfn = max_mapnr;

	return kdump_ok;
}

static kdump_status
read_sub_hdr_32(kdump_ctx *ctx, int32_t header_version)
{
	struct kdump_sub_header_32 subhdr;
	kdump_status ret = kdump_ok;

	if (header_version < 1)
		return header_version < 0 ? kdump_dataerr : kdump_ok;

	if (pread(ctx->fd, &subhdr, sizeof subhdr, ctx->page_size)
	    != sizeof subhdr)
		return kdump_syserr;

	kdump_set_phys_base(ctx, dump32toh(ctx, subhdr.phys_base));

	if (header_version >= 4)
		ret = read_notes(ctx, dump64toh(ctx, subhdr.offset_note),
				 dump32toh(ctx, subhdr.size_note));
	else if (header_version >= 3)
		ret = read_vmcoreinfo(ctx,
				      dump64toh(ctx, subhdr.offset_vmcoreinfo),
				      dump32toh(ctx, subhdr.size_vmcoreinfo));

	if (header_version >= 6)
		ctx->max_pfn = dump64toh(ctx, subhdr.max_mapnr_64);

	return ret;
}

static kdump_status
do_header_32(kdump_ctx *ctx, struct disk_dump_header_32 *dh, int endian)
{
	kdump_status ret;

	ctx->endian = endian;
	ctx->ptr_size = 4;

	ret = read_sub_hdr_32(ctx, dump32toh(ctx, dh->header_version));
	if (ret != kdump_ok)
		return ret;

	return read_bitmap(ctx, dump32toh(ctx, dh->sub_hdr_size),
			   dump32toh(ctx, dh->bitmap_blocks));
}

static kdump_status
try_header_32(kdump_ctx *ctx, struct disk_dump_header_32 *dh)
{
	kdump_status ret;

	ret = try_header(ctx, le32toh(dh->block_size),
			 le32toh(dh->bitmap_blocks),
			 le32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_32(ctx, dh, __LITTLE_ENDIAN);

	if (ret != kdump_dataerr)
		return ret;

	ret = try_header(ctx, be32toh(dh->block_size),
			 be32toh(dh->bitmap_blocks),
			 be32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_32(ctx, dh, __BIG_ENDIAN);

	return ret;
}

static kdump_status
read_sub_hdr_64(kdump_ctx *ctx, int32_t header_version)
{
	struct kdump_sub_header_64 subhdr;
	kdump_status ret = kdump_ok;

	if (header_version < 0)
		return kdump_dataerr;

	if (pread(ctx->fd, &subhdr, sizeof subhdr, ctx->page_size)
	    != sizeof subhdr)
		return kdump_syserr;

	kdump_set_phys_base(ctx, dump64toh(ctx, subhdr.phys_base));

	if (header_version >= 4)
		ret = read_notes(ctx, dump64toh(ctx, subhdr.offset_note),
				 dump64toh(ctx, subhdr.size_note));
	else if (header_version >= 3)
		ret = read_vmcoreinfo(ctx,
				      dump64toh(ctx, subhdr.offset_vmcoreinfo),
				      dump64toh(ctx, subhdr.size_vmcoreinfo));

	if (header_version >= 6)
		ctx->max_pfn = dump64toh(ctx, subhdr.max_mapnr_64);

	return ret;
}

static kdump_status
do_header_64(kdump_ctx *ctx, struct disk_dump_header_64 *dh, int endian)
{
	kdump_status ret;

	ctx->endian = endian;
	ctx->ptr_size = 8;

	ret = read_sub_hdr_64(ctx, dump32toh(ctx, dh->header_version));
	if (ret != kdump_ok)
		return ret;

	return read_bitmap(ctx, dump32toh(ctx, dh->sub_hdr_size),
			   dump32toh(ctx, dh->bitmap_blocks));
}

static kdump_status
try_header_64(kdump_ctx *ctx, struct disk_dump_header_64 *dh)
{
	kdump_status ret;

	ret = try_header(ctx, le32toh(dh->block_size),
			 le32toh(dh->bitmap_blocks),
			 le32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_64(ctx, dh, __LITTLE_ENDIAN);

	if (ret != kdump_dataerr)
		return ret;

	ret = try_header(ctx, be32toh(dh->block_size),
			 be32toh(dh->bitmap_blocks),
			 be32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_64(ctx, dh, __BIG_ENDIAN);

	return ret;
}

static kdump_status
open_common(kdump_ctx *ctx)
{
	struct disk_dump_header_32 *dh32 = ctx->buffer;
	struct disk_dump_header_64 *dh64 = ctx->buffer;
	struct disk_dump_priv *ddp;
	kdump_status ret;

	ddp = malloc(sizeof *ddp);
	if (!ddp)
		return kdump_syserr;

	ctx->fmtdata = ddp;

	if (kdump_uts_looks_sane(&dh32->utsname))
		kdump_set_uts(ctx, &dh32->utsname);
	else if (kdump_uts_looks_sane(&dh64->utsname))
		kdump_set_uts(ctx, &dh64->utsname);

	ret = try_header_32(ctx, dh32);
	if (ret == kdump_dataerr)
		ret = try_header_64(ctx, dh64);
	if (ret == kdump_dataerr)
		ret = kdump_unsupported;

	if (ret == kdump_ok && ctx->arch == ARCH_UNKNOWN)
		ret = kdump_set_arch(ctx, kdump_machine_arch(
					     ctx->utsname.machine));

	return ret;
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

static void
diskdump_cleanup(kdump_ctx *ctx)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;

	if (ddp->bitmap)
		free(ddp->bitmap);
	free(ddp);
	ctx->fmtdata = NULL;
}

const struct format_ops kdump_diskdump_ops = {
	.probe = diskdump_probe,
	.read_page = diskdump_read_page,
	.cleanup = diskdump_cleanup,
};
