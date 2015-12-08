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
#include <errno.h>

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

	void *xen_map;
	unsigned long xen_map_size;
};

struct setup_data {
	kdump_ctx *ctx;
	off_t note_off;
	size_t note_sz;
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

static const struct format_ops xen_dom0_ops;

static void diskdump_cleanup(kdump_ctx *ctx);

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
	ssize_t rd;

	if (pfn == ctx->last_pfn)
		return kdump_ok;

	if (pfn >= ctx->max_pfn)
		return set_error(ctx, kdump_nodata, "Out-of-bounds PFN");

	if (!page_is_dumpable(ctx, pfn)) {
		memset(ctx->page, 0, ctx->page_size);
		ctx->last_pfn =  -(kdump_paddr_t)1;
		return kdump_ok;
	}

	pd_pos = pfn_to_pdpos(ctx, pfn);
	rd = pread(ctx->fd, &pd, sizeof pd, pd_pos);
	if (rd != sizeof pd)
		return set_error(ctx, read_error(rd),
				 "Cannot read page descriptor at %llu: %s",
				 (unsigned long long) pd_pos,
				 read_err_str(rd));

	pd.offset = dump64toh(ctx, pd.offset);
	pd.size = dump32toh(ctx, pd.size);
	pd.flags = dump32toh(ctx, pd.flags);
	pd.page_flags = dump64toh(ctx, pd.page_flags);

	if (pd.flags & DUMP_DH_COMPRESSED) {
		if (pd.size > MAX_PAGE_SIZE)
			return set_error(ctx, kdump_dataerr,
					 "Wrong compressed size: %lu",
					 (unsigned long)pd.size);
		buf = ctx->buffer;
	} else {
		if (pd.size != ctx->page_size)
			return set_error(ctx, kdump_dataerr,
					 "Wrong page size: %lu",
					 (unsigned long)pd.size);
		buf = ctx->page;
	}

	/* read page data */
	rd = pread(ctx->fd, buf, pd.size, pd.offset);
	if (rd != pd.size)
		return set_error(ctx, read_error(rd),
				 "Cannot read page data at %llu: %s",
				 (unsigned long long) pd.offset,
				 read_err_str(rd));

	if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
#if USE_ZLIB
		uLongf retlen = ctx->page_size;
		int ret = uncompress(ctx->page, &retlen,
				     buf, pd.size);
		if (ret != Z_OK)
			return set_error(ctx, kdump_dataerr,
					 "Decompression failed: %d", ret);
		if (retlen != ctx->page_size)
			return set_error(ctx, kdump_dataerr,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
#else
		return set_error(ctx, kdump_unsupported,
				 "Unsupported compression method: %s",
				 "zlib");
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_LZO) {
#if USE_LZO
		lzo_uint retlen = ctx->page_size;
		int ret = lzo1x_decompress_safe((lzo_bytep)buf, pd.size,
						(lzo_bytep)ctx->page, &retlen,
						LZO1X_MEM_DECOMPRESS);
		if (ret != LZO_E_OK)
			return set_error(ctx, kdump_dataerr,
					 "Decompression failed: %d", ret);
		if (retlen != ctx->page_size)
			return set_error(ctx, kdump_dataerr,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
#else
		return set_error(ctx, kdump_unsupported,
				 "Unsupported compression method: %s",
				 "lzo");
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_SNAPPY) {
#if USE_SNAPPY
		size_t retlen = ctx->page_size;
		snappy_status ret;
		ret = snappy_uncompress((char *)buf, pd.size,
					(char *)ctx->page, &retlen);
		if (ret != SNAPPY_OK)
			return set_error(ctx, kdump_dataerr,
					 "Decompression failed: %d",
					 (int) ret);
		if (retlen != ctx->page_size)
			return set_error(ctx, kdump_dataerr,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
#else
		return set_error(ctx, kdump_unsupported,
				 "Unsupported compression method: %s",
				 "snappy");
#endif
	}

	ctx->last_pfn = pfn;
	return kdump_ok;
}

static kdump_status
diskdump_read_xen_dom0(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;
	unsigned fpp = ctx->page_size / ctx->ptr_size;
	uint64_t mfn_idx, frame_idx;
	kdump_status ret;

	mfn_idx = pfn / fpp;
	frame_idx = pfn % fpp;
	if (mfn_idx >= ddp->xen_map_size)
		return set_error(ctx, kdump_nodata, "Out-of-bounds PFN");

	pfn = (ctx->ptr_size == 8)
		? ((uint64_t*)ddp->xen_map)[mfn_idx]
		: ((uint32_t*)ddp->xen_map)[mfn_idx];
	ret = diskdump_read_page(ctx, pfn);
	if (ret != kdump_ok)
		return set_error(ctx, ret, "Cannot read MFN %llx",
				 (unsigned long long) pfn);

	pfn = (ctx->ptr_size == 8)
		? ((uint64_t*)ctx->page)[frame_idx]
		: ((uint32_t*)ctx->page)[frame_idx];
	ret = diskdump_read_page(ctx, pfn);
	return set_error(ctx, ret, "Cannot read MFN %llx",
			 (unsigned long long) pfn);
}

static kdump_status
initialize_xen_map64(kdump_ctx *ctx, void *dir)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;
	unsigned fpp = ctx->page_size / ctx->ptr_size;
	uint64_t *dirp, *p, *map;
	uint64_t pfn;
	unsigned long mfns;
	kdump_status ret;

	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < ctx->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		ret = diskdump_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page; (void*)p < ctx->page + ctx->page_size; ++p)
			if (*p)
				++mfns;
	}

	map = ctx_malloc(mfns * sizeof(uint64_t), ctx, "Xen P2M map");
	if (!map)
		return kdump_syserr;
	ddp->xen_map = map;
	ddp->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		ret = diskdump_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page; (void*)p < ctx->page + ctx->page_size; ++p)
			if (*p) {
				*map++ = dump64toh(ctx, *p);
				--mfns;
			}
	}

	return kdump_ok;
}

static kdump_status
initialize_xen_map32(kdump_ctx *ctx, void *dir)
{
	struct disk_dump_priv *ddp = ctx->fmtdata;
	unsigned fpp = ctx->page_size / ctx->ptr_size;
	uint32_t *dirp, *p, *map;
	uint32_t pfn;
	unsigned long mfns;
	kdump_status ret;

	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < ctx->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		ret = diskdump_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page; (void*)p < ctx->page + ctx->page_size; ++p)
			if (*p)
				++mfns;
	}

	map = ctx_malloc(mfns * sizeof(uint32_t), ctx, "Xen P2M map");
	if (!map)
		return kdump_syserr;
	ddp->xen_map = map;
	ddp->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		ret = diskdump_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			ret = kdump_dataerr;
		if (ret != kdump_ok)
			return set_error(ctx, ret,
					 "Cannot read Xen P2M map MFN 0x%llx",
					 (unsigned long long) *dirp);

		for (p = ctx->page; (void*)p < ctx->page + ctx->page_size; ++p)
			if (*p) {
				*map++ = dump32toh(ctx, *p);
				--mfns;
			}
	}

	return kdump_ok;
}

static kdump_status
initialize_xen_map(kdump_ctx *ctx)
{
	void *dir, *page;
	kdump_status ret;

	ret = diskdump_read_page(ctx, ctx->xen_p2m_mfn);
	if (ret != kdump_ok)
		return set_error(ctx, ret,
				 "Cannot read Xen P2M directory MFN 0x%llx",
				 (unsigned long long) ctx->xen_p2m_mfn);

	dir = ctx->page;
	page = ctx_malloc(ctx->page_size, ctx, "page buffer");
	if (page == NULL)
		return kdump_syserr;
	ctx->page = page;

	ret = (ctx->ptr_size == 8)
		? initialize_xen_map64(ctx, dir)
		: initialize_xen_map32(ctx, dir);

	if (ret == kdump_ok)
		ctx->ops = &xen_dom0_ops;

	free(dir);
	return ret;
}

static kdump_status
read_vmcoreinfo(kdump_ctx *ctx, off_t off, size_t size)
{
	void *info;
	ssize_t rd;
	kdump_status ret = kdump_ok;

	info = ctx_malloc(size, ctx, "VMCOREINFO buffer");
	if (!info)
		return kdump_syserr;

	rd = pread(ctx->fd, info, size, off);
	if (rd != size)
		ret = set_error(ctx, read_error(rd),
				"Cannot read %zu VMCOREINFO bytes at %llu: %s",
				size, (unsigned long long) off,
				read_err_str(rd));

	if (ret == kdump_ok)
		ret = process_vmcoreinfo(ctx, info, size);
	free(info);

	return ret;
}

/* This function also sets architecture */
static kdump_status
read_notes(kdump_ctx *ctx, off_t off, size_t size)
{
	void *notes;
	ssize_t rd;
	kdump_status ret = kdump_ok;

	notes = ctx_malloc(size, ctx, "notes");
	if (!notes)
		return kdump_syserr;

	rd = pread(ctx->fd, notes, size, off);
	if (rd != size) {
		ret = set_error(ctx, read_error(rd),
				"Cannot read %zu note bytes at %llu: %s",
				size, (unsigned long long) off,
				read_err_str(rd));
		goto out;
	}

	ret = process_noarch_notes(ctx, notes, size);
	if (ret != kdump_ok) {
		ret = set_error(ctx, ret, "Cannot process noarch notes");
		goto out;
	}

	ret = set_arch(ctx, machine_arch(ctx->utsname.machine));
	if (ret != kdump_ok) {
		ret = set_error(ctx, ret, "Cannot set architecture");
		goto out;
	}

	ret = process_arch_notes(ctx, notes, size);
	if (ret != kdump_ok)
		ret = set_error(ctx, ret, "Cannot process arch notes");

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
	ssize_t rd;

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

	if (! (ddp->bitmap = ctx_malloc(bitmapsize, ctx, "page bitmap")) )
		return kdump_syserr;

	rd = pread(ctx->fd, ddp->bitmap, bitmapsize, off);
	if (rd != bitmapsize)
		return set_error(ctx, read_error(rd),
				 "Cannot read %zu bytes of page bitmap"
				 " at %llu: %s",
				 bitmapsize, (unsigned long long) off,
				 read_err_str(rd));

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
		return set_error(ctx, kdump_dataerr,
				 "Out-of-bounds page size: %lu",
				 (unsigned long) block_size);

	/* Number of bitmap blocks should cover all pages in the system */
	maxcovered = (uint64_t)8 * bitmap_blocks * block_size;
	if (maxcovered < max_mapnr)
		return set_error(ctx, kdump_dataerr,
				 "Page bitmap too small:"
				 " Need %llu bits, only %llu found",
				 (unsigned long long) max_mapnr,
				 (unsigned long long) maxcovered);

	/* basic sanity checks passed */
	ret = set_page_size(ctx, block_size);
	if (ret != kdump_ok)
		return ret;

	ctx->max_pfn = max_mapnr;

	return kdump_ok;
}

static kdump_status
read_sub_hdr_32(struct setup_data *sdp, int32_t header_version)
{
	kdump_ctx *ctx = sdp->ctx;
	struct kdump_sub_header_32 subhdr;
	ssize_t rd;
	kdump_status ret = kdump_ok;

	if (header_version < 0)
		return set_error(ctx, kdump_dataerr,
				 "Invalid header version: %lu",
				 (unsigned long) header_version);

	if (header_version < 1)
		return kdump_ok;

	rd = pread(ctx->fd, &subhdr, sizeof subhdr, ctx->page_size);
	if (rd != sizeof subhdr)
		return set_error(ctx, read_error(rd),
				 "Cannot read subheader: %s",
				 read_err_str(rd));

	set_phys_base(ctx, dump32toh(ctx, subhdr.phys_base));

	if (header_version >= 4) {
		sdp->note_off = dump64toh(ctx, subhdr.offset_note);
		sdp->note_sz = dump32toh(ctx, subhdr.size_note);
	} else if (header_version >= 3)
		ret = read_vmcoreinfo(ctx,
				      dump64toh(ctx, subhdr.offset_vmcoreinfo),
				      dump32toh(ctx, subhdr.size_vmcoreinfo));

	if (header_version >= 6)
		ctx->max_pfn = dump64toh(ctx, subhdr.max_mapnr_64);

	return ret;
}

static kdump_status
do_header_32(struct setup_data *sdp, struct disk_dump_header_32 *dh,
	     kdump_byte_order_t byte_order)
{
	kdump_ctx *ctx = sdp->ctx;
	kdump_status ret;

	ctx->byte_order = byte_order;

	ret = set_attr_number(ctx, "arch.ptr_size", 4);
	if (ret != kdump_ok)
		return ret;

	ret = read_sub_hdr_32(sdp, dump32toh(ctx, dh->header_version));
	if (ret != kdump_ok)
		return ret;

	return read_bitmap(ctx, dump32toh(ctx, dh->sub_hdr_size),
			   dump32toh(ctx, dh->bitmap_blocks));
}

static kdump_status
try_header_32(struct setup_data *sdp, struct disk_dump_header_32 *dh)
{
	kdump_ctx *ctx = sdp->ctx;
	kdump_status ret;

	ret = try_header(ctx, le32toh(dh->block_size),
			 le32toh(dh->bitmap_blocks),
			 le32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_32(sdp, dh, kdump_little_endian);

	if (ret != kdump_dataerr)
		return ret;
	clear_error(ctx);

	ret = try_header(ctx, be32toh(dh->block_size),
			 be32toh(dh->bitmap_blocks),
			 be32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_32(sdp, dh, kdump_big_endian);

	return ret;
}

static kdump_status
read_sub_hdr_64(struct setup_data *sdp, int32_t header_version)
{
	kdump_ctx *ctx = sdp->ctx;
	struct kdump_sub_header_64 subhdr;
	ssize_t rd;
	kdump_status ret = kdump_ok;

	if (header_version < 0)
		return set_error(ctx, kdump_dataerr,
				 "Invalid header version: %lu",
				 (unsigned long) header_version);

	if (header_version < 1)
		return kdump_ok;

	rd = pread(ctx->fd, &subhdr, sizeof subhdr, ctx->page_size);
	if (rd != sizeof subhdr)
		return set_error(ctx, read_error(rd),
				 "Cannot read subheader: %s",
				 read_err_str(rd));

	set_phys_base(ctx, dump64toh(ctx, subhdr.phys_base));

	if (header_version >= 4) {
		sdp->note_off = dump64toh(ctx, subhdr.offset_note);
		sdp->note_sz = dump64toh(ctx, subhdr.size_note);
	} else if (header_version >= 3)
		ret = read_vmcoreinfo(ctx,
				      dump64toh(ctx, subhdr.offset_vmcoreinfo),
				      dump64toh(ctx, subhdr.size_vmcoreinfo));

	if (header_version >= 6)
		ctx->max_pfn = dump64toh(ctx, subhdr.max_mapnr_64);

	return ret;
}

static kdump_status
do_header_64(struct setup_data *sdp, struct disk_dump_header_64 *dh,
	     kdump_byte_order_t byte_order)
{
	kdump_ctx *ctx = sdp->ctx;
	kdump_status ret;

	ctx->byte_order = byte_order;

	ret = set_attr_number(ctx, "arch.ptr_size", 8);
	if (ret != kdump_ok)
		return ret;

	ret = read_sub_hdr_64(sdp, dump32toh(ctx, dh->header_version));
	if (ret != kdump_ok)
		return ret;

	return read_bitmap(ctx, dump32toh(ctx, dh->sub_hdr_size),
			   dump32toh(ctx, dh->bitmap_blocks));
}

static kdump_status
try_header_64(struct setup_data *sdp, struct disk_dump_header_64 *dh)
{
	kdump_ctx *ctx = sdp->ctx;
	kdump_status ret;

	ret = try_header(ctx, le32toh(dh->block_size),
			 le32toh(dh->bitmap_blocks),
			 le32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_64(sdp, dh, kdump_little_endian);

	if (ret != kdump_dataerr)
		return ret;
	clear_error(ctx);

	ret = try_header(ctx, be32toh(dh->block_size),
			 be32toh(dh->bitmap_blocks),
			 be32toh(dh->max_mapnr));
	if (ret == kdump_ok)
		return do_header_64(sdp, dh, kdump_big_endian);

	return ret;
}

static kdump_status
open_common(kdump_ctx *ctx)
{
	struct disk_dump_header_32 *dh32 = ctx->buffer;
	struct disk_dump_header_64 *dh64 = ctx->buffer;
	struct disk_dump_priv *ddp;
	struct setup_data sd;
	kdump_status ret;

	memset(&sd, 0, sizeof sd);
	sd.ctx = ctx;

	ddp = calloc(1, sizeof *ddp);
	if (!ddp)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate diskdump private data: %s",
				 strerror(errno));

	ctx->fmtdata = ddp;

	if (uts_looks_sane(&dh32->utsname))
		set_uts(ctx, &dh32->utsname);
	else if (uts_looks_sane(&dh64->utsname))
		set_uts(ctx, &dh64->utsname);

	ret = try_header_32(&sd, dh32);
	if (ret == kdump_dataerr) {
		clear_error(ctx);
		ret = try_header_64(&sd, dh64);
	}
	if (ret == kdump_dataerr) {
		clear_error(ctx);
		ret = set_error(ctx, kdump_unsupported,
				"Invalid diskdump header content");
	}
	if (ret != kdump_ok)
		goto err_cleanup;

	if (sd.note_sz) {
		ret = read_notes(ctx, sd.note_off, sd.note_sz);
		if (ret != kdump_ok)
			goto err_cleanup;
	}

	if (!attr_isset(ctx, "arch.name"))
		ret = set_arch(ctx, machine_arch(ctx->utsname.machine));
	if (ret != kdump_ok)
		goto err_cleanup;

	if (ctx->xen_p2m_mfn) {
		ret = initialize_xen_map(ctx);
		if (ret != kdump_ok)
			return ret;
	}

	return ret;

 err_cleanup:
	diskdump_cleanup(ctx);
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
		return set_error(ctx, kdump_unsupported,
				 "Unknown diskdump signature");

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

const struct format_ops diskdump_ops = {
	.probe = diskdump_probe,
	.read_page = diskdump_read_page,
	.cleanup = diskdump_cleanup,
};

static const struct format_ops xen_dom0_ops = {
	.read_page = diskdump_read_xen_dom0,
	.read_xenmach_page = diskdump_read_page,
	.cleanup = diskdump_cleanup,
};
