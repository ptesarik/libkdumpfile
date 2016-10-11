/** @internal @file src/diskdump.c
 * @brief Routines to read diskdump/compressed kdump files.
 */
/* Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#if USE_LZO
# include <lzo/lzo1x.h>
#endif
#if USE_SNAPPY
# include <snappy-c.h>
#endif

#define SIG_LEN	8

/** @cond TARGET_ABI */

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

/** @endcond */

/** Descriptor of each page in vmcore. */
struct page_desc {
	uint64_t	offset;		/**< File offset of page data. */
	uint32_t	size;		/**< Size of this dump page. */
	uint32_t	flags;		/**< Flags. */
	uint64_t	page_flags;	/**< Page flags. */
};

/** PFN region mapping. */
struct pfn_rgn {
	kdump_pfn_t pfn;	/**< Starting PFN. */
	kdump_pfn_t cnt;	/**< Number of pages in this region. */
	off_t pos;		/**< File position of the first descriptor. */
};

/** Region mapping allocation increment.
 * For optimal performance, this should be a power of two.
 */
#define RGN_ALLOC_INC	1024

struct disk_dump_priv {
	struct pfn_rgn *pfn_rgn; /**< PFN region map. */
	size_t pfn_rgn_num;	 /**< Number of elements in the map. */

	/** Overridden methods for arch.page_size attribute. */
	struct attr_override page_size_override;
	int cbuf_slot;		/**< Compressed data per-context slot. */
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

static void diskdump_cleanup(struct kdump_shared *shared);

static kdump_status
add_pfn_rgn(kdump_ctx *ctx, const struct pfn_rgn *rgn)
{
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;

	if (ddp->pfn_rgn_num % RGN_ALLOC_INC == 0) {
		size_t num = ddp->pfn_rgn_num + RGN_ALLOC_INC;
		struct pfn_rgn *rgn =
			realloc(ddp->pfn_rgn, num * sizeof(struct pfn_rgn));
		if (!rgn)
			return set_error(ctx, kdump_syserr,
					 "Cannot allocate space for"
					 " %zu PFN region mappings", num);
		ddp->pfn_rgn = rgn;
	}

	ddp->pfn_rgn[ddp->pfn_rgn_num++] = *rgn;
	return kdump_ok;
}

static off_t
pfn_to_pdpos(struct disk_dump_priv *ddp, unsigned long pfn)
{
	size_t left = 0, right = ddp->pfn_rgn_num;
	while (left != right) {
		size_t mid = (left + right) / 2;
		const struct pfn_rgn *rgn = ddp->pfn_rgn + mid;
		if (pfn < rgn->pfn)
			right = mid;
		else if (pfn >= rgn->pfn + rgn->cnt)
			left = mid + 1;
		else
			return rgn->pos +
				(pfn - rgn->pfn) * sizeof(struct page_desc);
	}
	return (off_t)-1;
}

static kdump_status
diskdump_read_cache(kdump_ctx *ctx, kdump_pfn_t pfn, struct cache_entry *ce)
{
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;
	struct page_desc pd;
	off_t pd_pos;
	void *buf;
	ssize_t rd;
	kdump_status ret;

	pd_pos = pfn_to_pdpos(ddp, pfn);
	if (pd_pos == (off_t)-1) {
		memset(ce->data, 0, get_page_size(ctx));
		return kdump_ok;
	}

	rd = pread(get_file_fd(ctx), &pd, sizeof pd, pd_pos);
	if (rd != sizeof pd)
		return set_error(ctx, read_error(rd),
				 "Cannot read page descriptor at %llu",
				 (unsigned long long) pd_pos);

	pd.offset = dump64toh(ctx, pd.offset);
	pd.size = dump32toh(ctx, pd.size);
	pd.flags = dump32toh(ctx, pd.flags);
	pd.page_flags = dump64toh(ctx, pd.page_flags);

	if (pd.flags & DUMP_DH_COMPRESSED) {
		if (pd.size > MAX_PAGE_SIZE)
			return set_error(ctx, kdump_dataerr,
					 "Wrong compressed size: %lu",
					 (unsigned long)pd.size);
		buf = ctx->data[ddp->cbuf_slot];
	} else {
		if (pd.size != get_page_size(ctx))
			return set_error(ctx, kdump_dataerr,
					 "Wrong page size: %lu",
					 (unsigned long)pd.size);
		buf = ce->data;
	}

	/* read page data */
	rd = pread(get_file_fd(ctx), buf, pd.size, pd.offset);
	if (rd != pd.size)
		return set_error(ctx, read_error(rd),
				 "Cannot read page data at %llu",
				 (unsigned long long) pd.offset);

	if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
		ret = uncompress_page_gzip(ctx, ce->data, buf, pd.size);
		if (ret != kdump_ok)
			return ret;
	} else if (pd.flags & DUMP_DH_COMPRESSED_LZO) {
#if USE_LZO
		lzo_uint retlen = get_page_size(ctx);
		int ret = lzo1x_decompress_safe((lzo_bytep)buf, pd.size,
						(lzo_bytep)ce->data, &retlen,
						LZO1X_MEM_DECOMPRESS);
		if (ret != LZO_E_OK)
			return set_error(ctx, kdump_dataerr,
					 "Decompression failed: %d", ret);
		if (retlen != get_page_size(ctx))
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
		size_t retlen = get_page_size(ctx);
		snappy_status ret;
		ret = snappy_uncompress((char *)buf, pd.size,
					(char *)ce->data, &retlen);
		if (ret != SNAPPY_OK)
			return set_error(ctx, kdump_dataerr,
					 "Decompression failed: %d",
					 (int) ret);
		if (retlen != get_page_size(ctx))
			return set_error(ctx, kdump_dataerr,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
#else
		return set_error(ctx, kdump_unsupported,
				 "Unsupported compression method: %s",
				 "snappy");
#endif
	}

	return kdump_ok;
}

static kdump_status
diskdump_read_page(kdump_ctx *ctx, struct page_io *pio)
{
	if (pio->pfn >= get_max_pfn(ctx))
		return set_error(ctx, kdump_nodata, "Out-of-bounds PFN");

	return def_read_cache(ctx, pio, diskdump_read_cache, pio->pfn);
}

/** Reallocate buffer for compressed data.
 * @param ctx   Dump file object.
 * @param attr  "arch.page_size" attribute.
 * @returns     Error status.
 *
 * This function is used as a post-set handler for @c arch.page_size
 * to ensure that there is always a sufficiently large buffer for
 * compressed pages.
 */
static kdump_status
diskdump_realloc_compressed(kdump_ctx *ctx, struct attr_data *attr)
{
	const struct attr_ops *parent_ops;
	struct disk_dump_priv *ddp;
	int newslot;

	newslot = per_ctx_alloc(ctx->shared, attr_value(attr)->number);
	if (newslot < 0)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate buffer for compressed data");

	ddp = ctx->shared->fmtdata;
	if (ddp->cbuf_slot >= 0)
		per_ctx_free(ctx->shared, ddp->cbuf_slot);
	ddp->cbuf_slot = newslot;

	parent_ops = ddp->page_size_override.template.parent->ops;
	return (parent_ops && parent_ops->post_set)
		? parent_ops->post_set(ctx, attr)
		: kdump_ok;
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

	rd = pread(get_file_fd(ctx), info, size, off);
	if (rd != size)
		ret = set_error(ctx, read_error(rd),
				"Cannot read %zu VMCOREINFO bytes at %llu",
				size, (unsigned long long) off);

	if (ret == kdump_ok) {
		ret = set_attr_sized_string(
			ctx, gattr(ctx, GKI_linux_vmcoreinfo_raw),
			ATTR_DEFAULT, info, size);
		if (ret != kdump_ok)
			ret = set_error(ctx, ret, "Cannot set VMCOREINFO");
	}

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

	rd = pread(get_file_fd(ctx), notes, size, off);
	if (rd != size) {
		ret = set_error(ctx, read_error(rd),
				"Cannot read %zu note bytes at %llu",
				size, (unsigned long long) off);
		goto out;
	}

	ret = process_noarch_notes(ctx, notes, size);
	if (ret != kdump_ok) {
		ret = set_error(ctx, ret, "Cannot process noarch notes");
		goto out;
	}

	if (isset_arch_name(ctx)) {
		ret = process_arch_notes(ctx, notes, size);
		if (ret != kdump_ok)
			ret = set_error(ctx, ret, "Cannot process arch notes");
	}

 out:
	free(notes);

	return ret;
}

static kdump_pfn_t
skip_clear(unsigned char *bitmap, size_t size, kdump_pfn_t pfn)
{
	unsigned char *bp = bitmap + (pfn >> 3);
	int lead;

	if (bp >= bitmap + size)
		return pfn;

	lead = ffs(*bp >> (pfn & 7));
	if (lead)
		return pfn + lead - 1;

	pfn = (pfn | 7) + 1;
	++bp;
	while (bp < bitmap + size && *bp == 0x00)
		pfn += 8, ++bp;
	if (bp < bitmap + size)
		pfn += ffs(*bp) - 1;

	return pfn;
}

static kdump_pfn_t
skip_set(unsigned char *bitmap, size_t size, kdump_pfn_t pfn)
{
	unsigned char *bp = bitmap + (pfn >> 3);
	int lead;

	if (bp >= bitmap + size)
		return pfn;

	lead = ffs(~(*bp >> (pfn & 7)));
	if (lead)
		return pfn + lead - 1;

	pfn = (pfn | 7) + 1;
	++bp;
	while (bp < bitmap + size && *bp == 0xff)
		pfn += 8, ++bp;
	if (bp < bitmap + size)
		pfn += ffs(~(*bp)) - 1;

	return pfn;
}

static kdump_status
read_bitmap(kdump_ctx *ctx, int32_t sub_hdr_size,
	    int32_t bitmap_blocks)
{
	off_t off = (1 + sub_hdr_size) * get_page_size(ctx);
	off_t descoff;
	unsigned char *bitmap;
	size_t bitmapsize;
	kdump_pfn_t max_bitmap_pfn;
	kdump_pfn_t pfn;
	struct pfn_rgn rgn;
	ssize_t rd;
	kdump_status ret;

	descoff = off + bitmap_blocks * get_page_size(ctx);

	bitmapsize = bitmap_blocks * get_page_size(ctx);
	max_bitmap_pfn = (kdump_pfn_t)bitmapsize * 8;
	if (get_max_pfn(ctx) <= max_bitmap_pfn / 2) {
		/* partial dump */
		bitmap_blocks /= 2;
		bitmapsize = bitmap_blocks * get_page_size(ctx);
		off += bitmapsize;
		max_bitmap_pfn = (kdump_pfn_t)bitmapsize * 8;
	}

	if (get_max_pfn(ctx) > max_bitmap_pfn)
		set_max_pfn(ctx, max_bitmap_pfn);

	if (! (bitmap = ctx_malloc(bitmapsize, ctx, "page bitmap")) )
		return kdump_syserr;

	rd = pread(get_file_fd(ctx), bitmap, bitmapsize, off);
	if (rd != bitmapsize) {
		ret = set_error(ctx, read_error(rd),
				 "Cannot read %zu bytes of page bitmap"
				 " at %llu",
				 bitmapsize, (unsigned long long) off);
		goto out_free;
	}

	rgn.pos = descoff;
	pfn = 0;
	while (pfn < max_bitmap_pfn) {
		rgn.pfn = skip_clear(bitmap, bitmapsize, pfn);
		pfn = skip_set(bitmap, bitmapsize, rgn.pfn);
		rgn.cnt = pfn - rgn.pfn;
		if (rgn.cnt) {
			ret = add_pfn_rgn(ctx, &rgn);
			if (ret != kdump_ok)
				goto out_free;
			rgn.pos += rgn.cnt * sizeof(struct page_desc);
		}
	}

	ret = kdump_ok;

 out_free:
	free(bitmap);
	return ret;
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

	set_max_pfn(ctx, max_mapnr);

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

	rd = pread(get_file_fd(ctx), &subhdr, sizeof subhdr,
		   get_page_size(ctx));
	if (rd != sizeof subhdr)
		return set_error(ctx, read_error(rd),
				 "Cannot read subheader");

	set_phys_base(ctx, dump32toh(ctx, subhdr.phys_base));

	if (header_version >= 4) {
		sdp->note_off = dump64toh(ctx, subhdr.offset_note);
		sdp->note_sz = dump32toh(ctx, subhdr.size_note);
	} else if (header_version >= 3)
		ret = read_vmcoreinfo(ctx,
				      dump64toh(ctx, subhdr.offset_vmcoreinfo),
				      dump32toh(ctx, subhdr.size_vmcoreinfo));

	if (header_version >= 6)
		set_max_pfn(ctx, dump64toh(ctx, subhdr.max_mapnr_64));

	return ret;
}

static kdump_status
do_header_32(struct setup_data *sdp, struct disk_dump_header_32 *dh,
	     kdump_byte_order_t byte_order)
{
	kdump_ctx *ctx = sdp->ctx;
	kdump_status ret;

	set_byte_order(ctx, byte_order);
	set_ptr_size(ctx, 4);

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

	rd = pread(get_file_fd(ctx), &subhdr, sizeof subhdr,
		   get_page_size(ctx));
	if (rd != sizeof subhdr)
		return set_error(ctx, read_error(rd),
				 "Cannot read subheader");

	set_phys_base(ctx, dump64toh(ctx, subhdr.phys_base));

	if (header_version >= 4) {
		sdp->note_off = dump64toh(ctx, subhdr.offset_note);
		sdp->note_sz = dump64toh(ctx, subhdr.size_note);
	} else if (header_version >= 3)
		ret = read_vmcoreinfo(ctx,
				      dump64toh(ctx, subhdr.offset_vmcoreinfo),
				      dump64toh(ctx, subhdr.size_vmcoreinfo));

	if (header_version >= 6)
		set_max_pfn(ctx, dump64toh(ctx, subhdr.max_mapnr_64));

	return ret;
}

static kdump_status
do_header_64(struct setup_data *sdp, struct disk_dump_header_64 *dh,
	     kdump_byte_order_t byte_order)
{
	kdump_ctx *ctx = sdp->ctx;
	kdump_status ret;

	set_byte_order(ctx, byte_order);
	set_ptr_size(ctx, 8);

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
open_common(kdump_ctx *ctx, void *hdr)
{
	struct disk_dump_header_32 *dh32 = hdr;
	struct disk_dump_header_64 *dh64 = hdr;
	struct disk_dump_priv *ddp;
	struct setup_data sd;
	kdump_status ret;

	memset(&sd, 0, sizeof sd);
	sd.ctx = ctx;

	ddp = calloc(1, sizeof *ddp);
	if (!ddp)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate diskdump private data");

	attr_add_override(gattr(ctx, GKI_page_size),
			  &ddp->page_size_override);
	ddp->page_size_override.ops.post_set = diskdump_realloc_compressed;
	ddp->cbuf_slot = -1;

	ctx->shared->fmtdata = ddp;

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

	return ret;

 err_cleanup:
	diskdump_cleanup(ctx->shared);
	return ret;
}

static kdump_status
diskdump_probe(kdump_ctx *ctx, void *hdr)
{
	static const char magic_diskdump[] =
		{ 'D', 'I', 'S', 'K', 'D', 'U', 'M', 'P' };
	static const char magic_kdump[] =
		{ 'K', 'D', 'U', 'M', 'P', ' ', ' ', ' ' };

	if (!memcmp(hdr, magic_diskdump, sizeof magic_diskdump))
		set_file_description(ctx, "Diskdump");
	else if (!memcmp(hdr, magic_kdump, sizeof magic_kdump))
		set_file_description(ctx, "Compressed KDUMP");
	else
		return set_error(ctx, kdump_noprobe,
				 "Unrecognized diskdump signature");

	return open_common(ctx, hdr);
}

static void
diskdump_cleanup(struct kdump_shared *shared)
{
	struct disk_dump_priv *ddp = shared->fmtdata;

	if (ddp) {
		attr_remove_override(sgattr(shared, GKI_page_size),
				     &ddp->page_size_override);
		if (ddp->pfn_rgn)
			free(ddp->pfn_rgn);
		if (ddp->cbuf_slot >= 0)
			per_ctx_free(shared, ddp->cbuf_slot);
		free(ddp);
		shared->fmtdata = NULL;
	}
}

const struct format_ops diskdump_ops = {
	.name = "diskdump",
	.probe = diskdump_probe,
	.read_page = diskdump_read_page,
	.unref_page = cache_unref_page,
	.realloc_caches = def_realloc_caches,
	.cleanup = diskdump_cleanup,
};
