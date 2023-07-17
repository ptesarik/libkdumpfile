/** @internal @file src/kdumpfile/diskdump.c
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
#if USE_ZSTD
# include <zstd.h>
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

/* Sub header for KDUMP on 32-bit architectures with 64-bit entities aligned
 * to 32 bits (e.g. Intel IA-32).
 */
struct kdump_sub_header_32pack {
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

/* Sub header for KDUMP on 32-bit architectures with 64-bit entities aligned
 * to 64 bits (e.g. AArch32).
 */
struct kdump_sub_header_32pad {
	uint32_t	phys_base;
	int32_t		dump_level;	   /* header_version 1 and later */
	int32_t		split;		   /* header_version 2 and later */
	uint32_t	start_pfn;	   /* header_version 2 and later,
					      OBSOLETE! 32bit only, full
					      64bit in start_pfn_64. */
	uint32_t	end_pfn;	   /* header_version 2 and later,
					      OBSOLETE! 32bit only, full
					      64bit in end_pfn_64. */
	char		_pad1[4];	   /* alignment */
	uint64_t	offset_vmcoreinfo; /* header_version 3 and later */
	uint32_t	size_vmcoreinfo;   /* header_version 3 and later */
	char		_pad2[4];	   /* alignment */
	uint64_t	offset_note;	   /* header_version 4 and later */
	uint32_t	size_note;	   /* header_version 4 and later */
	char		_pad3[4];	   /* alignment */
	uint64_t	offset_eraseinfo;  /* header_version 5 and later */
	uint32_t	size_eraseinfo;	   /* header_version 5 and later */
	char		_pad4[4];	   /* alignment */
	uint64_t	start_pfn_64;	   /* header_version 6 and later */
	uint64_t	end_pfn_64;	   /* header_version 6 and later */
	uint64_t	max_mapnr_64;	   /* header_version 6 and later */
} __attribute__((packed));

/* Sub header for KDUMP */
struct kdump_sub_header_64 {
	uint64_t	phys_base;
	int32_t		dump_level;	   /* header_version 1 and later */
	int32_t		split;		   /* header_version 2 and later */
	uint64_t	start_pfn;	   /* header_version 2 and later */
	uint64_t	end_pfn;	   /* header_version 2 and later */
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

struct disk_dump_priv {
	/** Overridden methods for arch.page_size attribute. */
	struct attr_override page_size_override;
	int cbuf_slot;		/**< Compressed data per-context slot. */

	/** Number of split files in this dump. */
	unsigned num_files;

	/** Overridden methods for memory.bitmap attribute. */
	struct attr_override mem_pagemap_override;

	/** File offset of memory bitmap. */
	off_t mem_pagemap_off;

	/** Size of the memory bitmap. */
	size_t mem_pagemap_size;

	/** Memory region mapping. */
	struct pfn_file_map mem_pagemap;

	/** Page descriptor mapping. */
	struct pfn_file_map pdmap[];
};

struct setup_data {
	kdump_ctx_t *ctx;
	off_t note_off;
	size_t note_sz;
	int_fast32_t header_version;
	int_fast32_t sub_hdr_blocks;
};

/* flags */
#define DUMP_DH_COMPRESSED_ZLIB	0x1	/* page is compressed with zlib */
#define DUMP_DH_COMPRESSED_LZO	0x2	/* page is compressed with lzo */
#define DUMP_DH_COMPRESSED_SNAPPY 0x4	/* page is compressed with snappy */
#define DUMP_DH_COMPRESSED_ZSTD	0x20	/* page is compressed with zstd */

/* Any compression flag */
#define DUMP_DH_COMPRESSED	( 0	\
	| DUMP_DH_COMPRESSED_ZLIB	\
	| DUMP_DH_COMPRESSED_LZO	\
	| DUMP_DH_COMPRESSED_SNAPPY	\
	| DUMP_DH_COMPRESSED_ZSTD	\
		)

static void diskdump_cleanup(struct kdump_shared *shared);

/** Convert a PFN to a page descriptor file offset.
 * @param pdmap  Page descriptor mapping.
 * @param pfn    Page frame number.
 * @returns      File offset of struct page_desc,
 *               or @c (off_t)-1 if not found.
 */
static off_t
pfn_to_pdpos(const struct pfn_file_map *pdmap, unsigned long pfn)
{
	const struct pfn_region *rgn = find_pfn_region(pdmap, pfn);
	return rgn && pfn >= rgn->pfn
		? rgn->pos + (pfn - rgn->pfn) * sizeof(struct page_desc)
		: (off_t) -1;
}

static kdump_status
diskdump_get_bits(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		  kdump_addr_t first, kdump_addr_t last, unsigned char *bits)
{
	struct kdump_shared *shared = bmp->priv;
	struct disk_dump_priv *ddp;

	rwlock_rdlock(&shared->lock);
	ddp = shared->fmtdata;
	get_pfn_map_bits(ddp->pdmap, ddp->num_files, first, last, bits);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static kdump_status
diskdump_find_set(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		  kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	struct disk_dump_priv *ddp;
	kdump_status ret;

	rwlock_rdlock(&shared->lock);
	ddp = shared->fmtdata;
	ret = find_mapped_pfn(ddp->pdmap, ddp->num_files, idx)
		? KDUMP_OK
		: status_err(err, KDUMP_ERR_NODATA, "No such bit found");
	rwlock_unlock(&shared->lock);
	return ret;
}

static kdump_status
diskdump_find_clear(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		    kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	struct disk_dump_priv *ddp;

	rwlock_rdlock(&shared->lock);
	ddp = shared->fmtdata;
	*idx = find_unmapped_pfn(ddp->pdmap, ddp->num_files, *idx);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static void
diskdump_bmp_cleanup(const kdump_bmp_t *bmp)
{
	struct kdump_shared *shared = bmp->priv;
	shared_decref(shared);
}

static const struct kdump_bmp_ops diskdump_bmp_ops = {
	.get_bits = diskdump_get_bits,
	.find_set = diskdump_find_set,
	.find_clear = diskdump_find_clear,
	.cleanup = diskdump_bmp_cleanup,
};

static kdump_status
mem_pagemap_get_bits(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		     kdump_addr_t first, kdump_addr_t last,
		     unsigned char *bits)
{
	struct kdump_shared *shared = bmp->priv;
	struct disk_dump_priv *ddp;

	rwlock_rdlock(&shared->lock);
	ddp = shared->fmtdata;
	get_pfn_map_bits(&ddp->mem_pagemap, 1, first, last, bits);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static kdump_status
mem_pagemap_find_set(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		     kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	struct disk_dump_priv *ddp;
	kdump_status ret;

	rwlock_rdlock(&shared->lock);
	ddp = shared->fmtdata;
	ret = find_mapped_pfn(&ddp->mem_pagemap, 1, idx)
		? KDUMP_OK
		: status_err(err, KDUMP_ERR_NODATA, "No such bit found");
	rwlock_unlock(&shared->lock);
	return ret;
}

static kdump_status
mem_pagemap_find_clear(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		       kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	struct disk_dump_priv *ddp;

	rwlock_rdlock(&shared->lock);
	ddp = shared->fmtdata;
	*idx = find_unmapped_pfn(&ddp->mem_pagemap, 1, *idx);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static const struct kdump_bmp_ops mem_pagemap_ops = {
	.get_bits = mem_pagemap_get_bits,
	.find_set = mem_pagemap_find_set,
	.find_clear = mem_pagemap_find_clear,
	.cleanup = diskdump_bmp_cleanup,
};

static kdump_status
diskdump_read_page(struct page_io *pio)
{
	kdump_ctx_t *ctx = pio->ctx;
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;
	kdump_pfn_t pfn;
	const struct pfn_file_map *pdmap;
	struct page_desc pd;
	off_t pd_pos;
	void *buf;
	kdump_status ret;

	pfn = pio->addr.addr >> get_page_shift(ctx);
	if (pfn >= get_max_pfn(ctx))
		return set_error(ctx, KDUMP_ERR_NODATA, "Out-of-bounds PFN");

	pdmap = find_pfn_file_map(ddp->pdmap, ddp->num_files, pfn);
	pd_pos = pdmap && pdmap->start_pfn <= pfn
		? pfn_to_pdpos(pdmap, pfn)
		: (off_t) -1;
	if (pd_pos == (off_t)-1) {
		if (get_zero_excluded(ctx)) {
			memset(pio->chunk.data, 0, get_page_size(ctx));
			return KDUMP_OK;
		}
		return set_error(ctx, KDUMP_ERR_NODATA, "Excluded page");
	}

	mutex_lock(&ctx->shared->cache_lock);
	ret = fcache_pread(ctx->shared->fcache, &pd, sizeof pd,
			   pdmap->fidx, pd_pos);
	mutex_unlock(&ctx->shared->cache_lock);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read page descriptor at %llu",
				 (unsigned long long) pd_pos);

	pd.offset = dump64toh(ctx, pd.offset);
	pd.size = dump32toh(ctx, pd.size);
	pd.flags = dump32toh(ctx, pd.flags);
	pd.page_flags = dump64toh(ctx, pd.page_flags);

	if (pd.flags & DUMP_DH_COMPRESSED) {
		if (pd.size > MAX_PAGE_SIZE)
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong compressed size: %lu",
					 (unsigned long)pd.size);
		buf = ctx->data[ddp->cbuf_slot];
	} else {
		if (pd.size != get_page_size(ctx))
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong page size: %lu",
					 (unsigned long)pd.size);
		buf = pio->chunk.data;
	}

	/* read page data */
	mutex_lock(&ctx->shared->cache_lock);
	ret = fcache_pread(ctx->shared->fcache, buf, pd.size,
			   pdmap->fidx, pd.offset);
	mutex_unlock(&ctx->shared->cache_lock);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read page data at %llu",
				 (unsigned long long) pd.offset);

	if (pd.flags & DUMP_DH_COMPRESSED_ZLIB) {
		ret = uncompress_page_gzip(ctx, pio->chunk.data, buf, pd.size);
		if (ret != KDUMP_OK)
			return ret;
	} else if (pd.flags & DUMP_DH_COMPRESSED_LZO) {
#if USE_LZO
		lzo_uint retlen = get_page_size(ctx);
		int ret = lzo1x_decompress_safe((lzo_bytep)buf, pd.size,
						(lzo_bytep)pio->chunk.data,
						&retlen,
						LZO1X_MEM_DECOMPRESS);
		if (ret != LZO_E_OK)
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Decompression failed: %d", ret);
		if (retlen != get_page_size(ctx))
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
#else
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unsupported compression method: %s",
				 "lzo");
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_SNAPPY) {
#if USE_SNAPPY
		size_t retlen = get_page_size(ctx);
		snappy_status ret;
		ret = snappy_uncompress((char *)buf, pd.size,
					(char *)pio->chunk.data, &retlen);
		if (ret != SNAPPY_OK)
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Decompression failed: %d",
					 (int) ret);
		if (retlen != get_page_size(ctx))
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
#else
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unsupported compression method: %s",
				 "snappy");
#endif
	} else if (pd.flags & DUMP_DH_COMPRESSED_ZSTD) {
#if USE_ZSTD
		size_t ret;
		ret = ZSTD_decompress(pio->chunk.data, get_page_size(ctx),
				      buf, pd.size);
		if (ZSTD_isError(ret))
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Decompression failed: %s",
					 ZSTD_getErrorName(ret));
		if (ret != get_page_size(ctx))
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong uncompressed size: %zu", ret);
#else
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unsupported compression method: %s",
				 "zstd");
#endif
	}

	return KDUMP_OK;
}

static kdump_status
diskdump_get_page(struct page_io *pio)
{
	return cache_get_page(pio, diskdump_read_page);
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
diskdump_realloc_compressed(kdump_ctx_t *ctx, struct attr_data *attr)
{
	const struct attr_ops *parent_ops;
	struct disk_dump_priv *ddp;
	int newslot;

	newslot = per_ctx_alloc(ctx->shared, attr_value(attr)->number);
	if (newslot < 0)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate buffer for compressed data");

	ddp = ctx->shared->fmtdata;
	if (ddp->cbuf_slot >= 0)
		per_ctx_free(ctx->shared, ddp->cbuf_slot);
	ddp->cbuf_slot = newslot;

	parent_ops = ddp->page_size_override.template.parent->ops;
	return (parent_ops && parent_ops->post_set)
		? parent_ops->post_set(ctx, attr)
		: KDUMP_OK;
}

/** Read VMCOREINFO into its blob attribute.
 * @param ctx   Dump file object.
 * @param fidx  File index.
 * @param off   VMCOREINFO file offset.
 * @param size  VMCOREINFO size in bytes.
 */
static kdump_status
read_vmcoreinfo(kdump_ctx_t *ctx, unsigned fidx, off_t off, size_t size)
{
	struct fcache_chunk fch;
	kdump_attr_value_t val;
	kdump_status ret;

	ret = fcache_get_chunk(ctx->shared->fcache, &fch, size, fidx, off);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read %zu VMCOREINFO bytes at %llu",
				 size, (unsigned long long) off);

	val.blob = internal_blob_new_dup(fch.data, size);
	if (!val.blob)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s", "VMCOREINFO blob");
	ret = set_attr(ctx, gattr(ctx, GKI_linux_vmcoreinfo_raw),
		       ATTR_DEFAULT, &val);
	if (ret != KDUMP_OK)
		ret = set_error(ctx, ret, "Cannot set VMCOREINFO");

	fcache_put_chunk(&fch);
	return ret;
}

/* This function also sets architecture */
static kdump_status
read_notes(kdump_ctx_t *ctx, off_t off, size_t size)
{
	struct fcache_chunk fch;
	kdump_status ret;

	ret = fcache_get_chunk(ctx->shared->fcache, &fch, size, 0, off);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read %zu note bytes at %llu",
				 size, (unsigned long long) off);

	ret = process_noarch_notes(ctx, fch.data, size);
	if (ret != KDUMP_OK) {
		ret = set_error(ctx, ret, "Cannot process noarch notes");
		goto out;
	}

	if (isset_arch_name(ctx)) {
		ret = process_arch_notes(ctx, fch.data, size);
		if (ret != KDUMP_OK)
			ret = set_error(ctx, ret, "Cannot process arch notes");
	}

 out:
	fcache_put_chunk(&fch);
	return ret;
}

/** Read the page bitmap and translate it to PFN regions.
 * @param ctx            Dump file object.
 * @param pdmap          Target page descriptor map.
 * @param sub_hdr_size   Size of the sub header (in blocks).
 * @param bitmap_blocks  Number of page bitmap blocks.
 * @returns              Error status.
 */
static kdump_status
read_bitmap(kdump_ctx_t *ctx, struct pfn_file_map *pdmap,
	    int32_t sub_hdr_size, int32_t bitmap_blocks)
{
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;
	off_t off = (1 + sub_hdr_size) * get_page_size(ctx);
	off_t descoff;
	size_t bitmapsize;
	kdump_pfn_t max_bitmap_pfn;
	struct fcache_chunk fch;
	kdump_status ret;

	if (pdmap->fidx == 0)
		ddp->mem_pagemap_off = off;
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
	if (pdmap->fidx == 0)
		ddp->mem_pagemap_size = bitmapsize;

	if (get_max_pfn(ctx) > max_bitmap_pfn)
		set_max_pfn(ctx, max_bitmap_pfn);

	ret = fcache_get_chunk(ctx->shared->fcache,
			       &fch, bitmapsize, pdmap->fidx, off);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read %zu bytes of page bitmap"
				 " at %llu",
				 bitmapsize, (unsigned long long) off);

	if (max_bitmap_pfn > pdmap->end_pfn)
		max_bitmap_pfn = pdmap->end_pfn;
	ret = pfn_regions_from_bitmap(&ctx->err, pdmap, fch.data, false,
				      pdmap->start_pfn, max_bitmap_pfn,
				      descoff, sizeof(struct page_desc));

	fcache_put_chunk(&fch);
	return ret;
}

static kdump_status
try_header(kdump_ctx_t *ctx, int32_t block_size,
	   uint32_t bitmap_blocks, uint32_t max_mapnr)
{
	uint64_t maxcovered;
	kdump_status ret;

	/* Page size must be reasonable */
	if (block_size < MIN_PAGE_SIZE || block_size > MAX_PAGE_SIZE)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Out-of-bounds page size: %lu",
				 (unsigned long) block_size);

	/* Number of bitmap blocks should cover all pages in the system */
	maxcovered = (uint64_t)8 * bitmap_blocks * block_size;
	if (maxcovered < max_mapnr)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Page bitmap too small:"
				 " Need %llu bits, only %llu found",
				 (unsigned long long) max_mapnr,
				 (unsigned long long) maxcovered);

	/* basic sanity checks passed */
	ret = set_page_size(ctx, block_size);
	if (ret != KDUMP_OK)
		return ret;

	set_max_pfn(ctx, max_mapnr);

	return KDUMP_OK;
}

static kdump_status
parse_sub_hdr_32pack(struct setup_data *sdp, struct pfn_file_map *pdmap,
		     const struct kdump_sub_header_32pack *sh)
{
	kdump_ctx_t *ctx = sdp->ctx;
	kdump_status ret;

	set_phys_base(ctx, dump32toh(ctx, sh->phys_base));

	if (sdp->header_version >= 4) {
		sdp->note_off = dump64toh(ctx, sh->offset_note);
		sdp->note_sz = dump32toh(ctx, sh->size_note);
	} else if (sdp->header_version >= 3) {
		ret = read_vmcoreinfo(ctx, pdmap->fidx,
				      dump64toh(ctx, sh->offset_vmcoreinfo),
				      dump32toh(ctx, sh->size_vmcoreinfo));
		if (ret != KDUMP_OK)
			return ret;
	}

	pdmap->start_pfn = 0;
	pdmap->end_pfn = KDUMP_PFN_MAX;
	if (sdp->header_version >= 2 && sh->split) {
		pdmap->start_pfn = dump32toh(ctx, sh->start_pfn);
		pdmap->end_pfn = dump32toh(ctx, sh->end_pfn);
	}
	if (sdp->header_version >= 6) {
		if (sh->split) {
			pdmap->start_pfn = dump64toh(ctx, sh->start_pfn_64);
			pdmap->end_pfn = dump64toh(ctx, sh->end_pfn_64);
		}
		set_max_pfn(ctx, dump64toh(ctx, sh->max_mapnr_64));
	}

	return KDUMP_OK;
}

static kdump_status
parse_sub_hdr_32pad(struct setup_data *sdp, struct pfn_file_map *pdmap,
		    const struct kdump_sub_header_32pad *sh)
{
	kdump_ctx_t *ctx = sdp->ctx;
	kdump_status ret;

	set_phys_base(ctx, dump32toh(ctx, sh->phys_base));

	if (sdp->header_version >= 4) {
		sdp->note_off = dump64toh(ctx, sh->offset_note);
		sdp->note_sz = dump32toh(ctx, sh->size_note);
	} else if (sdp->header_version >= 3) {
		ret = read_vmcoreinfo(ctx, pdmap->fidx,
				      dump64toh(ctx, sh->offset_vmcoreinfo),
				      dump32toh(ctx, sh->size_vmcoreinfo));
		if (ret != KDUMP_OK)
			return ret;
	}

	pdmap->start_pfn = 0;
	pdmap->end_pfn = KDUMP_PFN_MAX;
	if (sdp->header_version >= 2 && sh->split) {
		pdmap->start_pfn = dump32toh(ctx, sh->start_pfn);
		pdmap->end_pfn = dump32toh(ctx, sh->end_pfn);
	}
	if (sdp->header_version >= 6) {
		if (sh->split) {
			pdmap->start_pfn = dump64toh(ctx, sh->start_pfn_64);
			pdmap->end_pfn = dump64toh(ctx, sh->end_pfn_64);
		}
		set_max_pfn(ctx, dump64toh(ctx, sh->max_mapnr_64));
	}

	return KDUMP_OK;
}

static kdump_status
read_sub_hdr_32(struct setup_data *sdp, struct pfn_file_map *pdmap)
{
	kdump_ctx_t *ctx = sdp->ctx;
	union {
		struct kdump_sub_header_32pack pack;
		struct kdump_sub_header_32pad pad;
	} subhdr;
	uint_fast64_t off_payload, off_vmci;
	uint_fast32_t sz_vmci;
	kdump_status ret;

	if (sdp->header_version < 0)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid header version: %ld",
				 (long) sdp->header_version);

	if (sdp->header_version < 1)
		return KDUMP_OK;

	ret = fcache_pread(ctx->shared->fcache, &subhdr, sizeof subhdr,
			   pdmap->fidx, get_page_size(ctx));
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read subheader");

	/* No differences in layout up to version 2 */
	if (sdp->header_version < 3)
		return parse_sub_hdr_32pack(sdp, pdmap, &subhdr.pack);

	off_payload = get_page_size(ctx) * (1 + sdp->sub_hdr_blocks);
	off_vmci = dump64toh(ctx, subhdr.pack.offset_vmcoreinfo);
	sz_vmci = dump32toh(ctx, subhdr.pack.size_vmcoreinfo);
	if ((!off_vmci && !sz_vmci) ||
	    (off_vmci > get_page_size(ctx) &&
	     off_vmci + sz_vmci <= off_payload))
		return parse_sub_hdr_32pack(sdp, pdmap, &subhdr.pack);
	else
		return parse_sub_hdr_32pad(sdp, pdmap, &subhdr.pad);
}

static kdump_status
do_header_32(struct setup_data *sdp, struct disk_dump_header_32 *dh,
	     kdump_byte_order_t byte_order)
{
	kdump_ctx_t *ctx = sdp->ctx;
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;
	kdump_status ret;
	unsigned fidx;

	set_byte_order(ctx, byte_order);
	set_ptr_size(ctx, 4);
	sdp->header_version = dump32toh(ctx, dh->header_version);

	ret = KDUMP_OK;
	for (fidx = 0; fidx < get_num_files(ctx); ++fidx) {
		struct pfn_file_map *pdmap = &ddp->pdmap[fidx];
		pdmap->fidx = fidx;

		ret = fcache_pread(ctx->shared->fcache, dh, sizeof *dh,
				   fidx, 0);
		if (ret != KDUMP_OK) {
			ret = set_error(ctx, ret, "Cannot read header");
			break;
		}

		ret = try_header(ctx, dump32toh(ctx, dh->block_size),
				 dump32toh(ctx, dh->bitmap_blocks),
				 dump32toh(ctx, dh->max_mapnr));
		if (ret != KDUMP_OK)
			break;

		sdp->sub_hdr_blocks = dump32toh(ctx, dh->sub_hdr_size);
		ret = read_sub_hdr_32(sdp, pdmap);
		if (ret != KDUMP_OK)
			break;

		ret = read_bitmap(ctx, pdmap, sdp->sub_hdr_blocks,
				  dump32toh(ctx, dh->bitmap_blocks));
		if (ret != KDUMP_OK)
			break;
	}

	return set_error(ctx, ret, "File #%u", fidx);
}

static kdump_status
try_header_32(struct setup_data *sdp, struct disk_dump_header_32 *dh)
{
	kdump_ctx_t *ctx = sdp->ctx;
	kdump_status ret;

	ret = try_header(ctx, le32toh(dh->block_size),
			 le32toh(dh->bitmap_blocks),
			 le32toh(dh->max_mapnr));
	if (ret == KDUMP_OK)
		return do_header_32(sdp, dh, KDUMP_LITTLE_ENDIAN);

	if (ret != KDUMP_ERR_CORRUPT)
		return ret;
	clear_error(ctx);

	ret = try_header(ctx, be32toh(dh->block_size),
			 be32toh(dh->bitmap_blocks),
			 be32toh(dh->max_mapnr));
	if (ret == KDUMP_OK)
		return do_header_32(sdp, dh, KDUMP_BIG_ENDIAN);

	return ret;
}

static kdump_status
read_sub_hdr_64(struct setup_data *sdp, struct pfn_file_map *pdmap)
{
	kdump_ctx_t *ctx = sdp->ctx;
	struct kdump_sub_header_64 subhdr;
	kdump_status ret;

	if (sdp->header_version < 0)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid header version: %ld",
				 (long) sdp->header_version);

	if (sdp->header_version < 1)
		return KDUMP_OK;

	ret = fcache_pread(ctx->shared->fcache, &subhdr, sizeof subhdr,
			   pdmap->fidx, get_page_size(ctx));
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read subheader");

	set_phys_base(ctx, dump64toh(ctx, subhdr.phys_base));

	if (sdp->header_version >= 4) {
		sdp->note_off = dump64toh(ctx, subhdr.offset_note);
		sdp->note_sz = dump64toh(ctx, subhdr.size_note);
	} else if (sdp->header_version >= 3) {
		ret = read_vmcoreinfo(ctx, pdmap->fidx,
				      dump64toh(ctx, subhdr.offset_vmcoreinfo),
				      dump64toh(ctx, subhdr.size_vmcoreinfo));
		if (ret != KDUMP_OK)
			return ret;
	}

	pdmap->start_pfn = 0;
	pdmap->end_pfn = KDUMP_PFN_MAX;
	if (sdp->header_version >= 2 && subhdr.split) {
		pdmap->start_pfn = dump64toh(ctx, subhdr.start_pfn);
		pdmap->end_pfn = dump64toh(ctx, subhdr.end_pfn);
	}
	if (sdp->header_version >= 6) {
		if (subhdr.split) {
			pdmap->start_pfn = dump64toh(ctx, subhdr.start_pfn_64);
			pdmap->end_pfn = dump64toh(ctx, subhdr.end_pfn_64);
		}
		set_max_pfn(ctx, dump64toh(ctx, subhdr.max_mapnr_64));
	}

	return KDUMP_OK;
}

static kdump_status
do_header_64(struct setup_data *sdp, struct disk_dump_header_64 *dh,
	     kdump_byte_order_t byte_order)
{
	kdump_ctx_t *ctx = sdp->ctx;
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;
	kdump_status ret;
	unsigned fidx;

	set_byte_order(ctx, byte_order);
	set_ptr_size(ctx, 8);
	sdp->header_version = dump32toh(ctx, dh->header_version);

	ret = KDUMP_OK;
	for (fidx = 0; fidx < get_num_files(ctx); ++fidx) {
		struct pfn_file_map *pdmap = &ddp->pdmap[fidx];
		pdmap->fidx = fidx;

		ret = fcache_pread(ctx->shared->fcache, dh, sizeof *dh,
				   fidx, 0);
		if (ret != KDUMP_OK) {
			ret = set_error(ctx, ret, "Cannot read header");
			break;
		}

		ret = try_header(ctx, dump32toh(ctx, dh->block_size),
				 dump32toh(ctx, dh->bitmap_blocks),
				 dump32toh(ctx, dh->max_mapnr));
		if (ret != KDUMP_OK)
			break;

		sdp->sub_hdr_blocks = dump32toh(ctx, dh->sub_hdr_size);
		ret = read_sub_hdr_64(sdp, pdmap);
		if (ret != KDUMP_OK)
			break;

		ret = read_bitmap(ctx, pdmap, sdp->sub_hdr_blocks,
				  dump32toh(ctx, dh->bitmap_blocks));
		if (ret != KDUMP_OK)
			break;
	}

	return set_error(ctx, ret, "File #%u", fidx);
}

static kdump_status
try_header_64(struct setup_data *sdp, struct disk_dump_header_64 *dh)
{
	kdump_ctx_t *ctx = sdp->ctx;
	kdump_status ret;

	ret = try_header(ctx, le32toh(dh->block_size),
			 le32toh(dh->bitmap_blocks),
			 le32toh(dh->max_mapnr));
	if (ret == KDUMP_OK)
		return do_header_64(sdp, dh, KDUMP_LITTLE_ENDIAN);

	if (ret != KDUMP_ERR_CORRUPT)
		return ret;
	clear_error(ctx);

	ret = try_header(ctx, be32toh(dh->block_size),
			 be32toh(dh->bitmap_blocks),
			 be32toh(dh->max_mapnr));
	if (ret == KDUMP_OK)
		return do_header_64(sdp, dh, KDUMP_BIG_ENDIAN);

	return ret;
}

static kdump_status
mem_pagemap_revalidate(kdump_ctx_t *ctx, struct attr_data *attr)
{
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;
	attr_revalidate_fn *parent_revalidate;
	const struct attr_ops *parent_ops;
	struct fcache_chunk fch;
	kdump_pfn_t maxpfn;
	kdump_status status;

	status = fcache_get_chunk(ctx->shared->fcache, &fch,
				  ddp->mem_pagemap_size, 0,
				  ddp->mem_pagemap_off);
	if (status != KDUMP_OK)
		return set_error(ctx, status,
				 "Cannot read %zu bytes of page bitmap"
				 " at %llu",
				 ddp->mem_pagemap_size,
				 (unsigned long long) ddp->mem_pagemap_off);

	ddp->mem_pagemap.start_pfn = 0;
	ddp->mem_pagemap.end_pfn = KDUMP_PFN_MAX;
	maxpfn = (kdump_pfn_t) ddp->mem_pagemap_size * 8;
	status = pfn_regions_from_bitmap(&ctx->err, &ddp->mem_pagemap,
					 fch.data, false, 0, maxpfn, 0, 0);
	fcache_put_chunk(&fch);

	parent_ops = ddp->mem_pagemap_override.template.parent->ops;
	parent_revalidate = parent_ops ? parent_ops->revalidate : NULL;
	if (status == KDUMP_OK && parent_revalidate)
		status = parent_revalidate(ctx, attr);
	if (status == KDUMP_OK) {
		ddp->mem_pagemap_override.ops.revalidate = parent_revalidate;
		attr->flags.invalid = 0;
	}
	return status;
}

static kdump_status
init_mem_pagemap(kdump_ctx_t *ctx)
{
	struct disk_dump_priv *ddp = ctx->shared->fmtdata;
	struct attr_data *attr = gattr(ctx, GKI_memory_pagemap);
	kdump_attr_value_t val;

	val.bitmap = kdump_bmp_new(&mem_pagemap_ops);
	if (!val.bitmap)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate memory pagemap");
	val.bitmap->priv = ctx->shared;
	shared_incref_locked(ctx->shared);

	attr_add_override(attr, &ddp->mem_pagemap_override);
	ddp->mem_pagemap_override.ops.revalidate = mem_pagemap_revalidate;
	return set_attr(ctx, attr, ATTR_INVALID, &val);
}

static kdump_status
open_common(kdump_ctx_t *ctx, void *hdr)
{
	struct disk_dump_header_32 *dh32 = hdr;
	struct disk_dump_header_64 *dh64 = hdr;
	struct disk_dump_priv *ddp;
	struct setup_data sd;
	kdump_bmp_t *bmp;
	kdump_status ret;

	memset(&sd, 0, sizeof sd);
	sd.ctx = ctx;

	ddp = calloc(1, sizeof(*ddp) +
		     get_num_files(ctx) * sizeof(ddp->pdmap[0]));
	if (!ddp)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate diskdump private data");
	ddp->num_files = get_num_files(ctx);

	attr_add_override(gattr(ctx, GKI_page_size),
			  &ddp->page_size_override);
	ddp->page_size_override.ops.post_set = diskdump_realloc_compressed;
	ddp->cbuf_slot = -1;

	ctx->shared->fmtdata = ddp;

	set_addrspace_caps(ctx->xlat, ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR));

	ret = try_header_32(&sd, dh32);
	if (ret == KDUMP_ERR_CORRUPT) {
		clear_error(ctx);
		ret = try_header_64(&sd, dh64);
	}
	if (ret == KDUMP_ERR_CORRUPT) {
		clear_error(ctx);
		ret = set_error(ctx, KDUMP_ERR_NOTIMPL,
				"Invalid diskdump header content");
	}
	if (ret != KDUMP_OK)
		goto err_cleanup;

	sort_pfn_file_maps(ddp->pdmap, ddp->num_files);

	bmp = kdump_bmp_new(&diskdump_bmp_ops);
	if (!bmp) {
		ret = set_error(ctx, KDUMP_ERR_SYSTEM,
				"Cannot allocate file pagemap");
		goto err_cleanup;
	}
	bmp->priv = ctx->shared;
	shared_incref_locked(ctx->shared);
	set_file_pagemap(ctx, bmp);

	ret = init_mem_pagemap(ctx);
	if (ret != KDUMP_OK)
		goto err_cleanup;

	if (uts_looks_sane(&dh32->utsname))
		set_uts(ctx, &dh32->utsname);
	else if (uts_looks_sane(&dh64->utsname))
		set_uts(ctx, &dh64->utsname);

	if (sd.note_sz) {
		ret = read_notes(ctx, sd.note_off, sd.note_sz);
		if (ret != KDUMP_OK)
			goto err_cleanup;
	}

	return ret;

 err_cleanup:
	diskdump_cleanup(ctx->shared);
	return ret;
}

static kdump_status
diskdump_probe(kdump_ctx_t *ctx)
{
	static const char magic_diskdump[] =
		{ 'D', 'I', 'S', 'K', 'D', 'U', 'M', 'P' };
	static const char magic_kdump[] =
		{ 'K', 'D', 'U', 'M', 'P', ' ', ' ', ' ' };

	char hdr[sizeof(struct disk_dump_header_64)];
	kdump_status status;

	status = fcache_pread(ctx->shared->fcache, hdr, sizeof hdr, 0, 0);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot read dump header");

	if (!memcmp(hdr, magic_diskdump, sizeof magic_diskdump))
		set_file_description(ctx, "Diskdump");
	else if (!memcmp(hdr, magic_kdump, sizeof magic_kdump))
		set_file_description(ctx, "Compressed KDUMP");
	else
		return set_error(ctx, KDUMP_NOPROBE,
				 "Unrecognized diskdump signature");

	return open_common(ctx, hdr);
}

static void
diskdump_attr_cleanup(struct attr_dict *dict)
{
	struct disk_dump_priv *ddp = dict->shared->fmtdata;

	attr_remove_override(dgattr(dict, GKI_page_size),
			     &ddp->page_size_override);
	attr_remove_override(dgattr(dict, GKI_memory_pagemap),
			     &ddp->mem_pagemap_override);
}

static void
diskdump_cleanup(struct kdump_shared *shared)
{
	struct disk_dump_priv *ddp = shared->fmtdata;

	if (ddp) {
		unsigned fidx;
		for (fidx = 0; fidx < ddp->num_files; ++fidx) {
			struct pfn_file_map *pdmap = &ddp->pdmap[fidx];
			if (pdmap->regions)
				free(pdmap->regions);
		}
		if (ddp->cbuf_slot >= 0)
			per_ctx_free(shared, ddp->cbuf_slot);
		free(ddp);
		shared->fmtdata = NULL;
	}
}

const struct format_ops diskdump_ops = {
	.name = "diskdump",
	.probe = diskdump_probe,
	.get_page = diskdump_get_page,
	.put_page = cache_put_page,
	.realloc_caches = def_realloc_caches,
	.attr_cleanup = diskdump_attr_cleanup,
	.cleanup = diskdump_cleanup,
};
