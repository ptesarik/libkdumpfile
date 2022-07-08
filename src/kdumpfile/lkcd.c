/** @internal @file src/kdumpfile/lkcd.c
 * @brief Routines to read LKCD dump files.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** @cond TARGET_ABI */

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

/** @endcond  */

/* Split the 32-bit PFN into 3 indices */
#define PFN_IDX1_BITS	10
#define PFN_IDX2_BITS	10
#define PFN_IDX3_BITS	12

#define PFN_IDX1_SIZE	((uint32_t)1 << PFN_IDX1_BITS)
#define PFN_IDX2_SIZE	((uint32_t)1 << PFN_IDX2_BITS)
#define PFN_IDX3_SIZE	((uint32_t)1 << PFN_IDX3_BITS)
#define PFN_IDX3_MASK	(PFN_IDX3_SIZE - 1)

#define pfn_idx1(pfn) \
	((uint32_t)(pfn) >> (PFN_IDX3_BITS + PFN_IDX2_BITS))
#define pfn_idx2(pfn) \
	(((uint32_t)(pfn) >> PFN_IDX3_BITS) & (PFN_IDX2_SIZE - 1))
#define pfn_idx3(pfn) \
	((uint32_t)(pfn) & (PFN_IDX3_SIZE - 1))

/**  Contiguous block of pages
 *
 * Storing only a 32-bit offset from the block beginning saves
 * 50% of the space used by @c offs.
 */
struct pfn_block {
	off_t filepos;		/**< absolute file offset */
	uint32_t idx3;		/**< level-3 index of first pfn in range */
	unsigned short n;	/**< number of pages */
	unsigned short alloc;	/**< allocated pages */
	uint32_t *offs;		/**< offsets from filepos */
	struct pfn_block *next;	/**< pointer to next block */
};

#define MAX_PFN_GAP 15

/* Maximum size of the format name: the version field is a 32-bit integer,
 * so it cannot be longer than 10 decimal digits.
 */
#define LKCD_FORMAT_PFX	"Linux Kernel Crash Dump v"
#define MAX_FORMAT_NAME	(sizeof(LKCD_FORMAT_PFX) + 10)

struct lkcd_priv {
	off_t data_offset;	/* offset to 1st page */
	off_t last_offset;	/* offset of last page parsed so far */
	off_t end_offset;	/* offset of end marker */

	unsigned version;
	unsigned compression;

	mutex_t pfn_block_mutex;
	struct pfn_block ***pfn_level1;
	unsigned l1_size;

	/** Overridden methods for arch.page_size attribute. */
	struct attr_override page_size_override;
	int cbuf_slot;		/**< Compressed data per-context slot. */

	/** Overridden methods for max.pfn attribute. */
	struct attr_override max_pfn_override;
	kdump_pfn_t max_pfn;	/**< Maximum PFN seen so far. */

	char format[MAX_FORMAT_NAME];
};

static void lkcd_cleanup(struct kdump_shared *shared);

static struct pfn_block **
get_pfn_slot(kdump_ctx_t *ctx, kdump_pfn_t pfn)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	struct pfn_block **l2;
	unsigned idx;

	idx = pfn_idx1(pfn);
	if (idx >= lkcdp->l1_size) {
		struct pfn_block ***new_l1;
		new_l1 = realloc(lkcdp->pfn_level1,
				 (idx + 1) * sizeof(*new_l1));
		if (!new_l1) {
			set_error(ctx, KDUMP_ERR_SYSTEM,
				  "Cannot allocate PFN level-%u table", 1);
			return NULL;
		}

		memset(new_l1 + lkcdp->l1_size, 0,
		       (idx + 1 - lkcdp->l1_size) * sizeof(*new_l1));
		lkcdp->pfn_level1 = new_l1;
		lkcdp->l1_size = idx + 1;
	}

	l2 = lkcdp->pfn_level1[idx];
	if (!l2) {
		l2 = calloc(PFN_IDX2_SIZE, sizeof(struct pfn_block*));
		if (!l2) {
			set_error(ctx, KDUMP_ERR_SYSTEM,
				  "Cannot allocate PFN level-%u table", 2);
			return NULL;
		}
		lkcdp->pfn_level1[idx] = l2;
	}

	return &l2[pfn_idx2(pfn)];
}

static struct pfn_block *
alloc_pfn_block(kdump_ctx_t *ctx, kdump_pfn_t pfn)
{
	struct pfn_block **pprev, *block;

	pprev = get_pfn_slot(ctx, pfn);
	if (!pprev)
		return NULL;

	block = ctx_malloc(sizeof(struct pfn_block), ctx, "PFN block");
	if (!block)
		return NULL;

	block->idx3 = pfn_idx3(pfn);
	block->n = 0;
	block->alloc = 0;
	block->offs = NULL;

	while (*pprev) {
		if ((*pprev)->idx3 >= block->idx3)
			break;
		pprev = &(*pprev)->next;
	}
	block->next = *pprev;
	*pprev = block;

	return block;
}

static kdump_status
realloc_pfn_offs(struct pfn_block *block, unsigned short alloc)
{
	uint32_t *newoffs;

	if (block->alloc == alloc)
		return KDUMP_OK;

	newoffs = realloc(block->offs, alloc * sizeof(uint32_t));
	if (!newoffs)
		return KDUMP_ERR_SYSTEM;

	if (alloc > block->alloc)
		memset(newoffs + block->alloc, 0,
		       (alloc - block->alloc) * sizeof(uint32_t));

	block->alloc = alloc;
	block->offs = newoffs;
	return KDUMP_OK;
}

static kdump_status
error_pfn_offs(kdump_ctx_t *ctx, kdump_status res)
{
	return set_error(ctx, res, "Cannot allocate PFN block offs");
}

static kdump_status
alloc_tail_pfn_block(kdump_ctx_t *ctx, struct pfn_block *block,
		     unsigned short idx, unsigned short nextidx)
{
	struct pfn_block *next;
	uint32_t blockoff;
	kdump_status res;

	next = ctx_malloc(sizeof(struct pfn_block), ctx, "PFN block");
	if (!next)
		return KDUMP_ERR_SYSTEM;

	next->idx3 = block->idx3 + nextidx + 1;
	next->n = block->n - nextidx - 1;
	next->alloc = 0;
	next->offs = NULL;
	res = realloc_pfn_offs(next, next->n);
	if (res != KDUMP_OK) {
		free(next);
		return error_pfn_offs(ctx, res);
	}

	blockoff = block->offs[nextidx];
	next->filepos = block->filepos + blockoff;
	for (idx = 0; idx < next->n; ++idx)
		next->offs[idx] = block->offs[++nextidx] - blockoff;

	next->next = block->next;
	block->next = next;

	return KDUMP_OK;
}

static kdump_status
split_pfn_block(kdump_ctx_t *ctx, struct pfn_block *block, unsigned short idx)
{
	unsigned short nextidx;
	kdump_status res;

	nextidx = idx;
	while (nextidx < block->n && block->offs[nextidx] == 0)
		++nextidx;
	if (nextidx < block->n) {
		res = alloc_tail_pfn_block(ctx, block, idx, nextidx);
		if (res != KDUMP_OK)
			return res;
	}

	block->n = idx - 1;
	realloc_pfn_offs(block, block->n);

	return KDUMP_OK;
}

static struct pfn_block *
lookup_pfn_block(kdump_ctx_t *ctx, kdump_pfn_t pfn, unsigned short tolerance)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	struct pfn_block **l2, *block;
	unsigned idx;

	idx = pfn_idx1(pfn);
	if (idx >= lkcdp->l1_size)
		return NULL;

	l2 = lkcdp->pfn_level1[idx];
	if (!l2)
		return NULL;

	idx = pfn_idx2(pfn);
	block = l2[idx];

	idx = pfn_idx3(pfn);
	while (block) {
		if (block->idx3 > idx)
			break;
		if (idx <= block->idx3 + block->n + tolerance)
			return block;
		block = block->next;
	}

	return NULL;
}

static int
idx_fits_block(unsigned idx, struct pfn_block *block)
{
	unsigned blockend;

	if (idx < block->idx3)
		return 0;

	blockend = block->idx3 + block->n;
	if (idx <= blockend)
		return 1;
	if (idx > blockend + MAX_PFN_GAP)
		return 0;
	if (idx > (block->idx3 | (PFN_IDX3_SIZE - 1)))
		return 0;

	if (block->next && block->next->idx3 <= idx)
		return 0;

	return 1;
}

static kdump_status
read_page_desc(kdump_ctx_t *ctx, struct dump_page *dp, off_t off)
{
	kdump_status ret;

	ret = fcache_pread(ctx->shared->fcache, dp, sizeof *dp, 0, off);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read page descriptor at %llu",
				 (unsigned long long) off);

	dp->dp_address = dump64toh(ctx, dp->dp_address);
	dp->dp_size = dump32toh(ctx, dp->dp_size);
	dp->dp_flags = dump32toh(ctx, dp->dp_flags);
	return KDUMP_OK;
}

static kdump_status
error_dup(kdump_ctx_t *ctx, off_t off, struct pfn_block *block, kdump_pfn_t pfn)
{
	off_t prevoff = block->filepos;
	unsigned idx = pfn_idx3(pfn);
	if (idx > block->idx3)
		prevoff += block->offs[idx - block->idx3 - 1];
	return set_error(ctx, KDUMP_ERR_CORRUPT,
			 "Duplicate PFN 0x%llx at %lld (previous %lld)",
			 (unsigned long long) pfn,
			 (unsigned long long) off,
			 (unsigned long long) prevoff);
}

static kdump_status
search_page_desc(kdump_ctx_t *ctx, kdump_pfn_t pfn,
		 struct dump_page *dp, off_t *dataoff)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	off_t off;
	kdump_pfn_t curpfn, blocktbl;
	struct pfn_block *block;
	unsigned short idx;
	kdump_status res;

	off = lkcdp->last_offset;
	if (off == lkcdp->end_offset)
		return set_error(ctx, KDUMP_ERR_NODATA, "Page not found");

	block = NULL;
	do {
		res = read_page_desc(ctx, dp, off);
		if (res != KDUMP_OK) {
			if (res == KDUMP_ERR_EOF)
				lkcdp->end_offset = off;
			if (block)
				realloc_pfn_offs(block, block->n);
			return res;
		}

		if (dp->dp_flags & DUMP_END) {
			lkcdp->end_offset = off;
			if (block)
				realloc_pfn_offs(block, block->n);
			return set_error(ctx, KDUMP_ERR_NODATA, "Page not found");
		}

		curpfn = dp->dp_address >> get_page_shift(ctx);
		if (!block)
			block = lookup_pfn_block(ctx, curpfn, MAX_PFN_GAP);
		else if (blocktbl != (curpfn & ~PFN_IDX3_MASK) ||
			 !idx_fits_block(pfn_idx3(curpfn), block)) {
			realloc_pfn_offs(block, block->n);
			block = lookup_pfn_block(ctx, curpfn, MAX_PFN_GAP);
		}
		if (block && off - block->filepos > UINT32_MAX) {
			idx = pfn_idx3(curpfn) - block->idx3;
			res = split_pfn_block(ctx, block, idx);
			if (res != KDUMP_OK)
				return set_error(ctx, res,
						 "Cannot split PFN block");
			block = NULL;
		}
		if (block) {
			idx = pfn_idx3(curpfn) - block->idx3;
			if (!idx--)
				return error_dup(ctx, off, block, curpfn);
			if (idx >= block->n)
				block->n = idx + 1;
			if (block->n >= block->alloc) {
				res = realloc_pfn_offs(block, PFN_IDX3_SIZE);
				if (res != KDUMP_OK)
					return error_pfn_offs(ctx, res);
			}
		}

		blocktbl = curpfn & ~PFN_IDX3_MASK;
		if (!block) {
			block = alloc_pfn_block(ctx, curpfn);
			if (!block)
				return KDUMP_ERR_SYSTEM;
			block->filepos = off;
		} else if (block->offs[idx] == 0)
			block->offs[idx] = off - block->filepos;
		else
			return error_dup(ctx, off, block, curpfn);

		if (curpfn >= lkcdp->max_pfn)
			lkcdp->max_pfn = curpfn + 1;

		off += sizeof(struct dump_page) + dp->dp_size;
		lkcdp->last_offset = off;
	} while (curpfn != pfn);

	*dataoff = off - dp->dp_size;
	return KDUMP_OK;
}

static inline int
idx_is_gap(struct pfn_block *block, unsigned idx)
{
	if (idx <= block->idx3)
		return 0;
	return block->offs[idx - block->idx3 - 1] == 0;
}

static kdump_status
get_page_desc(kdump_ctx_t *ctx, kdump_pfn_t pfn,
	      struct dump_page *dp, off_t *dataoff)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	struct pfn_block *block;
	unsigned idx;
	kdump_status status;

	mutex_lock(&lkcdp->pfn_block_mutex);

	block = lookup_pfn_block(ctx, pfn, 0);
	idx = pfn_idx3(pfn);
	if (block && !idx_is_gap(block, idx)) {
		off_t off = block->filepos;
		if (idx > block->idx3)
			off += block->offs[idx - block->idx3 - 1];
		*dataoff = off + sizeof *dp;
		status = read_page_desc(ctx, dp, off);
	} else
		status = search_page_desc(ctx, pfn, dp, dataoff);

	mutex_unlock(&lkcdp->pfn_block_mutex);

	return status;
}

static kdump_status
lkcd_max_pfn_revalidate(kdump_ctx_t *ctx, struct attr_data *attr)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	attr_revalidate_fn *parent_revalidate;
	const struct attr_ops *parent_ops;
	kdump_status res;

	mutex_lock(&lkcdp->pfn_block_mutex);

	if (lkcdp->last_offset != lkcdp->end_offset) {
		struct dump_page dummy_dp;
		off_t dummy_off;

		mutex_lock(&ctx->shared->cache_lock);
		res = search_page_desc(ctx, ~(kdump_pfn_t)0,
				       &dummy_dp, &dummy_off);
		mutex_unlock(&ctx->shared->cache_lock);
		if (res == KDUMP_ERR_NODATA) {
			clear_error(ctx);
			res = KDUMP_OK;
		}
		if (res != KDUMP_OK)
			res = set_error(ctx, res, "Cannot get max_pfn");
	} else
		res = KDUMP_OK;

	parent_ops = lkcdp->max_pfn_override.template.parent->ops;
	parent_revalidate = parent_ops ? parent_ops->revalidate : NULL;
	lkcdp->max_pfn_override.ops.revalidate = parent_revalidate;

	if (res == KDUMP_OK) {
		kdump_attr_value_t val;
		val.number = lkcdp->max_pfn;
		res = set_attr(ctx, attr, ATTR_DEFAULT, &val);
	}

	mutex_unlock(&lkcdp->pfn_block_mutex);

	if (res == KDUMP_OK && parent_revalidate)
		res = parent_revalidate(ctx, attr);
	return res;
}

static kdump_status
lkcd_read_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	kdump_pfn_t pfn;
	struct dump_page dp;
	unsigned type;
	off_t off;
	void *buf;
	kdump_status ret;

	mutex_lock(&ctx->shared->cache_lock);
	off = 0;
	pfn = pio->addr.addr >> get_page_shift(ctx);
	ret = get_page_desc(ctx, pfn, &dp, &off);
	mutex_unlock(&ctx->shared->cache_lock);
	if (ret != KDUMP_OK)
		return ret;

	type = dp.dp_flags & (DUMP_COMPRESSED|DUMP_RAW);
	switch (type) {
	case DUMP_COMPRESSED:
		if (dp.dp_size > MAX_PAGE_SIZE)
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong compressed size: %lu",
					 (unsigned long) dp.dp_size);
		buf = ctx->data[lkcdp->cbuf_slot];
		break;
	case DUMP_RAW:
		if (dp.dp_size != get_page_size(ctx))
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong page size: %lu",
					 (unsigned long) dp.dp_size);
		buf = pio->chunk.data;
		break;
	default:
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unsupported compression type: 0x%x", type);
	}

	/* read page data */
	mutex_lock(&ctx->shared->cache_lock);
	ret = fcache_pread(ctx->shared->fcache, buf, dp.dp_size, 0, off);
	mutex_unlock(&ctx->shared->cache_lock);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read page data at %llu",
				 (unsigned long long) off);

	if (type == DUMP_RAW)
		return KDUMP_OK;

	if (lkcdp->compression == DUMP_COMPRESS_RLE) {
		size_t retlen = get_page_size(ctx);
		int ret = uncompress_rle(pio->chunk.data, &retlen, buf, dp.dp_size);
		if (ret)
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Decompression failed: %d", ret);
		if (retlen != get_page_size(ctx))
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
	} else if (lkcdp->compression == DUMP_COMPRESS_GZIP) {
		ret = uncompress_page_gzip(ctx, pio->chunk.data, buf, dp.dp_size);
		if (ret != KDUMP_OK)
			return ret;
	} else
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unknown compression method: %d",
				 lkcdp->compression);

	return KDUMP_OK;
}

static kdump_status
lkcd_get_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	return cache_get_page(ctx, pio, lkcd_read_page);
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
lkcd_realloc_compressed(kdump_ctx_t *ctx, struct attr_data *attr)
{
	const struct attr_ops *parent_ops;
	struct lkcd_priv *lkcdp;
	int newslot;

	newslot = per_ctx_alloc(ctx->shared, attr_value(attr)->number);
	if (newslot < 0)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate buffer for compressed data");

	lkcdp = ctx->shared->fmtdata;
	if (lkcdp->cbuf_slot >= 0)
		per_ctx_free(ctx->shared, lkcdp->cbuf_slot);
	lkcdp->cbuf_slot = newslot;

	parent_ops = lkcdp->page_size_override.template.parent->ops;
	return (parent_ops && parent_ops->post_set)
		? parent_ops->post_set(ctx, attr)
		: KDUMP_OK;
}

static inline unsigned long
base_version(uint32_t version)
{
	return version & ~(LKCD_DUMP_MCLX_V0|LKCD_DUMP_MCLX_V1);
}

static kdump_status
init_v1(kdump_ctx_t *ctx, void *hdr)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	struct dump_header_v1_32 *dh32 = hdr;
	struct dump_header_v1_64 *dh64 = hdr;

	lkcdp->compression = DUMP_COMPRESS_RLE;
	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh64->dh_utsname))
		set_uts(ctx, &dh64->dh_utsname);
	else
		set_uts(ctx, &dh32->dh_utsname);

	return KDUMP_OK;
}

static kdump_status
init_v2(kdump_ctx_t *ctx, void *hdr)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	struct dump_header_v2_32 *dh32 = hdr;
	struct dump_header_v2_64 *dh64 = hdr;

	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh64->dh_utsname)) {
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(ctx, dh64->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
		set_uts(ctx, &dh64->dh_utsname);
	} else {
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(ctx, dh32->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
		set_uts(ctx, &dh32->dh_utsname);
	}

	return KDUMP_OK;
}

static kdump_status
init_v8(kdump_ctx_t *ctx, void *hdr)
{
	struct lkcd_priv *lkcdp = ctx->shared->fmtdata;
	struct dump_header_v8 *dh = hdr;

	lkcdp->compression = dump32toh(ctx, dh->dh_dump_compress);
	if (lkcdp->version >= LKCD_DUMP_V9) {
		lkcdp->data_offset = dump64toh(ctx, dh->dh_dump_buffer_size);
		lkcdp->last_offset = lkcdp->data_offset;
	}

	set_uts(ctx, &dh->dh_utsname);

	return KDUMP_OK;
}

static kdump_status
open_common(kdump_ctx_t *ctx, void *hdr)
{
	struct dump_header_common *dh = hdr;
	struct lkcd_priv *lkcdp;
	kdump_status ret;

	if (get_num_files(ctx) > 1)
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Multiple files not implemented");

	lkcdp = ctx_malloc(sizeof *lkcdp, ctx, "LKCD private data");
	if (!lkcdp)
		return KDUMP_ERR_SYSTEM;
	ctx->shared->fmtdata = lkcdp;

	lkcdp->version = base_version(dump32toh(ctx, dh->dh_version));
	snprintf(lkcdp->format, sizeof(lkcdp->format),
		 LKCD_FORMAT_PFX "%u", lkcdp->version);
	set_file_description(ctx, lkcdp->format);

	lkcdp->data_offset = LKCD_OFFSET_TO_FIRST_PAGE;
	lkcdp->last_offset = lkcdp->data_offset;
	lkcdp->end_offset = 0;
	lkcdp->max_pfn = 0;

	if (mutex_init(&lkcdp->pfn_block_mutex, NULL)) {
		free(lkcdp);
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot initialize LKCD data mutex");
	}
	lkcdp->pfn_level1 = NULL;
	lkcdp->l1_size = 0;

	attr_add_override(gattr(ctx, GKI_page_size),
			  &lkcdp->page_size_override);
	lkcdp->page_size_override.ops.post_set = lkcd_realloc_compressed;
	lkcdp->cbuf_slot = -1;

	ret = set_page_size(ctx, dump32toh(ctx, dh->dh_page_size));
	if (ret != KDUMP_OK)
		return ret;

	attr_add_override(gattr(ctx, GKI_max_pfn),
			  &lkcdp->max_pfn_override);
	lkcdp->max_pfn_override.ops.revalidate = lkcd_max_pfn_revalidate;
	set_attr_number(ctx, gattr(ctx, GKI_max_pfn), ATTR_INVALID, 0);

	set_addrspace_caps(ctx->xlat, ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR));

	switch(lkcdp->version) {
	case LKCD_DUMP_V1:
		ret = init_v1(ctx, hdr);
		break;

	case LKCD_DUMP_V2:
	case LKCD_DUMP_V3:
	case LKCD_DUMP_V5:
	case LKCD_DUMP_V6:
	case LKCD_DUMP_V7:
		ret = init_v2(ctx, hdr);
		break;

	case LKCD_DUMP_V8:
	case LKCD_DUMP_V9:
	case LKCD_DUMP_V10:
		ret = init_v8(ctx, hdr);
		break;

	default:
		ret = set_error(ctx, KDUMP_ERR_NOTIMPL,
				"Unsupported LKCD version: %u",
				lkcdp->version);
	}

	if (ret != KDUMP_OK)
		goto err_free;

	return KDUMP_OK;

  err_free:
	lkcd_cleanup(ctx->shared);
	return ret;
}

static kdump_status
lkcd_probe(kdump_ctx_t *ctx)
{
	static const char magic_le[] =
		{ 0xed, 0x23, 0x8f, 0x61, 0x73, 0x01, 0x19, 0xa8 };
	static const char magic_be[] =
		{ 0xa8, 0x19, 0x01, 0x73, 0x61, 0x8f, 0x23, 0xed };
	char hdr[sizeof(struct dump_header_v8)];
	kdump_status status;

	status = fcache_pread(ctx->shared->fcache, hdr, sizeof hdr, 0, 0);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot read dump header");

	if (!memcmp(hdr, magic_le, sizeof magic_le))
		set_byte_order(ctx, KDUMP_LITTLE_ENDIAN);
	else if (!memcmp(hdr, magic_be, sizeof magic_be))
		set_byte_order(ctx, KDUMP_BIG_ENDIAN);
	else
		return set_error(ctx, KDUMP_NOPROBE,
				 "Unrecognized LKCD signature");

	return open_common(ctx, hdr);
}

static void
free_level3(struct pfn_block *block)
{
	while (block) {
		struct pfn_block *next = block->next;
		free(block->offs);
		free(block);
		block = next;
	}
}

static void
free_level2(struct pfn_block **level2)
{
	if (level2) {
		unsigned i;
		for (i = 0; i < PFN_IDX2_SIZE; ++i)
			free_level3(level2[i]);
		free(level2);
	}
}

static void
free_level1(struct pfn_block ***level1, unsigned long n)
{
	if (level1) {
		unsigned long i;
		for (i = 0; i < n; ++i)
			free_level2(level1[i]);
		free(level1);
	}
}

static void
lkcd_attr_cleanup(struct attr_dict *dict)
{
	struct lkcd_priv *lkcdp = dict->shared->fmtdata;

	attr_remove_override(dgattr(dict, GKI_page_size),
			     &lkcdp->page_size_override);
	attr_remove_override(dgattr(dict, GKI_max_pfn),
			     &lkcdp->max_pfn_override);
}

static void
lkcd_cleanup(struct kdump_shared *shared)
{
	struct lkcd_priv *lkcdp = shared->fmtdata;

	free_level1(lkcdp->pfn_level1, lkcdp->l1_size);
	mutex_destroy(&lkcdp->pfn_block_mutex);
	if (lkcdp->cbuf_slot >= 0)
		per_ctx_free(shared, lkcdp->cbuf_slot);
	free(lkcdp);
	shared->fmtdata = NULL;
}

const struct format_ops lkcd_ops = {
	.name = "lkcd",
	.probe = lkcd_probe,
	.get_page = lkcd_get_page,
	.put_page = cache_put_page,
	.realloc_caches = def_realloc_caches,
	.attr_cleanup = lkcd_attr_cleanup,
	.cleanup = lkcd_cleanup,
};
