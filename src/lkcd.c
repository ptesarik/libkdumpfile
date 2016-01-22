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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if USE_ZLIB
# include <zlib.h>
#endif

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

/**  Contiguous block of pages
 *
 * Storing only a 32-bit offset from the block beginning saves
 * 50% of the space used by @c offs.
 */
struct pfn_block {
	off_t filepos;		/**< absolute file offset */
	kdump_pfn_t pfn;	/**< first pfn in range */
	unsigned short n;	/**< number of pages */
	unsigned short alloc;	/**< allocated pages */
	uint32_t *offs;		/**< offsets from filepos */
	struct pfn_block *next;	/**< pointer to next block */
};

/* Maximum size of the format name: the version field is a 32-bit integer,
 * so it cannot be longer than 10 decimal digits.
 */
#define LKCD_FORMAT_PFX	"LKCD v"
#define MAX_FORMAT_NAME	(sizeof(LKCD_FORMAT_PFX) + 10)

struct lkcd_priv {
	off_t data_offset;	/* offset to 1st page */
	off_t last_offset;	/* offset of last page parsed so far */
	off_t end_offset;	/* offset of end marker */
	struct pfn_block *last_block;

	unsigned version;
	unsigned compression;

	struct pfn_block ***pfn_level1;
	unsigned l1_size;

	char format[MAX_FORMAT_NAME];
};

static void lkcd_cleanup(kdump_ctx *ctx);

static struct pfn_block **
get_pfn_slot(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct pfn_block **l2;
	unsigned idx;

	idx = pfn_idx1(pfn);
	if (idx >= lkcdp->l1_size) {
		struct pfn_block ***new_l1;
		new_l1 = realloc(lkcdp->pfn_level1,
				 (idx + 1) * sizeof(*new_l1));
		if (!new_l1) {
			set_error(ctx, kdump_syserr,
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
			set_error(ctx, kdump_syserr,
				  "Cannot allocate PFN level-%u table", 2);
			return NULL;
		}
		lkcdp->pfn_level1[idx] = l2;
	}

	return &l2[pfn_idx2(pfn)];
}

static struct pfn_block *
alloc_pfn_block(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	struct pfn_block **pprev, *block;
	uint32_t *offs;

	pprev = get_pfn_slot(ctx, pfn);
	if (!pprev)
		return NULL;

	offs = ctx_malloc(PFN_IDX3_SIZE * sizeof(uint32_t),
			  ctx, "PFN level-3 table");
	if (!offs)
		return NULL;

	block = ctx_malloc(sizeof(struct pfn_block), ctx, "PFN block");
	if (!block) {
		free(offs);
		return NULL;
	}
	block->pfn = pfn;
	block->n = 0;
	block->alloc = PFN_IDX3_SIZE;
	block->offs = offs;

	while (*pprev) {
		if ((*pprev)->pfn >= block->pfn)
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

	if (!block || block->alloc == alloc)
		return kdump_ok;

	newoffs = realloc(block->offs, alloc * sizeof(uint32_t));
	if (!newoffs)
		return kdump_syserr;

	block->alloc = alloc;
	block->offs = newoffs;
	return kdump_ok;
}

static struct pfn_block *
lookup_pfn_block(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
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

	while (block) {
		if (block->pfn > pfn)
			break;
		if (pfn < block->pfn + block->n)
			return block;
		block = block->next;
	}

	return NULL;
}

static kdump_status
read_page_desc(kdump_ctx *ctx, struct dump_page *dp, off_t off)
{
	ssize_t rd = pread(ctx->fd, dp, sizeof *dp, off);
	if (rd != sizeof *dp)
		return set_error(ctx, read_error(rd),
				 "Cannot read page descriptor at %llu",
				 (unsigned long long) off);

	dp->dp_address = dump64toh(ctx, dp->dp_address);
	dp->dp_size = dump32toh(ctx, dp->dp_size);
	dp->dp_flags = dump32toh(ctx, dp->dp_flags);
	return kdump_ok;
}

static kdump_status
search_page_desc(kdump_ctx *ctx, kdump_pfn_t pfn,
		 struct dump_page *dp, off_t *dataoff)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	off_t off;
	kdump_pfn_t curpfn, prevpfn;
	struct pfn_block *block;
	kdump_status res;

	off = lkcdp->last_offset;
	if (off == lkcdp->end_offset)
		return set_error(ctx, kdump_nodata, "Page not found");

	block = lkcdp->last_block;
	prevpfn = block
		? block->pfn + block->n - 1
		: (kdump_pfn_t)-1;

	do {
		res = read_page_desc(ctx, dp, off);
		if (res != kdump_ok) {
			if (res == kdump_eof)
				lkcdp->end_offset = off;
			realloc_pfn_offs(block, block->n);
			return res;
		}

		if (dp->dp_flags & DUMP_END) {
			lkcdp->end_offset = off;
			realloc_pfn_offs(block, block->n);
			return set_error(ctx, kdump_nodata, "Page not found");
		}

		curpfn = dp->dp_address >> get_page_shift(ctx);
		if (block && (off > block->filepos + UINT32_MAX ||
			      curpfn != prevpfn + 1)) {
			realloc_pfn_offs(block, block->n);
			block = NULL;
		}
		if (block && block->n >= block->alloc) {
			unsigned short newalloc = block->n + PFN_IDX3_SIZE;
			if (realloc_pfn_offs(block, newalloc) != kdump_ok)
				block = NULL;
		}

		if (!block) {
			block = alloc_pfn_block(ctx, curpfn);
			if (!block)
				return kdump_syserr;
			block->filepos = off;
		} else if (pfn_idx3(curpfn) == 0) {
			struct pfn_block **slot;
			slot = get_pfn_slot(ctx, curpfn);
			if (!slot)
				return kdump_syserr;
			block->next = *slot;
			*slot = block;
		}

		block->offs[block->n++] = off - block->filepos;

		prevpfn = curpfn;
		off += sizeof(struct dump_page) + dp->dp_size;
		lkcdp->last_offset = off;
		lkcdp->last_block = block;
	} while (curpfn != pfn);

	*dataoff = off - dp->dp_size;
	return kdump_ok;
}

static kdump_status
get_page_desc(kdump_ctx *ctx, kdump_pfn_t pfn,
	      struct dump_page *dp, off_t *dataoff)
{
	struct pfn_block *block;
	off_t off;

	block = lookup_pfn_block(ctx, pfn);
	if (!block)
		return search_page_desc(ctx, pfn, dp, dataoff);

	off = block->filepos + block->offs[pfn - block->pfn];
	*dataoff = off + sizeof *dp;
	return read_page_desc(ctx, dp, off);
}

static kdump_status
lkcd_read_page(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct dump_page dp;
	unsigned type;
	off_t off;
	ssize_t rd;
	void *buf;
	kdump_status ret;

	if (pfn == ctx->last_pfn)
		return kdump_ok;

	ret = get_page_desc(ctx, pfn, &dp, &off);
	if (ret != kdump_ok)
		return ret;

	type = dp.dp_flags & (DUMP_COMPRESSED|DUMP_RAW);
	switch (type) {
	case DUMP_COMPRESSED:
		if (dp.dp_size > MAX_PAGE_SIZE)
			return set_error(ctx, kdump_dataerr,
					 "Wrong compressed size: %lu",
					 (unsigned long) dp.dp_size);
		buf = ctx->buffer;
		break;
	case DUMP_RAW:
		if (dp.dp_size != get_page_size(ctx))
			return set_error(ctx, kdump_dataerr,
					 "Wrong page size: %lu",
					 (unsigned long) dp.dp_size);
		buf = ctx->page;
		break;
	default:
		return set_error(ctx, kdump_unsupported,
				 "Unsupported compression type: 0x%x", type);
	}

	/* read page data */
	rd = pread(ctx->fd, buf, dp.dp_size, off);
	if (rd != dp.dp_size)
		return set_error(ctx, read_error(rd),
				 "Cannot read page data at %llu",
				 (unsigned long long) off);

	if (type == DUMP_RAW)
		goto out;

	if (lkcdp->compression == DUMP_COMPRESS_RLE) {
		size_t retlen = get_page_size(ctx);
		int ret = uncompress_rle(ctx->page, &retlen,
					 buf, dp.dp_size);
		if (ret)
			return set_error(ctx, kdump_dataerr,
					 "Decompression failed: %d", ret);
		if (retlen != get_page_size(ctx))
			return set_error(ctx, kdump_dataerr,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
	} else if (lkcdp->compression == DUMP_COMPRESS_GZIP) {
#if USE_ZLIB
		uLongf retlen = get_page_size(ctx);
		int ret = uncompress(ctx->page, &retlen,
				     buf, dp.dp_size);
		if (ret != Z_OK)
			return set_error(ctx, kdump_dataerr,
					 "Decompression failed: %d", ret);
		if (retlen != get_page_size(ctx))
			return set_error(ctx, kdump_dataerr,
					 "Wrong uncompressed size: %lu",
					 (unsigned long) retlen);
#else
		return set_error(ctx, kdump_unsupported,
				 "Unsupported compression method: %s",
				 "zlib");
#endif
	} else
		return set_error(ctx, kdump_unsupported,
				 "Unknown compression method: %d",
				 lkcdp->compression);

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

	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh64->dh_utsname))
		set_uts(ctx, &dh64->dh_utsname);
	else
		set_uts(ctx, &dh32->dh_utsname);
	lkcdp->compression = DUMP_COMPRESS_RLE;

	return kdump_ok;
}

static kdump_status
init_v2(kdump_ctx *ctx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct dump_header_v2_32 *dh32 = ctx->buffer;
	struct dump_header_v2_64 *dh64 = ctx->buffer;

	if (!uts_looks_sane(&dh32->dh_utsname) &&
	    uts_looks_sane(&dh64->dh_utsname)) {
		set_uts(ctx, &dh64->dh_utsname);
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(ctx, dh64->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
	} else {
		set_uts(ctx, &dh32->dh_utsname);
		lkcdp->compression = (lkcdp->version >= LKCD_DUMP_V5)
			? dump32toh(ctx, dh32->dh_dump_compress)
			: DUMP_COMPRESS_RLE;
	}

	return kdump_ok;
}

static kdump_status
init_v8(kdump_ctx *ctx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;
	struct dump_header_v8 *dh = ctx->buffer;

	set_uts(ctx, &dh->dh_utsname);
	lkcdp->compression = dump32toh(ctx, dh->dh_dump_compress);
	if (lkcdp->version >= LKCD_DUMP_V9)
		lkcdp->data_offset = dump64toh(ctx, dh->dh_dump_buffer_size);

	return kdump_ok;
}

static kdump_status
open_common(kdump_ctx *ctx)
{
	struct dump_header_common *dh = ctx->buffer;
	struct lkcd_priv *lkcdp;
	const struct attr_data *attr;
	kdump_status ret;

	lkcdp = ctx_malloc(sizeof *lkcdp, ctx, "LKCD private data");
	if (!lkcdp)
		return kdump_syserr;

	lkcdp->version = base_version(dump32toh(ctx, dh->dh_version));
	snprintf(lkcdp->format, sizeof(lkcdp->format),
		 "LKCD v%u", lkcdp->version);

	lkcdp->data_offset = LKCD_OFFSET_TO_FIRST_PAGE;

	ctx->format = lkcdp->format;

	ret = set_page_size(ctx, dump32toh(ctx, dh->dh_page_size));
	if (ret != kdump_ok)
		return ret;

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
		ret = set_error(ctx, kdump_unsupported,
				"Unsupported LKCD version: %u",
				lkcdp->version);
	}

	if (ret != kdump_ok)
		goto err_free;

	lkcdp->last_offset = lkcdp->data_offset;
	lkcdp->end_offset = 0;
	lkcdp->last_block = NULL;

	lkcdp->pfn_level1 = NULL;
	lkcdp->l1_size = 0;

	attr = lookup_attr(ctx, GATTR(GKI_linux_uts_machine));
	if (!attr) {
		ret = set_error(ctx, kdump_nodata, "Architecture is not set");
		goto err_free;
	}

	ret = set_arch(ctx, machine_arch(attr_value(attr)->string));
	if (ret != kdump_ok)
		goto err_free;

	return kdump_ok;

  err_free:
	lkcd_cleanup(ctx);
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
		set_byte_order(ctx, kdump_little_endian);
	else if (!memcmp(ctx->buffer, magic_be, sizeof magic_be))
		set_byte_order(ctx, kdump_big_endian);
	else
		return set_error(ctx, kdump_unsupported,
				 "Unknown LKCD signature");

	return open_common(ctx);
}

static void
free_level3(struct pfn_block *block, kdump_pfn_t endpfn)
{
	while (block) {
		struct pfn_block *next;

		/* PFN blocks which cross a level-3 boundary are freed
		 * with the last reference (highest level-3 index). */
		if (block->pfn + block->n > endpfn)
			break;

		next = block->next;
		free(block->offs);
		free(block);
		block = next;
	}
}

static void
free_level2(struct pfn_block **level2, kdump_pfn_t *pfn)
{
	if (level2) {
		unsigned i;
		for (i = 0; i < PFN_IDX2_SIZE; ++i) {
			*pfn += PFN_IDX3_SIZE;
			free_level3(level2[i], *pfn);
		}
		free(level2);
	}
}

static void
free_level1(struct pfn_block ***level1, unsigned long n)
{
	if (level1) {
		kdump_pfn_t pfn = 0;
		unsigned long i;
		for (i = 0; i < n; ++i)
			free_level2(level1[i], &pfn);
		free(level1);
	}
}

static void
lkcd_cleanup(kdump_ctx *ctx)
{
	struct lkcd_priv *lkcdp = ctx->fmtdata;

	free_level1(lkcdp->pfn_level1, lkcdp->l1_size);
	free(lkcdp);
	ctx->fmtdata = NULL;
}

const struct format_ops lkcd_ops = {
	.probe = lkcd_probe,
	.read_page = lkcd_read_page,
	.cleanup = lkcd_cleanup,
};
