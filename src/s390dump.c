/** @internal @file src/s390dump.c
 * @brief Routines to read S390 dump files.
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/** @cond TARGET_ABI */

#define S390_CPU_MAX	512

struct dump_header1 {
	uint64_t magic;
	uint32_t version;
	uint32_t hdr_size;
	uint32_t dump_level;
	uint32_t page_size;
	uint64_t mem_size;
	uint64_t mem_start;
	uint64_t mem_end;
	uint32_t num_pages;
	char     _pad1[4];	/* alignment */
	uint64_t tod;		/* creation timestamp (TOD format) */
	uint64_t cpu_id;
	uint32_t arch;
	uint32_t volnr;
	uint32_t build_arch;
	uint64_t mem_size_real;
	uint8_t  mvdump;
	uint16_t cpu_cnt;
	uint16_t real_cpu_cnt;
} __attribute((packed));

struct dump_header2 {
	uint64_t mvdump_sign;
	uint64_t mvdump_zipl_time;
} __attribute((packed));

struct dump_header {
	struct dump_header1 h1;
	char     _pad2[0x200-sizeof(struct dump_header1)];
	struct dump_header2 h2;
	char     _pad3[0x800-sizeof(struct dump_header2)-0x200];
	uint32_t lowcore[S390_CPU_MAX];
} __attribute((packed));

#define S390_MAGIC	0xa8190173618f23fdULL

#define S390_ARCH_32BIT	1
#define S390_ARCH_64BIT	2

#define END_MARKER	"DUMP_END"

struct end_marker {
	char     str[sizeof(END_MARKER)-1];
	uint64_t tod;
} __attribute__((packed));

/** @endcond */

struct s390dump_priv {
	off_t dataoff;		/* offset of data (size of s390 header) */
};

static void s390_cleanup(struct kdump_shared *shared);

static kdump_status
s390_get_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	struct s390dump_priv *sdp = ctx->shared->fmtdata;
	off_t pos;

	if ((pio->addr.addr >> get_page_shift(ctx)) >= get_max_pfn(ctx))
		return set_error(ctx, KDUMP_ERR_NODATA, "Out-of-bounds PFN");

	pos = (off_t)pio->addr.addr + (off_t)sdp->dataoff;
	return fcache_get_chunk(ctx->shared->fcache, &pio->chunk,
				pos, get_page_size(ctx));
}

static kdump_status
do_probe(kdump_ctx_t *ctx, struct dump_header *dh)
{
	struct s390dump_priv *sdp;
	struct fcache_chunk fch;
	struct end_marker *marker;
	off_t pos;
	kdump_status ret;

	if (be64toh(dh->h1.magic) != S390_MAGIC)
		return set_error(ctx, kdump_noprobe,
				 "Invalid S390DUMP signature");

	set_file_description(ctx, "S390 Dump");
	set_byte_order(ctx, KDUMP_BIG_ENDIAN);

	pos = dump32toh(ctx, dh->h1.hdr_size) +
		dump64toh(ctx, dh->h1.mem_size);
	ret = fcache_get_chunk(ctx->shared->fcache, &fch, pos, sizeof *marker);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot read end marker at %llu",
				 (unsigned long long) pos);
	marker = fch.data;
	if (memcmp(marker->str, END_MARKER, sizeof END_MARKER - 1) ||
	    dump64toh(ctx, marker->tod) < dump64toh(ctx, dh->h1.tod)) {
		fcache_put_chunk(&fch);
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "End marker not found");
	}
	fcache_put_chunk(&fch);

	sdp = calloc(1, sizeof *sdp);
	if (!sdp)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate s390dump private data");
	ctx->shared->fmtdata = sdp;

	sdp->dataoff = dump32toh(ctx, dh->h1.hdr_size);
	set_max_pfn(ctx, dump32toh(ctx, dh->h1.num_pages));

	ret = set_page_size(ctx, dump32toh(ctx, dh->h1.page_size));
	if (ret != KDUMP_OK)
		goto err;

	set_addrspace_caps(ctx->shared, ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR));

	switch (dump32toh(ctx, dh->h1.arch)) {
	case S390_ARCH_32BIT:
		set_arch_name(ctx, "s390");
		break;

	case S390_ARCH_64BIT:
		set_arch_name(ctx, "s390x");
		break;

	default:
		ret = set_error(ctx, KDUMP_ERR_NOTIMPL,
				"Unsupported dump architecture: %lu",
				(unsigned long) dump32toh(ctx, dh->h1.arch));
		goto err;
	}

	return KDUMP_OK;

 err:
	s390_cleanup(ctx->shared);
	return ret;
}

static kdump_status
s390_probe(kdump_ctx_t *ctx, void *hdr)
{
	struct fcache_chunk fch;
	kdump_status ret;

	ret = fcache_get_chunk(ctx->shared->fcache, &fch,
			       0, sizeof(struct dump_header));
	if (ret != KDUMP_OK)
		return set_error(ctx, ret, "Cannot read dump header");

	ret = do_probe(ctx, (struct dump_header*)fch.data);
	fcache_put_chunk(&fch);

	return ret;
}

static void
s390_cleanup(struct kdump_shared *shared)
{
	struct s390dump_priv *sdp = shared->fmtdata;

	free(sdp);
	shared->fmtdata = NULL;
}

const struct format_ops s390dump_ops = {
	.name = "s390dump",
	.probe = s390_probe,
	.get_page = s390_get_page,
	.put_page = cache_put_page,
	.realloc_caches = def_realloc_caches,
	.cleanup = s390_cleanup,
};
