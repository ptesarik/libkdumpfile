/** @internal @file src/kdumpfile/flatmap.c
 * @brief Routines to handle files in the flattened format.
 */
/* Copyright (C) 2024 Petr Tesarik <petr@tesarici.cz>

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

#define MDF_SIGNATURE		"makedumpfile"
#define MDF_SIG_LEN		16
#define MDF_TYPE_FLAT_HEADER	1
#define MDF_VERSION_FLAT_HEADER	1

#define MDF_HEADER_SIZE		4096
#define MDF_OFFSET_END_FLAG	(-(int64_t)1)

/* Flattened format header. */
struct makedumpfile_header {
	char	signature[MDF_SIG_LEN];
	int64_t	type;
	int64_t	version;
} __attribute__((packed));

/* Flattened segment header */
struct makedumpfile_data_header {
        int64_t offset;
        int64_t buf_size;
} __attribute__((packed));

#define ALLOC_INC	32

/** Initialize flattened dump maps for one file.
 * @param fmap  Flattened format mapping to be initialized.
 * @param ctx   Dump file object.
 * @param fidx  File index.
 * @returns     Error status.
 *
 * Read all flattened segment headers from file @p fidx and initialize
 * @p fmap.
 *
 * Note that the mapping may be already partially initialized when this
 * function fails with an error status, so you should always release the
 * associated resources with @ref flatmap_file_cleanup(). As a consequence,
 * the mapping must be initialized to all zeroes prior to calling
 * flatmap_file_init().
 */
static kdump_status
flatmap_file_init(struct flattened_file_map *fmap, kdump_ctx_t *ctx,
		  unsigned fidx)
{
	struct makedumpfile_data_header hdr;
	off_t *flatoffs = NULL;
	addrxlat_range_t range;
	int64_t pos, size;
	unsigned segidx;
	off_t flatpos;
	kdump_status status;

	fmap->map = addrxlat_map_new();
	if (!fmap->map)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s", "flattened map");

	segidx = 0;
	flatpos = MDF_HEADER_SIZE;
	for (;;) {
		status = fcache_pread(ctx->shared->fcache, &hdr, sizeof(hdr),
				      fidx, flatpos);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot read flattened header at %llu",
					 (unsigned long long) flatpos);
		pos = be64toh(hdr.offset);
		if (pos == MDF_OFFSET_END_FLAG)
			break;
                if (pos < 0)
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong flattened %s %"PRId64" at %llu",
					 "offset", pos,
					 (unsigned long long) flatpos);
		size = be64toh(hdr.buf_size);
		if (size <= 0)
			return set_error(ctx, KDUMP_ERR_CORRUPT,
					 "Wrong flattened %s %"PRId64" at %llu",
					 "segment size", size,
					 (unsigned long long) flatpos);

		if ((segidx % ALLOC_INC) == 0) {
			unsigned newlen = segidx + ALLOC_INC;

			flatoffs = realloc(flatoffs,
					 sizeof(*flatoffs) * newlen);
			if (!flatoffs)
				return set_error(ctx, KDUMP_ERR_SYSTEM,
						 "Cannot allocate %s",
						 "flattened offset array");
			fmap->offs = flatoffs;
		}
		flatpos += sizeof(hdr);
		flatoffs[segidx] = flatpos - pos;

		range.endoff = size - 1;
		range.meth = segidx;
		if (addrxlat_map_set(fmap->map, pos, &range) != ADDRXLAT_OK)
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot allocate %s",
					 "flattened map entry");

		++segidx;
		flatpos += size;
	}
	return KDUMP_OK;
}

static void
flatmap_file_cleanup(struct flattened_file_map *fmap)
{
	if (fmap->map)
		addrxlat_map_decref(fmap->map);
	if (fmap->offs)
		free(fmap->offs);
}

/** Allocate a flattened dump map.
 * @param nfiles  Number of mapped files.
 * @returns       Flattened offset map, or @c NULL on error.
 */
struct flattened_map*
flatmap_alloc(unsigned nfiles)
{
	struct flattened_map *map;

	map = calloc(1, sizeof(*map) +
		     nfiles * sizeof(map->fmap[0]));
	if (map)
		map->nfiles = nfiles;
	return map;
}

static inline kdump_status
err_notimpl(kdump_ctx_t *ctx, const char *what, int_fast64_t value)
{
	return set_error(ctx, KDUMP_ERR_NOTIMPL,
			 "Unknown flattened %s: %" PRId64 "\n", what, value);
}

/** Initialize flattened dump maps for all files.
 * @param map  Flattened offset map.
 * @param ctx  Dump file object.
 * @returns    Error status.
 *
 * Initialize flattened dump maps for all files.
 */
kdump_status
flatmap_init(struct flattened_map *map, kdump_ctx_t *ctx)
{
	static const char magic[MDF_SIG_LEN] = MDF_SIGNATURE;

	struct makedumpfile_header hdr;
	unsigned fidx;
	kdump_status status;

	map->fcache = ctx->shared->fcache;
	fcache_incref(map->fcache);

	for (fidx = 0; fidx < map->nfiles; ++fidx) {
		status = fcache_pread(map->fcache, &hdr, sizeof(hdr), fidx, 0);
		if (status != KDUMP_OK)
			return set_error(ctx, status, "Cannot read %s",
					 err_filename(ctx, fidx));

		if (memcmp(hdr.signature, magic, sizeof magic))
			continue;

		if (be64toh(hdr.type) != MDF_TYPE_FLAT_HEADER)
			return err_notimpl(ctx, "type",
					   be64toh(hdr.type));
		if (be64toh(hdr.version) != MDF_VERSION_FLAT_HEADER)
			return err_notimpl(ctx, "version",
					   be64toh(hdr.version));

		status = flatmap_file_init(&map->fmap[fidx], ctx, fidx);
		if (status != KDUMP_OK)
			return set_error(ctx, status,
					 "Cannot rearrange %s",
					 err_filename(ctx, fidx));
	}

	return KDUMP_OK;
}

/** Release all resources used by a flattened dump map.
 * @param map  Flattened offset map.
 */
void
flatmap_free(struct flattened_map *map)
{
	unsigned fidx;

	if (!map)
		return;
	for (fidx = 0; fidx < map->nfiles; ++fidx)
		flatmap_file_cleanup(&map->fmap[fidx]);
	if (map->fcache)
		fcache_decref(map->fcache);
	free(map);
}

/** Read buffer from a flattened dump file.
 * @param map   Flattened format mapping to be initialized.
 * @param buf   Target I/O buffer.
 * @param len   Length of data.
 * @param fidx  Index of the file to read from.
 * @param pos   File position.
 * @returns     Error status.
 *
 * Read data from the flattened segment(s) which contain(s) @p len bytes
 * at position @p pos after rearrangement.
 */
kdump_status
flatmap_pread_flat(struct flattened_map *map, void *buf, size_t len,
		   unsigned fidx, off_t pos)
{
	struct flattened_file_map *fmap = &map->fmap[fidx];
	const addrxlat_range_t *range, *end;
	off_t off;

	range = addrxlat_map_ranges(fmap->map);
	end = range + addrxlat_map_len(fmap->map);
	for (off = pos; range < end && off > range->endoff; ++range)
		off -= range->endoff + 1;
	while (range < end && len) {
		size_t seglen;

		seglen = range->endoff + 1 - off;
		if (seglen > len)
			seglen = len;

		if (range->meth != ADDRXLAT_SYS_METH_NONE) {
			off_t *flatoffs = fmap->offs;
			kdump_status ret;

			ret = fcache_pread(map->fcache, buf, seglen,
					   fidx, pos + flatoffs[range->meth]);
			if (ret != KDUMP_OK)
				return ret;
		} else
			memset(buf, 0, seglen);

		buf += seglen;
		len -= seglen;
		pos += seglen;
		++range;
		off = 0;
	}

	if (len)
		memset(buf, 0, len);
	return KDUMP_OK;
}

/** Get a contiguous data chunk from a flattened dump file.
 * @param map   Flattened format mapping to be initialized.
 * @param fch   File cache chunk, updated on success.
 * @param len   Length of data.
 * @param fidx  Index of the file to read from.
 * @param pos   File position.
 * @returns     Error status.
 *
 * Get a contiguous data chunk from a flattened dump file.
 */
kdump_status
flatmap_get_chunk_flat(struct flattened_map *map, struct fcache_chunk *fch,
		       size_t len, unsigned fidx, off_t pos)
{
	struct flattened_file_map *fmap = &map->fmap[fidx];
	const addrxlat_range_t *range, *end;
	off_t off;

	range = addrxlat_map_ranges(fmap->map);
	end = range + addrxlat_map_len(fmap->map);
	for (off = pos; range < end && off > range->endoff; ++range)
		off -= range->endoff + 1;
	if (len <= range->endoff + 1 - off) {
		pos += fmap->offs[range->meth];
		return fcache_get_chunk(map->fcache, fch, len, fidx, pos);
	}

	fch->data = malloc(len);
	if (!fch->data)
		return KDUMP_ERR_SYSTEM;
	fch->nent = 0;
	return flatmap_pread(map, fch->data, len, fidx, pos);
}
