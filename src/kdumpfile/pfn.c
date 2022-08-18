/** @internal @file src/kdumpfile/pfn.c
 * @brief Routines for mapping PFN ranges to file offsets.
 */
/* Copyright (C) 2022 Petr Tesarik <ptesarik@suse.com>

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
#include <string.h>

/** Region mapping allocation increment.
 * For optimal performance, this should be a power of two.
 */
#define RGN_ALLOC_INC	1024

/** Add a new PFN region.
 * @param map  Mapping from PFN to file.
 * @param rgn  New PFN region.
 * @returns    Pointer to the new region inside @p regions,
 *             or @c NULL on allocation failure.
 */
struct pfn_region *
add_pfn_region(struct pfn_file_map *map, const struct pfn_region *rgn)
{
	struct pfn_region *ret;

	if (map->nregions % RGN_ALLOC_INC == 0) {
		size_t num = map->nregions + RGN_ALLOC_INC;
		struct pfn_region *new_regions =
			realloc(map->regions, num * sizeof(struct pfn_region));
		if (!new_regions)
			return NULL;
		map->regions = new_regions;
	}

	ret = map->regions + map->nregions;
	*ret = *rgn;
	++map->nregions;
	return ret;
}

/** Find a PFN region by PFN.
 * @param map  Mapping from PFN to file.
 * @param pfn  Page frame number.
 * @returns    Pointer to a PFN region which contains @c pfn or the closest
 *             higher PFN, or @c NULL if there is no such region.
 */
const struct pfn_region *
find_pfn_region(const struct pfn_file_map *map, kdump_pfn_t pfn)
{
	size_t left = 0, right = map->nregions;
	while (left != right) {
		size_t mid = (left + right) / 2;
		const struct pfn_region *rgn = map->regions + mid;
		if (pfn < rgn->pfn)
			right = mid;
		else if (pfn >= rgn->pfn + rgn->cnt)
			left = mid + 1;
		else
			return rgn;
	}
	return right < map->nregions
		? map->regions + right
		: NULL;
}

/** Skip clear bits in a PFN bitmap with LSB 0 bit numbering.
 * @param bitmap  PFN bitmap.
 * @param size    Size of the bitmap in bytes.
 * @param pfn     Starting PFN.
 * @returns       Index of the next PFN bit that is not clear.
 *
 * If there are no set bits in @p bitmap beyond @p pfn, this function
 * returns one beyond the maximum index (i.e. size of the bitmap in bits).
 */
static kdump_pfn_t
skip_clear_lsb0(const unsigned char *bitmap, size_t size, kdump_pfn_t pfn)
{
	const unsigned char *bp = bitmap + (pfn >> 3);
	const unsigned char *endp = bitmap + size;
	unsigned char val;

	if (bp >= endp)
		return pfn;

	val = *bp >> (pfn & 7);
	if (val)
		return pfn + ctz(val);

	pfn = (pfn | 7) + 1;
	++bp;
	for (; endp - bp >= 1 && ((uintptr_t)bp & 3) != 0; pfn += 8, ++bp)
		if (*bp)
			return pfn + ctz(*bp);
	for (; endp - bp >= 4; pfn += 32, bp += 4)
		if (*(uint32_t*)bp)
			return pfn + ctz(*(uint32_t*)bp);
	for (; endp - bp >= 1; pfn += 8, ++bp)
		if (*bp)
			return pfn + ctz(*bp);

	return pfn;
}

/** Skip clear bits in a PFN bitmap with MSB 0 bit numbering.
 * @param bitmap  PFN bitmap.
 * @param size    Size of the bitmap in bytes.
 * @param pfn     Starting PFN.
 * @returns       Index of the next PFN bit that is not clear.
 *
 * If there are no set bits in @p bitmap beyond @p pfn, this function
 * returns one beyond the maximum index (i.e. size of the bitmap in bits).
 */
static kdump_pfn_t
skip_clear_msb0(const unsigned char *bitmap, size_t size, kdump_pfn_t pfn)
{
	const unsigned char *bp = bitmap + (pfn >> 3);
	const unsigned char *endp = bitmap + size;
	unsigned char val;

	if (bp >= endp)
		return pfn;

	val = *bp << (pfn & 7);
	if (val)
		return pfn + clz((uint32_t)val << 24);

	pfn = (pfn | 7) + 1;
	++bp;
	for (; endp - bp >= 1 && ((uintptr_t)bp & 3) != 0; pfn += 8, ++bp)
		if (*bp)
			return pfn + clz((uint32_t)*bp << 24);
	for (; endp - bp >= 4; pfn += 32, bp += 4)
		if (*(uint32_t*)bp)
			return pfn + clz(be32toh(*(uint32_t*)bp));
	for (; endp - bp >= 1; pfn += 8, ++bp)
		if (*bp)
			return pfn + clz((uint32_t)*bp << 24);

	return pfn;
}

/** Skip set bits in a PFN bitmap with LSB 0 bit numbering.
 * @param bitmap  PFN bitmap.
 * @param size    Size of the bitmap in bytes.
 * @param pfn     Starting PFN.
 * @returns       Index of the next PFN bit that is not set.
 *
 * If there are no clear bits in @p bitmap beyond @p pfn, this function
 * returns one beyond the maximum index (i.e. size of the bitmap in bits).
 */
static kdump_pfn_t
skip_set_lsb0(const unsigned char *bitmap, size_t size, kdump_pfn_t pfn)
{
	const unsigned char *bp = bitmap + (pfn >> 3);
	const unsigned char *endp = bitmap + size;
	unsigned char val;

	if (bp >= endp)
		return pfn;

	val = ~((signed char)*bp >> (pfn & 7));
	if (val)
		return pfn + ctz(val);

	pfn = (pfn | 7) + 1;
	++bp;
	for (; endp - bp >= 1 && ((uintptr_t)bp & 3) != 0; pfn += 8, ++bp)
		if (~*(signed char*)bp)
			return pfn + ctz(~*bp);
	for (; endp - bp >= 4; pfn += 32, bp += 4)
		if (~*(uint32_t*)bp)
			return pfn + ctz(~*(uint32_t*)bp);
	for (; endp - bp >= 1; pfn += 8, ++bp)
		if (~*(signed char*)bp)
			return pfn + ctz(~*bp);

	return pfn;
}

/** Skip set bits in a PFN bitmap with MSB 0 bit numbering.
 * @param bitmap  PFN bitmap.
 * @param size    Size of the bitmap in bytes.
 * @param pfn     Starting PFN.
 * @returns       Index of the next PFN bit that is not set.
 *
 * If there are no clear bits in @p bitmap beyond @p pfn, this function
 * returns one beyond the maximum index (i.e. size of the bitmap in bits).
 */
static kdump_pfn_t
skip_set_msb0(const unsigned char *bitmap, size_t size, kdump_pfn_t pfn)
{
	const unsigned char *bp = bitmap + (pfn >> 3);
	const unsigned char *endp = bitmap + size;
	unsigned char val;

	if (bp >= endp)
		return pfn;

	val = ~(*bp << (pfn & 7));
	if (val)
		return pfn + clz((uint32_t)val << 24);

	pfn = (pfn | 7) + 1;
	++bp;
	for (; endp - bp >= 1 && ((uintptr_t)bp & 3) != 0; pfn += 8, ++bp)
		if (~*(signed char*)bp)
			return pfn + clz(~((uint32_t)*bp << 24));
	for (; endp - bp >= 4; pfn += 32, bp += 4)
		if (~*(uint32_t*)bp)
			return pfn + clz(~be32toh(*(uint32_t*)bp));
	for (; endp - bp >= 1; pfn += 8, ++bp)
		if (~*(signed char*)bp)
			return pfn + clz(~((uint32_t)*bp << 24));

	return pfn;
}

/** Create PFN regions from a PFN bitmap.
 * @param err        Error context.
 * @param pfm        Target PFN-to-file mapping.
 * @param bitmap     Source PFN bitmap.
 * @param is_msb0    @c true means @p bitmap uses MSB 0 bit numbering,
 *                   @c false means @p bitmap uses LSB 0 bit numbering.
 * @param start_pfn  Lowest PFN to process.
 * @param end_pfn    One above the highest PFN to process.
 * @param fileoff    First target file offset.
 * @param elemsz     Size of the mapped file object.
 * @returns          Error status.
 */
kdump_status
pfn_regions_from_bitmap(kdump_errmsg_t *err, struct pfn_file_map *pfm,
			const unsigned char *bitmap, bool is_msb0,
			kdump_pfn_t start_pfn, kdump_pfn_t end_pfn,
			off_t fileoff, off_t elemsz)
{
	size_t bitmapsize = (end_pfn + 7) >> 3;
	kdump_pfn_t pfn = start_pfn;
	struct pfn_region rgn;

	rgn.pos = fileoff;
	while (pfn < end_pfn) {
		if (is_msb0) {
			rgn.pfn = skip_clear_msb0(bitmap, bitmapsize, pfn);
			pfn = skip_set_msb0(bitmap, bitmapsize, rgn.pfn);
		} else {
			rgn.pfn = skip_clear_lsb0(bitmap, bitmapsize, pfn);
			pfn = skip_set_lsb0(bitmap, bitmapsize, rgn.pfn);
		}
		if (rgn.pfn > end_pfn)
			rgn.pfn = end_pfn;
		if (pfn > end_pfn)
			pfn = end_pfn;
		rgn.cnt = pfn - rgn.pfn;
		if (!rgn.cnt)
			continue;

		if (!add_pfn_region(pfm, &rgn))
			return status_err(err, KDUMP_ERR_SYSTEM,
					  "Cannot allocate more than"
					  " %zu PFN region mappings",
					  pfm->nregions);
		rgn.pos += rgn.cnt * elemsz;
	}

	return KDUMP_OK;
}

/** Find the next mapped PFN.
 * @param maps   Array of PFN-to-file maps.
 * @param nmaps  Number of elements in @p maps.
 * @param ppfn   Pointer to a PFN (updated on success).
 * @returns      @c true if a mapped PFN was found, @c false otherwise.
 */
bool
find_mapped_pfn(const struct pfn_file_map *maps, size_t nmaps,
		kdump_pfn_t *ppfn)
{
	const struct pfn_file_map *pfm;
	const struct pfn_region *rgn;

	if (! (pfm = find_pfn_file_map(maps, nmaps, *ppfn)) ||
	    ! (rgn = find_pfn_region(pfm, *ppfn)))
		return false;

	if (rgn->pfn > *ppfn)
		*ppfn = rgn->pfn;
	return true;
}

/** Find the next unmapped PFN.
 * @param maps   Array of PFN-to-file maps.
 * @param nmaps  Number of elements in @p maps.
 * @param pfn    Starting PFN.
 */
kdump_pfn_t
find_unmapped_pfn(const struct pfn_file_map *maps, size_t nmaps,
		  kdump_pfn_t pfn)
{
	const struct pfn_file_map *pfm;

	if ( (pfm = find_pfn_file_map(maps, nmaps, pfn)) &&
	     pfm->start_pfn <= pfn) {
		const struct pfn_region *rgn = find_pfn_region(pfm, pfn);
		if (rgn && rgn->pfn <= pfn)
			return rgn->pfn + rgn->cnt;
	}
	return pfn;
}

/** Create a bitmap from PFN-to-file maps.
 * @param maps   Array of PFN-to-file maps.
 * @param nmaps  Number of elements in @p maps.
 * @param first  First PFN in @p bits.
 * @param last   Last PFN in @p bits.
 * @param bits   Buffer for the resulting bitmap.
 */
void
get_pfn_map_bits(const struct pfn_file_map *maps, size_t nmaps,
		 kdump_addr_t first, kdump_addr_t last, unsigned char *bits)
{
	const struct pfn_file_map *pfm, *last_pfm;
	const struct pfn_region *rgn, *end;
	kdump_addr_t cur, next;

	if (! (pfm = find_pfn_file_map(maps, nmaps, first)) ||
	    ! (rgn = find_pfn_region(pfm, first))) {
		memset(bits, 0, ((last - first) >> 3) + 1);
		return;
	}

	/* Clear extra bits in the last byte of the raw bitmap. */
	bits[(last - first) >> 3] = 0;

	/* Clear bits beyond last PFN region. */
	last_pfm = &maps[nmaps - 1];
	end = last_pfm->regions + last_pfm->nregions - 1;
	next = end->pfn + end->cnt;
	if (next <= last) {
		clear_bits(bits, next - first, last - first);
		last = next - 1;
	}

	cur = first;
	for ( ;; ) {
		next = rgn->pfn;
		if (cur < next) {
			if (next > last) {
				clear_bits(bits, cur - first, last - first);
				break;
			}
			clear_bits(bits, cur - first, next - 1 - first);
			cur = next;
		}

		next += rgn->cnt - 1;
		if (next >= last) {
			set_bits(bits, cur - first, last - first);
			break;
		}
		set_bits(bits, cur - first, next - first);
		cur = next + 1;
		if (++rgn == &pfm->regions[pfm->nregions]) {
			++pfm;
			rgn = pfm->regions;
		}
	}
}

/** Compare two PFN-to-file maps for @c qsort.
 * @param a  Pointer to first pdmap.
 * @param b  Pointer to second pdmap.
 * @returns  Result of comparison.
 */
static int
map_cmp(const void *a, const void *b)
{
	const struct pfn_file_map *mapa = a, *mapb = b;
	return mapa->end_pfn != mapb->end_pfn
		? (mapa->end_pfn > mapb->end_pfn ? 1 : -1)
		: 0;
}

/** Sort an array of PFN-to-file maps.
 * @param maps   Array of PFN-to-file maps.
 * @param nmaps  Number of elements in @p maps.
 */
void
sort_pfn_file_maps(struct pfn_file_map *maps, size_t nmaps)
{
	qsort(maps, nmaps, sizeof *maps, map_cmp);
}
