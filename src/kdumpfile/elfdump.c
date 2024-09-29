/** @internal @file src/kdumpfile/elfdump.c
 * @brief Routines to work with ELF kdump files.
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
#include <string.h>
#include <unistd.h>
#include <elf.h>

#include <sys/statfs.h>
#include <linux/magic.h>

/* This definition is missing from older version of <elf.h> */
#ifndef EM_AARCH64
# define EM_AARCH64      183
#endif

/* This definition is also missing from older version of <elf.h> */
#ifndef EM_RISCV
# define EM_RISCV        243
#endif

static const struct format_ops xc_core_elf_ops;

/** Invalid Xen page index.
 * This constant is used to denote that there is no valid index value,
 * e.g. to indicate search failure.
 */
#define IDX_NONE	(~(uint_fast64_t)0)

struct xen_p2m {
	uint64_t pfn;
	uint64_t gmfn;
};

struct load_segment {
	off_t file_offset;
	off_t filesz;
	kdump_paddr_t phys;
	kdump_addr_t memsz;
	kdump_vaddr_t virt;
};

struct section {
	off_t file_offset;
	uint64_t size;
	int name_index;
};

/** Translation of a single PFN to an index.
 */
struct pfn2idx {
	kdump_pfn_t pfn;	/**< PFN to be translated. */
	uint_fast64_t idx;	/**< Page index in .xen_pages.  */
};

/** Translation of a PFN range to an index.
 */
struct pfn2idx_range {
	kdump_pfn_t pfn;	/**< PFN to be translated. */
	uint_fast64_t idx;	/**< Page index in .xen_pages.  */

	/** Length of the range.
	 * If the number is negative, then PFNs are mapped in descending
	 * order (i.e. while PFN increases, the index decreases),
	 * otherwise in ascending order.
	 */
	int_fast64_t len;
};

/** Complete mapping of all PFNs to indices.
 */
struct pfn2idx_map {
	size_t nranges;		      /**< Number of ranges. */
	struct pfn2idx_range *ranges; /**< Page ranges (longer than 1). */

	size_t nsingles;	 /**< Number of single pages. */
	struct pfn2idx *singles; /**< Single pages outside of any range. */
};

/** PFN-to-index vector allocation increment.
 * For optimal performance, this should be a power of two.
 */
#define PFN2IDX_ALLOC_INC    16

struct elfdump_priv {
	int num_load_segments;
	struct load_segment *load_segments;

	int num_load_sorted;
	struct load_segment *load_sorted;
	struct load_segment *last_load;

	int num_load_vsorted;
	struct load_segment *load_vsorted;
	struct load_segment  *last_vload;

	int num_note_segments;
	struct load_segment *note_segments;

	int num_sections;
	struct section *sections;

	size_t strtab_size;
	char *strtab;

	off_t xen_pages_offset;

	int elfclass;

	/** Map PFN to page index in .xen_pages. */
	struct pfn2idx_map xen_pfnmap;

	/** Map GMFN to page index in .xen_pages. */
	struct pfn2idx_map xen_mfnmap;

	/** File offset of Xen page map (xc_core) */
	off_t xen_map_offset;

	/** File offset mappings for flattened files. */
	struct flattened_map *flatmap;
};

static void elf_cleanup(struct kdump_shared *shared);

static kdump_status
set_read_error(kdump_ctx_t *ctx, kdump_status status,
	       const char *what, off_t offset)
{
	return set_error(ctx, status,
			 "Cannot read %s at %llu",
			 what, (unsigned long long) offset);
}

static kdump_status
set_hdr_error(kdump_ctx_t *ctx, kdump_status status,
	      const char *type, uint64_t idx, off_t offset)
{
	return set_error(ctx, status,
			 "Cannot read ELF %s header #%" PRIu64 " at %llu",
			 type, idx, (unsigned long long) offset);
}

static const char *
mach2arch(unsigned mach, int elfclass)
{
	switch(mach) {
	case EM_AARCH64:
			return KDUMP_ARCH_AARCH64;
	case EM_ARM:	return KDUMP_ARCH_ARM;
	case EM_ALPHA:
	case EM_FAKE_ALPHA:
			return KDUMP_ARCH_ALPHA;
	case EM_IA_64:	return KDUMP_ARCH_IA64;
	case EM_MIPS:	return KDUMP_ARCH_MIPS;
	case EM_PPC:	return KDUMP_ARCH_PPC;
	case EM_PPC64:	return KDUMP_ARCH_PPC64;
	case EM_RISCV:	return (elfclass == ELFCLASS64
				? KDUMP_ARCH_RISCV64
				: KDUMP_ARCH_RISCV32);
	case EM_S390:	return (elfclass == ELFCLASS64
				? KDUMP_ARCH_S390X
				: KDUMP_ARCH_S390);
	case EM_386:	return KDUMP_ARCH_IA32;
	case EM_X86_64:	return KDUMP_ARCH_X86_64;
	default:	return NULL;
	}
}

/**  Find the LOAD segment that is closest to a physical address.
 * @param edp	 ELF dump private data.
 * @param paddr	 Requested physical address.
 * @param dist	 Maximum allowed distance from @c paddr.
 * @returns	 Pointer to the closest LOAD segment, or @c NULL if none.
 */
static struct load_segment *
find_closest_mem_load(struct elfdump_priv *edp, kdump_paddr_t paddr,
		      unsigned long dist)
{
	int i;

	if (edp->last_load &&
	    paddr >= edp->last_load->phys &&
	    paddr - edp->last_load->phys < edp->last_load->memsz)
		return edp->last_load;

	for (i = 0; i < edp->num_load_sorted; i++) {
		struct load_segment *pls = &edp->load_sorted[i];
		if (pls->memsz && paddr <= pls->phys + pls->memsz - 1) {
			if (paddr < pls->phys && pls->phys - paddr > dist)
				break;
			return edp->last_load = pls;
		}
	}
	return NULL;
}

/**  Find the file-backed LOAD segment that is closest to a physical address.
 * @param edp	 ELF dump private data.
 * @param paddr	 Requested physical address.
 * @param dist	 Maximum allowed distance from @c paddr.
 * @returns	 Pointer to the closest LOAD segment, or @c NULL if none.
 */
static struct load_segment *
find_closest_file_load(struct elfdump_priv *edp, kdump_paddr_t paddr,
		       unsigned long dist)
{
	int i;

	if (edp->last_load &&
	    paddr >= edp->last_load->phys &&
	    paddr - edp->last_load->phys < edp->last_load->filesz)
		return edp->last_load;

	for (i = 0; i < edp->num_load_sorted; i++) {
		struct load_segment *pls = &edp->load_sorted[i];
		if (pls->filesz && paddr <= pls->phys + pls->filesz - 1) {
			if (paddr < pls->phys && pls->phys - paddr > dist)
				break;
			return edp->last_load = pls;
		}
	}
	return NULL;
}

/**  Find the LOAD segment that is closest to a virtual address.
 * @param edp	 ELF dump private data.
 * @param vaddr	 Requested virtual address.
 * @param dist	 Maximum allowed distance from @c vaddr.
 * @returns	 Pointer to the closest LOAD segment, or @c NULL if none.
 */
static struct load_segment *
find_closest_mem_vload(struct elfdump_priv *edp, kdump_vaddr_t vaddr,
		       unsigned long dist)
{
	int i;

	if (edp->last_vload &&
	    vaddr >= edp->last_vload->virt &&
	    vaddr - edp->last_vload->virt < edp->last_vload->memsz)
		return edp->last_vload;

	for (i = 0; i < edp->num_load_vsorted; i++) {
		struct load_segment *pls = &edp->load_vsorted[i];
		if (pls->memsz && vaddr <= pls->virt + pls->memsz - 1) {
			if (vaddr < pls->virt && pls->virt - vaddr > dist)
				break;
			return edp->last_load = pls;
		}
	}
	return NULL;
}

/**  Find the file-backed LOAD segment that is closest to a virtual address.
 * @param edp	 ELF dump private data.
 * @param vaddr	 Requested virtual address.
 * @param dist	 Maximum allowed distance from @c vaddr.
 * @returns	 Pointer to the closest LOAD segment, or @c NULL if none.
 */
static struct load_segment *
find_closest_file_vload(struct elfdump_priv *edp, kdump_vaddr_t vaddr,
			unsigned long dist)
{
	int i;

	if (edp->last_vload &&
	    vaddr >= edp->last_vload->virt &&
	    vaddr - edp->last_vload->virt < edp->last_vload->filesz)
		return edp->last_vload;

	for (i = 0; i < edp->num_load_vsorted; i++) {
		struct load_segment *pls = &edp->load_vsorted[i];
		if (pls->filesz && vaddr <= pls->virt + pls->filesz - 1) {
			if (vaddr < pls->virt && pls->virt - vaddr > dist)
				break;
			return edp->last_load = pls;
		}
	}
	return NULL;
}

static kdump_status
elf_read_page(struct page_io *pio)
{
	kdump_ctx_t *ctx = pio->ctx;
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	kdump_addr_t addr;
	struct load_segment *pls;
	kdump_addr_t loadaddr;
	void *p, *endp;
	off_t pos;
	size_t size;
	kdump_status status;

	mutex_lock(&ctx->shared->cache_lock);

	addr = pio->addr.addr;
	p = pio->chunk.data;
	endp = p + get_page_size(ctx);
	while (p < endp) {
		pls = (pio->addr.as == ADDRXLAT_KVADDR
		       ? find_closest_mem_vload(edp, addr, endp - p)
		       : find_closest_mem_load(edp, addr, endp - p));
		if (!pls) {
			memset(p, 0, endp - p);
			break;
		}

		loadaddr = (pio->addr.as == ADDRXLAT_KVADDR
			    ? pls->virt
			    : pls->phys);
		if (loadaddr > addr) {
			memset(p, 0, loadaddr - addr);
			p += loadaddr - addr;
			addr = loadaddr;
		}

		pos = pls->file_offset + addr - loadaddr;
		if (loadaddr + pls->filesz > addr) {
			size = endp - p;
			if (size > loadaddr + pls->filesz - addr)
				size = loadaddr + pls->filesz - addr;

			status = flatmap_pread(edp->flatmap, p, size, 0, pos);
			if (status != KDUMP_OK)
				goto err_read;
			p += size;
			addr += size;
		}
		if (p < endp) {
			size = endp - p;
			if (size > loadaddr + pls->memsz - addr)
				size = loadaddr + pls->memsz - addr;
			memset(p, 0, size);
			p += size;
			addr += size;
		}
	}

	mutex_unlock(&ctx->shared->cache_lock);
	return KDUMP_OK;

 err_read:
	mutex_unlock(&ctx->shared->cache_lock);
	return set_read_error(ctx, status, "page data", pos);
}

static kdump_status
elf_get_page(struct page_io *pio)
{
	kdump_ctx_t *ctx = pio->ctx;
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	struct load_segment *pls;
	kdump_paddr_t addr, loadaddr;
	size_t sz;
	kdump_status status;

	sz = get_page_size(ctx);
	pls = pio->addr.as == ADDRXLAT_KVADDR
		? (get_zero_excluded(ctx)
		   ? find_closest_mem_vload(edp, pio->addr.addr, sz)
		   : find_closest_file_vload(edp, pio->addr.addr, sz))
		: (get_zero_excluded(ctx)
		   ? find_closest_mem_load(edp, pio->addr.addr, sz)
		   : find_closest_file_load(edp, pio->addr.addr, sz));
	if (!pls && pio->addr.as == ADDRXLAT_KVADDR) {
		addrxlat_status status;
		kdump_status ret;

		ret = revalidate_xlat(ctx);
		if (ret != KDUMP_OK)
			return ret;

		status = addrxlat_fulladdr_conv(
			&pio->addr, ADDRXLAT_MACHPHYSADDR,
			ctx->xlatctx, ctx->xlat->xlatsys);
		if (status != ADDRXLAT_OK)
			return addrxlat2kdump(ctx, status);

		pls = find_closest_mem_load(edp, pio->addr.addr, sz);
	}
	if (!pls)
		return set_error(ctx, KDUMP_ERR_NODATA, "Page not found");

	addr = pio->addr.addr;
	loadaddr = (pio->addr.as == ADDRXLAT_KVADDR
		    ? pls->virt
		    : pls->phys);

	/* Handle reads crossing a LOAD boundary. */
	if (! (loadaddr <= addr && pls->filesz >= addr - loadaddr + sz))
		return cache_get_page(pio, elf_read_page);

	mutex_lock(&ctx->shared->cache_lock);
	status = flatmap_get_chunk(edp->flatmap, &pio->chunk, sz,
				   0, pls->file_offset + addr - loadaddr);
	mutex_unlock(&ctx->shared->cache_lock);
	return status;
}

static void
elf_get_bits(struct kdump_shared *shared,
	     kdump_addr_t first, kdump_addr_t last, unsigned char *bits,
	     bool ismem)
{
	struct elfdump_priv *edp = shared->fmtdata;
	const struct load_segment *pls;
	kdump_paddr_t cur, next, size;

	cur = pfn_to_addr(shared, first);
	next = pfn_to_addr(shared, last - first  + 1);
	pls = ismem
		? find_closest_mem_load(edp, cur, next)
		: find_closest_file_load(edp, cur, next);
	if (!pls) {
		memset(bits, 0, ((last - first) >> 3) + 1);
		return;
	}

	/* Clear extra bits in the last byte of the raw bitmap. */
	bits[(last - first) >> 3] = 0;

	cur = first;
	do {
		next = addr_to_pfn(shared, pls->phys);
		if (cur < next) {
			clear_bits(bits, cur - first, next - 1 - first);
			cur = next;
		}

		size = ismem ? pls->memsz : pls->filesz;
		next = addr_to_pfn(shared, pls->phys + size - 1);
		if (next >= last) {
			set_bits(bits, cur - first, last - first);
			return;
		}
		if (cur <= next) {
			set_bits(bits, cur - first, next - first);
			cur = next + 1;
		}
		++pls;
	} while (pls < &edp->load_sorted[edp->num_load_sorted]);

	clear_bits(bits, cur - first, last - first);
}

static kdump_status
elf_file_get_bits(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		  kdump_addr_t first, kdump_addr_t last, unsigned char *bits)
{
	struct kdump_shared *shared = bmp->priv;

	rwlock_rdlock(&shared->lock);
	elf_get_bits(shared, first, last, bits, false);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static kdump_status
elf_mem_get_bits(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		 kdump_addr_t first, kdump_addr_t last, unsigned char *bits)
{
	struct kdump_shared *shared = bmp->priv;

	rwlock_rdlock(&shared->lock);
	elf_get_bits(shared, first, last, bits, true);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static kdump_status
elf_find_set(kdump_errmsg_t *err, struct kdump_shared *shared,
	     kdump_addr_t *idx, bool ismem)
{
	struct elfdump_priv *edp = shared->fmtdata;
	const struct load_segment *pls;
	kdump_paddr_t pfn;

	pls = ismem
		? find_closest_mem_load(edp, pfn_to_addr(shared, *idx),
					KDUMP_ADDR_MAX)
		: find_closest_file_load(edp, pfn_to_addr(shared, *idx),
					 KDUMP_ADDR_MAX);
	if (!pls)
		return status_err(err, KDUMP_ERR_NODATA,
				  "No such bit found");
	pfn = addr_to_pfn(shared, pls->phys);
	if (pfn > *idx)
		*idx = pfn;
	return KDUMP_OK;
}

static kdump_status
elf_file_find_set(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		  kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	kdump_status ret;

	rwlock_rdlock(&shared->lock);
	ret = elf_find_set(err, shared, idx, false);
	rwlock_unlock(&shared->lock);
	return ret;
}

static kdump_status
elf_mem_find_set(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		  kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;
	kdump_status ret;

	rwlock_rdlock(&shared->lock);
	ret = elf_find_set(err, shared, idx, true);
	rwlock_unlock(&shared->lock);
	return ret;
}

static void
elf_find_clear(kdump_errmsg_t *err, struct kdump_shared *shared,
	       kdump_addr_t *idx, bool ismem)
{
	struct elfdump_priv *edp = shared->fmtdata;
	const struct load_segment *pls;

	pls = ismem
		? find_closest_mem_load(edp, pfn_to_addr(shared, *idx),
					KDUMP_ADDR_MAX)
		: find_closest_file_load(edp, pfn_to_addr(shared, *idx),
					 KDUMP_ADDR_MAX);
	if (!pls)
		return;
	while (pls < &edp->load_sorted[edp->num_load_sorted] &&
	       *idx >= addr_to_pfn(shared, pls->phys)) {
		kdump_paddr_t size = ismem ? pls->memsz : pls->filesz;
		kdump_paddr_t pfn = addr_to_pfn(shared, pls->phys + size - 1);
		if (pfn >= *idx)
			*idx = pfn + 1;
		++pls;
	}
}

static kdump_status
elf_file_find_clear(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		    kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;

	rwlock_rdlock(&shared->lock);
	elf_find_clear(err, shared, idx, false);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static kdump_status
elf_mem_find_clear(kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		    kdump_addr_t *idx)
{
	struct kdump_shared *shared = bmp->priv;

	rwlock_rdlock(&shared->lock);
	elf_find_clear(err, shared, idx, true);
	rwlock_unlock(&shared->lock);
	return KDUMP_OK;
}

static void
elf_bmp_cleanup(const kdump_bmp_t *bmp)
{
	struct kdump_shared *shared = bmp->priv;
	shared_decref(shared);
}

static const struct kdump_bmp_ops elf_file_bmp_ops = {
	.get_bits = elf_file_get_bits,
	.find_set = elf_file_find_set,
	.find_clear = elf_file_find_clear,
	.cleanup = elf_bmp_cleanup,
};

static const struct kdump_bmp_ops elf_mem_bmp_ops = {
	.get_bits = elf_mem_get_bits,
	.find_set = elf_mem_find_set,
	.find_clear = elf_mem_find_clear,
	.cleanup = elf_bmp_cleanup,
};

static void
pfn2idx_map_start(struct pfn2idx_map *map, struct pfn2idx_range *cur)
{
	map->nranges = 0;
	map->ranges = NULL;
	map->nsingles = 0;
	map->singles = NULL;

	cur->idx = 0;
	cur->len = 0;
}

static void
pfn2idx_map_free(struct pfn2idx_map *map)
{
	free(map->ranges);
	free(map->singles);
}

static kdump_status
pfn2idx_map_addrange(struct pfn2idx_map *map, struct pfn2idx_range *range)
{
	if (range->len > 1 || range->len < -1) {
		if (map->nranges % PFN2IDX_ALLOC_INC == 0) {
			struct pfn2idx_range *newranges;
			size_t newsz = (map->nranges + PFN2IDX_ALLOC_INC) *
				sizeof *newranges;
			newranges = realloc(map->ranges, newsz);
			if (!newranges)
				return KDUMP_ERR_SYSTEM;
			map->ranges = newranges;
		}

		map->ranges[map->nranges].pfn = range->pfn;
		map->ranges[map->nranges].idx = range->idx - 1;
		map->ranges[map->nranges].len = range->len;
		map->nranges++;
	} else if (range->len) {
		if (map->nsingles % PFN2IDX_ALLOC_INC == 0) {
			struct pfn2idx *newsingles;
			size_t newsz = (map->nsingles + PFN2IDX_ALLOC_INC) *
				sizeof *newsingles;
			newsingles = realloc(map->singles, newsz);
			if (!newsingles)
				return KDUMP_ERR_SYSTEM;
			map->singles = newsingles;
		}
		map->singles[map->nsingles].pfn = range->pfn;
		map->singles[map->nsingles].idx = range->idx - 1;
		map->nsingles++;
	}

	return KDUMP_OK;
}

static kdump_status
pfn2idx_map_add(struct pfn2idx_map *map, struct pfn2idx_range *range,
		kdump_pfn_t pfn)
{
	kdump_status status;

	if (range->len > 0 && pfn == range->pfn + 1)
		++range->len;
	else if (range->len < 0 && pfn == range->pfn - 1)
		--range->len;
	else if (range->len == 1 && pfn == range->pfn - 1)
		range->len = -2;
	else {
		status = pfn2idx_map_addrange(map, range);
		if (status != KDUMP_OK)
			return status;
		range->len = 1;
	}
	range->pfn = pfn;
	++range->idx;
	return KDUMP_OK;
}

static int
pfn2idx_range_cmp(const void *a, const void *b)
{
	const struct pfn2idx_range *ra = a, *rb = b;
	return ra->pfn != rb->pfn ? (ra->pfn > rb->pfn ? 1 : -1) : 0;
}

static int
pfn2idx_single_cmp(const void *a, const void *b)
{
	const struct pfn2idx *sa = a, *sb = b;
	return sa->pfn != sb->pfn ? (sa->pfn > sb->pfn ? 1 : -1) : 0;
}

static kdump_status
pfn2idx_map_end(struct pfn2idx_map *map, struct pfn2idx_range *range)
{
	kdump_status status;

	status = pfn2idx_map_addrange(map, range);
	if (status != KDUMP_OK)
		return status;

	qsort(map->ranges, map->nranges, sizeof *map->ranges,
	      pfn2idx_range_cmp);
	qsort(map->singles, map->nsingles, sizeof *map->singles,
	      pfn2idx_single_cmp);

	return KDUMP_OK;
}

static uint_fast64_t
pfn2idx_map_search(struct pfn2idx_map *map, kdump_pfn_t pfn)
{
	size_t i;
	for (i = 0; i < map->nranges; ++i) {
		struct pfn2idx_range *r = &map->ranges[i];
		if (r->len >= 0) {
			if (pfn < r->pfn - r->len + 1)
				break;
			if (pfn <= r->pfn)
				return r->idx + pfn - r->pfn;
		} else {
			if (pfn < r->pfn)
				break;
			if (pfn <= r->pfn - r->len - 1)
				return r->idx + r->pfn - pfn;
		}
	}

	for (i = 0; i < map->nsingles && pfn >= map->singles[i].pfn; ++i)
		if (map->singles[i].pfn == pfn)
			return map->singles[i].idx;

	return IDX_NONE;
}

static kdump_status
make_xen_pfn_map_auto(kdump_ctx_t *ctx, const struct section *sect)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	kdump_pfn_t max_pfn = 0;
	uint64_t pfn;
	struct pfn2idx_range range;
	off_t pos, endpos;
	struct fcache_entry fce;
	kdump_status status;

	pfn2idx_map_start(&edp->xen_pfnmap, &range);

	pos = edp->xen_map_offset = sect->file_offset;
	endpos = pos + sect->size - sizeof pfn;
	fce.len = 0;
	fce.cache = NULL;
	while (pos <= endpos) {
		if (fce.len < sizeof pfn) {
			fcache_put(&fce);
			status = fcache_get_fb(ctx->shared->fcache, &fce,
					       0, pos, &pfn, sizeof pfn);
			if (status != KDUMP_OK)
				goto err_read;
		}
		pfn = dump64toh(ctx, *(uint64_t*)fce.data);

		if (pfn >= max_pfn)
			max_pfn = pfn + 1;

		status = pfn2idx_map_add(&edp->xen_pfnmap, &range, pfn);
		if (status != KDUMP_OK)
			goto err_pfn;

		fce.data += sizeof pfn;
		fce.len -= sizeof pfn;
		pos += sizeof pfn;
	}
	status = pfn2idx_map_end(&edp->xen_pfnmap, &range);
	if (status != KDUMP_OK)
		goto err_pfn;

	/* TODO: Warn if endpos - pos < sizeof pfn */

	fcache_put(&fce);

	set_max_pfn(ctx, max_pfn);
	return status;

 err_pfn:
	pfn = dump64toh(ctx, *(uint64_t*)fce.data);
	set_error(ctx, status, "Cannot map %s 0x%"PRIx64" -> 0x%"PRIxFAST64,
		  "PFN", pfn, range.idx);
	fcache_put(&fce);
	return status;

 err_read:
	return set_read_error(ctx, status, "Xen map", pos);
}

static kdump_status
make_xen_pfn_map_nonauto(kdump_ctx_t *ctx, const struct section *sect)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	kdump_pfn_t max_pfn = 0;
	struct xen_p2m p2m;
	struct pfn2idx_range pfnrange, mfnrange;
	off_t pos, endpos;
	struct fcache_entry fce;
	kdump_status status;

	pfn2idx_map_start(&edp->xen_pfnmap, &pfnrange);
	pfn2idx_map_start(&edp->xen_mfnmap, &mfnrange);

	pos = edp->xen_map_offset = sect->file_offset;
	endpos = pos + sect->size - sizeof p2m;
	fce.len = 0;
	fce.cache = NULL;
	while (pos <= endpos) {
		if (fce.len < sizeof p2m) {
			fcache_put(&fce);
			status = fcache_get_fb(ctx->shared->fcache, &fce,
					       0, pos, &p2m, sizeof p2m);
			if (status != KDUMP_OK)
				goto err_read;
		}
		p2m.pfn = dump64toh(ctx, ((struct xen_p2m*)fce.data)->pfn);
		p2m.gmfn = dump64toh(ctx, ((struct xen_p2m*)fce.data)->gmfn);

		if (p2m.pfn >= max_pfn)
			max_pfn = p2m.pfn + 1;

		status = pfn2idx_map_add(&edp->xen_pfnmap, &pfnrange, p2m.pfn);
		if (status != KDUMP_OK)
			goto err_pfn;
		status = pfn2idx_map_add(&edp->xen_mfnmap, &mfnrange, p2m.gmfn);
		if (status != KDUMP_OK)
			goto err_mfn;

		fce.data += sizeof p2m;
		fce.len -= sizeof p2m;
		pos += sizeof p2m;
	}
	status = pfn2idx_map_end(&edp->xen_pfnmap, &pfnrange);
	if (status != KDUMP_OK)
			goto err_pfn;
	status = pfn2idx_map_end(&edp->xen_mfnmap, &mfnrange);
	if (status != KDUMP_OK)
			goto err_mfn;

	/* TODO: Warn if endpos - pos < sizeof p2m */

	fcache_put(&fce);

	set_max_pfn(ctx, max_pfn);
	return status;

 err_pfn:
	p2m.pfn = dump64toh(ctx, ((struct xen_p2m*)fce.data)->pfn);
	set_error(ctx, status, "Cannot map %s 0x%"PRIx64" -> 0x%"PRIxFAST64,
		  "PFN", p2m.pfn, pfnrange.idx);
	fcache_put(&fce);
	return status;

err_mfn:
	p2m.gmfn = dump64toh(ctx, ((struct xen_p2m*)fce.data)->gmfn);
	set_error(ctx, status, "Cannot map %s 0x%"PRIx64" -> 0x%"PRIxFAST64,
			 "MFN", p2m.gmfn, mfnrange.idx);
	fcache_put(&fce);
	return status;

 err_read:
	return set_read_error(ctx, status, "Xen map", pos);
}

static addrxlat_status
addrxlat_read_error(addrxlat_ctx_t *ctx, const char *what, off_t offset)
{
	return addrxlat_ctx_err(ctx, ADDRXLAT_ERR_NODATA,
				"Cannot read %s at %llu",
				what, (unsigned long long) offset);
}

/** xc_core physical-to-machine first step function.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
xc_p2m_first_step(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_meth_t *meth = step->meth;
	struct kdump_shared *shared = meth->param.custom.data;
	struct elfdump_priv *edp = shared->fmtdata;
	struct xen_p2m p2m;
	uint_fast64_t idx;
	off_t pos;
	kdump_status status;

	idx = pfn2idx_map_search(&edp->xen_pfnmap,
				 addr >> shared->page_shift.number);
	if (idx == IDX_NONE)
		return addrxlat_ctx_err(step->ctx, ADDRXLAT_ERR_NODATA,
					"PFN not found");

	pos = edp->xen_map_offset + idx * sizeof(struct xen_p2m);
	mutex_lock(&shared->cache_lock);
	status = flatmap_pread(edp->flatmap, &p2m, sizeof p2m, 0, pos);
	mutex_unlock(&shared->cache_lock);
	if (status != KDUMP_OK)
		return addrxlat_read_error(step->ctx, "p2m entry", pos);

	step->base.addr = p2m.gmfn << shared->page_shift.number;
	step->idx[0] = addr & (shared->page_size.number - 1);
	step->remain = 1;
	step->elemsz = 1;
	return ADDRXLAT_OK;
}

/** xc_core machine-to-physical first step function.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
xc_m2p_first_step(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_meth_t *meth = step->meth;
	struct kdump_shared *shared = meth->param.custom.data;
	struct elfdump_priv *edp = shared->fmtdata;
	struct xen_p2m p2m;
	uint_fast64_t idx;
	off_t pos;
	kdump_status status;

	idx = pfn2idx_map_search(&edp->xen_mfnmap,
				 addr >> shared->page_shift.number);
	if (idx == IDX_NONE)
		return addrxlat_ctx_err(step->ctx, ADDRXLAT_ERR_NODATA,
					"MFN not found");

	pos = edp->xen_map_offset + idx * sizeof(struct xen_p2m);
	mutex_lock(&shared->cache_lock);
	status = flatmap_pread(edp->flatmap, &p2m, sizeof p2m, 0, pos);
	mutex_unlock(&shared->cache_lock);
	if (status != KDUMP_OK)
		return addrxlat_read_error(step->ctx, "m2p entry", pos);

	step->base.addr = p2m.pfn << shared->page_shift.number;
	step->idx[0] = addr & (shared->page_size.number - 1);
	step->remain = 1;
	step->elemsz = 1;
	return ADDRXLAT_OK;
}

/** Identity next step function.
 * @param walk  Current step state.
 * @returns     Error status.
 *
 * This method does not modify anything and always succeeds.
 */
static addrxlat_status
next_step_ident(addrxlat_step_t *state)
{
	return ADDRXLAT_OK;
}

static kdump_status
setup_custom_method(kdump_ctx_t *ctx, addrxlat_sys_meth_t methidx,
		    addrxlat_sys_map_t mapidx, const addrxlat_meth_t *meth)
{
	addrxlat_range_t range;
	addrxlat_map_t *map;
	addrxlat_status axstatus;

	map = addrxlat_map_new();
	if (!map)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate translation map");

	range.endoff = ADDRXLAT_ADDR_MAX;
	range.meth = methidx;
	axstatus = addrxlat_map_set(map, 0, &range);
	if (axstatus != ADDRXLAT_OK) {
		addrxlat_map_decref(map);
		return addrxlat2kdump(ctx, axstatus);
	}
	addrxlat_sys_set_map(ctx->xlat->xlatsys, mapidx, map);
	addrxlat_sys_set_meth(ctx->xlat->xlatsys, methidx, meth);

	return KDUMP_OK;
}

static kdump_status
xc_post_addrxlat(kdump_ctx_t *ctx)
{
	addrxlat_meth_t meth;
	kdump_status status;

	if (get_xen_xlat(ctx) != KDUMP_XEN_NONAUTO)
		return KDUMP_OK;

	/* common fields */
	meth.kind = ADDRXLAT_CUSTOM;
	meth.param.custom.next_step = next_step_ident;
	meth.param.custom.data = ctx->shared;

	/* p2m translation */
	meth.target_as = ADDRXLAT_MACHPHYSADDR;
	meth.param.custom.first_step = xc_p2m_first_step;
	status = setup_custom_method(ctx, ADDRXLAT_SYS_METH_KPHYS_MACHPHYS,
				     ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS, &meth);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Failed p2m setup");

	/* m2p translation */
	meth.target_as = ADDRXLAT_KPHYSADDR;
	meth.param.custom.first_step = xc_m2p_first_step;
	status = setup_custom_method(ctx, ADDRXLAT_SYS_METH_MACHPHYS_KPHYS,
				     ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS, &meth);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Failed m2p setup");

	return KDUMP_OK;
}

static kdump_status
xc_get_page(struct page_io *pio)
{
	kdump_ctx_t *ctx = pio->ctx;
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	kdump_pfn_t pfn = pio->addr.addr >> get_page_shift(ctx);
	uint_fast64_t idx;
	off_t offset;
	kdump_status status;

	idx = ( (get_xen_xlat(ctx) == KDUMP_XEN_NONAUTO &&
		 pio->addr.as == ADDRXLAT_MACHPHYSADDR)
		? pfn2idx_map_search(&edp->xen_mfnmap, pfn)
		: pfn2idx_map_search(&edp->xen_pfnmap, pfn));
	if (idx == IDX_NONE)
		return set_error(ctx, KDUMP_ERR_NODATA, "Page not found");

	offset = edp->xen_pages_offset + ((off_t)idx << get_page_shift(ctx));

	mutex_lock(&ctx->shared->cache_lock);
	status = flatmap_get_chunk(edp->flatmap, &pio->chunk,
				   get_page_size(ctx), 0, offset);
	mutex_unlock(&ctx->shared->cache_lock);
	return status;
}

static kdump_status
init_segments(kdump_ctx_t *ctx, uint64_t phnum)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;

	if (!phnum)
		return KDUMP_OK;

	if (phnum > SIZE_MAX / 2 / sizeof(struct load_segment)) {
		set_error(ctx, KDUMP_ERR_SYSTEM,
			  "Too many program headers (%" PRIu64 ")", phnum);
		return KDUMP_ERR_SYSTEM;
	}

	edp->load_segments =
		ctx_malloc(2 * phnum * sizeof(struct load_segment),
			   ctx, "program headers");
	if (!edp->load_segments)
		return KDUMP_ERR_SYSTEM;
	edp->num_load_segments = 0;

	edp->note_segments = edp->load_segments + phnum;
	edp->num_note_segments = 0;
	return KDUMP_OK;
}

static kdump_status
init_sections(kdump_ctx_t *ctx, uint64_t snum)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;

	if (!snum)
		return KDUMP_OK;

	if (snum > SIZE_MAX / sizeof(struct section)) {
		set_error(ctx, KDUMP_ERR_SYSTEM,
			  "Too many section headers (%" PRIu64 ")", snum);
		return KDUMP_ERR_SYSTEM;
	}

	edp->sections =
		ctx_malloc(snum * sizeof(struct section),
			   ctx, "section headers");
	if (!edp->sections)
		return KDUMP_ERR_SYSTEM;
	edp->num_sections = 0;
	return KDUMP_OK;
}

static struct load_segment *
next_phdr(struct elfdump_priv *edp, unsigned type)
{
	struct load_segment *pls;

	if (type == PT_LOAD) {
		pls = edp->load_segments + edp->num_load_segments;
		++edp->num_load_segments;
	} else if (type == PT_NOTE) {
		pls = edp->note_segments + edp->num_note_segments;
		++edp->num_note_segments;
	} else
		pls = NULL;

	return pls;
}

static void
store_sect(struct elfdump_priv *edp, off_t offset,
	   uint64_t size, unsigned name_index)
{
	struct section *ps;

	ps = edp->sections + edp->num_sections;
	ps->file_offset = offset;
	ps->size = size;
	ps->name_index = name_index;
	++edp->num_sections;
}

static kdump_status
init_strtab(kdump_ctx_t *ctx, unsigned strtabidx)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	struct section *ps;
	kdump_status status;

	if (!strtabidx || strtabidx >= edp->num_sections)
		return KDUMP_OK;	/* no string table */

	ps = edp->sections + strtabidx;
	edp->strtab_size = ps->size;
	edp->strtab = ctx_malloc(ps->size, ctx, "ELF string table");
	if (!edp->strtab)
		return KDUMP_ERR_SYSTEM;

	status = flatmap_pread(edp->flatmap, edp->strtab, ps->size,
			       0, ps->file_offset);
	if (status != KDUMP_OK) {
		free(edp->strtab);
		edp->strtab = NULL;
		return set_read_error(ctx, status, "ELF string table",
				      ps->file_offset);
	}

	return KDUMP_OK;
}

static const char *
strtab_entry(struct elfdump_priv *edp, unsigned index)
{
	return index < edp->strtab_size
		? edp->strtab + index
		: NULL;
}

static kdump_status
init_elf32(kdump_ctx_t *ctx, Elf32_Ehdr *ehdr)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	uint32_t shnum, phnum, i;
	off_t offset;
	size_t entsz;
	struct fcache_chunk fch;
	kdump_status ret;

	set_arch_machine(ctx, dump16toh(ctx, ehdr->e_machine));

	shnum = dump16toh(ctx, ehdr->e_shnum);
	phnum = dump16toh(ctx, ehdr->e_phnum);
	offset = dump32toh(ctx, ehdr->e_shoff);
	if (offset != 0 && (shnum == 0 || phnum == PN_XNUM)) {
		Elf32_Shdr *sect;

		ret = flatmap_get_chunk(edp->flatmap, &fch,
					dump16toh(ctx, ehdr->e_shentsize),
					0, offset);
		if (ret != KDUMP_OK)
			return set_hdr_error(ctx, ret, "section", 0, offset);
		sect = (Elf32_Shdr*) fch.data;

		if (shnum == 0)
			shnum = dump32toh(ctx, sect->sh_size);
		if (shnum > 0 && phnum == PN_XNUM)
			phnum = dump32toh(ctx, sect->sh_info);

		fcache_put_chunk(&fch);
	}

	ret = init_segments(ctx, phnum);
	if (ret != KDUMP_OK)
		return ret;

	ret = init_sections(ctx, shnum);
	if (ret != KDUMP_OK)
		return ret;

	offset = dump32toh(ctx, ehdr->e_phoff);
	entsz = dump16toh(ctx, ehdr->e_phentsize);
	for (i = 0; i < phnum; ++i) {
		Elf32_Phdr *prog;
		struct load_segment *pls;

		ret = flatmap_get_chunk(edp->flatmap, &fch, entsz, 0, offset);
		if (ret != KDUMP_OK)
			return set_hdr_error(ctx, ret, "program", i, offset);
		offset += entsz;
		prog = (Elf32_Phdr*) fch.data;

		pls = next_phdr(edp, dump32toh(ctx, prog->p_type));
		if (pls) {
			pls->file_offset = dump32toh(ctx, prog->p_offset);
			pls->filesz = dump32toh(ctx, prog->p_filesz);
			pls->phys = dump32toh(ctx, prog->p_paddr);
			if (pls->phys == UINT32_MAX)
				pls->phys = ADDRXLAT_ADDR_MAX;
			pls->memsz = dump32toh(ctx, prog->p_memsz);
			pls->virt = dump32toh(ctx, prog->p_vaddr);
		}
		fcache_put_chunk(&fch);
	}

	offset = dump32toh(ctx, ehdr->e_shoff);
	entsz = dump16toh(ctx, ehdr->e_shentsize);
	for (i = 0; i < shnum; ++i) {
		Elf32_Shdr *sect;

		ret = flatmap_get_chunk(edp->flatmap, &fch, entsz, 0, offset);
		if (ret != KDUMP_OK)
			return set_hdr_error(ctx, ret, "section", i, offset);
		offset += entsz;
		sect = (Elf32_Shdr*) fch.data;

		store_sect(edp,
			   dump32toh(ctx, sect->sh_offset),
			   dump32toh(ctx, sect->sh_size),
			   dump32toh(ctx, sect->sh_name));
		fcache_put_chunk(&fch);
	}

	ret = init_strtab(ctx, dump16toh(ctx, ehdr->e_shstrndx));
	if (ret != KDUMP_OK)
		return ret;

	return ret;
}

static kdump_status
init_elf64(kdump_ctx_t *ctx, Elf64_Ehdr *ehdr)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	uint64_t shnum, phnum, i;
	off_t offset;
	size_t entsz;
	struct fcache_chunk fch;
	kdump_status ret;

	set_arch_machine(ctx, dump16toh(ctx, ehdr->e_machine));

	shnum = dump16toh(ctx, ehdr->e_shnum);
	phnum = dump16toh(ctx, ehdr->e_phnum);
	offset = dump64toh(ctx, ehdr->e_shoff);
	if (offset != 0 && (shnum == 0 || phnum == PN_XNUM)) {
		Elf64_Shdr *sect;

		ret = flatmap_get_chunk(edp->flatmap, &fch,
					dump16toh(ctx, ehdr->e_shentsize),
					0, offset);
		if (ret != KDUMP_OK)
			return set_hdr_error(ctx, ret, "section", 0, offset);
		sect = (Elf64_Shdr*) fch.data;

		if (shnum == 0)
			shnum = dump64toh(ctx, sect->sh_size);
		if (shnum > 0 && phnum == PN_XNUM)
			phnum = dump32toh(ctx, sect->sh_info);

		fcache_put_chunk(&fch);
	}

	ret = init_segments(ctx, phnum);
	if (ret != KDUMP_OK)
		return ret;

	ret = init_sections(ctx, shnum);
	if (ret != KDUMP_OK)
		return ret;

	offset = dump64toh(ctx, ehdr->e_phoff);
	entsz = dump16toh(ctx, ehdr->e_phentsize);
	for (i = 0; i < phnum; ++i) {
		Elf64_Phdr *prog;
		struct load_segment *pls;

		ret = flatmap_get_chunk(edp->flatmap, &fch, entsz, 0, offset);
		if (ret != KDUMP_OK)
			return set_hdr_error(ctx, ret, "program", i, offset);
		offset += entsz;
		prog = (Elf64_Phdr*) fch.data;

		pls = next_phdr(edp, dump32toh(ctx, prog->p_type));
		if (pls) {
			pls->file_offset = dump64toh(ctx, prog->p_offset);
			pls->filesz = dump64toh(ctx, prog->p_filesz);
			pls->phys = dump64toh(ctx, prog->p_paddr);
			if (pls->phys == UINT64_MAX)
				pls->phys = ADDRXLAT_ADDR_MAX;
			pls->memsz = dump64toh(ctx, prog->p_memsz);
			pls->virt = dump64toh(ctx, prog->p_vaddr);
		}
		fcache_put_chunk(&fch);
	}

	offset = dump64toh(ctx, ehdr->e_shoff);
	entsz = dump16toh(ctx, ehdr->e_shentsize);
	for (i = 0; i < shnum; ++i) {
		Elf64_Shdr *sect;

		ret = flatmap_get_chunk(edp->flatmap, &fch, entsz, 0, offset);
		if (ret != KDUMP_OK)
			return set_hdr_error(ctx, ret, "section", i, offset);
		offset += entsz;
		sect = (Elf64_Shdr*) fch.data;

		store_sect(edp,
			   dump64toh(ctx, sect->sh_offset),
			   dump64toh(ctx, sect->sh_size),
			   dump32toh(ctx, sect->sh_name));
		fcache_put_chunk(&fch);
	}

	ret = init_strtab(ctx, dump16toh(ctx, ehdr->e_shstrndx));
	if (ret != KDUMP_OK)
		return ret;

	return ret;
}

typedef kdump_status walk_notes_fn(kdump_ctx_t *, void *, size_t);

static kdump_status
walk_elf_notes(kdump_ctx_t *ctx, walk_notes_fn *fn)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	unsigned i;
	struct fcache_chunk fch;
	kdump_status ret;

	for (i = 0; i < edp->num_note_segments; ++i) {
		struct load_segment *seg = edp->note_segments + i;

		ret = flatmap_get_chunk(edp->flatmap, &fch, seg->filesz, 0,
					seg->file_offset);
		if (ret != KDUMP_OK)
			return set_read_error(ctx, ret, "ELF notes",
					      seg->file_offset);

		ret = fn(ctx, fch.data, seg->filesz);
		fcache_put_chunk(&fch);
		if (ret != KDUMP_OK)
			return ret;
	}

	return KDUMP_OK;
}

static int
seg_phys_cmp(const void *a, const void *b)
{
	const struct load_segment *la = a, *lb = b;
	return la->phys != lb->phys ? (la->phys < lb->phys ? -1 : 1) : 0;
}

static int
seg_virt_cmp(const void *a, const void *b)
{
	const struct load_segment *la = a, *lb = b;
	return la->phys != lb->phys ? (la->phys < lb->phys ? -1 : 1) : 0;
}

static kdump_status
open_common(kdump_ctx_t *ctx)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	struct fcache_chunk fch;
	kdump_pfn_t max_pfn;
	unsigned long as_caps;
	kdump_bmp_t *bmp;
	kdump_attr_value_t val;
	kdump_status ret;
	int i;

	if (get_num_files(ctx) > 1)
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Multiple files not implemented");

	if (!edp->num_load_segments && !edp->num_sections)
		return set_error(ctx, KDUMP_ERR_NOTIMPL, "No content found");

	edp->load_sorted = ctx_malloc(2 * edp->num_load_segments *
				      sizeof(*edp->load_sorted),
				      ctx, "Sorted LOAD segments");
	if (!edp->load_sorted)
		return KDUMP_ERR_SYSTEM;
	edp->load_vsorted = edp->load_sorted + edp->num_load_segments;

	bmp = kdump_bmp_new(&elf_file_bmp_ops);
	if (!bmp)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s", "file pagemap");
	bmp->priv = ctx->shared;
	shared_incref_locked(ctx->shared);
	set_file_pagemap(ctx, bmp);

	val.bitmap = kdump_bmp_new(&elf_mem_bmp_ops);
	if (!val.bitmap)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s", "memory pagemap");
	val.bitmap->priv = ctx->shared;
	shared_incref_locked(ctx->shared);
	ret = set_attr(ctx, gattr(ctx, GKI_memory_pagemap), ATTR_DEFAULT, &val);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret,
				 "Cannot set %s attribute", "memory pagemap");

	/* process NOTE segments */
	ret = walk_elf_notes(ctx, process_noarch_notes);
	if (ret != KDUMP_OK)
		return ret;

	if (!isset_arch_name(ctx)) {
		uint_fast16_t mach = get_arch_machine(ctx);
		const char *arch = mach2arch(mach, edp->elfclass);
		if (arch) {
			ret = set_arch_name(ctx, arch);
			if (ret != KDUMP_OK)
				return ret;
		}
	}

	ret = walk_elf_notes(ctx, process_arch_notes);
	if (ret != KDUMP_OK)
		return ret;

	as_caps = get_xen_type(ctx) == KDUMP_XEN_NONE
		? ADDRXLAT_CAPS(ADDRXLAT_KVADDR)
		: 0;

	/* Check that physical addresses are usable */
	for (i = 0; i < edp->num_load_segments; ++i)
		if (edp->load_segments[i].phys)
			break;
	if (i >= edp->num_load_segments && i > 1)
		while (i--)
			edp->load_segments[i].phys = ADDRXLAT_ADDR_MAX;
	else
		as_caps |= ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR);

	/* Find max PFN */
	max_pfn = 0;
	for (i = 0; i < edp->num_load_segments; ++i) {
		struct load_segment *seg = edp->load_segments + i;
		unsigned long pfn;

		if (seg->phys == ADDRXLAT_ADDR_MAX)
			continue;

		pfn = (seg->phys + seg->memsz) >> get_page_shift(ctx);
		if (pfn > max_pfn)
			max_pfn = pfn;

		edp->load_sorted[edp->num_load_sorted++] = *seg;
	}
	set_max_pfn(ctx, max_pfn);

	/* Make sorted lists. */
	qsort(edp->load_sorted, edp->num_load_sorted,
	      sizeof(struct load_segment), seg_phys_cmp);

	edp->num_load_vsorted = edp->num_load_segments;
	memcpy(edp->load_vsorted, edp->load_segments,
	       edp->num_load_vsorted * sizeof(struct load_segment));
	qsort(edp->load_vsorted, edp->num_load_segments,
	      sizeof(struct load_segment), seg_virt_cmp);

	free(edp->load_segments);
	edp->load_segments = edp->note_segments = NULL;

	/* Process sections. */
	for (i = 0; i < edp->num_sections; ++i) {
		struct section *sect = edp->sections + i;
		const char *name = strtab_entry(edp, sect->name_index);
		if (!name)
			continue;
		if (!strcmp(name, ".xen_pages"))
			edp->xen_pages_offset = sect->file_offset;
		else if (!strcmp(name, ".xen_p2m")) {
			set_xen_xlat(ctx, KDUMP_XEN_NONAUTO);
			ret = make_xen_pfn_map_nonauto(ctx, sect);
			if (ret != KDUMP_OK)
				return set_error(ctx, ret,
						 "Cannot create Xen P2M map");
		} else if (!strcmp(name, ".xen_pfn")) {
			set_xen_xlat(ctx, KDUMP_XEN_AUTO);
			ret = make_xen_pfn_map_auto(ctx, sect);
			if (ret != KDUMP_OK)
				return set_error(ctx, ret,
						 "Cannot create Xen PFN map");
		} else if (!strcmp(name, ".note.Xen")) {
			ret = flatmap_get_chunk(edp->flatmap, &fch, sect->size,
						0, sect->file_offset);
			if (ret != KDUMP_OK)
				return set_error(ctx, ret,
						 "Cannot read '%s'", name);
			ret = process_notes(ctx, fch.data, sect->size);
			fcache_put_chunk(&fch);
			if (ret != KDUMP_OK)
				return set_error(ctx, ret,
						 "Cannot process Xen notes");
		} else if (!strcmp(name, ".xen_prstatus")) {
			ret = flatmap_get_chunk(edp->flatmap, &fch, sect->size,
						0, sect->file_offset);
			if (ret != KDUMP_OK)
				return set_error(ctx, ret,
						 "Cannot read '%s'", name);

			ret = ctx->shared->arch_ops->process_xen_prstatus(
				ctx, fch.data, sect->size);
			fcache_put_chunk(&fch);
			if (ret != KDUMP_OK)
				return set_error(ctx, ret,
						 "Cannot process Xen prstatus");
		}
	}

	if (edp->xen_pages_offset) {
		set_xen_type(ctx, KDUMP_XEN_DOMAIN);
		if (!edp->xen_map_offset)
			return set_error(ctx, KDUMP_ERR_NOTIMPL,
					 "Missing Xen P2M mapping");
		ctx->shared->ops = &xc_core_elf_ops;
		as_caps = ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR) |
			ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR);
	}

	set_addrspace_caps(ctx->xlat, as_caps);

	if (!attr_isset(gattr(ctx, GKI_linux_vmcoreinfo_raw)) &&
	    attr_isset(gattr(ctx, GKI_linux_task_struct))) {
		struct statfs stfs;

		if (fstatfs(ctx->shared->fcache->info[0].fd, &stfs) < 0)
			return set_error(ctx, KDUMP_ERR_SYSTEM,
					 "Cannot determine filesystem");
		if (stfs.f_type == PROC_SUPER_MAGIC) {
			read_current_vmcoreinfo(ctx);
			clear_error(ctx);
		}
	}

	return KDUMP_OK;
}

static kdump_status
do_probe(kdump_ctx_t *ctx, void *hdr)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	unsigned char *eheader = hdr;
	Elf32_Ehdr *elf32 = hdr;
	Elf64_Ehdr *elf64 = hdr;

	if (memcmp(eheader, ELFMAG, SELFMAG))
		return set_error(ctx, KDUMP_NOPROBE,
				 "Invalid ELF signature");

	switch (eheader[EI_DATA]) {
	case ELFDATA2LSB:
		set_byte_order(ctx, KDUMP_LITTLE_ENDIAN);
		break;
	case ELFDATA2MSB:
		set_byte_order(ctx, KDUMP_BIG_ENDIAN);
		break;
	default:
		return set_error(ctx, KDUMP_ERR_NOTIMPL,
				 "Unsupported ELF data format: %u",
				 eheader[EI_DATA]);
	}

        if ((elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
	    (dump16toh(ctx, elf32->e_type) == ET_CORE) &&
	    (dump32toh(ctx, elf32->e_version) == EV_CURRENT)) {
		edp->elfclass = ELFCLASS32;
		set_file_description(ctx, "ELF32 dump");
		return init_elf32(ctx, elf32);
	} else if ((elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
		   (dump16toh(ctx, elf64->e_type) == ET_CORE) &&
		   (dump32toh(ctx, elf64->e_version) == EV_CURRENT)) {
		edp->elfclass = ELFCLASS64;
		set_file_description(ctx, "ELF64 dump");
		return init_elf64(ctx, elf64);
	}

	return set_error(ctx, KDUMP_ERR_NOTIMPL,
			 "Unsupported ELF class: %u", elf32->e_ident[EI_CLASS]);
}

static kdump_status
elf_probe(kdump_ctx_t *ctx)
{
	struct elfdump_priv *edp;
	struct fcache_chunk fch;
	kdump_status ret;

	edp = calloc(1, sizeof *edp);
	if (!edp)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate ELF dump private data");
	ctx->shared->fmtdata = edp;

	edp->flatmap = flatmap_alloc(1);
	if (!edp->flatmap)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s",
				 "flattened dump maps");

	ret = flatmap_init(edp->flatmap, ctx);
	if (ret != KDUMP_OK)
		return ret;

	ret = flatmap_get_chunk(edp->flatmap, &fch, sizeof(Elf64_Ehdr), 0, 0);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret, "Cannot read dump header");

	ret = do_probe(ctx, fch.data);
	fcache_put_chunk(&fch);

	if (ret == KDUMP_OK)
		ret = open_common(ctx);

	if (ret != KDUMP_OK)
		elf_cleanup(ctx->shared);

	return ret;
}

static void
elf_cleanup(struct kdump_shared *shared)
{
	struct elfdump_priv *edp = shared->fmtdata;

	if (edp) {
		if (edp->load_sorted)
			free(edp->load_sorted);
		if (edp->load_segments)
			free(edp->load_segments);
		if (edp->sections)
			free(edp->sections);
		if (edp->strtab)
			free(edp->strtab);
		pfn2idx_map_free(&edp->xen_pfnmap);
		pfn2idx_map_free(&edp->xen_mfnmap);
		flatmap_free(edp->flatmap);
		free(edp);
		shared->fmtdata = NULL;
	}
};

const struct format_ops elfdump_ops = {
	.name = "elf",
	.probe = elf_probe,
	.get_page = elf_get_page,
	.put_page = cache_put_page,
	.realloc_caches = def_realloc_caches,
	.cleanup = elf_cleanup,
};

static const struct format_ops xc_core_elf_ops = {
	.name = "xc_core_elf",
	.get_page = xc_get_page,
	.put_page = cache_put_page,
	.post_addrxlat = xc_post_addrxlat,
	.realloc_caches = def_realloc_caches,
	.cleanup = elf_cleanup,
};
