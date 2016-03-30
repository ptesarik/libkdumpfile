/** @internal @file src/elfdump.c
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

/* This definition is missing from older version of <elf.h> */
#ifndef EM_AARCH64
# define EM_AARCH64      183
#endif

static const struct format_ops xc_core_elf_ops;

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

struct elfdump_priv {
	int num_load_segments;
	struct load_segment *load_segments;
	int num_note_segments;
	struct load_segment *note_segments;

	int num_sections;
	struct section *sections;

	size_t strtab_size;
	char *strtab;

	off_t xen_pages_offset;

	int elfclass;
};

static void elf_cleanup(struct kdump_shared *shared);

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
 * @param dist	 Maximum allowed distance from @ref paddr.
 * @returns	 Pointer to the closest LOAD segment, or @c NULL if none.
 */
static struct load_segment *
find_closest_load(struct elfdump_priv *edp, kdump_paddr_t paddr,
		  unsigned long dist)
{
	unsigned long bestdist;
	struct load_segment *bestload;
	int i;

	bestdist = dist;
	bestload = NULL;
	for (i = 0; i < edp->num_load_segments; i++) {
		struct load_segment *pls = &edp->load_segments[i];
		if (paddr >= pls->phys + pls->memsz)
			continue;
		if (paddr >= pls->phys)
			return pls;	/* Exact match */
		if (bestdist > pls->phys - paddr) {
			bestdist = pls->phys - paddr;
			bestload = pls;
		}
	}
	return bestload;
}

static kdump_status
elf_read_cache(kdump_ctx *ctx, kdump_pfn_t pfn, struct cache_entry *ce)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	struct load_segment *pls;
	kdump_paddr_t addr;
	void *p, *endp;
	off_t pos;
	ssize_t size, rd;

	addr = pfn << get_page_shift(ctx);

	p = ce->data;
	endp = p + get_page_size(ctx);
	while (p < endp) {
		pls = find_closest_load(edp, addr, endp - p);
		if (!pls)
			break;

		if (pls->phys > addr) {
			memset(p, 0, pls->phys - addr);
			p += pls->phys - addr;
			addr = pls->phys;
		}

		pos = pls->file_offset + addr - pls->phys;
		if (pls->phys + pls->filesz > addr) {
			size = endp - p;
			if (size > pls->phys + pls->filesz - addr)
				size = pls->phys + pls->filesz - addr;

			rd = pread(ctx->shared->fd, p, size, pos);
			if (rd != size)
				return set_error(
					ctx, read_error(rd),
					"Cannot read page data at %llu",
					(unsigned long long) pos);
			p += size;
			addr += size;
		}
		if (p < endp) {
			size = endp - p;
			if (size > pls->phys + pls->memsz - addr)
				size = pls->phys + pls->memsz - addr;
			memset(p, 0, size);
			p += size;
			addr += size;
		}
	}

	if (p == ce->data)
		return set_error(ctx, kdump_nodata, "Page not found");
	else if (p < endp)
		memset(p, 0, endp - p);

	return kdump_ok;
}

static kdump_status
elf_read_page(kdump_ctx *ctx, struct page_io *pio)
{
	return def_read_cache(ctx, pio, elf_read_cache, pio->pfn);
}

static void
get_max_pfn_xen_auto(kdump_ctx *ctx)
{
	uint64_t *p;
	unsigned long i;
	kdump_pfn_t max_pfn = 0;

	for (i = 0, p = ctx->shared->xen_map; i < ctx->shared->xen_map_size; ++i, ++p)
		if (*p >= max_pfn)
			max_pfn = *p + 1;

	set_max_pfn(ctx, max_pfn);
}

static void
get_max_pfn_xen_nonauto(kdump_ctx *ctx)
{
	struct xen_p2m *p;
	unsigned long i;
	kdump_pfn_t max_pfn = 0;

	for (i = 0, p = ctx->shared->xen_map; i < ctx->shared->xen_map_size;
	     ++i, ++p)
		if (p->pfn >= max_pfn)
			max_pfn = p->pfn + 1;

	set_max_pfn(ctx, max_pfn);
}

static unsigned long
pfn_to_idx(kdump_ctx *ctx, kdump_pfn_t pfn)
{
	unsigned long i;

	if (get_xen_xlat(ctx) == kdump_xen_auto) {
		uint64_t *p = ctx->shared->xen_map;
		for (i = 0; i < ctx->shared->xen_map_size; ++i, ++p)
			if (*p == pfn)
				return i;
	} else {
		struct xen_p2m *p = ctx->shared->xen_map;
		for (i = 0; i < ctx->shared->xen_map_size; ++i, ++p)
			if (p->pfn == pfn)
				return i;
	}

	return ~0UL;
}

static kdump_status
xc_read_cache(kdump_ctx *ctx, kdump_pfn_t idx, struct cache_entry *ce)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	off_t offset;
	ssize_t rd;

	offset = edp->xen_pages_offset + ((off_t)idx << get_page_shift(ctx));
	rd = pread(ctx->shared->fd, ce->data, get_page_size(ctx), offset);
	if (rd != get_page_size(ctx))
		return set_error(ctx, read_error(rd),
				 "Cannot read page data at %llu",
				 (unsigned long long) offset);
	return kdump_ok;
}

static kdump_status
xc_read_kpage(kdump_ctx *ctx, struct page_io *pio)
{
	unsigned long idx;

	idx = pfn_to_idx(ctx, pio->pfn);
	if (idx == ~0UL)
		return set_error(ctx, kdump_nodata, "Page not found");

	return def_read_cache(ctx, pio, xc_read_cache, idx);
}

static unsigned long
mfn_to_idx(kdump_ctx *ctx, kdump_pfn_t mfn)
{
	unsigned long i;

	if (get_xen_xlat(ctx) == kdump_xen_nonauto) {
		struct xen_p2m *p = ctx->shared->xen_map;
		for (i = 0; i < ctx->shared->xen_map_size; ++i, ++p)
			if (p->gmfn == mfn)
				return i;
	}

	return ~0UL;
}

static kdump_status
xc_mfn_to_pfn(kdump_ctx *ctx, kdump_pfn_t mfn, kdump_pfn_t *pfn)
{
	struct xen_p2m *p = ctx->shared->xen_map;
	unsigned long i;

	if (get_xen_xlat(ctx) != kdump_xen_nonauto) {
		*pfn = mfn;
		return kdump_ok;
	}

	for (i = 0; i < ctx->shared->xen_map_size; ++i, ++p)
		if (p->gmfn == mfn) {
			*pfn = p->pfn;
			return kdump_ok;
		}
	return set_error(ctx, kdump_nodata, "MFN not found");
}

static kdump_status
xc_read_page(kdump_ctx *ctx, struct page_io *pio)
{
	unsigned long idx;

	idx = mfn_to_idx(ctx, pio->pfn);
	if (idx == ~0UL)
		return set_error(ctx, kdump_nodata, "Page not found");

	return def_read_cache(ctx, pio, xc_read_cache, idx);
}

static kdump_status
init_segments(kdump_ctx *ctx, unsigned phnum)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;

	if (!phnum)
		return kdump_ok;

	edp->load_segments =
		ctx_malloc(2 * phnum * sizeof(struct load_segment),
			   ctx, "program headers");
	if (!edp->load_segments)
		return kdump_syserr;
	edp->num_load_segments = 0;

	edp->note_segments = edp->load_segments + phnum;
	edp->num_note_segments = 0;
	return kdump_ok;
}

static kdump_status
init_sections(kdump_ctx *ctx, unsigned snum)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;

	if (!snum)
		return kdump_ok;

	edp->sections =
		ctx_malloc(snum * sizeof(struct section),
			   ctx, "section headers");
	if (!edp->sections)
		return kdump_syserr;
	edp->num_sections = 0;
	return kdump_ok;
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

static void *
read_elf_sect(kdump_ctx *ctx, struct section *sect)
{
	void *buf;

	buf = ctx_malloc(sect->size, ctx, "ELF section buffer");
	if (!buf)
		return NULL;

	if (pread(ctx->shared->fd, buf, sect->size, sect->file_offset) == sect->size)
		return buf;

	free(buf);
	return NULL;
}

static kdump_status
init_strtab(kdump_ctx *ctx, unsigned strtabidx)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	struct section *ps;

	if (!strtabidx || strtabidx >= edp->num_sections)
		return kdump_ok;	/* no string table */

	ps = edp->sections + strtabidx;
	edp->strtab_size = ps->size;
	edp->strtab = read_elf_sect(ctx, ps);
	if (!edp->strtab)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate string table (%zu bytes)",
				 edp->strtab_size);

	return kdump_ok;
}

static const char *
strtab_entry(struct elfdump_priv *edp, unsigned index)
{
	return index < edp->strtab_size
		? edp->strtab + index
		: NULL;
}

static kdump_status
init_elf32(kdump_ctx *ctx, Elf32_Ehdr *ehdr)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	Elf32_Phdr prog;
	Elf32_Shdr sect;
	off_t offset;
	kdump_status ret;
	int i;

	set_arch_machine(ctx, dump16toh(ctx, ehdr->e_machine));

	ret = init_segments(ctx, dump16toh(ctx, ehdr->e_phnum));
	if (ret != kdump_ok)
		return ret;

	ret = init_sections(ctx, dump16toh(ctx, ehdr->e_shnum));
	if (ret != kdump_ok)
		return ret;

	offset = dump32toh(ctx, ehdr->e_phoff);
	if (lseek(ctx->shared->fd, offset, SEEK_SET) < 0)
		return set_error(ctx, kdump_syserr,
				 "Cannot seek to program headers at %llu",
				 (unsigned long long) offset);
	for (i = 0; i < dump16toh(ctx, ehdr->e_phnum); ++i) {
		struct load_segment *pls;
		ssize_t rd;

		rd = read(ctx->shared->fd, &prog, sizeof prog);
		if (rd != sizeof prog)
			return set_error(ctx, read_error(rd),
					 "Cannot read program header #%d", i);

		pls = next_phdr(edp, dump32toh(ctx, prog.p_type));
		if (pls) {
			pls->file_offset = dump32toh(ctx, prog.p_offset);
			pls->filesz = dump32toh(ctx, prog.p_filesz);
			pls->phys = dump32toh(ctx, prog.p_paddr);
			pls->memsz = dump32toh(ctx, prog.p_memsz);
			pls->virt = dump32toh(ctx, prog.p_vaddr);
		}
	}

	offset = dump32toh(ctx, ehdr->e_shoff);
	if (lseek(ctx->shared->fd, offset, SEEK_SET) < 0)
		return set_error(ctx, kdump_syserr,
				 "Cannot seek to section headers at %llu",
				 (unsigned long long) offset);
	for (i = 0; i < dump16toh(ctx, ehdr->e_shnum); ++i) {
		ssize_t rd;

		rd = read(ctx->shared->fd, &sect, sizeof sect);
		if (rd != sizeof sect)
			return set_error(ctx, read_error(rd),
					 "Cannot read section header #%d", i);
		store_sect(edp,
			   dump32toh(ctx, sect.sh_offset),
			   dump32toh(ctx, sect.sh_size),
			   dump32toh(ctx, sect.sh_name));
	}

	ret = init_strtab(ctx, dump16toh(ctx, ehdr->e_shstrndx));
	if (ret != kdump_ok)
		return ret;

	return ret;
}

static kdump_status
init_elf64(kdump_ctx *ctx, Elf64_Ehdr *ehdr)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	Elf64_Phdr prog;
	Elf64_Shdr sect;
	off_t offset;
	kdump_status ret;
	int i;

	set_arch_machine(ctx, dump16toh(ctx, ehdr->e_machine));

	ret = init_segments(ctx, dump16toh(ctx, ehdr->e_phnum));
	if (ret != kdump_ok)
		return ret;

	ret = init_sections(ctx, dump16toh(ctx, ehdr->e_shnum));
	if (ret != kdump_ok)
		return ret;


	offset = dump64toh(ctx, ehdr->e_phoff);
	if (lseek(ctx->shared->fd, offset, SEEK_SET) < 0)
		return set_error(ctx, kdump_syserr,
				 "Cannot seek to program headers at %llu",
				 (unsigned long long) offset);
	for (i = 0; i < dump16toh(ctx, ehdr->e_phnum); ++i) {
		struct load_segment *pls;
		ssize_t rd;

		rd = read(ctx->shared->fd, &prog, sizeof prog);
		if (rd != sizeof prog)
			return set_error(ctx, read_error(rd),
					 "Cannot read program header #%d", i);

		pls = next_phdr(edp, dump32toh(ctx, prog.p_type));
		if (pls) {
			pls->file_offset = dump64toh(ctx, prog.p_offset);
			pls->filesz = dump64toh(ctx, prog.p_filesz);
			pls->phys = dump64toh(ctx, prog.p_paddr);
			pls->memsz = dump64toh(ctx, prog.p_memsz);
			pls->virt = dump64toh(ctx, prog.p_vaddr);
		}
	}

	offset = dump32toh(ctx, ehdr->e_shoff);
	if (lseek(ctx->shared->fd, offset, SEEK_SET) < 0)
		return set_error(ctx, kdump_syserr,
				 "Cannot seek to section headers at %llu",
				 (unsigned long long) offset);
	for (i = 0; i < dump16toh(ctx, ehdr->e_shnum); ++i) {
		ssize_t rd;

		rd = read(ctx->shared->fd, &sect, sizeof sect);
		if (rd != sizeof sect)
			return set_error(ctx, read_error(rd),
					 "Cannot read section header #%d", i);
		store_sect(edp,
			   dump64toh(ctx, sect.sh_offset),
			   dump64toh(ctx, sect.sh_size),
			   dump32toh(ctx, sect.sh_name));
	}

	ret = init_strtab(ctx, dump16toh(ctx, ehdr->e_shstrndx));
	if (ret != kdump_ok)
		return ret;

	return ret;
}

static kdump_status
process_elf_notes(kdump_ctx *ctx, void *notes)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	void *p;
	unsigned i;
	ssize_t rd;
	kdump_status ret;

	p = notes;
	for (i = 0; i < edp->num_note_segments; ++i) {
		struct load_segment *seg = edp->note_segments + i;

		rd = pread(ctx->shared->fd, p, seg->filesz, seg->file_offset);
		if (rd != seg->filesz)
			return set_error(ctx, read_error(rd),
					 "Cannot read ELF notes at %llu",
					 (unsigned long long) seg->file_offset);

		ret = process_noarch_notes(ctx, p, seg->filesz);
		if (ret != kdump_ok)
			return ret;

		p += seg->filesz;
	}

	if (!isset_arch_name(ctx)) {
		uint_fast16_t mach = get_arch_machine(ctx);
		const char *arch = mach2arch(mach, edp->elfclass);
		if (arch) {
			ret = set_arch_name(ctx, arch);
			if (ret != kdump_ok)
				return ret;
		}
	}

	p = notes;
	for (i = 0; i < edp->num_note_segments; ++i) {
		struct load_segment *seg = edp->note_segments + i;

		ret = process_arch_notes(ctx, p, seg->filesz);
		if (ret != kdump_ok)
			return ret;
	}

	return kdump_ok;
}

static kdump_status
open_common(kdump_ctx *ctx)
{
	struct elfdump_priv *edp = ctx->shared->fmtdata;
	size_t notesz;
	void *notes;
	kdump_status ret;
	int i;

	if (!edp->num_load_segments && !edp->num_sections)
		return set_error(ctx, kdump_unsupported, "No content found");

	/* read notes */
	notesz = 0;
	for (i = 0; i < edp->num_note_segments; ++i)
		notesz += edp->note_segments[i].filesz;
	notes = ctx_malloc(notesz, ctx, "ELF notes");
	if (!notes)
		return kdump_syserr;

	ret = process_elf_notes(ctx, notes);
	free(notes);
	if (ret != kdump_ok)
		return ret;

	/* process LOAD segments */
	for (i = 0; i < edp->num_load_segments; ++i) {
		struct load_segment *seg = edp->load_segments + i;
		unsigned long pfn =
			(seg->phys + seg->filesz) >> get_page_shift(ctx);
		if (pfn > get_max_pfn(ctx))
			set_max_pfn(ctx, pfn);

		if (ctx->shared->arch_ops && ctx->shared->arch_ops->process_load) {
			ret = ctx->shared->arch_ops->process_load(
				ctx, seg->virt, seg->phys);
			if (ret != kdump_ok)
				return ret;
		}
	}

	for (i = 0; i < edp->num_sections; ++i) {
		struct section *sect = edp->sections + i;
		const char *name = strtab_entry(edp, sect->name_index);
		if (!strcmp(name, ".xen_pages"))
			edp->xen_pages_offset = sect->file_offset;
		else if (!strcmp(name, ".xen_p2m")) {
			ctx->shared->xen_map = read_elf_sect(ctx, sect);
			if (!ctx->shared->xen_map)
				return kdump_syserr;
			ctx->shared->xen_map_size = sect->size /sizeof(struct xen_p2m);
			set_xen_xlat(ctx, kdump_xen_nonauto);
			get_max_pfn_xen_nonauto(ctx);
		} else if (!strcmp(name, ".xen_pfn")) {
			ctx->shared->xen_map = read_elf_sect(ctx, sect);
			if (!ctx->shared->xen_map)
				return kdump_syserr;
			ctx->shared->xen_map_size = sect->size / sizeof(uint64_t);
			set_xen_xlat(ctx, kdump_xen_auto);
			get_max_pfn_xen_auto(ctx);
		} else if (!strcmp(name, ".note.Xen")) {
			notes = read_elf_sect(ctx, sect);
			if (!notes)
				return kdump_syserr;
			ret = process_notes(ctx, notes, sect->size);
			free(notes);
			if (ret != kdump_ok)
				return set_error(ctx, ret,
						 "Cannot process Xen notes");
		} else if (!strcmp(name, ".xen_prstatus")) {
			void *data = read_elf_sect(ctx, sect);
			if (!data)
				return kdump_syserr;
			ret = ctx->shared->arch_ops->process_xen_prstatus(
				ctx, data, sect->size);
			free(data);
			if (ret != kdump_ok)
				return set_error(ctx, ret,
						 "Cannot process Xen prstatus");
		}
	}

	if (edp->xen_pages_offset) {
		set_xen_type(ctx, kdump_xen_domain);
		if (!ctx->shared->xen_map)
			return set_error(ctx, kdump_unsupported,
					 "Missing Xen P2M mapping");
		ctx->shared->ops = &xc_core_elf_ops;
	}

	return kdump_ok;
}

static kdump_status
elf_probe(kdump_ctx *ctx, void *hdr)
{
	unsigned char *eheader = hdr;
	Elf32_Ehdr *elf32 = hdr;
	Elf64_Ehdr *elf64 = hdr;
	struct elfdump_priv *edp;
	kdump_status ret;

	if (memcmp(eheader, ELFMAG, SELFMAG))
		return set_error(ctx, kdump_noprobe,
				 "Invalid ELF signature");

	edp = calloc(1, sizeof *edp);
	if (!edp)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate ELF dump private data");
	ctx->shared->fmtdata = edp;

	switch (eheader[EI_DATA]) {
	case ELFDATA2LSB:
		set_byte_order(ctx, kdump_little_endian);
		break;
	case ELFDATA2MSB:
		set_byte_order(ctx, kdump_big_endian);
		break;
	default:
		return set_error(ctx, kdump_unsupported,
				 "Unsupported ELF data format: %u",
				 eheader[EI_DATA]);
	}

        if ((elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
	    (dump16toh(ctx, elf32->e_type) == ET_CORE) &&
	    (dump32toh(ctx, elf32->e_version) == EV_CURRENT)) {
		edp->elfclass = ELFCLASS32;
		set_format_longname(ctx, "ELF32 dump");
		ret = init_elf32(ctx, elf32);
		if (ret == kdump_ok)
			ret = open_common(ctx);
	} else if ((elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
		   (dump16toh(ctx, elf64->e_type) == ET_CORE) &&
		   (dump32toh(ctx, elf64->e_version) == EV_CURRENT)) {
		edp->elfclass = ELFCLASS64;
		set_format_longname(ctx, "ELF64 dump");
		ret = init_elf64(ctx, elf64);
		if (ret == kdump_ok)
			ret = open_common(ctx);
	} else
		ret = set_error(ctx, kdump_unsupported,
				"Unsupported ELF class: %u",
				elf32->e_ident[EI_CLASS]);

	if (ret != kdump_ok)
		elf_cleanup(ctx->shared);

	return ret;
}

static void
elf_cleanup(struct kdump_shared *shared)
{
	struct elfdump_priv *edp = shared->fmtdata;

	if (edp) {
		if (edp->load_segments)
			free(edp->load_segments);
		if (edp->sections)
			free(edp->sections);
		if (edp->strtab)
			free(edp->strtab);
		free(edp);
		shared->fmtdata = NULL;
	}
};

const struct format_ops elfdump_ops = {
	.name = "elf",
	.probe = elf_probe,
	.read_page = elf_read_page,
	.unref_page = cache_unref_page,
	.realloc_caches = def_realloc_caches,
	.cleanup = elf_cleanup,
};

static const struct format_ops xc_core_elf_ops = {
	.name = "xc_core_elf",
	.read_page = xc_read_page,
	.read_kpage = xc_read_kpage,
	.unref_page = cache_unref_page,
	.mfn_to_pfn = xc_mfn_to_pfn,
	.realloc_caches = def_realloc_caches,
	.cleanup = elf_cleanup,
};
