/* Routines to ELF kdump files.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <elf.h>

#include "kdumpfile-priv.h"

/* System information exported through crash notes. */
#define XEN_ELFNOTE_CRASH_INFO 0x1000001

/* .Xen.note types */
#define XEN_ELFNOTE_DUMPCORE_NONE            0x2000000
#define XEN_ELFNOTE_DUMPCORE_HEADER          0x2000001
#define XEN_ELFNOTE_DUMPCORE_XEN_VERSION     0x2000002
#define XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION  0x2000003

static const struct kdump_ops xen_dom0_ops;
static const struct kdump_ops xen_domU_ops;

struct xen_p2m {
	uint64_t pfn;
	uint64_t gmfn; 
};

struct xen_elfnote_header {
	uint64_t xch_magic;
	uint64_t xch_nr_vcpus;
	uint64_t xch_nr_pages;
	uint64_t xch_page_size;
}; 

struct load_segment {
	off_t file_offset;
	uint64_t phys_start;
	uint64_t phys_end;
};

struct section {
	off_t file_offset;
	uint64_t size;
	int name_index;
};

struct elfdump_priv {
	size_t ptr_size;	/* arch pointer size */

	int num_load_segments;
	struct load_segment *load_segments;
	int num_note_segments;
	struct load_segment *note_segments;

	int num_sections;
	struct section *sections;

	size_t strtab_size;
	char *strtab;

	off_t xen_pages_offset;
	void *xen_map;
	unsigned long xen_map_size;
	enum {
		xen_map_pfn,
		xen_map_p2m,
	} xen_map_type;
	unsigned long xen_p2m_mfn;
};

static enum kdump_arch
mach2arch(unsigned mach)
{
	switch(mach) {
	case EM_ARM:	return ARCH_ARM;
	case EM_ALPHA:
	case EM_FAKE_ALPHA:
			return ARCH_ALPHA;
	case EM_IA_64:	return ARCH_IA64;
	case EM_PPC:	return ARCH_PPC;
	case EM_PPC64:	return ARCH_PPC64;
	case EM_S390:	return ARCH_S390;
	case EM_386:	return ARCH_X86;
	case EM_X86_64:	return ARCH_X86_64;
	default:	return ARCH_UNKNOWN;
	}
}

static void
cleanup(struct elfdump_priv *edp)
{
	if (edp->load_segments)
		free(edp->load_segments);
	if (edp->sections)
		free(edp->sections);
	if (edp->strtab)
		free(edp->strtab);
}

static void
set_page_size(kdump_ctx *ctx)
{
	static const int arch_page_shifts[] = {
		[ARCH_ALPHA]= 13,
		[ARCH_ARM] = 12,
		[ARCH_IA64] = 0,
		[ARCH_PPC] = 0,
		[ARCH_PPC64] = 0,
		[ARCH_S390] = 12,
		[ARCH_S390X] = 12,
		[ARCH_X86] = 12,
		[ARCH_X86_64] = 12,
	};

	if (!ctx->page_size) {
		int shift = arch_page_shifts[ctx->arch];
		ctx->page_size = 1 << shift;
	}
}

static kdump_status
elf_read_page(kdump_ctx *ctx, kdump_paddr_t pfn)
{
	struct elfdump_priv *edp = ctx->fmtdata;
	uint64_t addr = pfn * ctx->page_size;
	off_t pos;

	if (edp->num_load_segments == 1) {
		pos = (off_t)addr + (off_t)edp->load_segments[0].file_offset;
	} else {
		struct load_segment *pls;
		int i;
		for (i = 0; i < edp->num_load_segments; i++) {
			pls = &edp->load_segments[i];
			if ((addr >= pls->phys_start) &&
			    (addr < pls->phys_end)) {
				pos = (off_t)(addr - pls->phys_start) +
					pls->file_offset;
				break;
			}
		}
		if (i >= edp->num_load_segments) 
	                return kdump_nodata;
	}

	/* read page data */
	if (pread(ctx->fd, ctx->page, ctx->page_size, pos) != ctx->page_size)
		return kdump_syserr;

	return kdump_ok;
}

static kdump_status
elf_read_xen_dom0(kdump_ctx *ctx, kdump_paddr_t pfn)
{
	struct elfdump_priv *edp = ctx->fmtdata;
	unsigned fpp = ctx->page_size / edp->ptr_size;
	uint64_t mfn_idx, frame_idx;
	kdump_status ret;

	mfn_idx = pfn / fpp;
	frame_idx = pfn % fpp;
	if (mfn_idx >= edp->xen_map_size)
		return kdump_nodata;

	pfn = (edp->ptr_size == 8)
		? ((uint64_t*)edp->xen_map)[mfn_idx]
		: ((uint32_t*)edp->xen_map)[mfn_idx];
	ret = elf_read_page(ctx, pfn);
	if (ret != kdump_ok)
		return ret;

	pfn = (edp->ptr_size == 8)
		? ((uint64_t*)ctx->page)[frame_idx]
		: ((uint32_t*)ctx->page)[frame_idx];
	return elf_read_page(ctx, pfn);
}

static unsigned long
pfn_to_mfn(struct elfdump_priv *edp, unsigned long pfn)
{
	unsigned long i;

	if (edp->xen_map_type == xen_map_pfn) {
		uint64_t *p = edp->xen_map;
		for (i = 0; i < edp->xen_map_size; ++i, ++p)
			if (*p == pfn)
				return i;
	} else if (edp->xen_map_type == xen_map_p2m) {
		struct xen_p2m *p = edp->xen_map;
		for (i = 0; i < edp->xen_map_size; ++i, ++p)
			if (p->pfn == pfn)
				return i;
	}

	return ~0UL;
}

static kdump_status
elf_read_xen_domU(kdump_ctx *ctx, unsigned long pfn)
{
	struct elfdump_priv *edp = ctx->fmtdata;
        unsigned long mfn;
	off_t offset;

	if ((mfn = pfn_to_mfn(edp, pfn)) == ~0UL)
		return kdump_nodata;

	offset = edp->xen_pages_offset + (off_t)mfn * ctx->page_size;
	if (pread(ctx->fd, ctx->page, ctx->page_size, offset) != ctx->page_size)
		return kdump_syserr;

	return 0;
}

static kdump_status
init_segments(struct elfdump_priv *edp, unsigned phnum)
{
	if (!phnum)
		return kdump_ok;

	edp->load_segments = malloc(2 * phnum * sizeof(struct load_segment));
	if (!edp->load_segments)
		return kdump_syserr;
	edp->num_load_segments = 0;

	edp->note_segments = edp->load_segments + phnum;
	edp->num_note_segments = 0;
	return kdump_ok;
}

static kdump_status
init_sections(struct elfdump_priv *edp, unsigned snum)
{
	if (!snum)
		return kdump_ok;

	edp->sections = malloc(snum * sizeof(struct section));
	if (!edp->sections)
		return kdump_syserr;
	edp->num_sections = 0;
	return kdump_ok;
}

static void
store_phdr(struct elfdump_priv *edp, unsigned type,
	   off_t offset, uint64_t addr, uint64_t size)
{
	struct load_segment *pls;

	if (type == PT_LOAD) {
		pls = edp->load_segments + edp->num_load_segments;
		++edp->num_load_segments;
	} else if (type == PT_NOTE) {
		pls = edp->note_segments + edp->num_note_segments;
		++edp->num_note_segments;
	} else
		return;

	pls->file_offset = offset;
	pls->phys_start = addr;
	pls->phys_end = addr + size;
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
read_elf_seg(kdump_ctx *ctx, struct load_segment *seg)
{
	size_t size = seg->phys_end - seg->phys_start;
	void *buf = malloc(size);
	if (!buf)
		return NULL;

	if (pread(ctx->fd, buf, size, seg->file_offset) == size)
		return buf;

	free(buf);
	return NULL;
}

static void *
read_elf_sect(kdump_ctx *ctx, struct section *sect)
{
	void *buf;

	buf = malloc(sect->size);
	if (!buf)
		return NULL;

	if (pread(ctx->fd, buf, sect->size, sect->file_offset) == sect->size)
		return buf;

	free(buf);
	return NULL;
}

static kdump_status
init_strtab(kdump_ctx *ctx, unsigned strtabidx)
{
	struct elfdump_priv *edp = ctx->fmtdata;
	struct section *ps;

	if (!strtabidx || strtabidx >= edp->num_sections)
		return kdump_ok;	/* no string table */

	ps = edp->sections + strtabidx;
	edp->strtab_size = ps->size;
	edp->strtab = read_elf_sect(ctx, ps);
	if (!edp->strtab)
		return kdump_syserr;

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
	struct elfdump_priv *edp = ctx->fmtdata;
	Elf32_Phdr prog;
	Elf32_Shdr sect;
	kdump_status ret;
	int i;

	ctx->arch = mach2arch(dump16toh(ctx, ehdr->e_machine));

	ret = init_segments(edp, dump16toh(ctx, ehdr->e_phnum));
	if (ret != kdump_ok)
		return ret;

	ret = init_sections(edp, dump16toh(ctx, ehdr->e_shnum));
	if (ret != kdump_ok)
		return ret;

	if (lseek(ctx->fd, dump32toh(ctx, ehdr->e_phoff), SEEK_SET) < 0)
		return kdump_syserr;
	for (i = 0; i < dump16toh(ctx, ehdr->e_phnum); ++i) {
		if (read(ctx->fd, &prog, sizeof prog) != sizeof prog)
			return kdump_syserr;
		store_phdr(edp,
			   dump32toh(ctx, prog.p_type),
			   dump32toh(ctx, prog.p_offset),
			   dump32toh(ctx, prog.p_paddr),
			   dump32toh(ctx, prog.p_filesz));
	}

	if (lseek(ctx->fd, dump32toh(ctx, ehdr->e_shoff), SEEK_SET) < 0)
		return kdump_syserr;
	for (i = 0; i < dump16toh(ctx, ehdr->e_shnum); ++i) {
		if (read(ctx->fd, &sect, sizeof sect) != sizeof sect)
			return kdump_syserr;
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
	struct elfdump_priv *edp = ctx->fmtdata;
	Elf64_Phdr prog;
	Elf64_Shdr sect;
	kdump_status ret;
	int i;

	ctx->arch = mach2arch(dump16toh(ctx, ehdr->e_machine));

	ret = init_segments(edp, dump16toh(ctx, ehdr->e_phnum));
	if (ret != kdump_ok)
		return ret;

	ret = init_sections(edp, dump16toh(ctx, ehdr->e_shnum));
	if (ret != kdump_ok)
		return ret;


	if (lseek(ctx->fd, dump64toh(ctx, ehdr->e_phoff), SEEK_SET) < 0)
		return kdump_syserr;
	for (i = 0; i < dump16toh(ctx, ehdr->e_phnum); ++i) {
		if (read(ctx->fd, &prog, sizeof prog) != sizeof prog)
			return kdump_syserr;
		store_phdr(edp,
			   dump32toh(ctx, prog.p_type),
			   dump64toh(ctx, prog.p_offset),
			   dump64toh(ctx, prog.p_paddr),
			   dump64toh(ctx, prog.p_filesz));
	}

	if (lseek(ctx->fd, dump32toh(ctx, ehdr->e_shoff), SEEK_SET) < 0)
		return kdump_syserr;
	for (i = 0; i < dump16toh(ctx, ehdr->e_shnum); ++i) {
		if (read(ctx->fd, &sect, sizeof sect) != sizeof sect)
			return kdump_syserr;
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

static void
process_xen_note(kdump_ctx *ctx, uint32_t type,
		 void *desc, size_t descsz)
{
	struct elfdump_priv *edp = ctx->fmtdata;
	unsigned words = descsz / edp->ptr_size;

	if (type == XEN_ELFNOTE_CRASH_INFO) {
		edp->xen_p2m_mfn = (edp->ptr_size == 8)
			? dump64toh(ctx, ((uint64_t*)desc)[words-1])
			: dump32toh(ctx, ((uint32_t*)desc)[words-1]);
	}

	ctx->flags |= DIF_XEN;
}

static void
process_xc_xen_note(kdump_ctx *ctx, uint32_t type,
		    void *desc, size_t descsz)
{
	if (type == XEN_ELFNOTE_DUMPCORE_HEADER) {
		struct xen_elfnote_header *header = desc;
		ctx->page_size = dump64toh(ctx, header->xch_page_size);
	} else if (type == XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION) {
		uint64_t version = dump64toh(ctx, *(uint64_t*)desc);

		/* TODO: check that version == 1 */
	}
}

static void
process_vmcoreinfo(kdump_ctx *ctx, void *desc, size_t descsz)
{
	char *p = desc;

	while (descsz) {
		char *eol, *eq;

		if (! (eol = memchr(p, '\n', descsz)) )
			eol = p + descsz;
		descsz -= eol - p;

		if ( (eq = memchr(p, '=', eol - p)) ) {
			size_t namesz = eq - p;

			++eq;
			if (namesz == sizeof("PAGESIZE") - 1 &&
			    !strncmp(p, "PAGESIZE", namesz))
				sscanf(eq, "%zd", &ctx->page_size);
			else if (namesz == sizeof("OSRELEASE") - 1 &&
				 !strncmp(p, "OSRELEASE", namesz)) {
				size_t valsz = eol - eq;
				if (valsz > NEW_UTS_LEN)
					valsz = NEW_UTS_LEN;
				memcpy(&ctx->utsname.release, eq, valsz);
				ctx->utsname.release[NEW_UTS_LEN] = 0;
			}
		}

		p = eol;
		while (descsz && *p == '\n')
			++p, --descsz;
	}
}

static int
note_equal(const char *name, const char *notename, size_t notenamesz)
{
	size_t namelen = strlen(name);
	if (notenamesz >= namelen && notenamesz <= namelen + 1)
		return !memcmp(name, notename, notenamesz);
	return 0;
}

static kdump_status
process_notes(kdump_ctx *ctx, Elf32_Nhdr *hdr, size_t size)
{
	kdump_status ret = kdump_ok;

	while (ret == kdump_ok && size >= sizeof(Elf32_Nhdr)) {
		char *name, *desc;
		Elf32_Word namesz = dump32toh(ctx, hdr->n_namesz);
		Elf32_Word descsz = dump32toh(ctx, hdr->n_descsz);
		Elf32_Word type = dump32toh(ctx, hdr->n_type);
		size_t descoff = sizeof(Elf32_Nhdr) + ((namesz + 3) & ~3);

		if (size < descoff + ((descsz + 3) & ~3))
			break;
		size -= descoff + ((descsz + 3) & ~3);

		name = (char*) (hdr + 1);
		desc = (char*)hdr + descoff;
		hdr = (Elf32_Nhdr*) (desc + ((descsz + 3) & ~3));

		if (note_equal("Xen", name, namesz))
			process_xen_note(ctx, type, desc, descsz);
		else if (note_equal(".note.Xen", name, namesz))
			process_xc_xen_note(ctx, type, desc, descsz);
		else if (note_equal("VMCOREINFO", name, namesz)) {
			process_vmcoreinfo(ctx, desc, descsz);
			ret = kdump_store_vmcoreinfo(ctx, desc, descsz);
		} else if (note_equal("VMCOREINFO_XEN", name, namesz))
			ret = kdump_store_vmcoreinfo_xen(ctx, desc, descsz);
	}

	return ret;
}

static kdump_status
initialize_xen_map64(kdump_ctx *ctx, void *dir)
{
	struct elfdump_priv *edp = ctx->fmtdata;
	unsigned fpp = ctx->page_size / edp->ptr_size;
	uint64_t *dirp, *p, *map;
	uint64_t pfn;
	unsigned mfns;
	kdump_status ret;

	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < ctx->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		ret = elf_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			return kdump_dataerr;
		else if (ret != kdump_ok)
			return ret;

		for (p = ctx->page; (void*)p < ctx->page + ctx->page_size; ++p)
			if (*p)
				++mfns;
	}

	if (! (map = malloc(mfns * sizeof(uint64_t))) )
		return kdump_syserr;
	edp->xen_map = map;
	edp->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		ret = elf_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			return kdump_dataerr;
		else if (ret != kdump_ok)
			return ret;

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
	struct elfdump_priv *edp = ctx->fmtdata;
	unsigned fpp = ctx->page_size / edp->ptr_size;
	uint32_t *dirp, *p, *map;
	uint32_t pfn;
	unsigned mfns;
	kdump_status ret;

	mfns = 0;
	for (dirp = dir, pfn = 0; *dirp && pfn < ctx->max_pfn;
	     ++dirp, pfn += fpp * fpp) {
		ret = elf_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			return kdump_dataerr;
		else if (ret != kdump_ok)
			return ret;

		for (p = ctx->page; (void*)p < ctx->page + ctx->page_size; ++p)
			if (*p)
				++mfns;
	}

	if (! (map = malloc(mfns * sizeof(uint32_t))) )
		return kdump_syserr;
	edp->xen_map = map;
	edp->xen_map_size = mfns;

	for (dirp = dir; mfns; ++dirp) {
		ret = elf_read_page(ctx, *dirp);
		if (ret == kdump_nodata)
			return kdump_dataerr;
		else if (ret != kdump_ok)
			return ret;

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
	struct elfdump_priv *edp = ctx->fmtdata;
	void *dir;
	kdump_status ret;

	if ( (dir = malloc(ctx->page_size)) == NULL) {
		ret = kdump_syserr;
		goto done;
	}
	ctx->page = dir;

	ret = elf_read_page(ctx, edp->xen_p2m_mfn);
	if (ret != kdump_ok)
		goto free_dir;

	if ( (ctx->page = malloc(ctx->page_size)) == NULL) {
		ret = kdump_syserr;
		goto free_dir;
	}

	ret = (edp->ptr_size == 8)
		? initialize_xen_map64(ctx, dir)
		: initialize_xen_map32(ctx, dir);

	if (ret == kdump_ok)
		ctx->ops = &xen_dom0_ops;

	free(ctx->page);
 free_dir:
	free(dir);
 done:
	return ret;
}

static kdump_status
open_common(kdump_ctx *ctx)
{
	struct elfdump_priv *edp = ctx->fmtdata;
	kdump_status ret;
	int i;

	if (!edp->num_load_segments && !edp->num_sections)
		return kdump_unsupported;

	edp->ptr_size = kdump_arch_ptr_size(ctx->arch);

	/* read notes */
	for (i = 0; i < edp->num_note_segments; ++i) {
		struct load_segment *seg = edp->note_segments + i;
		Elf32_Nhdr *hdr = read_elf_seg(ctx, seg);
		if (!hdr)
			return kdump_syserr;
		ret = process_notes(ctx, hdr, seg->phys_end - seg->phys_start);
		free(hdr);
		if (ret != kdump_ok)
			return ret;
	}

	set_page_size(ctx);

	/* get max PFN */
	for (i = 0; i < edp->num_load_segments; ++i) {
		unsigned long pfn =
			edp->load_segments[i].phys_end / ctx->page_size;
		if (pfn > ctx->max_pfn)
			ctx->max_pfn = pfn;
	}

	for (i = 0; i < edp->num_sections; ++i) {
		struct section *sect = edp->sections + i;
		const char *name = strtab_entry(edp, sect->name_index);
		if (!strcmp(name, ".xen_pages"))
			edp->xen_pages_offset = sect->file_offset;
		else if (!strcmp(name, ".xen_p2m")) {
			edp->xen_map = read_elf_sect(ctx, sect);
			if (!edp->xen_map)
				return kdump_syserr;
			edp->xen_map_type = xen_map_p2m;
			edp->xen_map_size = sect->size /sizeof(struct xen_p2m);
		} else if (!strcmp(name, ".xen_pfn")) {
			edp->xen_map = read_elf_sect(ctx, sect);
			if (!edp->xen_map)
				return kdump_syserr;
			edp->xen_map_type = xen_map_pfn;
			edp->xen_map_size = sect->size / sizeof(uint64_t);
		}
	}

	if (edp->xen_p2m_mfn) {
		ret = initialize_xen_map(ctx);
		if (ret != kdump_ok)
			return ret;
	}

	if (edp->xen_pages_offset) {
		if (!edp->xen_map)
			return kdump_unsupported;
		ctx->flags |= DIF_XEN;
		ctx->ops = &xen_domU_ops;
	}

	return kdump_ok;
}

static kdump_status
elf_probe(kdump_ctx *ctx)
{
	unsigned char *eheader = ctx->buffer;
	Elf32_Ehdr *elf32 = ctx->buffer;
	Elf64_Ehdr *elf64 = ctx->buffer;
	struct elfdump_priv *edp;
	kdump_status ret;

	if (memcmp(eheader, ELFMAG, SELFMAG))
		return kdump_unsupported;

	edp = calloc(1, sizeof *edp);
	if (!edp)
		return kdump_syserr;
	ctx->fmtdata = edp;

	switch (eheader[EI_DATA]) {
	case ELFDATA2LSB: ctx->endian = __LITTLE_ENDIAN; break;
	case ELFDATA2MSB: ctx->endian = __BIG_ENDIAN; break;
	default:
		return kdump_unsupported;
	}

        if ((elf32->e_ident[EI_CLASS] == ELFCLASS32) &&
	    (dump16toh(ctx, elf32->e_type) == ET_CORE) &&
	    (dump32toh(ctx, elf32->e_version) == EV_CURRENT)) {
		ctx->format = "ELF dump, 32-bit";
		ret = init_elf32(ctx, elf32);
		if (ret == kdump_ok)
			ret = open_common(ctx);
	} else if ((elf64->e_ident[EI_CLASS] == ELFCLASS64) &&
		   (dump16toh(ctx, elf64->e_type) == ET_CORE) &&
		   (dump32toh(ctx, elf64->e_version) == EV_CURRENT)) {
		ctx->format = "ELF dump, 64-bit";
		ret = init_elf64(ctx, elf64);
		if (ret == kdump_ok)
			ret = open_common(ctx);
	} else
		return kdump_unsupported;

	if (ret != kdump_ok) {
		cleanup(edp);
		free(edp);
	}

	return ret;
}

static void
elf_free(kdump_ctx *ctx)
{
	struct elfdump_priv *edp = ctx->fmtdata;

	cleanup(edp);
	free(edp);
	ctx->fmtdata = NULL;
};

const struct kdump_ops kdump_elfdump_ops = {
	.probe = elf_probe,
	.read_page = elf_read_page,
	.free = elf_free,
};

static const struct kdump_ops xen_dom0_ops = {
	.read_page = elf_read_xen_dom0,
	.free = elf_free,
};

static const struct kdump_ops xen_domU_ops = {
	.read_page = elf_read_xen_domU,
	.free = elf_free,
};
