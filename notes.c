/* Routines for parsing ELF notes.
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
#include <string.h>
#include <elf.h>

#include "kdumpfile-priv.h"

/* System information exported through crash notes. */
#define XEN_ELFNOTE_CRASH_INFO 0x1000001

/* .Xen.note types */
#define XEN_ELFNOTE_DUMPCORE_NONE            0x2000000
#define XEN_ELFNOTE_DUMPCORE_HEADER          0x2000001
#define XEN_ELFNOTE_DUMPCORE_XEN_VERSION     0x2000002
#define XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION  0x2000003

struct xen_elfnote_header {
	uint64_t xch_magic;
	uint64_t xch_nr_vcpus;
	uint64_t xch_nr_pages;
	uint64_t xch_page_size;
}; 

struct xen_crash_info_32 {
	uint32_t xen_major_version;
	uint32_t xen_minor_version;
	uint32_t xen_extra_version;
	uint32_t xen_changeset;
	uint32_t xen_compiler;
	uint32_t xen_compile_date;
	uint32_t xen_compile_time;
	uint32_t tainted;
	/* Additional arch-dependent and version-dependent fields  */
};

struct xen_crash_info_64 {
	uint64_t xen_major_version;
	uint64_t xen_minor_version;
	uint64_t xen_extra_version;
	uint64_t xen_changeset;
	uint64_t xen_compiler;
	uint64_t xen_compile_date;
	uint64_t xen_compile_time;
	uint64_t tainted;
	/* Additional arch-dependent and version-dependent fields  */
};

static void
process_xen_crash_info(kdump_ctx *ctx, void *data, size_t len)
{
	struct elfdump_priv *edp = ctx->fmtdata;
	unsigned words = len / ctx->ptr_size;

	if (ctx->ptr_size == 8 &&
	    len >= sizeof(struct xen_crash_info_64)) {
		struct xen_crash_info_64 *info = data;
		ctx->xen_ver.major = dump64toh(ctx, info->xen_major_version);
		ctx->xen_ver.minor = dump64toh(ctx, info->xen_minor_version);
		ctx->xen_extra_ver = dump64toh(ctx, info->xen_extra_version);
		ctx->xen_p2m_mfn = dump64toh(ctx, ((uint64_t*)data)[words-1]);
	} else if (ctx->ptr_size == 4 &&
		   len >= sizeof(struct xen_crash_info_32)){
		struct xen_crash_info_32 *info = data;
		ctx->xen_ver.major = dump32toh(ctx, info->xen_major_version);
		ctx->xen_ver.minor = dump32toh(ctx, info->xen_minor_version);
		ctx->xen_extra_ver = dump32toh(ctx, info->xen_extra_version);
		ctx->xen_p2m_mfn = dump32toh(ctx, ((uint32_t*)data)[words-1]);
	}
}

static void
process_xen_note(kdump_ctx *ctx, uint32_t type,
		 void *desc, size_t descsz)
{
	if (type == XEN_ELFNOTE_CRASH_INFO)
		process_xen_crash_info(ctx, desc, descsz);

	ctx->flags |= DIF_XEN;
}

static kdump_status
process_xc_xen_note(kdump_ctx *ctx, uint32_t type,
		    void *desc, size_t descsz)
{
	if (type == XEN_ELFNOTE_DUMPCORE_HEADER) {
		struct xen_elfnote_header *header = desc;
		uint64_t page_size = dump64toh(ctx, header->xch_page_size);

		/* It must be a power of 2 */
		if (page_size != (page_size & ~(page_size - 1)))
			return kdump_dataerr;

		ctx->page_size = page_size;
	} else if (type == XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION) {
		uint64_t version = dump64toh(ctx, *(uint64_t*)desc);

		if (version != 1)
			return kdump_unsupported;
	}

	return kdump_ok;
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
			    !strncmp(p, "PAGESIZE", namesz)) {
				unsigned long page_size;
				sscanf(eq, "%ul", &page_size);
				ctx->page_size = page_size;
			} else if (namesz == sizeof("OSRELEASE") - 1 &&
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

kdump_status
kdump_process_notes(kdump_ctx *ctx, void *data, size_t size)
{
	Elf32_Nhdr *hdr = data;
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
			ret = process_xc_xen_note(ctx, type, desc, descsz);
		else if (note_equal("VMCOREINFO", name, namesz)) {
			process_vmcoreinfo(ctx, desc, descsz);
			ret = kdump_store_vmcoreinfo(&ctx->vmcoreinfo,
						     desc, descsz);
		} else if (note_equal("VMCOREINFO_XEN", name, namesz))
			ret = kdump_store_vmcoreinfo(&ctx->vmcoreinfo_xen,
						     desc, descsz);
	}

	return ret;
}
