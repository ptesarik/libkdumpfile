/** @internal @file src/kdumpfile/s390x.c
 * @brief Functions for the s390x architecture.
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
#include <elf.h>

/** @cond TARGET_ABI */

#define PAGE_SHIFT	12
#define PAGE_SIZE	((uint64_t)1 << PAGE_SHIFT)

/* Well-known lowcore addresses */
#define LC_VMCORE_INFO	0x0e0c
#define LC_OS_INFO	0x0e18

#define OS_INFO_MAGIC	0x4f53494e464f535aULL

#define OS_INFO_VMCOREINFO	0
#define OS_INFO_REIPL_BLOCK	1

struct os_info_entry {
        uint64_t addr;
	uint64_t size;
        uint32_t csum;
} __attribute__ ((packed));

struct os_info {
	uint64_t magic;
	uint32_t csum;
	uint16_t version_major;
	uint16_t version_minor;
	uint64_t crashkernel_addr;
	uint64_t crashkernel_size;
	struct os_info_entry entry[2];
	/* possibly more fields up to PAGE_SIZE */
} __attribute__ ((packed));

/** @endcond */

static kdump_status
read_os_info_from_lowcore(kdump_ctx_t *ctx)
{
	unsigned char os_info_buf[PAGE_SIZE];
	struct os_info *os_info;
	size_t sz;
	uint64_t addr;
	uint64_t magic;
	uint32_t csum, csum_expect;
	void *vmcoreinfo;
	kdump_status ret;

	sz = sizeof(addr);
	ret = read_locked(ctx, KDUMP_KPHYSADDR, LC_OS_INFO, &addr, &sz);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret, "Cannot read LC_OS_INFO pointer");
	addr = dump64toh(ctx, addr);
	if (!addr)
		return set_error(ctx, KDUMP_ERR_NODATA,
				 "NULL os_info pointer");
	if (addr % PAGE_SIZE != 0)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid os_info pointer: 0x%llx",
				 (unsigned long long) addr);

	sz = PAGE_SIZE;
	ret = read_locked(ctx, KDUMP_KPHYSADDR, addr, os_info_buf, &sz);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret, "Cannot read os_info");
	os_info = (struct os_info*) os_info_buf;

	magic = dump64toh(ctx, os_info->magic);
	if (magic != OS_INFO_MAGIC)
		return set_error(ctx, KDUMP_ERR_NODATA,
				 "Invalid os_info magic: 0x%llx",
				 (unsigned long long) magic);

	sz = PAGE_SIZE - offsetof(struct os_info, version_major);
	csum = cksum32(&os_info->version_major, sz, 0);
	csum_expect = dump32toh(ctx, os_info->csum);
	if (csum != csum_expect)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid os_info checksum: 0x%lx != 0x%lx",
				 (unsigned long) csum,
				 (unsigned long) csum_expect);

	sz = dump64toh(ctx, os_info->entry[OS_INFO_VMCOREINFO].size);
	addr = dump64toh(ctx, os_info->entry[OS_INFO_VMCOREINFO].addr);
	if (!sz || !addr)
		return set_error(ctx, KDUMP_ERR_NODATA,
				 "No VMCOREINFO found in os_info");

	vmcoreinfo = ctx_malloc(sz, ctx, "VMCOREINFO buffer");
	if (!vmcoreinfo)
		return KDUMP_ERR_SYSTEM;

	ret = read_locked(ctx, KDUMP_KPHYSADDR, addr, vmcoreinfo, &sz);
	if (ret != KDUMP_OK) {
		free(vmcoreinfo);
		return set_error(ctx, ret, "Cannot read VMCOREINFO");
	}

	csum = cksum32(vmcoreinfo, sz, 0);
	csum_expect = dump32toh(ctx, os_info->entry[OS_INFO_VMCOREINFO].csum);
	if (csum != csum_expect) {
		free(vmcoreinfo);
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid VMCOREINFO checksum: 0x%lx != 0x%lx",
				 (unsigned long) csum,
				 (unsigned long) csum_expect);
	}

	ret = set_attr_sized_string(ctx, gattr(ctx, GKI_linux_vmcoreinfo_raw),
				    ATTR_DEFAULT, vmcoreinfo, sz);
	free(vmcoreinfo);
	if (ret != KDUMP_OK)
		return set_error(ctx, ret, "Cannot set VMCOREINFO");

	return KDUMP_OK;
}

static kdump_status
read_vmcoreinfo_from_lowcore(kdump_ctx_t *ctx)
{
	uint64_t addr;
	Elf64_Nhdr hdr;
	void *note;
	size_t sz, notesz, descoff;
	kdump_status ret;

	sz = sizeof(addr);
	ret = read_locked(ctx, KDUMP_KPHYSADDR, LC_VMCORE_INFO, &addr, &sz);
	if (ret != KDUMP_OK)
		return ret;
	addr = dump64toh(ctx, addr);
	if (!addr)
		return set_error(ctx, KDUMP_ERR_NODATA,
				 "NULL VMCOREINFO pointer");

	sz = sizeof(hdr);
	ret = read_locked(ctx, KDUMP_KPHYSADDR, addr, &hdr, &sz);
	if (ret != KDUMP_OK)
		return ret;
	hdr.n_namesz = dump32toh(ctx, hdr.n_namesz);
	hdr.n_descsz = dump32toh(ctx, hdr.n_descsz);
	hdr.n_type = dump32toh(ctx, hdr.n_type);

	descoff = sizeof(Elf64_Nhdr) + ((hdr.n_namesz + 3) & ~3);
	notesz = descoff + hdr.n_descsz;
	note = ctx_malloc(notesz, ctx, "VMCOREINFO buffer");
	if (!note)
		return KDUMP_ERR_SYSTEM;

	sz = notesz;
	ret = read_locked(ctx, KDUMP_KPHYSADDR, addr, note, &sz);
	if (ret == KDUMP_OK &&
	    !memcmp(note + sizeof(Elf64_Nhdr), "VMCOREINFO", hdr.n_namesz))
		ret = process_notes(ctx, note, notesz);

	free(note);
	return ret;
}

static kdump_status
process_lowcore_info(kdump_ctx_t *ctx)
{
	kdump_status ret;

	ret = read_os_info_from_lowcore(ctx);
	if (ret == KDUMP_ERR_NODATA) {
		clear_error(ctx);
		ret = read_vmcoreinfo_from_lowcore(ctx);
	}
	return ret;
}

static kdump_status
s390x_init(kdump_ctx_t *ctx)
{
	process_lowcore_info(ctx);
	clear_error(ctx);

	return KDUMP_OK;
}

const struct arch_ops s390x_ops = {
	.init = s390x_init,
};
