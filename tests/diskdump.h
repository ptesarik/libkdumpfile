/* DISKDUMP/KDUMP format definitions.
   Copyright (C) 2016 Petr Tesarik <ptesarik@suse.cz>

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

#ifndef _DISKDUMP_H
#define _DISKDUMP_H 1

#include <stdint.h>

#define MDF_SIGNATURE		"makedumpfile"
#define MDF_SIG_LEN		16
#define MDF_TYPE_FLAT_HEADER	1
#define MDF_VERSION_FLAT_HEADER	1
#define MDF_HEADER_SIZE		4096

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

#define MDF_OFFSET_END_FLAG	(-(int64_t)1)

#define DISKDUMP_SIGNATURE		"DISKDUMP"
#define KDUMP_SIGNATURE			"KDUMP   "
#define SIGNATURE_LEN			8
#define DISKDUMP_HEADER_BLOCKS		1

#define DUMP_HEADER_COMPLETED	0
#define DUMP_HEADER_INCOMPLETED 1
#define DUMP_HEADER_COMPRESSED  8

struct disk_dump_header_32 {
	char    signature[SIGNATURE_LEN];
	int32_t header_version;
	char    utsname_sysname[65];
	char    utsname_nodename[65];
	char    utsname_release[65];
	char    utsname_version[65];
	char    utsname_machine[65];
	char    utsname_domainname[65];
	char    _pad[2];
	struct {
		uint32_t tv_sec;
		uint32_t tv_usec;
	} timestamp;
	uint32_t status;
	int32_t  block_size;
	int32_t  sub_hdr_size;
	uint32_t bitmap_blocks;
	uint32_t max_mapnr;
	uint32_t total_ram_blocks;
	uint32_t device_blocks;
	uint32_t written_blocks;
	uint32_t current_cpu;
	int32_t  nr_cpus;
}  __attribute__((packed));

struct disk_dump_header_64 {
	char    signature[SIGNATURE_LEN];
	int32_t header_version;
	char    utsname_sysname[65];
	char    utsname_nodename[65];
	char    utsname_release[65];
	char    utsname_version[65];
	char    utsname_machine[65];
	char    utsname_domainname[65];
	char    _pad[6];
	struct {
		uint64_t tv_sec;
		uint64_t tv_usec;
	} timestamp;
	uint32_t status;
	int32_t  block_size;
	int32_t  sub_hdr_size;
	uint32_t bitmap_blocks;
	uint32_t max_mapnr;
	uint32_t total_ram_blocks;
	uint32_t device_blocks;
	uint32_t written_blocks;
	uint32_t current_cpu;
	int32_t  nr_cpus;
} __attribute__((packed));

struct kdump_sub_header_32 {
	uint32_t phys_base;
	int32_t  dump_level;
	int32_t  split;
	uint32_t start_pfn;
	uint32_t end_pfn;
	uint64_t offset_vmcoreinfo;
	uint32_t size_vmcoreinfo;
	uint64_t offset_note;
	uint32_t size_note;
	uint64_t offset_eraseinfo;
	uint32_t size_eraseinfo;
	uint64_t start_pfn_64;
	uint64_t end_pfn_64;
	uint64_t max_mapnr_64;
} __attribute__((packed));

struct kdump_sub_header_64 {
	uint64_t phys_base;
	int32_t  dump_level;
	int32_t  split;
	uint64_t start_pfn;
	uint64_t end_pfn;
	uint64_t offset_vmcoreinfo;
	uint64_t size_vmcoreinfo;
	uint64_t offset_note;
	uint64_t size_note;
	uint64_t offset_eraseinfo;
	uint64_t size_eraseinfo;
	uint64_t start_pfn_64;
	uint64_t end_pfn_64;
	uint64_t max_mapnr_64;
} __attribute__((packed));

#define DUMP_DH_COMPRESSED_ZLIB		0x1
#define DUMP_DH_COMPRESSED_LZO		0x2
#define DUMP_DH_COMPRESSED_SNAPPY	0x4
#define DUMP_DH_COMPRESSED_INCOMPLETE	0x8
#define DUMP_DH_EXCLUDED_VMEMMAP	0x10
#define DUMP_DH_COMPRESSED_ZSTD		0x20

#define DUMP_DH_COMPRESSED			\
	(DUMP_DH_COMPRESSED_ZLIB |		\
	 DUMP_DH_COMPRESSED_LZO |		\
	 DUMP_DH_COMPRESSED_SNAPPY)

struct page_desc {
	uint64_t offset;
	uint32_t size;
	uint32_t flags;
	uint64_t page_flags;
} __attribute__((packed));

#endif	/* diskdump.h */
