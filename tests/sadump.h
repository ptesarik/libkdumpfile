/* SADUMP format definitions.
   Copyright (C) 2022 Petr Tesarik <ptesarik@suse.com>

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

#ifndef _SADUMP_H
#define _SADUMP_H 1

#include <stdint.h>

/** Standard EFI time specification. */
struct efi_time {
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minute;
	uint8_t second;
	uint8_t _pad1;
	uint32_t nanosecond;
	int16_t timezone;
	uint8_t daylight;
	uint8_t _pad2;
} __attribute__((packed));

/** Standard EFI GUID. */
struct efi_guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
} __attribute__((packed));

#define SADUMP_PART_SIGNATURE0	0x75646173
#define SADUMP_PART_SIGNATURE1	0x0000706d

/** Single-partition or diskset format header. */
struct sadump_part_header {
	uint32_t signature[2];
	uint32_t enable;
	uint32_t reboot;
	uint32_t compress;
	uint32_t recycle;
	uint32_t label[16];
	struct efi_guid sadump_id;
	struct efi_guid disk_set_id;
	struct efi_guid vol_id;
	struct efi_time time_stamp;
	uint32_t set_disk_set;
	uint32_t _pad;
	uint64_t used_device;
	uint32_t magicnum[];
} __attribute__((packed));

/** One volume in diskset header. */
struct sadump_volume_info {
	struct efi_guid id;
	uint64_t vol_size;
	uint32_t status;
	uint32_t cache_size;
} __attribute__((packed));

/** Diskset header. */
struct sadump_disk_set_header {
	uint32_t disk_set_header_size;
	uint32_t disk_num;
	uint64_t disk_set_size;
	struct sadump_volume_info vol_info[];
} __attribute__((packed));

#define SADUMP_SIGNATURE "sadump\0\0"

/** Dump header. */
struct sadump_header {
	char signature[8];
	uint32_t header_version;
	uint32_t _pad1;
	struct efi_time timestamp;
	uint32_t status;
	uint32_t compress;
	uint32_t block_size;
	uint32_t extra_hdr_size;
	uint32_t sub_hdr_size;
	uint32_t bitmap_blocks;
	uint32_t dumpable_bitmap_blocks;
	uint32_t max_mapnr;
	uint32_t total_ram_blocks;
	uint32_t device_blocks;
	uint32_t written_blocks;
	uint32_t current_cpu;
	uint32_t nr_cpus;
	uint32_t _pad2;
	uint64_t max_mapnr_64;
	uint64_t total_ram_blocks_64;
	uint64_t device_blocks_64;
	uint64_t written_blocks_64;
} __attribute__((packed));

struct sadump_apic_state {
	uint64_t apic_id;
	uint64_t ldr;
} __attribute__((packed));

/** SMRAM CPU state. */
struct sadump_smram_cpu_state {
	uint64_t _reserved1[58];
	uint32_t gdt_hi;
	uint32_t ldt_hi;
	uint32_t idt_hi;
	uint32_t _reserved2[3];
	uint64_t io_eip;
	uint64_t _reserved3[10];
	uint32_t cr4;
	uint32_t _reserved4[18];
	uint32_t gdt_lo;
	uint32_t gdt_limit;
	uint32_t idt_lo;
	uint32_t idt_limit;
	uint32_t ldt_lo;
	uint32_t ldt_limit;
	uint32_t ldt_info;
	uint64_t _reserved5[6];
	uint64_t eptp;
	uint32_t eptp_setting;
	uint32_t _reserved6[5];
	uint32_t smbase;
	uint32_t smm_revision_id;
	uint16_t io_instruction_restart;
	uint16_t auto_halt_restart;
	uint32_t _reserved7[6];
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rbx;
	uint64_t rsp;
	uint64_t rbp;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t io_mem_addr;
	uint32_t io_misc;
	uint32_t es;
	uint32_t cs;
	uint32_t ss;
	uint32_t ds;
	uint32_t fs;
	uint32_t gs;
	uint32_t ldtr;
	uint32_t tr;
	uint64_t dr7;
	uint64_t dr6;
	uint64_t rip;
	uint64_t ia32_efer;
	uint64_t rflags;
	uint64_t cr3;
	uint64_t cr0;
} __attribute__((packed));

/* Media backup format header. */
struct sadump_media_header {
	struct efi_guid sadump_id;
	struct efi_guid disk_set_id;
	struct efi_time time_stamp;
	uint8_t sequential_num;
	uint8_t term_cord;
	uint8_t disk_set_header_size;
	uint8_t disks_in_use;
} __attribute__((packed));

#endif	/* sadump.h */
