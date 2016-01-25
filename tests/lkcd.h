/* LKCD format definitions.
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

#ifndef _LKCD_H
#define _LKCD_H 1

#include <stdint.h>

#define DUMP_MAGIC_NUMBER  0xa8190173618f23edULL
#define DUMP_PANIC_LEN     0x100

#define DUMP_LEVEL_NONE        0x0
#define DUMP_LEVEL_HEADER      0x1
#define DUMP_LEVEL_KERN        0x2
#define DUMP_LEVEL_USED        0x4
#define DUMP_LEVEL_ALL         0x8

#define DUMP_COMPRESS_NONE     0x0
#define DUMP_COMPRESS_RLE      0x1
#define DUMP_COMPRESS_GZIP     0x2

#define DUMP_DH_FLAGS_NONE     0x0
#define DUMP_DH_RAW            0x1
#define DUMP_DH_COMPRESSED     0x2
#define DUMP_DH_END            0x4

struct dump_header {
	uint64_t dh_magic_number;
	uint32_t dh_version;
	uint32_t dh_header_size;
	uint32_t dh_dump_level;
	uint32_t dh_page_size;
	uint64_t dh_memory_size;
	uint64_t dh_memory_start;
	uint64_t dh_memory_end;
	uint32_t dh_num_dump_pages;
	char     dh_panic_string[DUMP_PANIC_LEN];
	struct {
		uint64_t tv_sec;
		uint64_t tv_usec;
	} dh_time;
	char     dh_utsname_sysname[65];
	char     dh_utsname_nodename[65];
	char     dh_utsname_release[65];
	char     dh_utsname_version[65];
	char     dh_utsname_machine[65];
	char     dh_utsname_domainname[65];
	uint64_t dh_current_task;
	uint32_t dh_dump_compress;
	uint32_t dh_dump_flags;
	uint32_t dh_dump_device;
	uint64_t dh_dump_buffer_size;
} __attribute__((packed));

/* x86_64 stuff */

struct pt_regs_x86_64 {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t rbp;
	uint64_t rbx;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t orig_rax;
	uint64_t rip;
	uint64_t cs;
	uint64_t eflags;
	uint64_t rsp;
	uint64_t ss;
} __attribute__((packed));

#define DUMP_ASM_MAGIC_NUMBER_X86_64	0xdeaddeadULL
#define DUMP_ASM_VERSION_NUMBER_X86_64	2

struct dump_header_asm_x86_64 {
	uint64_t dha_magic_number;
	uint32_t dha_version;
	uint32_t dha_header_size;
	struct pt_regs_x86_64 dha_regs;

	uint32_t dha_smp_num_cpus;
	uint32_t dha_dumping_cpu;
	/* struct pt_regs_x86_64 dha_smp_regs[NR_CPUS]; */
	/* uint64_t dha_smp_current_task[NR_CPUS]; */
	/* uint64_t dha_stack[NR_CPUS]; */
	/* uint64_t dha_stack_ptr[NR_CPUS]; */
} __attribute__((packed));

/* i386 stuff */

struct pt_regs_i386 {
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
} __attribute__((packed));

#define DUMP_ASM_MAGIC_NUMBER_I386	0xdeaddeadULL
#define DUMP_ASM_VERSION_NUMBER_I386	3

struct dump_header_asm_i386 {
	uint64_t dha_magic_number;
	uint32_t dha_version;
	uint32_t dha_header_size;
	uint32_t dha_esp;
	uint32_t dha_eip;
	struct pt_regs_i386 dha_regs;

	uint32_t dha_smp_num_cpus;
	uint32_t dha_dumping_cpu;
	/* struct pt_regs_i386 dha_smp_regs[NR_CPUS]; */
	/* uint32_t dha_smp_current_task[NR_CPUS]; */
	/* uint32_t dha_stack[NR_CPUS]; */
	/* uint32_t dha_stack_ptr[NR_CPUS]; */
} __attribute__((packed));

#define DUMP_DH_FLAGS_NONE      0x0
#define DUMP_DH_RAW             0x1
#define DUMP_DH_COMPRESSED      0x2
#define DUMP_DH_END             0x4

struct dump_page {
	uint64_t  dp_address;
	uint32_t  dp_size;
	uint32_t  dp_flags;
} __attribute__((packed));

#endif	/* lkcd.h */
