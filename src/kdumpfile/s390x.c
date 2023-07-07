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
	kdump_attr_value_t val;
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

	val.blob = internal_blob_new(vmcoreinfo, sz);
	if (!val.blob) {
		free(vmcoreinfo);
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate %s", "VMCOREINFO blob");
	}
	ret = set_attr(ctx, gattr(ctx, GKI_linux_vmcoreinfo_raw),
		       ATTR_DEFAULT, &val);
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
s390x_post_ostype(kdump_ctx_t *ctx)
{
	return ctx->xlat->osdir == GKI_dir_linux
		? process_lowcore_info(ctx)
		: KDUMP_OK;
}

static kdump_status
s390x_init(kdump_ctx_t *ctx)
{
	if (ctx->xlat->osdir == GKI_dir_linux) {
		process_lowcore_info(ctx);
		clear_error(ctx);
	}

	return KDUMP_OK;
}

struct elf_siginfo
{
	int32_t si_signo;	/* signal number */
	int32_t si_code;	/* extra code */
	int32_t si_errno;	/* errno */
} __attribute__((packed));

struct psw {
	uint64_t mask;
	uint64_t addr;
} __attribute__((packed));

struct elf_s390_regs {
	struct psw psw;
	uint64_t gprs[16];
	uint32_t acrs[16];
	uint64_t orig_gpr2;
} __attribute__((packed));

struct elf_prstatus
{
	struct elf_siginfo pr_info;	/* UNUSED in kernel cores */
	int16_t	pr_cursig;		/* UNUSED in kernel cores */
	char	_pad1[2];		/* alignment */
	uint64_t pr_sigpend;		/* UNUSED in kernel cores */
	uint64_t pr_sighold;		/* UNUSED in kernel cores */
	int32_t	pr_pid;			/* PID of crashing task */
	int32_t	pr_ppid;		/* UNUSED in kernel cores */
	int32_t	pr_pgrp;		/* UNUSED in kernel cores */
	int32_t	pr_sid;			/* UNUSED in kernel cores */
	struct timeval_64 pr_utime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_stime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_cutime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_cstime;	/* UNUSED in kernel cores */
	struct elf_s390_regs pr_reg;	/* GP/ACR registers */
	/* optional UNUSED fields may follow */
} __attribute__((packed));

#define REG(name, field) \
	DERIVED_NUMBER(#name, 1, struct elf_prstatus, field)

static struct derived_attr_def s390x_reg_attrs[] = {
	REG(pswm, pr_reg.psw.mask),
	REG(pswa, pr_reg.psw.addr),
	REG(r0, pr_reg.gprs[0]),
	REG(r1, pr_reg.gprs[1]),
	REG(r2, pr_reg.gprs[2]),
	REG(r3, pr_reg.gprs[3]),
	REG(r4, pr_reg.gprs[4]),
	REG(r5, pr_reg.gprs[5]),
	REG(r6, pr_reg.gprs[6]),
	REG(r7, pr_reg.gprs[7]),
	REG(r8, pr_reg.gprs[8]),
	REG(r9, pr_reg.gprs[9]),
	REG(r10, pr_reg.gprs[10]),
	REG(r11, pr_reg.gprs[11]),
	REG(r12, pr_reg.gprs[12]),
	REG(r13, pr_reg.gprs[13]),
	REG(r14, pr_reg.gprs[14]),
	REG(r15, pr_reg.gprs[15]),
	REG(a0, pr_reg.acrs[0]),
	REG(a1, pr_reg.acrs[1]),
	REG(a2, pr_reg.acrs[2]),
	REG(a3, pr_reg.acrs[3]),
	REG(a4, pr_reg.acrs[4]),
	REG(a5, pr_reg.acrs[5]),
	REG(a6, pr_reg.acrs[6]),
	REG(a7, pr_reg.acrs[7]),
	REG(a8, pr_reg.acrs[8]),
	REG(a9, pr_reg.acrs[9]),
	REG(a10, pr_reg.acrs[10]),
	REG(a11, pr_reg.acrs[11]),
	REG(a12, pr_reg.acrs[12]),
	REG(a13, pr_reg.acrs[13]),
	REG(a14, pr_reg.acrs[14]),
	REG(a15, pr_reg.acrs[15]),
	REG(orig_gpr2, pr_reg.orig_gpr2),
	DERIVED_NUMBER("pid", 0, struct elf_prstatus, pr_pid),
};

static kdump_status
s390x_process_prstatus(kdump_ctx_t *ctx, const void *data, size_t size)
{
	unsigned cpu;
	kdump_status status;

	cpu = get_num_cpus(ctx);
	set_num_cpus(ctx, get_num_cpus(ctx) + 1);

	status = init_cpu_prstatus(ctx, cpu, data, size);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot set CPU %u %s",
				 cpu, "PRSTATUS");

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong PRSTATUS size: %zu", size);

	status = create_cpu_regs(
		ctx, cpu, s390x_reg_attrs, ARRAY_SIZE(s390x_reg_attrs));

	return status;
}

const struct arch_ops s390x_ops = {
	.init = s390x_init,
	.post_ostype = s390x_post_ostype,
	.process_prstatus = s390x_process_prstatus,
};
