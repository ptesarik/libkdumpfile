/** @internal @file src/ia32.c
 * @brief Functions for the Intel 32-bit (x86) architecture.
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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <linux/version.h>

#define ELF_NGREG 17

/* Maximum virtual address (architecture limit) */
#define VIRTADDR_MAX		UINT32_MAX

#define __START_KERNEL_map	0xc0000000UL

static const addrxlat_paging_form_t ia32_pf = {
	.pte_format = addrxlat_pte_ia32,
	.levels = 3,
	.bits = { 12, 10, 10 }
};

static const addrxlat_paging_form_t ia32_pf_pae = {
	.pte_format = addrxlat_pte_ia32_pae,
	.levels = 4,
	.bits = { 12, 9, 9, 4 }
};

/** @cond TARGET_ABI */

struct elf_siginfo
{
	int32_t si_signo;	/* signal number */
	int32_t si_code;	/* extra code */
	int32_t si_errno;	/* errno */
} __attribute__((packed));

struct elf_prstatus
{
	struct elf_siginfo pr_info;	/* UNUSED in kernel cores */
	int16_t	pr_cursig;		/* UNUSED in kernel cores */
	char	_pad1[2];		/* alignment */
	uint32_t pr_sigpend;		/* UNUSED in kernel cores */
	uint32_t pr_sighold;		/* UNUSED in kernel cores */
	int32_t	pr_pid;			/* PID of crashing task */
	int32_t	pr_ppid;		/* UNUSED in kernel cores */
	int32_t	pr_pgrp;		/* UNUSED in kernel cores */
	int32_t	pr_sid;			/* UNUSED in kernel cores */
	struct timeval_32 pr_utime;	/* UNUSED in kernel cores */
	struct timeval_32 pr_stime;	/* UNUSED in kernel cores */
	struct timeval_32 pr_cutime;	/* UNUSED in kernel cores */
	struct timeval_32 pr_cstime;	/* UNUSED in kernel cores */
	uint32_t pr_reg[ELF_NGREG];	/* GP registers */
	/* optional UNUSED fields may follow */
} __attribute__((packed));

/** @endcond */

static const struct attr_template reg_names[] = {
#define REG(name)	{ #name, NULL, kdump_number }
	REG(ebx),
	REG(ecx),
	REG(edx),
	REG(esi),
	REG(edi),
	REG(ebp),
	REG(eax),
	REG(ds),
	REG(es),
	REG(fs),
	REG(gs),
	REG(orig_eax),
	REG(eip),
	REG(cs),
	REG(eflags),
	REG(esp),
	REG(ss),
};

static const struct attr_template tmpl_pid =
	{ "pid", NULL, kdump_number };

struct ia32_data {
	int pae_state;		/* <0 .. no, >0 .. yes, 0 .. undetermined */
};

static kdump_status
ia32_init(kdump_ctx *ctx)
{
	kdump_status ret;

	clear_attr(ctx, gattr(ctx, GKI_pteval_size));

	ctx->shared->archdata = calloc(1, sizeof(struct ia32_data));
	if (!ctx->shared->archdata)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate ia32 private data");

	ret = set_vtop_xlat_linear(&ctx->shared->vtop_map,
				   __START_KERNEL_map, VIRTADDR_MAX,
				   __START_KERNEL_map);
	if (ret != kdump_ok)
		return set_error(ctx, ret,
				 "Cannot set up initial directmap");

	return kdump_ok;
}

static kdump_status
process_ia32_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	char cpukey[sizeof("cpu.") + 20];
	struct attr_data *dir, *attr;
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, kdump_dataerr,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs32(ctx, get_num_cpus(ctx),
			     reg_names, status->pr_reg, ELF_NGREG);
	if (res != kdump_ok)
		return res;

	sprintf(cpukey, "cpu.%u", get_num_cpus(ctx));
	dir = lookup_attr(ctx->shared, cpukey);
	if (!dir)
		return set_error(ctx, kdump_nokey,
				 "'%s': %s", cpukey, "No such key");
	attr = new_attr(ctx->shared, dir, &tmpl_pid);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate '%s'", cpukey);
	res = set_attr_number(ctx, attr, ATTR_DEFAULT,
			      dump32toh(ctx, status->pr_pid));
	if (res != kdump_ok)
		return set_error(ctx, res,
				 "Cannot set '%s'", cpukey);

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);
	return kdump_ok;
}

static kdump_status
read_pgt(kdump_ctx *ctx)
{
	struct ia32_data *archdata = ctx->shared->archdata;
	addrxlat_fulladdr_t pgtroot;
	const addrxlat_paging_form_t *pf;
	addrxlat_status axres;
	kdump_status ret;

	rwlock_unlock(&ctx->shared->lock);
	ret = get_symbol_val(ctx, "swapper_pg_dir", &pgtroot.addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (ret != kdump_ok)
		return ret;

	if (pgtroot.addr < __START_KERNEL_map)
		return set_error(ctx, kdump_dataerr,
				 "Wrong page directory address:"
				 " 0x%"ADDRXLAT_PRIXADDR, pgtroot.addr);
	pgtroot.addr -= __START_KERNEL_map;
	pgtroot.as = ADDRXLAT_KPHYSADDR;
	addrxlat_pgt_set_root(ctx->shared->vtop_map.pgt, &pgtroot);

	if (!archdata->pae_state) {
		kdump_vaddr_t addr = pgtroot.addr + 3 * sizeof(uint64_t);
		uint64_t entry;
		size_t sz = sizeof entry;
		ret = readp_locked(ctx, KDUMP_KPHYSADDR, addr, &entry, &sz);
		if (ret != kdump_ok)
			return ret;
		archdata->pae_state = entry ? 1 : -1;
	}

	pf = (archdata->pae_state > 0 ? &ia32_pf_pae : &ia32_pf);
	axres = addrxlat_pgt_set_form(ctx->shared->pgtxlat, pf);
	if (axres != addrxlat_ok)
		return set_error_addrxlat(ctx, axres);

	return kdump_ok;
}

static kdump_status
ia32_vtop_init(kdump_ctx *ctx)
{
	struct ia32_data *archdata = ctx->shared->archdata;
	struct attr_data *base, *attr;
	kdump_status ret;

	base = gattr(ctx, GKI_linux_vmcoreinfo_lines);
	attr = lookup_dir_attr(ctx->shared, base,
			       "CONFIG_X86_PAE", sizeof("CONFIG_X86_PAE")-1);
	if (attr && validate_attr(ctx, attr) == kdump_ok &&
	    !strcmp(attr_value(attr)->string, "y"))
		archdata->pae_state = 1;

	ret = read_pgt(ctx);
	if (ret != kdump_ok)
		return ret;

	set_attr_number(ctx, gattr(ctx, GKI_pteval_size), ATTR_DEFAULT,
			archdata->pae_state > 0 ? 8 : 4);

	flush_vtop_map(&ctx->shared->vtop_map);
	ret = set_vtop_xlat_pgt(&ctx->shared->vtop_map,
				0, VIRTADDR_MAX);
	if (ret != kdump_ok)
		return set_error(ctx, ret, "Cannot set up pagetable mapping");

	return kdump_ok;
}

static void
ia32_cleanup(struct kdump_shared *shared)
{
	struct ia32_data *archdata = shared->archdata;

	free(archdata);
	shared->archdata = NULL;
}

const struct arch_ops ia32_ops = {
	.init = ia32_init,
	.vtop_init = ia32_vtop_init,
	.process_prstatus = process_ia32_prstatus,
	.cleanup = ia32_cleanup,
};

