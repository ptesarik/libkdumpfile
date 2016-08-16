/** @internal @file src/ppc64.c
 * @brief Functions for the ppc64 architecture.
 */
/* Copyright (C) 2015 Free Software Foundation, Inc.

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
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#define VIRTADDR_MAX		UINT64_MAX

static const struct attr_template reg_names[] = {
#define REG(name)	{ #name, NULL, kdump_number }
	REG(gpr00),
	REG(gpr01),
	REG(gpr02),
	REG(gpr03),
	REG(gpr04),
	REG(gpr05),
	REG(gpr06),
	REG(gpr07),
	REG(gpr08),
	REG(gpr09),
	REG(gpr10),
	REG(gpr11),
	REG(gpr12),
	REG(gpr13),
	REG(gpr14),
	REG(gpr15),
	REG(gpr16),
	REG(gpr17),
	REG(gpr18),
	REG(gpr19),
	REG(gpr20),
	REG(gpr21),
	REG(gpr22),
	REG(gpr23),
	REG(gpr24),
	REG(gpr25),
	REG(gpr26),
	REG(gpr27),
	REG(gpr28),
	REG(gpr29),
	REG(gpr30),
	REG(gpr31),
	REG(nip),
	REG(msr),
	REG(or3),
	REG(ctr),
	REG(lr),
	REG(xer),
	REG(ccr),
	REG(mq),
	REG(dar),
	REG(dsisr),
	REG(rx1),
	REG(rx2),
	REG(rx3),
	REG(rx4),
	REG(rx5),
	REG(rx6),
	REG(rx7),
	REG(rx8),
	REG(rx9),
};

#define _64K (1<<16)

static kdump_status
ppc64_vtop_init(kdump_ctx *ctx)
{
	addrxlat_fulladdr_t pgtroot;
	kdump_vaddr_t addr, vmal;
	struct attr_data *base, *attr;
	char *endp;
	unsigned long off_vm_struct_addr;
	size_t sz = get_ptr_size(ctx);
	kdump_status res;

	rwlock_unlock(&ctx->shared->lock);
	res = get_symbol_val(ctx, "swapper_pg_dir", &pgtroot.addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot resolve %s",
				 "swapper_pg_dir");
	pgtroot.as = ADDRXLAT_KVADDR;
	addrxlat_pgt_set_root(ctx->shared->vtop_map.pgt, &pgtroot);

	rwlock_unlock(&ctx->shared->lock);
	res = get_symbol_val(ctx, "_stext", &addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot resolve %s",
				 "_stext");
	set_phys_base(ctx, addr);

	flush_vtop_map(&ctx->shared->vtop_map);
	res = set_vtop_xlat_linear(&ctx->shared->vtop_map,
				   addr, addr + 0x1000000000000000, addr);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot set up directmap");

	rwlock_unlock(&ctx->shared->lock);
	res = get_symbol_val(ctx, "vmlist", &addr);
	rwlock_wrlock(&ctx->shared->lock);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot resolve %s",
				 "vmlist");

	base = gattr(ctx, GKI_linux_vmcoreinfo_lines);
	attr = lookup_dir_attr(ctx->shared, base,
			       "OFFSET(vm_struct.addr)",
			       sizeof("OFFSET(vm_struct.addr)") - 1);
	if (!attr || validate_attr(ctx, attr) != kdump_ok)
		return set_error(ctx, kdump_nodata,
				 "No OFFSET(vm_struct.addr) in VMCOREINFO");
	off_vm_struct_addr = strtoul(attr_value(attr)->string, &endp, 10);
	if (*endp)
		return set_error(ctx, kdump_dataerr,
				 "Invalid value of OFFSET(vm_struct.addr)");

	res = readp_locked(ctx, KDUMP_KVADDR, addr, &addr, &sz);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read vmlist.addr");

	addr = dump64toh(ctx, addr);
	addr += off_vm_struct_addr;

	res = readp_locked(ctx, KDUMP_KVADDR, addr, &vmal, &sz);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot read vmlist.addr");

	vmal = dump64toh(ctx, vmal);

	res = set_vtop_xlat_pgt(&ctx->shared->vtop_map, vmal, VIRTADDR_MAX);
	if (res != kdump_ok)
		return set_error(ctx, res, "Cannot set up pagetable mapping");

	return kdump_ok;
}

static const addrxlat_paging_form_t ppc64_pf_64k = {
	.pte_format = addrxlat_pte_ppc64,
	.rpn_shift = 30,
	.levels = 4,
	.bits = { 16, 12, 12, 4 }
};

static kdump_status
ppc64_init(kdump_ctx *ctx)
{
	int pagesize;
	addrxlat_status axres;

	pagesize = get_page_size(ctx);

	if (pagesize == _64K) {
		axres = addrxlat_pgt_set_form(
			ctx->shared->pgtxlat, &ppc64_pf_64k);
		if (axres != addrxlat_ok)
			return set_error_addrxlat(ctx, axres);
	} else
		return set_error(ctx, kdump_nodata, "PAGESIZE == %d", pagesize);

	return kdump_ok;
}

/** @cond TARGET_ABI */

#define ELF_NGREG 49

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
	uint64_t pr_reg[ELF_NGREG];	/* GP registers */
	/* optional UNUSED fields may follow */
} __attribute__((packed));

/** @endcond */

static kdump_status
process_ppc64_prstatus(kdump_ctx *ctx, void *data, size_t size)
{
	struct elf_prstatus *status = data;
	kdump_status res;

	if (size < sizeof(struct elf_prstatus))
		return set_error(ctx, kdump_dataerr,
				 "Wrong PRSTATUS size: %zu", size);

	res = set_cpu_regs64(ctx, get_num_cpus(ctx), reg_names,
			     status->pr_reg, ELF_NGREG);

	if (res != kdump_ok)
		return res;

	set_num_cpus(ctx, get_num_cpus(ctx) + 1);

	return kdump_ok;
}

const struct arch_ops ppc64_ops = {
	.init = ppc64_init,
	.vtop_init = ppc64_vtop_init,
	.process_prstatus = process_ppc64_prstatus,
};
