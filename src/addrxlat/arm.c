/** @internal @file src/addrxlat/arm.c
 * @brief Routines specific to 32-bit Arm with short descriptors.
 */
/* Copyright (C) 2023 Petr Tesarik <petr@tesarici.cz>

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

#include "addrxlat-priv.h"

/* Maximum physical address bits (architectural limit) */
#define PHYSADDR_BITS_MAX	40
#define PHYSADDR_MASK		ADDR_MASK(PHYSADDR_BITS_MAX)

/* This value corresponds to kexec-tools' KVBASE_MASK defined in
 * kexec/arch/arm/crashdump-arm.h, which was in turn taken from the
 * crash utility. It seems that it was blindly copied from the i386
 * implementation where it was most likely derived from the maximum
 * value of CONFIG_PHYS_ALIGN on x86 (but off by one).
 *
 * For 32-bit Arm, the correct value should cover the maximum value
 * of TEXT_OFFSET, which depends on the configured target platform.
 * As of Linux 6.4, the maximum is 0x308000 for CONFIG_ARCH_AXXIA,
 * so 22 bits should be sufficient.
 *
 * However, I'm following the crowd, because then this code breaks
 * when all the other packages break too, so people can hopefully
 * remember the buzz...
 */
#define LINUX_KVBASE_MASK	ADDR_MASK(25)

#define PTE_MASK(bits)		(((uint64_t)1<<bits) - 1)
#define PTE_VAL(x, shift, bits)	(((x) >> (shift)) & PTE_MASK(bits))

#define PTE_TYPE(x)	PTE_VAL((x), 0, 2)
#define PTE_SECTYPE(x)	PTE_VAL((x), 18, 1)

#define SMALL_PAGE_MASK	PTE_MASK(12)
#define LARGE_PAGE_MASK	PTE_MASK(16)
#define PAGE_TABLE_MASK	PTE_MASK(10)

#define SECT_MASK	PTE_MASK(20)

#define SUPERSECT_MASK		PTE_MASK(24)
#define SUPERSECT_32_35(pte)	PTE_VAL((pte), 20, 4)
#define SUPERSECT_36_39(pte)	PTE_VAL((pte), 5, 4)

/** Descriptive names for page tables.
 * These names are used in error messages.
 */
static const char pgt_full_name[][16] = {
	"Page",
	"Level 2 table",
	"Level 1 table",
};

/** Short names for page table entries.
 * These names are used in error messages. They are named after their
 * use in the Linux kernel. This may have to change if you add support
 * for other operating systems.
 */
static const char pte_name[][4] = {
	"pte",
	"pgd",
};

/** Set an appropriate error message if the VALID bit is zero.
 * @param step  Current step state.
 * @returns     Error status.
 */
static addrxlat_status
pte_not_present(addrxlat_step_t *step)
{
	return !step->ctx->noerr.notpresent
		? set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
			    "%s not present: %s[%u] = 0x%" ADDRXLAT_PRIxPTE,
			    pgt_full_name[step->remain - 1],
			    pte_name[step->remain - 1],
			    (unsigned) step->idx[step->remain],
			    step->raw.pte)
		: ADDRXLAT_ERR_NOTPRESENT;
}

/** Add overlapping index bits from a higher-level table.
 * @param step	Current step state.
 * @param bits	Number of overlapping bits.
 *
 * Some paging forms reuse low bits from the table index as high bits in
 * a lower-level index (or offset within page). The paging form definition
 * assigns these bits to the higher-level table to allow walking up to that
 * table with the generic page-table helpers. Use this function to adjust
 * the index into the next level.
 */
static void
add_overlap(addrxlat_step_t *step, unsigned bits)
{
	const addrxlat_paging_form_t *pf = &step->meth->param.pgt.pf;
	unsigned shift = pf->fieldsz[step->remain - 1];

	step->idx[step->remain - 1] +=
		(step->idx[step->remain] & ADDR_MASK(bits)) << shift;
}

/** Arm AArch32 page table step function.
 * @param step  Current step state.
 * @returns     Error status.
 */
addrxlat_status
pgt_arm(addrxlat_step_t *step)
{
	addrxlat_pte_t pte;
	unsigned char type;
	addrxlat_status status;

	status = read_pte32(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;

	type = PTE_TYPE(pte);
	if (!type)
		return pte_not_present(step);

	step->base.as = step->meth->target_as;
	if (step->remain > 1) {
		/* Level 1 descriptor */
		if (type != 1) {
			if (PTE_SECTYPE(pte)) {
				/* Supersection */
				add_overlap(step, 4);
				step->base.addr = (pte & ~SUPERSECT_MASK) |
					(SUPERSECT_32_35(pte) << 32) |
					(SUPERSECT_36_39(pte) << 36);
			} else {
				/* Section */
				step->base.addr = pte & ~SECT_MASK;
			}
			return pgt_huge_page(step);
		}
		step->base.addr = pte & ~PAGE_TABLE_MASK;
	} else {
		/* Level 2 descriptor */
		if (type == 1) {
			/* Large page */
			add_overlap(step, 4);
			step->base.addr = pte & ~LARGE_PAGE_MASK;
		} else
			/* Small page */
			step->base.addr = pte & ~SMALL_PAGE_MASK;
		step->elemsz = 1;
	}

	return ADDRXLAT_OK;
}

/** Initialize the page table translation method.
 * @param ctl      Initialization data.
 * @param ttbcr_n  Value of TTBCR.N.
 */
static void
init_pgt_meth(struct os_init_data *ctl, unsigned ttbcr_n)
{
	static const addrxlat_paging_form_t arm_pf = {
		.pte_format = ADDRXLAT_PTE_ARM,
		.nfields = 3,
		.fieldsz = { 12, 8, 12 }
	};

	addrxlat_meth_t *meth;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	meth->kind = ADDRXLAT_PGT;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;
	if (opt_isset(ctl->popt, rootpgt))
		meth->param.pgt.root = ctl->popt.rootpgt;
	else
		meth->param.pgt.root.as = ADDRXLAT_NOADDR;
	meth->param.pgt.pte_mask = 0;
	meth->param.pgt.pf = arm_pf;
	meth->param.pgt.pf.fieldsz[2] -= ttbcr_n;
}

static addrxlat_status
map_ktext_linear(struct os_init_data *ctl, addrxlat_addr_t first,
		 addrxlat_addr_t last, addrxlat_off_t off)
{
	addrxlat_meth_t *meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_KTEXT];
	struct sys_region layout[2];

	meth->kind = ADDRXLAT_LINEAR;
	meth->target_as = ADDRXLAT_KPHYSADDR;
	meth->param.linear.off = off;

	layout[0].first = first;
	layout[0].last = last;
	layout[0].meth = ADDRXLAT_SYS_METH_KTEXT;
	layout[0].act = SYS_ACT_NONE;

	layout[1].meth = ADDRXLAT_SYS_METH_NUM;

	return sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KV_PHYS, layout);
}

/** Determine Linux page table root.
 * @param ctl	     Initialization data.
 * @param[out] root  Page table root address (set on successful return).
 * @returns	     Error status.
 *
 * It is not an error if the root page table address cannot be
 * determined; it merely stays uninitialized.
 */
static addrxlat_status
get_linux_pgtroot(struct os_init_data *ctl, addrxlat_fulladdr_t *root)
{
	addrxlat_status status;

	status = get_symval(ctl->ctx, "swapper_pg_dir", &root->addr);
	if (status != ADDRXLAT_OK)
		return set_error(ctl->ctx, status,
				 "Cannot determine page table virtual address");
	root->as = ADDRXLAT_KVADDR;

	/* If the read callback can handle virtual addresses, we're done. */
	if (direct_read_ok(ctl->ctx, root))
		return ADDRXLAT_OK;

	if (opt_isset(ctl->popt, phys_base)) {
		addrxlat_addr_t page_base, pgd_size;
		const addrxlat_paging_form_t *pf;

		status = get_symval(ctl->ctx, "_stext", &page_base);
		if (status != ADDRXLAT_OK)
			return status;
		page_base &= ~LINUX_KVBASE_MASK;

		pf = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT].param.pgt.pf;
		pgd_size = pf_table_size(pf, pf->nfields - 1) <<
			pteval_shift(ADDRXLAT_PTE_ARM);
		return map_ktext_linear(ctl, root->addr,
					root->addr + pgd_size - 1,
					ctl->popt.phys_base - page_base);
	}

	return set_error(ctl->ctx, ADDRXLAT_ERR_NOMETH,
			 "No way to determine kernel physical location");
}

/** Initialize a translation map for Linux/arm.
 * @param ctl  Initialization data.
 * @returns	  Error status.
 */
static addrxlat_status
map_linux_arm(struct os_init_data *ctl)
{
	addrxlat_meth_t *meth;
	addrxlat_status status;

	init_pgt_meth(ctl, 0);

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	if (meth->param.pgt.root.as == ADDRXLAT_NOADDR) {
		status = get_linux_pgtroot(ctl, &meth->param.pgt.root);
		if (status != ADDRXLAT_OK)
			return status;
	}

	return ADDRXLAT_OK;
}

/** Initialize a translation map for an arm OS.
 * @param ctl  Initialization data.
 * @returns    Error status.
 */
addrxlat_status
sys_arm(struct os_init_data *ctl)
{
	addrxlat_status status;

	status = sys_set_physmaps(ctl, PHYSADDR_MASK);
	if (status != ADDRXLAT_OK)
		return status;

	switch (ctl->os_type) {
	case OS_LINUX:
		return map_linux_arm(ctl);

	default:
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "OS type not implemented");
	}
}
