/** @internal @file src/addrxlat/step.c
 * @brief Address translation stepping.
 */
/* Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

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

#include <string.h>

#include "addrxlat-priv.h"

/** Count total size of all address bitfields.
 * @param pf  Paging form.
 * @returns   Number of significant bits in the source address.
*/
static unsigned short
vaddr_bits(const addrxlat_paging_form_t *pf)
{
	unsigned short i;
	unsigned short result = 0;
	for (i = 0; i < pf->nfields; ++i)
		result += pf->fieldsz[i];
	return result;
}

/* Calculate the maximum index into the page table hierarchy.
 * @param pf  Paging form.
 * @returns   Maximum mapped index.
 *
 * The maximum offset may not be the same as the maximum address that
 * can be translated (e.g. x86_64 sign-extends the highest bit).
 */
addrxlat_addr_t
paging_max_index(const addrxlat_paging_form_t *pf)
{
	unsigned bits = vaddr_bits(pf);
	return (bits < 8 * sizeof(addrxlat_addr_t)
		? ADDR_MASK(bits)
		: ADDRXLAT_ADDR_MAX);
}

/** Update current step state for huge page.
 * @param step  Current step state.
 * @returns     Always @c ADDRXLAT_OK.
 *
 * This function skips all lower paging levels and updates the state
 * so that the next page table step adds the correct page offset and
 * terminates.
 */
addrxlat_status
pgt_huge_page(addrxlat_step_t *step)
{
	const addrxlat_param_pgt_t *pgt = &step->meth->param.pgt;
	addrxlat_addr_t off = 0;

	while (step->remain > 1) {
		--step->remain;
		off |= step->idx[step->remain];
		off <<= pgt->pf.fieldsz[step->remain - 1];
	}
	step->elemsz = 1;
	step->idx[0] |= off;
	return ADDRXLAT_OK;
}

/** Initialize step state for linear offset.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_linear(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_linear_t *linear = &step->meth->param.linear;

	step->base.as = step->meth->target_as;
	step->base.addr = linear->off;
	step->remain = 1;
	step->elemsz = 1;
	step->idx[0] = addr;

	return ADDRXLAT_OK;
}

/** Generic initialization of the step state for page table walk.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Always returns success.
 */
static addrxlat_status
first_step_pgt_generic(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_pgt_t *pgt = &step->meth->param.pgt;
	unsigned short i;

	if (pgt->root.as == ADDRXLAT_NOADDR)
		return set_error(step->ctx, ADDRXLAT_ERR_NODATA,
				 "Page table address not specified");

	step->base = pgt->root;
	step->remain = pgt->pf.nfields;
	step->elemsz = step->remain > 1
		? 1 << addrxlat_pteval_shift(pgt->pf.pte_format)
		: 1;
	for (i = 0; i < pgt->pf.nfields; ++i) {
		unsigned short bits = pgt->pf.fieldsz[i];
		addrxlat_addr_t mask = bits < sizeof(addrxlat_addr_t) * 8
			? ((addrxlat_addr_t)1 << bits) - 1
			: ~(addrxlat_addr_t)0;
		step->idx[i] = addr & mask;
		addr >>= bits;
	}
	step->idx[i] = addr;
	return ADDRXLAT_OK;
}

/** Common next step helper for page frame number.
 * @param step  Current step state.
 * @param pte   Page table entry value (possibly masked).
 * @returns     Error status.
 *
 * This function contains the common processing for 32-bit and
 * 64-bit PFNs after the PTE was read.
 */
static addrxlat_status
next_step_pfn_common(addrxlat_step_t *step, addrxlat_pte_t pte)
{
	const addrxlat_meth_t *meth;
	if (!pte)
		return set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT,
				 "Level-%u PFN not present",
				 step->remain);
	meth = step->meth;
	step->base.addr = pte << meth->param.pgt.pf.fieldsz[0];
	step->base.as = meth->target_as;
	if (step->remain == 1)
		step->elemsz = 1;
	return ADDRXLAT_OK;
}

/** Next step function for a 32-bit page frame number.
 * @param step  Current step state.
 * @returns     Error status.
 *
 * This function handles 32-bit page frame numbers in a table.
 */
static addrxlat_status
next_step_pfn32(addrxlat_step_t *step)
{
	addrxlat_pte_t pte;
	addrxlat_status status = read_pte32(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;
	return next_step_pfn_common(step, pte);
}

/** Next step function for a 64-bit page frame number.
 * @param step  Current step state.
 * @returns     Error status.
 *
 * This function handles 64-bit page frame numbers in a table.
 */
static addrxlat_status
next_step_pfn64(addrxlat_step_t *step)
{
	addrxlat_pte_t pte;
	addrxlat_status status = read_pte64(step, &pte);
	if (status != ADDRXLAT_OK)
		return status;
	return next_step_pfn_common(step, pte);
}

/** Check unsigned address overflow.
 * @param step  Current step state.
 * @returns     Error status.
 *
 * This function is meant to be used by a first step function.
 * It checks whether the input address is too big when interpreted
 * as an unsigned integer.
 */
static addrxlat_status
step_check_uaddr(addrxlat_step_t *step)
{
	return step->idx[step->meth->param.pgt.pf.nfields]
		? set_error(step->ctx, ADDRXLAT_ERR_INVALID,
			    "Virtual address too big")
		: ADDRXLAT_OK;
}

/** Initialize step state for unsigned address page table walk.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_uaddr(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	addrxlat_status status;
	status = first_step_pgt_generic(step, addr);
	if (status != ADDRXLAT_OK)
		return status;
	return step_check_uaddr(step);
}

/** Check signed address overflow.
 * @param step  Current step state.
 * @returns     Error status.
 *
 * This function is meant to be used by a first step function.
 * It checks whether the input address is too big when interpreted
 * as a signed integer.
 */
static addrxlat_status
step_check_saddr(addrxlat_step_t *step)
{
	const addrxlat_paging_form_t *pf = &step->meth->param.pgt.pf;
	unsigned short lvl = pf->nfields;
	struct {
		int bit : 1;
	} s;
	addrxlat_addr_t signext;

	s.bit = step->idx[lvl - 1] >> (pf->fieldsz[lvl - 1] - 1);
	signext = s.bit & (ADDRXLAT_ADDR_MAX >> vaddr_bits(pf));
	return step->idx[lvl] != signext
		? set_error(step->ctx, ADDRXLAT_ERR_INVALID,
			    "Virtual address too big")
		: ADDRXLAT_OK;
}

/** Initialize step state for signed address page table walk.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_saddr(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	addrxlat_status status;
	status = first_step_pgt_generic(step, addr);
	if (status != ADDRXLAT_OK)
		return status;
	return step_check_saddr(step);
}

/** Initialize step state for page table walk.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Always returns success.
 */
static addrxlat_status
first_step_pgt(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	switch (step->meth->param.pgt.pf.pte_format) {
	case ADDRXLAT_PTE_NONE:
	case ADDRXLAT_PTE_AARCH64:
	case ADDRXLAT_PTE_AARCH64_LPA:
	case ADDRXLAT_PTE_AARCH64_LPA2:
	case ADDRXLAT_PTE_PPC64_LINUX_RPN30:
		return first_step_pgt_generic(step, addr);

	case ADDRXLAT_PTE_PFN32:
	case ADDRXLAT_PTE_PFN64:
	case ADDRXLAT_PTE_IA32:
	case ADDRXLAT_PTE_IA32_PAE:
	case ADDRXLAT_PTE_S390X:
		return first_step_uaddr(step, addr);

	case ADDRXLAT_PTE_X86_64:
		return first_step_saddr(step, addr);

	default:
		return set_error(step->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unknown PTE format");
	};
}

/** Make one step in the page table walk.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Always returns success.
 */
static addrxlat_status
next_step_pgt(addrxlat_step_t *step)
{
	switch (step->meth->param.pgt.pf.pte_format) {
	case ADDRXLAT_PTE_NONE:
		return ADDRXLAT_OK;

	case ADDRXLAT_PTE_PFN32:
		return next_step_pfn32(step);

	case ADDRXLAT_PTE_PFN64:
		return next_step_pfn64(step);

	case ADDRXLAT_PTE_AARCH64:
		return pgt_aarch64(step);

	case ADDRXLAT_PTE_AARCH64_LPA:
		return pgt_aarch64_lpa(step);

	case ADDRXLAT_PTE_AARCH64_LPA2:
		return pgt_aarch64_lpa2(step);

	case ADDRXLAT_PTE_IA32:
		return pgt_ia32(step);

	case ADDRXLAT_PTE_IA32_PAE:
		return pgt_ia32_pae(step);

	case ADDRXLAT_PTE_X86_64:
		return pgt_x86_64(step);

	case ADDRXLAT_PTE_S390X:
		return pgt_s390x(step);

	case ADDRXLAT_PTE_PPC64_LINUX_RPN30:
		return pgt_ppc64_linux_rpn30(step);

	default:
		return set_error(step->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unknown PTE format");
	};
}

/** Initialize step state for table lookup.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_lookup(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_lookup_t *lookup = &step->meth->param.lookup;
	size_t i;

	for (i = 0; i < lookup->nelem; ++i) {
		const addrxlat_lookup_elem_t *elem = &lookup->tbl[i];
		if (elem->orig <= addr &&
		    addr <= elem->orig + lookup->endoff) {
			step->base.as = step->meth->target_as;
			step->base.addr = elem->dest;
			step->remain = 1;
			step->elemsz = 1;
			step->idx[0] = addr - elem->orig;
			return ADDRXLAT_OK;
		}
	}

	return set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT, "Not mapped");
}

/** Initialize step state for memory array lookup.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_memarr(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_memarr_t *memarr = &step->meth->param.memarr;

	step->base = memarr->base;
	step->remain = 2;
	step->elemsz = memarr->elemsz;
	step->idx[0] = addr & ((1ULL << memarr->shift) - 1);
	step->idx[1] = addr >> memarr->shift;
	return ADDRXLAT_OK;
}

/** Memory array next step function.
 * @param walk  Current step state.
 * @returns     Error status.
 */
static addrxlat_status
next_step_memarr(addrxlat_step_t *step)
{
	const addrxlat_param_memarr_t *memarr = &step->meth->param.memarr;
	uint64_t val64;
	uint32_t val32;
	addrxlat_status status;

	switch (memarr->valsz) {
	case 4:
		status = read32(step, &step->base, &val32,
				"memory array element");
		step->raw.addr = val32;
		break;

	case 8:
		status = read64(step, &step->base, &val64,
				"memory array element");
		step->raw.addr = val64;
		break;

	default:
		return set_error(step->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unsupported value size: %u", memarr->valsz);
	}

	if (status == ADDRXLAT_OK) {
		step->base.addr = step->raw.addr << memarr->shift;
		step->base.as = step->meth->target_as;
		step->elemsz = 1;
	}

	return status;
}

/** Initialize step state.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	switch (step->meth->kind) {
	case ADDRXLAT_NOMETH:
		return set_error(step->ctx, ADDRXLAT_ERR_NOMETH,
				 "Null translation method");

	case ADDRXLAT_CUSTOM:
		return step->meth->param.custom.first_step(step, addr);

	case ADDRXLAT_LINEAR:
		return first_step_linear(step, addr);

	case ADDRXLAT_PGT:
		return first_step_pgt(step, addr);

	case ADDRXLAT_LOOKUP:
		return first_step_lookup(step, addr);

	case ADDRXLAT_MEMARR:
		return first_step_memarr(step, addr);

	default:
		return set_error(step->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unknown translation kind");
	}
}

/** Make the next translation step.
 * @param walk  Current step state.
 * @returns     Error status.
 */
static addrxlat_status
next_step(addrxlat_step_t *step)
{
	switch (step->meth->kind) {
	case ADDRXLAT_NOMETH:
		return set_error(step->ctx, ADDRXLAT_ERR_NOMETH,
				 "Null translation method");

	case ADDRXLAT_CUSTOM:
		return step->meth->param.custom.next_step(step);

	case ADDRXLAT_LINEAR:
	case ADDRXLAT_LOOKUP:
		return ADDRXLAT_OK;

	case ADDRXLAT_PGT:
		return next_step_pgt(step);

	case ADDRXLAT_MEMARR:
		return next_step_memarr(step);

	default:
		return set_error(step->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unknown translation kind");
	}
}

DEFINE_ALIAS(launch);

addrxlat_status
addrxlat_launch(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	clear_error(step->ctx);
	return first_step(step, addr);
}

DEFINE_ALIAS(step);

addrxlat_status
addrxlat_step(addrxlat_step_t *step)
{
	clear_error(step->ctx);

	if (!step->remain)
		return ADDRXLAT_OK;

	--step->remain;
	step->base.addr += step->idx[step->remain] * step->elemsz;
	if (!step->remain) {
		step->base.as = step->meth->target_as;
		step->elemsz = 0;
		return ADDRXLAT_OK;
	}

	return next_step(step);
}

DEFINE_ALIAS(walk);

addrxlat_status
addrxlat_walk(addrxlat_step_t *step)
{
	addrxlat_status status;

	clear_error(step->ctx);

	status = first_step(step, step->base.addr);
	if (status != ADDRXLAT_OK || !step->remain)
		return status;

	while (--step->remain) {
		step->base.addr += step->idx[step->remain] * step->elemsz;
		status = next_step(step);
		if (status != ADDRXLAT_OK)
			return status;
	}

	step->base.as = step->meth->target_as;
	step->base.addr += step->idx[0] * step->elemsz;
	step->elemsz = 0;
	return ADDRXLAT_OK;
}

/** Find the lowest mapped virtual address in a given page table.
 * @param step   Current step state.
 * @param addr   First address to try; updated on return.
 * @param limit  Last address to try.
 * @returns      Error status.
 */
static addrxlat_status
lowest_mapped_tbl(addrxlat_step_t *step,
		  addrxlat_addr_t *addr, addrxlat_addr_t limit)
{
	int i;
	addrxlat_addr_t nelem;
	addrxlat_addr_t tblmask;
	addrxlat_step_t mystep;
	addrxlat_status status;

	nelem = pf_table_size(&step->meth->param.pgt.pf, step->remain - 1);
	tblmask = pf_table_mask(&step->meth->param.pgt.pf, step->remain - 1);
	memcpy(&mystep, step, sizeof *step);
	while (*addr <= limit) {
		status = internal_step(step);
		if (status == ADDRXLAT_OK) {
			if (step->remain <= 1)
				return internal_step(step);

			status = lowest_mapped_tbl(step, addr, limit);
			if (status != ADDRXLAT_ERR_NOTPRESENT)
				return status;
		} else if (status == ADDRXLAT_ERR_NOTPRESENT) {
			clear_error(step->ctx);
			*addr = (*addr | tblmask) + 1;
		} else
			return status;

		for (i = 0; i < mystep.remain - 1; ++i)
			mystep.idx[i] = 0;
		if (++mystep.idx[i] >= nelem) {
			bury_cache_buffer(&step->ctx->cache, &mystep.base);
			return ADDRXLAT_ERR_NOTPRESENT;
		}
		memcpy(step, &mystep, sizeof *step);
	}

	return ADDRXLAT_ERR_NOTPRESENT;
}

/** Find the lowest mapped virtual address in a given range.
 * @param step   Initial step state.
 * @param addr   First address to try; updated on return.
 * @param limit  Last address to try.
 * @returns      Error status.
 *
 * The initial step state must be initialized same way as for a call
 * to @ref addrxlat_launch.
 */
addrxlat_status
lowest_mapped(addrxlat_step_t *step,
	      addrxlat_addr_t *addr, addrxlat_addr_t limit)
{
	addrxlat_addr_t page_mask;
	int savednoerr;
	addrxlat_status status;

	page_mask = pf_page_mask(&step->meth->param.pgt.pf);
	*addr &= ~page_mask;

	status = internal_launch(step, *addr);
	if (status != ADDRXLAT_OK)
		return status;

	savednoerr = step->ctx->noerr.notpresent;
	step->ctx->noerr.notpresent = 1;
	status = lowest_mapped_tbl(step, addr, limit);
	step->ctx->noerr.notpresent = savednoerr;
	return status;
}

/** Find the highest mapped virtual address in a given page table.
 * @param step   Current step state.
 * @param addr   First address to try; updated on return.
 * @param limit  Last address to try.
 * @returns      Error status.
 */
static addrxlat_status
highest_mapped_tbl(addrxlat_step_t *step,
		   addrxlat_addr_t *addr, addrxlat_addr_t limit)
{
	int i;
	addrxlat_addr_t tblmask;
	addrxlat_step_t mystep;
	addrxlat_status status;

	tblmask = pf_table_mask(&step->meth->param.pgt.pf, step->remain - 1);
	memcpy(&mystep, step, sizeof *step);
	while (*addr >= limit) {
		status = internal_step(step);
		if (status == ADDRXLAT_OK) {
			if (step->remain <= 1)
				return internal_step(step);

			status = highest_mapped_tbl(step, addr, limit);
			if (status != ADDRXLAT_ERR_NOTPRESENT)
				return status;
		} else if (status == ADDRXLAT_ERR_NOTPRESENT) {
			clear_error(step->ctx);
			*addr = (*addr & ~tblmask) - 1;
		} else
			return status;

		for (i = 0; i < mystep.remain - 1; ++i) {
			const addrxlat_paging_form_t *pf =
				&mystep.meth->param.pgt.pf;
			mystep.idx[i] = pf_table_size(pf, i) - 1;
		}
		if (!mystep.idx[i]--) {
			bury_cache_buffer(&step->ctx->cache, &mystep.base);
			return ADDRXLAT_ERR_NOTPRESENT;
		}
		memcpy(step, &mystep, sizeof *step);
	}

	return ADDRXLAT_ERR_NOTPRESENT;
}

/** Find the highest mapped virtual address in a given range.
 * @param step   Initial step state.
 * @param addr   First address to try; updated on return.
 * @param limit  Last address to try.
 * @returns      Error status.
 *
 * The initial step state must be initialized same way as for a call
 * to @ref addrxlat_launch.
 */
addrxlat_status
highest_mapped(addrxlat_step_t *step,
	       addrxlat_addr_t *addr, addrxlat_addr_t limit)
{
	addrxlat_addr_t page_mask;
	int savednoerr;
	addrxlat_status status;

	page_mask = pf_page_mask(&step->meth->param.pgt.pf);
	*addr |= page_mask;

	status = internal_launch(step, *addr);
	if (status != ADDRXLAT_OK)
		return status;

	savednoerr = step->ctx->noerr.notpresent;
	step->ctx->noerr.notpresent = 1;
	status = highest_mapped_tbl(step, addr, limit);
	step->ctx->noerr.notpresent = savednoerr;
	return status;
}

/** Find the lowest unmapped virtual address in a given page table.
 * @param step   Current step state.
 * @param addr   First address to try; updated on return.
 * @param limit  Last address to try.
 * @returns      Error status.
 */
static addrxlat_status
lowest_unmapped_tbl(addrxlat_step_t *step,
		    addrxlat_addr_t *addr, addrxlat_addr_t limit)
{
	int i;
	addrxlat_addr_t nelem;
	addrxlat_addr_t tblmask;
	addrxlat_step_t mystep;
	addrxlat_status status;

	nelem = pf_table_size(&step->meth->param.pgt.pf, step->remain - 1);
	tblmask = pf_table_mask(&step->meth->param.pgt.pf, step->remain - 1);
	memcpy(&mystep, step, sizeof *step);
	while (*addr <= limit) {
		status = internal_step(step);
		if (status == ADDRXLAT_ERR_NOTPRESENT) {
			clear_error(step->ctx);
			return ADDRXLAT_OK;
		} else if (status != ADDRXLAT_OK)
			return status;

		if (step->remain > 1) {
			status = lowest_unmapped_tbl(step, addr, limit);
			if (status != ADDRXLAT_ERR_NOTPRESENT)
				return status;
		} else
			*addr = (*addr | tblmask) + 1;

		for (i = 0; i < mystep.remain - 1; ++i)
			mystep.idx[i] = 0;
		if (++mystep.idx[i] >= nelem) {
			bury_cache_buffer(&step->ctx->cache, &mystep.base);
			break;
		}
		memcpy(step, &mystep, sizeof *step);
	}

	return ADDRXLAT_ERR_NOTPRESENT;
}

/** Find the lowest unmapped virtual address in a given range.
 * @param step   Initial step state.
 * @param addr   First address to try; updated on return.
 * @param limit  Last address to try.
 * @returns      Error status.
 *
 * The initial step state must be initialized same way as for a call
 * to @ref addrxlat_launch.
 */
addrxlat_status
lowest_unmapped(addrxlat_step_t *step,
		addrxlat_addr_t *addr, addrxlat_addr_t limit)
{
	addrxlat_addr_t page_mask;
	addrxlat_status status;

	page_mask = pf_page_mask(&step->meth->param.pgt.pf);
	*addr &= ~page_mask;

	status = internal_launch(step, *addr);
	if (status != ADDRXLAT_OK)
		return status;

	return lowest_unmapped_tbl(step, addr, limit);
}

/** Find the highest linear mapping in a given range.
 * @param step   Initial step state.
 * @param addr   First address to try; updated on return.
 * @param limit  Last address to try.
 * @param off    Required virtual-to-kernel-physical offset.
 * @returns      Error status.
 *
 * The initial step state must be initialized same way as for a call
 * to @ref addrxlat_launch.
 */
addrxlat_status
highest_linear(addrxlat_step_t *step,
	       addrxlat_addr_t *addr, addrxlat_addr_t limit,
	       addrxlat_addr_t off)
{
	addrxlat_addr_t nextaddr = *addr;
	addrxlat_status status;
	addrxlat_status ret = ADDRXLAT_ERR_NOTPRESENT;

	while ( (status = lowest_mapped(step, &nextaddr,
					limit)) == ADDRXLAT_OK) {
		addrxlat_fulladdr_t faddr;

		faddr.as = ADDRXLAT_KVADDR;
		faddr.addr = nextaddr;
		status = internal_fulladdr_conv(&faddr, ADDRXLAT_KPHYSADDR,
						step->ctx, step->sys);
		if (status != ADDRXLAT_OK)
			return status;

		if (faddr.addr - nextaddr != off)
			break;

		/* Assume that the whole range is linear. */
		status = lowest_unmapped(step, &nextaddr, limit);
		if (status != ADDRXLAT_OK &&
		    status != ADDRXLAT_ERR_NOTPRESENT)
			return status;
		*addr = nextaddr - 1;
		ret = ADDRXLAT_OK;
	}

	return (status == ADDRXLAT_OK || status == ADDRXLAT_ERR_NOTPRESENT)
		? ret
		: status;
}
