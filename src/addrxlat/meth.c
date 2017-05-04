/** @internal @file src/addrxlat/meth.c
 * @brief Generic address translation methods.
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

#include <stdlib.h>

#include "addrxlat-priv.h"

static void setup_nometh(addrxlat_meth_t *meth);

DEFINE_ALIAS(meth_new);

addrxlat_meth_t *
addrxlat_meth_new(void)
{
	addrxlat_meth_t *meth = calloc(1, sizeof(addrxlat_meth_t));
	if (meth) {
		meth->refcnt = 1;
		meth->desc.kind = ADDRXLAT_NOMETH;
		setup_nometh(meth);
	}
	return meth;
}

DEFINE_ALIAS(meth_incref);

unsigned long
addrxlat_meth_incref(addrxlat_meth_t *meth)
{
	return ++meth->refcnt;
}

DEFINE_ALIAS(meth_decref);

unsigned long
addrxlat_meth_decref(addrxlat_meth_t *meth)
{
	unsigned long refcnt = --meth->refcnt;
	if (!refcnt) {
		if (meth->desc.kind == ADDRXLAT_LOOKUP &&
		    meth->desc.param.lookup.tbl != NULL)
			free((void*)meth->desc.param.lookup.tbl);
		free(meth);
	}
	return refcnt;
}

/** Null first step function.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 *
 * This method does not modify anything and always fails with
 * @ref ADDRXLAT_ERR_NOMETH.
 */
static addrxlat_status
first_step_nometh(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	return set_error(step->ctx, ADDRXLAT_ERR_NOMETH,
			 "Null translation method");
}

/** Identity next step function.
 * @param walk  Current step state.
 * @returns     Error status.
 *
 * This method does not modify anything and always succeeds.
 */
static addrxlat_status
next_step_ident(addrxlat_step_t *state)
{
	return ADDRXLAT_OK;
}

/** Set up null translation.
 * @param meth  Translation method.
 */
static void
setup_nometh(addrxlat_meth_t *meth)
{
	meth->first_step = first_step_nometh;
	meth->next_step = next_step_ident;
}

/** Set up custom translation.
 * @param meth  Translation method.
 * @param desc  Translation description.
 */
static void
setup_custom(addrxlat_meth_t *meth, const addrxlat_desc_t *desc)
{
	meth->first_step = desc->param.custom.first_step;
	meth->next_step = desc->param.custom.next_step;
}

/** Initialize step state for linear offset.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_linear(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_linear_t *linear = &step->desc->param.linear;

	step->base.as = step->desc->target_as;
	step->base.addr = linear->off;
	step->remain = 1;
	step->elemsz = 1;
	step->idx[0] = addr;

	return ADDRXLAT_OK;
}

/** Set up linear translation.
 * @param meth  Translation method.
 */
static void
setup_linear(addrxlat_meth_t *meth)
{
	meth->first_step = first_step_linear;
	meth->next_step = next_step_ident;
}

/** Initialize step state for page table walk.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Always returns success.
 */
static addrxlat_status
first_step_pgt(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_pgt_t *pgt = &step->desc->param.pgt;
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
	return step->idx[step->desc->param.pgt.pf.nfields]
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
	status = first_step_pgt(step, addr);
	if (status != ADDRXLAT_OK)
		return status;
	return step_check_uaddr(step);
}

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
	const addrxlat_paging_form_t *pf = &step->desc->param.pgt.pf;
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
	status = first_step_pgt(step, addr);
	if (status != ADDRXLAT_OK)
		return status;
	return step_check_saddr(step);
}

/** Page frame number next step function.
 * @param step  Current step state.
 * @returns     Error status.
 *
 * This function handles page frame numbers in a table.
 */
static addrxlat_status
next_step_pfn(addrxlat_step_t *step)
{
	addrxlat_status status;

	status = read_pte(step);
	if (status == ADDRXLAT_OK) {
		const addrxlat_desc_t *desc = step->desc;
		step->base.addr =
			step->raw.pte << desc->param.pgt.pf.fieldsz[0];
		step->base.as = desc->target_as;
		if (step->remain == 1)
			step->elemsz = 1;
	}

	return status;
}

/** Set up page table translation.
 * @param meth  Translation method.
 * @param desc  Translation description.
 * @returns     Error status.
 */
static addrxlat_status
setup_pgt(addrxlat_meth_t *meth, const addrxlat_desc_t *desc)
{
#define SETUP(fmt, first, next)			\
	case fmt:				\
		meth->first_step = first;	\
		meth->next_step = next;		\
		break

	switch (desc->param.pgt.pf.pte_format) {
		SETUP(ADDRXLAT_PTE_NONE, first_step_pgt, next_step_ident);
		SETUP(ADDRXLAT_PTE_PFN32, first_step_uaddr, next_step_pfn);
		SETUP(ADDRXLAT_PTE_PFN64, first_step_uaddr, next_step_pfn);
		SETUP(ADDRXLAT_PTE_IA32, first_step_uaddr, pgt_ia32);
		SETUP(ADDRXLAT_PTE_IA32_PAE, first_step_uaddr, pgt_ia32_pae);
		SETUP(ADDRXLAT_PTE_X86_64, first_step_saddr, pgt_x86_64);
		SETUP(ADDRXLAT_PTE_S390X, first_step_uaddr, pgt_s390x);
		SETUP(ADDRXLAT_PTE_PPC64_LINUX_RPN30,
		      first_step_pgt, pgt_ppc64_linux_rpn30);
	default:
		return ADDRXLAT_ERR_NOTIMPL;
	};

	return ADDRXLAT_OK;
}

/** Initialize step state for table lookup.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_lookup(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_lookup_t *lookup = &step->desc->param.lookup;
	size_t i;

	for (i = 0; i < lookup->nelem; ++i) {
		const addrxlat_lookup_elem_t *elem = &lookup->tbl[i];
		if (elem->orig <= addr &&
		    addr <= elem->orig + lookup->endoff) {
			step->base.as = step->desc->target_as;
			step->base.addr = elem->dest;
			step->remain = 1;
			step->elemsz = 1;
			step->idx[0] = addr - elem->orig;
			return ADDRXLAT_OK;
		}
	}

	return set_error(step->ctx, ADDRXLAT_ERR_NOTPRESENT, "Not mapped");
}

/** Set up table lookup translation.
 * @param meth  Translation method.
 */
static void
setup_lookup(addrxlat_meth_t *meth)
{
	meth->first_step = first_step_lookup;
	meth->next_step = next_step_ident;
}

/** Initialize step state for memory array lookup.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_memarr(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_param_memarr_t *memarr = &step->desc->param.memarr;

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
	const addrxlat_param_memarr_t *memarr = &step->desc->param.memarr;
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
		step->base.as = step->desc->target_as;
		step->elemsz = 1;
	}

	return status;
}


/** Set up memory array translation.
 * @param meth  Translation method.
 */
static void
setup_memarr(addrxlat_meth_t *meth)
{
	meth->first_step = first_step_memarr;
	meth->next_step = next_step_memarr;
}

DEFINE_ALIAS(meth_set_desc);

addrxlat_status
addrxlat_meth_set_desc(addrxlat_meth_t *meth, const addrxlat_desc_t *desc)
{
	addrxlat_status status;

	switch (desc->kind) {
	case ADDRXLAT_NOMETH:
		setup_nometh(meth);
		break;

	case ADDRXLAT_CUSTOM:
		setup_custom(meth, desc);
		break;

	case ADDRXLAT_LINEAR:
		setup_linear(meth);
		break;

	case ADDRXLAT_PGT:
		status = setup_pgt(meth, desc);
		if (status != ADDRXLAT_OK)
			return status;
		break;

	case ADDRXLAT_LOOKUP:
		setup_lookup(meth);
		break;

	case ADDRXLAT_MEMARR:
		setup_memarr(meth);
		break;

	default:
		return ADDRXLAT_ERR_NOTIMPL;
	}

	meth->desc = *desc;
	return ADDRXLAT_OK;
}

const addrxlat_desc_t *
addrxlat_meth_get_desc(const addrxlat_meth_t *meth)
{
	return &meth->desc;
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
	unsigned short i;
	unsigned bits = 0;
	for (i = 0; i < pf->nfields; ++i)
		bits += pf->fieldsz[i];
	return (bits < 8 * sizeof(addrxlat_addr_t)
		? (((addrxlat_addr_t)1 << bits) - 1)
		: ADDRXLAT_ADDR_MAX);
}
