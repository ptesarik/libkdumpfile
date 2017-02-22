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

static void setup_none(addrxlat_meth_t *meth);

DEFINE_INTERNAL(meth_new);

addrxlat_meth_t *
addrxlat_meth_new(void)
{
	addrxlat_meth_t *meth = calloc(1, sizeof(addrxlat_meth_t));
	if (meth) {
		meth->refcnt = 1;
		meth->def.kind = ADDRXLAT_NONE;
		setup_none(meth);
	}
	return meth;
}

DEFINE_INTERNAL(meth_incref);

unsigned long
addrxlat_meth_incref(addrxlat_meth_t *meth)
{
	return ++meth->refcnt;
}

DEFINE_INTERNAL(meth_decref);

unsigned long
addrxlat_meth_decref(addrxlat_meth_t *meth)
{
	unsigned long refcnt = --meth->refcnt;
	if (!refcnt) {
		if (meth->def.kind == ADDRXLAT_LOOKUP &&
		    meth->def.param.lookup.tbl != NULL)
			free((void*)meth->def.param.lookup.tbl);
		free(meth);
	}
	return refcnt;
}

/** Null first step function.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 *
 * This method does not modify anything and always succeeds.
 */
static addrxlat_status
first_step_none(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	return addrxlat_ok;
}

/** Null next step function.
 * @param walk  Current step state.
 * @returns     Error status.
 *
 * This method does not modify anything and always succeeds.
 */
static addrxlat_status
next_step_none(addrxlat_step_t *state)
{
	return addrxlat_continue;
}

/** Set up null translation.
 * @param meth  Translation method.
 */
static void
setup_none(addrxlat_meth_t *meth)
{
	meth->first_step = first_step_none;
	meth->next_step = next_step_none;
}

/** Initialize step state for linear offset.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_linear(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_def_linear_t *linear = &step->meth->def.param.linear;

	step->base.as = step->meth->def.target_as;
	step->base.addr = -linear->off;
	step->remain = 1;
	step->idx[0] = addr;

	return addrxlat_ok;
}

/** Set up linear translation.
 * @param meth  Translation method.
 */
static void
setup_linear(addrxlat_meth_t *meth)
{
	meth->first_step = first_step_linear;
	meth->next_step = next_step_none;
}

/** Initialize step state for page table walk.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Always returns success.
 */
static addrxlat_status
first_step_pgt(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_def_pgt_t *pgt = &step->meth->def.param.pgt;
	unsigned short i;

	if (pgt->root.as == ADDRXLAT_NOADDR)
		return set_error(step->ctx, addrxlat_nodata,
				 "Page table address not specified");

	step->base = pgt->root;
	step->remain = pgt->pf.levels;
	for (i = 0; i < pgt->pf.levels; ++i) {
		unsigned short bits = pgt->pf.bits[i];
		addrxlat_addr_t mask = bits < sizeof(addrxlat_addr_t) * 8
			? ((addrxlat_addr_t)1 << bits) - 1
			: ~(addrxlat_addr_t)0;
		step->idx[i] = addr & mask;
		addr >>= bits;
	}
	step->idx[i] = addr;
	return addrxlat_ok;
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
	return step->idx[step->meth->def.param.pgt.pf.levels]
		? set_error(step->ctx, addrxlat_invalid,
			    "Virtual address too big")
		: addrxlat_ok;
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
	if (status != addrxlat_ok)
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
	const addrxlat_paging_form_t *pf = &step->meth->def.param.pgt.pf;
	const struct pgt_extra_def *extra = &step->meth->extra.pgt;
	unsigned short lvl = pf->levels;
	struct {
		int bit : 1;
	} s;
	addrxlat_addr_t signext;

	s.bit = step->idx[lvl - 1] >> (pf->bits[lvl - 1] - 1);
	signext = s.bit & (extra->pgt_mask[lvl - 1] >> extra->vaddr_bits);
	return step->idx[lvl] != signext
		? set_error(step->ctx, addrxlat_invalid,
			    "Virtual address too big")
		: addrxlat_ok;
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
	if (status != addrxlat_ok)
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
	if (status != addrxlat_ok)
		return status;

	step->base.addr =
		step->raw_pte << step->meth->def.param.pgt.pf.bits[0];
	step->base.as = step->meth->def.target_as;

	return addrxlat_continue;
}

/** Set up page table translation.
 * @param meth  Translation method.
 * @param def   Translation definition.
 * @returns     Error status.
 */
static addrxlat_status
setup_pgt(addrxlat_meth_t *meth, const addrxlat_def_t *def)
{
	const addrxlat_paging_form_t *pf = &def->param.pgt.pf;
	struct pgt_extra_def *extra = &meth->extra.pgt;
	addrxlat_addr_t mask;
	unsigned short i;

#define SETUP(fmt, first, next, shift)		\
	case fmt:				\
		meth->first_step = first;	\
		meth->next_step = next;		\
		extra->pte_shift = shift;	\
		break

	switch (pf->pte_format) {
		SETUP(addrxlat_pte_none, first_step_pgt, next_step_none, 0);
		SETUP(addrxlat_pte_pfn32, first_step_uaddr, next_step_pfn, 2);
		SETUP(addrxlat_pte_pfn64, first_step_uaddr, next_step_pfn, 3);
		SETUP(addrxlat_pte_ia32, first_step_uaddr, pgt_ia32, 2);
		SETUP(addrxlat_pte_ia32_pae, first_step_uaddr, pgt_ia32_pae, 3);
		SETUP(addrxlat_pte_x86_64, first_step_saddr, pgt_x86_64, 3);
		SETUP(addrxlat_pte_s390x, first_step_uaddr, pgt_s390x, 3);
		SETUP(addrxlat_pte_ppc64_linux_rpn30,
		      first_step_pgt, pgt_ppc64_linux_rpn30, 3);
	default:
		return addrxlat_notimpl;
	};

	extra->vaddr_bits = 0;
	mask = 1;
	for (i = 0; i < pf->levels; ++i) {
		extra->vaddr_bits += pf->bits[i];
		mask <<= pf->bits[i];
		extra->pgt_mask[i] = ~(mask - 1);
	}

	return addrxlat_ok;
}

/** Initialize step state for table lookup.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_lookup(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_def_lookup_t *lookup = &step->meth->def.param.lookup;
	size_t i;

	for (i = 0; i < lookup->nelem; ++i) {
		const addrxlat_lookup_elem_t *elem = &lookup->tbl[i];
		if (elem->orig <= addr &&
		    addr <= elem->orig + lookup->endoff) {
			step->base.as = step->meth->def.target_as;
			step->base.addr = elem->dest;
			step->remain = 1;
			step->idx[0] = addr - elem->orig;
			return addrxlat_ok;
		}
	}

	return set_error(step->ctx, addrxlat_notpresent, "Not mapped");
}

/** Set up table lookup translation.
 * @param meth  Translation method.
 */
static void
setup_lookup(addrxlat_meth_t *meth)
{
	meth->first_step = first_step_lookup;
	meth->next_step = next_step_none;
}

/** Initialize step state for memory array lookup.
 * @param step  Step state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
first_step_memarr(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_def_memarr_t *memarr = &step->meth->def.param.memarr;

	step->base = memarr->base;
	step->remain = 2;
	step->idx[0] = addr & ((1ULL << memarr->shift) - 1);
	step->idx[1] = addr >> memarr->shift;
	return addrxlat_ok;
}

/** Memory array next step function.
 * @param walk  Current step state.
 * @returns     Error status.
 */
static addrxlat_status
next_step_memarr(addrxlat_step_t *step)
{
	const addrxlat_def_memarr_t *memarr = &step->meth->def.param.memarr;
	uint64_t val64;
	uint32_t val32;
	addrxlat_addr_t val;
	addrxlat_status status;

	step->base.addr += step->idx[step->remain] * memarr->elemsz;
	switch (memarr->valsz) {
	case 4:
		status = read32(step, &step->base, &val32,
				"memory array element");
		val =val32;
		break;

	case 8:
		status = read64(step, &step->base, &val64,
				"memory array element");
		val = val64;
		break;

	default:
		return set_error(step->ctx, addrxlat_notimpl,
				 "Unsupported value size: %u", memarr->valsz);
	}

	if (status != addrxlat_ok)
		return status;

	step->base.addr = val << memarr->shift;
	step->base.as = step->meth->def.target_as;

	return addrxlat_continue;
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

DEFINE_INTERNAL(meth_set_def);

addrxlat_status
addrxlat_meth_set_def(addrxlat_meth_t *meth, const addrxlat_def_t *def)
{
	addrxlat_status status;

	switch (def->kind) {
	case ADDRXLAT_NONE:
		setup_none(meth);
		break;

	case ADDRXLAT_LINEAR:
		setup_linear(meth);
		break;

	case ADDRXLAT_PGT:
		status = setup_pgt(meth, def);
		if (status != addrxlat_ok)
			return status;
		break;

	case ADDRXLAT_LOOKUP:
		setup_lookup(meth);
		break;

	case ADDRXLAT_MEMARR:
		setup_memarr(meth);
		break;

	default:
		return addrxlat_notimpl;
	}

	meth->def = *def;
	return addrxlat_ok;
}

const addrxlat_def_t *
addrxlat_meth_get_def(const addrxlat_meth_t *meth)
{
	return &meth->def;
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
	for (i = 0; i < pf->levels; ++i)
		bits += pf->bits[i];
	return (bits < 8 * sizeof(addrxlat_addr_t)
		? (((addrxlat_addr_t)1 << bits) - 1)
		: ADDRXLAT_ADDR_MAX);
}

/** Choose the page table root for a translation definition.
 * @param def   Translation definition.
 * @param meth  Translation method.
 *
 * If @c meth already specifies a page table root, it is reused. If not
 * (e.g. it is a null translation), an ADDRXLAT_NONE address is used to
 * specify that the address is unknown.
 */
void
def_choose_pgtroot(addrxlat_def_t *def, const addrxlat_meth_t *meth)
{
	if (meth->def.kind == ADDRXLAT_PGT)
		def->param.pgt.root = meth->def.param.pgt.root;
	else
		def->param.pgt.root.as = ADDRXLAT_NOADDR;
}
