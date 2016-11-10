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

DEFINE_INTERNAL(meth_new)

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

DEFINE_INTERNAL(meth_incref)

unsigned long
addrxlat_meth_incref(addrxlat_meth_t *meth)
{
	return ++meth->refcnt;
}

DEFINE_INTERNAL(meth_decref)

unsigned long
addrxlat_meth_decref(addrxlat_meth_t *meth)
{
	unsigned long refcnt = --meth->refcnt;
	if (!refcnt)
		free(meth);
	return refcnt;
}

/** Null walk function.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 *
 * This method does not modify anything and always succeeds.
 */
static addrxlat_status
walk_init_none(addrxlat_walk_t *walk, addrxlat_addr_t addr)
{
	return addrxlat_continue;
}

/** Null walk function.
 * @param walk  Page table walk state.
 * @returns     Error status.
 *
 * This method does not modify anything and always succeeds.
 */
static addrxlat_status
step_none(addrxlat_walk_t *state)
{
	return addrxlat_continue;
}

/** Set up null translation.
 * @param meth  Translation method.
 */
static void
setup_none(addrxlat_meth_t *meth)
{
	meth->walk_init = walk_init_none;
	meth->walk_step = step_none;
}

/** Initialize walk state for linear offset.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
walk_init_linear(addrxlat_walk_t *walk, addrxlat_addr_t addr)
{
	const addrxlat_def_linear_t *linear = &walk->meth->def.param.linear;

	walk->base.as = ADDRXLAT_KPHYSADDR;
	walk->base.addr = -linear->off;
	walk->level = 1;
	walk->idx[0] = addr;

	return addrxlat_continue;
}

/** Set up linear translation.
 * @param meth  Translation method.
 */
static void
setup_linear(addrxlat_meth_t *meth)
{
	meth->walk_init = walk_init_linear;
	meth->walk_step = step_none;
}

/** Initialize walk state for page table walk.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Always returns success (@c addrxlat_continue)
 */
addrxlat_status
walk_init_pgt(addrxlat_walk_t *walk, addrxlat_addr_t addr)
{
	const addrxlat_def_pgt_t *pgt = &walk->meth->def.param.pgt;
	unsigned short i;

	walk->base = pgt->root;
	walk->level = pgt->pf.levels;
	for (i = 0; i < pgt->pf.levels; ++i) {
		unsigned short bits = pgt->pf.bits[i];
		addrxlat_addr_t mask = bits < sizeof(addrxlat_addr_t) * 8
			? ((addrxlat_addr_t)1 << bits) - 1
			: ~(addrxlat_addr_t)0;
		walk->idx[i] = addr & mask;
		addr >>= bits;
	}
	walk->idx[i] = addr;
	return addrxlat_continue;
}

/** Check unsigned address overflow.
 * @param walk  Page table walk state.
 * @returns     Error status.
 *
 * This function is meant to be used as a walk init function.
 * It checks whether the input address is too big when interpreted
 * as an unsigned integer.
 */
addrxlat_status
walk_check_uaddr(addrxlat_walk_t *walk)
{
	return walk->idx[walk->meth->def.param.pgt.pf.levels]
		? set_error(walk->ctx, addrxlat_invalid,
			    "Virtual address too big")
		: addrxlat_continue;
}

/** Initialize walk state for unsigned address page table walk.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
addrxlat_status
walk_init_uaddr(addrxlat_walk_t *walk, addrxlat_addr_t addr)
{
	walk_init_pgt(walk, addr);
	return walk_check_uaddr(walk);
}

/** Check signed address overflow.
 * @param walk  Page table walk state.
 * @returns     Error status.
 *
 * This function is meant to be used as a walk init function.
 * It checks whether the input address is too big when interpreted
 * as a signed integer.
 */
addrxlat_status
walk_check_saddr(addrxlat_walk_t *walk)
{
	const addrxlat_paging_form_t *pf = &walk->meth->def.param.pgt.pf;
	const struct pgt_extra_def *extra = &walk->meth->extra.pgt;
	unsigned short lvl = pf->levels;
	struct {
		int bit : 1;
	} s;
	addrxlat_addr_t signext;

	s.bit = walk->idx[lvl - 1] >> (pf->bits[lvl - 1] - 1);
	signext = s.bit & (extra->pgt_mask[lvl - 1] >> extra->vaddr_bits);
	return walk->idx[lvl] != signext
		? set_error(walk->ctx, addrxlat_invalid,
			    "Virtual address too big")
		: addrxlat_continue;
}

/** Initialize walk state for signed address page table walk.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
addrxlat_status
walk_init_saddr(addrxlat_walk_t *walk, addrxlat_addr_t addr)
{
	walk_init_pgt(walk, addr);
	return walk_check_saddr(walk);
}

struct pte_def {
	addrxlat_walk_init_fn *init;
	addrxlat_walk_step_fn *step;
	unsigned short shift;
};

/** Set up page table translation.
 * @param meth  Translation method.
 * @param def   Translation definition.
 * @returns     Error status.
 */
static addrxlat_status
setup_pgt(addrxlat_meth_t *meth, const addrxlat_def_t *def)
{
	static const struct pte_def formats[] = {
		[addrxlat_pte_none] = { walk_init_pgt, step_none, 0 },
		[addrxlat_pte_ia32] = { walk_init_uaddr, pgt_ia32, 2 },
		[addrxlat_pte_ia32_pae] = { walk_init_uaddr, pgt_ia32_pae, 3 },
		[addrxlat_pte_x86_64] = { walk_init_saddr, pgt_x86_64, 3 },
		[addrxlat_pte_s390x] = { walk_init_uaddr, pgt_s390x, 3 },
		[addrxlat_pte_ppc64_linux_rpn30] =
			{ walk_init_pgt, pgt_ppc64_linux_rpn30, 3 },
	};

	const addrxlat_paging_form_t *pf = &def->param.pgt.pf;
	struct pgt_extra_def *extra = &meth->extra.pgt;
	const struct pte_def *fmt;
	addrxlat_addr_t mask;
	unsigned short i;

	if (pf->pte_format >= ARRAY_SIZE(formats))
		return addrxlat_notimpl;

	fmt = &formats[pf->pte_format];
	meth->walk_init = fmt->init;
	meth->walk_step = fmt->step;
	extra->pte_shift = fmt->shift;

	extra->vaddr_bits = 0;
	mask = 1;
	for (i = 0; i < pf->levels; ++i) {
		extra->vaddr_bits += pf->bits[i];
		mask <<= pf->bits[i];
		extra->pgt_mask[i] = ~(mask - 1);
	}

	return addrxlat_ok;
}

DEFINE_INTERNAL(meth_set_def)

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
