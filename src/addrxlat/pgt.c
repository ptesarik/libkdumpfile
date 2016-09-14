/** @internal @file src/addrxlat/pgt.c
 * @brief Page table translation.
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

static addrxlat_walk_init_fn walk_init_none;
static addrxlat_walk_init_fn walk_init_linear;
static addrxlat_pgt_step_fn pgt_none;

DEFINE_INTERNAL(pgt_new)

addrxlat_pgt_t *
addrxlat_pgt_new(void)
{
	addrxlat_pgt_t *pgt = calloc(1, sizeof(addrxlat_pgt_t));
	if (pgt) {
		pgt->refcnt = 1;
		pgt->walk_init = walk_init_none;
		pgt->step = pgt_none;
		pgt->kind = ADDRXLAT_NONE;
	}
	return pgt;
}

DEFINE_INTERNAL(pgt_incref)

unsigned long
addrxlat_pgt_incref(addrxlat_pgt_t *pgt)
{
	return ++pgt->refcnt;
}

DEFINE_INTERNAL(pgt_decref)

unsigned long
addrxlat_pgt_decref(addrxlat_pgt_t *pgt)
{
	unsigned long refcnt = --pgt->refcnt;
	if (!refcnt)
		free(pgt);
	return refcnt;
}

addrxlat_method_t
addrxlat_pgt_get_kind(const addrxlat_pgt_t *pgt)
{
	return pgt->kind;
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
pgt_none(addrxlat_walk_t *state)
{
	return addrxlat_continue;
}

/** Initialize walk state for linear offset.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 */
static addrxlat_status
walk_init_linear(addrxlat_walk_t *walk, addrxlat_addr_t addr)
{
	const struct linear_xlat *linear = &walk->pgt->linear;

	walk->base.as = ADDRXLAT_KPHYSADDR;
	walk->base.addr = -linear->off;
	walk->level = 1;
	walk->idx[0] = addr;

	return addrxlat_continue;
}

addrxlat_status
addrxlat_pgt_set_offset(addrxlat_pgt_t *pgt, addrxlat_off_t off)
{
	pgt->walk_init = walk_init_linear;
	pgt->step = pgt_none;
	pgt->kind = ADDRXLAT_LINEAR;
	pgt->linear.off = off;
	return addrxlat_ok;
}

/** Initialize walk state for page table walk.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Always returns success (@c addrxlat_continue)
 */
addrxlat_status
walk_init_pgt(addrxlat_walk_t *walk, addrxlat_addr_t addr)
{
	const struct pgt_xlat *pgt = &walk->pgt->pgt;
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
	return walk->idx[walk->pgt->pgt.pf.levels]
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
	const struct pgt_xlat *pgt = &walk->pgt->pgt;
	unsigned short lvl = pgt->pf.levels;
	struct {
		int bit : 1;
	} s;
	addrxlat_addr_t signext;

	s.bit = walk->idx[lvl - 1] >> (pgt->pf.bits[lvl - 1] - 1);
	signext = s.bit & (pgt->pgt_mask[lvl - 1] >> pgt->vaddr_bits);
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
	addrxlat_pgt_step_fn *step;
	unsigned short shift;
};

DEFINE_INTERNAL(pgt_set_form)

addrxlat_status
addrxlat_pgt_set_form(addrxlat_pgt_t *pgt, const addrxlat_paging_form_t *pf)
{
	static const struct pte_def formats[] = {
		[addrxlat_pte_none] = { walk_init_pgt, pgt_none, 0 },
		[addrxlat_pte_ia32] = { walk_init_uaddr, pgt_ia32, 2 },
		[addrxlat_pte_ia32_pae] = { walk_init_uaddr, pgt_ia32_pae, 3 },
		[addrxlat_pte_x86_64] = { walk_init_saddr, pgt_x86_64, 3 },
		[addrxlat_pte_s390x] = { walk_init_uaddr, pgt_s390x, 3 },
		[addrxlat_pte_ppc64] = { walk_init_ppc64, pgt_ppc64, 3 },
	};

	const struct pte_def *fmt;
	addrxlat_addr_t mask;
	unsigned short i;

	if (pf->pte_format >= ARRAY_SIZE(formats))
		return addrxlat_notimpl;

	fmt = &formats[pf->pte_format];
	pgt->walk_init = fmt->init;
	pgt->step = fmt->step;
	pgt->kind = ADDRXLAT_PGT;
	pgt->pgt.pte_shift = fmt->shift;
	pgt->pgt.pf = *pf;

	pgt->pgt.vaddr_bits = 0;
	mask = 1;
	for (i = 0; i < pf->levels; ++i) {
		pgt->pgt.vaddr_bits += pf->bits[i];
		mask <<= pf->bits[i];
		pgt->pgt.pgt_mask[i] = ~(mask - 1);
	}

	return addrxlat_ok;
}

const addrxlat_paging_form_t *
addrxlat_pgt_get_form(const addrxlat_pgt_t *pgt)
{
	return &pgt->pgt.pf;
}

void
addrxlat_pgt_set_root(addrxlat_pgt_t *pgt, const addrxlat_fulladdr_t *root)
{
	pgt->pgt.root = *root;
}

const addrxlat_fulladdr_t *
addrxlat_pgt_get_root(const addrxlat_pgt_t *pgt)
{
	return &pgt->pgt.root;
}
