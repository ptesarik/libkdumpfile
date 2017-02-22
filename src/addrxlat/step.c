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

#include "addrxlat-priv.h"

/** Read the raw PTE value.
 * @param step  Current step state.
 * @returns     Error status.
 *
 * On successful return, @c step->raw_pte contains the raw
 * PTE value for the current translation step.
 */
addrxlat_status
read_pte(addrxlat_step_t *step)
{
	const struct pgt_extra_def *pgt = &step->meth->extra.pgt;
	uint64_t pte64;
	uint32_t pte32;
	addrxlat_pte_t pte;
	addrxlat_status status;

	step->base.addr += step->idx[step->remain] << pgt->pte_shift;

	switch(pgt->pte_shift) {
	case 2:
		status = read32(step, &step->base, &pte32, "PTE");
		pte = pte32;
		break;

	case 3:
		status = read64(step, &step->base, &pte64, "PTE");
		pte = pte64;
		break;

	default:
		return set_error(step->ctx, addrxlat_notimpl,
				 "Unsupported PTE size: %u",
				 1 << pgt->pte_shift);
	}

	if (status == addrxlat_ok)
		step->raw_pte = pte;

	return status;
}

/** Update current step state for huge page.
 * @param step  Current step state.
 * @returns     Always @c addrxlat_continue.
 *
 * This function skips all lower paging levels and updates the state
 * so that the next page table step adds the correct page offset and
 * terminates.
 */
addrxlat_status
pgt_huge_page(addrxlat_step_t *step)
{
	const addrxlat_def_pgt_t *pgt = &step->meth->def.param.pgt;
	addrxlat_addr_t off = 0;

	while (step->remain > 1) {
		--step->remain;
		off |= step->idx[step->remain];
		off <<= pgt->pf.bits[step->remain - 1];
	}
	step->idx[0] |= off;
	return addrxlat_continue;
}

DEFINE_INTERNAL(step);

addrxlat_status
addrxlat_step(addrxlat_step_t *step)
{
	const addrxlat_meth_t *meth = step->meth;

	clear_error(step->ctx);

	if (!step->remain)
		return addrxlat_ok;

	--step->remain;
	if (!step->remain) {
		step->base.addr += step->idx[0];
		step->base.as = meth->def.target_as;
		return addrxlat_ok;
	}

	return meth->next_step(step);
}

DEFINE_INTERNAL(walk);

addrxlat_status
addrxlat_walk(addrxlat_step_t *step)
{
	addrxlat_status status;

	clear_error(step->ctx);

	do {
		status = internal_step(step);
	} while (status == addrxlat_continue);

	return status;
}

DEFINE_INTERNAL(launch_meth);

addrxlat_status
addrxlat_launch_meth(addrxlat_step_t *step, addrxlat_ctx_t *ctx,
		     const addrxlat_meth_t *meth, addrxlat_addr_t addr)
{
	clear_error(ctx);

	step->ctx = ctx;
	step->sys = NULL;
	step->meth = meth;
	return meth->first_step(step, addr);
}
