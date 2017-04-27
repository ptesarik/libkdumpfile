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
 * On successful return, @c step->raw.pte contains the raw
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
		return set_error(step->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unsupported PTE size: %u",
				 1 << pgt->pte_shift);
	}

	if (status == ADDRXLAT_OK)
		step->raw.pte = pte;

	return status;
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
	const addrxlat_param_pgt_t *pgt = &step->meth->desc.param.pgt;
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

DEFINE_ALIAS(launch);

addrxlat_status
addrxlat_launch(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	clear_error(step->ctx);
	return step->meth
		? step->meth->first_step(step, addr)
		: set_error(step->ctx, ADDRXLAT_ERR_NOMETH,
			    "Null translation method");
}

DEFINE_ALIAS(launch_map);

addrxlat_status
addrxlat_launch_map(addrxlat_step_t *step, addrxlat_addr_t addr,
		    const addrxlat_map_t *map)
{
	clear_error(step->ctx);

	step->meth = internal_map_search(map, addr);
	if (!step->meth)
		return set_error(step->ctx, ADDRXLAT_ERR_NOMETH,
				 "No translation method defined");

	return step->meth->first_step(step, addr);
}

DEFINE_ALIAS(step);

addrxlat_status
addrxlat_step(addrxlat_step_t *step)
{
	const addrxlat_meth_t *meth = step->meth;

	clear_error(step->ctx);

	if (!step->remain)
		return ADDRXLAT_OK;

	--step->remain;
	step->base.addr += step->idx[step->remain] * step->elemsz;
	if (!step->remain) {
		step->base.as = meth->desc.target_as;
		step->elemsz = 0;
		return ADDRXLAT_OK;
	}

	return meth->next_step(step);
}

DEFINE_ALIAS(walk);

addrxlat_status
addrxlat_walk(addrxlat_step_t *step)
{
	addrxlat_status status;

	clear_error(step->ctx);

	while (step->remain) {
		status = internal_step(step);
		if (status != ADDRXLAT_OK)
			break;
	}

	return status;
}
