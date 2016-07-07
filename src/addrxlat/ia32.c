/** @internal @file src/addrxlat/ia32.c
 * @brief Routines specific to Intel IA32.
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

/** IA32 vtop function.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
vtop_ia32(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	return set_error(ctx, addrxlat_notimplemented,
			 "IA-32 not yet implemented");
}

/** IA32 PAE vtop function.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 */
addrxlat_status
vtop_ia32_pae(addrxlat_ctx *ctx, addrxlat_vtop_state_t *state)
{
	return set_error(ctx, addrxlat_notimplemented,
			 "IA-32 PAE not yet implemented");
}
