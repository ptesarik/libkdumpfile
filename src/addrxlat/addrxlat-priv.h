/** @internal @file src/addrxlat/addrxlat-priv.h
 * @brief Private interfaces for libaddrxlat (address translation library).
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

#ifndef _ADDRXLAT_PRIV_H
#define _ADDRXLAT_PRIV_H 1

#pragma GCC visibility push(default)
#include "addrxlat.h"
#pragma GCC visibility pop

/* Minimize chance of name clashes (in a static link) */
#ifndef PIC
#define INTERNAL_NAME(x)	_libaddrxlat_priv_ ## x
#else
#define INTERNAL_NAME(x)	x
#endif

/** Maximum length of the error message. */
#define ERRBUF	64

/**  Representation of address translation.
 *
 * This structure contains all internal state needed to perform address
 * translation.
 */
struct _addrxlat_ctx {
	/** Paging form description. */
	const addrxlat_paging_form_t *pf;

	/** Page mask, pre-computed from paging form. */
	addrxlat_addr_t page_mask;

	/** Function to make one step in vtop translation. */
	addrxlat_vtop_step_fn *vtop_step;

	/** Base address of the highest-level page table. */
	addrxlat_fulladdr_t pgt_root;

	char err_buf[ERRBUF];	/**< Error string. */
};

/* utils */

/** Set the error message.
 * @param ctx     Address tranlsation object.
 * @param status  Error status
 * @param msgfmt  Message format string (@c printf style).
 */
#define set_error INTERNAL_NAME(set_error)
addrxlat_status set_error(
	addrxlat_ctx *ctx, addrxlat_status status,
	const char *msgfmt, ...)
	__attribute__ ((format (printf, 3, 4)));

#endif	/* addrxlat-priv.h */
