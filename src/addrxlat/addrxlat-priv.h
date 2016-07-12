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

/* General macros */

/** Number of elements in an array variable. */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/** Maximum length of the error message. */
#define ERRBUF	64

/**  Representation of address translation.
 *
 * This structure contains all internal state needed to perform address
 * translation.
 */
struct _addrxlat_ctx {
	/** Refernce counter. */
	unsigned long refcnt;

	/** Paging form description. */
	addrxlat_paging_form_t pf;

	/** Pointers to root page tables. */
	addrxlat_pgt_root_t pgt_root;

	/** Paging masks, pre-computed from paging form. */
	addrxlat_addr_t pgt_mask[ADDRXLAT_MAXLEVELS];

	/** Function to make one step in vtop translation. */
	addrxlat_vtop_step_fn *vtop_step;

	/** Callback for reading 32-bit integers. */
	addrxlat_read32_fn *cb_read32;

	/** Callback for reading 64-bit integers. */
	addrxlat_read64_fn *cb_read64;

	/** PTE size as a log2 value. */
	unsigned short pte_shift;

	/** Size of virtual address space covered by page tables. */
	unsigned short vaddr_bits;

	char err_buf[ERRBUF];	/**< Error string. */
};

/* vtop */

#define vtop_huge_page INTERNAL_NAME(vtop_huge_page)
addrxlat_status vtop_huge_page(addrxlat_ctx *ctx,
			       addrxlat_vtop_state_t *state);

#define vtop_none INTERNAL_NAME(vtop_none)
addrxlat_vtop_step_fn vtop_none;

#define vtop_ia32 INTERNAL_NAME(vtop_ia32)
addrxlat_vtop_step_fn vtop_ia32;

#define vtop_ia32_pae INTERNAL_NAME(vtop_ia32_pae)
addrxlat_vtop_step_fn vtop_ia32_pae;

#define vtop_x86_64 INTERNAL_NAME(vtop_x86_64)
addrxlat_vtop_step_fn vtop_x86_64;

#define vtop_s390x INTERNAL_NAME(vtop_s390x)
addrxlat_vtop_step_fn vtop_s390x;

#define vtop_ppc64 INTERNAL_NAME(vtop_ppc64)
addrxlat_vtop_step_fn vtop_ppc64;

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
