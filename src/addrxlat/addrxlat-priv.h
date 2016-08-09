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

#ifndef PIC
#define INTERNAL_ALIAS(x)		addrxlat_ ## x
#define _DECLARE_INTERNAL(s, a)
#define _DEFINE_INTERNAL(s, a)
#else
#define INTERNAL_ALIAS(x)		internal_ ## x
#define _DECLARE_INTERNAL(s, a)		\
	extern typeof(s) (a);
#define _DEFINE_INTERNAL(s, a)		\
	extern typeof(s) (a)		\
	__attribute__((alias(#s)));
#endif

/** Internal alias declaration. */
#define DECLARE_INTERNAL(x) _DECLARE_INTERNAL(addrxlat_ ## x, internal_ ## x)

/** Define an internal alias for a symbol. */
#define DEFINE_INTERNAL(x) _DEFINE_INTERNAL(addrxlat_ ## x, internal_ ## x)

/* General macros */

/** Number of elements in an array variable. */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/** Maximum length of the error message. */
#define ERRBUF	64

/** Internal state for address translation using page tables.
 * Page table translation uses some pre-computed values, which are
 * stored in this structure on initialization.
 */
struct _addrxlat_pgt {
	/** Reference counter. */
	unsigned long refcnt;

	/** Function to make one step in page table translation. */
	addrxlat_pgt_step_fn *pgt_step;

	/** PTE size as a log2 value. */
	unsigned short pte_shift;

	/** Size of virtual address space covered by page tables. */
	unsigned short vaddr_bits;

	/** Paging form description. */
	addrxlat_paging_form_t pf;

	/** Paging masks, pre-computed from paging form. */
	addrxlat_addr_t pgt_mask[ADDRXLAT_MAXLEVELS];
};

/**  Representation of address translation.
 *
 * This structure contains all internal state needed to perform address
 * translation.
 */
struct _addrxlat_ctx {
	/** Reference counter. */
	unsigned long refcnt;

	/** Callback private data. */
	void *priv;

	/** Callback for reading 32-bit integers. */
	addrxlat_read32_fn *cb_read32;

	/** Callback for reading 64-bit integers. */
	addrxlat_read64_fn *cb_read64;

	/** Page table translation object. */
	addrxlat_pgt_t *pgt;

	char err_buf[ERRBUF];	/**< Error string. */
};

/* vtop */

#define pgt_huge_page INTERNAL_NAME(pgt_huge_page)
addrxlat_status pgt_huge_page(addrxlat_ctx *ctx,
			      addrxlat_pgt_state_t *state);

#define pgt_none INTERNAL_NAME(pgt_none)
addrxlat_pgt_step_fn pgt_none;

#define pgt_ia32 INTERNAL_NAME(pgt_ia32)
addrxlat_pgt_step_fn pgt_ia32;

#define pgt_ia32_pae INTERNAL_NAME(pgt_ia32_pae)
addrxlat_pgt_step_fn pgt_ia32_pae;

#define pgt_x86_64 INTERNAL_NAME(pgt_x86_64)
addrxlat_pgt_step_fn pgt_x86_64;

#define pgt_s390x INTERNAL_NAME(pgt_s390x)
addrxlat_pgt_step_fn pgt_s390x;

#define pgt_ppc64 INTERNAL_NAME(pgt_ppc64)
addrxlat_pgt_step_fn pgt_ppc64;

/* map by OS */

#define map_os_x86_64 INTERNAL_NAME(map_os_x86_64)
addrxlat_status map_os_x86_64(
	addrxlat_ctx *ctx, const addrxlat_osdesc_t *osdesc,
	addrxlat_pgt_t *pgt, addrxlat_map_t **pmap);

/* internal aliases */

#define internal_pgt_new INTERNAL_ALIAS(pgt_new)
DECLARE_INTERNAL(pgt_new)

#define internal_pgt_incref INTERNAL_ALIAS(pgt_incref)
DECLARE_INTERNAL(pgt_incref)

#define internal_pgt_decref INTERNAL_ALIAS(pgt_decref)
DECLARE_INTERNAL(pgt_decref)

#define internal_pgt_set_form INTERNAL_ALIAS(pgt_set_form)
DECLARE_INTERNAL(pgt_set_form)

#define internal_pgt_start INTERNAL_ALIAS(pgt_start)
DECLARE_INTERNAL(pgt_start)

#define internal_pgt_next INTERNAL_ALIAS(pgt_next)
DECLARE_INTERNAL(pgt_next)

#define internal_pgt INTERNAL_ALIAS(pgt)
DECLARE_INTERNAL(pgt)

#define internal_by_def INTERNAL_ALIAS(by_def)
DECLARE_INTERNAL(by_def)

#define internal_map_set INTERNAL_ALIAS(map_set)
DECLARE_INTERNAL(map_set)

#define internal_map_search INTERNAL_ALIAS(map_search)
DECLARE_INTERNAL(map_search)

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
