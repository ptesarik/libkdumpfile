/**  @file addrxlat.h
 * Public interface for `libaddrxlat` (address translation library).
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

#ifndef _LIBADDRXLAT_H
#define _LIBADDRXLAT_H	1

#include <stddef.h>
#include <stdint.h>

/** Major version (1st number in the release tag). */
#define LIBADDRXLAT_VER_MAJOR	0
/** Minor version (2nd number in the release tag). */
#define LIBADDRXLAT_VER_MINOR	2
/** Micro version (3rd number in the release tag). */
#define LIBADDRXLAT_VER_MICRO	0

#ifdef  __cplusplus
extern "C" {
#endif

/**  Status code.
 *
 * Positive codes are reserved for future library enhancements. Negative
 * status codes may be used for custom use.
 */
typedef enum _addrxlat_status {
	addrxlat_ok = 0,		/**< Success. */
	addrxlat_notimplemented,	/**< Unimplemented feature. */
} addrxlat_status;

/**  Type of a physical or virtual address.
 *
 * This type is large enough to hold any possible address type on any
 * architecture supported by `libaddrxlat`. Note that this type may
 * be larger than the actual address in the target.
 */
typedef uint_fast64_t addrxlat_addr_t;

/**  Address spaces
 *
 * This type is used to specify the kind of address.
 *
 * The difference between @c KDUMP_KPHYSADDR and @c KDUMP_MACHPHYSADDR
 * matters only in environments where the kernel has a different view
 * of physical address space than the CPU, e.g. paravirtualized kernels
 * under Xen.
 */
typedef enum _addrxlat_addrspace {
	ADDRXLAT_KPHYSADDR,	/**< Kernel physical address. */
	ADDRXLAT_MACHPHYSADDR,	/**< Machine physical address. */
	ADDRXLAT_KVADDR,	/**< Kernel virtual address. */
	ADDRXLAT_XENVADDR,	/**< Xen virtual address.  */
} addrxlat_addrspace_t;

typedef struct _addrxlat_paging_form {
	size_t pteval_size;
	unsigned short levels;
	unsigned short bits[];
} addrxlat_paging_form_t;

typedef struct _addrxlat_ctx addrxlat_ctx;

/** Allocate and initialize a new address translation object.
 * @returns    New initialized object, or @c NULL on failure.
 *
 * This call can fail if and only if memory allocation fails.
 */
addrxlat_ctx *addrxlat_new(void);

/** Free an address translation object.
 * @param ctx  Object to be freed.
 *
 * Free all resources associated with the address translation object.
 * Do not just call @c free(ctx), because that may leak some resources.
 *
 * The object must not be used after calling this function.
 */
void addrxlat_free(addrxlat_ctx *ctx);

/**  Get a detailed error string.
 * @param ctx  Address translation object.
 * @returns    Last error string.
 *
 * If an error status is returned, this function can be used to get
 * a human-readable description of the error. The error string is
 * never reset, so you should check the return status first.
 */
const char *addrxlat_err_str(addrxlat_ctx *ctx);

/** Initialize address translation for a given architecture.
 *
 * @param ctx   Address translation object.
 * @param name  Cannonical architecture name.
 */
addrxlat_status	addrxlat_set_arch(addrxlat_ctx *ctx, const char *name);

/** Set paging form description.
 * @param ctx   Address translation object.
 * @param pf    Paging form description.
 *
 * This function can be used to set the paging form explicitly. Note that
 * the library does not make a copy of the description. In other words,
 * you must ensure that the pointer passed to this function is valid until
 * it is changed again, or the address translation object is destroyed.
 */
void addrxlat_set_paging_form(
	addrxlat_ctx *ctx, const addrxlat_paging_form_t *pf);

/** Get paging form description.
 * @param ctx   Address translation object.
 * @returns     Paging form description.
 */
const addrxlat_paging_form_t *addrxlat_get_paging_form(addrxlat_ctx *ctx);

/** Perform virtual-to-phyiscal address translation using page tables.
 * @param ctx         Address translation object.
 * @param[in] vaddr   Virtual address.
 * @param[out] paddr  Physical address (on succesful return).
 * @returns           Error status.
 */
addrxlat_status addrxlat_vtop_pgt(
	addrxlat_ctx *ctx, addrxlat_addr_t vaddr, addrxlat_addr_t *paddr);

#ifdef  __cplusplus
}
#endif

#endif	/* libaddrxlat.h */
