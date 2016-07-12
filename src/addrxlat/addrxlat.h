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
#include <inttypes.h>

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
	addrxlat_notimpl,		/**< Unimplemented feature. */
	addrxlat_continue,		/**< Repeat the last step. */
	addrxlat_notpresent,		/**< Page not present. */
	addrxlat_invalid,		/**< Invalid address. */
} addrxlat_status;

/**  Type of a physical or virtual address.
 *
 * This type is large enough to hold any possible address type on any
 * architecture supported by `libaddrxlat`. Note that this type may
 * be larger than the actual address in the target.
 */
typedef uint_fast64_t addrxlat_addr_t;

/**  Type for a PTE value.
 *
 * Use this type to work with PTE values. Note that this type may be
 * bigger than the actual PTE on a given architecture and always uses
 * host byte order, so variables of this type are not suitable for use
 * as a buffer.
 */
typedef uint_fast64_t addrxlat_pte_t;

/** @name fprintf() macros for addrxlat types
 * @{
 *
 * These macros are similar to POSIX @c PRI_xxx macros. Each of these
 * macros expands to a character string literal containing a conversion
 * specifier, possibly modified by a length modifier, suitable for use
 * within the format argument of a formatted input/output function when
 * converting the corresponding integer type.
 */
#define ADDRXLAT_PRIoADDR	PRIoFAST64 /**< Octal address */
#define ADDRXLAT_PRIuADDR	PRIuFAST64 /**< Decimal address */
#define ADDRXLAT_PRIxADDR	PRIxFAST64 /**< Lowercase hex address */
#define ADDRXLAT_PRIXADDR	PRIXFAST64 /**< Uppercase hex address */

#define ADDRXLAT_PRIoPTE	PRIoFAST64 /**< Octal PTE */
#define ADDRXLAT_PRIuPTE	PRIuFAST64 /**< Decimal PTE */
#define ADDRXLAT_PRIxPTE	PRIxFAST64 /**< Lowercase hex PTE */
#define ADDRXLAT_PRIXPTE	PRIXFAST64 /**< Uppercase hex PTE */
/* @} */

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

/** Scope of a virtual address.
 * This defines whether the address is valid for kernel objects,
 * or user-space objects.
 */
typedef enum _addrxlat_vaddr_scope {
	ADDRXLAT_SCOPE_KERNEL,	/**< Kernel-space virtual address. */
	ADDRXLAT_SCOPE_USER,	/**< User-space virtual address. */
} addrxlat_vaddr_scope_t;

/** Full address (including address space specification).
 */
typedef struct _addrxlat_fulladdr {
	addrxlat_addr_t addr;	 /**< Raw address. */
	addrxlat_addrspace_t as; /**< Address space for @c addr. */
} addrxlat_fulladdr_t;

/** Root page table specification.
 * This is the base address of the highest-level page table.
 */
typedef struct _addrxlat_pgt_root {
	addrxlat_fulladdr_t kernel; /**< Kernel-space root page table. */
	addrxlat_fulladdr_t user;   /**< User-space root page table. */
} addrxlat_pgt_root_t;

/** Page table entry format.
 */
typedef enum _addrxlat_pte_format {
	addrxlat_pte_none,	/**< Undefined */
	addrxlat_pte_ia32,	/**< Original 32-bit Intel */
	addrxlat_pte_ia32_pae,	/**< Intel IA32 with PAE */
	addrxlat_pte_x86_64,	/**< AMD64 (Intel 64)  */
	addrxlat_pte_s390x,	/**< IBM z/Architecture (64-bit) */
	addrxlat_pte_ppc64,	/**< IBM POWER (64-bit) */
} addrxlat_pte_format_t;

/** Maximum address translation levels.
 * This is a theoretical limit, with enough reserve for future enhancements.
 * Currently, IBM z/Architecture has up to 5 levels, but only 4 are used
 * by the Linux kernel. All other architectures have less paging levels.
 */
#define ADDRXLAT_MAXLEVELS	8

typedef struct _addrxlat_paging_form {
	addrxlat_pte_format_t pte_format;

	/** Real PFN shift.
	 * This is only used on powerpc and specifies the bit position
	 * of the PFN inside the PTE (or huge PTE).
	 */
	unsigned short rpn_shift;

	unsigned short levels;
	unsigned short bits[ADDRXLAT_MAXLEVELS];
} addrxlat_paging_form_t;

typedef struct _addrxlat_ctx addrxlat_ctx;

/** Allocate and initialize a new address translation object.
 * @returns    New initialized object, or @c NULL on failure.
 *
 * This call can fail if and only if memory allocation fails.
 * The reference count of the newly created object is one.
 */
addrxlat_ctx *addrxlat_new(void);

/** Increment the reference counter.
 * @param ctx  Address translation object.
 * @returns    New reference count.
 */
unsigned long addrxlat_incref(addrxlat_ctx *ctx);

/** Decrement the reference counter.
 * @param ctx  Address translation object.
 * @returns    New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
unsigned long addrxlat_decref(addrxlat_ctx *ctx);

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
 * @returns     Error status.
 *
 * This function can be used to set the paging form explicitly. Note that
 * the library does not make a copy of the description. In other words,
 * you must ensure that the pointer passed to this function is valid until
 * it is changed again, or the address translation object is destroyed.
 */
addrxlat_status addrxlat_set_paging_form(
	addrxlat_ctx *ctx, const addrxlat_paging_form_t *pf);

/** Get paging form description.
 * @param ctx   Address translation object.
 * @returns     Paging form description.
 */
const addrxlat_paging_form_t *addrxlat_get_paging_form(addrxlat_ctx *ctx);

/** Set page table root address.
 * @param ctx   Address translation object.
 * @param root  Root page table definition.
 *
 * The @c root pointer need not stay valid after this function returns;
 * the library makes an internal copy of the root page table definition.
 */
void addrxlat_set_pgt_root(addrxlat_ctx *ctx, const addrxlat_pgt_root_t *root);

/** Get page table root address.
 * @param ctx  Address translation object.
 * @returns    Pointer to the object's root page table definition.
 *
 * This function does not make a copy of the definition. It returns
 * a pointer to the internal structure, so:
 *   - The returned pointer is valid only as long as @c ctx is valid.
 *   - The referenced structure is subject to change (e.g. if you call
 *     @ref addrxlat_set_pgt_root).
 */
const addrxlat_pgt_root_t *addrxlat_get_pgt_root(addrxlat_ctx *ctx);

/** Data type for one-by-one VTOP translation. */
typedef struct _addrxlat_vtop_state {
	/** Page table level. */
	unsigned short level;

	/** Virtual address scope (user or kernel). */
	addrxlat_vaddr_scope_t scope;

	/** On input, base address of the page table.
	 * On output base address of the lower-level page table or
	 * the target physical address.
	 */
	addrxlat_fulladdr_t base;

	/** Raw PTE value.
	 * This value is stored on output, but it may be also used
	 * as input for the next step.
	 */
	addrxlat_pte_t raw_pte;

	/** Table indices at individual levels.
	 *
	 * There is one extra index, which contains the remaining part
	 * of the virtual address after all page table bits were used.
	 */
	addrxlat_addr_t idx[ADDRXLAT_MAXLEVELS + 1];
} addrxlat_vtop_state_t;

/** Type of the callback to make one step in vtop translation.
 * @param ctx    Address translation object.
 * @param state  Translation state.
 * @returns      Error status.
 *
 * The function is first called by @ref addrxlat_vtop_start to allow
 * arch-specific initialization (or direct translation). For this initial
 * call:
 *   - @c state->level is set to zero
 *   - @c state->scope is set to the virtual address scope
 *   - @c state->base is set to @c pgt_root
 *   - virtual address is broken down to table indices in @c state->idx
 *   - @c state->raw_pte is left uninitialized
 *
 * The function is then called repeatedly with a non-zero @c state->level
 * and @c state->raw_pte already filled from the page table. On each of
 * these subsequent calls, the callback should interpret the PTE value
 * and update @state.
 *
 * The function returns:
 *   - @c addrxlat_continue if another step is necessary,
 *   - @c addrxlat_ok if @state->base contains the address, or
 *   - an appropriate error code.
 *
 * Note that page offset is automatically added by the caller if the
 * callback returns @c addrxlat_continue and @c state->level is 1.
 *
 * The callback function is explicitly allowed to modify @c state->level
 * and/or the indices in @c state->idx[]. This is needed if some levels
 * of paging are skipped (huge pages).
 */
typedef addrxlat_status addrxlat_vtop_step_fn(
	addrxlat_ctx *ctx, addrxlat_vtop_state_t *state);

/** Start gradual virtual-to-physical address translation.
 * @param ctx            Address translation object.
 * @param[in] scope      Scope (kernel-space or user-space).
 * @param[in] vaddr      Virtual address.
 * @param[out] state     Translation state.
 * @returns              Error status.
 */
addrxlat_status addrxlat_vtop_start(
	addrxlat_ctx *ctx,
	addrxlat_vaddr_scope_t scope, addrxlat_addr_t vaddr,
	addrxlat_vtop_state_t *state);

/** Perform one step in virtual-to-physical address translation.
 * @param ctx            Address translation object.
 * @param[in,out] state  Translation state.
 * @returns              Error status.
 */
addrxlat_status addrxlat_vtop_next(
	addrxlat_ctx *ctx, addrxlat_vtop_state_t *state);

/** Perform virtual-to-phyiscal address translation using page tables.
 * @param ctx         Address translation object.
 * @param[in] scope   Scope (kernel-space or user-space).
 * @param[in] vaddr   Virtual address.
 * @param[out] paddr  Physical address (on succesful return).
 * @returns           Error status.
 */
addrxlat_status addrxlat_vtop_pgt(
	addrxlat_ctx *ctx,
	addrxlat_vaddr_scope_t scope, addrxlat_addr_t vaddr,
	addrxlat_addr_t *paddr);

/** Type of the read callback for 32-bit integers.
 * @param ctx       Address translation object.
 * @param[in] addr  Address of the 32-bit integer.
 * @param[out] val  Value in host byte order.
 * @param data      Arbitrary user-supplied data.
 * @returns         Error status.
 */
typedef addrxlat_status addrxlat_read32_fn(
	addrxlat_ctx *ctx, addrxlat_fulladdr_t addr, uint32_t *val,
	void *data);

/** Set the read callback for 32-bit integers.
 * @param ctx  Address translation object.
 * @param cb   New callback function.
 * @returns    Previous callback function.
 */
addrxlat_read32_fn *addrxlat_cb_read32(
	addrxlat_ctx *ctx, addrxlat_read32_fn *cb);

/** Type of the read callback for 64-bit integers.
 * @param ctx       Address translation object.
 * @param[in] addr  Address of the 64-bit integer.
 * @param[out] val  Value in host byte order.
 * @param data      Arbitrary user-supplied data.
 * @returns         Error status.
 */
typedef addrxlat_status addrxlat_read64_fn(
	addrxlat_ctx *ctx, addrxlat_fulladdr_t addr, uint64_t *val,
	void *data);

/** Set the read callback for 64-bit integers.
 * @param ctx  Address translation object.
 * @param cb   New callback function.
 * @returns    Previous callback function.
 */
addrxlat_read64_fn *addrxlat_cb_read64(
	addrxlat_ctx *ctx, addrxlat_read64_fn *cb);

#ifdef  __cplusplus
}
#endif

#endif	/* libaddrxlat.h */
