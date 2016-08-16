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
	addrxlat_nomem,			/**< Memory allocation failure. */

	/** Base for custom status codes.
	 * More importantly, this enumerator forces the whole enum
	 * type to be signed, so you can compare it against 0 without
	 * an explicit typecast to a signed integer.
	 */
	addrxlat_custom_status_base = -1
} addrxlat_status;

/**  Type of a physical or virtual address.
 *
 * This type is large enough to hold any possible address type on any
 * architecture supported by `libaddrxlat`. Note that this type may
 * be larger than the actual address in the target.
 */
typedef uint_fast64_t addrxlat_addr_t;

/**  Maximum value that can be represented by addrxlat_addr_t.
 */
#define ADDRXLAT_ADDR_MAX	(~(addrxlat_addr_t)0)

/**  Type of an address offset.
 *
 * This type is as large as @ref addrxlat_addr_t, but it is signed,
 * so suitable for offsets, both positive and negative.
 */
typedef int_fast64_t addrxlat_off_t;

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

	ADDRXLAT_NOADDR = -1,	/**< Invalid address. */
} addrxlat_addrspace_t;

/** Full address (including address space specification).
 */
typedef struct _addrxlat_fulladdr {
	addrxlat_addr_t addr;	 /**< Raw address. */
	addrxlat_addrspace_t as; /**< Address space for @c addr. */
} addrxlat_fulladdr_t;

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

/** Address translation using page tables. */
typedef struct _addrxlat_pgt addrxlat_pgt_t;

/** Allocate a new page table translation object.
 * @returns    New initialized object, or @c NULL on failure.
 *
 * This call can fail if and only if memory allocation fails.
 * The reference count of the newly created object is one.
 */
addrxlat_pgt_t *addrxlat_pgt_new(void);

/** Increment page table translation reference counter.
 * @param pgt  Page table translation object.
 * @returns    New reference count.
 */
unsigned long addrxlat_pgt_incref(addrxlat_pgt_t *pgt);

/** Decrement page table translation reference counter.
 * @param pgt  Page table translation object.
 * @returns    New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
unsigned long addrxlat_pgt_decref(addrxlat_pgt_t *pgt);

/** Set paging form description.
 * @param pgt  Page table translation object.
 * @param pf   Paging form description.
 * @returns    Error status.
 *
 * This function sets the paging form and initializes pre-computed
 * internal state of te page table translation object. It also stores
 * a copy of the paging form description inside the translation object.
 */
addrxlat_status addrxlat_pgt_set_form(
	addrxlat_pgt_t *pgt, const addrxlat_paging_form_t *pf);

/** Get paging form description.
 * @param pgt  Page table translation object.
 * @returns    Pointer to the internal paging form description.
 *
 * The returned pointer is valid as long as you hold a reference to
 * the translation object. It does not change by subsequent calls to
 * @ref addrxlat_pgt_set_form (but the referenced value does).
 */
const addrxlat_paging_form_t *addrxlat_pgt_get_form(addrxlat_pgt_t *pgt);

/** Set root page table base address.
 * @param pgt   Page table translation object.
 * @param root  Address of the root page table.
 *
 * This function stores a copy of the root page table base address in
 */
void addrxlat_pgt_set_root(
	addrxlat_pgt_t *pgt, const addrxlat_fulladdr_t *root);

/** Get root page table base address.
 * @param  pgt  Page table translation object.
 * @returns     Pointer to the internal root page table.
 *
 * The returned pointer is valid as long as you hold a reference to
 * the translation object. It does not change by subsequent calls to
 * @ref addrxlat_pgt_set_root (but the referenced value does).
 */
const addrxlat_fulladdr_t *addrxlat_pgt_get_root(const addrxlat_pgt_t *pgt);

/** Set page table translation.
 * @param ctx   Address translation object.
 * @param pgt   Page table translation object (or @c NULL).
 */
void addrxlat_set_pgt(addrxlat_ctx *ctx, addrxlat_pgt_t *pgt);

/** Get the page table translation object associated with a context.
 * @param ctx   Address translation object.
 * @returns     Associated page table translation object (new reference).
 *
 * Note that the return value may be @c NULL if page table translation
 * is not available for the given context.
 */
addrxlat_pgt_t *addrxlat_get_pgt(addrxlat_ctx *ctx);

/** Create a new page table translation and assign it to a context.
 * @param ctx  Address translation object.
 * @param pf   Paging form description.
 * @returns    Error status.
 *
 * This is a shorthand for creating a new page table translation object,
 * initializing it from the given paging form and assigning it to the
 * address translation context.
 */
addrxlat_status addrxlat_set_paging_form(
	addrxlat_ctx *ctx, const addrxlat_paging_form_t *pf);

/** Data type for a single page table walk. */
typedef struct _addrxlat_pgt_walk {
	/** Address translation context. */
	addrxlat_ctx *ctx;

	/** Page table level. */
	unsigned short level;

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
} addrxlat_pgt_walk_t;

/** Type of the function which moves to the next-level page table.
 * @param state  Page table walk state.
 * @returns      Error status.
 *
 * The function is first called by @ref addrxlat_pgt_start to allow
 * arch-specific initialization (or direct translation). For this initial
 * call:
 *   - @c state->level is set to zero
 *   - @c state->base is set to the highest-level page table origin
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
typedef addrxlat_status addrxlat_pgt_step_fn(addrxlat_pgt_walk_t *state);

/** Start page-table address translation.
 * @param state     Page table walk state.
 * @param[in] addr  Address to be translated.
 * @returns         Error status.
 *
 * Most of the state gets initialized by this function. The following
 * fields should be set by the caller prior to calling this function:
 *   - @c ctx:  set to the context used for the translation
 *   - @c base: set to the root page table origin
 */
addrxlat_status addrxlat_pgt_start(addrxlat_pgt_walk_t *state,
				   addrxlat_addr_t addr);

/** Descend one level in page table translation.
 * @param[in,out] state  Page table walk state.
 * @returns              Error status.
 */
addrxlat_status addrxlat_pgt_next(addrxlat_pgt_walk_t *state);

/** Translate an address using page tables.
 * @param[in,out] state  Page table walk state.
 * @param[in] addr       Address to be translated.
 * @returns              Error status.
 *
 * On input, fill in @c state->ctx and @c state->base
 * (see @ref addrxlat_pgt_start for details).
 * On successful return, the resulting address is found in @c state->base.
 */
addrxlat_status addrxlat_pgt(addrxlat_pgt_walk_t *state, addrxlat_addr_t addr);

/** Address translation method.
 */
typedef enum _addrxlat_method {
	/** No mapping set. */
	ADDRXLAT_NONE,

	/** Linear mapping: dest = src + off. */
	ADDRXLAT_LINEAR,

	/** Linear mapping with indirect offset: dest = src + *poff. */
	ADDRXLAT_LINEAR_IND,

	/** Page tables. */
	ADDRXLAT_PGT,

	/** Page tables with indirect origin (*ppgt). */
	ADDRXLAT_PGT_IND,
} addrxlat_method_t;

/** Address translation definition.
 * This structure holds all information required to translate an address
 * using one of the available methods.
 */
typedef struct _addrxlat_def {
	/** Address translation method. */
	addrxlat_method_t method;

	union {
		/** Offset used by @ref ADDRXLAT_LINEAR. */
		addrxlat_off_t off;

		/** Pointer to offset used by @ref ADDRXLAT_LINEAR_IND. */
		const addrxlat_off_t *poff;

		/** Page table origin used by @ref ADDRXLAT_PGT. */
		addrxlat_fulladdr_t pgt;

		/** Pointer to page table origin used by
		 * @ref ADDRXLAT_PGT_IND. */
		const addrxlat_fulladdr_t *ppgt;
	};
} addrxlat_def_t;

/** Translate an address using a single translation definition.
 * @param ctx           Address translation object.
 * @param[in,out] addr  Address.
 * @param[in] def       Translation definition.
 * @returns             Error status.
 */
addrxlat_status addrxlat_by_def(
	addrxlat_ctx *ctx, addrxlat_addr_t *addr, const addrxlat_def_t *def);

/** Definition of an address range.
 */
typedef struct _addrxlat_range {
	/** Max address offset inside the range. */
	addrxlat_addr_t endoff;

	/** Translation definition */
	addrxlat_def_t xlat;
} addrxlat_range_t;

/**  Address translation map.
 */
typedef struct _addrxlat_map {
	/** Number of elements in @c ranges. */
	size_t n;

	/** Actual range definitions. */
	addrxlat_range_t ranges[];
} addrxlat_map_t;

/** Set map translation for an address range.
 * @param map    Address translation map.
 * @param addr   Range start address.
 * @param range  Translation range definition.
 * @returns      Updated map, or @c NULL on allocation error.
 *
 * If this function fails, the original @c map is left untouched.
 */
addrxlat_map_t *
addrxlat_map_set(addrxlat_map_t *map, addrxlat_addr_t addr,
		 const addrxlat_range_t *range);

/** Find an address translation definition in a translation map.
 * @param map   Address translation map.
 * @param addr  Address to be translated.
 * @returns     Translation definition.
 *
 * It is allowed to pass @c NULL as the translation map. The function
 * always returns a pointer to a static variable for @ref ADDRXLAT_NONE.
 */
const addrxlat_def_t *addrxlat_map_search(
	const addrxlat_map_t *map, addrxlat_addr_t addr);

/** Translate an address using a translation map.
 * @param ctx            Address translation object.
 * @param[in,out] paddr  Address.
 * @param[in] map        Translation map.
 * @returns              Error status.
 */
addrxlat_status addrxlat_by_map(
	addrxlat_ctx *ctx, addrxlat_addr_t *paddr, const addrxlat_map_t *map);

/** Operating system type. */
typedef enum _addrxlat_ostype {
	addrxlat_os_unknown,	/**< Unknown OS. */
	addrxlat_os_linux,	/**< Linux kernel. */
	addrxlat_os_xen,	/**< Xen hypervisor. */
} addrxlat_ostype_t;

/** Description of an operating system.
 * This structure is used to pass some details about the operating system
 * to set up a translation map.
 */
typedef struct _addrxlat_osdesc {
	/** Operating system type. */
	addrxlat_ostype_t type;

	/** Operating system version. */
	unsigned long ver;

	/** Architecture name. */
	const char *arch;

	/** Root page table base. */
	const addrxlat_fulladdr_t *pgtaddr;
} addrxlat_osdesc_t;

/** Set up translation for a given operating system.
 * @param ctx         Address translation object.
 * @param[in] osdesc  Description of the operating system.
 * @param[out] ppgt   Page table translation on successful return.
 * @param[out] pmap   Translation map on successful return.
 * @returns           Error status.
 *
 * This function uses OS-specific data and built-in heuristics to
 * determine the translation map for an operating system.
 */
addrxlat_status addrxlat_init_os(addrxlat_ctx *ctx,
				 const addrxlat_osdesc_t *osdesc,
				 addrxlat_pgt_t **ppgt, addrxlat_map_t **pmap);

/** Type of the read callback for 32-bit integers.
 * @param data      Arbitrary user-supplied data.
 * @param[in] addr  Address of the 32-bit integer.
 * @param[out] val  Value in host byte order.
 * @returns         Error status.
 */
typedef addrxlat_status addrxlat_read32_fn(
	void *data, const addrxlat_fulladdr_t *addr, uint32_t *val);

/** Set the read callback for 32-bit integers.
 * @param ctx  Address translation object.
 * @param cb   New callback function.
 * @returns    Previous callback function.
 */
addrxlat_read32_fn *addrxlat_cb_read32(
	addrxlat_ctx *ctx, addrxlat_read32_fn *cb);

/** Type of the read callback for 64-bit integers.
 * @param data      Arbitrary user-supplied data.
 * @param[in] addr  Address of the 64-bit integer.
 * @param[out] val  Value in host byte order.
 * @returns         Error status.
 */
typedef addrxlat_status addrxlat_read64_fn(
	void *data, const addrxlat_fulladdr_t *addr, uint64_t *val);

/** Set the read callback for 64-bit integers.
 * @param ctx  Address translation object.
 * @param cb   New callback function.
 * @returns    Previous callback function.
 */
addrxlat_read64_fn *addrxlat_cb_read64(
	addrxlat_ctx *ctx, addrxlat_read64_fn *cb);

/**  Set pointer to user private data.
 * @param ctx  Address translation object.
 * @param data Generic data pointer.
 *
 * A private pointer can be used to associate the address translation
 * object with arbitrary data. The addrxlat library does not use the
 * pointer in any way, but it can be retrieved later from a @ref addrxlat_ctx
 * pointer with @ref addrxlat_get_priv.
 */
void addrxlat_set_priv(addrxlat_ctx *ctx, void *data);

/**  Get pointer to user private data.
 * @param ctx  Address translation object.
 * @returns    The data pointer stored previously with @ref addrxlat_set_priv.
 */
void *addrxlat_get_priv(addrxlat_ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif	/* libaddrxlat.h */
