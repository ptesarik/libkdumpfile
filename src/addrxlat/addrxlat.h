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

#ifndef _ADDRXLAT_H
#define _ADDRXLAT_H	1

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
	addrxlat_nodata,		/**< Uninitialized data. */

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

/** Address translation method. */
typedef struct _addrxlat_meth addrxlat_meth_t;

/** Address translation kind.
 */
typedef enum _addrxlat_kind {
	/** No mapping set. */
	ADDRXLAT_NONE,

	/** Linear mapping: dest = src + off. */
	ADDRXLAT_LINEAR,

	/** Page table walk. */
	ADDRXLAT_PGT,

	/** Table lookup. */
	ADDRXLAT_LOOKUP,

	/** Array in target memory. */
	ADDRXLAT_MEMARR,
} addrxlat_kind_t;

/** Allocate a translation method.
 * @returns    New initialized object, or @c NULL on failure.
 *
 * This call can fail if and only if memory allocation fails.
 * The reference count of the newly created object is one.
 */
addrxlat_meth_t *addrxlat_meth_new(void);

/** Increment translation method reference counter.
 * @param meth  Translation method.
 * @returns     New reference count.
 */
unsigned long addrxlat_meth_incref(addrxlat_meth_t *meth);

/** Decrement translation method reference counter.
 * @param meth  Translation method.
 * @returns     New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
unsigned long addrxlat_meth_decref(addrxlat_meth_t *meth);

/** Parameters of linear translation. */
typedef struct _addrxlat_def_linear {
	addrxlat_off_t off;	/**< Address offset. */
} addrxlat_def_linear_t;

/** Page table entry format.
 */
typedef enum _addrxlat_pte_format {
	addrxlat_pte_none,	/**< Undefined */
	addrxlat_pte_pfn32,	/**< 32-bit page frame number */
	addrxlat_pte_pfn64,	/**< 64-bit page frame number */
	addrxlat_pte_ia32,	/**< Original 32-bit Intel */
	addrxlat_pte_ia32_pae,	/**< Intel IA32 with PAE */
	addrxlat_pte_x86_64,	/**< AMD64 (Intel 64)  */
	addrxlat_pte_s390x,	/**< IBM z/Architecture (64-bit) */

	/** IBM POWER (64-bit) running Linux with RPN shift 30 (64k pages) */
	addrxlat_pte_ppc64_linux_rpn30,
} addrxlat_pte_format_t;

/** Maximum address translation levels.
 * This is a theoretical limit, with enough reserve for future enhancements.
 * Currently, IBM z/Architecture has up to 5 levels, but only 4 are used
 * by the Linux kernel. All other architectures have less paging levels.
 */
#define ADDRXLAT_MAXLEVELS	8

typedef struct _addrxlat_paging_form {
	/** Format of each page table entry. */
	addrxlat_pte_format_t pte_format;

	/** Number of paging levels.
	 * Note that this is one higher than the number of page tables,
	 * because adding the offset within a page is also counted as
	 * one level here.
	 */
	unsigned short levels;

	/** Number of bits in each source address part.
	 * This array is sorted from lowest-level tables to the top level;
	 * the first element corresponds to page size.
	 */
	unsigned short bits[ADDRXLAT_MAXLEVELS];
} addrxlat_paging_form_t;

/** Parameters of page table translation. */
typedef struct _addrxlat_def_pgt {
	addrxlat_fulladdr_t root;  /**< Root page table address. */
	addrxlat_paging_form_t pf; /**< Paging form. */
} addrxlat_def_pgt_t;

/** Lookup table element.
 * This defines address mapping for a single object.
 * Addresses inside the object are mapped linearly using an offset.
 */
typedef struct _addrxlat_lookup_elem {
	addrxlat_addr_t orig;	/**< Original address. */
	addrxlat_addr_t dest;	/**< Corresponding destination address. */
} addrxlat_lookup_elem_t;

/** Parameters of table lookup translation. */
typedef struct _addrxlat_def_lookup {
	/** Max address offset inside each object.
	 * This is in fact object size - 1. However, specifying the end
	 * offset gives maximum flexibility (from 1-byte objects to the
	 * full size of the address space).
	 */
	addrxlat_addr_t endoff;

	/** Size of the table. */
	size_t nelem;

	/** Lookup table.
	 * The lookup table is owned by the translation method, i.e. it
	 * is freed when the method reference count becomes zero.
	 */
	const addrxlat_lookup_elem_t *tbl;
} addrxlat_def_lookup_t;

/** Parameters of memory array translation. */
typedef struct _addrxlat_def_memarr {
	/** Base address of the translation array. */
	addrxlat_fulladdr_t base;

	/** Address bit shift.
	 * The address is shifted right by this many bits to
	 * get the corresponding index inside the memory array.
	 * The target value is then shifted left and remaining
	 * bits are copied from the source address.
	 * The intention is to allow indexing by page frame number.
	 */
	unsigned shift;

	/** Size of each array element. */
	unsigned elemsz;

	/** Size of the value. */
	unsigned valsz;
} addrxlat_def_memarr_t;

/** Parameters of the translation method. */
typedef union _addrxlat_def_param {
	addrxlat_def_linear_t linear; /**< For @ref ADDRXLAT_LINEAR. */
	addrxlat_def_pgt_t pgt;	      /**< For @ref ADDRXLAT_PGT. */
	addrxlat_def_lookup_t lookup; /**< For @ref ADDRXLAT_LOOKUP.  */
	addrxlat_def_memarr_t memarr; /**< For @ref ADDRXLAT_MEMARR. */
} addrxlat_def_param_t;

/** Address translation definition. */
typedef struct _addrxlat_def {
	/** Kind of translation method. */
	addrxlat_kind_t kind;

	/** Target address space. */
	addrxlat_addrspace_t target_as;

	/** Additional parameters. */
	addrxlat_def_param_t param;
} addrxlat_def_t;

/** Set up a translation definition.
 * @param meth  Translation method.
 * @param def   Translation definition.
 * @returns     Error status.
 */
addrxlat_status addrxlat_meth_set_def(addrxlat_meth_t *meth,
				      const addrxlat_def_t *def);

/** Get the translation definition.
 * @param meth  Translation method.
 * @returns     Translation definition.
 *
 * The returned pointer is valid as long as you hold a reference to
 * the translation object. It does not change by subsequent calls to
 * @ref addrxlat_meth_set_def (but the referenced value does).
 */
const addrxlat_def_t *addrxlat_meth_get_def(const addrxlat_meth_t *meth);

typedef struct _addrxlat_ctx addrxlat_ctx_t;

/** Allocate and initialize a new address translation context.
 * @returns    New initialized context, or @c NULL on failure.
 *
 * This call can fail if and only if memory allocation fails.
 * The reference count of the newly created object is one.
 */
addrxlat_ctx_t *addrxlat_ctx_new(void);

/** Increment the reference counter.
 * @param ctx  Address translation context.
 * @returns    New reference count.
 */
unsigned long addrxlat_ctx_incref(addrxlat_ctx_t *ctx);

/** Decrement the reference counter.
 * @param ctx  Address translation context.
 * @returns    New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
unsigned long addrxlat_ctx_decref(addrxlat_ctx_t *ctx);

/**  Get a detailed error string.
 * @param ctx  Address translation context.
 * @returns    Last error string.
 *
 * If an error status is returned, this function can be used to get
 * a human-readable description of the error. The error string is
 * never reset, so you should check the return status first.
 */
const char *addrxlat_ctx_err(addrxlat_ctx_t *ctx);

/**  Set private callback data.
 * @param ctx  Address translation context.
 * @param data Generic data pointer.
 *
 * Callback data can be used to associate the address translation context
 * with an arbitrary object. The addrxlat library does not interpret the
 * pointer in any way, but it is passed as the first argument to callback
 * functions. It can also be retrieved with @ref addrxlat_ctx_get_cbdata.
 */
void addrxlat_ctx_set_cbdata(addrxlat_ctx_t *ctx, void *data);

/**  Get private callback data.
 * @param ctx  Address translation context.
 * @returns    Pointer stored previously with @ref addrxlat_ctx_set_cbdata.
 */
void *addrxlat_ctx_get_cbdata(addrxlat_ctx_t *ctx);

/** Type of symbolic information. */
typedef enum _addrxlat_sym_type {
	/** Register value.
	 * Input:
	 * - @c args[0] = register name
	 * Output:
	 * - @c val = register value
	 */
	ADDRXLAT_SYM_REG,

	/** Symbol value.
	 * Input:
	 * - @c args[0] = symbol name
	 * Output:
	 * - @c val = symbol value (e.g. address of a variable)
	 */
	ADDRXLAT_SYM_VALUE,

	/** Size of an object.
	 * Input:
	 * - @c args[0] = name of symbol or data type
	 * Output:
	 * - @c val = @c sizeof(args[0])
	 */
	ADDRXLAT_SYM_SIZEOF,

	/** Offset of a member within a structure.
	 * Input:
	 * - @c args[0] = container name (e.g. of a @c struct)
	 * - @c args[1] = element name (e.g. a structure member)
	 * Output:
	 * - @c val = @c offsetof(args[0],args[1])
	 */
	ADDRXLAT_SYM_OFFSETOF,
} addrxlat_sym_type_t;

/** Data structure used to hold symbolic information. */
typedef struct _addrxlat_sym {
	/** [out] Resolved value. */
	addrxlat_addr_t val;

	/** [in] Type of information. */
	addrxlat_sym_type_t type;

	/** [in] Symbolic arguments. */
	const char *args[];
} addrxlat_sym_t;

/** Type of the symbolic information callback.
 * @param data  Arbitrary user-supplied data.
 * @param sym   Symbolic information, updated on success.
 * @returns     Error status.
 *
 * The callback function should check the information type and fill in
 * the output fields in @c sym. If it is called for a type that is not
 * handled (including an unknown type, not listed above), it must return
 * @ref addrxlat_notimpl,
 */
typedef addrxlat_status addrxlat_sym_fn(void *data, addrxlat_sym_t *sym);

/** Set the symbolic information callback.
 * @param ctx  Address translation context.
 * @param cb   New callback function.
 * @returns    Previous callback function.
 */
addrxlat_sym_fn *addrxlat_ctx_cb_sym(
	addrxlat_ctx_t *ctx, addrxlat_sym_fn *cb);

/** Type of the read callback for 32-bit integers.
 * @param data      Arbitrary user-supplied data.
 * @param[in] addr  Address of the 32-bit integer.
 * @param[out] val  Value in host byte order.
 * @returns         Error status.
 */
typedef addrxlat_status addrxlat_read32_fn(
	void *data, const addrxlat_fulladdr_t *addr, uint32_t *val);

/** Set the read callback for 32-bit integers.
 * @param ctx  Address translation context.
 * @param cb   New callback function.
 * @returns    Previous callback function.
 */
addrxlat_read32_fn *addrxlat_ctx_cb_read32(
	addrxlat_ctx_t *ctx, addrxlat_read32_fn *cb);

/** Type of the read callback for 64-bit integers.
 * @param data      Arbitrary user-supplied data.
 * @param[in] addr  Address of the 64-bit integer.
 * @param[out] val  Value in host byte order.
 * @returns         Error status.
 */
typedef addrxlat_status addrxlat_read64_fn(
	void *data, const addrxlat_fulladdr_t *addr, uint64_t *val);

/** Set the read callback for 64-bit integers.
 * @param ctx  Address translation context.
 * @param cb   New callback function.
 * @returns    Previous callback function.
 */
addrxlat_read64_fn *addrxlat_ctx_cb_read64(
	addrxlat_ctx_t *ctx, addrxlat_read64_fn *cb);

/** Data type for a single page table walk. */
typedef struct _addrxlat_walk {
	/** Address translation context. */
	addrxlat_ctx_t *ctx;

	/** Translation method. */
	const addrxlat_meth_t *meth;

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
} addrxlat_walk_t;

/** Type of the function which initializes a page table walk.
 * @param walk  Page table walk state.
 * @param addr  Address to be translated.
 * @returns     Error status.
 *
 * This function is called by @ref addrxlat_walk_init to initialize
 * the walk state. Only @c ctx and @c pgt is set by the caller, other
 * fields are left uninitialized.
 */
typedef addrxlat_status addrxlat_walk_init_fn(
	addrxlat_walk_t *walk, addrxlat_addr_t addr);

/** Type of the function which moves to the next-level page table.
 * @param walk  Page table walk state.
 * @returns     Error status.
 *
 * This function is called repeatedly with a non-zero @c walk->level
 * and @c walk->raw_pte already filled from the page table. On each of
 * these subsequent calls, the callback should interpret the PTE value
 * and update @c walk.
 *
 * The function returns:
 *   - @c addrxlat_continue if another step is necessary,
 *   - @c addrxlat_ok if @c walk->base contains the address, or
 *   - an appropriate error code.
 *
 * Note that page offset is automatically added by the caller if the
 * callback returns @c addrxlat_continue and @c walk->level is 1.
 *
 * The callback function is explicitly allowed to modify @c walk->level
 * and/or the indices in @c walk->idx[]. This is needed if some levels
 * of paging are skipped (huge pages).
 */
typedef addrxlat_status addrxlat_walk_step_fn(addrxlat_walk_t *walk);

/** Initialize page-table walk.
 * @param walk  Page table walk state.
 * @param ctx   Address translation context.
 * @param meth  Translation method.
 * @param add   Address to be translated.
 * @returns     Error status.
 *
 * If an error is returned, this function also sets the error message
 * in @c ctx.
 */
addrxlat_status addrxlat_walk_init(
	addrxlat_walk_t *walk, addrxlat_ctx_t *ctx,
	const addrxlat_meth_t *meth, addrxlat_addr_t addr);

/** Descend one level in page table translation.
 * @param walk  Page table walk state.
 * @returns     Error status.
 */
addrxlat_status addrxlat_walk_next(addrxlat_walk_t *walk);

/** Translate an address using page tables.
 * @param ctx    Address translation context.
 * @param meth   Translation method.
 * @param paddr  Address to be translated.
 * @returns      Error status.
 *
 * On successful return, the resulting address is found in @c *paddr.
 */
addrxlat_status addrxlat_walk(addrxlat_ctx_t *ctx, const addrxlat_meth_t *meth,
			      addrxlat_addr_t *paddr);

/** Definition of an address range.
 */
typedef struct _addrxlat_range {
	/** Max address offset inside the range. */
	addrxlat_addr_t endoff;

	/** Translation method */
	addrxlat_meth_t *meth;
} addrxlat_range_t;

/**  Address translation map.
 * Note that the start address does not have to be stored in the
 * structure. The first range in a map starts at address 0, and
 * each following range starts right after the previous one (i.e.
 * at @c endoff + 1).
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

/** Find an address translation method in a translation map.
 * @param map   Address translation map.
 * @param addr  Address to be translated.
 * @returns     Translation method, or @c NULL if not found.
 *
 * It is allowed to pass @c NULL as the translation map; the result
 * is the same as if an empty map was given, i.e. the function always
 * returns @c NULL.
 */
addrxlat_meth_t *addrxlat_map_search(
	const addrxlat_map_t *map, addrxlat_addr_t addr);

/** Clean up all data used by a translation map.
 * @param map  Address translation map.
 *
 * This function re-initializes the translation map, freeing up all
 * associated resources. The resulting empty map may be reused after
 * calling this function.
 */
void addrxlat_map_clear(addrxlat_map_t *map);

/** Translate an address using a translation map.
 * @param ctx            Address translation context.
 * @param[in,out] paddr  Address.
 * @param[in] map        Translation map.
 * @returns              Error status.
 */
addrxlat_status addrxlat_by_map(
	addrxlat_ctx_t *ctx, addrxlat_fulladdr_t *paddr,
	const addrxlat_map_t *map);

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

	/** Further options, e.g. architecture variant */
	const char *opts;
} addrxlat_osdesc_t;

/** Linux kernel version code.
 * This macro can be used to convert a three-part Linux kernel version
 * to a single number for use as @c ver in @ref addrxlat_osdesc_t.
 */
#define ADDRXLAT_VER_LINUX(a,b,c)	\
	(((a) << 16) + ((b) << 8) + (c))

/** Xen version code.
 * This macro can be used to convert a Xen major/minor version pair
 * to a single number for use as @c ver in @ref addrxlat_osdesc_t.
 */
#define ADDRXLAT_VER_XEN(major,minor)	\
	(((major) << 16) | (minor))

/** Address translations system.
 * In addition to a @ref addrxlat_map_t, this structure also contains
 * any OS-specific data.
 */
typedef struct _addrxlat_sys addrxlat_sys_t;

/** Allocate a new translation system.
 * @returns  A new translation system, or @c NULL.
 *
 * This call can fail if and only if memory allocation fails.
 */
addrxlat_sys_t *addrxlat_sys_new(void);

/** Increment translation system reference counter.
 * @param sys    Translation system.
 * @returns      New reference count.
 */
unsigned long addrxlat_sys_incref(addrxlat_sys_t *sys);

/** Decrement translation system reference counter.
 * @param sys    Translation system.
 * @returns      New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
unsigned long addrxlat_sys_decref(addrxlat_sys_t *sys);

/** Set up a translation system for a pre-defined operating system.
 * @param sys     Translation sytem.
 * @param ctx     Address translation context.
 * @param osdesc  Description of the operating system.
 * @returns       Error status.
 *
 * This function uses OS-specific data and built-in heuristics to
 * determine the translation map and page-table translation for an
 * operating system.
 */
addrxlat_status addrxlat_sys_init(
	addrxlat_sys_t *sys, addrxlat_ctx_t *ctx,
	const addrxlat_osdesc_t *osdesc);

/** Translation system map index.
 *
 * The OS map object contains several translation maps to allow
 * translation between different address spaces. They can be
 * manipulated directly using
 * @ref addrxlat_sys_set_map and
 * @ref addrxlat_sys_get_map
 * using one of these indices.
 */
typedef enum _addrxlat_sys_map {
	/** Map kernel virtual addresses to physical addresses.
	 * This translation accepts @ref ADDRXLAT_KVADDR on input
	 * and translates it to a physical address. This is either
	 * @ref ADDRXLAT_KPHYSADDR or @ref ADDRXLAT_MACHPHYSADDR,
	 * whichever is more efficient.
	 */
	ADDRXLAT_SYS_MAP_KV_PHYS,

	/** Map kernel physical addresses to a direct-mapped
	 * virtual address.
	 */
	ADDRXLAT_SYS_MAP_KPHYS_DIRECT,

	/** Map machine physical addresses to kernel physical addresses.
	 */
	ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS,

	/** Map kernel physical addresses to machine physical addresses.
	 */
	ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS,

	ADDRXLAT_SYS_MAP_NUM,	/**< Total number of indices. */
} addrxlat_sys_map_t;

/** Explicitly set the translation map of an OS map object.
 * @param sys     Translation system.
 * @param idx     Map index.
 * @param map     Translation map.
 */
void addrxlat_sys_set_map(
	addrxlat_sys_t *sys, addrxlat_sys_map_t idx,
	addrxlat_map_t *map);

/** Get the translation map of an OS map object.
 * @param sys     Translation system.
 * @param idx     Map index.
 * @returns       Associated translation map.
 */
const addrxlat_map_t *addrxlat_sys_get_map(
	const addrxlat_sys_t *sys, addrxlat_sys_map_t idx);

/** Translation system method index.
 *
 * A translation system uses a number of translation methods to do its job.
 * Any of them can be obtained with
 * @ref addrxlat_sys_get_meth or overridden with
 * @ref addrxlat_sys_set_meth using one of these indices.
 */
typedef enum _addrxlat_sys_meth {
	ADDRXLAT_SYS_METH_PGT,	   /**< Kernel-space page table. */
	ADDRXLAT_SYS_METH_UPGT,	   /**< User-space page table. */
	ADDRXLAT_SYS_METH_DIRECT,  /**< Direct mapping. */
	ADDRXLAT_SYS_METH_KTEXT,   /**< Kernel text mapping. */
	ADDRXLAT_SYS_METH_VMEMMAP, /**< Fixed VMEMMAP (on IBM POWER). */

	ADDRXLAT_SYS_METH_RDIRECT, /**< Reverse direct mapping. */

	/** Default machine physical to kernel physical mapping. */
	ADDRXLAT_SYS_METH_MACHPHYS_KPHYS,

	/**< Default kernel physical to machine physical mapping. */
	ADDRXLAT_SYS_METH_KPHYS_MACHPHYS,

	ADDRXLAT_SYS_METH_NUM,	   /**< Total number of indices. */
} addrxlat_sys_meth_t;

/** Explicitly set an address translation method for a translation system.
 * @param sys     Translation system.
 * @param idx     Translation method index.
 * @param meth    New translation method.
 */
void addrxlat_sys_set_meth(
	addrxlat_sys_t *sys, addrxlat_sys_meth_t idx,
	addrxlat_meth_t *meth);

/** Get a specific translation method of a translation system.
 * @param sys     Translation system.
 * @param idx     Translation method index.
 * @returns       Associated translation method.
 */
addrxlat_meth_t *addrxlat_sys_get_meth(
	addrxlat_sys_t *sys, addrxlat_sys_meth_t idx);

#ifdef  __cplusplus
}
#endif

#endif	/* addrxlat.h */
