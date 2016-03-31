/** @internal @file src/kdumpfile-priv.h
 * @brief Private interfaces for libkdumpfile (kernel coredump file access).
 */
/* Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#ifndef _KDUMPFILE_PRIV_H
#define _KDUMPFILE_PRIV_H	1

#include "config.h"

#pragma GCC visibility push(default)
#include "kdumpfile.h"
#pragma GCC visibility pop

#include "list.h"
#include "threads.h"

#include <endian.h>

/* Minimize chance of name clashes (in a static link) */
#ifndef PIC
#define INTERNAL_NAME(x)	_libkdump_priv_ ## x
#else
#define INTERNAL_NAME(x)	x
#endif

/* Older glibc didn't have the byteorder macros */
#ifndef be16toh

#include <byteswap.h>

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htobe16(x) bswap_16(x)
#  define htole16(x) (x)
#  define be16toh(x) bswap_16(x)
#  define le16toh(x) (x)

#  define htobe32(x) bswap_32(x)
#  define htole32(x) (x)
#  define be32toh(x) bswap_32(x)
#  define le32toh(x) (x)

#  define htobe64(x) bswap_64(x)
#  define htole64(x) (x)
#  define be64toh(x) bswap_64(x)
#  define le64toh(x) (x)
# else
#  define htobe16(x) (x)
#  define htole16(x) bswap_16(x)
#  define be16toh(x) (x)
#  define le16toh(x) bswap_16(x)

#  define htobe32(x) (x)
#  define htole32(x) bswap_32(x)
#  define be32toh(x) (x)
#  define le32toh(x) bswap_32(x)

#  define htobe64(x) (x)
#  define htole64(x) bswap_64(x)
#  define be64toh(x) (x)
#  define le64toh(x) bswap_64(x)
# endif
#endif

/* This should cover all possibilities:
 * - no supported architecture has less than 4K pages.
 * - PowerPC can have up to 256K large pages.
 */
#define MIN_PAGE_SIZE	(1UL << 12)
#define MAX_PAGE_SIZE	(1UL << 18)

/* General macros */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/** Bits per byte.
 * Use this instead of a magic constant to illustrate why something
 * is multiplied by 8. */
#define BITS_PER_BYTE	8

/** Type of a Page Frame Number (PFN).
 * This type is big enough to represent any PFN. It is equal to
 * @ref kdump_addr_t, because there is probably no type that would
 * have @c arch.page_shift less bits than @ref kdump_addr_t.
 */
typedef kdump_addr_t kdump_pfn_t;

/** Bits for kdump_pfn_t */
#define PFN_BITS		(BITS_PER_BYTE * sizeof(kdump_pfn_t))

/** Error status for non-matching probe.
 * This error status must never be returned through the public API.
 * It is intended to let the open method know that the file cannot
 * be handled by the current format operations, but it is not really
 * an error.
 */
#define kdump_noprobe	((kdump_status)-1)

enum kdump_arch {
	ARCH_UNKNOWN = 0,
	ARCH_AARCH64,
	ARCH_ALPHA,
	ARCH_ARM,
	ARCH_IA32,
	ARCH_IA64,
	ARCH_MIPS,
	ARCH_PPC,
	ARCH_PPC64,
	ARCH_S390,
	ARCH_S390X,
	ARCH_X86_64,
};

struct cache_entry;

/**  Page I/O information.
 * This structure is used to pass information between @ref kdump_read
 * and the format-specific I/O methods.
 */
struct page_io {
	kdump_pfn_t pfn;	/**< PFN under I/O. */
	struct cache_entry *ce;	/**< Buffer cache entry. */
	int precious;		/**< Is this page precious? */
};

struct kdump_shared;

struct format_ops {
	/**  Format name (identifier).
	 * This is a unique identifier for the dump file format. In other
	 * words, there is a 1:1 mapping between this identifier and the
	 * access methods for the corresponding dump file.
	 */
	const char *name;

	/* Probe for a given file format.
	 * Input:
	 *   ctx->ops        ops with the probe function
	 * Output:
	 *   ctx->format     descriptive name of the file format
	 *   ctx->arch       target architecture (if known)
	 *   ctx->endian     dump file endianness
	 *   ctx->ptr_size   target pointer size (in bytes)
	 *   ctx->page_size  target page size
	 *   ctx->utsname    filled in as much as possible
	 *   ctx->ops        possibly modified
	 * Return:
	 *   kdump_ok        can be handled by these ops
	 *   kdump_noprobe   cannot be handled by these ops
	 *   or any other kdump_* error status
	 */
	kdump_status (*probe)(kdump_ctx *ctx, void *hdr);

	/* Read a (machine physical) page from the dump file.
	 * Input:
	 *   ctx->fd         core dump file descriptor open for reading
	 * Return:
	 *   kdump_ok        buffer is filled with page data
	 *   kdump_nodata    data for the given page is not present
	 */
	kdump_status (*read_page)(kdump_ctx *ctx, struct page_io *pio);

	/* Read a kernel physical page from the dump file.
	 * Input:
	 *   ctx->fd         core dump file descriptor open for reading
	 * Return:
	 *   kdump_ok        buffer is filled with page data
	 *   kdump_nodata    data for the given page is not present
	 *
	 * If a format handler has an efficient way to read a kernel physical
	 * page, it can set this method. Otherwise, the generic code will
	 * fall back to first translating KPHYSADDR to MACHPHYSADDR and
	 * use @ref read_page.
	 */
	kdump_status (*read_kpage)(kdump_ctx *ctx, struct page_io *pio);

	/** Drop a reference to a page.
	 * @param ctx  Dump file object.
	 * @param pio  Page I/O control.
	 */
	void (*unref_page)(kdump_ctx *ctx, struct page_io *pio);

	/* Translate a machine frame number to physical frame number.
	 *   ctx->fmtdata    initialized in probe()
	 * Return:
	 *   kdump_ok        output variable contains translated PFN
	 *   kdump_nodata    given MFN was not found
	 *
	 * This function should be used for single domain dumps.
	 */
	kdump_status (*mfn_to_pfn)(kdump_ctx *, kdump_pfn_t, kdump_pfn_t *);

	/** Reallocate any format-specific caches.
	 * @param ctx  Dump file object.
	 * @returns    Status (@ref kdump_ok on success).
	 */
	kdump_status (*realloc_caches)(kdump_ctx *ctx);

	/* Clean up all private data.
	 */
	void (*cleanup)(struct kdump_shared *);
};

struct arch_ops {
	/* Initialize any arch-specific data
	 */
	kdump_status (*init)(kdump_ctx *);

	/* Initialise virtual-to-physical translation.
	 */
	kdump_status (*vtop_init)(kdump_ctx *);

	/* Initialise Xen virtual-to-physical translation.
	 */
	kdump_status (*vtop_init_xen)(kdump_ctx *);

	/* Process an NT_PRSTATUS note
	 */
	kdump_status (*process_prstatus)(kdump_ctx *, void *, size_t);

	/* Get a register name:
	 *   index  register index (arch-dependent)
	 *
	 * Returns the register name or @c NULL if index is out of range.
	 */
	const char* (*reg_name)(unsigned index);

	/* Process a LOAD segment
	 */
	kdump_status (*process_load)(kdump_ctx *ctx, kdump_vaddr_t vaddr,
				     kdump_paddr_t paddr);

	/* Process a Xen .xen_prstatus section
	 */
	kdump_status (*process_xen_prstatus)(kdump_ctx *, void *, size_t);

	/* Translate a virtual address to a physical address
	 *
	 * In case of Xen, this should be the address as used by the CPU,
	 * i.e. a Xen machine address for a non-auto-translated domain.
	 */
	kdump_status (*vtop)(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			     kdump_paddr_t *paddr);

	/* Translate a Xen virtual address to a physical address
	 */
	kdump_status (*vtop_xen)(kdump_ctx *ctx, kdump_vaddr_t vaddr,
				 kdump_paddr_t *paddr);

	/* Translate a physical frame number to a machine frame number */
	kdump_status (*pfn_to_mfn)(kdump_ctx *, kdump_pfn_t, kdump_pfn_t *);

	/* Translate a machine frame number to physical frame number
	 *
	 * This function should be used for Xen system dumps.
	 */
	kdump_status (*mfn_to_pfn)(kdump_ctx *, kdump_pfn_t, kdump_pfn_t *);

	/* Clean up any arch-specific data
	 */
	void (*cleanup)(struct kdump_shared *);
};

/* provide our own definition of new_utsname */
#define NEW_UTS_LEN 64
#define UTS_SYSNAME "Linux"
struct new_utsname {
	char sysname[NEW_UTS_LEN + 1];
	char nodename[NEW_UTS_LEN + 1];
	char release[NEW_UTS_LEN + 1];
	char version[NEW_UTS_LEN + 1];
	char machine[NEW_UTS_LEN + 1];
	char domainname[NEW_UTS_LEN + 1];
};

/* Global attribute keys */
enum global_keyidx {
#define ATTR(dir, key, field, type, ctype, ...)	\
	GKI_ ## field,

#include "global-attr.def"

	GKI_static_first,
	GKI_nonstatic_first = 0,
	GKI_nonstatic_last = GKI_static_first - 1,

#include "static-attr.def"

	NR_GLOBAL_ATTRS,	/**< Total number of global attributes. */
	GKI_static_last = NR_GLOBAL_ATTRS - 1

#undef ATTR
};

struct attr_data;

/**  Type for early attribute hooks.
 * @param ctx      Dump file object.
 * @param attr     Attribute.
 * @param val      New attribute value.
 * @returns        Error status.
 *
 * This function is called before making a change to an attribute.
 * If this function returns an error code, it is passed up the chain,
 * and no other action is taken.
 *
 * This function is not called if the attribute value does not change
 * as a result of calling @ref set_attr.
 */
typedef kdump_status attr_pre_fn(
	kdump_ctx *ctx, struct attr_data *attr, union kdump_attr_value *val);

/**  Type for late attribute hooks.
 * @param ctx      Dump file object.
 * @param attr     Attribute.
 * @returns        Error status.
 *
 * This function is called after making a change to an attribute.
 * If this function returns an error code, it is passed up the chain,
 * but the value had been changed already.
 *
 * This function is not called if the attribute value does not change
 * as a result of calling @ref set_attr.
 */
typedef kdump_status attr_post_fn(
	kdump_ctx *ctx, struct attr_data *attr);

/**  Type for attribute validation hooks.
 * @param ctx      Dump file object.
 * @param attr     Attribute.
 * @returns        Error status.
 *
 * This function is called by @ref validate_attr before checking
 * that the attribute has a value. The hook is intended for lazy
 * initialization of attributes which should be listed in the hierarchy
 * even before the value is known (presumably because getting its value
 * needs considerable resources).
 */
typedef kdump_status attr_validate_fn(
	kdump_ctx *ctx, struct attr_data *attr);

/**  Attribute ops
 */
struct attr_ops {
	attr_pre_fn *pre_set;	    /**< Called before value change. */
	attr_post_fn *post_set;	    /**< Called after value change. */
	attr_validate_fn *validate; /**< Called before validating value. */
};

/**  Attribute template.
 *
 * All instances of a key share the same characteristics (such as key name
 * and value type).
 */
struct attr_template {
	const char *key;
	const struct attr_template *parent;
	enum kdump_attr_type type;
	const struct attr_ops *ops;
};

/**  Data type for storing attribute value in each instance.
 *
 * Note that this structure does not include type, because it must be
 * equal to the template type.
 */
struct attr_data {
	struct attr_data *next, *parent;
	const struct attr_template *template;

	unsigned isset : 1;	/**< Zero if attribute has no value */
	unsigned dynstr : 1;	/**< Dynamically allocated string */
	unsigned indirect : 1;	/**< Actual value is at @c *pval */
	unsigned dyntmpl : 1;	/**< Dynamically allocated template */

	union {
		union kdump_attr_value val;
		struct attr_data *dir;	      /**< For @c kdump_directory */
		union kdump_attr_value *pval; /**< Pointer to indirect value */
	};
};

/**  Size of the attribute hash table.
 */
#define ATTR_HASH_BITS	8
#define ATTR_HASH_SIZE	(1U<<ATTR_HASH_BITS)
#define ATTR_HASH_FUZZ	8

/**  Attribute hash table.
 *
 * Attributes are in fact stored in a linked list of hash tables.
 * Allocation is first attempted from a given slot, walking through
 * all linked hash tables. If this fails, allocation is retried from
 * the following slot(s) in the table.
 */
struct attr_hash {
	struct attr_hash *next;
	struct attr_data table[ATTR_HASH_SIZE];
};

typedef enum _tag_kdump_xlat_method {
	/* No mapping set */
	KDUMP_XLAT_NONE,

	/* Invalid virtual addresses */
	KDUMP_XLAT_INVALID,

	/* Arbitrary: use vtop to map between virtual and physical */
	KDUMP_XLAT_VTOP,

	/* Direct mapping: virtual = physical + phys_off */
	KDUMP_XLAT_DIRECT,

	/* Kernel text: virtual = physical + phys_off - ctx->phys_base */
	KDUMP_XLAT_KTEXT,
} kdump_xlat_method_t;

struct kdump_xlat {
	kdump_addr_t phys_off;	    /**< offset from physical addresses */
	kdump_xlat_method_t method; /**< vaddr->paddr translation method */
};

struct kdump_vaddr_region {
	kdump_vaddr_t max_off;	/**< max offset inside the range */
	struct kdump_xlat xlat; /**< translation definition */
};

typedef kdump_status vtop_pgt_fn(
	kdump_ctx *ctx, kdump_vaddr_t vaddr, kdump_paddr_t *paddr);

/**  Map for virtual-to-physical translation
 */
struct vtop_map {
	vtop_pgt_fn *vtop_pgt_fn;     /**< function to walk page tables */
	enum global_keyidx phys_base; /**< kernel physical base  */

	unsigned num_regions;	      /**< number of elements in @c region */
	struct kdump_vaddr_region *region;
};

struct cache;

/** Number of per-context data slots.
 * If needed, this number can be increased without breaking public ABI.
 */
#define PER_CTX_SLOTS	16

/**  Shared state of the dump file object.
 *
 * This structure describes the data portion of the dump file object,
 * which can be shared by many @ref kdump_ctx objects.
 */
struct kdump_shared {
	/** Guard accesses to shared data. */
	mutex_t lock;

	/** List of all refererring @c kdump_ctx structures.
	 * Each @c kdump_ctx that holds a reference to this shared data
	 * must be added to this list.
	 */
	struct list_head ctx;

	int fd;			/**< Dump file descriptor. */

	const struct format_ops *ops; /**< File format operations. */
	void *fmtdata;		      /**< File format private data. */

	const struct arch_ops *arch_ops; /**< Arch-specific operations. */
	void *archdata;			 /**< Arch-specific private data. */
	enum kdump_arch arch;		 /**< Internal-only arch index. */
	int arch_init_done;	/**< Non-zero if arch init has been called. */

	struct cache *cache;	/**< Page cache. */

	struct vtop_map vtop_map;     /**< Linux address translation. */
	struct vtop_map vtop_map_xen; /**< Xen address translation. */

	/* Attribute hash table. */
	struct attr_hash *attr;

	/** Global attributes. */
	struct attr_data *global_attrs[NR_GLOBAL_ATTRS];

	/** Static attributes. */
#define ATTR(dir, key, field, type, ctype, ...)	\
	union kdump_attr_value field;
#include "static-attr.def"
#undef ATTR

	/* Xen maps */
	void *xen_map;
	unsigned long xen_map_size;

	/** Size of per-context data. Zero means unallocated. */
	size_t per_ctx_size[PER_CTX_SLOTS];
};

/* Maximum length of the error message */
#define ERRBUF	160

/**  Representation of a dump file.
 *
 * This structure contains state information and a pointer to @c struct
 * @ref kdump_shared.
 */
struct _tag_kdump_ctx {
	struct kdump_shared *shared; /**< Dump file shared data. */

	/** Node of the @c ctx list in @c struct @ref kdump_shared. */
	struct list_head list;

	void *priv;		/**< User private data. */

	/* callbacks */
	kdump_get_symbol_val_fn *cb_get_symbol_val;
	kdump_get_symbol_val_fn *cb_get_symbol_val_xen;

	/** Per-context data. */
	void *data[PER_CTX_SLOTS];

	char *err_str;		/**< Error string. */
	char err_buf[ERRBUF];	/**< Buffer for the error string. */
};

/* Per-context data */

#define per_ctx_alloc INTERNAL_NAME(per_ctx_alloc)
int per_ctx_alloc(struct kdump_shared *shared, size_t sz);

#define per_ctx_free INTERNAL_NAME(per_ctx_free)
void per_ctx_free(struct kdump_shared *shared, int slot);

/* File formats */

#define elfdump_ops INTERNAL_NAME(elfdump_ops)
extern const struct format_ops elfdump_ops;

#define qemu_ops INTERNAL_NAME(qemu_ops)
extern const struct format_ops qemu_ops;

#define libvirt_ops INTERNAL_NAME(libvirt_ops)
extern const struct format_ops libvirt_ops;

#define xc_save_ops INTERNAL_NAME(xc_save_ops)
extern const struct format_ops xc_save_ops;

#define xc_core_ops INTERNAL_NAME(xc_core_ops)
extern const struct format_ops xc_core_ops;

#define diskdump_ops INTERNAL_NAME(diskdump_ops)
extern const struct format_ops diskdump_ops;

#define lkcd_ops INTERNAL_NAME(lkcd_ops)
extern const struct format_ops lkcd_ops;

#define mclxcd_ops INTERNAL_NAME(mclxcd_ops)
extern const struct format_ops mclxcd_ops;

#define s390dump_ops INTERNAL_NAME(s390dump_ops)
extern const struct format_ops s390dump_ops;

#define devmem_ops INTERNAL_NAME(devmem_ops)
extern const struct format_ops devmem_ops;

/* Architectures */

#define ia32_ops INTERNAL_NAME(ia32_ops)
extern const struct arch_ops ia32_ops;

#define s390x_ops INTERNAL_NAME(s390x_ops)
extern const struct arch_ops s390x_ops;

#define x86_64_ops INTERNAL_NAME(x86_64_ops)
extern const struct arch_ops x86_64_ops;

#define ppc64_ops INTERNAL_NAME(ppc64_ops)
extern const struct arch_ops ppc64_ops;

/* struct timeval has a different layout on 32-bit and 64-bit */
struct timeval_32 {
	int32_t tv_sec;
	int32_t tv_usec;
};
struct timeval_64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

#define raw_read_page INTERNAL_NAME(raw_read_page)
kdump_status raw_read_page(kdump_ctx *ctx, kdump_addrspace_t as,
			   struct page_io *pio);

#define read_u64 INTERNAL_NAME(read_u64)
kdump_status read_u64(kdump_ctx *ctx, kdump_addrspace_t as, kdump_addr_t addr,
		      int precious, char *what, uint64_t *result);

/* utils */

#define set_error INTERNAL_NAME(set_error)
kdump_status set_error(kdump_ctx *ctx, kdump_status ret,
		       const char *msgfmt, ...)
	__attribute__ ((format (printf, 3, 4)));

#define ctx_malloc INTERNAL_NAME(ctx_malloc)
void *ctx_malloc(size_t size, kdump_ctx *ctx, const char *desc);

#define set_uts INTERNAL_NAME(set_uts)
kdump_status set_uts(kdump_ctx *ctx, const struct new_utsname *src);

#define uts_looks_sane INTERNAL_NAME(uts_looks_sane)
int uts_looks_sane(struct new_utsname *uts);

#define uncompress_rle INTERNAL_NAME(uncompress_rle)
int uncompress_rle(unsigned char *dst, size_t *pdstlen,
		   const unsigned char *src, size_t srclen);

#define uncompress_page_gzip INTERNAL_NAME(uncompress_page_gzip)
kdump_status uncompress_page_gzip(kdump_ctx *ctx, unsigned char *dst,
				  unsigned char *src, size_t srclen);

#define store_vmcoreinfo INTERNAL_NAME(store_vmcoreinfo)
kdump_status store_vmcoreinfo(kdump_ctx *ctx, const char *path,
			      void *data, size_t len);

#define paged_read INTERNAL_NAME(paged_read)
ssize_t paged_read(int fd, void *buffer, size_t size);

#define cksum32 INTERNAL_NAME(cksum32)
uint32_t cksum32(void *buffer, size_t size, uint32_t csum);

#define get_symbol_val INTERNAL_NAME(get_symbol_val)
kdump_status get_symbol_val(kdump_ctx *ctx, const char *name,
			    kdump_addr_t *val);

#define get_symbol_val_xen INTERNAL_NAME(get_symbol_val_xen)
kdump_status get_symbol_val_xen(kdump_ctx *ctx, const char *name,
				kdump_addr_t *val);

#define set_cpu_regs64 INTERNAL_NAME(set_cpu_regs64)
kdump_status set_cpu_regs64(kdump_ctx *ctx, unsigned cpu,
			    const struct attr_template *tmpl,
			    uint64_t *regs, unsigned num);

#define set_cpu_regs32 INTERNAL_NAME(set_cpu_regs32)
kdump_status set_cpu_regs32(kdump_ctx *ctx, unsigned cpu,
			    const struct attr_template *tmpl,
			    uint32_t *regs, unsigned num);

#define set_format_longname INTERNAL_NAME(set_format_longname)
kdump_status set_format_longname(kdump_ctx *ctx, const char *name);

/* hashing */
#define string_hash INTERNAL_NAME(string_hash)
unsigned long string_hash(const char *s);

#define mem_hash INTERNAL_NAME(mem_hash)
unsigned long mem_hash(const char *s, size_t len);

/**  Partial hash.
 * This structure is used to store the state of the hashing algorithm,
 * while making incremental updates.
 */
struct phash {
	unsigned long val;	/**< Current hash value. */
	unsigned idx;		/**< Index in @ref part. */
	union {
		/** Partial data as bytes. */
		unsigned char bytes[sizeof(unsigned long)];
		/** Partial data as an unsigned long number. */
		unsigned long num;
	} part;			/**< Partial data. */
};

/**  Initialize a partial hash.
 * @param[out] phash  Partial hash state.
 */
static inline void
phash_init(struct phash *hash)
{
	hash->val = 0UL;
	hash->idx = 0;
}

#define phash_update INTERNAL_NAME(phash_update)
void phash_update(struct phash *ph, const char *s, size_t len);

#if SIZEOF_LONG == 8
# define belongtoh(x)	be64toh(x)
#elif SIZEOF_LONG == 4
# define belongtoh(x)	be32toh(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
# define belongtoh(x)	(x)
#else
/**  Convert a big-endian unsigned long to host order.
 * @param x  Number in big-endian order.
 * @returns  @ref x in host order.
 */
static inline unsigned long
belongtoh(unsigned long x)
{
	unsigned long ret;
	unsigned i;

	ret = x & 0xff;
	for (i = 1; i < sizeof(unsigned long); ++i) {
		x >>= BITS_PER_BYTE;
		ret <<= BITS_PER_BYTE;
		ret |= x & 0xff;
	}
	return ret;
}
#endif

/**  Get the current hash value.
 * @param[in]  phash  Partial hash state.
 *
 * This function returns the hash value, as if the has was computed from
 * all data passed to @ref phash_update() so far. However, it is possible
 * to update @ref phash again after calling this function and repeat this
 * process indefinitely.
 */
static inline unsigned long
phash_value(const struct phash *ph)
{
	unsigned long hash = ph->val;
	if (ph->idx)
		hash += (belongtoh(ph->part.num) >>
			 (BITS_PER_BYTE * (sizeof(ph->part) - ph->idx)));
	return hash;
}

/* Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 */
#define GOLDEN_RATIO_PRIME_32 2654435761UL
#define GOLDEN_RATIO_PRIME_64 11400714819323198549ULL

static inline unsigned long
fold_hash(unsigned long hash, unsigned bits)
{
#if SIZEOF_LONG == 8
	return (hash * GOLDEN_RATIO_PRIME_64) >> (8 * sizeof(long) - bits);
#else
	return (hash * GOLDEN_RATIO_PRIME_32) >> (8 * sizeof(long) - bits);
#endif
}

/* ELF notes */

#define process_notes INTERNAL_NAME(process_notes)
kdump_status process_notes(kdump_ctx *ctx, void *data, size_t size);

#define process_noarch_notes INTERNAL_NAME(process_noarch_notes)
kdump_status process_noarch_notes(kdump_ctx *ctx, void *data, size_t size);

#define process_arch_notes INTERNAL_NAME(process_arch_notes)
kdump_status process_arch_notes(kdump_ctx *ctx, void *data, size_t size);

#define process_vmcoreinfo INTERNAL_NAME(process_vmcoreinfo)
kdump_status process_vmcoreinfo(kdump_ctx *ctx, void *data, size_t size);

/* Virtual address space regions */

#define init_vtop_maps INTERNAL_NAME(init_vtop_maps)
void init_vtop_maps(kdump_ctx *ctx);

#define set_vtop_xlat INTERNAL_NAME(set_vtop_xlat)
kdump_status set_vtop_xlat(struct vtop_map *map,
			   kdump_vaddr_t first, kdump_vaddr_t last,
			   kdump_xlat_method_t method, kdump_vaddr_t phys_off);

#define flush_vtop_map INTERNAL_NAME(flush_vtop_map)
void flush_vtop_map(struct vtop_map *map);

#define get_vtop_xlat INTERNAL_NAME(get_vtop_xlat)
const struct kdump_xlat *get_vtop_xlat(const struct vtop_map *map,
				       kdump_vaddr_t vaddr);

#define vtop_pgt INTERNAL_NAME(vtop_pgt)
kdump_status vtop_pgt(kdump_ctx *ctx, kdump_vaddr_t vaddr,
		      kdump_paddr_t *paddr);

#define vtop_pgt_xen INTERNAL_NAME(vtop_pgt_xen)
kdump_status vtop_pgt_xen(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			  kdump_paddr_t *paddr);

/* Attribute handling */

#define add_attr_template INTERNAL_NAME(add_attr_template)
kdump_status add_attr_template(kdump_ctx *ctx, const char *path,
			       enum kdump_attr_type type);

#define init_attrs INTERNAL_NAME(init_attrs)
kdump_status init_attrs(kdump_ctx *ctx);

#define lookup_attr INTERNAL_NAME(lookup_attr)
struct attr_data *lookup_attr(const struct kdump_shared *shared,
			      const char *key);

#define lookup_dir_attr INTERNAL_NAME(lookup_dir_attr)
struct attr_data *lookup_dir_attr(const struct kdump_shared *shared,
				  const struct attr_data *dir,
				  const char *key, size_t keylen);

/**  Attribute data by shared data and global key index.
 * @param shared  Shared data of a dump file object.
 * @param idx     Global key index.
 * @returns       Attribute data.
 */
static inline struct attr_data *
sgattr(const struct kdump_shared *shared, enum global_keyidx idx)
{
	return shared->global_attrs[idx];
}

/**  Attribute data by context and global key index.
 * @param ctx  Dump file object.
 * @param idx  Global key index.
 * @returns    Attribute data.
 */
static inline struct attr_data *
gattr(const kdump_ctx *ctx, enum global_keyidx idx)
{
	return sgattr(ctx->shared, idx);
}

/**  Check if an attribute is set.
 * @param data  Pointer to the attribute data.
 * @returns     Non-zero if attribute data is valid.
 */
static inline int
attr_isset(const struct attr_data *data)
{
	return data->isset;
}

static inline const union kdump_attr_value *
attr_value(const struct attr_data *attr)
{
	return attr->indirect ? attr->pval : &attr->val;
}

#define validate_attr INTERNAL_NAME(validate_attr)
kdump_status validate_attr(kdump_ctx *ctx, struct attr_data *attr);

#define set_attr INTERNAL_NAME(set_attr)
kdump_status set_attr(kdump_ctx *ctx, struct attr_data *attr,
		      union kdump_attr_value val);

#define set_attr_indirect INTERNAL_NAME(set_attr_indirect)
kdump_status set_attr_indirect(kdump_ctx *ctx, struct attr_data *attr,
			       union kdump_attr_value *pval);

#define set_attr_number INTERNAL_NAME(set_attr_number)
kdump_status set_attr_number(kdump_ctx *ctx, struct attr_data *attr,
			     kdump_num_t num);

#define set_attr_address INTERNAL_NAME(set_attr_address)
kdump_status set_attr_address(kdump_ctx *ctx, struct attr_data *key,
			      kdump_addr_t addr);

#define set_attr_string INTERNAL_NAME(set_attr_string)
kdump_status set_attr_string(kdump_ctx *ctx, struct attr_data *attr,
			     const char *str);

#define set_attr_static_string INTERNAL_NAME(set_attr_static_string)
kdump_status set_attr_static_string(kdump_ctx *ctx, struct attr_data *attr,
				    const char *str);

#define add_attr_number INTERNAL_NAME(add_attr_number)
kdump_status add_attr_number(kdump_ctx *ctx, const char *path,
			     const struct attr_template *tmpl,
			     kdump_num_t num);

#define add_attr_string INTERNAL_NAME(add_attr_string)
kdump_status add_attr_string(kdump_ctx *ctx, const char *path,
			     const struct attr_template *tmpl,
			     const char *str);

#define add_attr_static_string INTERNAL_NAME(add_attr_static_string)
kdump_status add_attr_static_string(kdump_ctx *ctx, const char *path,
				    const struct attr_template *tmpl,
				    const char *str);

#define clear_attr INTERNAL_NAME(clear_attr)
void clear_attr(struct attr_data *attr);

/**  Clear (unset) all attributes.
 * @param ctx   Dump file object.
 */
static inline void
clear_attrs(kdump_ctx *ctx)
{
	clear_attr(gattr(ctx, GKI_dir_root));
}

#define cleanup_attr INTERNAL_NAME(cleanup_attr)
void cleanup_attr(struct kdump_shared *shared);

/* Accessor functions for static attributes */

#define DEFINE_GET_ACCESSOR(name, type, ctype)			\
	static inline ctype					\
	get_ ## name(kdump_ctx *ctx)				\
	{							\
		return ctx->shared->name.type;			\
	}
#define DEFINE_SET_ACCESSOR(name, type, ctype)			\
	static inline kdump_status				\
	set_ ## name(kdump_ctx *ctx, ctype newval)		\
	{							\
		struct attr_data *d = gattr(ctx, GKI_ ## name);	\
		union kdump_attr_value val;			\
		val.type = newval;				\
		return set_attr(ctx, d,	val); 			\
	}
#define DEFINE_ISSET_ACCESSOR(name)				\
	static inline int					\
	isset_ ## name(kdump_ctx *ctx)				\
	{							\
		struct attr_data *d = gattr(ctx, GKI_ ## name);	\
		return attr_isset(d);				\
	}

#define DEFINE_ACCESSORS(name, type, ctype)	\
	DEFINE_GET_ACCESSOR(name, type, ctype)	\
	DEFINE_SET_ACCESSOR(name, type, ctype)	\
	DEFINE_ISSET_ACCESSOR(name)

#define ATTR(dir, key, field, type, ctype, ...)	\
	DEFINE_ACCESSORS(field, type, ctype)
#include "static-attr.def"
#undef ATTR

/* Attribute ops */
#define page_size_ops INTERNAL_NAME(page_size_ops)
extern const struct attr_ops page_size_ops;

#define page_shift_ops INTERNAL_NAME(page_shift_ops)
extern const struct attr_ops page_shift_ops;

#define cache_size_ops INTERNAL_NAME(cache_size_ops)
extern const struct attr_ops cache_size_ops;

#define arch_name_ops INTERNAL_NAME(arch_name_ops)
extern const struct attr_ops arch_name_ops;

#define uts_machine_ops INTERNAL_NAME(uts_machine_ops)
extern const struct attr_ops uts_machine_ops;

/**  Attribute template override.
 *
 * This structure is used for temporary overrides of an existing
 * attribute template. The @c parent member in the @c template
 * field is used to link multiple overrides.
 */
struct attr_override {
	struct attr_template template; /**< Modified template. */
	struct attr_ops ops;	       /**< Modified attribute ops. */
};

#define attr_add_override INTERNAL_NAME(attr_add_override)
void attr_add_override(struct attr_data *attr,
		       struct attr_override *override);

#define attr_remove_override INTERNAL_NAME(attr_remove_override)
void attr_remove_override(struct attr_data *attr,
			  struct attr_override *override);

/* Xen */

/**  Check if kernel physical address space is equal to machine physical one.
 */
static inline int
kphys_is_machphys(kdump_ctx *ctx)
{
	return get_xen_type(ctx) == kdump_xen_none ||
		(get_xen_type(ctx) == kdump_xen_domain &&
		 get_xen_xlat(ctx) == kdump_xen_auto);
}

/* Caching */

/** Default cache size.
 * The size is chosen so that it does not do much harm in constrained
 * environments. On a dump with 4K pages, it takes up 256K.
 */
#define DEFAULT_CACHE_SIZE	64

/** Number of bits used for cache flags.
 * Cache flags are stored in the high bits of a cached PFN.
 * This number must be big enough to hold all possible flags
 * and small enough to leave enough bits for the actual PFN.
 *
 * Since @ref kdump_pfn_t is the same size as @ref kdump_addr_t,
 * this number must be smaller than the minimum page shift.
 */
#define CF_BITS			2
#define CF_MASK			(((kdump_pfn_t)1 << CF_BITS) - 1)
#define CF_SHIFT		(PFN_BITS - CF_BITS)
#define CACHE_FLAGS_PFN(f)	((kdump_pfn_t)(f) << CF_SHIFT)
#define CACHE_PFN_FLAGS(pfn)	(((pfn) >> CF_SHIFT) & CF_MASK)
#define CACHE_PFN(pfn)		((pfn) & ~(CACHE_FLAGS_PFN(CF_MASK)))

/**  Cache flags.
 *
 * These flags are stored in the top 2 bits of the @c pfn field.
 * Note that @ref cf_valid is zero, so the PFN for valid entries can
 * be used directly (without masking off any bits).
 */
enum cache_flags {
	cf_valid,		/**< Valid (active) cache entry */
	cf_probe,		/**< In flight, target probe list */
	cf_precious,		/**< In flight, target precious list */
};

/**  Cache entry.
 */
struct cache_entry {
	kdump_pfn_t pfn;	/**< PFN in the cache; highest @ref CF_BITS
				 *   are used for cache flags. */
	unsigned next;		/**< Index of next entry in evict list. */
	unsigned prev;		/**< Index of previous entry in evict list. */
	unsigned refcnt;	/**< Reference count. */
	void *data;		/**< Pointer to page data. */
};

#define get_cache_size INTERNAL_NAME(get_cache_size)
unsigned get_cache_size(kdump_ctx *ctx);

#define cache_alloc INTERNAL_NAME(cache_alloc)
struct cache *cache_alloc(unsigned n, size_t size);

#define cache_free INTERNAL_NAME(cache_free)
void cache_free(struct cache *);

#define cache_flush INTERNAL_NAME(cache_flush)
void cache_flush(struct cache *);

#define cache_get_entry INTERNAL_NAME(cache_get_entry)
struct cache_entry *cache_get_entry(struct cache *, kdump_pfn_t);

#define cache_put_entry INTERNAL_NAME(cache_put_entry)
void cache_put_entry(struct cache *cache, struct cache_entry *entry);

#define cache_insert INTERNAL_NAME(cache_insert)
void cache_insert(struct cache *, struct cache_entry *);

#define cache_discard INTERNAL_NAME(cache_discard)
void cache_discard(struct cache *, struct cache_entry *);

#define cache_make_precious INTERNAL_NAME(cache_make_precious)
void cache_make_precious(struct cache *cache, struct cache_entry *entry);

typedef kdump_status read_cache_fn(
	kdump_ctx *ctx, kdump_pfn_t pfn, struct cache_entry *entry);

#define def_read_cache INTERNAL_NAME(def_read_cache)
kdump_status def_read_cache(kdump_ctx *ctx, struct page_io *pio,
			    read_cache_fn *fn, kdump_pfn_t idx);

#define cache_unref_page INTERNAL_NAME(cache_unref_page)
void cache_unref_page(kdump_ctx *ctx, struct page_io *pio);

static inline
void unref_page(kdump_ctx *ctx, struct page_io *pio)
{
	ctx->shared->ops->unref_page(ctx, pio);
}

#define def_realloc_caches INTERNAL_NAME(def_realloc_caches)
kdump_status def_realloc_caches(kdump_ctx *ctx);

/**  Check if a cache entry is valid.
 *
 * @param entry  Cache entry.
 * @returns      Non-zero if the data is valid, zero otherwise.
 */
static inline int
cache_entry_valid(struct cache_entry *entry)
{
	return CACHE_PFN_FLAGS(entry->pfn) == cf_valid;
}

/* Inline utility functions */

static inline unsigned
bitcount(unsigned x)
{
	return (uint32_t)((((x * 0x08040201) >> 3) & 0x11111111) * 0x11111111)
		>> 28;
}

static inline uint16_t
dump16toh(kdump_ctx *ctx, uint16_t x)
{
	return get_byte_order(ctx) == kdump_big_endian
		? be16toh(x)
		: le16toh(x);
}

static inline uint32_t
dump32toh(kdump_ctx *ctx, uint32_t x)
{
	return get_byte_order(ctx) == kdump_big_endian
		? be32toh(x)
		: le32toh(x);
}

static inline uint64_t
dump64toh(kdump_ctx *ctx, uint64_t x)
{
	return get_byte_order(ctx) == kdump_big_endian
		? be64toh(x)
		: le64toh(x);
}

static inline void
clear_error(kdump_ctx *ctx)
{
	ctx->err_str = NULL;
}

/* These are macros to avoid possible conversions of the "rd" parameter */

#define read_error(rd)  ((rd) < 0 ? kdump_syserr : kdump_eof)

#endif	/* kdumpfile-priv.h */
