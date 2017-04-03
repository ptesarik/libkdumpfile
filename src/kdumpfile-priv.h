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
#include <kdumpfile.h>
#pragma GCC visibility pop

#include "list.h"
#include "threads.h"

#include <endian.h>

#include <addrxlat.h>

#define STRINGIFY(x)	#x
#define XSTRINGIFY(x)	STRINGIFY(x)
#define CONCATENATE(a, b)	a ## b
#define XCONCATENATE(a, b)	CONCATENATE(a, b)

/** Assembler name corresponding to a C identifier. */
#define ASM_NAME(sym) \
	XCONCATENATE(__USER_LABEL_PREFIX__, sym)

/* Minimize chance of name clashes (in a static link) */
#ifndef PIC
#define INTERNAL_DECL(type, sym, param)	\
	type sym param			\
	__asm__(XSTRINGIFY(ASM_NAME(_libkdump_priv_ ## sym)))
#else
#define INTERNAL_DECL(type, sym, param)	\
	type sym param
#endif

#ifndef PIC
#define INTERNAL_ALIAS(x)		libkdump_ ## x
#define _DECLARE_ALIAS(s, a)		\
	extern typeof(s) (a) __asm__(XSTRINGIFY(ASM_NAME(s)))
#define _DEFINE_ALIAS(s, a)		_DECLARE_ALIAS(s, a)
#else
#define INTERNAL_ALIAS(x)		internal_ ## x
#define _DECLARE_ALIAS(s, a)		\
	extern typeof(s) (a)
#define _DEFINE_ALIAS(s, a)		\
	extern typeof(s) (a)		\
	__attribute__((alias(#s)))
#endif

/** Internal alias declaration. */
#define DECLARE_ALIAS(x) _DECLARE_ALIAS(kdump_ ## x, internal_ ## x)

/** Define an internal alias for a symbol. */
#define DEFINE_ALIAS(x) _DEFINE_ALIAS(kdump_ ## x, internal_ ## x)

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
	addrxlat_fulladdr_t addr; /**< Address of page under I/O. */
	struct cache *cache;	/**< Referenced cache. */
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
	 *   KDUMP_OK        can be handled by these ops
	 *   kdump_noprobe   cannot be handled by these ops
	 *   or any other kdump_* error status
	 */
	kdump_status (*probe)(kdump_ctx_t *ctx, void *hdr);

	/* Read a page from the dump file.
	 * Input:
	 *   ctx->fd         core dump file descriptor open for reading
	 * Return:
	 *   KDUMP_OK        buffer is filled with page data
	 *   KDUMP_NODATA    data for the given page is not present
	 *
	 * Note: The requested address space is specified in @c pio.
	 * It is always an address space specified by @c xlat_caps.
	 * Since most file formats will specify only one, their read_page
	 * method does not have to care.
	 */
	kdump_status (*read_page)(kdump_ctx_t *ctx, struct page_io *pio);

	/** Drop a reference to a page.
	 * @param ctx  Dump file object.
	 * @param pio  Page I/O control.
	 */
	void (*unref_page)(kdump_ctx_t *ctx, struct page_io *pio);

	/* Translate a machine frame number to physical frame number.
	 *   ctx->fmtdata    initialized in probe()
	 * Return:
	 *   KDUMP_OK        output variable contains translated PFN
	 *   KDUMP_NODATA    given MFN was not found
	 *
	 * This function should be used for single domain dumps.
	 */
	kdump_status (*mfn_to_pfn)(kdump_ctx_t *, kdump_pfn_t, kdump_pfn_t *);

	/** Reallocate any format-specific caches.
	 * @param ctx  Dump file object.
	 * @returns    Status (@ref KDUMP_OK on success).
	 */
	kdump_status (*realloc_caches)(kdump_ctx_t *ctx);

	/* Clean up all private data.
	 */
	void (*cleanup)(struct kdump_shared *);
};

struct arch_ops {
	/** Initialize any arch-specific data. */
	kdump_status (*init)(kdump_ctx_t *);

	/** Late initialization (after everything else is done). */
	kdump_status (*late_init)(kdump_ctx_t *);

	/** Process an NT_PRSTATUS note. */
	kdump_status (*process_prstatus)(kdump_ctx_t *, void *, size_t);

	/** Process a LOAD segment. */
	kdump_status (*process_load)(kdump_ctx_t *ctx, kdump_vaddr_t vaddr,
				     kdump_paddr_t paddr);

	/** Process a Xen .xen_prstatus section. */
	kdump_status (*process_xen_prstatus)(kdump_ctx_t *, void *, size_t);

	/** Clean up any arch-specific data. */
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
typedef kdump_status attr_pre_set_fn(
	kdump_ctx_t *ctx, struct attr_data *attr, kdump_attr_value_t *val);

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
typedef kdump_status attr_post_set_fn(
	kdump_ctx_t *ctx, struct attr_data *attr);

/**  Type for clear attribute hooks.
 * @param ctx      Dump file object.
 * @param attr     Attribute.
 *
 * This function is called before clearing an attribute's value.
 */
typedef void attr_pre_clear_fn(
	kdump_ctx_t *ctx, struct attr_data *attr);

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
	kdump_ctx_t *ctx, struct attr_data *attr);

/**  Attribute ops
 */
struct attr_ops {
	/** Called before value change. */
	attr_pre_set_fn *pre_set;

	/** Called after value change. */
	attr_post_set_fn *post_set;

	/** Called before clearing value. */
	attr_pre_clear_fn *pre_clear;

	/** Called before validating value. */
	attr_validate_fn *validate;
};

/**  Attribute template.
 *
 * All instances of a key share the same characteristics (such as key name
 * and value type).
 */
struct attr_template {
	const char *key;
	const struct attr_template *parent;
	kdump_attr_type_t type;
	const struct attr_ops *ops;
};

/**  Attribute value flags.
 */
struct attr_flags {
	uint8_t isset : 1;	/**< Zero if attribute has no value */
	uint8_t persist : 1;	/**< Persistent (never cleared) */
	uint8_t dynstr : 1;	/**< Dynamically allocated string */
	uint8_t indirect : 1;	/**< Actual value is at @c *pval */
};

/**  Get the default attribute flags.
 * @returns Default attribute flags.
 */
static inline struct attr_flags
attr_flags_default(void)
{
	const struct attr_flags flags = { };
	return flags;
}

/**  Default attribute flags. */
#define ATTR_DEFAULT	(attr_flags_default())

/**  Get the persistent attribute flags.
 * @returns Persistent attribute flags.
 */
static inline struct attr_flags
attr_flags_persist(void)
{
	const struct attr_flags flags = {
		.persist = 1,
	};
	return flags;
}

/**  Persistent attribute flags. */
#define ATTR_PERSIST	(attr_flags_persist())

/**  Get the default indirect flags.
 * @returns Indirect attribute flags.
 */
static inline struct attr_flags
attr_flags_indirect(void)
{
	const struct attr_flags flags = {
		.indirect = 1,
	};
	return flags;
}

/**  Indirect attribute flags. */
#define ATTR_INDIRECT	(attr_flags_indirect())

/**  Attribute template flags.
 */
struct attr_template_flags {
	uint8_t dyntmpl : 1;	/**< Dynamically allocated template */
};

/**  Data type for storing attribute value in each instance.
 *
 * Note that this structure does not include type, because it must be
 * equal to the template type.
 */
struct attr_data {
	struct attr_data *next, *parent;
	const struct attr_template *template;

	/** Attribute value flags */
	struct attr_flags flags;

	/** Attribute template flags */
	struct attr_template_flags tflags;

	union {
		kdump_attr_value_t val;
		struct attr_data *dir;	  /**< For @c kdump_directory */
		kdump_attr_value_t *pval; /**< Pointer to indirect value */
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

/** OS type to attribute key mapping.
 */
struct ostype_attr_map {
	addrxlat_ostype_t ostype;   /**< OS type */
	enum global_keyidx attrkey; /**< Corresponding attribute key */
};

INTERNAL_DECL(struct attr_data *, ostype_attr,
	      (const struct kdump_shared *shared,
	       const struct ostype_attr_map *map));

struct cache;

/** Number of per-context data slots.
 * If needed, this number can be increased without breaking public ABI.
 */
#define PER_CTX_SLOTS	16

/**  Shared state of the dump file object.
 *
 * This structure describes the data portion of the dump file object,
 * which can be shared by many @ref kdump_ctx_t objects.
 */
struct kdump_shared {
	rwlock_t lock;		/**< Guard accesses to shared data. */

	/** List of all refererring @c kdump_ctx_t structures.
	 * Each @c kdump_ctx_t that holds a reference to this shared data
	 * must be added to this list.
	 */
	struct list_head ctx;

	/** File format operations. */
	const struct format_ops *ops;
	void *fmtdata;		/**< File format private data. */

	/** Arch-specific operations. */
	const struct arch_ops *arch_ops;
	void *archdata;		/**< Arch-specific private data. */
	enum kdump_arch arch;	/**< Internal-only arch index. */
	int arch_init_done;	/**< Non-zero if arch init has been called. */

	struct cache *cache;	/**< Page cache. */

	addrxlat_ostype_t ostype; /**< OS for address translation. */
	addrxlat_sys_t *xlatsys;  /**< Address translation system. */
	unsigned long xlat_caps;  /**< Address space capabilities. */

	struct attr_hash *attr;	/**< Attribute hash table. */

	/** Global attributes. */
	struct attr_data *global_attrs[NR_GLOBAL_ATTRS];

	/** Static attributes. */
#define ATTR(dir, key, field, type, ctype, ...)	\
	kdump_attr_value_t field;
#include "static-attr.def"
#undef ATTR

	/** Xen p2m map. */
	void *xen_map;
	/** Xen map size. */
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
struct _kdump_ctx {
	struct kdump_shared *shared; /**< Dump file shared data. */

	/** Node of the @c ctx list in @c struct @ref kdump_shared. */
	struct list_head list;

	void *priv;		/**< User private data. */

	/** Address translation context. */
	addrxlat_ctx_t *xlatctx;

	/* callbacks */
	kdump_get_symbol_val_fn *cb_get_symbol_val;

	/** Per-context data. */
	void *data[PER_CTX_SLOTS];

	char *err_str;		/**< Error string. */
	char *err_dyn;		/**< Dynamically allocated error string. */
	char err_buf[ERRBUF];	/**< Fallback buffer for the error string. */
};

/* Per-context data */

INTERNAL_DECL(int, per_ctx_alloc, (struct kdump_shared *shared, size_t sz));
INTERNAL_DECL(void, per_ctx_free, (struct kdump_shared *shared, int slot));

/* File formats */

INTERNAL_DECL(extern const struct format_ops, elfdump_ops, );
INTERNAL_DECL(extern const struct format_ops, qemu_ops, );
INTERNAL_DECL(extern const struct format_ops, libvirt_ops, );
INTERNAL_DECL(extern const struct format_ops, xc_save_ops, );
INTERNAL_DECL(extern const struct format_ops, xc_core_ops, );
INTERNAL_DECL(extern const struct format_ops, diskdump_ops, );
INTERNAL_DECL(extern const struct format_ops, lkcd_ops, );
INTERNAL_DECL(extern const struct format_ops, mclxcd_ops, );
INTERNAL_DECL(extern const struct format_ops, s390dump_ops, );
INTERNAL_DECL(extern const struct format_ops, devmem_ops, );

INTERNAL_DECL(kdump_status, linux_iomem_kcode,
	      (kdump_ctx_t *ctx, kdump_paddr_t *paddr));

/* Architectures */

INTERNAL_DECL(extern const struct arch_ops, ia32_ops, );
INTERNAL_DECL(extern const struct arch_ops, s390x_ops, );
INTERNAL_DECL(extern const struct arch_ops, x86_64_ops, );
INTERNAL_DECL(extern const struct arch_ops, ppc64_ops, );

/* struct timeval has a different layout on 32-bit and 64-bit */
struct timeval_32 {
	int32_t tv_sec;
	int32_t tv_usec;
};
struct timeval_64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

/* read */

INTERNAL_DECL(kdump_status, read_string_locked,
	      (kdump_ctx_t *ctx, kdump_addrspace_t as,
	       kdump_addr_t addr, char **pstr));
INTERNAL_DECL(kdump_status, read_locked,
	      (kdump_ctx_t *ctx, kdump_addrspace_t as,
	       kdump_addr_t addr, void *buffer, size_t *plength));
INTERNAL_DECL(kdump_status, read_u32,
	      (kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	       int precious, char *what, uint32_t *result));
INTERNAL_DECL(kdump_status, read_u64,
	      (kdump_ctx_t *ctx, kdump_addrspace_t as, kdump_addr_t addr,
	       int precious, char *what, uint64_t *result));
INTERNAL_DECL(void, set_addrspace_caps,
	      (struct kdump_shared *shared, unsigned long caps));


/* utils */

INTERNAL_DECL(kdump_status, set_error,
	      (kdump_ctx_t *ctx, kdump_status ret, const char *msgfmt, ...))
	__attribute__ ((format (printf, 3, 4)));

INTERNAL_DECL(kdump_status, addrxlat2kdump,
	      (kdump_ctx_t *ctx, addrxlat_status status));
INTERNAL_DECL(addrxlat_status, kdump2addrxlat,
	      (kdump_ctx_t *ctx, kdump_status status));

INTERNAL_DECL(void *, ctx_malloc,
	      (size_t size, kdump_ctx_t *ctx, const char *desc));

INTERNAL_DECL(kdump_status, set_uts,
	      (kdump_ctx_t *ctx, const struct new_utsname *src));
INTERNAL_DECL(int, uts_looks_sane, (struct new_utsname *uts));

INTERNAL_DECL(int, uncompress_rle,
	      (unsigned char *dst, size_t *pdstlen,
	       const unsigned char *src, size_t srclen));
INTERNAL_DECL(kdump_status, uncompress_page_gzip,
	      (kdump_ctx_t *ctx, unsigned char *dst,
	       unsigned char *src, size_t srclen));

INTERNAL_DECL(ssize_t, paged_read, (int fd, void *buffer, size_t size));

INTERNAL_DECL(uint32_t, cksum32, (void *buffer, size_t size, uint32_t csum));

INTERNAL_DECL(kdump_status, get_symbol_val,
	      (kdump_ctx_t *ctx, const char *name, kdump_addr_t *val));

INTERNAL_DECL(kdump_status, set_cpu_regs64,
	      (kdump_ctx_t *ctx, unsigned cpu,
	       const struct attr_template *tmpl,
	       uint64_t *regs, unsigned num));
INTERNAL_DECL(kdump_status, set_cpu_regs32,
	      (kdump_ctx_t *ctx, unsigned cpu,
	       const struct attr_template *tmpl,
	       uint32_t *regs, unsigned num));

INTERNAL_DECL(kdump_status, set_file_description,
	      (kdump_ctx_t *ctx, const char *name));

/* hashing */
INTERNAL_DECL(unsigned long, string_hash, (const char *s));
INTERNAL_DECL(unsigned long, mem_hash, (const char *s, size_t len));

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

INTERNAL_DECL(void, phash_update,
	      (struct phash *ph, const char *s, size_t len));

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

INTERNAL_DECL(kdump_status, process_notes,
	      (kdump_ctx_t *ctx, void *data, size_t size));
INTERNAL_DECL(kdump_status, process_noarch_notes,
	      (kdump_ctx_t *ctx, void *data, size_t size));
INTERNAL_DECL(kdump_status, process_arch_notes,
	      (kdump_ctx_t *ctx, void *data, size_t size));

/* Virtual address space regions */
INTERNAL_DECL(addrxlat_ctx_t *, init_addrxlat, (kdump_ctx_t *ctx));

INTERNAL_DECL(kdump_status, vtop_init, (kdump_ctx_t *ctx));

/* Attribute handling */
INTERNAL_DECL(extern const struct attr_template, dir_template, );
INTERNAL_DECL(struct attr_template *, alloc_attr_template,
	      (const struct attr_template *tmpl,
	       const char *key, size_t keylen));
INTERNAL_DECL(struct attr_data *, new_attr,
	      (struct kdump_shared *shared, struct attr_data *parent,
	       const struct attr_template *tmpl));
INTERNAL_DECL(void, dealloc_attr, (struct attr_data *attr));
INTERNAL_DECL(struct attr_data **, init_attrs, (struct kdump_shared *shared));
INTERNAL_DECL(struct attr_data *, lookup_attr,
	      (const struct kdump_shared *shared, const char *key));
INTERNAL_DECL(struct attr_data *, lookup_dir_attr,
	      (const struct kdump_shared *shared, const struct attr_data *dir,
	       const char *key, size_t keylen));

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
gattr(const kdump_ctx_t *ctx, enum global_keyidx idx)
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
	return data->flags.isset;
}

static inline const kdump_attr_value_t *
attr_value(const struct attr_data *attr)
{
	return attr->flags.indirect ? attr->pval : &attr->val;
}

INTERNAL_DECL(kdump_status, validate_attr,
	      (kdump_ctx_t *ctx, struct attr_data *attr));
INTERNAL_DECL(kdump_status, set_attr,
	      (kdump_ctx_t *ctx, struct attr_data *attr,
	       struct attr_flags flags, kdump_attr_value_t *pval));
INTERNAL_DECL(kdump_status, set_attr_number,
	      (kdump_ctx_t *ctx, struct attr_data *attr,
	       struct attr_flags flags, kdump_num_t num));
INTERNAL_DECL(kdump_status, set_attr_address,
	      (kdump_ctx_t *ctx, struct attr_data *key,
	       struct attr_flags flags, kdump_addr_t addr));
INTERNAL_DECL(kdump_status, set_attr_string,
	      (kdump_ctx_t *ctx, struct attr_data *attr,
	       struct attr_flags flags, const char *str));
INTERNAL_DECL(kdump_status, set_attr_sized_string,
	      (kdump_ctx_t *ctx, struct attr_data *attr,
	       struct attr_flags flags,
	       const char *str, size_t len));
INTERNAL_DECL(kdump_status, set_attr_static_string,
	      (kdump_ctx_t *ctx, struct attr_data *attr,
	       struct attr_flags flags, const char *str));
INTERNAL_DECL(void, clear_attr, (kdump_ctx_t *ctx, struct attr_data *attr));
INTERNAL_DECL(void, clear_volatile_attrs, (kdump_ctx_t *ctx));
INTERNAL_DECL(void, cleanup_attr, (struct kdump_shared *shared));
INTERNAL_DECL(struct attr_data *, create_attr_path,
	      (struct kdump_shared *shared,
	       struct attr_data *dir, const char *path, size_t pathlen,
	       const struct attr_template *atmpl));

/* Accessor functions for static attributes */

#define DEFINE_GET_ACCESSOR(name, type, ctype)			\
	static inline ctype					\
	get_ ## name(kdump_ctx_t *ctx)				\
	{							\
		return ctx->shared->name.type;			\
	}
#define DEFINE_SET_ACCESSOR(name, type, ctype)			\
	static inline kdump_status				\
	set_ ## name(kdump_ctx_t *ctx, ctype newval)		\
	{							\
		struct attr_data *d = gattr(ctx, GKI_ ## name);	\
		kdump_attr_value_t val;				\
		val.type = newval;				\
		return set_attr(ctx, d, ATTR_DEFAULT, &val);	\
	}
#define DEFINE_ISSET_ACCESSOR(name)				\
	static inline int					\
	isset_ ## name(kdump_ctx_t *ctx)				\
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
INTERNAL_DECL(extern const struct attr_ops, file_fd_ops, );
INTERNAL_DECL(extern const struct attr_ops, page_size_ops, );
INTERNAL_DECL(extern const struct attr_ops, page_shift_ops, );
INTERNAL_DECL(extern const struct attr_ops, cache_size_ops, );
INTERNAL_DECL(extern const struct attr_ops, arch_name_ops, );
INTERNAL_DECL(extern const struct attr_ops, ostype_ops, );
INTERNAL_DECL(extern const struct attr_ops, uts_machine_ops, );
INTERNAL_DECL(extern const struct attr_ops, vmcoreinfo_raw_ops, );

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

INTERNAL_DECL(void, attr_add_override,
	      (struct attr_data *attr, struct attr_override *override));
INTERNAL_DECL(void, attr_remove_override,
	      (struct attr_data *attr, struct attr_override *override));

/* Xen */

/**  Check if kernel physical address space is equal to machine physical one.
 */
static inline int
kphys_is_machphys(kdump_ctx_t *ctx)
{
	return get_xen_type(ctx) == KDUMP_XEN_NONE ||
		(get_xen_type(ctx) == KDUMP_XEN_DOMAIN &&
		 get_xen_xlat(ctx) == kdump_xen_auto);
}

/* Caching */

/** Default cache size.
 * The size is chosen to give some performance boost during crash analysis.
 * Constrained environments (e.g. kdump kernel) should use a lower value.
 */
#define DEFAULT_CACHE_SIZE	1024

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

INTERNAL_DECL(unsigned, get_cache_size, (kdump_ctx_t *ctx));
INTERNAL_DECL(struct cache *, cache_alloc, (unsigned n, size_t size));
INTERNAL_DECL(struct cache *, cache_ref, (struct cache *));
INTERNAL_DECL(void, cache_unref, (struct cache *));
INTERNAL_DECL(void, cache_flush, (struct cache *));
INTERNAL_DECL(struct cache_entry *, cache_get_entry,
	      (struct cache *, kdump_pfn_t));
INTERNAL_DECL(void, cache_put_entry,
	      (struct cache *cache, struct cache_entry *entry));
INTERNAL_DECL(void, cache_insert, (struct cache *, struct cache_entry *));
INTERNAL_DECL(void, cache_discard, (struct cache *, struct cache_entry *));
INTERNAL_DECL(void, cache_make_precious,
	      (struct cache *cache, struct cache_entry *entry));

typedef kdump_status read_cache_fn(
	kdump_ctx_t *ctx, kdump_pfn_t pfn, struct cache_entry *entry);

INTERNAL_DECL(kdump_status, def_read_cache,
	      (kdump_ctx_t *ctx, struct page_io *pio,
	       read_cache_fn *fn, kdump_pfn_t idx));
INTERNAL_DECL(void, cache_unref_page,
	      (kdump_ctx_t *ctx, struct page_io *pio));

static inline
void unref_page(kdump_ctx_t *ctx, struct page_io *pio)
{
	ctx->shared->ops->unref_page(ctx, pio);
}

INTERNAL_DECL(kdump_status, def_realloc_caches, (kdump_ctx_t *ctx));

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
dump16toh(kdump_ctx_t *ctx, uint16_t x)
{
	return get_byte_order(ctx) == KDUMP_BIG_ENDIAN
		? be16toh(x)
		: le16toh(x);
}

static inline uint32_t
dump32toh(kdump_ctx_t *ctx, uint32_t x)
{
	return get_byte_order(ctx) == KDUMP_BIG_ENDIAN
		? be32toh(x)
		: le32toh(x);
}

static inline uint64_t
dump64toh(kdump_ctx_t *ctx, uint64_t x)
{
	return get_byte_order(ctx) == KDUMP_BIG_ENDIAN
		? be64toh(x)
		: le64toh(x);
}

/** Check if a character is a POSIX white space.
 * @param c  Character to check.
 *
 * We are not using @c isspace here, because the library function may
 * be called in a strange locale, and the parsing should not really
 * depend on locale and this function is less overhead then messing around
 * with the C library locale...
 * Note that this code does not make any assumptions about system
 * character set, because it checks each character individually. Leave
 * possible optimizations to the C compiler.
 */
static inline int
is_posix_space(int c)
{
	return (c == ' ' || c == '\f' || c == '\n' ||
		c == '\r' || c == '\t' || c == '\v');
}

static inline kdump_addr_t
page_align(kdump_ctx_t *ctx, kdump_addr_t addr)
{
	return addr & (-get_page_size(ctx));
}

#define set_error internal_err
DECLARE_ALIAS(err);

static inline void
clear_error(kdump_ctx_t *ctx)
{
	ctx->err_str = NULL;
}

/* These are macros to avoid possible conversions of the "rd" parameter */

#define read_error(rd)  ((rd) < 0 ? KDUMP_SYSERR : KDUMP_EOF)

#endif	/* kdumpfile-priv.h */
