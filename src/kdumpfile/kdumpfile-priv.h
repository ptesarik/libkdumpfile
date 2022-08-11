/** @internal @file src/kdumpfile/kdumpfile-priv.h
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
#include <libkdumpfile/kdumpfile.h>
#pragma GCC visibility pop

#define LIBNAME	kdump
#include "../internal.h"

#include "../errmsg.h"
#include "../list.h"
#include "../threads.h"

#include <stdbool.h>
#include <endian.h>

#include <libkdumpfile/addrxlat.h>

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

/**  Maximum value represented by @ref kdump_pfn_t.
 */
#define KDUMP_PFN_MAX	KDUMP_ADDR_MAX

/** Bits for kdump_pfn_t */
#define PFN_BITS		(BITS_PER_BYTE * sizeof(kdump_pfn_t))

/** Error status for non-matching probe.
 * This error status must never be returned through the public API.
 * It is intended to let the open method know that the file cannot
 * be handled by the current format operations, but it is not really
 * an error.
 */
#define KDUMP_NOPROBE	((kdump_status)-1)

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

struct page_io;
struct kdump_shared;
struct attr_dict;

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
	 *   KDUMP_NOPROBE   cannot be handled by these ops
	 *   or any other kdump_* error status
	 */
	kdump_status (*probe)(kdump_ctx_t *ctx);

	/** Get page data.
	 * @param pio  Page I/O control.
	 *
	 * Note: The requested address space is specified in @c pio.
	 * It is always an address space specified by @c xlat_caps.
	 * Since most file formats specify only one capability, their
	 * get_page methods do not have to care.
	 */
	kdump_status (*get_page)(struct page_io *pio);

	/** Drop a reference to a page.
	 * @param pio  Page I/O control.
	 */
	void (*put_page)(struct page_io *pio);

	/** Address translation post-hook.
	 * @param ctx  Dump file object.
	 * @returns    Status code.
	 *
	 * This routine is called whenever address translation is
	 * (re-)initialized to allow format-specific adjustments to the
	 * translation system (e.g. physical<->machine address translation
	 * in a Xen DomU dump file).
	 */
	kdump_status (*post_addrxlat)(kdump_ctx_t *ctx);

	/** Reallocate any format-specific caches.
	 * @param ctx  Dump file object.
	 * @returns    Status (@ref KDUMP_OK on success).
	 */
	kdump_status (*realloc_caches)(kdump_ctx_t *ctx);

	/** Clean up attribute hooks.
	 * @param dict    Attribute dictionary.
	 */
	void (*attr_cleanup)(struct attr_dict *dict);

	/* Clean up all private data.
	 */
	void (*cleanup)(struct kdump_shared *);
};

INTERNAL_DECL(kdump_status, def_realloc_caches, (kdump_ctx_t *ctx));

struct arch_ops {
	/** Initialize any arch-specific data. */
	kdump_status (*init)(kdump_ctx_t *);

	/** Process an NT_PRSTATUS note. */
	kdump_status (*process_prstatus)(kdump_ctx_t *, const void *, size_t);

	/** Process a Xen .xen_prstatus section. */
	kdump_status (*process_xen_prstatus)(kdump_ctx_t *, const void *, size_t);

	/** OS type post-hook.
	 * @param ctx  Dump file object.
	 * @returns    Status code.
	 *
	 * This hook is called after the OS type is changed to allow
	 * arch-specific initialization (e.g. read OS_INFO on s390x).
	 */
	kdump_status (*post_ostype)(kdump_ctx_t *ctx);

	/** Address translation post-hook.
	 * @param ctx  Dump file object.
	 * @returns    Status code.
	 *
	 * This routine is called whenever address translation is
	 * (re-)initialized to allow arch-specific adjustments to the
	 * translation system (e.g. phys_base recalculation).
	 */
	kdump_status (*post_addrxlat)(kdump_ctx_t *ctx);

	/** Clean up attribute hooks.
	 * @param dict    Attribute dictionary.
	 */
	void (*attr_cleanup)(struct attr_dict *dict);

	/** Clean up any arch-specific data. */
	void (*cleanup)(struct kdump_shared *);
};

struct kdump_bmp_ops {
	/** Get raw bits. */
	kdump_status (*get_bits)(
		kdump_errmsg_t *err, const kdump_bmp_t *bmp,
		kdump_addr_t first, kdump_addr_t last, unsigned char *bits);

	/** Find a set bit. */
	kdump_status (*find_set)(
		kdump_errmsg_t *err, const kdump_bmp_t *bmp, kdump_addr_t *idx);

	/** Find a zero bit. */
	kdump_status (*find_clear)(
		kdump_errmsg_t *err, const kdump_bmp_t *bmp, kdump_addr_t *idx);

	/** Clean up any private data. */
	void (*cleanup)(const kdump_bmp_t *bmp);
};

/* kdump bitmaps */
struct _kdump_bmp {
	/** Reference counter. */
	unsigned long refcnt;

	/** Operations. */
	const struct kdump_bmp_ops *ops;

	/** Any private data (owned by the respective ops). */
	void *priv;

	/** Error message.
	 * This must be the last member. */
	kdump_errmsg_t err;
};

DECLARE_ALIAS(bmp_incref);
DECLARE_ALIAS(bmp_decref);

INTERNAL_DECL(kdump_bmp_t *, kdump_bmp_new,
	      (const struct kdump_bmp_ops *ops));

INTERNAL_DECL(void, set_bits,
	      (unsigned char *buf, size_t start, size_t end));
INTERNAL_DECL(void, clear_bits,
	      (unsigned char *buf, size_t start, size_t end));

/* kdump blobs */
struct _kdump_blob {
	/** Reference counter. */
	unsigned long refcnt;

	/** Pin counter. */
	unsigned long pincnt;

	void *data;		/**< Binary data. */
	size_t size;		/**< Size of binary data. */
};

DECLARE_ALIAS(blob_new);
DECLARE_ALIAS(blob_new_dup);
DECLARE_ALIAS(blob_incref);
DECLARE_ALIAS(blob_decref);
DECLARE_ALIAS(blob_pin);
DECLARE_ALIAS(blob_unpin);

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
 * This function is called by @ref attr_revalidate before checking
 * that the attribute has a value. The hook is intended for lazy
 * initialization of attributes which should be listed in the hierarchy
 * even before the value is known (presumably because getting its value
 * needs considerable resources).
 */
typedef kdump_status attr_revalidate_fn(
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
	attr_revalidate_fn *revalidate;
};

/**  Attribute template.
 *
 * All instances of a key share the same characteristics (such as key name
 * and value type).
 */
struct attr_template {
	const char *key;
	union {
		/** Overrides: pointer to original template. */
		const struct attr_template *parent;
		/** Global keys: attribute index in the global array. */
		enum global_keyidx parent_key;
		/** Derived attributes: number of levels below the directory
		 *  that contains the corresponding blob attribute. */
		unsigned depth;
		/** Addrxlat option attributes: target option index.
		 */
		addrxlat_optidx_t optidx;
		/** File set attributes: index inside file.fdset.*/
		size_t fidx;
	};
	kdump_attr_type_t type;
	unsigned override:1;	/**< Set iff this is a template override. */
	const struct attr_ops *ops;
};

/**  Attribute value flags.
 */
struct attr_flags {
	uint8_t isset : 1;	/**< Zero if attribute has no value */
	uint8_t persist : 1;	/**< Persistent (not cleared on re-open) */
	uint8_t dynstr : 1;	/**< Dynamically allocated string */
	uint8_t indirect : 1;	/**< Actual value is at @c *pval */
	uint8_t invalid : 1;	/**< Value needs revalidation */
};

/**  Default attribute flags. */
#define ATTR_DEFAULT	\
	((struct attr_flags){ })

/**  Persistent attribute flags. */
#define ATTR_PERSIST	\
	((struct attr_flags){ .persist = 1 })

/**  Indirect attribute flags. */
#define ATTR_INDIRECT	\
	((struct attr_flags){ .indirect = 1 })

/**  Invalid attribute flags. */
#define ATTR_INVALID	\
	((struct attr_flags){ .invalid = 1 })

/**  Persistent indirect attribute flags. */
#define ATTR_PERSIST_INDIRECT	\
	((struct attr_flags){ .persist = 1, .indirect = 1 })


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
		struct attr_data *dir;	  /**< For @c KDUMP_DIRECTORY */
		kdump_attr_value_t *pval; /**< Pointer to indirect value */
	};

	struct hlist_node list;		/**< Hash table element node */
};

/**  Size of the attribute hash table.
 */
#define ATTR_HASH_BITS	10
#define ATTR_HASH_SIZE	(1U<<ATTR_HASH_BITS)

/**  Attribute hash table.
 */
struct attr_hash {
	struct hlist_head table[ATTR_HASH_SIZE];
};

/** Shareable attribute dictionary. */
struct attr_dict {
	/** Reference counter. */
	unsigned long refcnt;

	/** Attribute hash table. */
	struct attr_hash attr;

	/** Fallback dictionary if an attribute is not found. */
	struct attr_dict *fallback;

	/** Global attributes. */
	struct attr_data *global_attrs[NR_GLOBAL_ATTRS];

	/** Dump file shared data. */
	struct kdump_shared *shared;
};

INTERNAL_DECL(kdump_status, ostype_attr,
	      (kdump_ctx_t *ctx, const char *name, struct attr_data **attr));

DECLARE_ALIAS(open_fdset);

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

	unsigned long refcnt;	/**< Reference counter. */

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

	size_t pendfiles;	/**< Number of unspecified files. */
	struct cache *cache;	/**< Page cache. */
	struct fcache *fcache;	/**< File cache. */
	mutex_t cache_lock;	/**< Cache access lock. */

	/** Static attributes. */
#define ATTR(dir, key, field, type, ctype, ...)	\
	kdump_attr_value_t field;
#include "static-attr.def"
#undef ATTR

	/** Size of per-context data. Zero means unallocated. */
	size_t per_ctx_size[PER_CTX_SLOTS];
};

INTERNAL_DECL(void, shared_free,
	      (struct kdump_shared *shared));

/** Increment shared info reference counter.
 * @param shared  Shared info.
 * @returns       New reference count.
 *
 * The shared info must be locked by the caller.
 */
static inline unsigned long
shared_incref_locked(struct kdump_shared *shared)
{
	return ++shared->refcnt;
}

INTERNAL_DECL(unsigned long, shared_incref, (struct kdump_shared *shared));

/** Decrement shared info reference counter.
 * @param shared  Shared info.
 * @returns       New reference count.
 *
 * The shared info must be locked by the caller.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards. Note that the caller
 * must not even try to unlock the object in that case.
 */
static inline unsigned long
shared_decref_locked(struct kdump_shared *shared)
{
	unsigned long refcnt = --shared->refcnt;
	if (refcnt)
		return refcnt;
	shared_free(shared);
	return 0;
}

INTERNAL_DECL(unsigned long, shared_decref, (struct kdump_shared *shared));

/**  Shareable address translation.
 */
struct kdump_xlat {
	unsigned long refcnt;	/**< Reference counter. */

	/** Is libaddrxlat (re-)initialization needed? */
	bool dirty;

	/** List of all refererring @c kdump_ctx_t structures.
	 * Each @c kdump_ctx_t that holds a reference to this shared data
	 * must be added to this list.
	 */
	struct list_head ctx;

	/** OS attribute base directory.
	 * If OS type is not set, this field contains @xref NR_GLOBAL_ATTRS,
	 * which is an invalid value.
	 */
	enum global_keyidx osdir;
	addrxlat_sys_t *xlatsys;  /**< Address translation system. */
	unsigned long xlat_caps;  /**< Address space capabilities. */
};

INTERNAL_DECL(struct kdump_xlat *, xlat_new, (void));
INTERNAL_DECL(struct kdump_xlat *, xlat_clone,
	      (const struct kdump_xlat *orig));
INTERNAL_DECL(void, xlat_free, (struct kdump_xlat *xlat));

/** Increment address translation reference counter.
 * @param xlat  Address translation.
 * @returns     New reference count.
 */
static inline unsigned long
xlat_incref(struct kdump_xlat *xlat)
{
	return ++xlat->refcnt;
}

/** Decrement address translation reference counter.
 * @param dict  Address translation.
 * @returns     New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
static inline unsigned long
xlat_decref(struct kdump_xlat *xlat)
{
	unsigned long refcnt = --xlat->refcnt;
	if (refcnt)
		return refcnt;
	xlat_free(xlat);
	return 0;
}

/**  Representation of a dump file.
 *
 * This structure contains state information and a pointer to @c struct
 * @ref kdump_shared.
 */
struct _kdump_ctx {
	struct kdump_shared *shared; /**< Dump file shared data. */

	struct attr_dict *dict;	/**< Attribute dictionary. */

	/** Node of the @c ctx list in @c struct @ref kdump_shared. */
	struct list_head list;

	/** Node of the @c ctx list in @c struct @ref kdump_xlat. */
	struct list_head xlat_list;

	/** Shared address translation data. */
	struct kdump_xlat *xlat;

	/** Address translation context. */
	addrxlat_ctx_t *xlatctx;

	/** Address translation callbacks. */
	addrxlat_cb_t *xlatcb;

	/** Per-context data. */
	void *data[PER_CTX_SLOTS];

	/** Error message buffer.
	 * This must be the last member. */
	kdump_errmsg_t err;
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
INTERNAL_DECL(extern const struct format_ops, sadump_ops, );
INTERNAL_DECL(extern const struct format_ops, devmem_ops, );

INTERNAL_DECL(kdump_status, linux_iomem_kcode,
	      (kdump_ctx_t *ctx, kdump_paddr_t *paddr));

/* Architectures */

INTERNAL_DECL(extern const struct arch_ops, aarch64_ops, );
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
INTERNAL_DECL(void, set_addrspace_caps,
	      (struct kdump_xlat *xlat, unsigned long caps));


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

INTERNAL_DECL(uint32_t, cksum32, (void *buffer, size_t size, uint32_t csum));

INTERNAL_DECL(kdump_status, get_symbol_val,
	      (kdump_ctx_t *ctx, const char *name, kdump_addr_t *val));

INTERNAL_DECL(kdump_status, set_file_description,
	      (kdump_ctx_t *ctx, const char *name));

/**  Definition of a derived attribute.
 *
 * This structure is used to translate raw binary data to an attribute
 * value and vice versa.
 */
struct derived_attr_def {
	/** Attribute template. */
	struct attr_template tmpl;

	/** Byte offset inside the blob. */
	unsigned short offset;

	/** Length in bytes. */
	unsigned short length;
};

/** Get pointer to the definition of a derived attribute.
 *
 * This macro only works for derived attributes which are embedded inside
 * a struct @ref derived_attr_def, but no checking is done. If you use
 * it on any other attribute, your code will cause memory corruption and/or
 * program crash.
 */
#define attr_to_derived_def(attr) \
	container_of((attr)->template, struct derived_attr_def, tmpl)

INTERNAL_DECL(kdump_status, init_cpu_prstatus,
	      (kdump_ctx_t *ctx, unsigned cpu, const void *data, size_t size));
INTERNAL_DECL(kdump_status, create_cpu_regs,
	      (kdump_ctx_t *ctx, unsigned cpu,
	       struct derived_attr_def *def, unsigned ndef));

INTERNAL_DECL(kdump_status, init_xen_cpu_prstatus,
	      (kdump_ctx_t *ctx, unsigned cpu, const void *data, size_t size));
INTERNAL_DECL(kdump_status, create_xen_cpu_regs,
	      (kdump_ctx_t *ctx, unsigned cpu,
	       struct derived_attr_def *def, unsigned ndef));

/* hashing */
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
INTERNAL_DECL(kdump_status, init_addrxlat, (kdump_ctx_t *ctx));

INTERNAL_DECL(kdump_status, create_addrxlat_attrs, (struct attr_dict *dict));

INTERNAL_DECL(kdump_status, vtop_init, (kdump_ctx_t *ctx));

/** Revalidate address translation.
 * @param ctx  Dump file object.
 * @returns    Error status.
 */
static inline kdump_status
revalidate_xlat(kdump_ctx_t *ctx)
{
	return ctx->xlat->dirty
		? vtop_init(ctx)
		: KDUMP_OK;
}

/* Attribute handling */
INTERNAL_DECL(extern const struct attr_template, dir_template, );
INTERNAL_DECL(struct attr_template *, alloc_attr_template,
	      (const struct attr_template *tmpl,
	       const char *key, size_t keylen));
INTERNAL_DECL(struct attr_data *, new_attr,
	      (struct attr_dict *dict, struct attr_data *parent,
	       const struct attr_template *tmpl));
INTERNAL_DECL(void, dealloc_attr, (struct attr_data *attr));
INTERNAL_DECL(struct attr_data *, lookup_attr,
	      (struct attr_dict *dict, const char *key));
INTERNAL_DECL(struct attr_data *, lookup_dir_attr,
	      (struct attr_dict *dict, const struct attr_data *dir,
	       const char *key, size_t keylen));
INTERNAL_DECL(struct attr_data *, lookup_attr_child,
	      (const struct attr_data *dir,
	       const struct attr_template *tmpl));

INTERNAL_DECL(struct attr_dict *, attr_dict_new, (struct kdump_shared *shared));
INTERNAL_DECL(struct attr_dict *, attr_dict_clone, (struct attr_dict *orig));
INTERNAL_DECL(void, attr_dict_free, (struct attr_dict *dict));

/** Increment attribute dictionary reference counter.
 * @param dict  Attribute dictionary.
 * @returns     New reference count.
 */
static inline unsigned long
attr_dict_incref(struct attr_dict *dict)
{
	return ++dict->refcnt;
}

/** Decrement attribute dictionary reference counter.
 * @param dict  Attribute dictionary.
 * @returns     New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards. Note that the caller
 * must not even try to unlock the object in that case.
 */
static inline unsigned long
attr_dict_decref(struct attr_dict *dict)
{
	unsigned long refcnt = --dict->refcnt;
	if (refcnt)
		return refcnt;
	attr_dict_free(dict);
	return 0;
}

DECLARE_ALIAS(get_attr);

/**  Attribute data by dict and global key index.
 * @param dict  Attribute dictionary.
 * @param idx   Global key index.
 * @returns     Attribute data.
 */
static inline struct attr_data *
dgattr(const struct attr_dict *dict, enum global_keyidx idx)
{
	return dict->global_attrs[idx];
}

/**  Attribute data by context and global key index.
 * @param ctx  Dump file object.
 * @param idx  Global key index.
 * @returns    Attribute data.
 */
static inline struct attr_data *
gattr(const kdump_ctx_t *ctx, enum global_keyidx idx)
{
	return dgattr(ctx->dict, idx);
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

static inline kdump_attr_value_t *
attr_mut_value(struct attr_data *attr)
{
	return attr->flags.indirect ? attr->pval : &attr->val;
}

/**  Make sure that attribute value is embedded (not indirect).
 * @param attr  Attribute data.
 *
 * If the attribute is indirect, copy the value into the attribute
 * data itself and clear the indirect flag.
 */
static inline void
attr_embed_value(struct attr_data *attr)
{
	if (attr->flags.indirect) {
		attr->val = *attr->pval;
		attr->flags.indirect = 0;
	}
}

/**  Revalidate attribute data.
 * @param ctx   Dump file object.
 * @param attr  Attribute data.
 * @returns     Error status.
 */
static inline kdump_status
attr_revalidate(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return attr->flags.invalid
		? attr->template->ops->revalidate(ctx, attr)
		: KDUMP_OK;
}

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
INTERNAL_DECL(struct attr_data *, create_attr_path,
	      (struct attr_dict *dict,
	       struct attr_data *dir, const char *path, size_t pathlen,
	       const struct attr_template *atmpl));
INTERNAL_DECL(struct attr_data *, clone_attr_path,
	      (struct attr_dict *dict, struct attr_data *orig));

/* Accessor functions for static attributes */

#define DEFINE_SGET_ACCESSOR(name, type, ctype)			\
	static inline ctype					\
	sget_ ## name(struct kdump_shared *shared)		\
	{							\
		return shared->name.type;			\
	}
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
	isset_ ## name(kdump_ctx_t *ctx)			\
	{							\
		struct attr_data *d = gattr(ctx, GKI_ ## name);	\
		return attr_isset(d);				\
	}

#define DEFINE_ACCESSORS(name, type, ctype)	\
	DEFINE_SGET_ACCESSOR(name, type, ctype)	\
	DEFINE_GET_ACCESSOR(name, type, ctype)	\
	DEFINE_SET_ACCESSOR(name, type, ctype)	\
	DEFINE_ISSET_ACCESSOR(name)

#define ATTR(dir, key, field, type, ctype, ...)	\
	DEFINE_ACCESSORS(field, type, ctype)
#include "static-attr.def"
#undef ATTR

/* Attribute ops */
INTERNAL_DECL(extern const struct attr_ops, file_fd_ops, );
INTERNAL_DECL(extern const struct attr_ops, num_files_ops, );
INTERNAL_DECL(extern const struct attr_ops, page_size_ops, );
INTERNAL_DECL(extern const struct attr_ops, page_shift_ops, );
INTERNAL_DECL(extern const struct attr_ops, cache_size_ops, );
INTERNAL_DECL(extern const struct attr_ops, arch_name_ops, );
INTERNAL_DECL(extern const struct attr_ops, ostype_ops, );
INTERNAL_DECL(extern const struct attr_ops, uts_machine_ops, );
INTERNAL_DECL(extern const struct attr_ops, vmcoreinfo_raw_ops, );
INTERNAL_DECL(extern const struct attr_ops, dirty_xlat_ops, );
INTERNAL_DECL(extern const struct attr_ops, linux_dirty_xlat_ops, );
INTERNAL_DECL(extern const struct attr_ops, xen_dirty_xlat_ops, );
INTERNAL_DECL(extern const struct attr_ops, linux_version_code_ops, );
INTERNAL_DECL(extern const struct attr_ops, linux_ver_ops, );
INTERNAL_DECL(extern const struct attr_ops, xen_version_code_ops, );
INTERNAL_DECL(extern const struct attr_ops, xen_ver_ops, );

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
		 get_xen_xlat(ctx) == KDUMP_XEN_AUTO);
}

/* Caching */

/** Type of a cache entry key.
 * This type must be big enough to hold anything that is used as
 * a key in the cache:
 *  - kdump_addr_t (used by most file handlers)
 *  - unsigned long (used by xc_core)
 *
 * An unsigned long cannot be bigger than an address (because then the
 * address would have to be bigger on such architecture).
 * So, it is safe to define this type as an alias for @ref kdump_addr_t.
 */
typedef kdump_addr_t	cache_key_t;

/** Default cache size.
 * The size is chosen to give some performance boost during crash analysis.
 * Constrained environments (e.g. kdump kernel) should use a lower value.
 */
#define DEFAULT_CACHE_SIZE	1024

/**  Cache entry state.
 */
enum cache_state {
	cs_valid,		/**< Valid (active) cache entry */
	cs_probe,		/**< In flight, target probe list */
	cs_precious,		/**< In flight, target precious list */
};

/**  Cache entry.
 */
struct cache_entry {
	cache_key_t key;	/**< Cache entry key. */
	enum cache_state state;	/**< Cache entry state. */
	unsigned next;		/**< Index of next entry in evict list. */
	unsigned prev;		/**< Index of previous entry in evict list. */
	unsigned refcnt;	/**< Reference count. */
	void *data;		/**< Pointer to data. */
};

/** Cache entry destructor.
 * @param data  User-supplied data pointer.
 * @param ce    Cache entry.
 * @sa set_cache_entry_cleanup
 */
typedef void cache_entry_cleanup_fn(void *data, struct cache_entry *ce);

INTERNAL_DECL(unsigned, get_cache_size, (kdump_ctx_t *ctx));
INTERNAL_DECL(struct cache *, cache_alloc, (unsigned n, size_t size));
INTERNAL_DECL(void, set_cache_entry_cleanup,
	      (struct cache *, cache_entry_cleanup_fn *, void *));
INTERNAL_DECL(void, cache_free, (struct cache *));
INTERNAL_DECL(void, cache_flush, (struct cache *));
INTERNAL_DECL(struct cache_entry *, cache_get_entry,
	      (struct cache *, cache_key_t));
INTERNAL_DECL(void, cache_put_entry,
	      (struct cache *cache, struct cache_entry *entry));
INTERNAL_DECL(void, cache_insert, (struct cache *, struct cache_entry *));
INTERNAL_DECL(void, cache_discard, (struct cache *, struct cache_entry *));

INTERNAL_DECL(kdump_status, cache_set_attrs,
	      (struct cache *cache, kdump_ctx_t *ctx,
	       struct attr_data *hits, struct attr_data *misses));

/**  Check if a cache entry is valid.
 *
 * @param entry  Cache entry.
 * @returns      Non-zero if the data is valid, zero otherwise.
 */
static inline int
cache_entry_valid(struct cache_entry *entry)
{
	return entry->state == cs_valid;
}

/* File cache */

/** File cache entry.
 */
struct fcache_entry {
	/** Data start. */
	void *data;

	/** Data length. */
	size_t len;

	/** Entry in the underlying cache. */
	struct cache_entry *ce;

	/** Main cache or fallback cache. */
	struct cache *cache;
};

/** Information about an open file in a file cache.
 */
struct fcache_fileinfo {
	/** Open file descriptor. */
	int fd;

	/** File size (if known) or maximum off_t. */
	off_t filesz;
};

/** File cache.
 *
 * This file cache uses one memory cache to access data from multiple
 * files. These files are denoted by an array of open file descriptors
 * (see @ref fcache_new), and later referenced by an index into that
 * array. This file index is stored in the low bits of the cache key,
 * which are normally zero, because cache entries are aligned to a page
 * boundary. As a consequence, the number of files is limited to (host)
 * page size in bytes.
 */
struct fcache {
	/** Reference counter. */
	unsigned long refcnt;

	/** Policy for using mmap(2) vs. read(2).
	 * @sa kdump_mmap_policy_t
	 */
	kdump_attr_value_t mmap_policy;

	/** Page size (in bytes). */
	size_t pgsz;

	/** Size of mmap'ed regions. */
	size_t mmapsz;

	/** Main cache (for mmap'ed regions). */
	struct cache *cache;

	/** Fallback cache (for read regions). */
	struct cache *fbcache;

	/** Information about the files. */
	struct fcache_fileinfo info[];
};

INTERNAL_DECL(struct fcache *, fcache_new,
	      (unsigned nfds, const int *fd, unsigned n, unsigned order));
INTERNAL_DECL(void, fcache_free,
	      (struct fcache *fc));

/** Increment file cache reference counter.
 * @param fc  File cache.
 * @returns   New reference count.
 */
static inline unsigned long
fcache_incref(struct fcache *fc)
{
	return ++fc->refcnt;
}

/** Decrement file cache reference counter.
 * @param fc  File cache.
 * @returns   New reference count.
 *
 * If the new reference count is zero, the underlying object is freed
 * and its address must not be used afterwards.
 */
static inline unsigned long
fcache_decref(struct fcache *fc)
{
	unsigned long refcnt = --fc->refcnt;
	if (refcnt)
		return refcnt;
	fcache_free(fc);
	return 0;
}

/** Get the file descriptor of an underlying open file.
 * @param fc    File cache.
 * @param fidx  File index.
 * @returns     File descriptor of the referenced file.
 */
static inline int
fcache_fd(struct fcache *fc, int fidx)
{
	return fc->info[fidx].fd;
}

INTERNAL_DECL(kdump_status, fcache_get,
	      (struct fcache *fc, struct fcache_entry *fce,
	       unsigned fidx, off_t pos));

INTERNAL_DECL(kdump_status, fcache_get_fb,
	      (struct fcache *fc, struct fcache_entry *fce,
	       unsigned fidx, off_t pos,
	       void *fb, size_t sz));

static inline void
fcache_put(struct fcache_entry *fce)
{
	/* Cache may be NULL after a call to fcache_get_fb. */
	if (fce->cache)
		cache_put_entry(fce->cache, fce->ce);
}

INTERNAL_DECL(kdump_status, fcache_pread,
	      (struct fcache *fc, void *buf, size_t len,
	       unsigned fidx, off_t pos));

/** Number of file cache entries embedded in a chunk descriptor. */
#define MAX_EMBED_FCES	2

/** A contiguous cached data chunk.
 */
struct fcache_chunk {
	/** Actual file data. */
	void *data;

	/** Number of cache entries. */
	size_t nent;

	union {
		/** File cache entries if @c nent <= @ref MAX_EMBED_FCES. */
		struct fcache_entry embed_fces[MAX_EMBED_FCES];

		/** File cache entries if @c nent > @ref MAX_EMBED_FCES. */
		struct fcache_entry *fces;
	};
};

INTERNAL_DECL(kdump_status, fcache_get_chunk,
	      (struct fcache *fc, struct fcache_chunk *fch,
	       size_t len, unsigned fidx, off_t pos));
INTERNAL_DECL(void, fcache_put_chunk, (struct fcache_chunk *fch));

/**  Page I/O information.
 * This structure is used to pass information between @ref kdump_read
 * and the format-specific I/O methods.
 */
struct page_io {
	kdump_ctx_t *ctx;	   /**< Associated dump file object. */
	addrxlat_fulladdr_t addr;  /**< Address of page under I/O. */
	struct fcache_chunk chunk; /**< File cache chunk. */
};

typedef kdump_status read_page_fn(struct page_io *pio);

INTERNAL_DECL(kdump_status, cache_get_page,
	      (struct page_io *pio, read_page_fn *fn));
INTERNAL_DECL(void, cache_put_page,
	      (struct page_io *pio));

/** Get page data.
 * @param pio  Page I/O control.
 * @returns    Error status.
 *
 * Intended use of this function:
 * - Fill in @c pio.ctx and @c pio.addr.
 * - Call @c get_page.
 * - Check return status. If successful, @c pio.chunk.data
 *   contains a pointer to the cached page data.
 */
static inline kdump_status
get_page(struct page_io *pio)
{
	return pio->ctx->shared->ops->get_page(pio);
}

/** Release page data.
 * @param pio  Page I/O control.
 *
 * Call this function to let the cache know that the data structures
 * used to provide the buffer are no longer needed.
 */
static inline void
put_page(struct page_io *pio)
{
	pio->ctx->shared->ops->put_page(pio);
}

/* Inline utility functions */

static inline unsigned
popcount(uint32_t x)
{
#ifdef __GNUC__
	return __builtin_popcount(x);
#else
	x -= (x >> 1) & 0x55555555;
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	x = (x + (x >> 4)) & 0x0f0f0f0f;
	return (x * 0x01010101) >> 24;
#endif
}

static inline unsigned
ctz(uint32_t x)
{
#ifdef __GNUC__
	return __builtin_ctz(x);
#else
	unsigned c = 1;
	if (!(x & 0xffff)) {
		x >>= 16;
		c += 16;
	}
	if (!(x & 0xff)) {
		x >>= 8;
		c += 8;
	}
	if (!(x & 0xf)) {
		x >>= 4;
		c += 4;
	}
	if (!(x & 0x3)) {
		x >>= 2;
		c += 2;
	}
	return c - (x & 0x1);
#endif
}

static inline unsigned
clz(uint32_t x)
{
#ifdef __GNUC__
	return __builtin_clz(x);
#else
	unsigned c = 0;
	if (!(x & 0xffff0000)) {
		x <<= 16;
		c += 16;
	}
	if (!(x & 0xff000000)) {
		x <<= 8;
		c += 8;
	}
	if (!(x & 0xf0000000)) {
		x <<= 4;
		c += 4;
	}
	if (!(x & 0xc0000000)) {
		x <<= 2;
		c += 2;
	}
	return c + !(x & 0x80000000);
#endif
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

static inline uint16_t
htodump16(kdump_ctx_t *ctx, uint16_t x)
{
	return get_byte_order(ctx) == KDUMP_BIG_ENDIAN
		? htobe16(x)
		: htole16(x);
}

static inline uint32_t
htodump32(kdump_ctx_t *ctx, uint32_t x)
{
	return get_byte_order(ctx) == KDUMP_BIG_ENDIAN
		? htobe32(x)
		: htole32(x);
}

static inline uint64_t
htodump64(kdump_ctx_t *ctx, uint64_t x)
{
	return get_byte_order(ctx) == KDUMP_BIG_ENDIAN
		? htobe64(x)
		: htole64(x);
}

/** Convert an address to a PFN.
 * @param shared  Shared variables.
 * @param addr    Address to be converted.
 * @returns       Page frame number.
 */
static inline kdump_addr_t
addr_to_pfn(struct kdump_shared *shared, kdump_addr_t addr)
{
	return addr >> sget_page_shift(shared);
}

/** Convert a PFN to an address.
 * @param shared  Shared variables.
 * @param pfn     Page frame number to be converted.
 * @returns       First address in the page.
 */
static inline kdump_addr_t
pfn_to_addr(struct kdump_shared *shared, kdump_addr_t pfn)
{
	return pfn << sget_page_shift(shared);
}

/** PFN region mapping. */
struct pfn_region {
	/** First PFN in the region. */
	kdump_pfn_t pfn;

	/** Number of pages in this region. */
	kdump_pfn_t cnt;

	/** File position corresponding to the first PFN. */
	off_t pos;
};

/** Mapping from PFN to file position using @c struct @ref pfn_region.
 */
struct pfn_file_map {
	/** PFN region map. */
	struct pfn_region *regions;

	/** Number of elements in the map. */
	size_t nregions;

	/** File index in dump file set. */
	unsigned fidx;

	/** Lowest PFN mapped to this file. */
	kdump_pfn_t start_pfn;

	/** One above the highest PFN mapped to this file.
	 * This is the lowest next PFN which is not mapped.
	 */
	kdump_pfn_t end_pfn;
};

INTERNAL_DECL(struct pfn_region *, add_pfn_region,
	      (struct pfn_file_map *map, const struct pfn_region *rgn));
INTERNAL_DECL(const struct pfn_region *, find_pfn_region,
	      (const struct pfn_file_map *map, kdump_pfn_t pfn));
INTERNAL_DECL(kdump_status, pfn_regions_from_bitmap,
	      (kdump_errmsg_t *err, struct pfn_file_map *pfm,
	       const unsigned char *bitmap, bool is_msb0,
	       kdump_pfn_t start_pfn, kdump_pfn_t end_pfn,
	       off_t fileoff, off_t elemsz));

INTERNAL_DECL(bool, find_mapped_pfn,
	      (const struct pfn_file_map *maps, size_t nmaps,
	       kdump_pfn_t *ppfn));
INTERNAL_DECL(kdump_pfn_t, find_unmapped_pfn,
	      (const struct pfn_file_map *maps, size_t nmaps,
	       kdump_pfn_t pfn));
INTERNAL_DECL(void, get_pfn_map_bits,
	      (const struct pfn_file_map *maps, size_t nmaps,
	       kdump_addr_t first, kdump_addr_t last, unsigned char *bits));
INTERNAL_DECL(void, sort_pfn_file_maps,
	      (struct pfn_file_map *maps, size_t nmaps));

/** Find a page descriptor map by PFN.
 * @param maps   Array of PFN-to-file maps.
 * @param nmaps  Number of elements in @p maps.
 * @param pfn    Page frame number.
 * @returns      PFN-to-file map which contains @p pfn or the closest
 *               higher PFN. If there is no such map, returns @c NULL.
 */
static inline const struct pfn_file_map *
find_pfn_file_map(const struct pfn_file_map *maps, size_t nmaps,
		  unsigned long pfn)
{
	while (nmaps--) {
		if (pfn < maps->end_pfn)
			return maps;
		++maps;
	}
	return NULL;
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
	return addr & (-(kdump_addr_t)get_page_size(ctx));
}

INTERNAL_DECL(kdump_status, status_err,
	      (kdump_errmsg_t *err, kdump_status status,
	       const char *msgfmt, ...));

#define set_error internal_err
DECLARE_ALIAS(err);

static inline void
clear_error(kdump_ctx_t *ctx)
{
	err_clear(&ctx->err);
}

/* These are macros to avoid possible conversions of the "rd" parameter */

#define read_error(rd)  ((rd) < 0 ? KDUMP_ERR_SYSTEM : KDUMP_ERR_EOF)

#endif	/* kdumpfile-priv.h */
