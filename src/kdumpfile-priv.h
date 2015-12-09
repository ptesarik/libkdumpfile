/* Private interfaces for libkdumpfile (kernel coredump file access).
   Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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
#include "kdumpfile.h"

#include <endian.h>

/* Minimize chance of name clashes (in a static link) */
#define INTERNAL_NAME(x)	_libkdump_priv_ ## x

/* This should cover all possibilities:
 * - no supported architecture has less than 4K pages.
 * - PowerPC can have up to 256K large pages.
 */
#define MIN_PAGE_SIZE	(1UL << 12)
#define MAX_PAGE_SIZE	(1UL << 18)

/* General macros */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

typedef kdump_addr_t kdump_pfn_t;

enum kdump_arch {
	ARCH_UNKNOWN = 0,
	ARCH_AARCH64,
	ARCH_ALPHA,
	ARCH_ARM,
	ARCH_IA64,
	ARCH_MIPS,
	ARCH_PPC,
	ARCH_PPC64,
	ARCH_S390,
	ARCH_S390X,
	ARCH_X86,
	ARCH_X86_64,
};

struct format_ops {
	/* Probe for a given file format.
	 * Input:
	 *   ctx->buffer     MAX_PAGE_SIZE bytes from the file beginning
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
	 *   kdump_unsupported dump file format does not match
	 *   kdump_syserr    OS error (e.g. read or memory allocation)
	 *   kdump_dataerr   file data is not valid
	 */
	kdump_status (*probe)(kdump_ctx *);

	/* Read a page from the dump file.
	 * Input:
	 *   ctx->fd         core dump file descriptor open for reading
	 *   ctx->page       pointer to a page-sized buffer
	 *   ctx->buffer     temporary buffer of MAX_PAGE_SIZE bytes
	 * Return:
	 *   kdump_ok        buffer is filled with page data
	 *   kdump_nodata    data for the given page is not present
	 */
	kdump_status (*read_page)(kdump_ctx *, kdump_pfn_t);

	/* Read a page from the dump file using Xen machine addresses.
	 * Input:
	 *   ctx->fd         core dump file descriptor open for reading
	 *   ctx->page       pointer to a page-sized buffer
	 *   ctx->buffer     temporary buffer of MAX_PAGE_SIZE bytes
	 * Return:
	 *   kdump_ok        buffer is filled with page data
	 *   kdump_nodata    data for the given page is not present
	 */
	kdump_status (*read_xenmach_page)(kdump_ctx *, kdump_pfn_t);

	/* Translate a machine frame number to physical frame number.
	 *   ctx->fmtdata    initialized in probe()
	 * Return:
	 *   kdump_ok        output variable contains translated PFN
	 *   kdump_nodata    given MFN was not found
	 */
	kdump_status (*mfn_to_pfn)(kdump_ctx *, kdump_pfn_t, kdump_pfn_t *);

	/* Clean up all private data.
	 */
	void (*cleanup)(kdump_ctx *);
};

struct arch_ops {
	/* Initialize any arch-specific data
	 */
	kdump_status (*init)(kdump_ctx *);

	/* Initialise virtual-to-physical translation.
	 */
	kdump_status (*vtop_init)(kdump_ctx *);

	/* Process an NT_PRSTATUS note
	 */
	kdump_status (*process_prstatus)(kdump_ctx *, void *, size_t);

	/* Read a register value:
	 *   cpu    CPU number (in dumpfile order)
	 *   index  CPU index (arch-dependent)
	 *          no guarantees - return kdump_nodata if out of range
	 *   value  will contain register value on success
	 */
	kdump_status (*read_reg)(kdump_ctx *ctx, unsigned cpu, unsigned index,
				 kdump_reg_t *value);

	/* Process a LOAD segment
	 */
	kdump_status (*process_load)(kdump_ctx *ctx, kdump_vaddr_t vaddr,
				     kdump_paddr_t paddr);

	/* Translate a virtual address to a physical address
	 */
	kdump_status (*vtop)(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			     kdump_paddr_t *paddr);

	/* Clean up any arch-specific data
	 */
	void (*cleanup)(kdump_ctx *);
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

struct vmcoreinfo_row {
	const char *key, *val;
};

struct vmcoreinfo {
	char *raw;		/* raw content */
	unsigned n;		/* number of rows */
	struct vmcoreinfo_row row[]; /* parsed rows */
};

typedef enum _tag_kdump_xlat {
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
} kdump_xlat_t;

/* Maximum length of the error message */
#define ERRBUF	160

struct kdump_vaddr_region {
	kdump_vaddr_t max_off;	/* max offset inside the range */
	kdump_addr_t phys_off;	/* offset from physical addresses */
	kdump_xlat_t xlat;	/* vaddr->paddr translation method */
};

/* Global attribute keys */
enum global_keyidx {
#define ATTR(dir, key, field, type, ctype)	\
	GKI_ ## field,
#include "static-attr.def"
#include "global-attr.def"
#undef ATTR
};

#define GATTR(idx)	((const char*)-(intptr_t)(idx))

/**  Attribute template.
 *
 * All instances of a key share the same characteristics (such as key name
 * and value type).
 */
struct attr_template {
	const char *key;
	const struct attr_template *parent;
	enum kdump_attr_type type;
};

/**  Dynamically allocated attribute template.
 *
 * Dynamically allocated templates are maintained in a linked list,
 * so they need a separate type with a @c next field.
 */
struct dyn_attr_template {
	struct dyn_attr_template *next;
	struct attr_template template;
};

/**  Data type for storing attribute value in each instance.
 *
 * Note that this structure does not include type, because it must be
 * equal to the template type.
 */
struct attr_data {
	struct attr_data *next, **pprev;
	const struct attr_template *template;
	union kdump_attr_value val;
};

struct _tag_kdump_ctx {
	int fd;			/* dump file descriptor */
	const char *format;	/* file format (descriptive name) */
	unsigned long flags;	/* see DIF_XXX below */

	/* format-specific fields */
	const struct format_ops *ops;
	void *fmtdata;		/* private data */

	/* arch-specific fields */
	const struct arch_ops *arch_ops;
	void *archdata;		/* private data */

	/* read_page internals */
	void *buffer;		/* temporary buffer */
	void *page;		/* page data buffer */
	kdump_pfn_t last_pfn;	/* last read PFN */
	kdump_pfn_t max_pfn;	/* max PFN for read_page */

	/* address translation */
	struct kdump_vaddr_region *region;
	unsigned num_regions;	/* number of elements in ->region */

	/* attribute templates */
	struct dyn_attr_template *tmpl;

	/* static attributes */
#define ATTR(dir, key, field, type, ctype)	\
	struct attr_data field;
#include "static-attr.def"
#undef ATTR

	struct vmcoreinfo *vmcoreinfo;
	struct vmcoreinfo *vmcoreinfo_xen;

	kdump_pfn_t xen_p2m_mfn;
	int xen_pte_is_mach;

	/* callbacks */
	kdump_get_symbol_val_fn *cb_get_symbol_val;

	/* error messages */
	char *err_str;		/* error string */
	char err_buf[ERRBUF];	/* buffer for error string */
};

/* kdump_ctx flags */
#define DIF_XEN		(1UL<<1)

/* File formats */

#define elfdump_ops INTERNAL_NAME(elfdump_ops)
extern const struct format_ops elfdump_ops;

#define kvm_ops INTERNAL_NAME(kvm_ops)
extern const struct format_ops kvm_ops;

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

/* struct timeval has a different layout on 32-bit and 64-bit */
struct timeval_32 {
	int32_t tv_sec;
	int32_t tv_usec;
};
struct timeval_64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

/* utils */

#define set_error INTERNAL_NAME(set_error)
kdump_status set_error(kdump_ctx *ctx, kdump_status ret,
		       const char *msgfmt, ...)
	__attribute__ ((format (printf, 3, 4)));

#define ctx_malloc INTERNAL_NAME(ctx_malloc)
void *ctx_malloc(size_t size, kdump_ctx *ctx, const char *desc);

#define machine_arch INTERNAL_NAME(machine_arch)
enum kdump_arch machine_arch(const char *machine);

#define set_arch INTERNAL_NAME(set_arch)
kdump_status set_arch(kdump_ctx *ctx, enum kdump_arch arch);

#define set_page_size INTERNAL_NAME(set_page_size)
kdump_status set_page_size(kdump_ctx *ctx, size_t page_size);

#define set_uts INTERNAL_NAME(set_uts)
kdump_status set_uts(kdump_ctx *ctx, const struct new_utsname *src);

#define uts_looks_sane INTERNAL_NAME(uts_looks_sane)
int uts_looks_sane(struct new_utsname *uts);

#define uncompress_rle INTERNAL_NAME(uncompress_rle)
int uncompress_rle(unsigned char *dst, size_t *pdstlen,
		   const unsigned char *src, size_t srclen);

#define store_vmcoreinfo INTERNAL_NAME(store_vmcoreinfo)
kdump_status store_vmcoreinfo(kdump_ctx *ctx, struct vmcoreinfo **pinfo,
			      void *data, size_t len);

#define paged_read INTERNAL_NAME(paged_read)
ssize_t paged_read(int fd, void *buffer, size_t size);

#define cksum32 INTERNAL_NAME(cksum32)
uint32_t cksum32(void *buffer, size_t size, uint32_t csum);

#define get_symbol_val INTERNAL_NAME(get_symbol_val)
kdump_status get_symbol_val(kdump_ctx *ctx, const char *name,
			    kdump_addr_t *val);

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

#define set_region INTERNAL_NAME(set_region)
kdump_status set_region(kdump_ctx *ctx,
			kdump_vaddr_t first, kdump_vaddr_t last,
			kdump_xlat_t xlat, kdump_vaddr_t phys_off);

#define flush_regions INTERNAL_NAME(flush_regions)
void flush_regions(kdump_ctx *ctx);

#define get_xlat INTERNAL_NAME(get_xlat)
kdump_xlat_t get_xlat(kdump_ctx *ctx, kdump_vaddr_t vaddr,
		      kdump_paddr_t *phys_off);

/* Attribute handling */

#define add_attr_template INTERNAL_NAME(add_attr_template)
kdump_status add_attr_template(kdump_ctx *ctx, const char *path,
			       enum kdump_attr_type type);

#define init_static_attrs INTERNAL_NAME(init_static_attrs)
void init_static_attrs(kdump_ctx *ctx);

#define attr_isset INTERNAL_NAME(attr_isset)
int attr_isset(const kdump_ctx *ctx, const char *key);

/**  Check if a statically allocated attribute is set.
 * @param data  Pointer to the static attribute.
 * @returns     Non-zero if attribute data is valid.
 */
static inline int
static_attr_isset(const struct attr_data *data)
{
	return !!data->pprev;
}

#define set_attr INTERNAL_NAME(set_attr)
kdump_status set_attr(kdump_ctx *ctx, struct attr_data *attr);

#define set_attr_number INTERNAL_NAME(set_attr_number)
kdump_status set_attr_number(kdump_ctx *ctx, const char *key,
			     kdump_num_t num);

#define set_attr_address INTERNAL_NAME(set_attr_address)
kdump_status set_attr_address(kdump_ctx *ctx, const char *key,
			      kdump_addr_t addr);

#define set_attr_string INTERNAL_NAME(set_attr_string)
kdump_status set_attr_string(kdump_ctx *ctx, const char *key,
			     const char *str);

#define set_attr_static_string INTERNAL_NAME(set_attr_static_string)
kdump_status set_attr_static_string(kdump_ctx *ctx, const char *key,
				    const char *str);

#define cleanup_attr INTERNAL_NAME(cleanup_attr)
void cleanup_attr(kdump_ctx *ctx);

/* Accessor functions for static attributes */

#define DEFINE_GET_ACCESSOR(name, type, ctype)			\
	static inline ctype					\
	get_attr_ ## name(kdump_ctx *ctx)			\
	{							\
		return ctx->name.val.type;			\
	}
#define DEFINE_SET_ACCESSOR(name, type, ctype)			\
	static inline void					\
	set_attr_ ## name(kdump_ctx *ctx, ctype newval)		\
	{							\
		ctx->name.val.type = newval;			\
		set_attr(ctx, &ctx->name); /* fail-safe */	\
	}

#define ATTR(dir, key, field, type, ctype)	\
	DEFINE_GET_ACCESSOR(field, type, ctype) \
	DEFINE_SET_ACCESSOR(field, type, ctype)
#include "static-attr.def"
#undef ATTR

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
	return get_attr_byte_order(ctx) == kdump_big_endian
		? be16toh(x)
		: le16toh(x);
}

static inline uint32_t
dump32toh(kdump_ctx *ctx, uint32_t x)
{
	return get_attr_byte_order(ctx) == kdump_big_endian
		? be32toh(x)
		: le32toh(x);
}

static inline uint64_t
dump64toh(kdump_ctx *ctx, uint64_t x)
{
	return get_attr_byte_order(ctx) == kdump_big_endian
		? be64toh(x)
		: le64toh(x);
}

static inline void
clear_error(kdump_ctx *ctx)
{
	ctx->err_str = NULL;
}

/* These are macros to avoid possible conversions of the "rd" parameter */

#define read_error(rd)  ((rd) < 0 ? kdump_syserr : kdump_dataerr)
#define read_err_str(rd) ((rd) < 0 ? strerror(errno) : "Unexpected EOF")

#endif	/* kdumpfile-priv.h */
