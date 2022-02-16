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
#include <libkdumpfile/addrxlat.h>
#pragma GCC visibility pop

#define LIBNAME	addrxlat
#include "../internal.h"
#include "../errmsg.h"

#include <stdbool.h>

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

/* General macros */

/** Number of elements in an array variable. */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/** Use this to mask off address bits above @c bits. */
#define ADDR_MASK(bits)		(((addrxlat_addr_t)1 << (bits)) - 1)

/**  In-flight translation. */
struct inflight;

/** Number of read cache slots. */
#define READ_CACHE_SLOTS	4

/** Cache slot (buffer plus cache metadata). */
struct read_cache_slot {
	/** Buffer metadata */
	addrxlat_buffer_t buffer;

	/** MRU chain. */
	struct read_cache_slot *prev, *next;
};

/** Read cache storage and metadata. */
struct read_cache {
	/** Most recently used cache slot. */
	struct read_cache_slot *mru;

	/** Cache slots. */
	struct read_cache_slot slot[READ_CACHE_SLOTS];
};

INTERNAL_DECL(void, bury_cache_buffer,
	      (struct read_cache *cache, const addrxlat_fulladdr_t *addr));

/**  Representation of address translation.
 *
 * This structure contains all internal state needed to perform address
 * translation.
 */
struct _addrxlat_ctx {
	/** Reference counter. */
	unsigned long refcnt;

	/** Events with no eror reporting. */
	struct {
		/** Skip error reporting of non-present pages. */
		int notpresent : 1;
	} noerr;

	/** Callback definitions. */
	addrxlat_cb_t cb;

	/** Original callback definitions.
	 * This is the value originally passed to @ref addrxlat_ctx_set_cb,
	 * i.e. before being modified by a callback hook.
	 */
	addrxlat_cb_t orig_cb;

	/** In-flight translations. */
	struct inflight *inflight;

	/** Read cache. */
	struct read_cache cache;

	/** Error message buffer.
	 * This must be the last member. */
	kdump_errmsg_t err;
};

/* utils */

INTERNAL_DECL(addrxlat_status, get_cache_buf,
	      (addrxlat_ctx_t *ctx, const addrxlat_fulladdr_t *addr,
	       addrxlat_buffer_t **pbuf));

INTERNAL_DECL(addrxlat_status, read32,
	      (addrxlat_step_t *step, const addrxlat_fulladdr_t *addr,
	       uint32_t *val, const char *what));

INTERNAL_DECL(addrxlat_status, read64,
	      (addrxlat_step_t *step, const addrxlat_fulladdr_t *addr,
	       uint64_t *val, const char *what));

INTERNAL_DECL(addrxlat_status, do_read32,
	      (addrxlat_ctx_t *ctx, const addrxlat_fulladdr_t *addr,
	       uint32_t *val));

INTERNAL_DECL(addrxlat_status, do_read64,
	      (addrxlat_ctx_t *ctx, const addrxlat_fulladdr_t *addr,
	       uint64_t *val));

INTERNAL_DECL(addrxlat_status, get_reg,
	      (addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *val));

INTERNAL_DECL(addrxlat_status, get_symval,
	      (addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *val));

INTERNAL_DECL(addrxlat_status, get_sizeof,
	      (addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *sz));

INTERNAL_DECL(addrxlat_status, get_offsetof,
	      (addrxlat_ctx_t *ctx, const char *type, const char *memb,
	       addrxlat_addr_t *off));

INTERNAL_DECL(addrxlat_status, get_number,
	      (addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *num));

/** Maximum symbol specifier name length. */
#define SYM_SPEC_NAMELEN 24

/** Symbolic type specifier.
 * @sa get_first_sym
 */
struct sym_spec {
	/** Type of information.
	 * Use @ref ADDRXLAT_SYM_NONE to terminate a vector.
	 */
	addrxlat_sym_type_t type;

	/** Symbol address space. */
	addrxlat_addrspace_t as;

	/** Symbolic name.
	 */
	const char name[SYM_SPEC_NAMELEN];
};

/** Non-existent type of symbolic information. */
#define ADDRXLAT_SYM_NONE	((addrxlat_sym_type_t)-1)

INTERNAL_DECL(addrxlat_status, get_first_sym,
	      (addrxlat_ctx_t *ctx, const struct sym_spec *spec,
	       addrxlat_fulladdr_t *addr));

/**  Internal definition of an address translation map.
 * Note that the start address does not have to be stored in the
 * structure. The first range in a map starts at address 0, and
 * each following range starts right after the previous one (i.e.
 * at @c endoff + 1).
 */
struct _addrxlat_map {
	/** Reference counter. */
	unsigned long refcnt;

	/** Number of elements in @c ranges. */
	size_t n;

	/** Actual range definitions. */
	addrxlat_range_t *ranges;
};

/** Clear a translation map.
 * @param map  Address translation map.
 *
 * This function re-initializes the translation map. The resulting empty
 * map may be reused after calling this function.
 */
static inline void
map_clear(addrxlat_map_t *map)
{
	map->n = 0;
}

/** Translation system.
 */
struct _addrxlat_sys {
	/** Reference counter. */
	unsigned long refcnt;

	/** Translation map. */
	addrxlat_map_t *map[ADDRXLAT_SYS_MAP_NUM];

	/** Address translation methods. */
	addrxlat_meth_t meth[ADDRXLAT_SYS_METH_NUM];
};

/* vtop */

/** Read raw 32-bit PTE value.
 * @param step  Current step state.
 * @param pte   Set to the (masked) PTE value on success.
 * @returns     Error status.
 *
 * On successful return, @c step->raw.pte contains the raw
 * PTE value for the current translation step.
 */
static inline addrxlat_status
read_pte32(addrxlat_step_t *step, addrxlat_pte_t *pte)
{
	uint32_t pte32;
	addrxlat_status status;
	status = read32(step, &step->base, &pte32, "PTE");
	if (status == ADDRXLAT_OK) {
		step->raw.pte = pte32;
		*pte = pte32 & ~step->meth->param.pgt.pte_mask;
	}
	return status;
}

/** Read raw 64-bit PTE value.
 * @param step  Current step state.
 * @param pte   Set to the (masked) PTE value on success.
 * @returns     Error status.
 *
 * On successful return, @c step->raw.pte contains the raw
 * PTE value for the current translation step.
 */
static inline addrxlat_status
read_pte64(addrxlat_step_t *step, addrxlat_pte_t *pte)
{
	uint64_t pte64;
	addrxlat_status status;
	status = read64(step, &step->base, &pte64, "PTE");
	if (status == ADDRXLAT_OK) {
		step->raw.pte = pte64;
		*pte = pte64 & ~step->meth->param.pgt.pte_mask;
	}
	return status;
}

INTERNAL_DECL(addrxlat_status, pgt_huge_page, (addrxlat_step_t *state));

INTERNAL_DECL(addrxlat_next_step_fn, pgt_aarch64, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_ia32, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_ia32_pae, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_x86_64, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_s390x, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_ppc64_linux_rpn30, );

/** Get the page size for a given paging form.
 * @param pf  Paging form.
 * @returns   Page size.
 */
static inline addrxlat_addr_t
pf_page_size(const addrxlat_paging_form_t *pf)
{
	return (addrxlat_addr_t)1 << pf->fieldsz[0];
}

/** Get the page mask for a given paging form.
 * @param pf  Paging form.
 * @returns   Page mask.
 *
 * When applied to an address, page mask gives the offset within a page.
 */
static inline addrxlat_addr_t
pf_page_mask(const addrxlat_paging_form_t *pf)
{
	return pf_page_size(pf) - 1;
}

/** Get the number of elements in a page table at a given level.
 * @param pf     Paging form.
 * @param level  Page table level.
 * @returns      Number of elements in this page.
 *
 * NB if @c level is zero, page size is returned.
 */
static inline addrxlat_addr_t
pf_table_size(const addrxlat_paging_form_t *pf, unsigned short level)
{
	return (addrxlat_addr_t)1 << pf->fieldsz[level];
}

/** Get the number of addresses covered by a page table at a given level.
 * @param pf     Paging form.
 * @param level  Page table level.
 * @returns      Number of addresses spanned by the page table entry.
 */
static inline addrxlat_addr_t
pf_table_span(const addrxlat_paging_form_t *pf, unsigned short level)
{
	addrxlat_addr_t ret = 1;
	while (level--)
		ret <<= pf->fieldsz[level];
	return ret;
}

/** Get the address mask for a page table at a given level.
 * @param pf     Paging form.
 * @param level  Page table level.
 * @returns      Page mask.
 */
static inline addrxlat_addr_t
pf_table_mask(const addrxlat_paging_form_t *pf, unsigned short level)
{
	return pf_table_span(pf, level) - 1;
}

INTERNAL_DECL(addrxlat_addr_t, paging_max_index,
	      (const addrxlat_paging_form_t *pf));

INTERNAL_DECL(addrxlat_status, lowest_mapped,
	      (addrxlat_step_t *step, addrxlat_addr_t *addr,
	       addrxlat_addr_t limit));
INTERNAL_DECL(addrxlat_status, highest_mapped,
	      (addrxlat_step_t *step, addrxlat_addr_t *addr,
	       addrxlat_addr_t limit));
INTERNAL_DECL(addrxlat_status, lowest_unmapped,
	      (addrxlat_step_t *step, addrxlat_addr_t *addr,
	       addrxlat_addr_t limit));

INTERNAL_DECL(addrxlat_status, highest_linear,
	      (addrxlat_step_t *step, addrxlat_addr_t *addr,
	       addrxlat_addr_t limit, addrxlat_addr_t off));

/* Option parsing. */

/** All options recognized by @ref parse_opts. */
enum optidx {
	OPT_levels,		/**< Number of page table levels. */
	OPT_pagesize,		/**< Page size (number). */
	OPT_phys_base,		/**< [x86-64] Linux physical base address. */
	OPT_rootpgt,		/**< Root page table address. */
	OPT_xen_p2m_mfn,	/**< Xen p2m root machine frame number. */
	OPT_xen_xlat,		/**< Use Xen m2p and p2m translation. */

	OPT_NUM			/**< Total number of options. */
};

/** Single option value. */
union optval {
	const char *str;	/**< String(-like) values. */
	long num;		/**< Number(-like) values. */
	addrxlat_addr_t addr;	/**< Simple address or offset. */

	/** Full address (with address space).*/
	addrxlat_fulladdr_t fulladdr;
};

/** This structure holds parsed options. */
struct parsed_opts {
	/** Buffer for parsed option values. */
	char *buf;

	/** Set/unset flag for each option. */
	bool isset[OPT_NUM];

	/** Parsed option values. */
	union optval val[OPT_NUM];
};

INTERNAL_DECL(addrxlat_status, parse_opts,
	      (struct parsed_opts *popt, addrxlat_ctx_t *ctx,
	       const char *opts));

/* Translation system */

/** Data used during translation system initialization. */
struct os_init_data {
	/** Target translation system. */
	addrxlat_sys_t *sys;

	/** Translation context used for initialization. */
	addrxlat_ctx_t *ctx;

	/** OS description. */
	const addrxlat_osdesc_t *osdesc;

	/** Parsed options. */
	struct parsed_opts popt;
};

/** Arch-specific translation system initialization funciton.
 * @param ctl    Initialization data.
 * @returns      Error status.
 */
typedef addrxlat_status sys_arch_fn(struct os_init_data *ctl);

INTERNAL_DECL(sys_arch_fn, sys_aarch64, );

INTERNAL_DECL(sys_arch_fn, sys_ia32, );

INTERNAL_DECL(sys_arch_fn, sys_ppc64, );

INTERNAL_DECL(sys_arch_fn, sys_s390x, );

INTERNAL_DECL(sys_arch_fn, sys_x86_64, );

/** Optional action associated with a translation system region. */
enum sys_action {
	SYS_ACT_NONE,
	SYS_ACT_DIRECT,
	SYS_ACT_RDIRECT,
	SYS_ACT_IDENT_KPHYS,
	SYS_ACT_IDENT_MACHPHYS,
};

/** Single OS-map region definition. */
struct sys_region {
	addrxlat_addr_t first, last;
	addrxlat_sys_meth_t meth;
	enum sys_action act;
};

/** OS-map layout table end marker. */
#define SYS_REGION_END	{ 0, 0, ADDRXLAT_SYS_METH_NUM }

INTERNAL_DECL(addrxlat_status, sys_set_layout,
	      (struct os_init_data *ctl, addrxlat_sys_map_t idx,
	       const struct sys_region layout[]));

INTERNAL_DECL(addrxlat_status, sys_set_physmaps,
	      (struct os_init_data *ctl, addrxlat_addr_t maxaddr));

INTERNAL_DECL(addrxlat_status, sys_sym_pgtroot,
	      (struct os_init_data *ctl, const struct sym_spec *spec));

/* internal aliases */

DECLARE_ALIAS(addrspace_name);

#define set_error internal_ctx_err
DECLARE_ALIAS(ctx_err);

DECLARE_ALIAS(map_new);
DECLARE_ALIAS(map_incref);
DECLARE_ALIAS(map_decref);
DECLARE_ALIAS(map_set);
DECLARE_ALIAS(map_search);
DECLARE_ALIAS(map_copy);
DECLARE_ALIAS(launch);
DECLARE_ALIAS(step);
DECLARE_ALIAS(walk);
DECLARE_ALIAS(op);
DECLARE_ALIAS(fulladdr_conv);

/** Clear the error message.
 * @param ctx     Address translation context.
 */
static inline void
clear_error(addrxlat_ctx_t *ctx)
{
	err_clear(&ctx->err);
}

static inline addrxlat_status
bad_paging_levels(addrxlat_ctx_t *ctx, long levels)
{
	return set_error(ctx, ADDRXLAT_ERR_NOTIMPL,
			 "%ld-level paging not implemented", levels);
}

#endif	/* addrxlat-priv.h */
