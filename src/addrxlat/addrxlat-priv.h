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

/** Extra definitions specific to pagetable translation.
 * Page table translation uses some pre-computed values, which are
 * stored in this structure on initialization.
 */
struct pgt_extra_def {
	/** PTE size as a log2 value. */
	unsigned short pte_shift;

	/** Size of virtual address space covered by page tables. */
	unsigned short vaddr_bits;

	/** Paging masks, pre-computed from paging form. */
	addrxlat_addr_t pgt_mask[ADDRXLAT_MAXLEVELS];
};

/** Internal definition of the address translation method.
 */
struct _addrxlat_meth {
	/** Reference counter. */
	unsigned long refcnt;

	/** Function to initialize a page table walk. */
	addrxlat_walk_init_fn *walk_init;

	/** Function to make one step in address translation. */
	addrxlat_walk_step_fn *walk_step;

	/** Translation definition. */
	addrxlat_def_t def;

	/** Extra kind-specific fields. */
	union {
		struct pgt_extra_def pgt;
	} extra;
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

	/** Callback for getting symbolic information. */
	addrxlat_sym_fn *cb_sym;

	/** Callback for reading 32-bit integers. */
	addrxlat_read32_fn *cb_read32;

	/** Callback for reading 64-bit integers. */
	addrxlat_read64_fn *cb_read64;

	char err_buf[ERRBUF];	/**< Error string. */
};

/** Translation map with OS-specific pieces.
 */
struct _addrxlat_osmap {
	/** Reference counter. */
	unsigned long refcnt;

	/** Translation map. */
	addrxlat_map_t *map;

	/** Address translation methods. */
	addrxlat_meth_t *meth[ADDRXLAT_OSMAP_NUM];
};

/* vtop */

#define pgt_huge_page INTERNAL_NAME(pgt_huge_page)
addrxlat_status pgt_huge_page(addrxlat_walk_t *state);

#define walk_init_pgt INTERNAL_NAME(walk_init_pgt)
addrxlat_walk_init_fn walk_init_pgt;

#define walk_check_uaddr INTERNAL_NAME(walk_check_uaddr)
addrxlat_status walk_check_uaddr(addrxlat_walk_t *walk);

#define walk_init_uaddr INTERNAL_NAME(walk_init_uaddr)
addrxlat_walk_init_fn walk_init_uaddr;

#define walk_check_saddr INTERNAL_NAME(walk_check_saddr)
addrxlat_status walk_check_saddr(addrxlat_walk_t *walk);

#define walk_init_saddr INTERNAL_NAME(walk_init_saddr)
addrxlat_walk_init_fn walk_init_saddr;

#define pgt_ia32 INTERNAL_NAME(pgt_ia32)
addrxlat_walk_step_fn pgt_ia32;

#define pgt_ia32_pae INTERNAL_NAME(pgt_ia32_pae)
addrxlat_walk_step_fn pgt_ia32_pae;

#define pgt_x86_64 INTERNAL_NAME(pgt_x86_64)
addrxlat_walk_step_fn pgt_x86_64;

#define pgt_s390x INTERNAL_NAME(pgt_s390x)
addrxlat_walk_step_fn pgt_s390x;

#define pgt_ppc64_linux_rpn30 INTERNAL_NAME(pgt_ppc64_linux_rpn30)
addrxlat_walk_step_fn pgt_ppc64_linux_rpn30;

#define paging_max_index INTERNAL_NAME(paging_max_index)
addrxlat_addr_t paging_max_index(const addrxlat_paging_form_t *pf);

/* Option parsing. */

/** All options recognized by @ref parse_opts. */
enum optidx {
	OPT_pae,		/**< [ia32] PAE state (boolean). */
	OPT_pagesize,		/**< Page size (number). */

	OPT_NUM			/**< Total number of options. */
};

/** Single option value. */
struct optval {
	unsigned char set;	/**< Non-zero if the option was specified. */
	union {
		const char *str;	/**< String(-like) values. */
		long num;		/**< Number(-like) values. */
	};
};

/** This structure holds parsed options. */
struct parsed_opts {
	/** Buffer for parsed option values. */
	char *buf;

	/** Parsed option values. */
	struct optval val[OPT_NUM];
};

#define parse_opts INTERNAL_NAME(parse_opts)
addrxlat_status parse_opts(
	struct parsed_opts *popt, addrxlat_ctx_t *ctx, const char *opts);

/* map by OS */

/** Data used during OS map initialization. */
struct osmap_init_data {
	/** Target OS map object. */
	addrxlat_osmap_t *osmap;

	/** Translation context used for initialization. */
	addrxlat_ctx_t *ctx;

	/** OS description. */
	const addrxlat_osdesc_t *osdesc;

	/** Parsed options. */
	struct parsed_opts popt;
};

/** Arch-specific OS map initialization funciton.
 * @param ctl    Initialization data.
 * @returns      Error status.
 */
typedef addrxlat_status osmap_arch_fn(struct osmap_init_data *ctl);

#define osmap_ia32 INTERNAL_NAME(osmap_ia32)
osmap_arch_fn osmap_ia32;

#define osmap_ppc64 INTERNAL_NAME(osmap_ppc64)
osmap_arch_fn osmap_ppc64;

#define osmap_s390x INTERNAL_NAME(osmap_s390x)
osmap_arch_fn osmap_s390x;

#define osmap_x86_64 INTERNAL_NAME(osmap_x86_64)
osmap_arch_fn osmap_x86_64;

/** Optional action associated with an OS-map region. */
enum osmap_action {
	OSMAP_ACT_NONE,
	OSMAP_ACT_DIRECT,
	OSMAP_ACT_X86_64_KTEXT,
};

/** Single OS-map region definition. */
struct osmap_region {
	addrxlat_addr_t first, last;
	addrxlat_osmap_xlat_t xlat;
	enum osmap_action act;
};

/** OS-map layout table end marker. */
#define OSMAP_REGION_END	{ 0, 0, ADDRXLAT_OSMAP_NUM }

/** Type of the action function for @ref osmap_set_layout.
 * @parma ctl     Initialization data.
 * @param region  Associated region definition.
 */
typedef void osmap_action_fn(
	struct osmap_init_data *ctl, const struct osmap_region *);

#define x86_64_ktext_hook INTERNAL_NAME(x86_64_ktext_hook)
osmap_action_fn x86_64_ktext_hook;

#define osmap_set_layout INTERNAL_NAME(osmap_set_layout)
addrxlat_status osmap_set_layout(
	struct osmap_init_data *ctl, const struct osmap_region layout[]);

/* internal aliases */

#define internal_meth_new INTERNAL_ALIAS(meth_new)
DECLARE_INTERNAL(meth_new)

#define internal_meth_incref INTERNAL_ALIAS(meth_incref)
DECLARE_INTERNAL(meth_incref)

#define internal_meth_decref INTERNAL_ALIAS(meth_decref)
DECLARE_INTERNAL(meth_decref)

#define internal_meth_set_def INTERNAL_ALIAS(meth_set_def)
DECLARE_INTERNAL(meth_set_def)

#define internal_walk_init INTERNAL_ALIAS(walk_init)
DECLARE_INTERNAL(walk_init)

#define internal_walk_next INTERNAL_ALIAS(walk_next)
DECLARE_INTERNAL(walk_next)

#define internal_walk INTERNAL_ALIAS(walk)
DECLARE_INTERNAL(walk)

#define internal_map_set INTERNAL_ALIAS(map_set)
DECLARE_INTERNAL(map_set)

#define internal_map_search INTERNAL_ALIAS(map_search)
DECLARE_INTERNAL(map_search)

#define internal_map_clear INTERNAL_ALIAS(map_clear)
DECLARE_INTERNAL(map_clear)

/* utils */

#define def_choose_pgtroot INTERNAL_NAME(def_choose_pgtroot)
void def_choose_pgtroot(addrxlat_def_t *def, const addrxlat_meth_t *meth);

#define get_symval INTERNAL_NAME(get_symval)
addrxlat_status get_symval(
	addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *val);

#define get_sizeof INTERNAL_NAME(get_sizeof)
addrxlat_status get_sizeof(
	addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *sz);

#define get_offsetof INTERNAL_NAME(get_offsetof)
addrxlat_status get_offsetof(
	addrxlat_ctx_t *ctx, const char *type, const char *memb,
	addrxlat_addr_t *off);

/** Set the error message.
 * @param ctx     Address translation context.
 * @param status  Error status
 * @param msgfmt  Message format string (@c printf style).
 */
#define set_error INTERNAL_NAME(set_error)
addrxlat_status set_error(
	addrxlat_ctx_t *ctx, addrxlat_status status,
	const char *msgfmt, ...)
	__attribute__ ((format (printf, 3, 4)));

#endif	/* addrxlat-priv.h */
