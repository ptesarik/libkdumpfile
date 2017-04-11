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
#include <addrxlat.h>
#pragma GCC visibility pop

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
	__asm__(XSTRINGIFY(ASM_NAME(_addrxlat_priv_ ## sym)))
#else
#define INTERNAL_DECL(type, sym, param)	\
	type sym param
#endif

#ifndef PIC
#define INTERNAL_ALIAS(x)		addrxlat_ ## x
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
#define DECLARE_ALIAS(x) _DECLARE_ALIAS(addrxlat_ ## x, internal_ ## x)

/** Define an internal alias for a symbol. */
#define DEFINE_ALIAS(x) _DEFINE_ALIAS(addrxlat_ ## x, internal_ ## x)

/* General macros */

/** Number of elements in an array variable. */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/** Size of the fallback error buffer. */
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

	/** Function to make the first translation step. */
	addrxlat_first_step_fn *first_step;

	/** Function to make the next translation step. */
	addrxlat_next_step_fn *next_step;

	/** Translation description. */
	addrxlat_desc_t desc;

	/** Extra kind-specific fields. */
	union {
		struct pgt_extra_def pgt;
	} extra;
};

/**  In-flight translation. */
struct inflight;

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

/**  Representation of address translation.
 *
 * This structure contains all internal state needed to perform address
 * translation.
 */
struct _addrxlat_ctx {
	/** Reference counter. */
	unsigned long refcnt;

	/** Callback definitions. */
	addrxlat_cb_t cb;

	/** In-flight translations. */
	struct inflight *inflight;

	char *err_str;		/**< Error string. */
	char *err_dyn;		/**< Dynamically allocated error string. */
	char err_buf[ERRBUF];	/**< Fallback buffer for the error string. */
};

/** Translation system.
 */
struct _addrxlat_sys {
	/** Reference counter. */
	unsigned long refcnt;

	/** Translation map. */
	addrxlat_map_t *map[ADDRXLAT_SYS_MAP_NUM];

	/** Address translation methods. */
	addrxlat_meth_t *meth[ADDRXLAT_SYS_METH_NUM];
};

/* vtop */

INTERNAL_DECL(addrxlat_status, read_pte, (addrxlat_step_t *step));

INTERNAL_DECL(addrxlat_status, pgt_huge_page, (addrxlat_step_t *state));

INTERNAL_DECL(addrxlat_next_step_fn, pgt_ia32, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_ia32_pae, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_x86_64, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_s390x, );

INTERNAL_DECL(addrxlat_next_step_fn, pgt_ppc64_linux_rpn30, );

INTERNAL_DECL(addrxlat_addr_t, paging_max_index,
	      (const addrxlat_paging_form_t *pf));

/* Option parsing. */

/** All options recognized by @ref parse_opts. */
enum optidx {
	OPT_pae,		/**< [ia32] PAE state (boolean). */
	OPT_pagesize,		/**< Page size (number). */
	OPT_physbase,		/**< [x86-64] Linux physical base address. */
	OPT_rootpgt,		/**< Root page table address. */
	OPT_xen_p2m_mfn,	/**< Xen p2m root machine frame number. */
	OPT_xen_xlat,		/**< Use Xen m2p and p2m translation. */

	OPT_NUM			/**< Total number of options. */
};

/** Single option value. */
struct optval {
	unsigned char set;	/**< Non-zero if the option was specified. */
	union {
		const char *str;	/**< String(-like) values. */
		long num;		/**< Number(-like) values. */

		/** Full address (with address space).*/
		addrxlat_fulladdr_t fulladdr;
	};
};

/** This structure holds parsed options. */
struct parsed_opts {
	/** Buffer for parsed option values. */
	char *buf;

	/** Parsed option values. */
	struct optval val[OPT_NUM];
};

INTERNAL_DECL(addrxlat_status, parse_opts,
	      (struct parsed_opts *popt, addrxlat_ctx_t *ctx,
	       const char *opts));

/* Translation system */

/** Data used during translation system initialization. */
struct sys_init_data {
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
typedef addrxlat_status sys_arch_fn(struct sys_init_data *ctl);

INTERNAL_DECL(sys_arch_fn, sys_ia32, );

INTERNAL_DECL(sys_arch_fn, sys_ppc64, );

INTERNAL_DECL(sys_arch_fn, sys_s390x, );

INTERNAL_DECL(sys_arch_fn, sys_x86_64, );

/** Optional action associated with a translation system region. */
enum sys_action {
	SYS_ACT_NONE,
	SYS_ACT_DIRECT,
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

INTERNAL_DECL(addrxlat_status, sys_ensure_meth,
	      (struct sys_init_data *ctl, addrxlat_sys_meth_t idx));

INTERNAL_DECL(addrxlat_status, sys_set_layout,
	      (struct sys_init_data *ctl, addrxlat_sys_map_t idx,
	       const struct sys_region layout[]));

INTERNAL_DECL(addrxlat_status, sys_set_physmaps,
	      (struct sys_init_data *ctl, addrxlat_addr_t maxaddr));

INTERNAL_DECL(addrxlat_status, sys_sym_pgtroot,
	      (struct sys_init_data *ctl, const char *reg, const char *sym));

/* internal aliases */

#define set_error internal_ctx_err
DECLARE_ALIAS(ctx_err);

DECLARE_ALIAS(meth_new);
DECLARE_ALIAS(meth_incref);
DECLARE_ALIAS(meth_decref);
DECLARE_ALIAS(meth_set_desc);
DECLARE_ALIAS(map_new);
DECLARE_ALIAS(map_incref);
DECLARE_ALIAS(map_decref);
DECLARE_ALIAS(map_set);
DECLARE_ALIAS(map_search);
DECLARE_ALIAS(map_clear);
DECLARE_ALIAS(map_dup);
DECLARE_ALIAS(launch);
DECLARE_ALIAS(launch_map);
DECLARE_ALIAS(step);
DECLARE_ALIAS(walk);
DECLARE_ALIAS(op);
DECLARE_ALIAS(fulladdr_conv);

/* near alias */
INTERNAL_DECL(addrxlat_status, xlat_op,
	      (const addrxlat_op_ctl_t *ctl,
	       const addrxlat_fulladdr_t *paddr));

/* utils */

INTERNAL_DECL(addrxlat_status, read32,
	      (addrxlat_step_t *step, const addrxlat_fulladdr_t *addr,
	       uint32_t *val, const char *what));

INTERNAL_DECL(addrxlat_status, read64,
	      (addrxlat_step_t *step, const addrxlat_fulladdr_t *addr,
	       uint64_t *val, const char *what));

INTERNAL_DECL(addrxlat_status, get_reg,
	      (addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *val));

INTERNAL_DECL(addrxlat_status, get_symval,
	      (addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *val));

INTERNAL_DECL(addrxlat_status, get_sizeof,
	      (addrxlat_ctx_t *ctx, const char *name, addrxlat_addr_t *sz));

INTERNAL_DECL(addrxlat_status, get_offsetof,
	      (addrxlat_ctx_t *ctx, const char *type, const char *memb,
	       addrxlat_addr_t *off));

/** Clear the error message.
 * @param ctx     Address translation context.
 */
static inline void
clear_error(addrxlat_ctx_t *ctx)
{
	ctx->err_str = NULL;
}

#endif	/* addrxlat-priv.h */
