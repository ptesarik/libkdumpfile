/** @internal @file src/addrxlat/sys.c
 * @brief Translation system routines.
 */
/* Copyright (C) 2016-2017 Petr Tesarik <ptesarik@suse.com>

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

#include <stdlib.h>
#include <string.h>

#include "addrxlat-priv.h"

addrxlat_sys_t *
addrxlat_sys_new(void)
{
	addrxlat_sys_t *ret;

	ret = calloc(1, sizeof(addrxlat_sys_t));
	if (ret) {
		ret->refcnt = 1;
	}
	return ret;
}

unsigned long
addrxlat_sys_incref(addrxlat_sys_t *sys)
{
	return ++sys->refcnt;
}

/** Clean up all translation system maps and methods.
 * @param sys  Translation system.
 */
static void
sys_cleanup(addrxlat_sys_t *sys)
{
	unsigned i;

	for (i = 0; i < ADDRXLAT_SYS_MAP_NUM; ++i)
		if (sys->map[i]) {
			internal_map_decref(sys->map[i]);
			sys->map[i] = NULL;
		}
}

unsigned long
addrxlat_sys_decref(addrxlat_sys_t *sys)
{
	unsigned long refcnt = --sys->refcnt;
	if (!refcnt) {
		sys_cleanup(sys);
		free(sys);
	}
	return refcnt;
}

addrxlat_status
addrxlat_sys_os_init(addrxlat_sys_t *sys, addrxlat_ctx_t *ctx,
		     const addrxlat_osdesc_t *osdesc)
{
	struct os_init_data ctl;
	sys_arch_fn *arch_fn;
	addrxlat_status status;

	clear_error(ctx);

	if (!strcmp(osdesc->arch, "x86_64"))
		arch_fn = sys_x86_64;
	else if ((osdesc->arch[0] == 'i' &&
		  (osdesc->arch[1] >= '3' && osdesc->arch[1] <= '6') &&
		  !strcmp(osdesc->arch + 2, "86")) ||
		 !strcmp(osdesc->arch, "ia32"))
		arch_fn = sys_ia32;
	else if (!strcmp(osdesc->arch, "s390x"))
		arch_fn = sys_s390x;
	else if (!strcmp(osdesc->arch, "ppc64"))
		arch_fn = sys_ppc64;
	else if (!strcmp(osdesc->arch, "aarch64"))
		arch_fn = sys_aarch64;
	else
		return set_error(ctx, ADDRXLAT_ERR_NOTIMPL,
				"Unsupported architecture");

	sys_cleanup(sys);

	ctl.sys = sys;
	ctl.ctx = ctx;
	ctl.osdesc = osdesc;

	status = parse_opts(&ctl.popt, ctx, osdesc->opts);
	if (status != ADDRXLAT_OK)
		return status;

	return arch_fn(&ctl);
}

void
addrxlat_sys_set_map(addrxlat_sys_t *sys, addrxlat_sys_map_t idx,
		      addrxlat_map_t *map)
{
	if (map)
		internal_map_incref(map);
	if (sys->map[idx])
		internal_map_decref(sys->map[idx]);
	sys->map[idx] = map;
}

addrxlat_map_t *
addrxlat_sys_get_map(const addrxlat_sys_t *sys, addrxlat_sys_map_t idx)
{
	return sys->map[idx];
}

void
addrxlat_sys_set_meth(addrxlat_sys_t *sys,
		      addrxlat_sys_meth_t idx, const addrxlat_meth_t *meth)
{
	sys->meth[idx] = *meth;
}

const addrxlat_meth_t *
addrxlat_sys_get_meth(const addrxlat_sys_t *sys, addrxlat_sys_meth_t idx)
{
	return &sys->meth[idx];
}

/** Action function for @ref SYS_ACT_DIRECT.
 * @param ctl     Initialization data.
 * @param region  Directmap region definition.
 * @returns       Error status.
 *
 * This action sets up the direct mapping as a linear mapping that
 * maps the current region to kernel physical addresses starting at 0.
 */
static addrxlat_status
act_direct(struct os_init_data *ctl, const struct sys_region *region)
{
	struct sys_region layout[2] = {
		{ 0, region->last - region->first,
		  ADDRXLAT_SYS_METH_RDIRECT, SYS_ACT_RDIRECT },
		SYS_REGION_END
	};
	addrxlat_meth_t *meth;

	meth = &ctl->sys->meth[region->meth];
	meth->kind = ADDRXLAT_LINEAR;
	meth->target_as = ADDRXLAT_KPHYSADDR;
	meth->param.linear.off = -region->first;

	return sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KPHYS_DIRECT, layout);
}

/** Action function for @ref SYS_ACT_RDIRECT.
 * @param ctl     Initialization data.
 * @param region  Reverse directmap region definition.
 *
 * This action sets up the reverse direct mapping as a linear mapping
 * that maps the current region to kernel virtual addresses, using
 * offset from the direct mapping method.
 */
static void
act_rdirect(struct os_init_data *ctl, const struct sys_region *region)
{
	addrxlat_meth_t *meth = &ctl->sys->meth[region->meth];
	meth->kind = ADDRXLAT_LINEAR;
	meth->target_as = ADDRXLAT_KVADDR;
	meth->param.linear.off =
		-ctl->sys->meth[ADDRXLAT_SYS_METH_DIRECT].param.linear.off;
}

/** Action function for @ref SYS_ACT_IDENT_KPHYS.
 * @param ctl     Initialization data.
 * @param region  Identity region definition.
 *
 * If the current method is @c ADDRXLAT_NOMETH, this action sets it up
 * as identity mapping to kernel physical addresses.
 * If the current method is not @c ADDRXLAT_NOMETH, nothing is done.
 */
static void
act_ident_kphys(struct os_init_data *ctl, const struct sys_region *region)
{
	addrxlat_meth_t *meth = &ctl->sys->meth[region->meth];
	meth->kind = ADDRXLAT_LINEAR;
	meth->target_as = ADDRXLAT_KPHYSADDR;
	meth->param.linear.off = 0;
}

/** Action function for @ref SYS_ACT_IDENT_MACHPHYS.
 * @param ctl     Initialization data.
 * @param region  Identity region definition.
 *
 * If the current method is @c ADDRXLAT_NOMETH, this action sets it up
 * as identity mapping to machine physical addresses.
 * If the current method is not @c ADDRXLAT_NOMETH, nothing is done.
 */
static void
act_ident_machphys(struct os_init_data *ctl, const struct sys_region *region)
{
	addrxlat_meth_t *meth = &ctl->sys->meth[region->meth];
	meth->kind = ADDRXLAT_LINEAR;
	meth->target_as = ADDRXLAT_MACHPHYSADDR;
	meth->param.linear.off = 0;
}

/** Set memory map layout.
 * @param ctl     Initialization data.
 * @param idx     Map index.
 * @param layout  Layout definition table.
 * @returns       Error status.
 */
addrxlat_status
sys_set_layout(struct os_init_data *ctl, addrxlat_sys_map_t idx,
	       const struct sys_region layout[])
{
	const struct sys_region *region;
	addrxlat_map_t *map = ctl->sys->map[idx];

	if (!map) {
		map = internal_map_new();
		if (!map)
			return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
					 "Cannot allocate translation map");
		ctl->sys->map[idx] = map;
	}

	for (region = layout; region->meth != ADDRXLAT_SYS_METH_NUM;
	     ++region) {
		addrxlat_range_t range;
		addrxlat_status status;

		range.endoff = region->last - region->first;
		range.meth = region->meth;

		switch (region->act) {
		case SYS_ACT_DIRECT:
			status = act_direct(ctl, region);
			if (status != ADDRXLAT_OK)
				return status;
			break;

		case SYS_ACT_RDIRECT:
			act_rdirect(ctl, region);
			break;

		case SYS_ACT_IDENT_KPHYS:
			act_ident_kphys(ctl, region);
			break;

		case SYS_ACT_IDENT_MACHPHYS:
			act_ident_machphys(ctl, region);
			break;

		default:
			break;
		}

		status = internal_map_set(map, region->first, &range);
		if (status != ADDRXLAT_OK)
			return set_error(ctl->ctx, status,
					 "Cannot set up mapping for"
					 " 0x%"ADDRXLAT_PRIxADDR
					 "-0x%"ADDRXLAT_PRIxADDR,
					 region->first,
					 region->last);
	}

	return ADDRXLAT_OK;
}

/** Set default (identity) physical mappings.
 * @param ctl     Initialization data.
 * @param maxaddr Maximum physical address.
 * @returns       Error status.
 */
addrxlat_status
sys_set_physmaps(struct os_init_data *ctl, addrxlat_addr_t maxaddr)
{
	struct sys_region layout[2];
	addrxlat_status status;

	layout[1].meth = ADDRXLAT_SYS_METH_NUM;
	layout[0].first = 0;
	layout[0].last = maxaddr;

	layout[0].meth = ADDRXLAT_SYS_METH_MACHPHYS_KPHYS;
	layout[0].act = SYS_ACT_IDENT_KPHYS;
	status = sys_set_layout(ctl, ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS, layout);
	if (status != ADDRXLAT_OK)
		return status;

	layout[0].meth = ADDRXLAT_SYS_METH_KPHYS_MACHPHYS;
	layout[0].act = SYS_ACT_IDENT_MACHPHYS;
	return sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS, layout);
}

/** Get page table root address using symbolic information.
 * @param ctl  Initialization data.
 * @param spec Symbolic name specifiers.
 * @returns    Error status.
 *
 * @sa get_first_sym
 */
addrxlat_status
sys_sym_pgtroot(struct os_init_data *ctl, const struct sym_spec *spec)
{
	addrxlat_meth_t *meth;
	addrxlat_status status;

	meth = &ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	if (meth->param.pgt.root.as != ADDRXLAT_NOADDR)
		return ADDRXLAT_OK;

	status = get_first_sym(ctl->ctx, spec, &meth->param.pgt.root);
	clear_error(ctl->ctx);
	return status;
}

#define MAX_ALT_NUM	2
struct xlat_alt {
	unsigned num;
	addrxlat_sys_map_t map[MAX_ALT_NUM];
};
#define ALT(num, ...)		{ (num), { __VA_ARGS__ } }

struct xlat_chain {
	unsigned len;
	struct xlat_alt alt[];
};
#define CHAIN(len, ...)		{ (len), { __VA_ARGS__ } }

/** Virtual to any physical (stop after first item for machphys). */
static const struct xlat_chain kv2phys =
	CHAIN(2,
	      ALT(2,
		  ADDRXLAT_SYS_MAP_KV_PHYS,
		  ADDRXLAT_SYS_MAP_HW),
	      ALT(2,
		  ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS,
		  ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS));

/** Kernel physical to machine physical. */
static const struct xlat_chain kphys2machphys =
	CHAIN(1, ALT(1, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS));

/** Kernel physical to virtual using directmap. */
static const struct xlat_chain kphys2direct =
	CHAIN(1, ALT(1, ADDRXLAT_SYS_MAP_KPHYS_DIRECT));

/** Kernel physical to any other. */
static const struct xlat_chain kphys2any =
	CHAIN(1, ALT(2,
		     ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS,
		     ADDRXLAT_SYS_MAP_KPHYS_DIRECT));

/** Machine physical to kernel physical or virtual using directmap. */
static const struct xlat_chain machphys2direct =
	CHAIN(2,
	      ALT(1, ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS),
	      ALT(1, ADDRXLAT_SYS_MAP_KPHYS_DIRECT));

/** Which address space is expected as input to each map? */
static const addrxlat_addrspace_t map_expect_as[ADDRXLAT_SYS_MAP_NUM] =
{
	[ADDRXLAT_SYS_MAP_HW] = ADDRXLAT_KVADDR,
	[ADDRXLAT_SYS_MAP_KV_PHYS] = ADDRXLAT_KVADDR,
	[ADDRXLAT_SYS_MAP_KPHYS_DIRECT] = ADDRXLAT_KPHYSADDR,
	[ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS] = ADDRXLAT_MACHPHYSADDR,
	[ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS] = ADDRXLAT_KPHYSADDR,
};

/**  In-flight translation.
 * This is used to detect infinite recursion.
 * @sa addrxlat_op
 */
struct inflight {
	/** Full address to be translated. */
	addrxlat_fulladdr_t faddr;
	/** Corresponding translation chain. */
	const struct xlat_chain *chain;
	/** Next translation in the chain. */
	struct inflight *next;
};

static addrxlat_status
do_op(const addrxlat_op_ctl_t *ctl, const addrxlat_fulladdr_t *paddr,
      const struct xlat_chain *chain)
{
	unsigned i, j;
	addrxlat_fulladdr_t lastbase;
	addrxlat_step_t step;
	addrxlat_status status;

	step.ctx = ctl->ctx;
	step.sys = ctl->sys;

	for (i = 0; i < chain->len; ++i) {
		const struct xlat_alt *alt = &chain->alt[i];

		for (j = 0; j < alt->num; ++j) {
			addrxlat_sys_map_t mapidx = alt->map[j];
			addrxlat_map_t *map;
			addrxlat_sys_meth_t methidx;
			addrxlat_meth_t *meth;

			if (paddr->as != map_expect_as[mapidx])
				continue;

			map = ctl->sys->map[mapidx];
			if (!map)
				continue;

			clear_error(ctl->ctx);
			methidx = internal_map_search(map, paddr->addr);
			if (methidx == ADDRXLAT_SYS_METH_NONE)
				continue;

			meth = &ctl->sys->meth[methidx];
			if (meth->kind == ADDRXLAT_LINEAR) {
				lastbase.as = meth->target_as;
				lastbase.addr =
					paddr->addr + meth->param.linear.off;
				if (ctl->caps & ADDRXLAT_CAPS(lastbase.as))
					return ctl->op(ctl->data, &lastbase);
				paddr = &lastbase;
				break;
			}

			step.meth = meth;
			step.base.addr = paddr->addr;
			status = internal_walk(&step);
			if (status == ADDRXLAT_OK) {
				if (ctl->caps & ADDRXLAT_CAPS(step.base.as))
					return ctl->op(ctl->data, &step.base);
				lastbase = step.base;
				paddr = &lastbase;
				break;
			} else if (status != ADDRXLAT_ERR_NOMETH &&
				   status != ADDRXLAT_ERR_NODATA)
				return status;
		}
	}

	return set_error(ctl->ctx, ADDRXLAT_ERR_NOMETH, "No way to translate");
}

DEFINE_ALIAS(op);

addrxlat_status
addrxlat_op(const addrxlat_op_ctl_t *ctl, const addrxlat_fulladdr_t *paddr)
{
	struct inflight inflight, *pif;
	const struct xlat_chain *chain;
	addrxlat_status status;

	clear_error(ctl->ctx);

	if (ctl->caps & ADDRXLAT_CAPS(paddr->as))
		return ctl->op(ctl->data, paddr);

	/* Check that some translation is possible. */
	if ((ctl->caps & (ADDRXLAT_CAPS(ADDRXLAT_KVADDR) |
			  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR) |
			  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR))) == 0)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMETH,
				 "No suitable capabilities");

	if (!ctl->sys)
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOMETH,
				 "No translation system");

	switch (paddr->as) {
	case ADDRXLAT_KVADDR:
		chain = &kv2phys;
		break;

	case ADDRXLAT_KPHYSADDR:
		chain = (ctl->caps & ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
			 ? (ctl->caps & ADDRXLAT_CAPS(ADDRXLAT_KVADDR)
			    ? &kphys2any
			    : &kphys2machphys)
			 : &kphys2direct);
		break;

	case ADDRXLAT_MACHPHYSADDR:
		chain = &machphys2direct;
		break;

	default:
		return set_error(ctl->ctx, ADDRXLAT_ERR_NOTIMPL,
				 "Unrecognized address space");
	}

	inflight.faddr = *paddr;
	inflight.chain = chain;
	for (pif = ctl->ctx->inflight; pif; pif = pif->next)
		if (pif->faddr.addr == inflight.faddr.addr &&
		    pif->faddr.as == inflight.faddr.as &&
		    pif->chain == inflight.chain)
			return set_error(ctl->ctx, ADDRXLAT_ERR_NOMETH,
					 "Infinite recursion loop");
	inflight.next = ctl->ctx->inflight;
	ctl->ctx->inflight = &inflight;

	status = do_op(ctl, paddr, chain);

	ctl->ctx->inflight = inflight.next;
	return status;
}

static addrxlat_status
storeaddr(void *data, const addrxlat_fulladdr_t *paddr)
{
	addrxlat_fulladdr_t *dstaddr = data;
	*dstaddr = *paddr;
	return ADDRXLAT_OK;
}

DEFINE_ALIAS(fulladdr_conv);

addrxlat_status
addrxlat_fulladdr_conv(addrxlat_fulladdr_t *faddr, addrxlat_addrspace_t as,
		       addrxlat_ctx_t *ctx, addrxlat_sys_t *sys)
{
	addrxlat_op_ctl_t opctl;

	opctl.ctx = ctx;
	opctl.sys = sys;
	opctl.op = storeaddr;
	opctl.data = faddr;
	opctl.caps = ADDRXLAT_CAPS(as);
	return internal_op(&opctl, faddr);
}
