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


	for (i = 0; i < ADDRXLAT_SYS_METH_NUM; ++i)
		if (sys->meth[i]) {
			internal_meth_decref(sys->meth[i]);
			sys->meth[i] = NULL;
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
addrxlat_sys_init(addrxlat_sys_t *sys, addrxlat_ctx_t *ctx,
		  const addrxlat_osdesc_t *osdesc)
{
	struct sys_init_data ctl;
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
	if (sys->map[idx])
		internal_map_decref(sys->map[idx]);
	sys->map[idx] = map;
	if (map)
		internal_map_incref(map);
}

addrxlat_map_t *
addrxlat_sys_get_map(const addrxlat_sys_t *sys, addrxlat_sys_map_t idx)
{
	if (sys->map[idx])
		internal_map_incref(sys->map[idx]);
	return sys->map[idx];
}

void
addrxlat_sys_set_meth(addrxlat_sys_t *sys,
		      addrxlat_sys_meth_t idx, addrxlat_meth_t *meth)
{
	if (sys->meth[idx])
		internal_meth_decref(sys->meth[idx]);
	sys->meth[idx] = meth;
	if (meth)
		internal_meth_incref(meth);
}

addrxlat_meth_t *
addrxlat_sys_get_meth(const addrxlat_sys_t *sys, addrxlat_sys_meth_t idx)
{
	if (sys->meth[idx])
		internal_meth_incref(sys->meth[idx]);
	return sys->meth[idx];
}

/** Allocate a translation method if needed.
 * @param ctl  Initialization data.
 * @parma idx  Method index
 * @returns    Error status.
 */
addrxlat_status
sys_ensure_meth(struct sys_init_data *ctl, addrxlat_sys_meth_t idx)
{
	if (ctl->sys->meth[idx])
		return ADDRXLAT_OK;

	if ( (ctl->sys->meth[idx] = internal_meth_new()) )
		return ADDRXLAT_OK;

	return set_error(ctl->ctx, ADDRXLAT_ERR_NOMEM,
			 "Cannot allocate translation method %u",
			 (unsigned) idx);
}

/** Action function for @ref SYS_ACT_DIRECT.
 * @param ctl     Initialization data.
 * @param meth    Current directmap translation method.
 * @param region  Directmap region definition.
 *
 * This action sets up the direct mapping as a linear mapping that
 * maps the current region to kernel physical addresses starting at 0.
 */
static addrxlat_status
act_direct(struct sys_init_data *ctl,
	   addrxlat_meth_t *meth, const struct sys_region *region)
{
	struct sys_region layout[2] = {
		{ 0, region->last - region->first,
		  ADDRXLAT_SYS_METH_RDIRECT },
		SYS_REGION_END
	};
	addrxlat_desc_t desc;
	addrxlat_status status;

	desc.kind = ADDRXLAT_LINEAR;
	desc.target_as = ADDRXLAT_KPHYSADDR;
	desc.param.linear.off = -region->first;
	internal_meth_set_desc(meth, &desc);

	status = sys_ensure_meth(ctl, ADDRXLAT_SYS_METH_RDIRECT);
	if (status != ADDRXLAT_OK)
		return status;

	desc.target_as = ADDRXLAT_KVADDR;
	desc.param.linear.off = region->first;
	internal_meth_set_desc(
		ctl->sys->meth[ADDRXLAT_SYS_METH_RDIRECT], &desc);

	return sys_set_layout(ctl, ADDRXLAT_SYS_MAP_KPHYS_DIRECT, layout);
}

/** Action function for @ref SYS_ACT_IDENT_KPHYS.
 * @param meth  Current translation method.
 *
 * If the current method is @c ADDRXLAT_NONE, this action sets it up
 * as identity mapping to kernel physical addresses.
 * If the current method is not @c ADDRXLAT_NONE, nothing is done.
 */
static void
act_ident_kphys(addrxlat_meth_t *meth)
{
	addrxlat_desc_t desc;
	desc.kind = ADDRXLAT_LINEAR;
	desc.target_as = ADDRXLAT_KPHYSADDR;
	desc.param.linear.off = 0;
	internal_meth_set_desc(meth, &desc);
}

/** Action function for @ref SYS_ACT_IDENT_MACHPHYS.
 * @param meth  Current translation method.
 *
 * If the current method is @c ADDRXLAT_NONE, this action sets it up
 * as identity mapping to machine physical addresses.
 * If the current method is not @c ADDRXLAT_NONE, nothing is done.
 */
static void
act_ident_machphys(addrxlat_meth_t *meth)
{
	addrxlat_desc_t desc;
	desc.kind = ADDRXLAT_LINEAR;
	desc.target_as = ADDRXLAT_MACHPHYSADDR;
	desc.param.linear.off = 0;
	internal_meth_set_desc(meth, &desc);
}

/** Set memory map layout.
 * @param ctl     Initialization data.
 * @param idx     Map index.
 * @param layout  Layout definition table.
 * @returns       Error status.
 */
addrxlat_status
sys_set_layout(struct sys_init_data *ctl, addrxlat_sys_map_t idx,
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

		status = sys_ensure_meth(ctl, region->meth);
		if (status != ADDRXLAT_OK)
			return status;

		range.endoff = region->last - region->first;
		range.meth = ctl->sys->meth[region->meth];

		switch (region->act) {
		case SYS_ACT_DIRECT:
			status = act_direct(ctl, range.meth, region);
			if (status != ADDRXLAT_OK)
				return status;
			break;

		case SYS_ACT_IDENT_KPHYS:
			act_ident_kphys(range.meth);
			break;

		case SYS_ACT_IDENT_MACHPHYS:
			act_ident_machphys(range.meth);
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
sys_set_physmaps(struct sys_init_data *ctl, addrxlat_addr_t maxaddr)
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
 * @param reg  Page table register name.
 * @param sym  Symbol name of the page table.
 * @returns    Error status.
 */
addrxlat_status
sys_sym_pgtroot(struct sys_init_data *ctl, const char *reg, const char *sym)
{
	addrxlat_meth_t *meth;
	addrxlat_addr_t addr;

	meth = ctl->sys->meth[ADDRXLAT_SYS_METH_PGT];
	if (meth->desc.param.pgt.root.as != ADDRXLAT_NOADDR)
		return ADDRXLAT_OK;

	if (reg && get_reg(ctl->ctx, "cr3", &addr) == ADDRXLAT_OK) {
		meth->desc.param.pgt.root.as = ADDRXLAT_MACHPHYSADDR;
		meth->desc.param.pgt.root.addr = addr;
		return ADDRXLAT_OK;
	}
	clear_error(ctl->ctx);

	if (sym && get_symval(ctl->ctx, sym, &addr) == ADDRXLAT_OK) {
		meth->desc.param.pgt.root.as = ADDRXLAT_KVADDR;
		meth->desc.param.pgt.root.addr = addr;
		return ADDRXLAT_OK;
	}
	clear_error(ctl->ctx);

	return ADDRXLAT_ERR_NODATA;
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
 * @sa addrxlat_by_sys
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
	addrxlat_step_t step;
	addrxlat_status status;

	step.ctx = ctl->ctx;
	step.sys = ctl->sys;

	for (i = 0; i < chain->len; ++i) {
		const struct xlat_alt *alt = &chain->alt[i];

		for (j = 0; j < alt->num; ++j) {
			addrxlat_sys_map_t mapidx = alt->map[j];
			addrxlat_map_t *map;

			if (paddr->as != map_expect_as[mapidx])
				continue;

			map = ctl->sys->map[mapidx];
			if (!map)
				continue;

			clear_error(ctl->ctx);
			status = internal_launch_map(&step, paddr->addr, map);
			if (status == ADDRXLAT_OK)
				status = internal_walk(&step);

			if (status == ADDRXLAT_OK) {
				paddr = &step.base;
				if (ctl->caps & ADDRXLAT_CAPS(paddr->as))
					return ctl->op(ctl->data, paddr);
				break;
			} else if (status != ADDRXLAT_ERR_NOMETH)
				return status;
		}
	}

	return ctl->ctx->err_str == NULL
		? set_error(ctl->ctx, ADDRXLAT_ERR_NOMETH, "No way to translate")
		: ADDRXLAT_ERR_NOMETH;
}

/** A version of @ref addrxlat_op for internal use.
 * @param ctl   Control structure.
 * @param addr  Address (in any address space).
 * @returns     Error status.
 *
 * This version does not clear errors and, more importantly, does not
 * reset recursion detection.
 */
addrxlat_status
xlat_op(const addrxlat_op_ctl_t *ctl, const addrxlat_fulladdr_t *paddr)
{
	struct inflight inflight, *pif;
	const struct xlat_chain *chain;
	addrxlat_status status;

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

addrxlat_status
addrxlat_op(const addrxlat_op_ctl_t *ctl, const addrxlat_fulladdr_t *paddr)
{
	struct inflight *inflight;
	addrxlat_status status;

	clear_error(ctl->ctx);

	inflight = ctl->ctx->inflight;
	ctl->ctx->inflight = NULL;
	status = xlat_op(ctl, paddr);
	ctl->ctx->inflight = inflight;
	return status;
}

static addrxlat_status
storeaddr(void *data, const addrxlat_fulladdr_t *paddr)
{
	addrxlat_fulladdr_t *dstaddr = data;
	*dstaddr = *paddr;
	return ADDRXLAT_OK;
}

DEFINE_ALIAS(by_sys);

addrxlat_status
addrxlat_by_sys(addrxlat_ctx_t *ctx, const addrxlat_sys_t *sys,
		addrxlat_fulladdr_t *paddr, addrxlat_addrspace_t goal)
{
	addrxlat_op_ctl_t opctl;

	opctl.ctx = ctx;
	opctl.sys = sys;
	opctl.op = storeaddr;
	opctl.data = paddr;
	opctl.caps = ADDRXLAT_CAPS(goal);
	return addrxlat_op(&opctl, paddr);
}
