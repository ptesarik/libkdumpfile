/** @internal @file src/addrxlat/osmap.c
 * @brief OS translation map routines.
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

#include <stdlib.h>
#include <string.h>

#include "addrxlat-priv.h"

addrxlat_osmap_t *
addrxlat_osmap_new(void)
{
	addrxlat_osmap_t *ret;

	ret = calloc(1, sizeof(addrxlat_osmap_t));
	if (ret) {
		ret->refcnt = 1;
	}
	return ret;
}

unsigned long
addrxlat_osmap_incref(addrxlat_osmap_t *osmap)
{
	return ++osmap->refcnt;
}

static void
free_map(addrxlat_map_t *map)
{
	if (map) {
		internal_map_clear(map);
		free(map);
	}
}

unsigned long
addrxlat_osmap_decref(addrxlat_osmap_t *osmap)
{
	unsigned long refcnt = --osmap->refcnt;
	if (!refcnt) {
		unsigned i;

		free_map(osmap->map);
		for (i = 0; i < ADDRXLAT_OSMAP_NUM; ++i)
			if (osmap->meth[i])
				internal_meth_decref(osmap->meth[i]);
		free(osmap);
	}
	return refcnt;
}

addrxlat_status
addrxlat_osmap_init(addrxlat_osmap_t *osmap, addrxlat_ctx_t *ctx,
		    const addrxlat_osdesc_t *osdesc)
{
	struct osmap_init_data ctl;
	osmap_arch_fn *arch_fn;

	if (!strcmp(osdesc->arch, "x86_64"))
		arch_fn = osmap_x86_64;
	else if ((osdesc->arch[0] == 'i' &&
		  (osdesc->arch[1] >= '3' && osdesc->arch[1] <= '6') &&
		  !strcmp(osdesc->arch + 2, "86")) ||
		 !strcmp(osdesc->arch, "ia32"))
		arch_fn = osmap_ia32;
	else if (!strcmp(osdesc->arch, "s390x"))
		arch_fn = osmap_s390x;
	else if (!strcmp(osdesc->arch, "ppc64"))
		arch_fn = osmap_ppc64;
	else
		return set_error(ctx, addrxlat_notimpl,
				"Unsupported architecture");

	ctl.osmap = osmap;
	ctl.ctx = ctx;
	ctl.osdesc = osdesc;

	return arch_fn(&ctl);
}

void
addrxlat_osmap_set_map(addrxlat_osmap_t *osmap, addrxlat_map_t *map)
{
	free_map(osmap->map);
	osmap->map = map;
}

const addrxlat_map_t *
addrxlat_osmap_get_map(const addrxlat_osmap_t *osmap)
{
	return osmap->map;
}

void
addrxlat_osmap_set_xlat(addrxlat_osmap_t *osmap,
			addrxlat_osmap_xlat_t xlat, addrxlat_meth_t *meth)
{
	if (osmap->meth[xlat])
		internal_meth_decref(osmap->meth[xlat]);
	osmap->meth[xlat] = meth;
	if (meth)
		internal_meth_incref(meth);
}

addrxlat_meth_t *
addrxlat_osmap_get_xlat(addrxlat_osmap_t *osmap, addrxlat_osmap_xlat_t xlat)
{
	if (osmap->meth[xlat])
		internal_meth_incref(osmap->meth[xlat]);
	return osmap->meth[xlat];
}

/** Action function for @ref OSMAP_ACT_DIRECT.
 * @parma ctl  Initialization data.
 */
static void
direct_hook(struct osmap_init_data *ctl, const struct osmap_region *region)
{
	addrxlat_def_t def;
	def.kind = ADDRXLAT_LINEAR;
	def.param.linear.off = region->first;
	internal_meth_set_def(ctl->osmap->meth[region->xlat], &def);
}

/** Set memory map layout.
 * @parma ctl     Initialization data.
 * @param layout  Layout definition table.
 * @returns       Error status.
 */
addrxlat_status
osmap_set_layout(struct osmap_init_data *ctl,
		 const struct osmap_region layout[])
{
	static osmap_action_fn *const actions[] = {
		[OSMAP_ACT_DIRECT] = direct_hook,
		[OSMAP_ACT_X86_64_KTEXT] = x86_64_ktext_hook,
	};

	const struct osmap_region *region;
	addrxlat_map_t *newmap;

	for (region = layout; region->xlat != ADDRXLAT_OSMAP_NUM; ++region) {
		addrxlat_range_t range;

		if (!ctl->osmap->meth[region->xlat])
			ctl->osmap->meth[region->xlat] = internal_meth_new();
		if (!ctl->osmap->meth[region->xlat])
			return set_error(ctl->ctx, addrxlat_nomem,
					 "Cannot allocate translation"
					 " method %u",
					 (unsigned) region->xlat);

		if (region->act != OSMAP_ACT_NONE)
			actions[region->act](ctl, region);

		range.endoff = region->last - region->first;
		range.meth = ctl->osmap->meth[region->xlat];
		newmap = internal_map_set(ctl->osmap->map,
					  region->first, &range);
		if (!newmap)
			return set_error(ctl->ctx, addrxlat_nomem,
					 "Cannot set up mapping for"
					 " 0x%"ADDRXLAT_PRIxADDR
					 "-0x%"ADDRXLAT_PRIxADDR,
					 region->first,
					 region->last);
		ctl->osmap->map = newmap;
	}

	return addrxlat_ok;
}
