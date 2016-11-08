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
			if (osmap->def[i])
				internal_def_decref(osmap->def[i]);
		free(osmap);
	}
	return refcnt;
}

addrxlat_status
addrxlat_osmap_init(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
		    const addrxlat_osdesc_t *osdesc)
{
	addrxlat_status ret;

	if (!strcmp(osdesc->arch, "x86_64"))
		ret = osmap_x86_64(osmap, ctx, osdesc);
	else if ((osdesc->arch[0] == 'i' &&
		  (osdesc->arch[1] >= '3' && osdesc->arch[1] <= '6') &&
		  !strcmp(osdesc->arch + 2, "86")) ||
		 !strcmp(osdesc->arch, "ia32"))
		ret = osmap_ia32(osmap, ctx, osdesc);
	else if (!strcmp(osdesc->arch, "s390x"))
		ret = osmap_s390x(osmap, ctx, osdesc);
	else if (!strcmp(osdesc->arch, "ppc64"))
		ret = osmap_ppc64(osmap, ctx, osdesc);
	else
		ret = set_error(ctx, addrxlat_notimpl,
				"Unsupported architecture");

	return ret;
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
			addrxlat_osmap_xlat_t xlat, addrxlat_def_t *def)
{
	if (osmap->def[xlat])
		internal_def_decref(osmap->def[xlat]);
	osmap->def[xlat] = def;
	if (def)
		internal_def_incref(def);
}

addrxlat_def_t *
addrxlat_osmap_get_xlat(addrxlat_osmap_t *osmap, addrxlat_osmap_xlat_t xlat)
{
	if (osmap->def[xlat])
		internal_def_incref(osmap->def[xlat]);
	return osmap->def[xlat];
}

/** Action function for @ref OSMAP_ACT_DIRECT.
 * @param osmap   OS map object.
 * @parma ctx     Address translation object.
 * @param region  Associated region definition.
 */
static void
direct_hook(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
	    const struct osmap_region *region)
{
	internal_def_set_offset(osmap->def[region->xlat], region->first);
}

/** Set memory map layout.
 * @param osmap   OS map object.
 * @parma ctx     Address translation object.
 * @param layout  Layout definition table.
 * @returns       Error status.
 */
addrxlat_status
osmap_set_layout(addrxlat_osmap_t *osmap, addrxlat_ctx *ctx,
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

		if (!osmap->def[region->xlat])
			osmap->def[region->xlat] = internal_def_new();
		if (!osmap->def[region->xlat])
			return set_error(ctx, addrxlat_nomem,
					 "Cannot allocate translation"
					 " definition %u",
					 (unsigned) region->xlat);

		if (region->act != OSMAP_ACT_NONE)
			actions[region->act](osmap, ctx, region);

		range.endoff = region->last - region->first;
		range.def = osmap->def[region->xlat];
		newmap = internal_map_set(osmap->map, region->first, &range);
		if (!newmap)
			return set_error(ctx, addrxlat_nomem,
					 "Cannot set up mapping for"
					 " 0x%"ADDRXLAT_PRIxADDR
					 "-0x%"ADDRXLAT_PRIxADDR,
					 region->first,
					 region->last);
		osmap->map = newmap;
	}

	return addrxlat_ok;
}
