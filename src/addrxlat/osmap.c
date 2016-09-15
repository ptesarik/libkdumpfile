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
	if (!ret)
		return NULL;
	ret->refcnt = 1;

	ret->pgt = internal_def_new();
	if (!ret->pgt) {
		free(ret);
		return NULL;
	}

	return ret;
}

unsigned long
addrxlat_osmap_incref(addrxlat_osmap_t *osmap)
{
	return ++osmap->refcnt;
}

unsigned long
addrxlat_osmap_decref(addrxlat_osmap_t *osmap)
{
	unsigned long refcnt = --osmap->refcnt;
	if (!refcnt) {
		if (osmap->map) {
			internal_map_clear(osmap->map);
			free(osmap->map);
		}
		if (osmap->pgt)
			internal_def_decref(osmap->pgt);
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
	else
		ret = set_error(ctx, addrxlat_notimpl,
				"Unsupported architecture");

	return ret;
}

void
addrxlat_osmap_set_map(addrxlat_osmap_t *osmap, addrxlat_map_t *map)
{
	if (osmap->map)
		free(osmap->map);
	osmap->map = map;
}

const addrxlat_map_t *
addrxlat_osmap_get_map(const addrxlat_osmap_t *osmap)
{
	return osmap->map;
}

void
addrxlat_osmap_set_pgt(addrxlat_osmap_t *osmap, addrxlat_def_t *pgt)
{
	if (osmap->pgt)
		internal_def_decref(osmap->pgt);
	osmap->pgt = pgt;
	if (osmap->pgt)
		internal_def_incref(osmap->pgt);
}

addrxlat_def_t *
addrxlat_osmap_get_pgt(addrxlat_osmap_t *osmap)
{
	if (osmap->pgt)
		internal_def_incref(osmap->pgt);
	return osmap->pgt;
}
