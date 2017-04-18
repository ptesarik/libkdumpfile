/** @internal @file python/addrxlatmod.h
 * @brief Header file with addrxlat module's C API bindings.
 */
/* Copyright (C) 2017 Petr Tesarik <ptesarik@suse.cz>

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

#ifndef ADDRXLATMOD_H
#define ADDRXLATMOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <Python.h>
#include <addrxlat.h>

#define addrxlat_CAPSULE_NAME	"_addrxlat._C_API"
#define addrxlat_CAPI_VER	1UL

struct addrxlat_CAPI {
	unsigned long ver;	/**< Structure version. */

	PyObject *convert;	/**< Default conversion object. */

	addrxlat_fulladdr_t *(*fulladdr_AsPointer)(PyObject *value);
	PyObject *(*fulladdr_FromPointer)(
		PyObject *conv, const addrxlat_fulladdr_t *faddr);
	addrxlat_ctx_t *(*ctx_AsPointer)(PyObject *value);
	PyObject *(*ctx_FromPointer)(PyObject *conv, addrxlat_ctx_t *ctx);
	addrxlat_desc_t *(*desc_AsPointer)(PyObject *value);
	PyObject *(*desc_FromPointer)(
		PyObject *conv, const addrxlat_desc_t *desc);
	addrxlat_meth_t *(*meth_AsPointer)(PyObject *value);
	PyObject *(*meth_FromPointer)(PyObject *conv, addrxlat_meth_t *meth);
	addrxlat_range_t *(*range_AsPointer)(PyObject *value);
	PyObject *(*range_FromPointer)(
		PyObject *conv, const addrxlat_range_t *range);
	addrxlat_map_t *(*map_AsPointer)(PyObject *value);
	PyObject *(*map_FromPointer)(PyObject *conv, addrxlat_map_t *map);
	addrxlat_sys_t *(*sys_AsPointer)(PyObject *value);
	PyObject *(*sys_FromPointer)(PyObject *conv, addrxlat_sys_t *sys);
};

#ifdef __cplusplus
}
#endif

#endif	/* addrxlatmod.h */
