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
#include <libkdumpfile/addrxlat.h>

#define addrxlat_CAPSULE_NAME	"_addrxlat._C_API"
#define addrxlat_CAPI_VER	1UL

struct addrxlat_CAPI {
	unsigned long ver;	/**< Structure version. */

	PyObject *convert;	/**< Default conversion object. */

	PyObject *(*FullAddress_FromPointer)(
		PyObject *conv, const addrxlat_fulladdr_t *faddr);
	addrxlat_fulladdr_t *(*FullAddress_AsPointer)(PyObject *self);

	PyObject *(*Context_FromPointer)(PyObject *conv, addrxlat_ctx_t *ctx);
	addrxlat_ctx_t *(*Context_AsPointer)(PyObject *self);

	PyObject *(*Method_FromPointer)(
		PyObject *conv, const addrxlat_meth_t *meth);
	addrxlat_meth_t *(*Method_AsPointer)(PyObject *self);

	PyObject *(*Range_FromPointer)(
		PyObject *conv, const addrxlat_range_t *range);
	addrxlat_range_t *(*Range_AsPointer)(PyObject *self);

	PyObject *(*Map_FromPointer)(PyObject *conv, addrxlat_map_t *map);
	addrxlat_map_t *(*Map_AsPointer)(PyObject *self);

	PyObject *(*System_FromPointer)(PyObject *conv, addrxlat_sys_t *sys);
	addrxlat_sys_t *(*System_AsPointer)(PyObject *self);

	PyObject *(*Step_FromPointer)(
		PyObject *conv, const addrxlat_step_t *step);
	int (*Step_Init)(PyObject *self, const addrxlat_step_t *step);
	addrxlat_step_t *(*Step_AsPointer)(PyObject *self);

	PyObject *(*Operator_FromPointer)(
		PyObject *conv, const addrxlat_op_ctl_t *opctl);
	int (*Operator_Init)(PyObject *self, const addrxlat_op_ctl_t *opctl);
	addrxlat_op_ctl_t *(*Operator_AsPointer)(PyObject *self);

};

#ifdef __cplusplus
}
#endif

#endif	/* addrxlatmod.h */
