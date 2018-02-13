/** @internal @file python/test_addrxlat.c
 * @brief Python module for testing libaddrxlat bindings.
 */
/* Copyright (C) 2017 Petr Tesarik <ptesarik@suse.com>

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

#include <Python.h>
#include "addrxlatmod.h"

#define MOD_NAME	"_test_addrxlat"
#define MOD_DOC		"helper for unit testing"

static struct addrxlat_CAPI *addrxlat_API;

#define CUSTOM_MAGIC_ADDR	0x4d795f4d61676963 /* My_Magic */
#define CUSTOM_MAGIC_ADDR2	0x4d61676963546f6f /* MagicToo */

static char custom_magic_str[] = "_test_addrxlat_custom";

static addrxlat_status
magic_first_step(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_meth_t *meth = step->meth;

	if (meth->param.custom.data != custom_magic_str)
		return addrxlat_ctx_err(step->ctx, ADDRXLAT_ERR_INVALID,
					"Wrong magic");

	step->base.as = ADDRXLAT_NOADDR;
	step->base.addr = CUSTOM_MAGIC_ADDR;
	step->idx[0] = addr & 0xff;
	step->idx[1] = addr >> 8;
	step->remain = 2;

	return ADDRXLAT_OK;
}

static addrxlat_status
magic_next_step(addrxlat_step_t *step)
{
	const addrxlat_meth_t *meth = step->meth;

	if (meth->param.custom.data != custom_magic_str)
		return addrxlat_ctx_err(step->ctx, ADDRXLAT_ERR_INVALID,
					"Wrong magic");

	step->base.addr = CUSTOM_MAGIC_ADDR2 + step->idx[1];
	step->elemsz = 0x100;

	return ADDRXLAT_OK;
}

PyDoc_STRVAR(get_custmeth__doc__,
"getCustomMethod(conv) -> CustomMethod\n\
\n\
Get a custom method that translates to a magic value.");

static PyObject *
get_custmeth(PyObject *self, PyObject *args)
{
	PyObject *conv;
	addrxlat_meth_t meth;

	if (!PyArg_ParseTuple(args, "O", &conv))
		return NULL;

	meth.kind = ADDRXLAT_CUSTOM;
	meth.target_as = ADDRXLAT_NOADDR;
	meth.param.custom.first_step = magic_first_step;
	meth.param.custom.next_step = magic_next_step;
	meth.param.custom.data = custom_magic_str;
	return addrxlat_API->Method_FromPointer(conv, &meth);
}

static PyMethodDef test_methods[] = {
	{ "getCustomMethod", (PyCFunction)get_custmeth, METH_VARARGS,
	  get_custmeth__doc__ },
	{ NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef addrxlat_moddef = {
        PyModuleDef_HEAD_INIT,
        MOD_NAME,            /* m_name */
        MOD_DOC,             /* m_doc */
        -1,                  /* m_size */
        test_methods,        /* m_methods */
        NULL,                /* m_reload */
        NULL,                /* m_traverse */
        NULL,                /* m_clear */
        NULL,                /* m_free */
};
#endif

#if PY_MAJOR_VERSION >= 3
#  define MOD_ERROR_VAL NULL
#  define MOD_SUCCESS_VAL(val) val
#else
#  define MOD_ERROR_VAL
#  define MOD_SUCCESS_VAL(val)
#endif

PyMODINIT_FUNC
#if PY_MAJOR_VERSION >= 3
PyInit__test_addrxlat (void)
#else
init_test_addrxlat (void)
#endif
{
	PyObject *mod;

	addrxlat_API = (struct addrxlat_CAPI*)
		PyCapsule_Import(addrxlat_CAPSULE_NAME, 0);
	if (!addrxlat_API)
		goto err;
	if (addrxlat_API->ver < addrxlat_CAPI_VER) {
		PyErr_Format(PyExc_RuntimeError,
			     "addrxlat CAPI ver >= %lu needed, %lu found",
			     addrxlat_CAPI_VER, addrxlat_API->ver);
		goto err;
	}

#if PY_MAJOR_VERSION >= 3
	mod = PyModule_Create(&addrxlat_moddef);
#else
	mod = Py_InitModule3(MOD_NAME, test_methods, MOD_DOC);
#endif
	if (!mod)
		goto err;

	return MOD_SUCCESS_VAL(mod);

 err:
	return MOD_ERROR_VAL;
}
