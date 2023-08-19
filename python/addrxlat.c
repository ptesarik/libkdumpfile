/** @internal @file python/addrxlat.c
 * @brief Python bindings for libaddrxlat.
 */
/* Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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
#include <structmember.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "addrxlatmod.h"

#if PY_MAJOR_VERSION >= 3
#define PyInt_FromLong(x)	PyLong_FromLong(x)
#define PyInt_FromSize_t(x)	PyLong_FromSize_t(x)

#define Text_FromUTF8(x)	PyUnicode_FromString(x)
#define Text_AsUTF8(x)		PyUnicode_AsUTF8(x)
#else
#define Text_FromUTF8(x)	PyString_FromString(x)
#define Text_AsUTF8(x)		PyString_AsString(x)
#endif

#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))

#define MOD_NAME	"_addrxlat"
#define MOD_DOC		"low-level interface to libaddrxlat"

/** Python exception status code.
 * This code is returned when a callback raises an exception, so
 * it can be passed correctly up the chain.
 */
#define STATUS_PYEXC	ADDRXLAT_ERR_CUSTOM_BASE

static PyObject *ctx_status_result(PyObject *_self, addrxlat_status status);
static PyObject *make_meth_param(PyObject *meth);

/** Default type converter object. */
static PyObject *convert;

/* Conversion functions */
static PyObject *fulladdr_FromPointer(
	PyObject *_conv, const addrxlat_fulladdr_t *faddr);
static addrxlat_fulladdr_t *fulladdr_AsPointer(PyObject *self);
static PyObject *ctx_FromPointer(PyObject *_conv, addrxlat_ctx_t *ctx);
static addrxlat_ctx_t *ctx_AsPointer(PyObject *self);
static PyObject *meth_FromPointer(
	PyObject *_conv, const addrxlat_meth_t *meth);
static addrxlat_meth_t *meth_AsPointer(PyObject *self);
static PyObject *range_FromPointer(
	PyObject *_conv, const addrxlat_range_t *range);
static addrxlat_range_t *range_AsPointer(PyObject *self);
static PyObject *map_FromPointer(PyObject *_conv, addrxlat_map_t *map);
static addrxlat_map_t *map_AsPointer(PyObject *self);
static PyObject *sys_FromPointer(PyObject *_conv, addrxlat_sys_t *sys);
static addrxlat_sys_t *sys_AsPointer(PyObject *self);
static PyObject *step_FromPointer(
	PyObject *_conv, const addrxlat_step_t *step);
static int step_Init(PyObject *self, const addrxlat_step_t *step);
static addrxlat_step_t *step_AsPointer(PyObject *self);
static PyObject *op_FromPointer(
	PyObject *conv, const addrxlat_op_ctl_t *opctl);
static int op_Init(PyObject *self, const addrxlat_op_ctl_t *opctl);
static addrxlat_op_ctl_t *op_AsPointer(PyObject *self);

/** Capsule data. */
static struct addrxlat_CAPI CAPI;

/** Documentation for the convert attribute (multiple types). */
PyDoc_STRVAR(attr_convert__doc__,
"C type converter");

/** Convert a PyLong or PyInt to a C long.
 * @param num  a @c PyLong or @c PyInt object
 * @returns    numeric value of @c num or -1
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static long
Number_AsLong(PyObject *num)
{
	long result;

	if (PyLong_Check(num))
		return PyLong_AsLong(num);
#if PY_MAJOR_VERSION < 3
	else if (PyInt_Check(num))
		return PyInt_AsLong(num);
#endif

	num = PyNumber_Long(num);
	if (!num)
		return -1L;
	result = PyLong_AsLong(num);
	Py_DECREF(num);
	return result;
}

/** Convert a PyLong or PyInt to a C unsigned long long.
 * @param num  a @c PyLong or @c PyInt object
 * @returns    numeric value of @c num or -1
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static unsigned long long
Number_AsUnsignedLongLong(PyObject *num)
{
	unsigned long long result;

	if (PyLong_Check(num))
		return PyLong_AsUnsignedLongLong(num);
#if PY_MAJOR_VERSION < 3
	else if (PyInt_Check(num))
		return PyInt_AsLong(num);
#endif

	num = PyNumber_Long(num);
	if (!num)
		return -1LL;
	result = PyLong_AsUnsignedLongLong(num);
	Py_DECREF(num);
	return result;
}

/** Convert a PyLong or PyInt to a C unsigned long long with no overflow.
 * @param num  a @c PyLong or @c PyInt object
 * @returns    numeric value of @c num or -1
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static unsigned long long
Number_AsUnsignedLongLongMask(PyObject *num)
{
	unsigned long long result;

	if (PyLong_Check(num))
		return PyLong_AsUnsignedLongLongMask(num);
#if PY_MAJOR_VERSION < 3
	else if (PyInt_Check(num))
		return PyInt_AsLong(num);
#endif

	num = PyNumber_Long(num);
	if (!num)
		return -1LL;
	result = PyLong_AsUnsignedLongLongMask(num);
	Py_DECREF(num);
	return result;
}

/** Convert a Python sequence of integers to a memory buffer.
 * @param seq     a Python sequence
 * @param buffer  buffer for the result
 * @param buflen  maximum buffer length
 * @returns       zero on success, -1 otherwise
 */
static int
ByteSequence_AsBuffer(PyObject *seq, void *buffer, size_t buflen)
{
	Py_ssize_t i, len;

	if (!PySequence_Check(seq)) {
		PyErr_SetString(PyExc_TypeError,
				"'%.200s' object is not a sequence");
		return -1;
	}

	len = PySequence_Length(seq);
	if (len > buflen) {
		PyErr_Format(PyExc_ValueError,
			     "sequence bigger than %zd bytes", buflen);
		return -1;
	}

	if (PyByteArray_Check(seq)) {
		memcpy(buffer, PyByteArray_AsString(seq), len);
		return 0;
	}

	for (i = 0; i < len; ++i) {
		long byte = 0;
		PyObject *obj = PySequence_GetItem(seq, i);

		if (seq) {
			byte = Number_AsLong(obj);
			Py_DECREF(obj);
		}
		if (PyErr_Occurred())
			return -1;
		if (byte < 0 || byte > 0xff) {
			PyErr_SetString(PyExc_OverflowError,
					"byte value out of range");
			return -1;
		}
		((char*)buffer)[i] = byte;
	}

	return 0;
}

/** Check whether an attribute is being deleted.
 * @param obj   new value
 * @param name  name of the attribute (used in the exception message)
 * @returns     zero if attribute is not NULL, -1 otherwise
 */
static int
check_null_attr(PyObject *obj, const char *name)
{
	if (obj)
		return 0;

	PyErr_Format(PyExc_TypeError,
		     "'%s' attribute cannot be deleted", name);
	return -1;
}

/** Fetch positional and keyword arguments.
 * @param kwds     NULL-terminated array of recognized keywords
 * @param min      minimum required number of arguments
 * @param pargs    positional arguments
 * @param pkwargs  keyword arguments
 * @returns        zero on success, -1 otherwise
 *
 * Fetch all arguments listed in @c kwds and put them into variables
 * passed as variadic. The variables referenced by @c pargs and
 * @c pkwargs are updated to hold a tuple and dictionary with unprocessed
 * arguments.
 *
 * On failure, the variables referenced by @c pargs and @c pkwargs are not
 * touched, but the values of argument variables (variadic) are undefined.
 */
static int
fetch_args(const char *kwds[], Py_ssize_t min,
	   PyObject **pargs, PyObject **pkwargs, ...)
{
	const char **kw;
	PyObject *args, *kwargs;
	PyObject **argvar;
	Py_ssize_t argc, n;
	va_list ap;

	args = *pargs;
	if (*pkwargs) {
		kwargs = PyDict_Copy(*pkwargs);
		if (!kwargs)
			return -1;
	} else
		kwargs = NULL;

	va_start(ap, pkwargs);
	argc = PyTuple_GET_SIZE(args);
	for (n = 0, kw = kwds; n < argc; ++n, ++kw) {
		if (!*kw)
			break;
		argvar = va_arg(ap, PyObject **);
		*argvar = PyTuple_GET_ITEM(args, n);
	}
	min -= n;

	if (kwargs) {
		const char **kw2;
		for (kw2 = kwds; kw2 < kw; ++kw2) {
			if (PyDict_GetItemString(kwargs, *kw2)) {
				/* arg present in tuple and in dict */
				PyErr_Format(PyExc_TypeError,
					     "Argument given by name ('%s') "
					     "and position (%zd)",
					     *kw2, kw2 - kwds);
				goto err;
			}
			PyErr_Clear();
		}
	}

	for ( ; *kw; ++kw, --min) {
		argvar = va_arg(ap, PyObject **);
		if (kwargs) {
			*argvar = PyDict_GetItemString(kwargs, *kw);
			if (*argvar)
				PyDict_DelItemString(kwargs, *kw);
		} else
			*argvar = NULL;

		if (!*argvar && min > 0) {
			PyErr_Format(PyExc_TypeError,
				     "Required argument '%s' missing", *kw);
			goto err;
		}
	}
	va_end(ap);

	args = PyTuple_GetSlice(args, n, argc);
	if (!args)
		goto err;

	*pargs = args;
	*pkwargs = kwargs;
	return 0;

err:
	Py_XDECREF(kwargs);
	va_end(ap);
	return -1;
}

/** Call a method by name
 * @param obj     object
 * @param name    method name
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       method return value, or @c NULL on failure
 */
static PyObject *
call_method(PyObject *obj, const char *name, PyObject *args, PyObject *kwargs)
{
	PyObject *func;
	PyObject *result;

	func = PyObject_GetAttrString(obj, name);
	if (!func)
		return NULL;

	result = PyObject_Call(func, args, kwargs);
	Py_DECREF(func);
	return result;
}

/** Copy the value of an attribute to another attribute of the same object.
 * @param obj      Python object
 * @param srcname  Name of the source attribute.
 * @param dstname  Name of the destination attribute.
 * @returns        Zero on success, -1 on failure.
 */
static int
copy_attr(PyObject *obj, const char *srcname, const char *dstname)
{
	PyObject *attr;
	int result;

	attr = PyObject_GetAttrString(obj, srcname);
	if (!attr)
		return 0;

	result = PyObject_SetAttrString(obj, dstname, attr);
	Py_DECREF(attr);
	return result;
}

/** Call a cooperative superclass method
 * @param type    derived class type
 * @param obj     object
 * @param name    method name
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       method return value, or @c NULL on failure
 */
static PyObject *
call_super(PyTypeObject *type, PyObject *obj,
	   const char *name, PyObject *args, PyObject *kwargs)
{
	PyObject *super;
	PyObject *result;

	super = PyObject_CallFunction((PyObject*)&PySuper_Type,
				      "(OO)", type, obj);
	if (!super)
		return NULL;

	result = call_method(super, name, args, kwargs);
	Py_DECREF(super);
	return result;
}

/** Offset of a type member as a void pointer. */
#define OFFSETOF_PTR(type, member)	((void*)&(((type*)0)->member))

/** Getter for a Python object.
 * @param self  any object
 * @param data  offset of the meth member
 * @returns     referenced PyObject
 */
static PyObject *
get_object(PyObject *self, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	PyObject **pobj = (PyObject**)((char*)self + off);

	if (!*pobj)
		Py_RETURN_NONE;

	Py_INCREF(*pobj);
	return *pobj;
}

/** Getter for the addrxlat_addr_t type.
 * @param self  any object
 * @param data  offset of the addrxlat_addr_t member
 * @returns     PyLong object (or @c NULL on failure)
 */
static PyObject *
get_addr(PyObject *self, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_addr_t *paddr = (addrxlat_addr_t*)((char*)self + off);
	return PyLong_FromUnsignedLongLong(*paddr);
}

/** Setter for the addrxlat_addr_t type.
 * @param self   any object
 * @param value  new value (a @c PyLong or @c PyInt)
 * @param data   offset of the addrxlat_addr_t member
 * @returns      zero on success, -1 otherwise
 */
static int
set_addr(PyObject *self, PyObject *value, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_addr_t *paddr = (addrxlat_addr_t*)((char*)self + off);
	unsigned long long addr = Number_AsUnsignedLongLong(value);

	if (PyErr_Occurred())
		return -1;

	*paddr = addr;
	return 0;
}

/** Getter for the addrxlat_off_t type.
 * @param self  any object
 * @param data  offset of the addrxlat_off_t member
 * @returns     PyLong object (or @c NULL on failure)
 */
static PyObject *
get_off(PyObject *self, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_off_t *paddr = (addrxlat_off_t*)((char*)self + off);
	return PyLong_FromUnsignedLongLong(*paddr);
}

/** Setter for the addrxlat_off_t type.
 * @param self   any object
 * @param value  new value (a @c PyLong or @c PyInt)
 * @param data   offset of the addrxlat_off_t member
 * @returns      zero on success, -1 otherwise
 */
static int
set_off(PyObject *self, PyObject *value, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_off_t *paddr = (addrxlat_off_t*)((char*)self + off);
	unsigned long long addr = Number_AsUnsignedLongLongMask(value);

	if (PyErr_Occurred())
		return -1;

	*paddr = addr;
	return 0;
}

/** Getter for the addrxlat_addrspace_t type.
 * @param self  any object
 * @param data  offset of the addrxlat_addrspace_t member
 * @returns     PyLong object (or @c NULL on failure)
 */
static PyObject *
get_addrspace(PyObject *self, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_addrspace_t *paddrspace =
		(addrxlat_addrspace_t*)((char*)self + off);
	return PyInt_FromLong(*paddrspace);
}

/** Setter for the addrxlat_addr_t type.
 * @param self   any object
 * @param value  new value (a @c PyLong or @c PyInt)
 * @param data   offset of the addrxlat_addrspace_t member
 * @returns      zero on success, -1 otherwise
 */
static int
set_addrspace(PyObject *self, PyObject *value, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_addrspace_t *paddrspace =
		(addrxlat_addrspace_t*)((char*)self + off);
	long addrspace = Number_AsLong(value);

	if (PyErr_Occurred())
		return -1;

	*paddrspace = addrspace;
	return 0;
}

/** Getter for the addrxlat_pte_t type.
 * @param self  any object
 * @param data  offset of the addrxlat_pte_t member
 * @returns     PyLong object (or @c NULL on failure)
 */
static PyObject *
get_pte(PyObject *self, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_pte_t *pval = (addrxlat_pte_t*)((char*)self + off);
	return PyLong_FromUnsignedLongLong(*pval);
}

/** Setter for the addrxlat_pte_t type.
 * @param self   any object
 * @param value  new value (a @c PyLong or @c PyInt)
 * @param data   offset of the addrxlat_pte_t member
 * @returns      zero on success, -1 otherwise
 */
static int
set_pte(PyObject *self, PyObject *value, void *data)
{
	Py_ssize_t off = (intptr_t)data;
	addrxlat_pte_t *pval = (addrxlat_pte_t*)((char*)self + off);
	unsigned long long pte = Number_AsUnsignedLongLongMask(value);

	if (PyErr_Occurred())
		return -1;

	*pval = pte;
	return 0;
}

/** An object with a C pointer.
 * This object is used to create a Python object from a C pointer to
 * the corresponding libaddrxlat object passed as a _C_POINTER argument.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Pointer to the C structure. */
	void *ptr;
} c_pointer_object;

PyDoc_STRVAR(c_pointer__doc__,
"Internal-only type for creating Python objects from C pointers.");

static PyTypeObject c_pointer_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".c-pointer",		/* tp_name */
	sizeof (c_pointer_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	0,				/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,		/* tp_flags */
	c_pointer__doc__,		/* tp_doc */
};

/** Create a c-pointer object with a given pointer value.
 * @param ptr  C pointer to an object
 * @returns    Python object, or @c NULL on error
 *
 * This function returns @c NULL on error, or if the argument is not
 * found.  To distinguish between these two cases, the caller should
 * use @c PyErr_Occurred().
 */
static PyObject *
make_c_pointer(void *ptr)
{
	PyTypeObject *type = &c_pointer_type;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	if (result)
		((c_pointer_object*)result)->ptr = ptr;
	return result;
}

/** Name of the C pointer parameter.
 * Use this variable instead of a literal string to prevent typos.
 */
static const char _C_POINTER[] = "_C_POINTER";

/** Create keyword args with a _C_POINTER value.
 * @param ptr C pointer
 * @returns     Python dictionary to be used as kwargs
 */
static PyObject *
c_pointer_arg(void *ptr)
{
	PyObject *obj;
	PyObject *result;

	result = PyDict_New();
	if (result) {
		obj = make_c_pointer(ptr);
		if (!obj)
			goto err_dict;
		if (PyDict_SetItemString(result, _C_POINTER, obj))
			goto err_obj;
	}
	return result;

 err_obj:
	Py_DECREF(obj);
 err_dict:
	Py_DECREF(result);
	return NULL;
}

/** Get the _C_POINTER from keyword arguments (with type check).
 * @param kwargs  keyword arguments
 * @returns       C pointer, or @c NULL
 *
 * This function returns @c NULL on error, or if the argument is not
 * found.  To distinguish between these two cases, the caller should
 * use @c PyErr_Occurred().
 */
static void *
get_c_pointer(PyObject *kwargs)
{
	PyObject *obj;

	if (!kwargs)
		return NULL;

	obj = PyDict_GetItemString(kwargs, _C_POINTER);
	if (!obj)
		return NULL;

	if (!PyObject_TypeCheck(obj, &c_pointer_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a c-pointer, not '%.200s'",
			     Py_TYPE(obj)->tp_name);
		return NULL;
	}

	return ((c_pointer_object*)obj)->ptr;
}

/** Call superclass init, removing a C-pointer from args.
 * @param type    derived class type
 * @param self    calling object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       zero on success, -1 on failure
 */
static int
c_pointer_super_init(PyTypeObject *type, PyObject *self,
		     PyObject *args, PyObject *kwargs)
{
	PyObject *result;

	if (kwargs) {
		kwargs = PyDict_Copy(kwargs);
		if (!kwargs)
			return -1;

		if (PyDict_DelItemString(kwargs, _C_POINTER))
			PyErr_Clear();
	}

	result = call_super(type, self, "__init__", args, kwargs);
	Py_XDECREF(kwargs);
	if (!result)
		return -1;

	if (result != Py_None) {
		PyErr_Format(PyExc_TypeError,
			     "__init__() should return None, not '%.200s'",
			     Py_TYPE(result)->tp_name);
		Py_DECREF(result);
		return -1;
	}

	Py_DECREF(result);
	return 0;
}

/** Create a new Python object from a C pointer.
 * @param type  type of object
 * @param ptr   C pointer used for initialization
 * @returns     new Python object, or @c NULL on failure
 */
static PyObject *
object_FromPointer(PyTypeObject *type, void *ptr)
{
	PyObject *args, *kwargs;
	PyObject *result;

	args = PyTuple_New(0);
	if (!args)
		return NULL;

	kwargs = c_pointer_arg(ptr);
	if (!kwargs) {
		Py_DECREF(args);
		return NULL;
	}

	result = PyObject_Call((PyObject*)type, args, kwargs);
	Py_DECREF(kwargs);
	Py_DECREF(args);
	return result;
}

static PyObject *BaseException;

PyDoc_STRVAR(BaseException__doc__,
"Common base for all addrxlat exceptions.\n\
\n\
Attributes:\n\
    status   addrxlat status code, see ERR_xxx\n\
    message  verbose error message");

PyDoc_STRVAR(BaseException_init__doc__,
"__init__(status[, message])\n\
\n\
Initialize status code and error message. If message is not specified,\n\
use addrxlat_strerror(status).");

static PyObject *
BaseException_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"status", "message", NULL};
	PyTypeObject *basetype = ((PyTypeObject*)BaseException)->tp_base;
	PyObject *statobj, *msgobj;
	addrxlat_status status;
	int result;

	msgobj = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|O:BaseException",
					 keywords, &statobj, &msgobj))
		return NULL;

	args = msgobj
		? Py_BuildValue("(OO)", statobj, msgobj)
		: Py_BuildValue("(O)", statobj);
	if (!args)
		return NULL;
	result = basetype->tp_init(self, args, NULL);
	Py_DECREF(args);
	if (result)
		return NULL;

	status = Number_AsLong(statobj);
	if (PyErr_Occurred())
		return NULL;

	if (PyObject_SetAttrString(self, "status", statobj))
		return NULL;
	if (msgobj) {
		if (PyObject_SetAttrString(self, "message", msgobj))
			return NULL;
		Py_RETURN_NONE;
	}

	msgobj = Text_FromUTF8(addrxlat_strerror(status));
	if (!msgobj)
		return NULL;
	result = PyObject_SetAttrString(self, "message", msgobj);
	Py_DECREF(msgobj);
	if (result)
		return NULL;

	Py_RETURN_NONE;
}

static PyMethodDef BaseException_init_method = {
	"__init__", (PyCFunction)BaseException_init,
	METH_VARARGS | METH_KEYWORDS,
	BaseException_init__doc__
};

static PyObject *
make_BaseException(PyObject *mod)
{
	PyObject *descr;
	PyObject *result;

	result = PyErr_NewExceptionWithDoc(MOD_NAME ".BaseException",
					   BaseException__doc__, NULL, NULL);
	if (!result)
		return result;

	descr = PyDescr_NewMethod((PyTypeObject*)result,
				      &BaseException_init_method);
	if (!descr)
		goto err;
	if (PyObject_SetAttrString(result, "__init__", descr))
		goto err;
	Py_DECREF(descr);

	return result;

 err:
	Py_DECREF(result);
	return NULL;
}

/** Raise an _addrxlat.BaseException.
 * @param ctx     Address translation context
 * @param status  Status code (see @c ADDRXLAT_ERR_xxx)
 *
 * Use the provided context object to construct the arguments of
 * an addrxlat exception.
 */
static PyObject *
raise_exception(addrxlat_ctx_t *ctx, addrxlat_status status)
{
	const char *err = ctx
		? addrxlat_ctx_get_err(ctx)
		: NULL;
	PyObject *exc_val = err
		? Py_BuildValue("(is)", (int)status, err)
		: Py_BuildValue("(i)", (int)status);
	if (exc_val) {
		PyErr_SetObject(BaseException, exc_val);
		Py_DECREF(exc_val);
		if (ctx)
			addrxlat_ctx_clear_err(ctx);
	}
	return NULL;
}

/** Raise an NotImplemented exception.
 * @param msg  Verbose message
 * @returns    Always @c NULL
 */
static PyObject *
raise_notimpl(const char *msg)
{
	PyObject *exc_val;

	exc_val= Py_BuildValue("(is)", (int)ADDRXLAT_ERR_NOTIMPL, msg);
	if (exc_val) {
		PyErr_SetObject(BaseException, exc_val);
		Py_DECREF(exc_val);
	}
	return NULL;
}

/** Converter between C types and Python types.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD

	/** Target type for FullAddress conversions. */
	PyTypeObject *fulladdr_type;
	/** Target type for Context conversions. */
	PyTypeObject *ctx_type;
	/** Target type for Method conversions. */
	PyTypeObject *meth_type;
	/** Target type for CustomMethod conversions. */
	PyTypeObject *custommeth_type;
	/** Target type for LinearMethod conversions. */
	PyTypeObject *linearmeth_type;
	/** Target type for PageTableMethod conversions. */
	PyTypeObject *pgtmeth_type;
	/** Target type for LookupMethod conversions. */
	PyTypeObject *lookupmeth_type;
	/** Target type for MemoryArrayMethod conversions. */
	PyTypeObject *memarrmeth_type;
	/** Target type for Range conversions. */
	PyTypeObject *range_type;
	/** Target type for Map conversions. */
	PyTypeObject *map_type;
	/** Target type for System conversions. */
	PyTypeObject *sys_type;
	/** Target type for Step conversions. */
	PyTypeObject *step_type;
	/** Target type for Operator conversions. */
	PyTypeObject *op_type;
} convert_object;

static PyTypeObject fulladdr_type;
static PyTypeObject ctx_type;
static PyTypeObject meth_type;
static PyTypeObject custommeth_type;
static PyTypeObject linearmeth_type;
static PyTypeObject pgtmeth_type;
static PyTypeObject lookupmeth_type;
static PyTypeObject memarrmeth_type;
static PyTypeObject range_type;
static PyTypeObject map_type;
static PyTypeObject sys_type;
static PyTypeObject step_type;
static PyTypeObject op_type;

PyDoc_STRVAR(convert__doc__,
"Converter type between C pointer types and Python types");

/** Create a new convert object.
 * @param type    convert type
 * @param args    ignored
 * @param kwargs  ignored
 * @returns       new convert object, or @c NULL on failure
 */
static PyObject *
convert_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	convert_object *self;

	self = (convert_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->fulladdr_type = &fulladdr_type;
	Py_INCREF(self->fulladdr_type);
	self->ctx_type = &ctx_type;
	Py_INCREF(self->ctx_type);
	self->meth_type = &meth_type;
	Py_INCREF(self->meth_type);
	self->custommeth_type = &custommeth_type;
	Py_INCREF(self->custommeth_type);
	self->linearmeth_type = &linearmeth_type;
	Py_INCREF(self->linearmeth_type);
	self->pgtmeth_type = &pgtmeth_type;
	Py_INCREF(self->pgtmeth_type);
	self->lookupmeth_type = &lookupmeth_type;
	Py_INCREF(self->lookupmeth_type);
	self->memarrmeth_type = &memarrmeth_type;
	Py_INCREF(self->memarrmeth_type);
	self->range_type = &range_type;
	Py_INCREF(self->range_type);
	self->map_type = &map_type;
	Py_INCREF(self->map_type);
	self->sys_type = &sys_type;
	Py_INCREF(self->sys_type);
	self->step_type = &step_type;
	Py_INCREF(self->step_type);
	self->op_type = &op_type;
	Py_INCREF(self->op_type);

	return (PyObject*)self;
}

static void
convert_dealloc(PyObject *_self)
{
	convert_object *self = (convert_object *)_self;

	PyObject_GC_UnTrack(_self);

	Py_XDECREF(self->fulladdr_type);
	Py_XDECREF(self->ctx_type);
	Py_XDECREF(self->meth_type);
	Py_XDECREF(self->custommeth_type);
	Py_XDECREF(self->linearmeth_type);
	Py_XDECREF(self->pgtmeth_type);
	Py_XDECREF(self->lookupmeth_type);
	Py_XDECREF(self->memarrmeth_type);
	Py_XDECREF(self->range_type);
	Py_XDECREF(self->map_type);
	Py_XDECREF(self->sys_type);
	Py_XDECREF(self->step_type);
	Py_XDECREF(self->op_type);
}

static int
convert_traverse(PyObject *_self, visitproc visit, void *arg)
{
	convert_object *self = (convert_object *)_self;

	Py_VISIT(self->fulladdr_type);
	Py_VISIT(self->ctx_type);
	Py_VISIT(self->meth_type);
	Py_VISIT(self->custommeth_type);
	Py_VISIT(self->linearmeth_type);
	Py_VISIT(self->pgtmeth_type);
	Py_VISIT(self->lookupmeth_type);
	Py_VISIT(self->memarrmeth_type);
	Py_VISIT(self->range_type);
	Py_VISIT(self->map_type);
	Py_VISIT(self->sys_type);
	Py_VISIT(self->step_type);
	Py_VISIT(self->op_type);
	return 0;
}

PyDoc_STRVAR(convert_fulladdr__doc__,
"target type for FullAddress conversions");

PyDoc_STRVAR(convert_ctx__doc__,
"Target type for Context conversions.");

PyDoc_STRVAR(convert_meth__doc__,
"Target type for Method conversions.");

PyDoc_STRVAR(convert_custommeth__doc__,
"Target type for CustomMethod conversions.");

PyDoc_STRVAR(convert_linearmeth__doc__,
"Target type for LinearMethod conversions.");

PyDoc_STRVAR(convert_pgtmeth__doc__,
"Target type for PageTableMethod conversions.");

PyDoc_STRVAR(convert_lookupmeth__doc__,
"Target type for LookupMethod conversions.");

PyDoc_STRVAR(convert_memarrmeth__doc__,
"Target type for MemoryArrayMethod conversions.");

PyDoc_STRVAR(convert_range__doc__,
"Target type for Range conversions.");

PyDoc_STRVAR(convert_map__doc__,
"Target type for Map conversions.");

PyDoc_STRVAR(convert_sys__doc__,
"Target type for System conversions.");

PyDoc_STRVAR(convert_step__doc__,
"Target type for Step conversions.");

PyDoc_STRVAR(convert_op__doc__,
"Target type for Operator conversions.");

static PyMemberDef convert_members[] = {
	{ "FullAddress", T_OBJECT, offsetof(convert_object, fulladdr_type),
	  0, convert_fulladdr__doc__ },
	{ "Context", T_OBJECT, offsetof(convert_object, ctx_type),
	  0, convert_ctx__doc__ },
	{ "Method", T_OBJECT, offsetof(convert_object, meth_type),
	  0, convert_meth__doc__ },
	{ "CustomMethod", T_OBJECT,
	  offsetof(convert_object, custommeth_type),
	  0, convert_custommeth__doc__ },
	{ "LinearMethod", T_OBJECT,
	  offsetof(convert_object, linearmeth_type),
	  0, convert_linearmeth__doc__ },
	{ "PageTableMethod", T_OBJECT,
	  offsetof(convert_object, pgtmeth_type),
	  0, convert_pgtmeth__doc__ },
	{ "LookupMethod", T_OBJECT,
	  offsetof(convert_object, lookupmeth_type),
	  0, convert_lookupmeth__doc__ },
	{ "MemoryArrayMethod", T_OBJECT,
	  offsetof(convert_object, memarrmeth_type),
	  0, convert_memarrmeth__doc__ },
	{ "Range", T_OBJECT, offsetof(convert_object, range_type),
	  0, convert_range__doc__ },
	{ "Map", T_OBJECT, offsetof(convert_object, map_type),
	  0, convert_map__doc__ },
	{ "System", T_OBJECT, offsetof(convert_object, sys_type),
	  0, convert_sys__doc__ },
	{ "Step", T_OBJECT, offsetof(convert_object, step_type),
	  0, convert_step__doc__ },
	{ "Operator", T_OBJECT, offsetof(convert_object, op_type),
	  0, convert_op__doc__ },

	{ NULL }
};

static PyTypeObject convert_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".TypeConvert",	/* tp_name */
	sizeof (convert_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	convert_dealloc,		/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	convert__doc__,			/* tp_doc */
	convert_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	convert_members,		/* tp_members */
	0,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	convert_new,			/* tp_new */
};

/** Python representation of @ref addrxlat_fulladdr_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Full address in libaddrxlat format. */
	addrxlat_fulladdr_t faddr;
} fulladdr_object;

PyDoc_STRVAR(fulladdr__doc__,
"FullAddress() -> fulladdr\n\
\n\
Construct a full address, that is an address within a given\n\
address space (ADDRXLAT_xxxADDR).");

/** Construct a fulladdr object from an @c addrxlat_fulladdr_t pointer.
 * @param _conv  TypeConvert object.
 * @param faddr  New value as a C object.
 * @returns      Corresponding Python object (or @c NULL on failure).
 *
 * This function makes a new copy of the full address.
 */
static PyObject *
fulladdr_FromPointer(PyObject *_conv, const addrxlat_fulladdr_t *faddr)
{
	convert_object *conv = (convert_object *)_conv;
	PyTypeObject *type = conv->fulladdr_type;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	if (result)
		((fulladdr_object*)result)->faddr = *faddr;
	return result;
}

static int
fulladdr_equal(fulladdr_object *v, fulladdr_object *w)
{
	return v->faddr.addr == w->faddr.addr &&
		v->faddr.as == w->faddr.as;
}

static PyObject *
fulladdr_richcompare(PyObject *v, PyObject *w, int op)
{
	PyObject *result;

	if ((op == Py_EQ || op == Py_NE) &&
	    PyObject_TypeCheck(v, &fulladdr_type) &&
	    PyObject_TypeCheck(w, &fulladdr_type)) {
		int cmp = fulladdr_equal((fulladdr_object*)v,
					 (fulladdr_object*)w);
		result = (cmp == (op == Py_EQ))
			? Py_True
			: Py_False;
	} else
		result = Py_NotImplemented;

	Py_INCREF(result);
	return result;
}

PyDoc_STRVAR(fulladdr_addr__doc__,
"address (unsigned)");

PyDoc_STRVAR(fulladdr_addrspace__doc__,
"address space");

static PyGetSetDef fulladdr_getset[] = {
	{ "addr", get_addr, set_addr, fulladdr_addr__doc__,
	  OFFSETOF_PTR(fulladdr_object, faddr.addr) },
	{ "addrspace", get_addrspace, set_addrspace,
	  fulladdr_addrspace__doc__ ,
	  OFFSETOF_PTR(fulladdr_object, faddr.as) },
	{ NULL }
};

PyDoc_STRVAR(fulladdr_conv__doc__,
"FULLADDR.conv(addrspace, ctx, sys) -> status\n\
\n\
Convert a full address to a given target address space.");

/** Wrapper for @ref addrxlat_fulladdr_conv
 * @param _self   step object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       status code (or @c NULL on failure)
 */
static PyObject *
fulladdr_conv(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	fulladdr_object *self = (fulladdr_object*)_self;
	static char *keywords[] = {"addrspace", "ctx", "sys", NULL};
	PyObject *ctxobj, *sysobj;
	addrxlat_ctx_t *ctx;
	addrxlat_sys_t *sys;
	int addrspace;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "iOO:conv",
					 keywords, &addrspace,
					 &ctxobj, &sysobj))
		return NULL;

	ctx = ctx_AsPointer(ctxobj);
	if (!ctx)
		return NULL;

	sys = sys_AsPointer(sysobj);
	if (PyErr_Occurred())
		return NULL;

	status = addrxlat_fulladdr_conv(&self->faddr, addrspace, ctx, sys);
	return ctx_status_result(ctxobj, status);
}

static PyMethodDef fulladdr_methods[] = {
	{ "conv", (PyCFunction)fulladdr_conv,
	  METH_VARARGS | METH_KEYWORDS,
	  fulladdr_conv__doc__ },
	{ NULL }
};

static PyTypeObject fulladdr_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".FullAddress",	/* tp_name */
	sizeof (fulladdr_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	0,				/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	fulladdr__doc__,		/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	fulladdr_richcompare,		/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	fulladdr_methods,		/* tp_methods */
	0,				/* tp_members */
	fulladdr_getset,		/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	0,				/* tp_new */
};

/** Get the libaddrxlat representation of a Python fulladdr object.
 * @param self   FullAddress object.
 * @returns      Address of the embedded @c libaddrxlat_fulladdr_t,
 *               or @c NULL on error.
 *
 * The returned pointer refers to a @c libaddrxlat_fulladdr_t
 * structure embedded in the Python object, i.e. the pointer is
 * valid only as long as the containing Python object exists.
 *
 * If @c self is @c Py_None, return a pointer to a null address singleton.
 * This singleton should not be modified, as it would affect all other
 * @c None full addresses.
 */
static addrxlat_fulladdr_t *
fulladdr_AsPointer(PyObject *self)
{
	static addrxlat_fulladdr_t nulladdr = { 0, ADDRXLAT_NOADDR };

	if (self == Py_None)
		return &nulladdr;

	if (!PyObject_TypeCheck(self, &fulladdr_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a FullAddress or None, not '%.200s'",
			     Py_TYPE(self)->tp_name);
		return NULL;
	}

	return &((fulladdr_object*)self)->faddr;
}

typedef struct tag_ctx_object {
	PyObject_HEAD

	addrxlat_ctx_t *ctx;
	addrxlat_cb_t *cb;

	PyObject *exc_type, *exc_val, *exc_tb;

	PyObject *convert;
} ctx_object;

static void
ctx_set_exception(ctx_object *self,
		  PyObject *exc_type, PyObject *exc_val, PyObject *exc_tb)
{
	PyObject *old_type, *old_val, *old_tb;

	old_type = self->exc_type;
	old_val = self->exc_val;
	old_tb = self->exc_tb;
	self->exc_type = exc_type;
	self->exc_val = exc_val;
	self->exc_tb = exc_tb;
	Py_XDECREF(old_type);
	Py_XDECREF(old_val);
	Py_XDECREF(old_tb);
}

static addrxlat_status
ctx_error_status(ctx_object *self)
{
	PyObject *exc_type, *exc_val, *exc_tb;
	PyObject *obj;
	addrxlat_status status;
	const char *msg;

	PyErr_Fetch(&exc_type, &exc_val, &exc_tb);
	if (!exc_type)
		return ADDRXLAT_OK;

	if (!PyErr_GivenExceptionMatches(exc_type, BaseException))
		goto err;

	PyErr_NormalizeException(&exc_type, &exc_val, &exc_tb);
	obj = PyObject_GetAttrString(exc_val, "status");
	if (!obj)
		goto err;
	status = Number_AsLong(obj);
	if (PyErr_Occurred()) {
		Py_DECREF(obj);
		goto err;
	}
	Py_DECREF(obj);

	obj = PyObject_GetAttrString(exc_val, "message");
	if (!obj)
		goto err;
	msg = Text_AsUTF8(obj);
	if (!msg) {
		Py_DECREF(obj);
		goto err;
	}
	addrxlat_ctx_err(self->ctx, status, "%s", msg);
	Py_DECREF(obj);

	Py_DECREF(exc_type);
	Py_DECREF(exc_val);
	Py_XDECREF(exc_tb);
	return status;

 err:
	PyErr_Clear();
	ctx_set_exception(self, exc_type, exc_val, exc_tb);
	return STATUS_PYEXC;
}

/** Handle a possible exception raised by a callback.
 * @param self    Context object
 * @param status  Error status
 * @returns       Negative if an exception was restored, zero otherwise.
 *
 * A special return code is used to pass Python exceptions from a callback
 * to the caller. The exception is stored in the Context object in that
 * case.
 *
 * However, the library code may decide to ignore any errors returned by
 * the callback. If that happens, the exception must be cleared accordingly.
 */
static int
handle_cb_exception(ctx_object *self, addrxlat_status status)
{
	if (status == STATUS_PYEXC && self->exc_type) {
		PyErr_Restore(self->exc_type, self->exc_val, self->exc_tb);
		self->exc_type = NULL;
		self->exc_val = NULL;
		self->exc_tb = NULL;
		return -1;
	}
	ctx_set_exception(self, NULL, NULL, NULL);
	return 0;
}

static PyObject *
ctx_status_result(PyObject *_self, addrxlat_status status)
{
	ctx_object *self = (ctx_object*)_self;
	return !handle_cb_exception(self, status)
		? PyInt_FromLong(status)
		: NULL;
}

/** Callback function return on None return.
 * @param self  Python Context object
 * @returns     Always ADDRXLAT_ERR_NODATA
 */
static addrxlat_status
cb_none(ctx_object *self)
{
	return addrxlat_ctx_err(self->ctx, ADDRXLAT_ERR_NODATA,
				"Callback returned None");
}

static void
cb_put_page(const addrxlat_buffer_t *buf)
{
	PyMem_Free(buf->priv);
}

static addrxlat_status
cb_get_page(const addrxlat_cb_t *cb, addrxlat_buffer_t *buf)
{
	ctx_object *self = (ctx_object*)cb->priv;
	PyObject *addrobj, *result, *bufferobj;
	addrxlat_fulladdr_t *addr;
	int byte_order;
	Py_buffer view;

	addrobj = fulladdr_FromPointer(self->convert, &buf->addr);
	if (!addrobj)
		return ctx_error_status(self);
	result = PyObject_CallMethod(
		(PyObject*)self, "cb_get_page", "O", addrobj);
	if (!result) {
		Py_DECREF(addrobj);
		return ctx_error_status(self);
	}
	if (result == Py_None) {
		Py_DECREF(result);
		Py_DECREF(addrobj);
		return cb_none(self);
	}

	byte_order = ADDRXLAT_HOST_ENDIAN;
	if (PyTuple_Check(result)) {
		if (!PyArg_ParseTuple(result, "O|i:cb_get_page",
				      &bufferobj, &byte_order)) {
			Py_DECREF(result);
			Py_DECREF(addrobj);
			return ctx_error_status(self);
		}
		Py_INCREF(bufferobj);
		Py_DECREF(result);
	} else
		bufferobj = result;

	addr = fulladdr_AsPointer(addrobj);
	if (!addr) {
		Py_DECREF(addrobj);
		Py_DECREF(bufferobj);
		return ctx_error_status(self);
	}
	buf->addr = *addr;
	Py_DECREF(addrobj);

	if (PyObject_GetBuffer(bufferobj, &view, PyBUF_CONTIG_RO) < 0) {
		Py_DECREF(bufferobj);
		return ctx_error_status(self);
	}
	Py_DECREF(bufferobj);
	buf->put_page = cb_put_page;
	buf->priv = PyMem_Malloc(view.len);
	if (buf->priv == NULL) {
		PyBuffer_Release(&view);
		PyErr_NoMemory();
		return ctx_error_status(self);
	}
	if (PyBuffer_ToContiguous(buf->priv, &view, view.len, 'C') < 0) {
		PyBuffer_Release(&view);
		return ctx_error_status(self);
	}
	buf->ptr = buf->priv;
	buf->size = view.len;
	buf->byte_order = byte_order;
	PyBuffer_Release(&view);

	return ADDRXLAT_OK;
}

static unsigned long
cb_read_caps(const addrxlat_cb_t *cb)
{
	ctx_object *self = (ctx_object*)cb->priv;
	PyObject *result;
	unsigned long caps;

	result = PyObject_CallMethod((PyObject*)self, "cb_read_caps", NULL);
	if (!result)
		return 0;
	if (result == Py_None) {
		Py_DECREF(result);
		return 0;
	}

	caps = Number_AsUnsignedLongLong(result);
	Py_DECREF(result);
	if (PyErr_Occurred())
		return 0;

	return caps;
}

static addrxlat_status
cb_sym_offsetof(const addrxlat_cb_t *cb, const char *obj,
		const char *elem, addrxlat_addr_t *val)
{
	ctx_object *self = (ctx_object*)cb->priv;
	PyObject *result;
	unsigned long tmpval;

	result = PyObject_CallMethod((PyObject*)self, "cb_sym_offsetof",
				     "ss", obj, elem);
	if (!result)
		return ctx_error_status(self);
	if (result == Py_None) {
		Py_DECREF(result);
		return cb_none(self);
	}

	tmpval = Number_AsUnsignedLongLong(result);
	Py_DECREF(result);
	if (PyErr_Occurred())
		return ctx_error_status(self);

	*val = tmpval;
	return ADDRXLAT_OK;
}

static addrxlat_status
cb_arg1_value(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val,
	      const char *method)
{
	ctx_object *self = (ctx_object*)cb->priv;
	PyObject *result;
	unsigned long tmpval;

	result = PyObject_CallMethod((PyObject*)self, method, "s", name);
	if (!result)
		return ctx_error_status(self);
	if (result == Py_None) {
		Py_DECREF(result);
		return cb_none(self);
	}

	tmpval = Number_AsUnsignedLongLong(result);
	Py_DECREF(result);
	if (PyErr_Occurred())
		return ctx_error_status(self);

	*val = tmpval;
	return ADDRXLAT_OK;
}

static addrxlat_status
cb_reg_value(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	return cb_arg1_value(cb, name, val, "cb_reg_value");
}

static addrxlat_status
cb_sym_value(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	return cb_arg1_value(cb, name, val, "cb_sym_value");
}

static addrxlat_status
cb_sym_sizeof(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	return cb_arg1_value(cb, name, val, "cb_sym_sizeof");
}

static addrxlat_status
cb_num_value(const addrxlat_cb_t *cb, const char *name, addrxlat_addr_t *val)
{
	return cb_arg1_value(cb, name, val, "cb_num_value");
}

PyDoc_STRVAR(ctx__doc__,
"Context() -> address translation context");

static PyObject *
ctx_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	ctx_object *self;

	self = (ctx_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->ctx = get_c_pointer(kwargs);
	if (!self->ctx) {
		if (PyErr_Occurred())
			return NULL;

		self->ctx = addrxlat_ctx_new();
		if (!self->ctx) {
			Py_DECREF(self);
			return PyErr_NoMemory();
		}
	} else {
		addrxlat_ctx_incref(self->ctx);

		if (copy_attr((PyObject*)self, "next_cb_get_page", "cb_get_page"))
			goto err;
		if (copy_attr((PyObject*)self, "next_read_caps", "cb_read_caps"))
			goto err;
		if (copy_attr((PyObject*)self, "next_cb_reg_value", "cb_reg_value"))
			goto err;
		if (copy_attr((PyObject*)self, "next_cb_sym_value", "cb_sym_value"))
			goto err;
		if (copy_attr((PyObject*)self, "next_cb_sym_sizeof", "cb_sym_sizeof"))
			goto err;
		if (copy_attr((PyObject*)self, "next_cb_sym_offsetof", "cb_sym_offsetof"))
			goto err;
		if (copy_attr((PyObject*)self, "next_cb_num_value", "cb_num_value"))
			goto err;
	}

	self->cb = addrxlat_ctx_add_cb(self->ctx);
	if (!self->cb) {
		addrxlat_ctx_decref(self->ctx);
		Py_DECREF(self);
		return PyErr_NoMemory();
	}
	self->cb->priv = self;
	self->cb->get_page = cb_get_page;
	self->cb->read_caps = cb_read_caps;
	self->cb->reg_value = cb_reg_value;
	self->cb->sym_value = cb_sym_value;
	self->cb->sym_sizeof = cb_sym_sizeof;
	self->cb->sym_offsetof = cb_sym_offsetof;
	self->cb->num_value = cb_num_value;

	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;

 err:
	Py_DECREF(self);
	return NULL;
}

static int
ctx_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return c_pointer_super_init(&ctx_type, self, args, kwargs);
}

/** Construct a context object from an @c addrxlat_ctx_t pointer.
 * @param _conv  TypeConvert object.
 * @param ctx    New value as a C object, or @c NULL.
 * @returns      Corresponding Python object (or @c NULL on failure).
 *
 * The Python object contains a new reference to the translation context.
 */
static PyObject *
ctx_FromPointer(PyObject *_conv, addrxlat_ctx_t *ctx)
{
	convert_object *conv = (convert_object *)_conv;

	if (!ctx)
		Py_RETURN_NONE;

	return object_FromPointer(conv->ctx_type, ctx);
}

static void
ctx_dealloc(PyObject *_self)
{
	ctx_object *self = (ctx_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);

	Py_XDECREF(self->exc_type);
	Py_XDECREF(self->exc_val);
	Py_XDECREF(self->exc_tb);

	if (self->ctx) {
		addrxlat_ctx_del_cb(self->ctx, self->cb);
		addrxlat_ctx_decref(self->ctx);
	}

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
ctx_traverse(PyObject *_self, visitproc visit, void *arg)
{
	ctx_object *self = (ctx_object*)_self;

	Py_VISIT(self->exc_type);
	Py_VISIT(self->exc_val);
	Py_VISIT(self->exc_tb);

	Py_VISIT(self->convert);

	return 0;
}

static PyObject *
ctx_richcompare(PyObject *v, PyObject *w, int op)
{
	PyObject *result;

	if ((op == Py_EQ || op == Py_NE) &&
	    PyObject_TypeCheck(v, &ctx_type) &&
	    PyObject_TypeCheck(w, &ctx_type)) {
		int cmp = (((ctx_object*)v)->ctx == ((ctx_object*)w)->ctx);
		result = (cmp == (op == Py_EQ))
			? Py_True
			: Py_False;
	} else
		result = Py_NotImplemented;

	Py_INCREF(result);
	return result;
}

PyDoc_STRVAR(ctx_err__doc__,
"CTX.err(status, str) -> error status\n\
\n\
Set the error message.");

static PyObject *
ctx_err(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	ctx_object *self = (ctx_object*)_self;
	static char *keywords[] = {"status", "str", NULL};
	int statusparam;
	const char *msg;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "is:err",
					 keywords, &statusparam, &msg))
		return NULL;

	status = addrxlat_ctx_err(self->ctx, statusparam, "%s", msg);
	return ctx_status_result((PyObject*)self, status);
}

PyDoc_STRVAR(ctx_clear_err__doc__,
"CTX.clear_err()\n\
\n\
Clear the error message.");

static PyObject *
ctx_clear_err(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;

	addrxlat_ctx_clear_err(self->ctx);
	Py_RETURN_NONE;
}

PyDoc_STRVAR(ctx_get_err__doc__,
"CTX.get_err() -> error string\n\
\n\
Return a detailed error description of the last error condition.");

static PyObject *
ctx_get_err(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	const char *err = addrxlat_ctx_get_err(self->ctx);

	return err
		? Text_FromUTF8(err)
		: (Py_INCREF(Py_None), Py_None);
}

PyDoc_STRVAR(ctx_cb_get_page__doc__,
"CTX.cb_get_page(fulladdr) -> (value, [byte_order])\n\
\n\
Callback function to read a page at a given address. The first element\n\
of the return tuple must implement the buffer protocol. The second\n\
element is optional and defaults to HOST_ENDIAN.");

PyDoc_STRVAR(ctx_next_cb_get_page__doc__,
"CTX.next_cb_get_page(type, *args) -> value\n\
\n\
Call the next callback to read a page.");

static PyObject *
ctx_next_cb_get_page(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	PyObject *addrobj, *bytearrayobj, *result;
	addrxlat_fulladdr_t *addr;
	addrxlat_buffer_t buffer;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);

	if (!PyArg_ParseTuple(args, "O", &addrobj))
		return NULL;
	addr = fulladdr_AsPointer(addrobj);
	if (!addr)
		return NULL;

	buffer.addr = *addr;
	status = self->cb->next->get_page(self->cb->next, &buffer);
	*addr = buffer.addr;

	if (self->cb->next->get_page == cb_get_page &&
	    handle_cb_exception((ctx_object*)self->cb->next->priv, status))
		return NULL;

	if (status != ADDRXLAT_OK)
		return raise_exception(self->ctx, status);

	bytearrayobj = PyByteArray_FromStringAndSize(buffer.ptr, buffer.size);
	if (!bytearrayobj)
		goto err;
	result = Py_BuildValue("(Oi)", bytearrayobj, buffer.byte_order);
	if (!result)
		goto err_bytearray;
	return result;

 err_bytearray:
	Py_DECREF(bytearrayobj);
 err:
	return NULL;
}

PyDoc_STRVAR(ctx_cb_read_caps__doc__,
"CTX.cb_read_caps() -> capabilities\n\
\n\
Callback function to get a bitmask of address spaces accepted by\n\
the cb_get_page callback.");

PyDoc_STRVAR(ctx_next_cb_read_caps__doc__,
"CTX.next_cb_read_caps() -> value\n\
\n\
Call the next callback to get the capabilities.");

static PyObject *
ctx_next_cb_read_caps(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	unsigned long caps;
	PyObject *result;

	caps = self->cb->next->read_caps(self->cb->next);
	if (PyErr_Occurred())
		return NULL;

	result = Py_BuildValue("k", caps);
	if (!result)
		return NULL;
	return result;
}

PyDoc_STRVAR(ctx_cb_reg_value__doc__,
"CTX.cb_reg_value(type, name) -> value\n\
\n\
Callback function to read register value.");

PyDoc_STRVAR(ctx_next_cb_reg_value__doc__,
"CTX.next_cb_reg_value(type, name) -> value\n\
\n\
Call the next register value callback.");

static PyObject *
ctx_next_cb_reg_value(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	const char *name;
	addrxlat_addr_t val;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	status = self->cb->next->reg_value(self->cb->next, name, &val);

	if (self->cb->next->reg_value == cb_reg_value &&
	    handle_cb_exception((ctx_object*)self->cb->next->priv, status))
		return NULL;

	if (status != ADDRXLAT_OK)
		return raise_exception(self->ctx, status);

	return PyLong_FromUnsignedLongLong(val);
}

PyDoc_STRVAR(ctx_cb_sym_value__doc__,
"CTX.cb_sym_value(type, name) -> value\n\
\n\
Callback function to get the value of a symbol.");

PyDoc_STRVAR(ctx_next_cb_sym_value__doc__,
"CTX.next_cb_sym_value(type, name) -> value\n\
\n\
Call the next symbol value callback.");

static PyObject *
ctx_next_cb_sym_value(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	const char *name;
	addrxlat_addr_t val;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	status = self->cb->next->sym_value(self->cb->next, name, &val);

	if (self->cb->next->sym_value == cb_sym_value &&
	    handle_cb_exception((ctx_object*)self->cb->next->priv, status))
		return NULL;

	if (status != ADDRXLAT_OK)
		return raise_exception(self->ctx, status);

	return PyLong_FromUnsignedLongLong(val);
}

PyDoc_STRVAR(ctx_cb_sym_sizeof__doc__,
"CTX.cb_sym_sizeof(type, name) -> value\n\
\n\
Callback function to get the size of a symbol.");

PyDoc_STRVAR(ctx_next_cb_sym_sizeof__doc__,
"CTX.next_cb_sym_sizeof(type, name) -> value\n\
\n\
Call the next symbol size callback.");

static PyObject *
ctx_next_cb_sym_sizeof(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	const char *name;
	addrxlat_addr_t val;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	status = self->cb->next->sym_sizeof(self->cb->next, name, &val);

	if (self->cb->next->sym_sizeof == cb_sym_sizeof &&
	    handle_cb_exception((ctx_object*)self->cb->next->priv, status))
		return NULL;

	if (status != ADDRXLAT_OK)
		return raise_exception(self->ctx, status);

	return PyLong_FromUnsignedLongLong(val);
}

PyDoc_STRVAR(ctx_cb_sym_offsetof__doc__,
"CTX.cb_sym_offsetof(type, obj, elem) -> value\n\
\n\
Callback function to get the offset of an element within a container object.");

PyDoc_STRVAR(ctx_next_cb_sym_offsetof__doc__,
"CTX.next_cb_sym_offsetof(type, obj, elem) -> value\n\
\n\
Call the next element offset callback.");

static PyObject *
ctx_next_cb_sym_offsetof(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	const char *obj, *elem;
	addrxlat_addr_t val;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);

	if (!PyArg_ParseTuple(args, "ss", &obj, &elem))
		return NULL;

	status = self->cb->next->sym_offsetof(self->cb->next, obj, elem, &val);

	if (self->cb->next->sym_offsetof == cb_sym_offsetof &&
	    handle_cb_exception((ctx_object*)self->cb->next->priv, status))
		return NULL;

	if (status != ADDRXLAT_OK)
		return raise_exception(self->ctx, status);

	return PyLong_FromUnsignedLongLong(val);
}

PyDoc_STRVAR(ctx_cb_num_value__doc__,
"CTX.cb_num_value(type, name) -> value\n\
\n\
Callback function to get the value of a numeric parameter.");

PyDoc_STRVAR(ctx_next_cb_num_value__doc__,
"CTX.next_cb_num_value(type, name) -> value\n\
\n\
Call the next numeric parameter callback.");

static PyObject *
ctx_next_cb_num_value(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	const char *name;
	addrxlat_addr_t val;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);

	if (!PyArg_ParseTuple(args, "s", &name))
		return NULL;

	status = self->cb->next->num_value(self->cb->next, name, &val);

	if (self->cb->next->num_value == cb_num_value &&
	    handle_cb_exception((ctx_object*)self->cb->next->priv, status))
		return NULL;

	if (status != ADDRXLAT_OK)
		return raise_exception(self->ctx, status);

	return PyLong_FromUnsignedLongLong(val);
}

static PyMethodDef ctx_methods[] = {
	{ "err", (PyCFunction)ctx_err, METH_VARARGS | METH_KEYWORDS,
	  ctx_err__doc__ },
	{ "clear_err", ctx_clear_err, METH_NOARGS,
	  ctx_clear_err__doc__ },
	{ "get_err", ctx_get_err, METH_NOARGS,
	  ctx_get_err__doc__ },

	/* Callbacks */
	{ "cb_get_page", ctx_next_cb_get_page, METH_VARARGS,
	  ctx_cb_get_page__doc__ },
	{ "cb_read_caps", ctx_next_cb_read_caps, METH_VARARGS,
	  ctx_cb_read_caps__doc__ },
	{ "cb_reg_value", ctx_next_cb_reg_value, METH_VARARGS,
	  ctx_cb_reg_value__doc__ },
	{ "cb_sym_value", ctx_next_cb_sym_value, METH_VARARGS,
	  ctx_cb_sym_value__doc__ },
	{ "cb_sym_sizeof", ctx_next_cb_sym_sizeof, METH_VARARGS,
	  ctx_cb_sym_sizeof__doc__ },
	{ "cb_sym_offsetof", ctx_next_cb_sym_offsetof, METH_VARARGS,
	  ctx_cb_sym_offsetof__doc__ },
	{ "cb_num_value", ctx_next_cb_num_value, METH_VARARGS,
	  ctx_cb_num_value__doc__ },

	{ "next_cb_get_page", ctx_next_cb_get_page, METH_VARARGS,
	  ctx_next_cb_get_page__doc__ },
	{ "next_read_caps", ctx_next_cb_read_caps, METH_VARARGS,
	  ctx_next_cb_read_caps__doc__ },
	{ "next_cb_reg_value", ctx_next_cb_reg_value, METH_VARARGS,
	  ctx_next_cb_reg_value__doc__ },
	{ "next_cb_sym_value", ctx_next_cb_sym_value, METH_VARARGS,
	  ctx_next_cb_sym_value__doc__ },
	{ "next_cb_sym_sizeof", ctx_next_cb_sym_sizeof, METH_VARARGS,
	  ctx_next_cb_sym_sizeof__doc__ },
	{ "next_cb_sym_offsetof", ctx_next_cb_sym_offsetof, METH_VARARGS,
	  ctx_next_cb_sym_offsetof__doc__ },
	{ "next_cb_num_value", ctx_next_cb_num_value, METH_VARARGS,
	  ctx_next_cb_num_value__doc__ },

	{ NULL }
};

static PyMemberDef ctx_members[] = {
	{ "convert", T_OBJECT, offsetof(ctx_object, convert), 0,
	  attr_convert__doc__ },
	{ NULL }
};

static PyTypeObject ctx_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Context",		/* tp_name */
	sizeof (ctx_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	ctx_dealloc,			/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	ctx__doc__,			/* tp_doc */
	ctx_traverse,			/* tp_traverse */
	0,				/* tp_clear */
	ctx_richcompare,		/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	ctx_methods,			/* tp_methods */
	ctx_members,			/* tp_members */
	0,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	ctx_init,			/* tp_init */
	0,				/* tp_alloc */
	ctx_new,			/* tp_new */
};

/** Get the libaddrxlat representation of a Context object.
 * @param self  Context object.
 * @returns     Associated @c libaddrxlat_ctx_t, or @c NULL on error.
 *
 * This function does not increment the reference count of the returned
 * C object. It is assumed that the caller holds a reference to the Python
 * object, which in turn holds a reference to the C object.
 */
static addrxlat_ctx_t *
ctx_AsPointer(PyObject *self)
{
	if (!PyObject_TypeCheck(self, &ctx_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a Context, not '%.200s'",
			     Py_TYPE(self)->tp_name);
		return NULL;
	}

	return ((ctx_object*)self)->ctx;
}

static int
replace_ctx(PyObject **pctxobj, addrxlat_ctx_t **pctx, PyObject *newval)
{
	addrxlat_ctx_t *ctx;
	PyObject *oldval;

	ctx = ctx_AsPointer(newval);
	if (!ctx)
		return -1;

	addrxlat_ctx_incref(ctx);
	if (*pctx)
		addrxlat_ctx_decref(*pctx);
	*pctx = ctx;

	Py_INCREF(newval);
	oldval = *pctxobj;
	*pctxobj = newval;
	Py_XDECREF(oldval);
	return 0;
}

typedef struct {
	void *ptr;
	unsigned off;
	unsigned len;
} param_loc;

static void
loc_scatter(const param_loc *loc, unsigned n, const void *buffer)
{
	unsigned i;
	for (i = 0; i < n; ++i, ++loc)
		if (loc->ptr && loc->ptr != buffer + loc->off)
			memcpy(loc->ptr, buffer + loc->off, loc->len);
}

static void
loc_gather(const param_loc *loc, unsigned n, void *buffer)
{
	unsigned i;
	for (i = 0; i < n; ++i, ++loc)
		if (loc->ptr && loc->ptr != buffer + loc->off)
			memcpy(buffer + loc->off, loc->ptr, loc->len);
}

/** Location of a fulladdr parameter within another object. */
typedef struct {
	/** Offset of the Python object. */
	size_t off_obj;

	/** Offset of the corresponding @ref param_loc structure. */
	size_t off_loc;

	/** Name of the attribute (used in exception messages). */
	const char name[];
} fulladdr_loc;

/** Getter for the fulladdr type.
 * @param self  any object
 * @param data  fulladdr attribute location
 * @returns     PyLong object (or @c NULL on failure)
 */
static PyObject *
get_fulladdr(PyObject *self, void *data)
{
	fulladdr_loc *addrloc = data;
	PyObject **fulladdr = (PyObject**)((char*)self + addrloc->off_obj);
	Py_INCREF(*fulladdr);
	return *fulladdr;
}

/** Setter for the fulladdr type.
 * @param self   any object
 * @param value  new value (a fulladdr object)
 * @param data   fulladdr attribute location
 * @returns      zero on success, -1 otherwise
 */
static int
set_fulladdr(PyObject *self, PyObject *value, void *data)
{
	fulladdr_loc *addrloc = data;
	PyObject **pobj = (PyObject**)((char*)self + addrloc->off_obj);
	param_loc *loc = (param_loc*)((char*)self + addrloc->off_loc);
	PyObject *oldval;
	addrxlat_fulladdr_t *addr;

	if (check_null_attr(value, addrloc->name))
		return -1;

	addr = fulladdr_AsPointer(value);
	if (!addr)
		return -1;

	Py_INCREF(value);
	oldval = *pobj;
	*pobj = value;
	loc->ptr = (value == Py_None ? NULL : addr);
	Py_XDECREF(oldval);
	return 0;
}

/** Maximum number of parameter locations in meth_object.
 * This is not checked anywhere, but should be less than the maximum
 * possible number of parameter locations. The assignment is currently:
 *
 * - @c loc[0] corresponds to the whole raw param object
 * - @c loc[1] is the root address (for PageTableMethod) or
 *             base address (for MemoryArrayMethod)
 */
#define MAXLOC	2

#define meth_HEAD		\
	PyObject_HEAD		\
	addrxlat_meth_t meth;	\
	PyObject *paramobj;	\
	unsigned nloc;		\
	param_loc loc[MAXLOC];	\
	PyObject *convert;

typedef struct {
	meth_HEAD
} meth_object;

/** Number of parameter locations in meth_object. */
#define METH_NLOC	1

PyDoc_STRVAR(meth__doc__,
"Method(kind) -> address translation method\n\
\n\
This is a generic base class for all translation descriptions.\n\
Use a subclass to get a more suitable interface to the parameters\n\
of a specific translation kind.");

static PyObject *
meth_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	static const char *keywords[] = {"kind", NULL};
	meth_object *self;
	PyObject *value;
	long kind;

	if (fetch_args(keywords, 1, &args, &kwargs, &value))
		return NULL;
	Py_DECREF(args);
	Py_XDECREF(kwargs);
	kind = Number_AsLong(value);
	if (PyErr_Occurred())
		return NULL;

	self = (meth_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->meth.kind = kind;
	self->meth.target_as = ADDRXLAT_NOADDR;
	self->nloc = METH_NLOC;
	self->loc[0].ptr = &self->meth.param;
	self->loc[0].off = 0;
	self->loc[0].len = sizeof(self->meth.param);
	self->paramobj = make_meth_param((PyObject*)self);
	if (!self->paramobj) {
		Py_DECREF(self);
		return NULL;
	}
	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;
}

/** Initialize a Method object using a C @c addrxlat_meth_t object.
 * @param _self  Python Method object
 * @param meth   libaddrxlat translation method
 * @returns      zero on success, -1 otherwise
 */
static int
meth_Init(PyObject *_self, const addrxlat_meth_t *meth)
{
	meth_object *self = (meth_object*)_self;

	self->meth.target_as = meth->target_as;
	loc_scatter(self->loc, self->nloc, &meth->param);
	return 0;
}

static void
meth_dealloc(PyObject *_self)
{
	meth_object *self = (meth_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);
	Py_XDECREF(self->paramobj);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
meth_traverse(PyObject *_self, visitproc visit, void *arg)
{
	meth_object *self = (meth_object*)_self;
	Py_VISIT(self->paramobj);
	Py_VISIT(self->convert);
	return 0;
}

static int
meth_equal(meth_object *v, meth_object *w)
{
	return v->loc[0].len == w->loc[0].len &&
		!memcmp(&v->meth, &w->meth, v->loc[0].len);
}

static PyObject *
meth_richcompare(PyObject *v, PyObject *w, int op)
{
	PyObject *result;

	if ((op == Py_EQ || op == Py_NE) &&
	    PyObject_TypeCheck(v, &meth_type) &&
	    PyObject_TypeCheck(w, &meth_type)) {
		int cmp = meth_equal((meth_object*)v, (meth_object*)w);
		result = (cmp == (op == Py_EQ))
			? Py_True
			: Py_False;
	} else
		result = Py_NotImplemented;

	Py_INCREF(result);
	return result;
}

static PyMemberDef meth_members[] = {
	{ "convert", T_OBJECT, offsetof(meth_object, convert), 0,
	  attr_convert__doc__ },
	{ NULL }
};

PyDoc_STRVAR(meth_kind__doc__,
"translation kind");

static PyObject *
meth_get_kind(PyObject *_self, void *data)
{
	meth_object *self = (meth_object*)_self;
	return PyInt_FromLong(self->meth.kind);
}

PyDoc_STRVAR(meth_target_as__doc__,
"target address space");

PyDoc_STRVAR(meth_param__doc__,
"metho parameters as a raw bytearray");

static int
meth_set_param(PyObject *_self, PyObject *value, void *data)
{
	meth_object *self = (meth_object*)_self;

	if (check_null_attr(value, "param"))
		return -1;

	if (ByteSequence_AsBuffer(value, &self->meth.param,
				  sizeof(self->meth.param)))
		return -1;

	loc_scatter(self->loc, self->nloc, &self->meth.param);

	return 0;
}

static PyGetSetDef meth_getset[] = {
	{ "kind", meth_get_kind, 0, meth_kind__doc__ },
	{ "target_as", get_addrspace, set_addrspace, meth_target_as__doc__,
	  OFFSETOF_PTR(meth_object, meth.target_as) },
	{ "param", get_object, meth_set_param, meth_param__doc__,
	  OFFSETOF_PTR(meth_object, paramobj) },
	{ NULL }
};

static PyTypeObject meth_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Method",		/* tp_name */
	sizeof (meth_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	0,				/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	meth__doc__,			/* tp_doc */
	meth_traverse,			/* tp_traverse */
	0,				/* tp_clear */
	meth_richcompare,		/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	meth_members,			/* tp_members */
	meth_getset,			/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	meth_new,			/* tp_new */
};

/** Get the libaddrxlat representation of a Method object.
 * @param self  Method object.
 * @returns     Address of the embedded @c libaddrxlat_meth_t,
 *              or @c NULL on error.
 *
 * The returned pointer refers to a @c libaddrxlat_meth_t structure embedded
 * in the Python object, i.e. the pointer is valid only as long as the
 * containing Python object exists.
 *
 * NB: Some fields are updated dynamically, so the returned data may be stale
 * after the Python object is modified.
 */
static addrxlat_meth_t *
meth_AsPointer(PyObject *self)
{
	meth_object *methobj;

	if (!PyObject_TypeCheck(self, &meth_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a Method, not '%.200s'",
			     Py_TYPE(self)->tp_name);
		return NULL;
	}

	methobj = (meth_object*)self;
	loc_gather(methobj->loc, methobj->nloc, &methobj->meth.param);
	return &methobj->meth;
}

static PyObject *
make_meth(PyTypeObject *type, addrxlat_kind_t kind, PyObject *kwargs)
{
	PyObject *args, *result;

	args = Py_BuildValue("(l)", (long)kind);
	if (!args)
		return NULL;
	result = meth_new(type, args, kwargs);
	Py_DECREF(args);

	return result;
}

typedef struct {
	PyObject_HEAD
	PyObject *meth;
} meth_param_object;

static void
meth_param_dealloc(PyObject *_self)
{
	meth_param_object *self = (meth_param_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_DECREF(self->meth);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
meth_param_traverse(PyObject *_self, visitproc visit, void *arg)
{
	meth_param_object *self = (meth_param_object*)_self;
	Py_VISIT(self->meth);
	return 0;
}

static Py_ssize_t
meth_param_len(PyObject *_self)
{
	meth_param_object *self = (meth_param_object*)_self;
	meth_object *param = (meth_object*)self->meth;

	return param->loc[0].len;
}

static void *
meth_param_ptr(meth_object *param, Py_ssize_t index)
{
	param_loc *loc;
	void *ptr = NULL;

	for (loc = param->loc; loc < &param->loc[param->nloc]; ++loc)
		if (loc->ptr &&
		    loc->off <= index && index < loc->off + loc->len)
			ptr = loc->ptr + index - loc->off;
	return ptr;
}

static PyObject *
meth_param_item(PyObject *_self, Py_ssize_t index)
{
	meth_param_object *self = (meth_param_object*)_self;
	unsigned char *ptr = meth_param_ptr((meth_object*)self->meth, index);

	if (!ptr) {
		PyErr_SetString(PyExc_IndexError,
				"param index out of range");
		return NULL;
	}

	return PyInt_FromLong(*ptr);
}

static int
meth_param_ass_item(PyObject *_self, Py_ssize_t index, PyObject *value)
{
	meth_param_object *self = (meth_param_object*)_self;
	unsigned char *ptr;
	long byte;

	if (!value) {
		PyErr_SetString(PyExc_TypeError,
				"param items cannot be deleted");
		return -1;
	}

	ptr = meth_param_ptr((meth_object*)self->meth, index);
	if (!ptr) {
		PyErr_SetString(PyExc_IndexError,
				"param assignment index out of range");
		return -1;
	}

	byte = Number_AsLong(value);
	if (byte < 0 || byte > 0xff) {
		PyErr_SetString(PyExc_OverflowError,
				"param byte value out of range");
		return -1;
	}

	*ptr = byte;
	return 0;
}

static PySequenceMethods meth_param_as_sequence = {
	meth_param_len,		/* sq_length */
	0,			/* sq_concat */
	0,			/* sq_repeat */
	meth_param_item,	/* sq_item */
	0,			/* sq_slice */
	meth_param_ass_item,	/* sq_ass_item */
	0,			/* sq_ass_slice */
	0,			/* sq_contains */
};

static PyTypeObject meth_param_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".meth-param",		/* tp_name */
	sizeof (meth_param_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	meth_param_dealloc,		/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	&meth_param_as_sequence,	/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC,	/* tp_flags */
	0,				/* tp_doc */
	meth_param_traverse,		/* tp_traverse */
};

static PyObject *
make_meth_param(PyObject *meth)
{
	PyTypeObject *type = &meth_param_type;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	if (!result)
		return NULL;

	Py_INCREF(meth);
	((meth_param_object*)result)->meth = meth;
	return result;
}

PyDoc_STRVAR(linearmeth__doc__,
"LinearMethod() -> linear address translation method");

static PyObject *
linearmeth_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	meth_object *self;

	self = (meth_object*) make_meth(type, ADDRXLAT_LINEAR, kwargs);
	if (self)
		self->loc[0].len = sizeof(addrxlat_param_linear_t);

	return (PyObject*)self;
}

PyDoc_STRVAR(linearmeth_kind__doc__,
"translation kind (always ADDRXLAT_LINEAR)");

PyDoc_STRVAR(linearmeth_off__doc__,
"target linear offset from source");

static PyGetSetDef linearmeth_getset[] = {
	{ "kind", meth_get_kind, 0, linearmeth_kind__doc__ },
	{ "off", get_off, set_off, linearmeth_off__doc__,
	  OFFSETOF_PTR(meth_object, meth.param.linear.off) },
	{ NULL }
};

static PyTypeObject linearmeth_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".LinearMethod",	/* tp_name */
	sizeof (meth_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	0,				/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	linearmeth__doc__,		/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	0,				/* tp_members */
	linearmeth_getset,		/* tp_getset */
	&meth_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	linearmeth_new,			/* tp_new */
};

typedef struct {
	meth_HEAD
	addrxlat_param_custom_t origparam;
} custommeth_object;

static addrxlat_status
meth_error_status(custommeth_object *self, addrxlat_step_t *step)
{
	PyObject *ctx;
	addrxlat_status status;

	ctx = ctx_FromPointer(self->convert, step->ctx);
	if (!ctx) {
		PyErr_Clear();
		return addrxlat_ctx_err(step->ctx, ADDRXLAT_ERR_NOMEM,
					"Cannot allocate context");
	}

	status = ctx_error_status((ctx_object*) ctx);
	Py_DECREF(ctx);
	return status;
}

/** Update an @c addrxlat_step_t using another object.
 * @param step   Object to be updated.
 * @param other  Desired new values for @c step.
 */
static void
update_step(addrxlat_step_t *step, const addrxlat_step_t *other)
{
	if (step->ctx != other->ctx) {
		if (step->ctx)
			addrxlat_ctx_decref(step->ctx);
		if (other->ctx)
			addrxlat_ctx_incref(other->ctx);
	}
	if (step->sys != other->sys) {
		if (step->sys)
			addrxlat_sys_decref(step->sys);
		if (other->sys)
			addrxlat_sys_incref(other->sys);
	}
	memcpy(step, other, sizeof(*step));
}

PyDoc_STRVAR(custommeth__doc__,
"CustomMethod() -> custom address translation method");

static addrxlat_status
cb_first_step(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_meth_t *meth = step->meth;
	custommeth_object *self = meth->param.custom.data;
	PyObject *func;
	PyObject *stepobj;
	PyObject *result;

	func = PyObject_GetAttrString((PyObject*)self, "cb_first_step");
	if (!func)
		return addrxlat_ctx_err(step->ctx, ADDRXLAT_ERR_NOTIMPL,
					"NULL callback");

	stepobj = step_FromPointer(self->convert, step);
	if (!stepobj) {
		Py_DECREF(func);
		return meth_error_status(self, step);
	}

	result = PyObject_CallFunction(func, "OK",
				       stepobj, (unsigned PY_LONG_LONG) addr);
	if (result)
		update_step(step, step_AsPointer(stepobj));
	Py_DECREF(stepobj);
	Py_DECREF(func);
	if (!result)
		return meth_error_status(self, step);

	Py_DECREF(result);
	return ADDRXLAT_OK;
}

static addrxlat_status
cb_next_step(addrxlat_step_t *step)
{
	const addrxlat_meth_t *meth = step->meth;
	custommeth_object *self = meth->param.custom.data;
	PyObject *func;
	PyObject *stepobj;
	PyObject *result;

	func = PyObject_GetAttrString((PyObject*)self, "cb_next_step");
	if (!func)
		return addrxlat_ctx_err(step->ctx, ADDRXLAT_ERR_NOTIMPL,
					"NULL callback");

	stepobj = step_FromPointer(self->convert, step);
	if (!stepobj) {
		Py_DECREF(func);
		return meth_error_status(self, step);
	}

	result = PyObject_CallFunction(func, "O", stepobj);
	if (result)
		update_step(step, step_AsPointer(stepobj));
	Py_DECREF(stepobj);
	Py_DECREF(func);
	if (!result)
		return meth_error_status(self, step);

	Py_DECREF(result);
	return ADDRXLAT_OK;
}

static PyObject *
custommeth_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	custommeth_object *self;

	self = (custommeth_object*) make_meth(type, ADDRXLAT_CUSTOM, kwargs);
	if (self) {
		self->loc[0].len = sizeof(addrxlat_param_custom_t);

		self->meth.param.custom.first_step = cb_first_step;
		self->meth.param.custom.next_step = cb_next_step;
		self->meth.param.custom.data = self;
	}

	return (PyObject*)self;
}

static int
custommeth_Init(PyObject *_self, const addrxlat_meth_t *meth)
{
	custommeth_object *self = (custommeth_object*)_self;

	if (meth_Init(_self, meth))
		return -1;

	self->origparam = meth->param.custom;
	self->meth.param.custom.first_step = cb_first_step;
	self->meth.param.custom.next_step = cb_next_step;
	self->meth.param.custom.data = self;

	return 0;
}

PyDoc_STRVAR(custommeth_first_step__doc__,
"METH.cb_first_step(step, addr)\n\
\n\
Callback to perform the initial translation step.");

static PyObject *
custommeth_first_step(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"step", "addr", NULL};

	custommeth_object *self = (custommeth_object*)_self;
	PyObject *stepobj;
	addrxlat_step_t *step;
	const addrxlat_meth_t *origmeth;
	addrxlat_meth_t tmpmeth;
	PyObject *addrobj;
	addrxlat_addr_t addr;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OO:first_step",
					 keywords, &stepobj, &addrobj))
		return NULL;
	step = step_AsPointer(stepobj);
	if (!step)
		return NULL;
	addr = Number_AsUnsignedLongLong(addrobj);
	if (PyErr_Occurred())
		return NULL;

	if (!self->origparam.first_step)
		return raise_notimpl("NULL callback");

	origmeth = step->meth;
	tmpmeth.kind = step->meth->kind;
	tmpmeth.target_as = step->meth->target_as;
	tmpmeth.param.custom = self->origparam;
	step->meth = &tmpmeth;
	status = self->origparam.first_step(step, addr);
	self->origparam = step->meth->param.custom;
	step->meth = origmeth;
	if (status != ADDRXLAT_OK)
		return raise_exception(step->ctx, status);

	if (step_Init(stepobj, step))
		return NULL;

	Py_RETURN_NONE;
}

PyDoc_STRVAR(custommeth_next_step__doc__,
"METH.cb_next_step(step)\n\
\n\
Callback to perform further translation steps.");

static PyObject *
custommeth_next_step(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"step", NULL};

	custommeth_object *self = (custommeth_object*)_self;
	PyObject *stepobj;
	addrxlat_step_t *step;
	const addrxlat_meth_t *origmeth;
	addrxlat_meth_t tmpmeth;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:next_step",
					 keywords, &stepobj))
		return NULL;
	step = step_AsPointer(stepobj);
	if (!step)
		return NULL;

	if (!self->origparam.next_step)
		return raise_notimpl("NULL callback");

	origmeth = step->meth;
	tmpmeth.kind = step->meth->kind;
	tmpmeth.target_as = step->meth->target_as;
	tmpmeth.param.custom = self->origparam;
	step->meth = &tmpmeth;
	status = self->origparam.next_step(step);
	self->origparam = step->meth->param.custom;
	step->meth = origmeth;
	if (status != ADDRXLAT_OK)
		return raise_exception(step->ctx, status);

	if (step_Init(stepobj, step))
		return NULL;

	Py_RETURN_NONE;
}

static PyMethodDef custommeth_methods[] = {
	{ "cb_first_step", (PyCFunction)custommeth_first_step,
	  METH_VARARGS | METH_KEYWORDS,
	  custommeth_first_step__doc__ },
	{ "cb_next_step", (PyCFunction)custommeth_next_step,
	  METH_VARARGS | METH_KEYWORDS,
	  custommeth_next_step__doc__ },

	{ NULL }
};

PyDoc_STRVAR(custommeth_kind__doc__,
"translation kind (always ADDRXLAT_CUSTOM)");

static PyGetSetDef custommeth_getset[] = {
	{ "kind", meth_get_kind, 0, custommeth_kind__doc__ },
	{ NULL }
};

static PyTypeObject custommeth_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".CustomMethod",	/* tp_name */
	sizeof (custommeth_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	0,				/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	custommeth__doc__,		/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	custommeth_methods,		/* tp_methods */
	0,				/* tp_members */
	custommeth_getset,		/* tp_getset */
	&meth_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	custommeth_new,			/* tp_new */
};

typedef struct {
	meth_HEAD
	PyObject *root;
} pgtmeth_object;

PyDoc_STRVAR(pgtmeth__doc__,
"PageTableMethod() -> page table address translation method");

static PyObject *
pgtmeth_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	pgtmeth_object *self;

	self = (pgtmeth_object*) make_meth(type, ADDRXLAT_PGT, kwargs);
	if (self) {
		param_loc *loc;

		self->loc[0].len = sizeof(addrxlat_param_pgt_t);

		Py_INCREF(Py_None);
		self->root = Py_None;
		self->meth.param.pgt.root = *fulladdr_AsPointer(self->root);
		loc = &self->loc[METH_NLOC];
		loc->ptr = NULL;
		loc->off = offsetof(addrxlat_param_t, pgt.root);
		loc->len = sizeof(addrxlat_fulladdr_t);
		self->nloc = METH_NLOC + 1;
	}

	return (PyObject*)self;
}

static int
pgtmeth_Init(PyObject *_self, const addrxlat_meth_t *meth)
{
	pgtmeth_object *self = (pgtmeth_object*)_self;
	PyObject *addr, *oldaddr;

	if (meth_Init(_self, meth))
		return -1;

	addr = fulladdr_FromPointer(self->convert, &meth->param.pgt.root);
	if (!addr)
		return -1;

	oldaddr = self->root;
	self->root = addr;
	self->loc[METH_NLOC].ptr = fulladdr_AsPointer(addr);
	Py_DECREF(oldaddr);
	return 0;
}

static void
pgtmeth_dealloc(PyObject *_self)
{
	pgtmeth_object *self = (pgtmeth_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->root);
	meth_dealloc(_self);
}

static int
pgtmeth_traverse(PyObject *_self, visitproc visit, void *arg)
{
	pgtmeth_object *self = (pgtmeth_object*)_self;
	Py_VISIT(self->root);
	return meth_traverse(_self, visit, arg);
}

PyDoc_STRVAR(pgtmeth_kind__doc__,
"translation kind (always ADDRXLAT_PGT)");

PyDoc_STRVAR(pgtmeth_pte_format__doc__,
"format of a page tabe entry (ADDRXLAT_PTE_xxx)");

static PyObject *
pgtmeth_get_pte_format(PyObject *_self, void *data)
{
	meth_object *self = (meth_object*)_self;
	return PyInt_FromLong(self->meth.param.pgt.pf.pte_format);
}

static int
pgtmeth_set_pte_format(PyObject *_self, PyObject *value, void *data)
{
	meth_object *self = (meth_object*)_self;
	long pte_format;

	if (check_null_attr(value, "pte_format"))
		return -1;

	pte_format = Number_AsLong(value);
	if (PyErr_Occurred())
		return -1;

	self->meth.param.pgt.pf.pte_format = pte_format;
	return 0;
}

PyDoc_STRVAR(pgtmeth_fields__doc__,
"size of address fields in bits");

static PyObject *
pgtmeth_get_fields(PyObject *_self, void *data)
{
	meth_object *self = (meth_object*)_self;
	const addrxlat_paging_form_t *pf = &self->meth.param.pgt.pf;
	PyObject *result;
	unsigned i;

	result = PyTuple_New(pf->nfields);
	if (!result)
		return NULL;

	for (i = 0; i < pf->nfields; ++i) {
		PyObject *obj = PyInt_FromLong(pf->fieldsz[i]);
		if (!obj) {
			Py_DECREF(result);
			return NULL;
		}
		PyTuple_SET_ITEM(result, i, obj);
	}

	return result;
}

static int
pgtmeth_set_fields(PyObject *_self, PyObject *value, void *data)
{
	meth_object *self = (meth_object*)_self;
	addrxlat_paging_form_t pf;
	Py_ssize_t n;
	unsigned i;

	if (check_null_attr(value, "fields"))
		return -1;

	if (!PySequence_Check(value)) {
		PyErr_Format(PyExc_TypeError,
			     "'%.200s' object is not a sequence",
			     Py_TYPE(value)->tp_name);
		return -1;
	}

	n = PySequence_Length(value);
	if (n > ADDRXLAT_FIELDS_MAX) {
		PyErr_Format(PyExc_ValueError,
			     "cannot have more than %d address fields",
			     ADDRXLAT_FIELDS_MAX);
		return -1;
	}

	for (i = 0; i < n; ++i) {
		long bits = 0;
		PyObject *obj = PySequence_GetItem(value, i);

		if (obj) {
			bits = Number_AsLong(obj);
			Py_DECREF(obj);
		}
		if (PyErr_Occurred())
			return -1;
		if (bits < 0 || bits > sizeof(addrxlat_addr_t) * 8) {
			PyErr_Format(PyExc_OverflowError,
				     "address field %u out of range", i);
			return -1;
		}
		pf.fieldsz[i] = bits;
	}

	self->meth.param.pgt.pf.nfields = i;
	memcpy(self->meth.param.pgt.pf.fieldsz, pf.fieldsz,
	       i * sizeof(pf.fieldsz[0]));
	while (i < ADDRXLAT_FIELDS_MAX)
		self->meth.param.pgt.pf.fieldsz[i++] = 0;

	return 0;
}

PyDoc_STRVAR(pgtmeth_root__doc__,
"root page table address");

static fulladdr_loc pgtmeth_root_loc = {
	offsetof(pgtmeth_object, root),
	offsetof(pgtmeth_object, loc[METH_NLOC]),
	"root"
};

PyDoc_STRVAR(pgtmeth_pte_mask__doc__,
"page table entry mask");

static PyGetSetDef pgtmeth_getset[] = {
	{ "kind", meth_get_kind, 0, pgtmeth_kind__doc__ },
	{ "root", get_fulladdr, set_fulladdr, pgtmeth_root__doc__,
	  &pgtmeth_root_loc },
	{ "pte_mask", get_pte, set_pte, pgtmeth_pte_mask__doc__,
	  OFFSETOF_PTR(meth_object, meth.param.pgt.pte_mask) },
	{ "pte_format", pgtmeth_get_pte_format, pgtmeth_set_pte_format,
	  pgtmeth_pte_format__doc__ },
	{ "fields", pgtmeth_get_fields, pgtmeth_set_fields,
	  pgtmeth_fields__doc__ },
	{ NULL }
};

static PyTypeObject pgtmeth_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".PageTableMethod", /* tp_name */
	sizeof (pgtmeth_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	pgtmeth_dealloc,		/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	pgtmeth__doc__,			/* tp_doc */
	pgtmeth_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	0,				/* tp_members */
	pgtmeth_getset,			/* tp_getset */
	&meth_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	pgtmeth_new,			/* tp_new */
};

static PyObject *
lookupmeth_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	meth_object *self;

	self = (meth_object*) make_meth(type, ADDRXLAT_LOOKUP, kwargs);
	if (self) {
		self->loc[0].len = sizeof(addrxlat_param_lookup_t);
	}

	return (PyObject*)self;
}

static void
lookupmeth_dealloc(PyObject *_self)
{
	meth_object *self = (meth_object*)_self;
	if (self->meth.param.lookup.tbl) {
		free(self->meth.param.lookup.tbl);
		self->meth.param.lookup.tbl = NULL;
	}
	meth_dealloc(_self);
}

PyDoc_STRVAR(lookupmeth__doc__,
"LookupMethod() -> table lookup address translation method");

PyDoc_STRVAR(lookupmeth_kind__doc__,
"translation kind (always ADDRXLAT_LOOKUP)");

PyDoc_STRVAR(lookupmeth_endoff__doc__,
"max address offset inside each object");

PyDoc_STRVAR(lookupmeth_tbl__doc__,
"lookup table");

static PyObject *
lookupmeth_get_tbl(PyObject *_self, void *data)
{
	meth_object *self = (meth_object*)_self;
	const addrxlat_lookup_elem_t *elem;
	PyObject *result;
	size_t i;

	result = PyTuple_New(self->meth.param.lookup.nelem);
	if (!result)
		return NULL;

	for (i = 0, elem = self->meth.param.lookup.tbl;
	     i < self->meth.param.lookup.nelem;
	     ++i, ++elem) {
		PyObject *tuple;

		tuple = Py_BuildValue("(KK)",
				      (unsigned PY_LONG_LONG)elem->orig,
				      (unsigned PY_LONG_LONG)elem->dest);
		if (!tuple) {
			Py_DECREF(result);
			return NULL;
		}
		PyTuple_SET_ITEM(result, i, tuple);
	}

	return result;
}

static int
lookupmeth_set_tbl(PyObject *_self, PyObject *value, void *data)
{
	meth_object *self = (meth_object*)_self;
	PyObject *pair, *obj;
	addrxlat_lookup_elem_t *tbl, *elem;
	size_t i, n;

	if (!PySequence_Check(value)) {
		PyErr_Format(PyExc_TypeError,
			     "'%.200s' object is not a sequence",
			     Py_TYPE(value)->tp_name);
		return -1;
	}

	n = PySequence_Length(value);
	if (!n) {
		tbl = NULL;
		goto out;
	}

	tbl = malloc(n * sizeof(addrxlat_lookup_elem_t));
	if (!tbl) {
		PyErr_NoMemory();
		return -1;
	}

	for (elem = tbl, i = 0; i < n; ++i, ++elem) {
		pair = PySequence_GetItem(value, i);
		if (!pair)
			goto err_tbl;
		if (!PySequence_Check(pair)) {
			PyErr_Format(PyExc_TypeError,
				     "'%.200s' object is not a sequence",
				     Py_TYPE(pair)->tp_name);
			goto err_pair;
		}
		if (PySequence_Length(pair) != 2) {
			PyErr_SetString(PyExc_ValueError,
					"Table elements must be integer pairs");
			goto err_pair;
		}

		obj = PySequence_GetItem(pair, 0);
		if (obj) {
			elem->orig = Number_AsUnsignedLongLong(obj);
			Py_DECREF(obj);
		}
		if (PyErr_Occurred())
			goto err_pair;

		obj = PySequence_GetItem(pair, 1);
		if (obj) {
			elem->dest = Number_AsUnsignedLongLong(obj);
			Py_DECREF(obj);
		}
		if (PyErr_Occurred())
			goto err_pair;

		Py_DECREF(pair);
	}

 out:
	self->meth.param.lookup.nelem = n;
	if (self->meth.param.lookup.tbl)
		free(self->meth.param.lookup.tbl);
	self->meth.param.lookup.tbl = tbl;
	return 0;

 err_pair:
	Py_DECREF(pair);
 err_tbl:
	free(tbl);
	return -1;
}

static PyGetSetDef lookupmeth_getset[] = {
	{ "kind", meth_get_kind, 0, lookupmeth_kind__doc__ },
	{ "endoff", get_addr, set_addr, lookupmeth_endoff__doc__,
	  OFFSETOF_PTR(meth_object, meth.param.lookup.endoff) },
	{ "tbl", lookupmeth_get_tbl, lookupmeth_set_tbl,
	  lookupmeth_tbl__doc__ },
	{ NULL }
};

static PyTypeObject lookupmeth_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".LookupMethod",	/* tp_name */
	sizeof (meth_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	lookupmeth_dealloc,		/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	lookupmeth__doc__,		/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	0,				/* tp_members */
	lookupmeth_getset,		/* tp_getset */
	&meth_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	lookupmeth_new,			/* tp_new */
};

typedef struct {
	meth_HEAD
	PyObject *base;
} memarrmeth_object;

PyDoc_STRVAR(memarrmeth__doc__,
"MemoryArrayMethod() -> memory array address translation method");

static PyObject *
memarrmeth_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	memarrmeth_object *self;

	self = (memarrmeth_object*) make_meth(type, ADDRXLAT_MEMARR, kwargs);
	if (self) {
		param_loc *loc;

		self->loc[0].len = sizeof(addrxlat_param_memarr_t);

		Py_INCREF(Py_None);
		self->base = Py_None;
		self->meth.param.memarr.base = *fulladdr_AsPointer(self->base);
		loc = &self->loc[METH_NLOC];
		loc->ptr = NULL;
		loc->off = offsetof(addrxlat_param_t, memarr.base);
		loc->len = sizeof(addrxlat_fulladdr_t);
		self->nloc = METH_NLOC + 1;
	}

	return (PyObject*)self;
}

static int
memarrmeth_Init(PyObject *_self, const addrxlat_meth_t *meth)
{
	memarrmeth_object *self = (memarrmeth_object*)_self;
	PyObject *addr, *oldaddr;

	if (meth_Init(_self, meth))
		return -1;

	addr = fulladdr_FromPointer(self->convert, &meth->param.memarr.base);
	if (!addr)
		return -1;

	oldaddr = self->base;
	self->base = addr;
	self->loc[METH_NLOC].ptr = fulladdr_AsPointer(addr);
	Py_DECREF(oldaddr);
	return 0;
}

static void
memarrmeth_dealloc(PyObject *_self)
{
	memarrmeth_object *self = (memarrmeth_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->base);
	meth_dealloc(_self);
}

static int
memarrmeth_traverse(PyObject *_self, visitproc visit, void *arg)
{
	memarrmeth_object *self = (memarrmeth_object*)_self;
	Py_VISIT(self->base);
	return meth_traverse(_self, visit, arg);
}

PyDoc_STRVAR(memarrmeth_kind__doc__,
"translation kind (always ADDRXLAT_MEMARR)");

PyDoc_STRVAR(memarrmeth_shift__doc__,
"address bit shift");

PyDoc_STRVAR(memarrmeth_elemsz__doc__,
"size of each array element");

PyDoc_STRVAR(memarrmeth_valsz__doc__,
"size of the value");

static PyMemberDef memarrmeth_members[] = {
	{ "shift", T_UINT, offsetof(meth_object, meth.param.memarr.shift),
	  0, memarrmeth_shift__doc__ },
	{ "elemsz", T_UINT, offsetof(meth_object, meth.param.memarr.elemsz),
	  0, memarrmeth_elemsz__doc__ },
	{ "valsz", T_UINT, offsetof(meth_object, meth.param.memarr.valsz),
	  0, memarrmeth_valsz__doc__ },
	{ NULL }
};

PyDoc_STRVAR(memarrmeth_base__doc__,
"base address of the translation array");

static fulladdr_loc memarrmeth_base_loc = {
	offsetof(memarrmeth_object, base),
	offsetof(memarrmeth_object, loc[METH_NLOC]),
	"base"
};

static PyGetSetDef memarrmeth_getset[] = {
	{ "kind", meth_get_kind, 0, memarrmeth_kind__doc__ },
	{ "base", get_fulladdr, set_fulladdr,
	  memarrmeth_base__doc__, &memarrmeth_base_loc },
	{ NULL }
};

static PyTypeObject memarrmeth_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".MemoryArrayMethod", /* tp_name */
	sizeof (memarrmeth_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	memarrmeth_dealloc,		/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	memarrmeth__doc__,		/* tp_doc */
	memarrmeth_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	memarrmeth_members,		/* tp_members */
	memarrmeth_getset,		/* tp_getset */
	&meth_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	memarrmeth_new,			/* tp_new */
};

/** Construct a Method object from an @c addrxlat_meth_t pointer.
 * @param _conv  TypeConvert object.
 * @param meth   New value as a C object, or @c NULL.
 * @returns      Corresponding Python object (or @c NULL on failure).
 *
 * This function makes a new copy of the method.
 */
static PyObject *
meth_FromPointer(PyObject *_conv, const addrxlat_meth_t *meth)
{
	convert_object *conv = (convert_object *)_conv;
	PyTypeObject *type;
	PyObject *args;
	int (*init)(PyObject *, const addrxlat_meth_t *);
	PyObject *result;

	if (!meth)
		Py_RETURN_NONE;

	init = meth_Init;
	switch (meth->kind) {
	case ADDRXLAT_CUSTOM:
		type = conv->custommeth_type;
		init = custommeth_Init;
		break;

	case ADDRXLAT_LINEAR:
		type = conv->linearmeth_type;
		break;

	case ADDRXLAT_PGT:
		type = conv->pgtmeth_type;
		init = pgtmeth_Init;
		break;

	case ADDRXLAT_LOOKUP:
		type = conv->lookupmeth_type;
		break;

	case ADDRXLAT_MEMARR:
		type = conv->memarrmeth_type;
		init = memarrmeth_Init;
		break;

	default:
		type = conv->meth_type;
		break;
	}

	args = (type == conv->meth_type
		? Py_BuildValue("(k)", meth->kind)
		: PyTuple_New(0));
	if (!args)
		return NULL;
	result = PyObject_Call((PyObject*)type, args, NULL);
	Py_DECREF(args);
	if (!result)
		return NULL;

	if (init(result, meth))
		goto err;

	return result;

 err:
	Py_DECREF(result);
	return NULL;
}

/** Python representation of @ref addrxlat_range_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Range in libaddrxlat format. */
	addrxlat_range_t range;
} range_object;

PyDoc_STRVAR(range__doc__,
"Range() -> range\n\
\n\
Construct an empty address range.");

/** Construct a range object from an @c addrxlat_range_t pointer.
 * @param _conv  TypeConvert object.
 * @param range  New value as a C object.
 * @returns      Corresponding Python object (or @c NULL on failure).
 *
 * This function makes a new copy of the range.
 */
static PyObject *
range_FromPointer(PyObject *_conv, const addrxlat_range_t *range)
{
	convert_object *conv = (convert_object *)_conv;
	PyTypeObject *type = conv->range_type;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	if (!result)
		return NULL;

	((range_object*)result)->range = *range;
	return result;
}

PyDoc_STRVAR(range_meth__doc__,
"translation method for this range");

/** Getter for the meth attribute.
 * @param self  Range object
 * @param data  ignored
 * @returns     PyLong object (or @c NULL on failure)
 */
static PyObject *
range_get_meth(PyObject *_self, void *data)
{
	range_object *self = (range_object*)_self;
	return PyInt_FromLong(self->range.meth);
}

/** Setter for the meth attribute.
 * @param self   Range object
 * @param value  new value (see @c SYS_METH_xxx)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
range_set_meth(PyObject *_self, PyObject *value, void *data)
{
	range_object *self = (range_object*)_self;
	addrxlat_sys_meth_t meth;

	if (check_null_attr(value, "meth"))
		return -1;

	meth = Number_AsLong(value);
	if (PyErr_Occurred())
		return -1;

	self->range.meth = meth;
	return 0;
}

PyDoc_STRVAR(range_endoff__doc__,
"maximum offset contained in the range");

static PyGetSetDef range_getset[] = {
	{ "endoff", get_addr, set_addr, range_endoff__doc__,
	  OFFSETOF_PTR(range_object, range.endoff) },
	{ "meth", range_get_meth, range_set_meth, range_meth__doc__ },
	{ NULL }
};

static PyTypeObject range_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Range",		/* tp_name */
	sizeof (range_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	0,				/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	range__doc__,			/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	0,				/* tp_members */
	range_getset,			/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	0,				/* tp_new */
};

/** Get the libaddrxlat representation of a Python range object.
 * @param self  Range object.
 * @returns     Address of the embedded @c libaddrxlat_range_t,
 *              or @c NULL on error.
 *
 * The returned pointer refers to a @c libaddrxlat_range_t
 * structure embedded in the Python object, i.e. the pointer is
 * valid only as long as the containing Python object exists.
 */
static addrxlat_range_t *
range_AsPointer(PyObject *self)
{
	if (!PyObject_TypeCheck(self, &range_type)) {
		PyErr_Format(PyExc_TypeError, "need a Range, not '%.200s'",
			     Py_TYPE(self)->tp_name);
		return NULL;
	}

	return &((range_object*)self)->range;
}

typedef struct {
	PyObject_HEAD

	addrxlat_map_t *map;

	PyObject *convert;
} map_object;

PyDoc_STRVAR(map__doc__,
"Map() -> address translation map");

static PyObject *
map_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	map_object *self;

	self = (map_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->map = get_c_pointer(kwargs);
	if (!self->map) {
		if (PyErr_Occurred())
			return NULL;

		self->map = addrxlat_map_new();
		if (!self->map) {
			Py_DECREF(self);
			return PyErr_NoMemory();
		}
	} else
		addrxlat_map_incref(self->map);

	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;
}

static int
map_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return c_pointer_super_init(&map_type, self, args, kwargs);
}

/** Construct a map object from an @c addrxlat_map_t pointer.
 * @param _conv  TypeConvert object.
 * @param map    New value as a C object, or @c NULL.
 * @returns      corresponding Python object (or @c NULL on failure).
 *
 * The Python object contains a new reference to the translation map.
 */
static PyObject *
map_FromPointer(PyObject *_conv, addrxlat_map_t *map)
{
	convert_object *conv = (convert_object *)_conv;

	if (!map)
		Py_RETURN_NONE;

	return object_FromPointer(conv->map_type, map);
}

static void
map_dealloc(PyObject *_self)
{
	map_object *self = (map_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);

	if (self->map) {
		addrxlat_map_decref(self->map);
		self->map = NULL;
	}

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
map_traverse(PyObject *_self, visitproc visit, void *arg)
{
	map_object *self = (map_object*)_self;
	Py_VISIT(self->convert);
	return 0;
}

static PyObject *
map_richcompare(PyObject *v, PyObject *w, int op)
{
	PyObject *result;

	if ((op == Py_EQ || op == Py_NE) &&
	    PyObject_TypeCheck(v, &map_type) &&
	    PyObject_TypeCheck(w, &map_type)) {
		int cmp = (((map_object*)v)->map == ((map_object*)w)->map);
		result = (cmp == (op == Py_EQ))
			? Py_True
			: Py_False;
	} else
		result = Py_NotImplemented;

	Py_INCREF(result);
	return result;
}

static Py_ssize_t
map_len(PyObject *_self)
{
	map_object *self = (map_object*)_self;
	return self->map
		? addrxlat_map_len(self->map)
		: 0;
}

static PyObject *
map_item(PyObject *_self, Py_ssize_t index)
{
	map_object *self = (map_object*)_self;
	const addrxlat_range_t *ranges;
	Py_ssize_t n;

	n = map_len((PyObject*)self);
	if (index < 0)
		index = n - index;
	if (index >= n) {
		PyErr_SetString(PyExc_IndexError, "map index out of range");
		return NULL;
	}

	ranges = addrxlat_map_ranges(self->map);
	return range_FromPointer(self->convert, &ranges[index]);
}

static PySequenceMethods map_as_sequence = {
	map_len,		/* sq_length */
	0,			/* sq_concat */
	0,			/* sq_repeat */
	map_item,		/* sq_item */
	0,			/* sq_slice */
	0,			/* sq_ass_item */
	0,			/* sq_ass_slice */
	0,			/* sq_contains */
};

PyDoc_STRVAR(map_set__doc__,
"MAP.set(addr, range) -> status\n\
\n\
Modify map so that addresses between addr and addr+range.off\n\
(inclusive) are mapped using range.meth.");

static PyObject *
map_set(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	map_object *self = (map_object*)_self;
	static char *keywords[] = {"addr", "range", NULL};
	unsigned long long addr;
	PyObject *rangeobj;
	addrxlat_range_t *range;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "KO:set",
					 keywords, &addr, &rangeobj))
		return NULL;

	range = range_AsPointer(rangeobj);
	if (!range)
		return NULL;

	status = addrxlat_map_set(self->map, addr, range);
	return PyInt_FromLong(status);
}

PyDoc_STRVAR(map_search__doc__,
"MAP.search(addr) -> meth\n\
\n\
Find the translation method for the given address.");

static PyObject *
map_search(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	map_object *self = (map_object*)_self;
	static char *keywords[] = {"addr", NULL};
	unsigned long long addr;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "K:search",
					 keywords, &addr))
		return NULL;

	return PyInt_FromLong(addrxlat_map_search(self->map, addr));
}

PyDoc_STRVAR(map_copy__doc__,
"M.copy() -> map\n\
\n\
Return a shallow copy of a translation map.");

static PyObject *
map_copy(PyObject *_self, PyObject *args)
{
	map_object *self = (map_object*)_self;
	addrxlat_map_t *map;
	PyObject *result;

	map = addrxlat_map_copy(self->map);
	if (!map)
		return PyErr_NoMemory();

	result = map_FromPointer(self->convert, map);
	addrxlat_map_decref(map);
	return result;
}

static PyMethodDef map_methods[] = {
	{ "set", (PyCFunction)map_set, METH_VARARGS | METH_KEYWORDS,
	  map_set__doc__ },
	{ "search", (PyCFunction)map_search, METH_VARARGS | METH_KEYWORDS,
	  map_search__doc__ },
	{ "copy", map_copy, METH_NOARGS,
	  map_copy__doc__ },
	{ NULL }
};

static PyMemberDef map_members[] = {
	{ "convert", T_OBJECT, offsetof(map_object, convert), 0,
	  attr_convert__doc__ },
	{ NULL }
};

static PyTypeObject map_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Map",		/* tp_name */
	sizeof (map_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	map_dealloc,			/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	&map_as_sequence,		/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	map__doc__,			/* tp_doc */
	map_traverse,			/* tp_traverse */
	0,				/* tp_clear */
	map_richcompare,		/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	map_methods,			/* tp_methods */
	map_members,			/* tp_members */
	0,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	map_init,			/* tp_init */
	0,				/* tp_alloc */
	map_new,			/* tp_new */
};

/** Get the libaddrxlat representation of a Python map object.
 * @param self  Map object.
 * @returns     Associated @c libaddrxlat_map_t,
 *              @c NULL if @c self is None or on failure.
 *
 * This function does not increment the reference count of the returned
 * C object. It is assumed that the caller holds a reference to the Python
 * object, which in turn holds a reference to the C object.
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static addrxlat_map_t *
map_AsPointer(PyObject *self)
{
	if (self == Py_None)
		return NULL;

	if (!PyObject_TypeCheck(self, &map_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a Map or None, not '%.200s'",
			     Py_TYPE(self)->tp_name);
		return NULL;
	}

	return ((map_object*)self)->map;
}

typedef struct {
	PyObject_HEAD

	addrxlat_sys_t *sys;

	PyObject *convert;
} sys_object;

PyDoc_STRVAR(sys__doc__,
"System() -> address translation system");

static PyObject *
sys_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	sys_object *self;

	self = (sys_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->sys = get_c_pointer(kwargs);
	if (!self->sys) {
		if (PyErr_Occurred())
			return NULL;

		self->sys = addrxlat_sys_new();
		if (!self->sys) {
			Py_DECREF(self);
			return PyErr_NoMemory();
		}
	} else
		addrxlat_sys_incref(self->sys);

	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;
}

static int
sys_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return c_pointer_super_init(&sys_type, self, args, kwargs);
}

/** Construct a sys object from an @c addrxlat_sys_t pointer.
 * @param _conv  TypeConvert object.
 * @param sys    New value as a C object, or @c NULL.
 * @returns      Corresponding Python object (or @c NULL on failure).
 *
 * The Python object contains a new reference to the translation system.
 */
static PyObject *
sys_FromPointer(PyObject *_conv, addrxlat_sys_t *sys)
{
	convert_object *conv = (convert_object *)_conv;

	if (!sys)
		Py_RETURN_NONE;

	return object_FromPointer(conv->sys_type, sys);
}

static void
sys_dealloc(PyObject *_self)
{
	sys_object *self = (sys_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);

	if (self->sys) {
		addrxlat_sys_decref(self->sys);
		self->sys = NULL;
	}

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
sys_traverse(PyObject *_self, visitproc visit, void *arg)
{
	sys_object *self = (sys_object*)_self;
	Py_VISIT(self->convert);
	return 0;
}

static PyObject *
sys_richcompare(PyObject *v, PyObject *w, int op)
{
	PyObject *result;

	if ((op == Py_EQ || op == Py_NE) &&
	    PyObject_TypeCheck(v, &sys_type) &&
	    PyObject_TypeCheck(w, &sys_type)) {
		int cmp = (((sys_object*)v)->sys == ((sys_object*)w)->sys);
		result = (cmp == (op == Py_EQ))
			? Py_True
			: Py_False;
	} else
		result = Py_NotImplemented;

	Py_INCREF(result);
	return result;
}

PyDoc_STRVAR(sys_os_init__doc__,
"SYS.os_init(ctx, arch=None, os_type=None, version_code=None, phys_bits=None, virt_bits=None, page_shift=None, phys_base=None, rootpgt=None, xen_p2m_mfn=None, xen_xlat=None) -> status\n\
\n\
Set up a translation system for a pre-defined operating system.");

static PyObject *
sys_os_init(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	sys_object *self = (sys_object*)_self;
	static char *keywords[] = {
		"ctx",
		"arch",
		"os_type",
		"version_code",
		"phys_bits",
		"virt_bits",
		"page_shift",
		"phys_base",
		"rootpgt",
		"xen_p2m_mfn",
		"xen_xlat",
		NULL
	};
	PyObject *ctxobj;
	PyObject *arch, *type, *ver, *page_shift, *phys_base,
		*rootpgt, *xen_p2m_mfn, *xen_xlat, *phys_bits, *virt_bits;
	addrxlat_ctx_t *ctx;
	addrxlat_opt_t opts[ADDRXLAT_OPT_NUM], *p;
	addrxlat_status status;

	arch = type = ver = page_shift = phys_base = rootpgt =
		xen_p2m_mfn = xen_xlat = phys_bits = virt_bits = Py_None;
	if (!PyArg_ParseTupleAndKeywords(
		    args, kwargs, "O|OOOOOOOOOO:os_init", keywords,
		    &ctxobj, &arch, &type, &ver, &phys_bits, &virt_bits,
		    &page_shift, &phys_base, &rootpgt, &xen_p2m_mfn,
		    &xen_xlat))
		return NULL;

	ctx = ctx_AsPointer(ctxobj);
	if (!ctx)
		return NULL;

	p = opts;

	if (arch != Py_None) {
		const char *str = Text_AsUTF8(arch);
		if (!str)
			return NULL;
		addrxlat_opt_arch(p, str);
		++p;
	}
	if (type != Py_None) {
		const char *str = Text_AsUTF8(type);
		if (!str)
			return NULL;
		addrxlat_opt_os_type(p, str);
		++p;
	}
	if (ver != Py_None) {
		addrxlat_opt_version_code(
			p, Number_AsUnsignedLongLong(ver));
		if (PyErr_Occurred())
			return NULL;
		++p;
	}
	if (phys_bits != Py_None) {
		addrxlat_opt_phys_bits(
			p, Number_AsUnsignedLongLong(phys_bits));
		if (PyErr_Occurred())
			return NULL;
		++p;
	}
	if (virt_bits != Py_None) {
		addrxlat_opt_virt_bits(
			p, Number_AsUnsignedLongLong(virt_bits));
		if (PyErr_Occurred())
			return NULL;
		++p;
	}
	if (page_shift != Py_None) {
		addrxlat_opt_page_shift(
			p, Number_AsUnsignedLongLong(page_shift));
		if (PyErr_Occurred())
			return NULL;
		++p;
	}
	if (phys_base != Py_None) {
		addrxlat_opt_phys_base(
			p, Number_AsUnsignedLongLong(phys_base));
		if (PyErr_Occurred())
			return NULL;
		++p;
	}
	if (rootpgt != Py_None) {
		addrxlat_fulladdr_t *faddr = fulladdr_AsPointer(rootpgt);
		if (!faddr)
			return NULL;
		addrxlat_opt_rootpgt(p, faddr);
		++p;
	}
	if (xen_p2m_mfn != Py_None) {
		addrxlat_opt_xen_p2m_mfn(
			p, Number_AsUnsignedLongLong(xen_p2m_mfn));
		if (PyErr_Occurred())
			return NULL;
		++p;
	}
	if (xen_xlat != Py_None && Number_AsLong(xen_xlat)) {
		addrxlat_opt_xen_xlat(p, 1);
		++p;
	}

	status = addrxlat_sys_os_init(self->sys, ctx, p - opts, opts);
	return ctx_status_result(ctxobj, status);
}

PyDoc_STRVAR(sys_set_map__doc__,
"SYS.set_map(idx, map)\n\
\n\
Explicitly set the given translation map of a translation system.\n\
See SYS_MAP_xxx for valid values of idx.");

static PyObject *
sys_set_map(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	sys_object *self = (sys_object*)_self;
	static char *keywords[] = { "idx", "map", NULL };
	unsigned long idx;
	PyObject *mapobj;
	addrxlat_map_t *map;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "kO:set_map",
					 keywords, &idx, &mapobj))
		return NULL;

	if (idx >= ADDRXLAT_SYS_MAP_NUM) {
		PyErr_SetString(PyExc_IndexError,
				"system map index out of range");
		return NULL;
	}

	map = map_AsPointer(mapobj);
	if (PyErr_Occurred())
		return NULL;

	addrxlat_sys_set_map(self->sys, idx, map);
	Py_RETURN_NONE;
}

PyDoc_STRVAR(sys_get_map__doc__,
"SYS.get_map(idx) -> Map or None\n\
\n\
Get the given translation map of a translation system.\n\
See SYS_MAP_xxx for valid values of idx.");

static PyObject *
sys_get_map(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	sys_object *self = (sys_object*)_self;
	static char *keywords[] = { "idx", NULL };
	unsigned long idx;
	addrxlat_map_t *map;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k:get_map",
					 keywords, &idx))
		return NULL;

	if (idx >= ADDRXLAT_SYS_MAP_NUM) {
		PyErr_SetString(PyExc_IndexError,
				"system map index out of range");
		return NULL;
	}

	map = addrxlat_sys_get_map(self->sys, idx);
	return map_FromPointer(self->convert, map);
}

PyDoc_STRVAR(sys_set_meth__doc__,
"SYS.set_meth(idx, meth)\n\
\n\
Explicitly set a pre-defined translation method of a translation\n\
system.\n\
See SYS_METH_xxx for valid values of idx.");

static PyObject *
sys_set_meth(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	sys_object *self = (sys_object*)_self;
	static char *keywords[] = { "idx", "meth", NULL };
	unsigned long idx;
	PyObject *methobj;
	addrxlat_meth_t *meth;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "kO:set_meth",
					 keywords, &idx, &methobj))
		return NULL;

	if (idx >= ADDRXLAT_SYS_METH_NUM) {
		PyErr_SetString(PyExc_IndexError,
				"system meth index out of range");
		return NULL;
	}

	meth = meth_AsPointer(methobj);
	if (PyErr_Occurred())
		return NULL;

	addrxlat_sys_set_meth(self->sys, idx, meth);

	Py_RETURN_NONE;
}

PyDoc_STRVAR(sys_get_meth__doc__,
"SYS.get_meth(idx) -> Method\n\
\n\
Get the given translation method of a translation system.\n\
See SYS_METH_xxx for valid values of idx.");

static PyObject *
sys_get_meth(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	sys_object *self = (sys_object*)_self;
	static char *keywords[] = { "idx", NULL };
	unsigned long idx;
	const addrxlat_meth_t *meth;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k:get_meth",
					 keywords, &idx))
		return NULL;

	if (idx >= ADDRXLAT_SYS_METH_NUM) {
		PyErr_SetString(PyExc_IndexError,
				"system method index out of range");
		return NULL;
	}

	meth = addrxlat_sys_get_meth(self->sys, idx);
	return meth_FromPointer(self->convert, meth);
}

static PyMethodDef sys_methods[] = {
	{ "os_init", (PyCFunction)sys_os_init, METH_VARARGS | METH_KEYWORDS,
	  sys_os_init__doc__ },
	{ "set_map", (PyCFunction)sys_set_map, METH_VARARGS | METH_KEYWORDS,
	  sys_set_map__doc__ },
	{ "get_map", (PyCFunction)sys_get_map, METH_VARARGS | METH_KEYWORDS,
	  sys_get_map__doc__ },
	{ "set_meth", (PyCFunction)sys_set_meth, METH_VARARGS | METH_KEYWORDS,
	  sys_set_meth__doc__ },
	{ "get_meth", (PyCFunction)sys_get_meth, METH_VARARGS | METH_KEYWORDS,
	  sys_get_meth__doc__ },
	{ NULL }
};

static PyMemberDef sys_members[] = {
	{ "convert", T_OBJECT, offsetof(sys_object, convert), 0,
	  attr_convert__doc__ },
	{ NULL }
};

static PyTypeObject sys_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".System",		/* tp_name */
	sizeof (sys_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	sys_dealloc,			/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_sysping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	sys__doc__,			/* tp_doc */
	sys_traverse,			/* tp_traverse */
	0,				/* tp_clear */
	sys_richcompare,		/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	sys_methods,			/* tp_methods */
	sys_members,			/* tp_members */
	0,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	sys_init,			/* tp_init */
	0,				/* tp_alloc */
	sys_new,			/* tp_new */
};


/** Get the libaddrxlat representation of a Python sys object.
 * @param self  System object.
 * @returns     Associated @c libaddrxlat_sys_t,
 *              @c NULL if @c self is None or on failure.
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static addrxlat_sys_t *
sys_AsPointer(PyObject *self)
{
	if (self == Py_None)
		return NULL;

	if (!PyObject_TypeCheck(self, &sys_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a System or None, not '%.200s'",
			     Py_TYPE(self)->tp_name);
		return NULL;
	}

	return ((sys_object*)self)->sys;
}

static int
replace_sys(PyObject **psysobj, addrxlat_sys_t **psys, PyObject *newval)
{
	addrxlat_sys_t *sys;
	PyObject *oldval;

	sys = sys_AsPointer(newval);
	if (PyErr_Occurred())
		return -1;

	if (sys)
		addrxlat_sys_incref(sys);
	if (*psys)
		addrxlat_sys_decref(*psys);
	*psys = sys;

	Py_INCREF(newval);
	oldval = *psysobj;
	*psysobj = newval;
	Py_XDECREF(oldval);
	return 0;
}

/** Number of parameter locations in @ref step_object. */
#define STEP_NLOC	2

/** Python representation of @ref addrxlat_step_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Translation step in libaddrxlat format. */
	addrxlat_step_t step;

	/** Translation context. */
	PyObject *ctx;
	/** Translation system. */
	PyObject *sys;
	/** Translation method. */
	PyObject *meth;
	/** FullAddress object for @c base. */
	PyObject *base;

	/** Location configuration for @c step. */
	param_loc loc[STEP_NLOC];

	PyObject *convert;
} step_object;

/** Create a new Step object with.
 * @param type  Python type of the new object.
 * @param conv  Type converter object.
 * @returns     New object, or @c NULL on failure.
 *
 * This is the common code for brand new objects and objects created from
 * a C pointer.
 */
static step_object *
step_new_common(PyTypeObject *type, PyObject *conv)
{
	step_object *self;

	self = (step_object*) type->tp_alloc(type, 0);
	if (self) {
		self->loc[0].ptr = &self->step;
		self->loc[0].off = 0;
		self->loc[0].len = sizeof(addrxlat_step_t);

		self->loc[1].ptr = NULL;
		self->loc[1].off = offsetof(addrxlat_step_t, base);
		self->loc[1].len = sizeof(addrxlat_fulladdr_t);

		Py_INCREF(conv);
		self->convert = conv;
	}
	return self;
}

PyDoc_STRVAR(step__doc__,
"Step(ctx) -> step");

/** Create a new, uninitialized step object.
 * @param type    step type
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       new step object, or @c NULL on failure
 */
static PyObject *
step_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	static const char *keywords[] = {"ctx", NULL};
	step_object *self;
	PyObject *ctxobj;

	if (fetch_args(keywords, 1, &args, &kwargs, &ctxobj))
		return NULL;
	Py_DECREF(args);
	Py_XDECREF(kwargs);
	if (!ctxobj)
		return NULL;

	self = step_new_common(type, convert);
	if (!self)
		return NULL;

	if (replace_ctx(&self->ctx, &self->step.ctx, ctxobj)) {
		Py_DECREF(self);
		return NULL;
	}

	Py_INCREF(Py_None);
	self->base = Py_None;

	return (PyObject*)self;
}

/** Construct a step object from an @c addrxlat_step_t pointer.
 * @param conv   TypeConvert object.
 * @param step   New value as a C object.
 * @returns      Corresponding Python object (or @c NULL on failure).
 *
 * This function makes a new copy of the step.
 */
static PyObject *
step_FromPointer(PyObject *conv, const addrxlat_step_t *step)
{
	PyTypeObject *type = ((convert_object *)conv)->step_type;
	PyObject *result;

	result = (PyObject*) step_new_common(type, conv);
	if (!result)
		return NULL;

	if (step_Init(result, step)) {
		Py_DECREF(result);
		return NULL;
	}

	return result;
}

PyDoc_STRVAR(step_base__doc__,
"base address for next translation step");

static fulladdr_loc step_base_loc = {
	offsetof(step_object, base),
	offsetof(step_object, loc[1]),
	"base"
};

/** Initialize a Step object using an C @c addrxlat_step_t pointer.
 * @param _self  Step object.
 * @param step   New value as a C object.
 * @returns      Zero on success, -1 otherwise.
 */
static int
step_Init(PyObject *_self, const addrxlat_step_t *step)
{
	step_object *self = (step_object *)_self;
	PyObject *obj;
	int result;

	obj = fulladdr_FromPointer(self->convert, &step->base);
	if (!obj)
		return -1;
	result = set_fulladdr((PyObject*)self, obj, &step_base_loc);
	Py_DECREF(obj);
	if (result)
		return result;

	obj = ctx_FromPointer(self->convert, step->ctx);
	if (!obj)
		return -1;
	if (replace_ctx(&self->ctx, &self->step.ctx, obj))
		return -1;

	obj = sys_FromPointer(self->convert, step->sys);
	if (!obj)
		return -1;
	if (replace_sys(&self->sys, &self->step.sys, obj))
		return -1;

	loc_scatter(self->loc, STEP_NLOC, step);

	return 0;
}

static void
step_dealloc(PyObject *_self)
{
	step_object *self = (step_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);

	if (self->step.ctx) {
		addrxlat_ctx_decref(self->step.ctx);
		self->step.ctx = NULL;
	}
	Py_XDECREF(self->ctx);

	if (self->step.sys) {
		addrxlat_sys_decref(self->step.sys);
		self->step.sys = NULL;
	}
	Py_XDECREF(self->sys);

	Py_XDECREF(self->meth);
	Py_XDECREF(self->base);

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
step_traverse(PyObject *_self, visitproc visit, void *arg)
{
	step_object *self = (step_object*)_self;
	Py_VISIT(self->ctx);
	Py_VISIT(self->sys);
	Py_VISIT(self->meth);
	Py_VISIT(self->base);
	Py_VISIT(self->convert);
	return 0;
}

PyDoc_STRVAR(step_ctx__doc__,
"translation context for the next step");

/** Setter for the ctx type.
 * @param self   any object
 * @param value  new value (a ctx object)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
step_set_ctx(PyObject *_self, PyObject *value, void *data)
{
	step_object *self = (step_object*)_self;

	if (check_null_attr(value, "ctx"))
		return -1;

	return replace_ctx(&self->ctx, &self->step.ctx, value);
}

PyDoc_STRVAR(step_sys__doc__,
"translation system for the next step");

/** Setter for the sys type.
 * @param self   any object
 * @param value  new value (a sys object)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
step_set_sys(PyObject *_self, PyObject *value, void *data)
{
	step_object *self = (step_object*)_self;

	if (check_null_attr(value, "sys"))
		return -1;

	return replace_sys(&self->sys, &self->step.sys, value);
}

PyDoc_STRVAR(step_meth__doc__,
"translation method for the next step");

/** Setter for the meth attribute.
 * @param self   any object
 * @param value  new value (a Method object)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
step_set_meth(PyObject *_self, PyObject *value, void *data)
{
	step_object *self = (step_object*)_self;
	addrxlat_meth_t *meth;
	PyObject *oldval;

	if (check_null_attr(value, "meth"))
		return -1;

	meth = meth_AsPointer(value);
	if (PyErr_Occurred())
		return -1;
	self->step.meth = meth;
	Py_INCREF(value);
	oldval = self->meth;
	self->meth = value;
	Py_XDECREF(oldval);

	return 0;
}

PyDoc_STRVAR(step_raw__doc__,
"raw value from last step");

/** Getter for the raw attribute.
 * @param _self  step object
 * @param data   ignored
 * @returns      PyLong object (or @c NULL on failure)
 */
static PyObject *
step_get_raw(PyObject *_self, void *data)
{
	step_object *self = (step_object*)_self;
	const addrxlat_lookup_elem_t *elem;

	if (!self->step.meth)
		Py_RETURN_NONE;

	switch (self->step.meth->kind) {
	case ADDRXLAT_PGT:
		return PyLong_FromUnsignedLongLong(self->step.raw.pte);

	case ADDRXLAT_LOOKUP:
		elem = self->step.raw.elem;
		return Py_BuildValue("(KK)",
				     (unsigned PY_LONG_LONG)elem->orig,
				     (unsigned PY_LONG_LONG)elem->dest);

	case ADDRXLAT_MEMARR:
		return PyLong_FromUnsignedLongLong(self->step.raw.addr);

	default:
		Py_RETURN_NONE;
	}
}

/** Setter for the raw attribute.
 * @param _self  step object
 * @param value  new value (a @c PyLong or @c PyInt)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
step_set_raw(PyObject *_self, PyObject *value, void *data)
{
	step_object *self = (step_object*)_self;

	if (self->step.meth) {
		addrxlat_pte_t pte;
		addrxlat_addr_t addr;

		switch (self->step.meth->kind) {
		case ADDRXLAT_PGT:
			pte = Number_AsUnsignedLongLong(value);
			if (PyErr_Occurred())
				return -1;
			self->step.raw.pte = pte;
			return 0;

		case ADDRXLAT_MEMARR:
			addr = Number_AsUnsignedLongLong(value);
			if (PyErr_Occurred())
				return -1;
			self->step.raw.addr = addr;
			return 0;

		default:
			break;
		}
	}

	PyErr_SetString(PyExc_TypeError,
			"attribute cannot be changed for this method");
	return -1;
}

PyDoc_STRVAR(step_idx__doc__,
"size of address idx in bits");

/** Getter for the idx attribute.
 * @param _self  step object
 * @param data   ignored
 * @returns      PyTuple object (or @c NULL on failure)
 */
static PyObject *
step_get_idx(PyObject *_self, void *data)
{
	step_object *self = (step_object*)_self;
	PyObject *result;
	unsigned i;

	result = PyTuple_New(ADDRXLAT_FIELDS_MAX + 1);
	if (!result)
		return NULL;

	for (i = 0; i < ADDRXLAT_FIELDS_MAX + 1; ++i) {
		PyObject *obj;
		obj = PyLong_FromUnsignedLongLong(self->step.idx[i]);
		if (!obj) {
			Py_DECREF(result);
			return NULL;
		}
		PyTuple_SET_ITEM(result, i, obj);
	}

	return result;
}

/** Setter for the idx attribute.
 * @param _self  step object
 * @param value  new value (a sequence of addresses)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
step_set_idx(PyObject *_self, PyObject *value, void *data)
{
	step_object *self = (step_object*)_self;
	addrxlat_addr_t idx[ADDRXLAT_FIELDS_MAX + 1];
	Py_ssize_t n;
	unsigned i;

	if (check_null_attr(value, "idx"))
		return -1;

	if (!PySequence_Check(value)) {
		PyErr_Format(PyExc_TypeError,
			     "'%.200s' object is not a sequence",
			     Py_TYPE(value)->tp_name);
		return -1;
	}

	n = PySequence_Length(value);
	if (n > ADDRXLAT_FIELDS_MAX + 1) {
		PyErr_Format(PyExc_ValueError,
			     "cannot have more than %d indices",
			     ADDRXLAT_FIELDS_MAX + 1);
		return -1;
	}

	for (i = 0; i < n; ++i) {
		unsigned long long tmp = 0;
		PyObject *obj = PySequence_GetItem(value, i);

		if (obj) {
			tmp = Number_AsUnsignedLongLong(obj);
			Py_DECREF(obj);
		}
		if (PyErr_Occurred())
			return -1;
		idx[i] = tmp;
	}
	memcpy(self->step.idx, idx, n * sizeof(idx[0]));
	while (i < ADDRXLAT_FIELDS_MAX)
		self->step.idx[i++] = 0;

	return 0;
}

static PyGetSetDef step_getset[] = {
	{ "ctx", get_object, step_set_ctx, step_ctx__doc__,
	  OFFSETOF_PTR(step_object, ctx) },
	{ "sys", get_object, step_set_sys, step_sys__doc__,
	  OFFSETOF_PTR(step_object, sys) },
	{ "meth", get_object, step_set_meth, step_meth__doc__,
	  OFFSETOF_PTR(step_object, meth) },
	{ "base", get_fulladdr, set_fulladdr, step_base__doc__,
	  &step_base_loc },
	{ "raw", step_get_raw, step_set_raw,
	  step_raw__doc__ },
	{ "idx", step_get_idx, step_set_idx,
	  step_idx__doc__ },
	{ NULL }
};

PyDoc_STRVAR(step_remain__doc__,
"remaining steps");

PyDoc_STRVAR(step_elemsz__doc__,
"size of the indexed element");

static PyMemberDef step_members[] = {
	{ "convert", T_OBJECT, offsetof(step_object, convert), 0,
	  attr_convert__doc__ },
	{ "remain", T_USHORT, offsetof(step_object, step.remain),
	  0, step_remain__doc__ },
	{ "elemsz", T_UINT, offsetof(step_object, step.elemsz),
	  0, step_elemsz__doc__ },
	{ NULL }
};

PyDoc_STRVAR(step_launch__doc__,
"STEP.launch(addr) -> status\n\
\n\
Make the first translation step (launch a translation).");

/** Wrapper for @ref addrxlat_launch
 * @param _self   step object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       status code (or @c NULL on failure)
 */
static PyObject *
step_launch(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	step_object *self = (step_object*)_self;
	static char *keywords[] = { "addr", NULL };
	unsigned long long addr;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "K:launch",
					 keywords, &addr))
		return NULL;

	status = addrxlat_launch(&self->step, addr);
	step_Init((PyObject*)self, &self->step);
	return ctx_status_result(self->ctx, status);
}

PyDoc_STRVAR(step_step__doc__,
"STEP.step() -> status\n\
\n\
Perform one translation step.");

/** Wrapper for @ref addrxlat_step
 * @param _self   step object
 * @param args    ignored
 * @returns       status code (or @c NULL on failure)
 */
static PyObject *
step_step(PyObject *_self, PyObject *args)
{
	step_object *self = (step_object*)_self;
	addrxlat_status status;

	status = addrxlat_step(&self->step);
	step_Init((PyObject*)self, &self->step);
	return ctx_status_result(self->ctx, status);
}

PyDoc_STRVAR(step_walk__doc__,
"STEP.walk() -> status\n\
\n\
Perform one complete address translation.");

/** Wrapper for @ref addrxlat_walk
 * @param _self   step object
 * @param args    ignored
 * @returns       status code (or @c NULL on failure)
 */
static PyObject *
step_walk(PyObject *_self, PyObject *args)
{
	step_object *self = (step_object*)_self;
	addrxlat_status status;

	status = addrxlat_walk(&self->step);
	return ctx_status_result(self->ctx, status);
}

static PyMethodDef step_methods[] = {
	{ "launch", (PyCFunction)step_launch, METH_VARARGS | METH_KEYWORDS,
	  step_launch__doc__ },
	{ "step", step_step, METH_NOARGS, step_step__doc__ },
	{ "walk", step_walk, METH_NOARGS, step_walk__doc__ },
	{ NULL }
};

static PyTypeObject step_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Step",		/* tp_name */
	sizeof (step_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	step_dealloc,			/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	step__doc__,			/* tp_doc */
	step_traverse,			/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	step_methods,			/* tp_methods */
	step_members,			/* tp_members */
	step_getset,			/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	step_new,			/* tp_new */
};

/** Get the libaddrxlat representation of a Python step object.
 * @param self  Step object.
 * @returns     Address of the embedded @c libaddrxlat_step_t,
 *              or @c NULL on error.
 *
 * The returned pointer refers to a @c libaddrxlat_step_t
 * structure embedded in the Python object, i.e. the pointer is
 * valid only as long as the containing Python object exists.
 */
static addrxlat_step_t *
step_AsPointer(PyObject *self)
{
	step_object *stepobj;

	if (!PyObject_TypeCheck(self, &step_type)) {
		PyErr_Format(PyExc_TypeError, "need a Step, not '%.200s'",
			     Py_TYPE(self)->tp_name);
		return NULL;
	}

	stepobj = (step_object*)self;
	loc_gather(stepobj->loc, STEP_NLOC, &stepobj->step);
	return &stepobj->step;
}

/** Python representation of @ref addrxlat_op_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Translation context. */
	PyObject *ctx;
	/** Translation system. */
	PyObject *sys;
	/** Translation op in libaddrxlat format. */
	addrxlat_op_ctl_t opctl;
	/** Result of the last callback. */
	PyObject *result;

	PyObject *convert;
} op_object;

/** Operation callback wrapper */
static addrxlat_status
cb_op(void *data, const addrxlat_fulladdr_t *addr)
{
	op_object *self = (op_object*)data;
	PyObject *addrobj;
	PyObject *result;

	addrobj = fulladdr_FromPointer(self->convert, addr);
	if (!addrobj)
		return ctx_error_status((ctx_object*)self->ctx);

	result = PyObject_CallMethod((PyObject*)self, "callback",
				     "O", addrobj);
	Py_XDECREF(self->result);
	if (!result) {
		Py_INCREF(Py_None);
		self->result = Py_None;
		return ctx_error_status((ctx_object*)self->ctx);
	}
	self->result = result;

	return ADDRXLAT_OK;
}

PyDoc_STRVAR(op__doc__,
"Operator(ctx) -> op\n\
\n\
Base class for generic addrxlat operations.");

/** Create a new, uninitialized op object.
 * @param type    op type
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       new op object, or @c NULL on failure
 */
static PyObject *
op_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	static const char *keywords[] = {"ctx", NULL};
	op_object *self;
	PyObject *ctxobj;

	if (fetch_args(keywords, 1, &args, &kwargs, &ctxobj))
		return NULL;
	Py_DECREF(args);
	Py_XDECREF(kwargs);
	if (!ctxobj)
		return NULL;

	self = (op_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	if (replace_ctx(&self->ctx, &self->opctl.ctx, ctxobj)) {
		Py_DECREF(self);
		return NULL;
	}

	self->opctl.op = cb_op;
	self->opctl.data = self;

	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;
}

/** Construct a op object from an @c addrxlat_op_ctl_t pointer.
 * @param _conv  TypeConvert object.
 * @param opctl  New value as a C object.
 * @returns      Corresponding Python object (or @c NULL on failure).
 *
 * This function makes a new copy of the op.
 */
static PyObject *
op_FromPointer(PyObject *_conv, const addrxlat_op_ctl_t *opctl)
{
	convert_object *conv = (convert_object *)_conv;
	PyTypeObject *type = conv->op_type;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	if (!result)
		return NULL;
	Py_INCREF(conv);
	((op_object*)result)->convert = (PyObject*)conv;

	if (op_Init(result, opctl)) {
		Py_DECREF(result);
		return NULL;
	}

	return result;
}

/** Initialize an Operator object using an C @c addrxlat_op_ctl_t pointer.
 * @param _self  Operator object.
 * @param opctl  New value as a C object.
 * @returns      Zero on success, -1 otherwise.
 */
static int
op_Init(PyObject *_self, const addrxlat_op_ctl_t *opctl)
{
	op_object *self = (op_object *)_self;
	PyObject *obj;

	obj = ctx_FromPointer(self->convert, opctl->ctx);
	if (!obj)
		return -1;
	if (replace_ctx(&self->ctx, &self->opctl.ctx, obj))
		return -1;

	obj = sys_FromPointer(self->convert, opctl->sys);
	if (!obj)
		return -1;
	if (replace_sys(&self->sys, &self->opctl.sys, obj))
		return -1;

	self->opctl = *opctl;
	return 0;
}

static void
op_dealloc(PyObject *_self)
{
	op_object *self = (op_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);

	if (self->opctl.ctx) {
		addrxlat_ctx_decref(self->opctl.ctx);
		self->opctl.ctx = NULL;
	}
	Py_XDECREF(self->ctx);

	if (self->opctl.sys) {
		addrxlat_sys_decref(self->opctl.sys);
		self->opctl.sys = NULL;
	}
	Py_XDECREF(self->sys);

	Py_XDECREF(self->result);

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
op_traverse(PyObject *_self, visitproc visit, void *arg)
{
	op_object *self = (op_object*)_self;
	Py_VISIT(self->ctx);
	Py_VISIT(self->sys);
	Py_VISIT(self->result);
	Py_VISIT(self->convert);
	return 0;
}

static PyObject *
op_call(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	op_object *self = (op_object*)_self;
	static char *keywords[] = {"addr", NULL};
	PyObject *addrobj;
	const addrxlat_fulladdr_t *addr;
	addrxlat_status status;
	PyObject *result;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:Operator",
					 keywords, &addrobj))
		return NULL;

	addr = fulladdr_AsPointer(addrobj);
	if (!addr)
		return NULL;

	status = addrxlat_op(&self->opctl, addr);
	result = ctx_status_result(self->ctx, status);
	if (result) {
		result = Py_BuildValue("(NN)", result, self->result);
		self->result = NULL;
	}
	return result;
}

PyDoc_STRVAR(op_ctx__doc__,
"translation context");

/** Setter for the ctx type.
 * @param self   any object
 * @param value  new value (a ctx object)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
op_set_ctx(PyObject *_self, PyObject *value, void *data)
{
	op_object *self = (op_object*)_self;

	if (check_null_attr(value, "ctx"))
		return -1;

	return replace_ctx(&self->ctx, &self->opctl.ctx, value);
}

PyDoc_STRVAR(op_sys__doc__,
"translation system");

/** Setter for the sys type.
 * @param self   any object
 * @param value  new value (a sys object)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
op_set_sys(PyObject *_self, PyObject *value, void *data)
{
	op_object *self = (op_object*)_self;

	if (check_null_attr(value, "sys"))
		return -1;

	return replace_sys(&self->sys, &self->opctl.sys, value);
}

static PyGetSetDef op_getset[] = {
	{ "ctx", get_object, op_set_ctx, op_ctx__doc__,
	  OFFSETOF_PTR(op_object, ctx) },
	{ "sys", get_object, op_set_sys, op_sys__doc__,
	  OFFSETOF_PTR(op_object, sys) },
	{ NULL }
};

PyDoc_STRVAR(op_caps__doc__,
"operation capabilities");

static PyMemberDef op_members[] = {
	{ "convert", T_OBJECT, offsetof(op_object, convert), 0,
	  attr_convert__doc__ },
	{ "caps", T_ULONG, offsetof(op_object, opctl.caps),
	  0, op_caps__doc__ },
	{ NULL }
};

PyDoc_STRVAR(op_callback__doc__,
"operation callback");

/** Getter for the sys attribute.
 * @param self  op object
 * @param args  ignored
 * @returns     None
 */
static PyObject *
op_callback(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	Py_RETURN_NONE;
}

static PyMethodDef op_methods[] = {
	{ "callback", (PyCFunction)op_callback, METH_VARARGS,
	  op_callback__doc__ },
	{ NULL }
};

static PyTypeObject op_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Operator",		/* tp_name */
	sizeof (op_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	op_dealloc,			/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	op_call,			/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
	    | Py_TPFLAGS_HAVE_GC
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	op__doc__,			/* tp_doc */
	op_traverse,			/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	op_methods,			/* tp_methods */
	op_members,			/* tp_members */
	op_getset,			/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	op_new,				/* tp_new */
};

/** Get the libaddrxlat representation of a Python op object.
 * @param value  a Python op object
 * @returns      address of the embedded @c libaddrxlat_op_ctl_t,
 *               or @c NULL on error
 *
 * The returned pointer refers to a @c libaddrxlat_op_ctl_t
 * structure embedded in the Python object, i.e. the pointer is
 * valid only as long as the containing Python object exists.
 */
static addrxlat_op_ctl_t *
op_AsPointer(PyObject *value)
{
	if (!PyObject_TypeCheck(value, &op_type)) {
		PyErr_Format(PyExc_TypeError, "need an Operator, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	return &((op_object*)value)->opctl;
}

PyDoc_STRVAR(_addrxlat_strerror__doc__,
"strerror(status) -> error message\n\
\n\
Return the string describing a given error status.");

/** Wrapper for @ref addrxlat_strerror
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       error message string (or @c NULL on failure)
 */
static PyObject *
_addrxlat_strerror(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"status", NULL};
	long status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "l",
					 keywords, &status))
		return NULL;

	return Text_FromUTF8(addrxlat_strerror(status));
}

PyDoc_STRVAR(_addrxlat_addrspace_name__doc__,
"addrspace_name(addrspace) -> name\n\
\n\
Return the name of an address space constant.");

/** Wrapper for @ref addrxlat_addrspace_name
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       error message string (or @c NULL on failure)
 */
static PyObject *
_addrxlat_addrspace_name(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"addrspace", NULL};
	long addrspace;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "l",
					 keywords, &addrspace))
		return NULL;

	return Text_FromUTF8(addrxlat_addrspace_name(addrspace));
}

PyDoc_STRVAR(_addrxlat_CAPS__doc__,
"CAPS(addrspace) -> capability bitmask\n\
\n\
Translate an address space constant into a capability bitmask.");

/** Wrapper for @ref ADDRXLAT_CAPS
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       integer capability mask (or @c NULL on failure)
 */
static PyObject *
_addrxlat_CAPS(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"addrspace", NULL};
	unsigned long addrspace;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k",
					 keywords, &addrspace))
		return NULL;

	return PyLong_FromUnsignedLong(ADDRXLAT_CAPS(addrspace));
}

PyDoc_STRVAR(_addrxlat_VER_LINUX__doc__,
"VER_LINUX(a, b, c) -> version code\n\
\n\
Calculate the Linux kernel version code.");

/** Wrapper for @ref ADDRXLAT_VER_LINUX
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       integer version code (or @c NULL on failure)
 */
static PyObject *
_addrxlat_VER_LINUX(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"a", "b", "c", NULL};
	unsigned long a, b, c;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "kkk",
					 keywords, &a, &b, &c))
		return NULL;

	return PyLong_FromUnsignedLong(ADDRXLAT_VER_LINUX(a, b, c));
}

PyDoc_STRVAR(_addrxlat_VER_XEN__doc__,
"VER_XEN(major, minor) -> version code\n\
\n\
Calculate the Xen hypervisor version code.");

/** Wrapper for @ref ADDRXLAT_VER_XEN
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       integer version code (or @c NULL on failure)
 */
static PyObject *
_addrxlat_VER_XEN(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"major", "minor", NULL};
	unsigned long major, minor;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "kk",
					 keywords, &major, &minor))
		return NULL;

	return PyLong_FromUnsignedLong(ADDRXLAT_VER_XEN(major, minor));
}

PyDoc_STRVAR(_addrxlat_pte_format_name__doc__,
"pte_format_name(fmt) -> name\n\
\n\
Return the name of a page table entry format constant.");

/** Wrapper for @ref addrxlat_pte_format_name
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       error message string (or @c NULL on failure)
 */
static PyObject *
_addrxlat_pte_format_name(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"fmt", NULL};
	long fmt;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "l",
					 keywords, &fmt))
		return NULL;

	return Text_FromUTF8(addrxlat_pte_format_name(fmt));
}

PyDoc_STRVAR(_addrxlat_pte_format__doc__,
"pte_format(name) -> fmt\n\
\n\
Return the page table entry format constant with the given name.");

/** Wrapper for @ref addrxlat_pte_format
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       error message string (or @c NULL on failure)
 */
static PyObject *
_addrxlat_pte_format(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"name", NULL};
	const char *name;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s",
					 keywords, &name))
		return NULL;

	return PyInt_FromLong(addrxlat_pte_format(name));
}

PyDoc_STRVAR(_addrxlat_pteval_shift__doc__,
"pteval_shift(fmt) -> capability bitmask\n\
\n\
Get the pteval shift for a PTE format.\n\
See PTE_xxx for valid values of fmt.");

/** Wrapper for @ref addrxlat_pteval_shift
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       Log2 value of the PTE size, -1 if unknown / invalid
 */
static PyObject *
_addrxlat_pteval_shift(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"fmt", NULL};
	unsigned long fmt;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k",
					 keywords, &fmt))
		return NULL;

	return PyInt_FromLong(addrxlat_pteval_shift(fmt));
}

static PyMethodDef addrxlat_methods[] = {
	{ "strerror", (PyCFunction)_addrxlat_strerror,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_strerror__doc__ },
	{ "addrspace_name", (PyCFunction)_addrxlat_addrspace_name,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_addrspace_name__doc__ },
	{ "CAPS", (PyCFunction)_addrxlat_CAPS, METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_CAPS__doc__ },
	{ "VER_LINUX", (PyCFunction)_addrxlat_VER_LINUX,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_VER_LINUX__doc__ },
	{ "VER_XEN", (PyCFunction)_addrxlat_VER_XEN,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_VER_XEN__doc__ },
	{ "pte_format_name", (PyCFunction)_addrxlat_pte_format_name,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_pte_format_name__doc__ },
	{ "pte_format", (PyCFunction)_addrxlat_pte_format,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_pte_format__doc__ },
	{ "pteval_shift", (PyCFunction)_addrxlat_pteval_shift,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_pteval_shift__doc__ },
	{ NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef addrxlat_moddef = {
        PyModuleDef_HEAD_INIT,
        MOD_NAME,            /* m_name */
        MOD_DOC,             /* m_doc */
        -1,                  /* m_size */
        addrxlat_methods,    /* m_methods */
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
PyInit__addrxlat (void)
#else
init_addrxlat (void)
#endif
{
	PyObject *mod;
	PyObject *obj;
	int ret;

	if (PyType_Ready(&c_pointer_type) < 0)
		return MOD_ERROR_VAL;

	fulladdr_type.tp_new = PyType_GenericNew;
	if (PyType_Ready(&fulladdr_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&ctx_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&meth_param_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&meth_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&custommeth_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&linearmeth_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&pgtmeth_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&lookupmeth_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&memarrmeth_type) < 0)
		return MOD_ERROR_VAL;

	range_type.tp_new = PyType_GenericNew;
	if (PyType_Ready(&range_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&map_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&sys_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&step_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&op_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&convert_type) < 0)
		return MOD_ERROR_VAL;

#if PY_MAJOR_VERSION >= 3
	mod = PyModule_Create(&addrxlat_moddef);
#else
	mod = Py_InitModule3(MOD_NAME, addrxlat_methods, MOD_DOC);
#endif
	if (!mod)
		goto err;

	BaseException = make_BaseException(mod);
	if (!BaseException)
		goto err_mod;
	ret = PyModule_AddObject(mod, "BaseException", BaseException);
	if (ret)
		goto err_exception;

	Py_INCREF((PyObject*)&fulladdr_type);
	ret = PyModule_AddObject(mod, "FullAddress",
				 (PyObject*)&fulladdr_type);
	if (ret)
		goto err_exception;

	Py_INCREF((PyObject*)&ctx_type);
	ret = PyModule_AddObject(mod, "Context", (PyObject*)&ctx_type);
	if (ret)
		goto err_fulladdr;

	Py_INCREF((PyObject*)&meth_type);
	ret = PyModule_AddObject(mod, "Method", (PyObject*)&meth_type);
	if (ret)
		goto err_ctx;

	Py_INCREF((PyObject*)&custommeth_type);
	ret = PyModule_AddObject(mod, "CustomMethod",
				 (PyObject*)&custommeth_type);
	if (ret)
		goto err_meth;

	Py_INCREF((PyObject*)&linearmeth_type);
	ret = PyModule_AddObject(mod, "LinearMethod",
				 (PyObject*)&linearmeth_type);
	if (ret)
		goto err_custommeth;

	Py_INCREF((PyObject*)&pgtmeth_type);
	ret = PyModule_AddObject(mod, "PageTableMethod",
				 (PyObject*)&pgtmeth_type);
	if (ret)
		goto err_linearmeth;

	Py_INCREF((PyObject*)&lookupmeth_type);
	ret = PyModule_AddObject(mod, "LookupMethod",
				 (PyObject*)&lookupmeth_type);
	if (ret)
		goto err_pgtmeth;

	Py_INCREF((PyObject*)&memarrmeth_type);
	ret = PyModule_AddObject(mod, "MemoryArrayMethod",
				 (PyObject*)&memarrmeth_type);
	if (ret)
		goto err_lookupmeth;

	Py_INCREF((PyObject*)&range_type);
	ret = PyModule_AddObject(mod, "Range", (PyObject*)&range_type);
	if (ret)
		goto err_memarrmeth;

	Py_INCREF((PyObject*)&map_type);
	ret = PyModule_AddObject(mod, "Map", (PyObject*)&map_type);
	if (ret)
		goto err_range;

	Py_INCREF((PyObject*)&sys_type);
	ret = PyModule_AddObject(mod, "System", (PyObject*)&sys_type);
	if (ret)
		goto err_map;

	Py_INCREF((PyObject*)&step_type);
	ret = PyModule_AddObject(mod, "Step", (PyObject*)&step_type);
	if (ret)
		goto err_sys;

	Py_INCREF((PyObject*)&op_type);
	ret = PyModule_AddObject(mod, "Operator", (PyObject*)&op_type);
	if (ret)
		goto err_step;

	Py_INCREF((PyObject*)&convert_type);
	ret = PyModule_AddObject(mod, "TypeConvert", (PyObject*)&convert_type);
	if (ret)
		goto err_op;

#define CONSTDEF(x)						\
	if (PyModule_AddIntConstant(mod, #x, ADDRXLAT_ ## x))	\
		goto err_convert

	/* status codes */
	CONSTDEF(OK);
	CONSTDEF(ERR_NOTIMPL);
	CONSTDEF(ERR_NOTPRESENT);
	CONSTDEF(ERR_INVALID);
	CONSTDEF(ERR_NOMEM);
	CONSTDEF(ERR_NODATA);
	CONSTDEF(ERR_NOMETH);
	CONSTDEF(ERR_CUSTOM_BASE);

	/* address spaces */
	CONSTDEF(KPHYSADDR);
	CONSTDEF(MACHPHYSADDR);
	CONSTDEF(KVADDR);
	CONSTDEF(NOADDR);

	/* endianity */
	CONSTDEF(BIG_ENDIAN);
	CONSTDEF(LITTLE_ENDIAN);
	CONSTDEF(HOST_ENDIAN);

	/* translation kinds */
	CONSTDEF(NOMETH);
	CONSTDEF(CUSTOM);
	CONSTDEF(LINEAR);
	CONSTDEF(PGT);
	CONSTDEF(LOOKUP);
	CONSTDEF(MEMARR);

	/* PTE types */
	CONSTDEF(PTE_NONE);
	CONSTDEF(PTE_PFN32);
	CONSTDEF(PTE_PFN64);
	CONSTDEF(PTE_AARCH64);
	CONSTDEF(PTE_AARCH64_LPA);
	CONSTDEF(PTE_AARCH64_LPA2);
	CONSTDEF(PTE_ARM);
	CONSTDEF(PTE_IA32);
	CONSTDEF(PTE_IA32_PAE);
	CONSTDEF(PTE_X86_64);
	CONSTDEF(PTE_S390X);
	CONSTDEF(PTE_PPC64_LINUX_RPN30);

	/* Other paging form constants */
	CONSTDEF(FIELDS_MAX);

	/* system map indices */
	CONSTDEF(SYS_MAP_HW);
	CONSTDEF(SYS_MAP_KV_PHYS);
	CONSTDEF(SYS_MAP_KPHYS_DIRECT);
	CONSTDEF(SYS_MAP_MACHPHYS_KPHYS);
	CONSTDEF(SYS_MAP_KPHYS_MACHPHYS);
	CONSTDEF(SYS_MAP_NUM);

	/* system method indices */
	CONSTDEF(SYS_METH_NONE);
	CONSTDEF(SYS_METH_PGT);
	CONSTDEF(SYS_METH_UPGT);
	CONSTDEF(SYS_METH_DIRECT);
	CONSTDEF(SYS_METH_KTEXT);
	CONSTDEF(SYS_METH_VMEMMAP);
	CONSTDEF(SYS_METH_RDIRECT);
	CONSTDEF(SYS_METH_MACHPHYS_KPHYS);
	CONSTDEF(SYS_METH_KPHYS_MACHPHYS);
	CONSTDEF(SYS_METH_CUSTOM);
	CONSTDEF(SYS_METH_NUM);

#undef CONSTDEF

	/* too big for PyModule_AddIntConstant() */
	obj = PyLong_FromUnsignedLongLong(ADDRXLAT_ADDR_MAX);
	if (!obj)
		goto err_convert;
	if (PyModule_AddObject(mod, "ADDR_MAX", obj)) {
		Py_DECREF(obj);
		goto err_convert;
	}

	obj = PyTuple_New(0);
	if (!obj)
		goto err_convert;
	convert = PyObject_Call((PyObject*)&convert_type, obj, NULL);
	Py_DECREF(obj);
	if (!convert)
		goto err_convert;

	if (PyModule_AddObject(mod, "convert", convert)) {
		Py_DECREF(convert);
		goto err_convert;
	}

	CAPI.ver = addrxlat_CAPI_VER;
	CAPI.convert = convert;
	CAPI.FullAddress_FromPointer = fulladdr_FromPointer;
	CAPI.FullAddress_AsPointer = fulladdr_AsPointer;
	CAPI.Context_FromPointer = ctx_FromPointer;
	CAPI.Context_AsPointer = ctx_AsPointer;
	CAPI.Method_FromPointer = meth_FromPointer;
	CAPI.Method_AsPointer = meth_AsPointer;
	CAPI.Range_FromPointer = range_FromPointer;
	CAPI.Range_AsPointer = range_AsPointer;
	CAPI.Map_FromPointer = map_FromPointer;
	CAPI.Map_AsPointer = map_AsPointer;
	CAPI.System_FromPointer = sys_FromPointer;
	CAPI.System_AsPointer = sys_AsPointer;
	CAPI.Step_FromPointer = step_FromPointer;
	CAPI.Step_Init = step_Init;
	CAPI.Step_AsPointer = step_AsPointer;
	CAPI.Operator_FromPointer = op_FromPointer;
	CAPI.Operator_Init = op_Init;
	CAPI.Operator_AsPointer = op_AsPointer;

	obj = PyCapsule_New(&CAPI, addrxlat_CAPSULE_NAME, NULL);
	if (!obj)
		goto err_convert;
	if (PyModule_AddObject(mod, "_C_API", obj)) {
		Py_DECREF(obj);
		goto err_convert;
	}

	return MOD_SUCCESS_VAL(mod);

 err_convert:
	Py_DECREF((PyObject*)&convert_type);
 err_op:
	Py_DECREF((PyObject*)&op_type);
 err_step:
	Py_DECREF((PyObject*)&step_type);
 err_sys:
	Py_DECREF((PyObject*)&sys_type);
 err_map:
	Py_DECREF((PyObject*)&map_type);
 err_range:
	Py_DECREF((PyObject*)&range_type);
 err_memarrmeth:
	Py_DECREF((PyObject*)&memarrmeth_type);
 err_lookupmeth:
	Py_DECREF((PyObject*)&lookupmeth_type);
 err_pgtmeth:
	Py_DECREF((PyObject*)&pgtmeth_type);
 err_linearmeth:
	Py_DECREF((PyObject*)&linearmeth_type);
 err_custommeth:
	Py_DECREF((PyObject*)&custommeth_type);
 err_meth:
	Py_DECREF((PyObject*)&meth_type);
 err_ctx:
	Py_DECREF((PyObject*)&ctx_type);
 err_fulladdr:
	Py_DECREF((PyObject*)&fulladdr_type);
 err_exception:
	Py_DECREF(BaseException);
 err_mod:
	Py_DECREF(mod);
 err:
	return MOD_ERROR_VAL;
}
