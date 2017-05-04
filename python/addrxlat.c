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
#include <addrxlat.h>
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
static PyObject *make_desc_param(PyObject *desc);

/** Default type converter object. */
static PyObject *convert;

/* Conversion functions */
static addrxlat_fulladdr_t *fulladdr_AsPointer(PyObject *value);
static PyObject *fulladdr_FromPointer(
	PyObject *_conv, const addrxlat_fulladdr_t *faddr);
static addrxlat_ctx_t *ctx_AsPointer(PyObject *value);
static PyObject *ctx_FromPointer(PyObject *_conv, addrxlat_ctx_t *ctx);
static addrxlat_desc_t *desc_AsPointer(PyObject *value);
static PyObject *desc_FromPointer(
	PyObject *_conv, const addrxlat_desc_t *desc);
static addrxlat_meth_t *meth_AsPointer(PyObject *value);
static PyObject *meth_FromPointer(PyObject *_conv, addrxlat_meth_t *meth);
static addrxlat_range_t *range_AsPointer(PyObject *value);
static PyObject *range_FromPointer(
	PyObject *_conv, const addrxlat_range_t *range);
static addrxlat_map_t *map_AsPointer(PyObject *value);
static PyObject *map_FromPointer(PyObject *_conv, addrxlat_map_t *map);
static addrxlat_sys_t *sys_AsPointer(PyObject *value);
static PyObject *sys_FromPointer(PyObject *_conv, addrxlat_sys_t *sys);
static addrxlat_step_t *step_AsPointer(PyObject *value);
static PyObject *step_FromPointer(
	PyObject *_conv, const addrxlat_step_t *step);
static int step_Init(PyObject *self, const addrxlat_step_t *step);
static addrxlat_op_ctl_t *op_AsPointer(PyObject *value);
static PyObject *op_FromPointer(
	PyObject *conv, const addrxlat_op_ctl_t *opctl);

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
	if (PyLong_Check(num))
		return PyLong_AsLong(num);
#if PY_MAJOR_VERSION < 3
	else if (PyInt_Check(num))
		return PyInt_AsLong(num);
#endif

	PyErr_Format(PyExc_TypeError, "'%.200s' object is not an integer",
		     Py_TYPE(num)->tp_name);
	return -1;
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
	if (PyLong_Check(num))
		return PyLong_AsUnsignedLongLong(num);
#if PY_MAJOR_VERSION < 3
	else if (PyInt_Check(num))
		return PyInt_AsLong(num);
#endif

	PyErr_Format(PyExc_TypeError, "'%.200s' object is not an integer",
		     Py_TYPE(num)->tp_name);
	return -1LL;
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
	if (PyLong_Check(num))
		return PyLong_AsUnsignedLongLongMask(num);
#if PY_MAJOR_VERSION < 3
	else if (PyInt_Check(num))
		return PyInt_AsLong(num);
#endif

	PyErr_Format(PyExc_TypeError, "'%.200s' object is not an integer",
		     Py_TYPE(num)->tp_name);
	return -1LL;
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

/** Python representation of @ref addrxlat_fulladdr_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Full address in libaddrxlat format. */
	addrxlat_fulladdr_t faddr;
} fulladdr_object;

static PyTypeObject fulladdr_type;

PyDoc_STRVAR(fulladdr__doc__,
"FullAddress() -> fulladdr\n\
\n\
Construct a full address, that is an address within a given\n\
address space (ADDRXLAT_xxxADDR).");

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
	if (PyErr_Occurred())
		return NULL;

	sys = sys_AsPointer(sysobj);
	if (PyErr_Occurred()) {
		addrxlat_ctx_decref(ctx);
		return NULL;
	}

	status = addrxlat_fulladdr_conv(&self->faddr, addrspace, ctx, sys);
	addrxlat_ctx_decref(ctx);
	addrxlat_sys_decref(sys);
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

typedef struct tag_ctx_object {
	PyObject_HEAD

	addrxlat_ctx_t *ctx;
	addrxlat_cb_t next_cb;

	PyObject *exc_type, *exc_val, *exc_tb;

	PyObject *convert;
} ctx_object;

static PyTypeObject ctx_type;

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
	addrxlat_ctx_err(self->ctx, status, msg);
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

/** Null callback function.
 * @param self  Python Context object
 * @returns     Always ADDRXLAT_ERR_NODATA
 */
static addrxlat_status
cb_null(ctx_object *self)
{
	return addrxlat_ctx_err(self->ctx, ADDRXLAT_ERR_NODATA,
				"NULL callback");
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

static addrxlat_status
cb_sym(void *_self, addrxlat_sym_t *sym)
{
	ctx_object *self = (ctx_object*)_self;
	PyObject *cb_sym;
	PyObject *args;
	PyObject *obj;
	PyObject *result;
	int argc, i;
	unsigned long long tmpval;

	cb_sym = PyObject_GetAttrString((PyObject*)self, "cb_sym");
	if (!cb_sym || cb_sym == Py_None)
		return cb_null(self);

	argc = addrxlat_sym_argc(sym->type);
	if (argc == -1)
		return addrxlat_ctx_err(self->ctx, ADDRXLAT_ERR_NOTIMPL,
					"Unknown symbolic info type: %d",
					(int)sym->type);
	args = PyTuple_New(1 + argc);
	if (!args)
		goto err;

	obj = PyInt_FromLong(sym->type);
	if (!obj)
		goto err_args;
	PyTuple_SET_ITEM(args, 0, obj);

	for (i = 0; i < argc; ++i) {
		obj = Text_FromUTF8(sym->args[i]);
		if (!obj)
			goto err_args;
		PyTuple_SET_ITEM(args, 1 + i, obj);
	}

	result = PyObject_Call(cb_sym, args, NULL);
	Py_DECREF(args);
	if (!result)
		goto err;
	if (result == Py_None) {
		Py_DECREF(result);
		return cb_none(self);
	}

	tmpval = Number_AsUnsignedLongLong(result);
	Py_DECREF(result);
	if (PyErr_Occurred())
		goto err;

	sym->val = tmpval;
	return ADDRXLAT_OK;

 err_args:
	Py_DECREF(args);
 err:
	return ctx_error_status(self);
}

static addrxlat_status
cb_read32(void *_self, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	ctx_object *self = (ctx_object*)_self;
	PyObject *addrobj, *result;
	unsigned long long tmpval;

	addrobj = fulladdr_FromPointer(self->convert, addr);
	if (!addrobj)
		return ctx_error_status(self);
	result = PyObject_CallMethod(
		(PyObject*)self, "cb_read32", "O", addrobj);
	Py_DECREF(addrobj);
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
cb_read64(void *_self, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	ctx_object *self = (ctx_object*)_self;
	PyObject *addrobj, *result;
	unsigned long long tmpval;

	addrobj = fulladdr_FromPointer(self->convert, addr);
	if (!addrobj)
		return ctx_error_status(self);
	result = PyObject_CallMethod(
		(PyObject*)self, "cb_read64", "O", addrobj);
	Py_DECREF(addrobj);
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

static void
cb_hook(void *_self, addrxlat_cb_t *cb)
{
	ctx_object *self = (ctx_object*)_self;

	if (self->next_cb.cb_hook)
		self->next_cb.cb_hook(self->next_cb.data, cb);

	if (self->ctx) {
		self->next_cb = *cb;

		cb->data = self;
		cb->cb_hook = cb_hook;
		cb->sym = cb_sym;
		cb->read32 = cb_read32;
		cb->read64 = cb_read64;
	}
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

		if (copy_attr((PyObject*)self, "next_cb_sym", "cb_sym"))
			goto err;
		if (copy_attr((PyObject*)self, "next_cb_read32", "cb_read32"))
			goto err;
		if (copy_attr((PyObject*)self, "next_cb_read64", "cb_read64"))
			goto err;
	}

	addrxlat_ctx_install_cb_hook(self->ctx, cb_hook, self);

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
		addrxlat_ctx_t *ctx = self->ctx;
		self->ctx = NULL;
		addrxlat_ctx_set_cb(ctx, addrxlat_ctx_get_cb(ctx));
		addrxlat_ctx_decref(ctx);
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

static PyObject *
cb_status_result(ctx_object *self, addrxlat_status status,
		 unsigned long long value)
{
	if (self->next_cb.cb_hook == cb_hook &&
	    handle_cb_exception((ctx_object*)self->next_cb.data, status))
		return NULL;

	if (status != ADDRXLAT_OK)
		return raise_exception(self->ctx, status);

	return PyLong_FromUnsignedLongLong(value);
}

PyDoc_STRVAR(ctx_cb_sym__doc__,
"CTX.cb_sym(type, *args) -> value\n\
\n\
Callback function to resolve symbolic information. The function\n\
can be called as:\n\
\n\
  - CTX.cb_sym(SYM_REG, regname) -> register value\n\
  - CTX.cb_sym(SYM_VALUE, symname) -> symbol value\n\
  - CTX.cb_sym(SYM_SIZEOF, symname) -> size\n\
  - CTX.cb_sym(SYM_OFFSETOF, typename, member) -> offset");

PyDoc_STRVAR(ctx_next_cb_sym__doc__,
"CTX.next_cb_sym(type, *args) -> value\n\
\n\
Call the next symbolic information callback.");

static PyObject *
ctx_next_cb_sym(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	PyObject *obj;
	addrxlat_sym_type_t type;
	Py_ssize_t argc, i;
	int symargc;
	addrxlat_sym_t *sym;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);
	if (!self->next_cb.sym)
		return raise_exception(self->ctx, cb_null(self));

	argc = PyTuple_GET_SIZE(args);
	if (argc < 1) {
		PyErr_Format(PyExc_TypeError,
			     "%s() takes at least one argument",
			     "next_cb_sym");
		return NULL;
	}

	obj = PyTuple_GET_ITEM(args, 0);
	type = Number_AsLong(obj);
	Py_DECREF(obj);
	if (PyErr_Occurred())
		return NULL;

	symargc = addrxlat_sym_argc(type);
	if (symargc == -1) {
		PyErr_Format(PyExc_NotImplementedError,
			     "Unknown symbolic info type: %d", (int)type);
		return NULL;
	}
	if (argc != symargc + 1) {
		PyErr_Format(PyExc_TypeError,
			     "%s(%d, ...) requires exactly %d arguments",
			     "next_cb_sym", (int)type, symargc + 1);
		return NULL;
	}

	sym = malloc(offsetof(addrxlat_sym_t, args) +
		     symargc * sizeof(const char*));
	if (!sym)
		return PyErr_NoMemory();

	sym->type = type;
	for (i = 1; i < argc; ++i) {
		char *arg = Text_AsUTF8(PyTuple_GET_ITEM(args, i));
		if (!arg) {
			free(sym);
			return NULL;
		}
		sym->args[i - 1] = arg;
	}

	status = self->next_cb.sym(self->next_cb.data, sym);
	obj = cb_status_result(self, status, sym->val);
	free(sym);

	return obj;
}

PyDoc_STRVAR(ctx_cb_read32__doc__,
"CTX.cb_read32(fulladdr) -> value\n\
\n\
Callback function to read a 32-bit integer from a given address.");

PyDoc_STRVAR(ctx_next_cb_read32__doc__,
"CTX.next_cb_read32(type, *args) -> value\n\
\n\
Call the next callback to read 32-bit entities.");

static PyObject *
ctx_next_cb_read32(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	PyObject *addrobj;
	addrxlat_fulladdr_t *addr;
	uint32_t val;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);
	if (!self->next_cb.read32)
		return raise_exception(self->ctx, cb_null(self));

	if (!PyArg_ParseTuple(args, "O", &addrobj))
		return NULL;
	addr = fulladdr_AsPointer(addrobj);
	if (!addr)
		return NULL;

	status = self->next_cb.read32(self->next_cb.data, addr, &val);
	return cb_status_result(self, status, val);
}

PyDoc_STRVAR(ctx_cb_read64__doc__,
"CTX.cb_read64(fulladdr) -> value\n\
\n\
Callback function to read a 64-bit integer from a given address.");

PyDoc_STRVAR(ctx_next_cb_read64__doc__,
"CTX.next_cb_read64(type, *args) -> value\n\
\n\
Call the next callback to read 64-bit entities.");

static PyObject *
ctx_next_cb_read64(PyObject *_self, PyObject *args)
{
	ctx_object *self = (ctx_object*)_self;
	PyObject *addrobj;
	addrxlat_fulladdr_t *addr;
	uint64_t val;
	addrxlat_status status;

	addrxlat_ctx_clear_err(self->ctx);
	if (!self->next_cb.read64)
		return raise_exception(self->ctx, cb_null(self));

	if (!PyArg_ParseTuple(args, "O", &addrobj))
		return NULL;
	addr = fulladdr_AsPointer(addrobj);
	if (!addr)
		return NULL;

	status = self->next_cb.read64(self->next_cb.data, addr, &val);
	return cb_status_result(self, status, val);
}

static PyMethodDef ctx_methods[] = {
	{ "err", (PyCFunction)ctx_err, METH_VARARGS | METH_KEYWORDS,
	  ctx_err__doc__ },
	{ "clear_err", ctx_clear_err, METH_NOARGS,
	  ctx_clear_err__doc__ },
	{ "get_err", ctx_get_err, METH_NOARGS,
	  ctx_get_err__doc__ },

	/* Callbacks */
	{ "cb_sym", ctx_next_cb_sym, METH_VARARGS,
	  ctx_cb_sym__doc__ },
	{ "cb_read32", ctx_next_cb_read32, METH_VARARGS,
	  ctx_cb_read32__doc__ },
	{ "cb_read64", ctx_next_cb_read64, METH_VARARGS,
	  ctx_cb_read64__doc__ },

	{ "next_cb_sym", ctx_next_cb_sym, METH_VARARGS,
	  ctx_next_cb_sym__doc__ },
	{ "next_cb_read32", ctx_next_cb_read32, METH_VARARGS,
	  ctx_next_cb_read32__doc__ },
	{ "next_cb_read64", ctx_next_cb_read64, METH_VARARGS,
	  ctx_next_cb_read64__doc__ },

	{ NULL }
};

static PyMemberDef ctx_members[] = {
	{ "convert", T_OBJECT, offsetof(ctx_object, convert), 0,
	  attr_convert__doc__ },
	{ NULL }
};

PyDoc_STRVAR(ctx_read_caps__doc__,
"read callback capabilities\n\
\n\
A bitmask of address spaces accepted by the read callback.");

static PyObject *
ctx_get_read_caps(PyObject *_self, void *data)
{
	ctx_object *self = (ctx_object*)_self;
	unsigned long read_caps = addrxlat_ctx_get_cb(self->ctx)->read_caps;

	return PyLong_FromUnsignedLong(read_caps);
}

static int
ctx_set_read_caps(PyObject *_self, PyObject *value, void *data)
{
	ctx_object *self = (ctx_object*)_self;
	addrxlat_cb_t cb = *addrxlat_ctx_get_cb(self->ctx);
	long read_caps = Number_AsLong(value);

	if (PyErr_Occurred())
		return -1;

	cb.read_caps = read_caps;
	addrxlat_ctx_set_cb(self->ctx, &cb);
	return 0;
}

static PyGetSetDef ctx_getset[] = {
	{ "read_caps", ctx_get_read_caps, ctx_set_read_caps,
	  ctx_read_caps__doc__ },
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
	ctx_getset,			/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	ctx_init,			/* tp_init */
	0,				/* tp_alloc */
	ctx_new,			/* tp_new */
};

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
		if (loc->ptr)
			memcpy(loc->ptr, buffer + loc->off, loc->len);
}

static void
loc_gather(const param_loc *loc, unsigned n, void *buffer)
{
	unsigned i;
	for (i = 0; i < n; ++i, ++loc)
		if (loc->ptr)
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

/** Maximum number of parameter locations in desc_object.
 * This is not checked anywhere, but should be less than the maximum
 * possible number of parameter locations. The assignment is currently:
 *
 * - @c loc[0] corresponds to the whole raw param object
 * - @c loc[1] is the root address (for PageTableDescription) or
 *             base address (for MemoryArrayDescription)
 */
#define MAXLOC	2

#define desc_HEAD		\
	PyObject_HEAD		\
	addrxlat_desc_t desc;	\
	PyObject *paramobj;	\
	unsigned nloc;		\
	param_loc loc[MAXLOC];	\
	PyObject *convert;

typedef struct {
	desc_HEAD
} desc_object;

/** Number of parameter locations in desc_object. */
#define DESC_NLOC	1

PyDoc_STRVAR(desc__doc__,
"Description(kind) -> address translation description\n\
\n\
This is a generic base class for all translation desriptions.\n\
Use a subclass to get a more suitable interface to the parameters\n\
of a specific translation kind.");

static PyObject *
desc_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	static const char *keywords[] = {"kind", NULL};
	desc_object *self;
	PyObject *value;
	long kind;

	if (fetch_args(keywords, 1, &args, &kwargs, &value))
		return NULL;
	Py_DECREF(args);
	Py_XDECREF(kwargs);
	kind = Number_AsLong(value);
	if (PyErr_Occurred())
		return NULL;

	self = (desc_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->desc.kind = kind;
	self->desc.target_as = ADDRXLAT_NOADDR;
	self->nloc = DESC_NLOC;
	self->loc[0].ptr = &self->desc.param;
	self->loc[0].off = 0;
	self->loc[0].len = sizeof(self->desc.param);
	self->paramobj = make_desc_param((PyObject*)self);
	if (!self->paramobj) {
		Py_DECREF(self);
		return NULL;
	}
	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;
}

static void
desc_dealloc(PyObject *_self)
{
	desc_object *self = (desc_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);
	Py_XDECREF(self->paramobj);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
desc_traverse(PyObject *_self, visitproc visit, void *arg)
{
	desc_object *self = (desc_object*)_self;
	Py_VISIT(self->paramobj);
	Py_VISIT(self->convert);
	return 0;
}

static PyMemberDef desc_members[] = {
	{ "convert", T_OBJECT, offsetof(desc_object, convert), 0,
	  attr_convert__doc__ },
	{ NULL }
};

PyDoc_STRVAR(desc_kind__doc__,
"translation kind");

static PyObject *
desc_get_kind(PyObject *_self, void *data)
{
	desc_object *self = (desc_object*)_self;
	return PyInt_FromLong(self->desc.kind);
}

PyDoc_STRVAR(desc_target_as__doc__,
"target address space");

PyDoc_STRVAR(desc_param__doc__,
"description parameters as a raw bytearray");

static int
desc_set_param(PyObject *_self, PyObject *value, void *data)
{
	desc_object *self = (desc_object*)_self;

	if (check_null_attr(value, "param"))
		return -1;

	if (ByteSequence_AsBuffer(value, &self->desc.param,
				  sizeof(self->desc.param)))
		return -1;

	loc_scatter(self->loc, self->nloc, &self->desc.param);

	return 0;
}

static PyGetSetDef desc_getset[] = {
	{ "kind", desc_get_kind, 0, desc_kind__doc__ },
	{ "target_as", get_addrspace, set_addrspace, desc_target_as__doc__,
	  OFFSETOF_PTR(desc_object, desc.target_as) },
	{ "param", get_object, desc_set_param, desc_param__doc__,
	  OFFSETOF_PTR(desc_object, paramobj) },
	{ NULL }
};

static PyTypeObject desc_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Description",	/* tp_name */
	sizeof (desc_object),		/* tp_basicsize */
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
	desc__doc__,			/* tp_doc */
	desc_traverse,			/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	desc_members,			/* tp_members */
	desc_getset,			/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	desc_new,			/* tp_new */
};

static PyObject *
make_desc(PyTypeObject *type, addrxlat_kind_t kind, PyObject *kwargs)
{
	PyObject *args, *result;

	args = Py_BuildValue("(l)", (long)kind);
	if (!args)
		return NULL;
	result = desc_new(type, args, kwargs);
	Py_DECREF(args);

	return result;
}

typedef struct {
	PyObject_HEAD
	PyObject *desc;
} desc_param_object;

static void
desc_param_dealloc(PyObject *_self)
{
	desc_param_object *self = (desc_param_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_DECREF(self->desc);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
desc_param_traverse(PyObject *_self, visitproc visit, void *arg)
{
	desc_param_object *self = (desc_param_object*)_self;
	Py_VISIT(self->desc);
	return 0;
}

static Py_ssize_t
desc_param_len(PyObject *_self)
{
	desc_param_object *self = (desc_param_object*)_self;
	desc_object *param = (desc_object*)self->desc;

	return param->loc[0].len;
}

static void *
desc_param_ptr(desc_object *param, Py_ssize_t index)
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
desc_param_item(PyObject *_self, Py_ssize_t index)
{
	desc_param_object *self = (desc_param_object*)_self;
	unsigned char *ptr = desc_param_ptr((desc_object*)self->desc, index);

	if (!ptr) {
		PyErr_SetString(PyExc_IndexError,
				"param index out of range");
		return NULL;
	}

	return PyInt_FromLong(*ptr);
}

static int
desc_param_ass_item(PyObject *_self, Py_ssize_t index, PyObject *value)
{
	desc_param_object *self = (desc_param_object*)_self;
	unsigned char *ptr;
	long byte;

	if (!value) {
		PyErr_SetString(PyExc_TypeError,
				"param items cannot be deleted");
		return -1;
	}

	ptr = desc_param_ptr((desc_object*)self->desc, index);
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

static PySequenceMethods desc_param_as_sequence = {
	desc_param_len,		/* sq_length */
	0,			/* sq_concat */
	0,			/* sq_repeat */
	desc_param_item,	/* sq_item */
	0,			/* sq_slice */
	desc_param_ass_item,	/* sq_ass_item */
	0,			/* sq_ass_slice */
	0,			/* sq_contains */
};

static PyTypeObject desc_param_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".desc-param",		/* tp_name */
	sizeof (desc_param_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	desc_param_dealloc,		/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	&desc_param_as_sequence,	/* tp_as_sequence */
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
	desc_param_traverse,		/* tp_traverse */
};

static PyObject *
make_desc_param(PyObject *desc)
{
	PyTypeObject *type = &desc_param_type;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	Py_INCREF(desc);
	((desc_param_object*)result)->desc = desc;
	return result;
}

PyDoc_STRVAR(lineardesc__doc__,
"LinearDescription() -> linear address translation description");

static PyObject *
lineardesc_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	desc_object *self;

	self = (desc_object*) make_desc(type, ADDRXLAT_LINEAR, kwargs);
	if (self)
		self->loc[0].len = sizeof(addrxlat_param_linear_t);

	return (PyObject*)self;
}

PyDoc_STRVAR(lineardesc_kind__doc__,
"translation kind (always ADDRXLAT_LINEAR)");

PyDoc_STRVAR(lineardesc_off__doc__,
"target linear offset from source");

static PyGetSetDef lineardesc_getset[] = {
	{ "kind", desc_get_kind, 0, lineardesc_kind__doc__ },
	{ "off", get_off, set_off, lineardesc_off__doc__,
	  OFFSETOF_PTR(desc_object, desc.param.linear.off) },
	{ NULL }
};

static PyTypeObject lineardesc_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".LinearDescription",	/* tp_name */
	sizeof (desc_object),		/* tp_basicsize */
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
	lineardesc__doc__,		/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	0,				/* tp_members */
	lineardesc_getset,		/* tp_getset */
	&desc_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	lineardesc_new,			/* tp_new */
};

typedef struct {
	desc_HEAD
	addrxlat_param_custom_t origparam;
} customdesc_object;

static addrxlat_status
desc_error_status(customdesc_object *self, addrxlat_step_t *step)
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

PyDoc_STRVAR(customdesc__doc__,
"CustomDescription() -> custom address translation description");

static addrxlat_status
cb_first_step(addrxlat_step_t *step, addrxlat_addr_t addr)
{
	const addrxlat_desc_t *desc = addrxlat_meth_get_desc(step->meth);
	customdesc_object *self = desc->param.custom.data;
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
		return desc_error_status(self, step);
	}

	result = PyObject_CallFunction(func, "OK",
				       stepobj, (unsigned PY_LONG_LONG) addr);
	Py_DECREF(stepobj);
	Py_DECREF(func);
	if (!result)
		return desc_error_status(self, step);

	Py_DECREF(result);
	return ADDRXLAT_OK;
}

static addrxlat_status
cb_next_step(addrxlat_step_t *step)
{
	const addrxlat_desc_t *desc = addrxlat_meth_get_desc(step->meth);
	customdesc_object *self = desc->param.custom.data;
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
		return desc_error_status(self, step);
	}

	result = PyObject_CallFunction(func, "O", stepobj);
	Py_DECREF(stepobj);
	Py_DECREF(func);
	if (!result)
		return desc_error_status(self, step);

	Py_DECREF(result);
	return ADDRXLAT_OK;
}

static PyObject *
customdesc_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	customdesc_object *self;

	self = (customdesc_object*) make_desc(type, ADDRXLAT_CUSTOM, kwargs);
	if (self) {
		self->loc[0].len = sizeof(addrxlat_param_custom_t);

		self->origparam = self->desc.param.custom;
		self->desc.param.custom.first_step = cb_first_step;
		self->desc.param.custom.next_step = cb_next_step;
		self->desc.param.custom.data = self;
	}

	return (PyObject*)self;
}

PyDoc_STRVAR(customdesc_first_step__doc__,
"DESC.cb_first_step(step, addr)\n\
\n\
Callback to perform the initial translation step.");

static PyObject *
customdesc_first_step(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"step", "addr", NULL};

	customdesc_object *self = (customdesc_object*)_self;
	PyObject *stepobj;
	addrxlat_step_t *step;
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

	status = self->origparam.first_step(step, addr);
	if (status != ADDRXLAT_OK)
		return raise_exception(step->ctx, status);

	Py_RETURN_NONE;
}

PyDoc_STRVAR(customdesc_next_step__doc__,
"DESC.cb_next_step(step)\n\
\n\
Callback to perform further translation steps.");

static PyObject *
customdesc_next_step(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"step", NULL};

	customdesc_object *self = (customdesc_object*)_self;
	PyObject *stepobj;
	addrxlat_step_t *step;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:next_step",
					 keywords, &stepobj))
		return NULL;
	step = step_AsPointer(stepobj);
	if (!step)
		return NULL;

	if (!self->origparam.next_step)
		return raise_notimpl("NULL callback");

	status = self->origparam.next_step(step);
	if (status != ADDRXLAT_OK)
		return raise_exception(step->ctx, status);

	Py_RETURN_NONE;
}

static PyMethodDef customdesc_methods[] = {
	{ "cb_first_step", (PyCFunction)customdesc_first_step,
	  METH_VARARGS | METH_KEYWORDS,
	  customdesc_first_step__doc__ },
	{ "cb_next_step", (PyCFunction)customdesc_next_step,
	  METH_VARARGS | METH_KEYWORDS,
	  customdesc_next_step__doc__ },

	{ NULL }
};

PyDoc_STRVAR(customdesc_kind__doc__,
"translation kind (always ADDRXLAT_CUSTOM)");

static PyGetSetDef customdesc_getset[] = {
	{ "kind", desc_get_kind, 0, customdesc_kind__doc__ },
	{ NULL }
};

static PyTypeObject customdesc_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".CustomDescription",	/* tp_name */
	sizeof (customdesc_object),	/* tp_basicsize */
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
	customdesc__doc__,		/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	customdesc_methods,		/* tp_methods */
	0,				/* tp_members */
	customdesc_getset,		/* tp_getset */
	&desc_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	customdesc_new,			/* tp_new */
};

typedef struct {
	desc_HEAD
	PyObject *root;
} pgtdesc_object;

PyDoc_STRVAR(pgtdesc__doc__,
"PageTableDescription() -> page table address translation description");

static PyObject *
pgtdesc_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	pgtdesc_object *self;

	self = (pgtdesc_object*) make_desc(type, ADDRXLAT_PGT, kwargs);
	if (self) {
		param_loc *loc;

		self->loc[0].len = sizeof(addrxlat_param_pgt_t);

		Py_INCREF(Py_None);
		self->root = Py_None;
		self->desc.param.pgt.root = *fulladdr_AsPointer(self->root);
		loc = &self->loc[DESC_NLOC];
		loc->ptr = NULL;
		loc->off = offsetof(addrxlat_param_t, pgt.root);
		loc->len = sizeof(addrxlat_fulladdr_t);
		self->nloc = DESC_NLOC + 1;
	}

	return (PyObject*)self;
}

static void
pgtdesc_dealloc(PyObject *_self)
{
	pgtdesc_object *self = (pgtdesc_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->root);
	desc_dealloc(_self);
}

static int
pgtdesc_traverse(PyObject *_self, visitproc visit, void *arg)
{
	pgtdesc_object *self = (pgtdesc_object*)_self;
	Py_VISIT(self->root);
	return desc_traverse(_self, visit, arg);
}

PyDoc_STRVAR(pgtdesc_kind__doc__,
"translation kind (always ADDRXLAT_PGT)");

PyDoc_STRVAR(pgtdesc_pte_format__doc__,
"format of a page tabe entry (ADDRXLAT_PTE_xxx)");

static PyObject *
pgtdesc_get_pte_format(PyObject *_self, void *data)
{
	desc_object *self = (desc_object*)_self;
	return PyInt_FromLong(self->desc.param.pgt.pf.pte_format);
}

static int
pgtdesc_set_pte_format(PyObject *_self, PyObject *value, void *data)
{
	desc_object *self = (desc_object*)_self;
	long pte_format;

	if (check_null_attr(value, "pte_format"))
		return -1;

	pte_format = Number_AsLong(value);
	if (PyErr_Occurred())
		return -1;

	self->desc.param.pgt.pf.pte_format = pte_format;
	return 0;
}

PyDoc_STRVAR(pgtdesc_fields__doc__,
"size of address fields in bits");

static PyObject *
pgtdesc_get_fields(PyObject *_self, void *data)
{
	desc_object *self = (desc_object*)_self;
	const addrxlat_paging_form_t *pf = &self->desc.param.pgt.pf;
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
pgtdesc_set_fields(PyObject *_self, PyObject *value, void *data)
{
	desc_object *self = (desc_object*)_self;
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

	self->desc.param.pgt.pf.nfields = i;
	memcpy(self->desc.param.pgt.pf.fieldsz, pf.fieldsz,
	       i * sizeof(pf.fieldsz[0]));
	while (i < ADDRXLAT_FIELDS_MAX)
		self->desc.param.pgt.pf.fieldsz[i++] = 0;

	return 0;
}

PyDoc_STRVAR(pgtdesc_root__doc__,
"root page table address");

static fulladdr_loc pgtdesc_root_loc = {
	offsetof(pgtdesc_object, root),
	offsetof(pgtdesc_object, loc[DESC_NLOC]),
	"root"
};

static PyGetSetDef pgtdesc_getset[] = {
	{ "kind", desc_get_kind, 0, pgtdesc_kind__doc__ },
	{ "root", get_fulladdr, set_fulladdr, pgtdesc_root__doc__,
	  &pgtdesc_root_loc },
	{ "pte_format", pgtdesc_get_pte_format, pgtdesc_set_pte_format,
	  pgtdesc_pte_format__doc__ },
	{ "fields", pgtdesc_get_fields, pgtdesc_set_fields,
	  pgtdesc_fields__doc__ },
	{ NULL }
};

static PyTypeObject pgtdesc_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".PageTableDescription", /* tp_name */
	sizeof (pgtdesc_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	pgtdesc_dealloc,		/* tp_dealloc */
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
	pgtdesc__doc__,			/* tp_doc */
	pgtdesc_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	0,				/* tp_members */
	pgtdesc_getset,			/* tp_getset */
	&desc_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	pgtdesc_new,			/* tp_new */
};

static PyObject *
lookupdesc_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	desc_object *self;

	self = (desc_object*) make_desc(type, ADDRXLAT_LOOKUP, kwargs);
	if (self) {
		self->loc[0].len = sizeof(addrxlat_param_lookup_t);
	}

	return (PyObject*)self;
}

static void
lookupdesc_dealloc(PyObject *_self)
{
	desc_object *self = (desc_object*)_self;
	if (self->desc.param.lookup.tbl) {
		free(self->desc.param.lookup.tbl);
		self->desc.param.lookup.tbl = NULL;
	}
	desc_dealloc(_self);
}

PyDoc_STRVAR(lookupdesc__doc__,
"LookupDescription() -> table lookup address translation description");

PyDoc_STRVAR(lookupdesc_kind__doc__,
"translation kind (always ADDRXLAT_LOOKUP)");

PyDoc_STRVAR(lookupdesc_endoff__doc__,
"max address offset inside each object");

PyDoc_STRVAR(lookupdesc_tbl__doc__,
"lookup table");

static PyObject *
lookupdesc_get_tbl(PyObject *_self, void *data)
{
	desc_object *self = (desc_object*)_self;
	const addrxlat_lookup_elem_t *elem;
	PyObject *result;
	size_t i;

	result = PyTuple_New(self->desc.param.lookup.nelem);
	if (!result)
		return NULL;

	for (i = 0, elem = self->desc.param.lookup.tbl;
	     i < self->desc.param.lookup.nelem;
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
lookupdesc_set_tbl(PyObject *_self, PyObject *value, void *data)
{
	desc_object *self = (desc_object*)_self;
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
	self->desc.param.lookup.nelem = n;
	if (self->desc.param.lookup.tbl)
		free(self->desc.param.lookup.tbl);
	self->desc.param.lookup.tbl = tbl;
	return 0;

 err_pair:
	Py_DECREF(pair);
 err_tbl:
	free(tbl);
	return -1;
}

static PyGetSetDef lookupdesc_getset[] = {
	{ "kind", desc_get_kind, 0, lookupdesc_kind__doc__ },
	{ "endoff", get_addr, set_addr, lookupdesc_endoff__doc__,
	  OFFSETOF_PTR(desc_object, desc.param.lookup.endoff) },
	{ "tbl", lookupdesc_get_tbl, lookupdesc_set_tbl,
	  lookupdesc_tbl__doc__ },
	{ NULL }
};

static PyTypeObject lookupdesc_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".LookupDescription",	/* tp_name */
	sizeof (desc_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	lookupdesc_dealloc,		/* tp_dealloc */
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
	lookupdesc__doc__,		/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	0,				/* tp_members */
	lookupdesc_getset,		/* tp_getset */
	&desc_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	lookupdesc_new,			/* tp_new */
};

typedef struct {
	desc_HEAD
	PyObject *base;
} memarrdesc_object;

PyDoc_STRVAR(memarrdesc__doc__,
"MemoryArrayDescription() -> memory array address translation description");

static PyObject *
memarrdesc_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	memarrdesc_object *self;

	self = (memarrdesc_object*) make_desc(type, ADDRXLAT_MEMARR, kwargs);
	if (self) {
		param_loc *loc;

		self->loc[0].len = sizeof(addrxlat_param_memarr_t);

		Py_INCREF(Py_None);
		self->base = Py_None;
		self->desc.param.memarr.base = *fulladdr_AsPointer(self->base);
		loc = &self->loc[DESC_NLOC];
		loc->ptr = NULL;
		loc->off = offsetof(addrxlat_param_t, memarr.base);
		loc->len = sizeof(addrxlat_fulladdr_t);
		self->nloc = DESC_NLOC + 1;
	}

	return (PyObject*)self;
}

static void
memarrdesc_dealloc(PyObject *_self)
{
	memarrdesc_object *self = (memarrdesc_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->base);
	desc_dealloc(_self);
}

static int
memarrdesc_traverse(PyObject *_self, visitproc visit, void *arg)
{
	memarrdesc_object *self = (memarrdesc_object*)_self;
	Py_VISIT(self->base);
	return desc_traverse(_self, visit, arg);
}

PyDoc_STRVAR(memarrdesc_kind__doc__,
"translation kind (always ADDRXLAT_MEMARR)");

PyDoc_STRVAR(memarrdesc_shift__doc__,
"address bit shift");

PyDoc_STRVAR(memarrdesc_elemsz__doc__,
"size of each array element");

PyDoc_STRVAR(memarrdesc_valsz__doc__,
"size of the value");

static PyMemberDef memarrdesc_members[] = {
	{ "shift", T_UINT, offsetof(desc_object, desc.param.memarr.shift),
	  0, memarrdesc_shift__doc__ },
	{ "elemsz", T_UINT, offsetof(desc_object, desc.param.memarr.elemsz),
	  0, memarrdesc_elemsz__doc__ },
	{ "valsz", T_UINT, offsetof(desc_object, desc.param.memarr.valsz),
	  0, memarrdesc_valsz__doc__ },
	{ NULL }
};

PyDoc_STRVAR(memarrdesc_base__doc__,
"base address of the translation array");

static fulladdr_loc memarrdesc_base_loc = {
	offsetof(memarrdesc_object, base),
	offsetof(memarrdesc_object, loc[DESC_NLOC]),
	"base"
};

static PyGetSetDef memarrdesc_getset[] = {
	{ "kind", desc_get_kind, 0, memarrdesc_kind__doc__ },
	{ "base", get_fulladdr, set_fulladdr,
	  memarrdesc_base__doc__, &memarrdesc_base_loc },
	{ NULL }
};

static PyTypeObject memarrdesc_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".MemoryArrayDescription", /* tp_name */
	sizeof (memarrdesc_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	memarrdesc_dealloc,		/* tp_dealloc */
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
	memarrdesc__doc__,		/* tp_doc */
	memarrdesc_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	0,				/* tp_methods */
	memarrdesc_members,		/* tp_members */
	memarrdesc_getset,		/* tp_getset */
	&desc_type,			/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0,				/* tp_init */
	0,				/* tp_alloc */
	memarrdesc_new,			/* tp_new */
};

typedef struct {
	PyObject_HEAD

	addrxlat_meth_t *meth;

	PyObject *convert;
} meth_object;

static PyTypeObject meth_type;

PyDoc_STRVAR(meth__doc__,
"Method() -> address translation method");

static PyObject *
meth_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
	meth_object *self;

	self = (meth_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->meth = get_c_pointer(kwargs);
	if (!self->meth) {
		if (PyErr_Occurred())
			return NULL;

		self->meth = addrxlat_meth_new();
		if (!self->meth) {
			Py_DECREF(self);
			return PyErr_NoMemory();
		}
	} else
		addrxlat_meth_incref(self->meth);

	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;
}

static int
meth_init(PyObject *self, PyObject *args, PyObject *kwargs)
{
	return c_pointer_super_init(&meth_type, self, args, kwargs);
}

static void
meth_dealloc(PyObject *_self)
{
	meth_object *self = (meth_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->convert);

	if (self->meth) {
		addrxlat_meth_decref(self->meth);
		self->meth = NULL;
	}

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
meth_traverse(PyObject *_self, visitproc visit, void *arg)
{
	meth_object *self = (meth_object*)_self;
	Py_VISIT(self->convert);
	return 0;
}

static PyObject *
meth_richcompare(PyObject *v, PyObject *w, int op)
{
	PyObject *result;

	if ((op == Py_EQ || op == Py_NE) &&
	    PyObject_TypeCheck(v, &meth_type) &&
	    PyObject_TypeCheck(w, &meth_type)) {
		int cmp = (((meth_object*)v)->meth == ((meth_object*)w)->meth);
		result = (cmp == (op == Py_EQ))
			? Py_True
			: Py_False;
	} else
		result = Py_NotImplemented;

	Py_INCREF(result);
	return result;
}

PyDoc_STRVAR(meth_set_desc__doc__,
"METH.set_desc(desc) -> status\n\
\n\
Set up the method from a translation description.");

static PyObject *
meth_set_desc(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	meth_object *self = (meth_object*)_self;
	static char *keywords[] = {"desc", NULL};
	PyObject *value;
	const addrxlat_desc_t *desc;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:set_desc",
					 keywords, &value))
		return NULL;

	desc = desc_AsPointer(value);
	if (!desc)
		return NULL;

	status = addrxlat_meth_set_desc(self->meth, desc);
	return PyInt_FromLong(status);
}

PyDoc_STRVAR(meth_get_desc__doc__,
"METH.get_desc() -> desc\n\
\n\
Get the translation description of a method.");

static PyObject *
meth_get_desc(PyObject *_self, PyObject *args)
{
	meth_object *self = (meth_object*)_self;
	return desc_FromPointer(
		self->convert, addrxlat_meth_get_desc(self->meth));
}

static PyMethodDef meth_methods[] = {
	{ "set_desc", (PyCFunction)meth_set_desc, METH_VARARGS | METH_KEYWORDS,
	  meth_set_desc__doc__ },
	{ "get_desc", meth_get_desc, METH_NOARGS,
	  meth_get_desc__doc__ },
	{ NULL }
};

static PyMemberDef meth_members[] = {
	{ "convert", T_OBJECT, offsetof(meth_object, convert), 0,
	  attr_convert__doc__ },
	{ NULL }
};

static PyTypeObject meth_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Method",		/* tp_name */
	sizeof (meth_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	meth_dealloc,			/* tp_dealloc */
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
	meth_methods,			/* tp_methods */
	meth_members,			/* tp_members */
	0,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	meth_init,			/* tp_init */
	0,				/* tp_alloc */
	meth_new,			/* tp_new */
};

/** Python representation of @ref addrxlat_range_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Range in libaddrxlat format. */
	addrxlat_range_t range;
	/** Translation method object. */
	PyObject *meth;
} range_object;

PyDoc_STRVAR(range__doc__,
"Range() -> range\n\
\n\
Construct an empty address range.");

static void
range_dealloc(PyObject *_self)
{
	range_object *self = (range_object*)_self;

	PyObject_GC_UnTrack(_self);
	Py_XDECREF(self->meth);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
range_traverse(PyObject *_self, visitproc visit, void *arg)
{
	range_object *self = (range_object*)_self;
	Py_VISIT(self->meth);
	return 0;
}

PyDoc_STRVAR(range_meth__doc__,
"translation method for this range");

/** Setter for the meth type.
 * @param self   any object
 * @param value  new value (a meth object)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
range_set_meth(PyObject *_self, PyObject *value, void *data)
{
	range_object *self = (range_object*)_self;
	addrxlat_meth_t *meth;
	PyObject *oldval;

	if (check_null_attr(value, "meth"))
		return -1;

	meth = meth_AsPointer(value);
	if (PyErr_Occurred())
		return -1;

	Py_INCREF(value);
	oldval = self->meth;
	self->meth = value;
	self->range.meth = meth;
	Py_XDECREF(oldval);

	return 0;
}

PyDoc_STRVAR(range_endoff__doc__,
"maximum offset contained in the range");

static PyGetSetDef range_getset[] = {
	{ "endoff", get_addr, set_addr, range_endoff__doc__,
	  OFFSETOF_PTR(range_object, range.endoff) },
	{ "meth", get_object, range_set_meth, range_meth__doc__,
	  OFFSETOF_PTR(range_object, meth) },
	{ NULL }
};

static PyTypeObject range_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".Range",		/* tp_name */
	sizeof (range_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	range_dealloc,			/* tp_dealloc */
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
	range__doc__,			/* tp_doc */
	range_traverse,			/* tp_traverse */
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

typedef struct {
	PyObject_HEAD

	addrxlat_map_t *map;

	PyObject *convert;
} map_object;

static PyTypeObject map_type;

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

	return meth_FromPointer(
		self->convert, addrxlat_map_search(self->map, addr));
}

PyDoc_STRVAR(map_clear__doc__,
"MAP.clear()\n\
\n\
Remove all entries from a translation map.");

static PyObject *
map_clear(PyObject *_self, PyObject *args)
{
	map_object *self = (map_object*)_self;

	addrxlat_map_clear(self->map);
	Py_RETURN_NONE;
}

PyDoc_STRVAR(map_copy__doc__,
"M.copy() -> map\n\
\n\
Return a shallow copy of a translation map.");

static PyTypeObject map_type;

static PyObject *
map_copy(PyObject *_self, PyObject *args)
{
	map_object *self = (map_object*)_self;
	addrxlat_map_t *map;

	map = addrxlat_map_copy(self->map);
	if (!map)
		return PyErr_NoMemory();

	return map_FromPointer(self->convert, map);
}

static PyMethodDef map_methods[] = {
	{ "set", (PyCFunction)map_set, METH_VARARGS | METH_KEYWORDS,
	  map_set__doc__ },
	{ "search", (PyCFunction)map_search, METH_VARARGS | METH_KEYWORDS,
	  map_search__doc__ },
	{ "clear", map_clear, METH_NOARGS,
	  map_clear__doc__ },
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

typedef struct {
	PyObject_HEAD

	addrxlat_sys_t *sys;

	PyObject *convert;
} sys_object;

static PyTypeObject sys_type;

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
"SYS.os_init(ctx, arch[, type[, ver[, opts]]]) -> status\n\
\n\
Set up a translation system for a pre-defined operating system.");

static PyObject *
sys_os_init(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	sys_object *self = (sys_object*)_self;
	static char *keywords[] = {
		"ctx", "arch", "type", "ver", "opts",
		NULL
	};
	PyObject *ctxobj;
	addrxlat_ctx_t *ctx;
	addrxlat_osdesc_t osdesc;
	long type;
	addrxlat_status status;

	type = ADDRXLAT_OS_UNKNOWN;
	osdesc.ver = 0;
	osdesc.opts = NULL;
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Os|lkz:init",
					 keywords, &ctxobj, &osdesc.arch,
					 &type, &osdesc.ver, &osdesc.opts))
		return NULL;

	ctx = ctx_AsPointer(ctxobj);
	if (!ctx)
		return NULL;

	osdesc.type = type;
	status = addrxlat_sys_os_init(self->sys, ctx, &osdesc);
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
	if (map)
		addrxlat_map_decref(map);

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

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k:get_map",
					 keywords, &idx))
		return NULL;

	if (idx >= ADDRXLAT_SYS_MAP_NUM) {
		PyErr_SetString(PyExc_IndexError,
				"system map index out of range");
		return NULL;
	}

	return map_FromPointer(
		self->convert, addrxlat_sys_get_map(self->sys, idx));
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
	if (meth)
		addrxlat_meth_decref(meth);

	Py_RETURN_NONE;
}

PyDoc_STRVAR(sys_get_meth__doc__,
"SYS.get_meth(idx) -> Method or None\n\
\n\
Get the given translation method of a translation system.\n\
See SYS_METH_xxx for valid values of idx.");

static PyObject *
sys_get_meth(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	sys_object *self = (sys_object*)_self;
	static char *keywords[] = { "idx", NULL };
	unsigned long idx;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k:get_meth",
					 keywords, &idx))
		return NULL;

	if (idx >= ADDRXLAT_SYS_METH_NUM) {
		PyErr_SetString(PyExc_IndexError,
				"system method index out of range");
		return NULL;
	}

	return meth_FromPointer(
		self->convert, addrxlat_sys_get_meth(self->sys, idx));
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

/** Number of parameter locations in @ref step_object. */
#define STEP_NLOC	2

/** Python representation of @ref addrxlat_step_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Translation context. */
	PyObject *ctx;
	/** Translation step in libaddrxlat format. */
	addrxlat_step_t step;

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

	self->step.ctx = ctx_AsPointer(ctxobj);
	if (PyErr_Occurred()) {
		Py_DECREF(self);
		return NULL;
	}
	Py_INCREF(ctxobj);
	self->ctx = ctxobj;
	Py_INCREF(Py_None);
	self->base = Py_None;

	return (PyObject*)self;
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
	if (self->step.meth) {
		addrxlat_meth_decref(self->step.meth);
		self->step.meth = NULL;
	}

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
step_traverse(PyObject *_self, visitproc visit, void *arg)
{
	step_object *self = (step_object*)_self;
	Py_VISIT(self->ctx);
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
	addrxlat_ctx_t *ctx;

	if (check_null_attr(value, "ctx"))
		return -1;

	ctx = ctx_AsPointer(value);
	if (PyErr_Occurred())
		return -1;
	if (self->step.ctx)
		addrxlat_ctx_decref(self->step.ctx);
	self->step.ctx = ctx;
	Py_INCREF(value);
	self->ctx = value;

	return 0;
}

PyDoc_STRVAR(step_sys__doc__,
"translation system for the next step");

/** Getter for the sys attribute.
 * @param _self  step object
 * @param data   ignored
 * @returns      sys object (or @c NULL on failure)
 */
static PyObject *
step_get_sys(PyObject *_self, void *data)
{
	step_object *self = (step_object*)_self;
	return sys_FromPointer(
		self->convert, (addrxlat_sys_t*)self->step.sys);
}

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
	addrxlat_sys_t *sys;

	if (check_null_attr(value, "sys"))
		return -1;

	sys = sys_AsPointer(value);
	if (PyErr_Occurred())
		return -1;
	if (self->step.sys)
		addrxlat_sys_decref(self->step.sys);
	self->step.sys = sys;

	return 0;
}

PyDoc_STRVAR(step_meth__doc__,
"translation method for the next step");

/** Getter for the meth attribute.
 * @param _self  step object
 * @param data   ignored
 * @returns      meth object (or @c NULL on failure)
 */
static PyObject *
step_get_meth(PyObject *_self, void *data)
{
	step_object *self = (step_object*)_self;
	return meth_FromPointer(
		self->convert, (addrxlat_meth_t*)self->step.meth);
}

/** Setter for the meth type.
 * @param self   any object
 * @param value  new value (a meth object)
 * @param data   ignored
 * @returns      zero on success, -1 otherwise
 */
static int
step_set_meth(PyObject *_self, PyObject *value, void *data)
{
	step_object *self = (step_object*)_self;
	addrxlat_meth_t *meth;

	if (check_null_attr(value, "meth"))
		return -1;

	meth = meth_AsPointer(value);
	if (PyErr_Occurred())
		return -1;
	if (self->step.meth)
		addrxlat_meth_decref(self->step.meth);
	self->step.meth = meth;

	return 0;
}

PyDoc_STRVAR(step_base__doc__,
"base address for next translation step");

static fulladdr_loc step_base_loc = {
	offsetof(step_object, base),
	offsetof(step_object, loc[1]),
	"base"
};

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

	switch (addrxlat_meth_get_desc(self->step.meth)->kind) {
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

		switch (addrxlat_meth_get_desc(self->step.meth)->kind) {
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
	{ "sys", step_get_sys, step_set_sys, step_sys__doc__ },
	{ "meth", step_get_meth, step_set_meth, step_meth__doc__ },
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
	return ctx_status_result(self->ctx, status);
}

PyDoc_STRVAR(step_launch_map__doc__,
"STEP.launch_map(addr, map) -> status\n\
\n\
Launch the translation using a translation map.");

/** Wrapper for @ref addrxlat_launch_map
 * @param _self   step object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       status code (or @c NULL on failure)
 */
static PyObject *
step_launch_map(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	step_object *self = (step_object*)_self;
	static char *keywords[] = { "addr", "map", NULL };
	unsigned long long addr;
	PyObject *mapobj;
	addrxlat_map_t *map;
	addrxlat_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "KO:launch_map",
					 keywords, &addr, &mapobj))
		return NULL;

	map = map_AsPointer(mapobj);
	if (PyErr_Occurred())
		return NULL;

	status = addrxlat_launch_map(&self->step, addr, map);

	if (map)
		addrxlat_map_decref(map);

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
	return ctx_status_result(self->ctx, status);
}

PyDoc_STRVAR(step_walk__doc__,
"STEP.walk() -> status\n\
\n\
Perform all remaining translation steps.");

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
	{ "launch_map", (PyCFunction)step_launch_map,
	  METH_VARARGS | METH_KEYWORDS,
	  step_launch_map__doc__ },
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

/** Python representation of @ref addrxlat_op_t.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD
	/** Translation context. */
	PyObject *ctx;
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
	if (!result)
		return ctx_error_status((ctx_object*)self->ctx);
	Py_XDECREF(self->result);
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

	self->opctl.ctx = ctx_AsPointer(ctxobj);
	if (PyErr_Occurred()) {
		Py_DECREF(self);
		return NULL;
	}
	Py_INCREF(ctxobj);
	self->ctx = ctxobj;

	self->opctl.op = cb_op;
	self->opctl.data = self;

	Py_INCREF(convert);
	self->convert = convert;

	return (PyObject*)self;
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
	Py_XDECREF(self->result);

	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
op_traverse(PyObject *_self, visitproc visit, void *arg)
{
	op_object *self = (op_object*)_self;
	Py_VISIT(self->ctx);
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
	addrxlat_ctx_t *ctx;

	if (check_null_attr(value, "ctx"))
		return -1;

	ctx = ctx_AsPointer(value);
	if (PyErr_Occurred())
		return -1;
	if (self->opctl.ctx)
		addrxlat_ctx_decref(self->opctl.ctx);
	self->opctl.ctx = ctx;
	Py_INCREF(value);
	self->ctx = value;

	return 0;
}

PyDoc_STRVAR(op_sys__doc__,
"translation system");

/** Getter for the sys attribute.
 * @param _self  op object
 * @param data   ignored
 * @returns      sys object (or @c NULL on failure)
 */
static PyObject *
op_get_sys(PyObject *_self, void *data)
{
	op_object *self = (op_object*)_self;
	return sys_FromPointer(
		self->convert, (addrxlat_sys_t*)self->opctl.sys);
}

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
	addrxlat_sys_t *sys;

	if (check_null_attr(value, "sys"))
		return -1;

	sys = sys_AsPointer(value);
	if (PyErr_Occurred())
		return -1;
	if (self->opctl.sys)
		addrxlat_sys_decref(self->opctl.sys);
	self->opctl.sys = sys;

	return 0;
}

static PyGetSetDef op_getset[] = {
	{ "ctx", get_object, op_set_ctx, op_ctx__doc__,
	  OFFSETOF_PTR(op_object, ctx) },
	{ "sys", op_get_sys, op_set_sys, op_sys__doc__ },
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

/** Converter between C types and Python types.
 */
typedef struct {
	/** Standard Python object header.  */
	PyObject_HEAD

	/** Target type for FullAddress conversions. */
	PyTypeObject *fulladdr_type;
	/** Target type for Context conversions. */
	PyTypeObject *ctx_type;
	/** Target type for Description conversions. */
	PyTypeObject *desc_type;
	/** Target type for CustomDescription conversions. */
	PyTypeObject *customdesc_type;
	/** Target type for LinearDescription conversions. */
	PyTypeObject *lineardesc_type;
	/** Target type for PageTableDescription conversions. */
	PyTypeObject *pgtdesc_type;
	/** Target type for LookupDescription conversions. */
	PyTypeObject *lookupdesc_type;
	/** Target type for MemoryArrayDescription conversions. */
	PyTypeObject *memarrdesc_type;
	/** Target type for Method conversions. */
	PyTypeObject *meth_type;
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
	self->desc_type = &desc_type;
	Py_INCREF(self->desc_type);
	self->customdesc_type = &customdesc_type;
	Py_INCREF(self->customdesc_type);
	self->lineardesc_type = &lineardesc_type;
	Py_INCREF(self->lineardesc_type);
	self->pgtdesc_type = &pgtdesc_type;
	Py_INCREF(self->pgtdesc_type);
	self->lookupdesc_type = &lookupdesc_type;
	Py_INCREF(self->lookupdesc_type);
	self->memarrdesc_type = &memarrdesc_type;
	Py_INCREF(self->memarrdesc_type);
	self->meth_type = &meth_type;
	Py_INCREF(self->meth_type);
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
	Py_XDECREF(self->desc_type);
	Py_XDECREF(self->customdesc_type);
	Py_XDECREF(self->lineardesc_type);
	Py_XDECREF(self->pgtdesc_type);
	Py_XDECREF(self->lookupdesc_type);
	Py_XDECREF(self->memarrdesc_type);
	Py_XDECREF(self->meth_type);
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
	Py_VISIT(self->desc_type);
	Py_VISIT(self->customdesc_type);
	Py_VISIT(self->lineardesc_type);
	Py_VISIT(self->pgtdesc_type);
	Py_VISIT(self->lookupdesc_type);
	Py_VISIT(self->memarrdesc_type);
	Py_VISIT(self->meth_type);
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

PyDoc_STRVAR(convert_desc__doc__,
"Target type for Description conversions.");

PyDoc_STRVAR(convert_customdesc__doc__,
"Target type for CustomDescription conversions.");

PyDoc_STRVAR(convert_lineardesc__doc__,
"Target type for LinearDescription conversions.");

PyDoc_STRVAR(convert_pgtdesc__doc__,
"Target type for PageTableDescription conversions.");

PyDoc_STRVAR(convert_lookupdesc__doc__,
"Target type for LookupDescription conversions.");

PyDoc_STRVAR(convert_memarrdesc__doc__,
"Target type for MemoryArrayDescription conversions.");

PyDoc_STRVAR(convert_meth__doc__,
"Target type for Method conversions.");

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
	{ "Description", T_OBJECT, offsetof(convert_object, desc_type),
	  0, convert_desc__doc__ },
	{ "CustomDescription", T_OBJECT,
	  offsetof(convert_object, customdesc_type),
	  0, convert_customdesc__doc__ },
	{ "LinearDescription", T_OBJECT,
	  offsetof(convert_object, lineardesc_type),
	  0, convert_lineardesc__doc__ },
	{ "PageTableDescription", T_OBJECT,
	  offsetof(convert_object, pgtdesc_type),
	  0, convert_pgtdesc__doc__ },
	{ "LookupDescription", T_OBJECT,
	  offsetof(convert_object, lookupdesc_type),
	  0, convert_lookupdesc__doc__ },
	{ "MemoryArrayDescription", T_OBJECT,
	  offsetof(convert_object, memarrdesc_type),
	  0, convert_memarrdesc__doc__ },
	{ "Method", T_OBJECT, offsetof(convert_object, meth_type),
	  0, convert_meth__doc__ },
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

/** Get the libaddrxlat representation of a Python fulladdr object.
 * @param value  a Python fulladdr object
 * @returns      address of the embedded @c libaddrxlat_fulladdr_t,
 *               or @c NULL on error
 *
 * The returned pointer refers to a @c libaddrxlat_fulladdr_t
 * structure embedded in the Python object, i.e. the pointer is
 * valid only as long as the containing Python object exists.
 *
 * If @c value is @c Py_None, return a pointer to a null address singleton.
 * This singleton should not be modified, as it would affect all other
 * @c None full addresses.
 */
static addrxlat_fulladdr_t *
fulladdr_AsPointer(PyObject *value)
{
	static addrxlat_fulladdr_t nulladdr = { 0, ADDRXLAT_NOADDR };

	if (value == Py_None)
		return &nulladdr;

	if (!PyObject_TypeCheck(value, &fulladdr_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a FullAddress or None, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	return &((fulladdr_object*)value)->faddr;
}

/** Construct a fulladdr object from @c addrxlat_fulladdr_t pointer.
 * @param _conv  convert object
 * @param faddr  libaddrxlat representation of a full address
 * @returns      corresponding Python object (or @c NULL on failure)
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

/** Get the libaddrxlat representation of a Python ctx object.
 * @param value  a Python ctx object
 * @returns      associated @c libaddrxlat_ctx_t (new reference),
 *               or @c NULL on error
 */
static addrxlat_ctx_t *
ctx_AsPointer(PyObject *value)
{
	addrxlat_ctx_t *ctx;

	if (!PyObject_TypeCheck(value, &ctx_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a Context, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	ctx = ((ctx_object*)value)->ctx;
	addrxlat_ctx_incref(ctx);
	return ctx;
}

/** Construct a context object from @c addrxlat_ctx_t.
 * @param _conv  convert object
 * @param ctx    libaddrxlat context or @c NULL
 * @returns      corresponding Python object (or @c NULL on failure)
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

/** Get the libaddrxlat representation of a Python desc object.
 * @param value  a Python desc object
 * @returns      address of the embedded @c libaddrxlat_desc_t,
 *               or @c NULL on error
 *
 * The returned pointer refers to a @c libaddrxlat_desc_t structure embedded
 * in the Python object, i.e. the pointer is valid only as long as the
 * containing Python object exists.
 *
 * NB: Some fields are updated dynamically, so the returned data may be stale
 * after the Python object is modified.
 */
static addrxlat_desc_t *
desc_AsPointer(PyObject *value)
{
	desc_object *descobj;

	if (!PyObject_TypeCheck(value, &desc_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a Description, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	descobj = (desc_object*)value;
	loc_gather(descobj->loc, descobj->nloc, &descobj->desc.param);
	return &descobj->desc;
}

/** Construct a desc object from @c addrxlat_desc_t.
 * @param _conv  convert object
 * @param desc   libaddrxlat description or @c NULL
 * @returns      corresponding Python object (or @c NULL on failure)
 *
 * This function makes a new copy of the description.
 */
static PyObject *
desc_FromPointer(PyObject *_conv, const addrxlat_desc_t *desc)
{
	convert_object *conv = (convert_object *)_conv;
	PyTypeObject *type;
	PyObject *args, *val;
	PyObject *addr = NULL;
	fulladdr_loc *addrloc = NULL;
	PyObject *result;
	desc_object *descobj;
	int res;

	switch (desc->kind) {
	case ADDRXLAT_CUSTOM:
		type = conv->customdesc_type;
		break;

	case ADDRXLAT_LINEAR:
		type = conv->lineardesc_type;
		break;

	case ADDRXLAT_PGT:
		type = conv->pgtdesc_type;
		addr = fulladdr_FromPointer(_conv, &desc->param.pgt.root);
		if (!addr)
			return NULL;
		addrloc = &pgtdesc_root_loc;
		break;

	case ADDRXLAT_LOOKUP:
		type = conv->lookupdesc_type;
		break;

	case ADDRXLAT_MEMARR:
		type = conv->memarrdesc_type;
		addr = fulladdr_FromPointer(_conv, &desc->param.memarr.base);
		if (!addr)
			return NULL;
		addrloc = &memarrdesc_base_loc;
		break;

	default:
		type = conv->desc_type;
		break;
	}

	args = (type == conv->desc_type
		? Py_BuildValue("(k)", desc->kind)
		: PyTuple_New(0));
	if (!args)
		goto err_addr;
	result = PyObject_Call((PyObject*)type, args, NULL);
	Py_DECREF(args);
	if (!result)
		goto err_addr;

	if (addr) {
		res = set_fulladdr(result, addr, addrloc);
		Py_DECREF(addr);
		if (res)
			goto err;
	}

	val = PyInt_FromLong(desc->target_as);
	if (!val)
		goto err;
	res = PyObject_SetAttrString(result, "target_as", val);
	Py_DECREF(val);
	if (res)
		goto err;

	descobj = (desc_object*)result;
	descobj->desc.target_as = desc->target_as;
	loc_scatter(descobj->loc, descobj->nloc, &desc->param);
	Py_INCREF(conv);
	descobj->convert = (PyObject*)conv;
	return result;

 err:
	Py_DECREF(result);
	return NULL;

 err_addr:
	Py_XDECREF(addr);
	return NULL;
}

/** Get the libaddrxlat representation of a Python meth object.
 * @param value   a Python meth object
 * @returns       associated @c libaddrxlat_meth_t (new reference),
 *                or @c NULL if @c value is None
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static addrxlat_meth_t *
meth_AsPointer(PyObject *value)
{
	addrxlat_meth_t *meth;

	if (value == Py_None)
		return NULL;

	if (!PyObject_TypeCheck(value, &meth_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a Method or None, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	meth = ((meth_object*)value)->meth;
	addrxlat_meth_incref(meth);
	return meth;
}

/** Construct a meth object from @c addrxlat_meth_t.
 * @param _conv  convert object
 * @param meth  libaddrxlat translation method or @c NULL
 * @returns     corresponding Python object (or @c NULL on failure)
 *
 * The Python object contains a new reference to the translation method.
 */
static PyObject *
meth_FromPointer(PyObject *_conv, addrxlat_meth_t *meth)
{
	convert_object *conv = (convert_object *)_conv;

	if (!meth)
		Py_RETURN_NONE;

	return object_FromPointer(conv->meth_type, meth);
}

/** Get the libaddrxlat representation of a Python range object.
 * @param value  a Python range object
 * @returns      address of the embedded @c libaddrxlat_range_t,
 *               or @c NULL on error
 *
 * The returned pointer refers to a @c libaddrxlat_range_t
 * structure embedded in the Python object, i.e. the pointer is
 * valid only as long as the containing Python object exists.
 */
static addrxlat_range_t *
range_AsPointer(PyObject *value)
{
	if (!PyObject_TypeCheck(value, &range_type)) {
		PyErr_Format(PyExc_TypeError, "need a Range, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	return &((range_object*)value)->range;
}

/** Construct a range object from @c addrxlat_range_t.
 * @param _conv  convert object
 * @param range  libaddrxlat representation of a range
 * @returns      corresponding Python object (or @c NULL on failure)
 *
 * This function makes a new copy of the range.
 */
static PyObject *
range_FromPointer(PyObject *_conv, const addrxlat_range_t *range)
{
	convert_object *conv = (convert_object *)_conv;
	PyTypeObject *type = conv->range_type;
	PyObject *meth;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	if (!result)
		return NULL;

	meth = meth_FromPointer((PyObject*)conv, range->meth);
	if (!meth) {
		Py_DECREF(result);
		return NULL;
	}
	((range_object*)result)->meth = meth;
	((range_object*)result)->range = *range;

	return result;
}

/** Get the libaddrxlat representation of a Python map object.
 * @param value   a Python map object
 * @returns       associated @c libaddrxlat_map_t (new reference),
 *                or @c NULL if @c value is None
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static addrxlat_map_t *
map_AsPointer(PyObject *value)
{
	map_object *mapobj;

	if (value == Py_None)
		return NULL;

	if (!PyObject_TypeCheck(value, &map_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a Map or None, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	mapobj = (map_object*)value;
	addrxlat_map_incref(mapobj->map);
	return mapobj->map;
}

/** Construct a map object from @c addrxlat_map_t.
 * @param _conv  convert object
 * @param map    libaddrxlat map or @c NULL
 * @returns      corresponding Python object (or @c NULL on failure)
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

/** Get the libaddrxlat representation of a Python sys object.
 * @param value   a Python sys object
 * @returns       associated @c libaddrxlat_sys_t (new reference),
 *                or @c NULL if @c value is None
 *
 * Since all possible return values error are valid, error conditions
 * must be detected by calling @c PyErr_Occurred.
 */
static addrxlat_sys_t *
sys_AsPointer(PyObject *value)
{
	addrxlat_sys_t *sys;

	if (value == Py_None)
		return NULL;

	if (!PyObject_TypeCheck(value, &sys_type)) {
		PyErr_Format(PyExc_TypeError,
			     "need a System or None, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	sys = ((sys_object*)value)->sys;
	addrxlat_sys_incref(sys);
	return sys;
}

/** Construct a sys object from @c addrxlat_sys_t.
 * @param _conv  convert object
 * @param sys  libaddrxlat translation system or @c NULL
 * @returns     corresponding Python object (or @c NULL on failure)
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

/** Get the libaddrxlat representation of a Python step object.
 * @param value  a Python step object
 * @returns      address of the embedded @c libaddrxlat_step_t,
 *               or @c NULL on error
 *
 * The returned pointer refers to a @c libaddrxlat_step_t
 * structure embedded in the Python object, i.e. the pointer is
 * valid only as long as the containing Python object exists.
 */
static addrxlat_step_t *
step_AsPointer(PyObject *value)
{
	step_object *stepobj;

	if (!PyObject_TypeCheck(value, &step_type)) {
		PyErr_Format(PyExc_TypeError, "need a Step, not '%.200s'",
			     Py_TYPE(value)->tp_name);
		return NULL;
	}

	stepobj = (step_object*)value;
	loc_gather(stepobj->loc, STEP_NLOC, &stepobj->step);
	return &stepobj->step;
}

/** Construct a step object from @c addrxlat_step_t.
 * @param conv   convert object
 * @param step   libaddrxlat representation of a step
 * @returns      corresponding Python object (or @c NULL on failure)
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

/** Initialize a Step object using a C @c addrxlat_step_t object.
 * @param _self  Python Step object
 * @param step   libaddrxlat representation of a step
 * @returns      corresponding Python object (or @c NULL on failure)
 */
static int
step_Init(PyObject *_self, const addrxlat_step_t *step)
{
	step_object *self = (step_object *)_self;
	PyObject *obj, *oldobj;
	int result;

	obj = ctx_FromPointer(self->convert, step->ctx);
	if (!obj)
		return -1;
	oldobj = self->ctx;
	self->ctx = obj;
	Py_XDECREF(oldobj);

	obj = fulladdr_FromPointer(self->convert, &step->base);
	if (!obj)
		return -1;
	result = set_fulladdr((PyObject*)self, obj, &step_base_loc);
	Py_DECREF(obj);
	if (result)
		return result;

	loc_scatter(self->loc, STEP_NLOC, step);

	if (self->step.ctx)
		addrxlat_ctx_incref(self->step.ctx);
	if (self->step.sys)
		addrxlat_sys_incref(self->step.sys);
	if (self->step.meth)
		addrxlat_meth_incref(self->step.meth);

	return 0;
}

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

/** Construct a op object from @c addrxlat_op_ctl_t.
 * @param _conv  convert object
 * @param opctl  libaddrxlat representation of an op
 * @returns      corresponding Python object (or @c NULL on failure)
 *
 * This function makes a new copy of the op.
 */
static PyObject *
op_FromPointer(PyObject *_conv, const addrxlat_op_ctl_t *opctl)
{
	convert_object *conv = (convert_object *)_conv;
	PyTypeObject *type = conv->op_type;
	PyObject *ctx;
	PyObject *result;

	result = type->tp_alloc(type, 0);
	if (!result)
		return NULL;

	ctx = ctx_FromPointer((PyObject*)conv, opctl->ctx);
	if (!ctx) {
		Py_DECREF(result);
		return NULL;
	}
	((op_object*)result)->ctx = ctx;
	((op_object*)result)->opctl = *opctl;
	Py_INCREF(conv);
	((op_object*)result)->convert = (PyObject*)conv;

	return result;
}

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

PyDoc_STRVAR(_addrxlat_sym_argc__doc__,
"sym_argc(type) -> number of arguments\n\
\n\
Get the number of arguments for a given type of symbolic info.\n\
See SYM_xxx for valid values of type.");

/** Wrapper for @ref addrxlat_sym_argc
 * @param self    module object
 * @param args    positional arguments
 * @param kwargs  keyword arguments
 * @returns       Log2 value of the PTE size, -1 if unknown / invalid
 */
static PyObject *
_addrxlat_sym_argc(PyObject *self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"type", NULL};
	unsigned long fmt;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k",
					 keywords, &fmt))
		return NULL;

	return PyInt_FromLong(addrxlat_sym_argc(fmt));
}

static PyMethodDef addrxlat_methods[] = {
	{ "strerror", (PyCFunction)_addrxlat_strerror,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_strerror__doc__ },
	{ "CAPS", (PyCFunction)_addrxlat_CAPS, METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_CAPS__doc__ },
	{ "VER_LINUX", (PyCFunction)_addrxlat_VER_LINUX,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_VER_LINUX__doc__ },
	{ "VER_XEN", (PyCFunction)_addrxlat_VER_XEN,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_VER_XEN__doc__ },
	{ "pteval_shift", (PyCFunction)_addrxlat_pteval_shift,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_pteval_shift__doc__ },
	{ "sym_argc", (PyCFunction)_addrxlat_sym_argc,
	  METH_VARARGS | METH_KEYWORDS,
	  _addrxlat_sym_argc__doc__ },
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

	if (PyType_Ready(&desc_param_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&desc_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&customdesc_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&lineardesc_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&pgtdesc_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&lookupdesc_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&memarrdesc_type) < 0)
		return MOD_ERROR_VAL;

	if (PyType_Ready(&meth_type) < 0)
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

	Py_INCREF((PyObject*)&desc_type);
	ret = PyModule_AddObject(mod, "Description", (PyObject*)&desc_type);
	if (ret)
		goto err_ctx;

	Py_INCREF((PyObject*)&customdesc_type);
	ret = PyModule_AddObject(mod, "CustomDescription",
				 (PyObject*)&customdesc_type);
	if (ret)
		goto err_desc;

	Py_INCREF((PyObject*)&lineardesc_type);
	ret = PyModule_AddObject(mod, "LinearDescription",
				 (PyObject*)&lineardesc_type);
	if (ret)
		goto err_customdesc;

	Py_INCREF((PyObject*)&pgtdesc_type);
	ret = PyModule_AddObject(mod, "PageTableDescription",
				 (PyObject*)&pgtdesc_type);
	if (ret)
		goto err_lineardesc;

	Py_INCREF((PyObject*)&lookupdesc_type);
	ret = PyModule_AddObject(mod, "LookupDescription",
				 (PyObject*)&lookupdesc_type);
	if (ret)
		goto err_pgtdesc;

	Py_INCREF((PyObject*)&memarrdesc_type);
	ret = PyModule_AddObject(mod, "MemoryArrayDescription",
				 (PyObject*)&memarrdesc_type);
	if (ret)
		goto err_lookupdesc;

	Py_INCREF((PyObject*)&meth_type);
	ret = PyModule_AddObject(mod, "Method", (PyObject*)&meth_type);
	if (ret)
		goto err_memarrdesc;

	Py_INCREF((PyObject*)&range_type);
	ret = PyModule_AddObject(mod, "Range", (PyObject*)&range_type);
	if (ret)
		goto err_meth;

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

	/* symbolic info types */
	CONSTDEF(SYM_REG);
	CONSTDEF(SYM_VALUE);
	CONSTDEF(SYM_SIZEOF);
	CONSTDEF(SYM_OFFSETOF);

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
	CONSTDEF(PTE_IA32);
	CONSTDEF(PTE_IA32_PAE);
	CONSTDEF(PTE_X86_64);
	CONSTDEF(PTE_S390X);
	CONSTDEF(PTE_PPC64_LINUX_RPN30);

	/* Other paging form constants */
	CONSTDEF(FIELDS_MAX);

	/* OS types */
	CONSTDEF(OS_UNKNOWN);
	CONSTDEF(OS_LINUX);
	CONSTDEF(OS_XEN);

	/* system map indices */
	CONSTDEF(SYS_MAP_HW);
	CONSTDEF(SYS_MAP_KV_PHYS);
	CONSTDEF(SYS_MAP_KPHYS_DIRECT);
	CONSTDEF(SYS_MAP_MACHPHYS_KPHYS);
	CONSTDEF(SYS_MAP_KPHYS_MACHPHYS);
	CONSTDEF(SYS_MAP_NUM);

	/* system method indices */
	CONSTDEF(SYS_METH_PGT);
	CONSTDEF(SYS_METH_UPGT);
	CONSTDEF(SYS_METH_DIRECT);
	CONSTDEF(SYS_METH_KTEXT);
	CONSTDEF(SYS_METH_VMEMMAP);
	CONSTDEF(SYS_METH_RDIRECT);
	CONSTDEF(SYS_METH_MACHPHYS_KPHYS);
	CONSTDEF(SYS_METH_KPHYS_MACHPHYS);
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
	CAPI.FullAddress_AsPointer = fulladdr_AsPointer;
	CAPI.FullAddress_FromPointer = fulladdr_FromPointer;
	CAPI.Context_AsPointer = ctx_AsPointer;
	CAPI.Context_FromPointer = ctx_FromPointer;
	CAPI.Description_AsPointer = desc_AsPointer;
	CAPI.Description_FromPointer = desc_FromPointer;
	CAPI.Method_AsPointer = meth_AsPointer;
	CAPI.Method_FromPointer = meth_FromPointer;
	CAPI.Range_AsPointer = range_AsPointer;
	CAPI.Range_FromPointer = range_FromPointer;
	CAPI.Map_AsPointer = map_AsPointer;
	CAPI.Map_FromPointer = map_FromPointer;
	CAPI.System_AsPointer = sys_AsPointer;
	CAPI.System_FromPointer = sys_FromPointer;
	CAPI.Step_AsPointer = step_AsPointer;
	CAPI.Step_FromPointer = step_FromPointer;
	CAPI.Step_Init = step_Init;
	CAPI.Operator_AsPointer = op_AsPointer;
	CAPI.Operator_FromPointer = op_FromPointer;

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
 err_meth:
	Py_DECREF((PyObject*)&meth_type);
 err_memarrdesc:
	Py_DECREF((PyObject*)&memarrdesc_type);
 err_lookupdesc:
	Py_DECREF((PyObject*)&lookupdesc_type);
 err_pgtdesc:
	Py_DECREF((PyObject*)&pgtdesc_type);
 err_lineardesc:
	Py_DECREF((PyObject*)&lineardesc_type);
 err_customdesc:
	Py_DECREF((PyObject*)&customdesc_type);
 err_desc:
	Py_DECREF((PyObject*)&desc_type);
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
