#include <Python.h>
#include <structmember.h>
#include <libkdumpfile/kdumpfile.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "addrxlatmod.h"

#define MOD_NAME	"_kdumpfile"
#define MOD_DOC		"kdumpfile - interface to libkdumpfile"

#if PY_MAJOR_VERSION >= 3
#define PyString_FromString(x) PyUnicode_FromString((x))
#define PyString_Check(x) PyUnicode_Check((x))
#define PyString_FromFormat(format, ...) PyUnicode_FromFormat(format, __VA_ARGS__)
#define PyString_AS_STRING PyBytes_AS_STRING
#define PyString_Concat PyUnicode_Concat
#endif

typedef struct {
	PyObject_HEAD
	kdump_ctx_t *ctx;
	int fd;
	PyObject *attr;
	PyObject *addrxlat_convert;
} kdumpfile_object;

static PyObject *OSErrorException;
static PyObject *NotImplementedException;
static PyObject *NoDataException;
static PyObject *CorruptException;
static PyObject *InvalidException;
static PyObject *NoKeyException;
static PyObject *EOFException;
static PyObject *BusyException;
static PyObject *AddressTranslationException;

static struct addrxlat_CAPI *addrxlat_API;

static PyTypeObject attr_dir_object_type;
static PyTypeObject attr_iterkey_object_type;
static PyTypeObject attr_itervalue_object_type;
static PyTypeObject attr_iteritem_object_type;

static PyTypeObject bmp_object_type;

static PyTypeObject blob_object_type;

static PyObject *attr_viewkeys_type;
static PyObject *attr_viewvalues_type;
static PyObject *attr_viewitems_type;
static PyObject *attr_viewdict_type;

static PyObject *attr_dir_new(kdumpfile_object *kdumpfile,
			      const kdump_attr_ref_t *baseref);

static PyObject *bmp_new(kdump_bmp_t *bitmap);

static PyObject *blob_new(kdump_blob_t *blob);

static PyObject *
exception_map(kdump_status status)
{
	switch (status) {
	case KDUMP_ERR_SYSTEM:	return OSErrorException;
	case KDUMP_ERR_NOTIMPL:	return NotImplementedException;
	case KDUMP_ERR_NODATA:	return NoDataException;
	case KDUMP_ERR_CORRUPT:	return CorruptException;
	case KDUMP_ERR_INVALID:	return InvalidException;
	case KDUMP_ERR_NOKEY:	return NoKeyException;
	case KDUMP_ERR_EOF:	return EOFException;
	case KDUMP_ERR_BUSY:	return BusyException;
	case KDUMP_ERR_ADDRXLAT: return AddressTranslationException;
	/* If we raise an exception with status == KDUMP_OK, it's a bug. */
	case KDUMP_OK:
	default:                return PyExc_RuntimeError;
	};
}

static int kdumpfile_init_common(kdumpfile_object *self)
{
	kdump_status status;
	kdump_attr_ref_t rootref;

	status = kdump_attr_ref(self->ctx, NULL, &rootref);
	if (status != KDUMP_OK) {
		PyErr_Format(exception_map(status),
			     "Cannot reference root attribute: %s",
			     kdump_get_err(self->ctx));
		return -1;
	}

	self->attr = attr_dir_new(self, &rootref);
	if (!self->attr) {
		kdump_attr_unref(self->ctx, &rootref);
		return -1;
	}

	Py_INCREF(addrxlat_API->convert);
	self->addrxlat_convert = addrxlat_API->convert;

	return 0;
}

static PyObject *
kdumpfile_new (PyTypeObject *type, PyObject *args, PyObject *kw)
{
	kdumpfile_object *self = NULL;
	static char *keywords[] = {"file", NULL};
	kdump_status status;
	const char *filepath;

	if (!PyArg_ParseTupleAndKeywords (args, kw, "s", keywords, &filepath))
		    return NULL;


	self = (kdumpfile_object*) type->tp_alloc (type, 0);
	if (!self)
		return NULL;

	self->ctx = kdump_new();
	if (!self->ctx) {
		PyErr_SetString(PyExc_MemoryError,
				"Couldn't allocate kdump context");
		goto fail;
	}

	self->fd = open (filepath, O_RDONLY);
	if (self->fd < 0) {
		PyErr_Format(OSErrorException, "Couldn't open dump file");
		goto fail;
	}

	status = kdump_open_fd(self->ctx, self->fd);
	if (status != KDUMP_OK) {
		PyErr_Format(exception_map(status),
			     "Cannot open dump: %s", kdump_get_err(self->ctx));
		goto fail;
	}

	if (kdumpfile_init_common(self))
		goto fail;

	return (PyObject*)self;

fail:
	Py_XDECREF(self);
	close(self->fd);
	return NULL;
}

static void
kdumpfile_dealloc(PyObject *_self)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;

	if (self->ctx) {
		kdump_free(self->ctx);
		self->ctx = NULL;
	}

	if (self->fd) close(self->fd);
	Py_XDECREF(self->addrxlat_convert);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(kdumpfile_from_pointer__doc__,
"from_pointer (address) -> kdumpfile\naddress must be valid pointer to kdump_ctx.");

static PyObject *kdumpfile_from_pointer (PyObject *_type, PyObject *args, PyObject *kwargs)
{
	PyTypeObject *type = (PyTypeObject *)_type;
	kdumpfile_object *self = NULL;
	unsigned long addr = 0;
	static char *keywords[] = { "address", NULL };

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "k:from_pointer",
					 keywords, &addr))
		return NULL;

	if (addr == 0) {
		PyErr_SetString(PyExc_ValueError,
				"Cannot instantiate object with NULL pointer.");
		return NULL;
	}

	self = (kdumpfile_object*) type->tp_alloc(type, 0);
	if (!self)
		return NULL;

	self->ctx = kdump_clone((kdump_ctx_t *)addr, 0);
	if (!self->ctx) {
		PyErr_SetString(PyExc_MemoryError,
				"Couldn't allocate kdump context");
		Py_XDECREF(self);
		goto fail;
	}

	self->fd = 0;
	if (kdumpfile_init_common(self))
		goto fail;

	return (PyObject *)self;

fail:
	Py_XDECREF(self);
	return NULL;

}

PyDoc_STRVAR(read__doc__,
"read (addrtype, address) -> buffer.");

static PyObject *kdumpfile_read (PyObject *_self, PyObject *args, PyObject *kw)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;
	PyObject *obj;
	kdump_paddr_t addr;
	kdump_status status;
	int addrspace;
	unsigned long size;
	static char *keywords[] = {"addrspace", "address", "size", NULL};
	size_t r;

	if (!PyArg_ParseTupleAndKeywords(args, kw, "ikk:",
					 keywords, &addrspace, &addr, &size))
		return NULL;

	if (!size) {
		PyErr_SetString(PyExc_ValueError, "Zero size buffer");
		return NULL;
	}

	obj = PyByteArray_FromStringAndSize(0, size);
	if (!obj)
		return NULL;

	r = size;
	status = kdump_read(self->ctx, addrspace, addr,
			    PyByteArray_AS_STRING(obj), &r);
	if (status != KDUMP_OK) {
		Py_XDECREF(obj);
		PyErr_SetString(exception_map(status),
				kdump_get_err(self->ctx));
		return NULL;
	}

	return obj;
}

static PyObject *
attr_new(kdumpfile_object *kdumpfile, kdump_attr_ref_t *ref, kdump_attr_t *attr)
{
	if (attr->type != KDUMP_DIRECTORY)
		kdump_attr_unref(kdumpfile->ctx, ref);

	switch (attr->type) {
		case KDUMP_NUMBER:
			return PyLong_FromUnsignedLong(attr->val.number);
		case KDUMP_ADDRESS:
			return PyLong_FromUnsignedLong(attr->val.address);
		case KDUMP_STRING:
			return PyString_FromString(attr->val.string);
		case KDUMP_DIRECTORY:
			return attr_dir_new(kdumpfile, ref);
		case KDUMP_BITMAP:
			return bmp_new(attr->val.bitmap);
		case KDUMP_BLOB:
			return blob_new(attr->val.blob);
		default:
			PyErr_SetString(PyExc_RuntimeError, "Unhandled attr type");
			return NULL;
	}
}

PyDoc_STRVAR(get_addrxlat_ctx__doc__,
"K.get_addrxlat_ctx() -> addrxlat.Context");

static PyObject *
get_addrxlat_ctx(PyObject *_self, PyObject *args)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;
	addrxlat_ctx_t *ctx;
	kdump_status status;

	status = kdump_get_addrxlat(self->ctx, &ctx, NULL);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status),
				kdump_get_err(self->ctx));
		return NULL;
	}
	return addrxlat_API->Context_FromPointer(self->addrxlat_convert, ctx);
}

PyDoc_STRVAR(get_addrxlat_sys__doc__,
"K.get_addrxlat_sys() -> addrxlat.System");

static PyObject *
get_addrxlat_sys(PyObject *_self, PyObject *args)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;
	addrxlat_sys_t *sys;
	kdump_status status;

	status = kdump_get_addrxlat(self->ctx, NULL, &sys);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status),
				kdump_get_err(self->ctx));
		return NULL;
	}
	return addrxlat_API->System_FromPointer(self->addrxlat_convert, sys);
}

static PyMethodDef kdumpfile_object_methods[] = {
	{ "from_pointer", (PyCFunction)kdumpfile_from_pointer,
		METH_VARARGS | METH_KEYWORDS | METH_CLASS,
		kdumpfile_from_pointer__doc__ },
	{"read",      (PyCFunction) kdumpfile_read, METH_VARARGS | METH_KEYWORDS,
		read__doc__},
	{ "get_addrxlat_ctx", get_addrxlat_ctx, METH_NOARGS,
	  get_addrxlat_ctx__doc__ },
	{ "get_addrxlat_sys", get_addrxlat_sys, METH_NOARGS,
	  get_addrxlat_sys__doc__ },
	{NULL}
};

static PyObject *
kdumpfile_getattr(PyObject *_self, void *_data)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;

	if (!self->attr)
		Py_RETURN_NONE;

	Py_INCREF(self->attr);
	return self->attr;
}

static void
cleanup_exceptions(void)
{
	Py_XDECREF(OSErrorException);
	Py_XDECREF(NotImplementedException);
	Py_XDECREF(NoDataException);
	Py_XDECREF(CorruptException);
	Py_XDECREF(InvalidException);
	Py_XDECREF(NoKeyException);
	Py_XDECREF(EOFException);
	Py_XDECREF(BusyException);
	Py_XDECREF(AddressTranslationException);
}

static int lookup_exceptions (void)
{
	PyObject *mod = PyImport_ImportModule("kdumpfile.exceptions");
	if (!mod)
		return -1;

#define lookup_exception(name)				\
do {							\
	name = PyObject_GetAttrString(mod, #name);	\
	if (!name)					\
		goto fail;				\
} while(0)

	lookup_exception(OSErrorException);
	lookup_exception(NotImplementedException);
	lookup_exception(NoDataException);
	lookup_exception(CorruptException);
	lookup_exception(InvalidException);
	lookup_exception(NoKeyException);
	lookup_exception(EOFException);
	lookup_exception(BusyException);
	lookup_exception(AddressTranslationException);
#undef lookup_exception

	Py_XDECREF(mod);
	return 0;
fail:
	cleanup_exceptions();
	Py_XDECREF(mod);
	return -1;
}

static void
cleanup_views(void)
{
	Py_XDECREF(attr_viewkeys_type);
	Py_XDECREF(attr_viewvalues_type);
	Py_XDECREF(attr_viewitems_type);
	Py_XDECREF(attr_viewdict_type);
}

static int
lookup_views(void)
{
	PyObject *mod = PyImport_ImportModule("kdumpfile.views");
	if (!mod)
		return -1;

#define lookup_view(name)						\
	do {								\
		name ## _type = PyObject_GetAttrString(mod, #name);	\
		if (! name ## _type)					\
				goto fail;				\
	} while(0)

	lookup_view(attr_viewkeys);
	lookup_view(attr_viewvalues);
	lookup_view(attr_viewitems);
	lookup_view(attr_viewdict);
#undef lookup_view

	Py_DECREF(mod);
	return 0;

fail:
	cleanup_views();
	Py_DECREF(mod);
	return -1;
}

static PyGetSetDef kdumpfile_object_getset[] = {
	{ "attr", kdumpfile_getattr, NULL,
	  "Access to libkdumpfile attributes" },
	{ NULL }
};

PyDoc_STRVAR(kdumpfile_addrxlat_convert__doc__,
"addrxlat C type converter");

static PyMemberDef kdumpfile_members[] = {
	{ "addrxlat_convert", T_OBJECT,
	  offsetof(kdumpfile_object, addrxlat_convert), 0,
	  kdumpfile_addrxlat_convert__doc__ },
	{ NULL }
};

static PyTypeObject kdumpfile_object_type = 
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".kdumpfile",		/* tp_name*/
	sizeof (kdumpfile_object),      /* tp_basicsize*/ 
	0,                              /* tp_itemsize*/ 
	kdumpfile_dealloc,              /* tp_dealloc*/ 
	0,                              /* tp_print*/ 
	0,                              /* tp_getattr*/ 
	0,                              /* tp_setattr*/ 
	0,                              /* tp_compare*/ 
	0,                              /* tp_repr*/ 
	0,                              /* tp_as_number*/ 
	0,                              /* tp_as_sequence*/
	0,                              /* tp_as_mapping*/ 
	0,                              /* tp_hash */ 
	0,                              /* tp_call*/ 
	0,                              /* tp_str*/ 
	0,                              /* tp_getattro*/ 
	0,                              /* tp_setattro*/ 
	0,                              /* tp_as_buffer*/ 
	Py_TPFLAGS_DEFAULT |
	    Py_TPFLAGS_BASETYPE,	/* tp_flags*/
	"kdumpfile - native extension", /* tp_doc */
	0,                              /* tp_traverse */ 
	0,                              /* tp_clear */ 
	0,                              /* tp_richcompare */ 
	0,                              /* tp_weaklistoffset */ 
	0,                              /* tp_iter */ 
	0,                              /* tp_iternext */ 
	kdumpfile_object_methods,       /* tp_methods */ 
	kdumpfile_members,		/* tp_members */
	kdumpfile_object_getset,        /* tp_getset */ 
	0,                              /* tp_base */
	0,                              /* tp_dict */
	0,                              /* tp_descr_get */
	0,                              /* tp_descr_set */
	0, 				  /* tp_dictoffset */
	0,                              /* tp_init */
	0,                              /* tp_alloc */
	kdumpfile_new,                  /* tp_new */
};

/* Attribute dictionary type */

typedef struct {
	PyObject_HEAD
	kdumpfile_object *kdumpfile;
	kdump_attr_ref_t baseref;
} attr_dir_object;

static PyObject *attr_iter_new(attr_dir_object *attr_dir,
			       PyTypeObject *itertype);

static int
lookup_attribute(attr_dir_object *self, PyObject *key, kdump_attr_ref_t *ref)
{
	PyObject *stringkey;
#if PY_MAJOR_VERSION >= 3
	PyObject *bytes;
#endif
	char *keystr = NULL;
	int ret;

	if (!PyString_Check(key)) {
		stringkey = PyObject_Str(key);
		if (!stringkey)
			return -1;
	} else
		stringkey = key;

	ret = -1;
#if PY_MAJOR_VERSION >= 3
	bytes = PyUnicode_AsASCIIString(stringkey);
	if (bytes) {
		keystr = PyBytes_AsString(bytes);
	}
#else
	keystr = PyString_AsString(stringkey);
#endif
	if (keystr) {
		kdump_ctx_t *ctx = self->kdumpfile->ctx;
		kdump_status status;

		status = kdump_sub_attr_ref(ctx, &self->baseref, keystr, ref);
		if (status == KDUMP_OK)
			ret = 1;
		else if (status == KDUMP_ERR_NOKEY)
			ret = 0;
		else
			PyErr_SetString(exception_map(status),
					kdump_get_err(ctx));
	}

	if (stringkey != key)
		Py_DECREF(stringkey);

#if PY_MAJOR_VERSION >= 3
	Py_DECREF(bytes);
#endif

	return ret;
}

static int
get_attribute(attr_dir_object *self, PyObject *key, kdump_attr_ref_t *ref)
{
	int ret = lookup_attribute(self, key, ref);
	if (ret == 0)
		PyErr_SetObject(PyExc_KeyError, key);
	return ret;
}

static int
attr_dir_contains(PyObject *_self, PyObject *key)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_attr_ref_t ref;
	int ret;

	ret = lookup_attribute(self, key, &ref);
	if (ret > 0) {
		ret = kdump_attr_ref_isset(&ref);
		kdump_attr_unref(self->kdumpfile->ctx, &ref);
	}
	return ret;
}

static PySequenceMethods attr_dir_as_sequence = {
	0,			/* sq_length */
	0,			/* sq_concat */
	0,			/* sq_repeat */
	0,			/* sq_item */
	0,			/* sq_slice */
	0,			/* sq_ass_item */
	0,			/* sq_ass_slice */
	attr_dir_contains,	/* sq_contains */
	0,			/* sq_inplace_concat */
	0,			/* sq_inplace_repeat */
};

static Py_ssize_t
attr_dir_length(PyObject *_self)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx_t *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_status status;
	Py_ssize_t len = 0;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != KDUMP_OK)
		goto err;

	while (iter.key) {
		++len;
		status = kdump_attr_iter_next(ctx, &iter);
		if (status != KDUMP_OK)
			break;
	}
	kdump_attr_iter_end(ctx, &iter);
	if (status != KDUMP_OK)
		goto err;

	return len;

 err:
	PyErr_SetString(exception_map(status), kdump_get_err(ctx));
	return -1;
}

static PyObject *
attr_dir_subscript(PyObject *_self, PyObject *key)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx_t *ctx;
	kdump_attr_t attr;
	kdump_attr_ref_t ref;
	kdump_status status;

	if (get_attribute(self, key, &ref) <= 0)
		return NULL;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &ref, &attr);
	if (status == KDUMP_OK)
		return attr_new(self->kdumpfile, &ref, &attr);

	if (status == KDUMP_ERR_NODATA)
		PyErr_SetObject(PyExc_KeyError, key);
	else
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));

	kdump_attr_unref(ctx, &ref);
	return NULL;
}

static PyObject *
object2attr(PyObject *value, kdump_attr_ref_t *ref, kdump_attr_t *attr)
{
	unsigned PY_LONG_LONG num;
	PyObject *conv;
#if PY_MAJOR_VERSION >= 3
	PyObject *bytes;
#endif

	attr->type = value
		? kdump_attr_ref_type(ref)
		: KDUMP_NIL;

	conv = value;
	switch (attr->type) {
	case KDUMP_NIL:		/* used for deletions */
		break;

	case KDUMP_DIRECTORY:
		/* TODO: We may want to enforce a specific type or even
		 * a specific value for directory instantiation.
		 */
		break;

	case KDUMP_NUMBER:
	case KDUMP_ADDRESS:
		if (PyLong_Check(value)) {
			num = PyLong_AsUnsignedLongLong(value);
			if (PyErr_Occurred())
				return NULL;
#if PY_MAJOR_VERSION < 3
		} else if (PyInt_Check(value)) {
			num = PyInt_AsLong(value);
			if (PyErr_Occurred())
				return NULL;
#endif
		} else {
			PyErr_Format(PyExc_TypeError,
				     "need an integer, not %.200s",
				     Py_TYPE(value)->tp_name);
			return NULL;
		}

		if (attr->type == KDUMP_NUMBER)
			attr->val.number = num;
		else
			attr->val.address = num;
		break;

	case KDUMP_STRING:
		if (!PyString_Check(value)) {
			conv = PyObject_Str(value);
			if (!conv)
				return NULL;
		}

#if PY_MAJOR_VERSION >= 3
		bytes = PyUnicode_AsASCIIString(conv);
		if (!bytes)
			return NULL;

		attr->val.string  = PyBytes_AsString(bytes);
		if (!attr->val.string)
			return NULL;
#else
		if (! (attr->val.string = PyString_AsString(conv)) )
			return NULL;
#endif
		break;

	default:
		PyErr_SetString(PyExc_TypeError,
				"assignment to an unknown type");
		return NULL;
	}

	return conv;
}

static int
set_attribute(attr_dir_object *self, kdump_attr_ref_t *ref, PyObject *value)
{
	PyObject *conv;
	kdump_ctx_t *ctx;
	kdump_attr_t attr;
	kdump_status status;

	conv = object2attr(value, ref, &attr);
	if (value && !conv)
		return -1;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_set(ctx, ref, &attr);
	if (conv != value)
		Py_XDECREF(conv);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		return -1;
	}

	return 0;
}

static int
attr_dir_ass_subscript(PyObject *_self, PyObject *key, PyObject *value)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_attr_ref_t ref;
	int ret = -1;

	if (get_attribute(self, key, &ref) <= 0)
		return ret;

	ret = set_attribute(self, &ref, value);
	kdump_attr_unref(self->kdumpfile->ctx, &ref);
	return ret;
}

static PyMappingMethods attr_dir_as_mapping = {
	attr_dir_length,	/* mp_length */
	attr_dir_subscript,	/* mp_subscript */
	attr_dir_ass_subscript,	/* mp_ass_subscript */
};

static PyObject *
attr_dir_new(kdumpfile_object *kdumpfile, const kdump_attr_ref_t *baseref)
{
	attr_dir_object *self;

	self = PyObject_GC_New(attr_dir_object, &attr_dir_object_type);
	if (self == NULL)
		return NULL;

	Py_INCREF((PyObject*)kdumpfile);
	self->kdumpfile = kdumpfile;
	self->baseref = *baseref;
	PyObject_GC_Track(self);
	return (PyObject*)self;
}

static void
attr_dir_dealloc(PyObject *_self)
{
	attr_dir_object *self = (attr_dir_object*)_self;

	PyObject_GC_UnTrack(self);
	kdump_attr_unref(self->kdumpfile->ctx, &self->baseref);
	Py_XDECREF((PyObject*)self->kdumpfile);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
attr_dir_traverse(PyObject *_self, visitproc visit, void *arg)
{
	attr_dir_object *self = (attr_dir_object*)_self;

	Py_VISIT((PyObject*)self->kdumpfile);
	return 0;
}

static PyObject *
attr_dir_getattro(PyObject *_self, PyObject *name)
{
	PyObject *ret;
#if PY_MAJOR_VERSION >= 3
	PyObject *temp;
#endif

	ret = PyObject_GenericGetAttr(_self, name);
	if (ret || !PyErr_ExceptionMatches(PyExc_AttributeError))
		return ret;

	PyErr_Clear();
	ret = attr_dir_subscript(_self, name);
	if (ret || !PyErr_ExceptionMatches(PyExc_KeyError))
		return ret;

#if PY_MAJOR_VERSION >= 3
	temp = PyUnicode_AsASCIIString(name);
	if (!temp)
		return NULL;
#endif

	PyErr_Format(PyExc_AttributeError,
		     "'%.50s' object has no attribute '%.400s'",
		     Py_TYPE(_self)->tp_name,
#if PY_MAJOR_VERSION >= 3
			 PyString_AS_STRING(temp)
#else
		     PyString_AS_STRING(name)
#endif
			);


#if PY_MAJOR_VERSION >= 3
	Py_DECREF(temp);
#endif
	return NULL;
}

static int
attr_dir_setattro(PyObject *_self, PyObject *name, PyObject *value)
{
	int ret;
#if PY_MAJOR_VERSION >= 3
	PyObject *temp;
#endif

	ret = PyObject_GenericSetAttr(_self, name, value);
	if (!ret || !PyErr_ExceptionMatches(PyExc_AttributeError))
		return ret;

	PyErr_Clear();
	ret = attr_dir_ass_subscript(_self, name, value);
	if (!ret || !PyErr_ExceptionMatches(PyExc_KeyError))
		return ret;

#if PY_MAJOR_VERSION >= 3
	temp = PyUnicode_AsASCIIString(name);
#endif
	PyErr_Format(PyExc_AttributeError,
		     "'%.50s' object has no attribute '%.400s'",
		     Py_TYPE(_self)->tp_name,
#if PY_MAJOR_VERSION >= 3
			 PyString_AS_STRING(temp)
#else
			 PyString_AS_STRING(name)
#endif
			);
#if PY_MAJOR_VERSION >= 3
	Py_DECREF(temp);
#endif
	return -1;
}

PyDoc_STRVAR(get__doc__,
"D.get(k[,d]) -> D[k] if k in D, else d.  d defaults to None.");

static PyObject *
attr_dir_get(PyObject *_self, PyObject *args)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	PyObject *key, *failobj;
	kdump_ctx_t *ctx;
	kdump_attr_ref_t ref;
	kdump_attr_t attr;
	kdump_status status;
	int res;

	failobj = Py_None;
	if (!PyArg_UnpackTuple(args, "get", 1, 2, &key, &failobj))
		return NULL;

	res = lookup_attribute(self, key, &ref);
	if (res < 0)
		return NULL;
	else if (res == 0)
		goto notfound;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &ref, &attr);
	if (status == KDUMP_OK)
		return attr_new(self->kdumpfile, &ref, &attr);

	if (status != KDUMP_ERR_NODATA) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		return NULL;
	}

 notfound:
	Py_INCREF(failobj);
	return failobj;
}

PyDoc_STRVAR(setdefault_doc__,
"D.setdefault(k[,d]) -> D.get(k,d), also set D[k]=d if k not in D");

static PyObject *
dict_setdefault(PyObject *_self, PyObject *args)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	PyObject *key, *failobj;
	PyObject *val = NULL;
	kdump_ctx_t *ctx;
	kdump_attr_ref_t ref;
	kdump_attr_t attr;
	kdump_status status;

	failobj = Py_None;
	if (!PyArg_UnpackTuple(args, "setdefault", 1, 2, &key, &failobj))
		return NULL;

	if (get_attribute(self, key, &ref) <= 0)
		return NULL;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &ref, &attr);
	if (status == KDUMP_OK)
		val = attr_new(self->kdumpfile, &ref, &attr);
	else if (status == KDUMP_ERR_NODATA)
		val = (set_attribute(self, &ref, failobj) == 0)
			? failobj
			: NULL;
	else {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		val = NULL;
	}
	kdump_attr_unref(ctx, &ref);

	Py_XINCREF(val);
	return val;
}

static PyObject *
attr_dir_merge(PyObject *_self, PyObject *map)
{
	PyObject *keys, *iter;
	PyObject *key, *value;
	int status;

	keys = PyMapping_Keys(map);
	if (!keys)
	    return NULL;
	iter = PyObject_GetIter(keys);
	Py_DECREF(keys);
	if (!iter)
	    return NULL;

	for (key = PyIter_Next(iter); key; key = PyIter_Next(iter)) {
		value = PyObject_GetItem(map, key);
		if (!value)
			goto err;

		status = attr_dir_ass_subscript(_self, key, value);
		Py_DECREF(value);
		if (status < 0)
			goto err;
		Py_DECREF(key);
	}
	Py_DECREF(iter);
	if (PyErr_Occurred())
		return NULL;

	return Py_None;

 err:
	Py_DECREF(iter);
	Py_DECREF(key);
	return NULL;
}

static PyObject *
attr_dir_merge_seq2(PyObject *_self, PyObject *seq2)
{
	PyObject *iter, *elem;
	Py_ssize_t i;		/* index into seq2 of current element */
	PyObject *fast;		/* item as a 2-tuple or 2-list */

	iter = PyObject_GetIter(seq2);
	if (!iter)
		return NULL;

	i = 0;
	while ( (elem = PyIter_Next(iter)) ) {
		PyObject *key, *value;
		Py_ssize_t n;
		int status;

		/* Convert item to sequence, and verify length 2. */
		fast = PySequence_Fast(elem, "");
		if (!fast) {
			if (PyErr_ExceptionMatches(PyExc_TypeError))
				PyErr_Format(PyExc_TypeError,
					     "cannot convert attribute update"
					     " sequence element #%zd"
					     " to a sequence", i);
			goto err;
		}
		n = PySequence_Fast_GET_SIZE(fast);
		if (n != 2) {
			PyErr_Format(PyExc_ValueError,
				     "attribute update sequence element #%zd "
				     "has length %zd; 2 is required",
				     i, n);
			goto err;
		}

		/* Update/merge with this (key, value) pair. */
		key = PySequence_Fast_GET_ITEM(fast, 0);
		value = PySequence_Fast_GET_ITEM(fast, 1);
		status = attr_dir_ass_subscript(_self, key, value);
		if (status < 0)
			goto err;
		Py_DECREF(fast);
		Py_DECREF(elem);
		++i;
	}
	Py_DECREF(iter);

	return PyErr_Occurred()
		? NULL
		: Py_None;

 err:
	Py_XDECREF(fast);
	Py_DECREF(elem);
	Py_DECREF(iter);
	return NULL;
}

PyDoc_STRVAR(update__doc__,
"D.update([E, ]**F) -> None.  Update D from dict/iterable E and F.\n"
"If E present and has a .keys() method, does:     for k in E: D[k] = E[k]\n"
"If E present and lacks .keys() method, does:     for (k, v) in E: D[k] = v\n"
"In either case, this is followed by: for k in F: D[k] = F[k]");

static PyObject *
attr_dir_update(PyObject *_self, PyObject *args, PyObject *kwds)
{
	PyObject *arg = NULL;
	PyObject *result;

	if (!PyArg_UnpackTuple(args, "update", 0, 1, &arg))
		return NULL;

	result = (arg == NULL)
		? Py_None
		: (PyObject_HasAttrString(arg, "keys")
		   ? attr_dir_merge(_self, arg)
		   : attr_dir_merge_seq2(_self, arg));

	if (result && kwds != NULL)
		result = attr_dir_merge(_self, kwds);
	return result;
}

PyDoc_STRVAR(clear__doc__,
"D.clear() -> None.  Remove all items from D.");

static PyObject *
attr_dir_clear(PyObject *_self, PyObject *args)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx_t *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_attr_t attr;
	kdump_status status;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != KDUMP_OK)
		goto err_noiter;

	attr.type = KDUMP_NIL;
	while (iter.key) {
		status = kdump_attr_ref_set(ctx, &iter.pos, &attr);
		if (status != KDUMP_OK)
			goto err;
		status = kdump_attr_iter_next(ctx, &iter);
		if (status != KDUMP_OK)
			goto err;
	}

	kdump_attr_iter_end(ctx, &iter);
	Py_RETURN_NONE;

 err:
	kdump_attr_iter_end(ctx, &iter);
 err_noiter:
	PyErr_SetString(exception_map(status), kdump_get_err(ctx));
	return NULL;
}

#if PY_MAJOR_VERSION < 3
static PyObject *
attr_dir_repr(PyObject *_self)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx_t *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_status status;
	PyObject *s, *temp, *temp2;
	PyObject *colon = NULL, *pieces = NULL;
	PyObject *result = NULL;
	int res;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		return NULL;
	}

	if (!iter.key) {
		result = PyString_FromFormat("%s({})",
					     Py_TYPE(_self)->tp_name);
		goto out;
	}

	colon = PyString_FromString(": ");
	if (!colon)
		goto out;

	pieces = PyList_New(0);
	if (!pieces)
		goto out;

	while (iter.key) {
		s = PyString_FromString(iter.key);
		if (!s)
			goto out;
		temp = attr_dir_subscript(_self, s);
		if (!temp) {
			Py_DECREF(s);
			goto out;
		}
		PyString_Concat(&s, colon);
		temp2 = PyObject_Repr(temp);
		PyString_Concat(&s, temp2);
		Py_DECREF(temp);
		Py_DECREF(temp2);
		if (!s)
			goto out;

		res = PyList_Append(pieces, s);
		Py_DECREF(s);
		if (res <0)
			goto out;

		status = kdump_attr_iter_next(ctx, &iter);
		if (status != KDUMP_OK) {
			PyErr_SetString(exception_map(status),
					kdump_get_err(ctx));
			goto out;
		}
	}

	s = PyString_FromFormat("%s({", Py_TYPE(_self)->tp_name);
	if (!s)
		goto out;
	temp = PyList_GET_ITEM(pieces, 0);
	PyString_Concat(&s, temp);
	PyList_SET_ITEM(pieces, 0, s);
	if (!s)
		goto out;

	s = PyString_FromString("})");
	if (!s)
		goto out;
	temp = PyList_GET_ITEM(pieces, PyList_GET_SIZE(pieces) - 1);
	PyString_Concat(&temp, s);
	PyList_SET_ITEM(pieces, PyList_GET_SIZE(pieces) - 1, temp);
	if (!temp)
		goto out;

	s = PyString_FromString(", ");
	if (!s)
		goto out;
	result = _PyString_Join(s, pieces);
	Py_DECREF(s);

 out:
	kdump_attr_iter_end(ctx, &iter);
	Py_XDECREF(pieces);
	Py_XDECREF(colon);
	return result;
}
#endif

static int
attr_dir_print(PyObject *_self, FILE *fp, int flags)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx_t *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_status status;
	PyObject *s, *temp;
	int res;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		return -1;
	}

	Py_BEGIN_ALLOW_THREADS
	fprintf(fp, "%s({", Py_TYPE(_self)->tp_name);
	Py_END_ALLOW_THREADS

	while (iter.key) {
		s = PyString_FromString(iter.key);
		if (!s)
			goto err;
		res = PyObject_Print(s, fp, 0);
		if (res != 0) {
			Py_DECREF(s);
			goto err;
		}

		Py_BEGIN_ALLOW_THREADS
		fputs(": ", fp);
		Py_END_ALLOW_THREADS

		temp = attr_dir_subscript(_self, s);
		Py_DECREF(s);
		if (!temp)
			goto err;
		res = PyObject_Print(temp, fp, 0);
		Py_DECREF(temp);
		if (res != 0)
			goto err;

		status = kdump_attr_iter_next(ctx, &iter);
		if (status != KDUMP_OK) {
			PyErr_SetString(exception_map(status),
					kdump_get_err(ctx));
			goto err;
		}

		if (iter.key) {
			Py_BEGIN_ALLOW_THREADS
			fputs(", ", fp);
			Py_END_ALLOW_THREADS
		}
	}

	kdump_attr_iter_end(ctx, &iter);

	Py_BEGIN_ALLOW_THREADS
	fputs("})", fp);
	Py_END_ALLOW_THREADS

	return 0;

 err:
	kdump_attr_iter_end(ctx, &iter);
	return -1;
}

static PyObject *
attr_iterkey_new(PyObject *_self)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	return attr_iter_new(self, &attr_iterkey_object_type);
}

PyDoc_STRVAR(iterkeys__doc__,
"D.iterkeys() -> an iterator over the keys of D");

static PyObject *
attr_dir_iterkeys(PyObject *_self, PyObject *arg)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	return attr_iter_new(self, &attr_iterkey_object_type);
}

PyDoc_STRVAR(itervalues__doc__,
"D.itervalues() -> an iterator over the values of D");

static PyObject *
attr_dir_itervalues(PyObject *_self, PyObject *arg)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	return attr_iter_new(self, &attr_itervalue_object_type);
}

PyDoc_STRVAR(iteritems__doc__,
"D.iteritems() -> an iterator over the (key, value) items of D");

static PyObject *
attr_dir_iteritems(PyObject *_self, PyObject *arg)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	return attr_iter_new(self, &attr_iteritem_object_type);
}

static PyObject *
attr_dir_make_list(PyObject *iter)
{
	PyObject *list, *object;
	iternextfunc iternext;

	if (!iter)
		return NULL;

	list = PyList_New(0);
	if (!list)
		goto err_iter;

	iternext = Py_TYPE(iter)->tp_iternext;
	while ( (object = iternext(iter)) )
		if (PyList_Append(list, object))
			goto err_list;

	if (PyErr_Occurred())
		goto err_list;

	Py_DECREF(iter);
	return list;

 err_list:
	Py_DECREF(list);
 err_iter:
	Py_DECREF(iter);
	return NULL;
}

PyDoc_STRVAR(keys__doc__,
"D.keys() -> list of D's keys");

static PyObject *
attr_dir_keys(PyObject *_self, PyObject *arg)
{
	return attr_dir_make_list(attr_dir_iterkeys(_self, arg));
}

PyDoc_STRVAR(values__doc__,
"D.values() -> list of D's values");

static PyObject *
attr_dir_values(PyObject *_self, PyObject *arg)
{
	return attr_dir_make_list(attr_dir_itervalues(_self, arg));
}

PyDoc_STRVAR(items__doc__,
"D.items() -> list of D's (key, value) pairs, as 2-tuples");

static PyObject *
attr_dir_items(PyObject *_self, PyObject *arg)
{
	return attr_dir_make_list(attr_dir_iteritems(_self, arg));
}

static PyObject *
attr_dir_view(PyObject *_self, PyObject *viewtype)
{
	PyObject *args, *result;

	args = Py_BuildValue("(O)", _self);
	if (!args)
		return NULL;
	result = PyObject_CallObject(viewtype, args);
	Py_DECREF(args);
	return result;
}

PyDoc_STRVAR(viewkeys__doc__,
"D.viewkeys() -> a set-like object providing a view on D's keys");

static PyObject *
attr_dir_viewkeys(PyObject *_self, PyObject *args)
{
	return attr_dir_view(_self, attr_viewkeys_type);
}

PyDoc_STRVAR(viewvalues__doc__,
"D.viewvalues() -> an object providing a view on D's values");

static PyObject *
attr_dir_viewvalues(PyObject *_self, PyObject *args)
{
	return attr_dir_view(_self, attr_viewvalues_type);
}

PyDoc_STRVAR(viewitems__doc__,
"D.viewitems() -> a set-like object providing a view on D's items");

static PyObject *
attr_dir_viewitems(PyObject *_self, PyObject *args)
{
	return attr_dir_view(_self, attr_viewitems_type);
}

PyDoc_STRVAR(viewdict__doc__,
"D.viewdict() -> a dict-like object providing a view on D");

static PyObject *
attr_dir_viewdict(PyObject *_self, PyObject *args)
{
	return attr_dir_view(_self, attr_viewdict_type);
}

PyDoc_STRVAR(copy__doc__,
"D.copy() -> a shallow dict copy of D");

static PyObject *
attr_dir_copy(PyObject *_self, PyObject *args)
{
	PyObject *dict = PyDict_New();
	if (!dict)
		return NULL;
	if (PyDict_Merge(dict, _self, 1) != 0) {
		Py_DECREF(dict);
		return NULL;
	}
	return dict;
}

PyDoc_STRVAR(dict__doc__,
"D.dict() -> a dict with a deep copy of D's attributes");

static PyObject *
attr_dir_dict(PyObject *_self, PyObject *args)
{
	PyObject *view;
	PyObject *dict;

	view = attr_dir_viewdict(_self, NULL);
	if (!view)
		return NULL;
	dict = PyDict_New();
	if (!dict)
		goto err;
	if (PyDict_Merge(dict, view, 1) != 0)
		goto err_dict;
	Py_DECREF(view);
	return dict;

 err_dict:
	Py_DECREF(dict);
 err:
	Py_DECREF(view);
	return NULL;
}

static PyMethodDef attr_dir_methods[] = {
	{"get",		attr_dir_get,		METH_VARARGS,
	 get__doc__},
	{"setdefault",	dict_setdefault,	METH_VARARGS,
	 setdefault_doc__},
	{"update",	(PyCFunction)attr_dir_update, METH_VARARGS | METH_KEYWORDS,
	 update__doc__},
	{"clear",	attr_dir_clear,		METH_NOARGS,
	 clear__doc__},
	{"iterkeys",	attr_dir_iterkeys,	METH_NOARGS,
	 iterkeys__doc__},
	{"itervalues",	attr_dir_itervalues,	METH_NOARGS,
	 itervalues__doc__},
	{"iteritems",	attr_dir_iteritems,	METH_NOARGS,
	 iteritems__doc__},
	{"keys",	attr_dir_keys,		METH_NOARGS,
	 keys__doc__},
	{"values",	attr_dir_values,	METH_NOARGS,
	 values__doc__},
	{"items",	attr_dir_items,		METH_NOARGS,
	 items__doc__},
	{"viewkeys",	attr_dir_viewkeys,	METH_NOARGS,
	 viewkeys__doc__},
	{"viewvalues",	attr_dir_viewvalues,	METH_NOARGS,
	 viewvalues__doc__},
	{"viewitems",	attr_dir_viewitems,	METH_NOARGS,
	 viewitems__doc__},
	{"viewdict",	attr_dir_viewdict,	METH_NOARGS,
	 viewdict__doc__},
	{"copy",	attr_dir_copy,		METH_NOARGS,
	 copy__doc__},
	{"dict",	attr_dir_dict,		METH_NOARGS,
	 dict__doc__},
	{NULL,		NULL}	/* sentinel */
};

static PyTypeObject attr_dir_object_type =
{
	PyVarObject_HEAD_INIT (NULL, 0)
	MOD_NAME ".attr_dir",
	sizeof(attr_dir_object),	/* tp_basicsize*/
	sizeof(char),			/* tp_itemsize*/
	/* methods */
	attr_dir_dealloc,		/* tp_dealloc*/
	attr_dir_print,			/* tp_print*/
	0,				/* tp_getattr*/
	0,				/* tp_setattr*/
	0,				/* tp_compare*/
#if PY_MAJOR_VERSION < 3
	attr_dir_repr,			/* tp_repr */
#else
	0,
#endif
	0,				/* tp_as_number*/
	&attr_dir_as_sequence,		/* tp_as_sequence*/
	&attr_dir_as_mapping,		/* tp_as_mapping*/
	0,				/* tp_hash */
	0,				/* tp_call*/
	0,				/* tp_str*/
	attr_dir_getattro,		/* tp_getattro*/
	attr_dir_setattro,		/* tp_setattro*/
	0,				/* tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC, /* tp_flags*/
	0,				/* tp_doc */
	attr_dir_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	attr_iterkey_new,		/* tp_iter */
	0,				/* tp_iternext */
	attr_dir_methods,		/* tp_methods */
};

/* Attribute iterator type */

typedef struct {
	PyObject_HEAD
	kdumpfile_object *kdumpfile;
	kdump_attr_iter_t iter;
} attr_iter_object;

static PyObject *
attr_iter_new(attr_dir_object *attr_dir, PyTypeObject *itertype)
{
	attr_iter_object *self;
	kdump_ctx_t *ctx = attr_dir->kdumpfile->ctx;
	kdump_status status;

	self = PyObject_GC_New(attr_iter_object, itertype);
	if (self == NULL)
		return NULL;

	status = kdump_attr_ref_iter_start(ctx, &attr_dir->baseref,
					   &self->iter);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		Py_DECREF(self);
		return NULL;
	}

	Py_INCREF((PyObject*)attr_dir->kdumpfile);
	self->kdumpfile = attr_dir->kdumpfile;
	PyObject_GC_Track(self);
	return (PyObject*)self;
}

static void
attr_iter_dealloc(PyObject *_self)
{
	attr_iter_object *self = (attr_iter_object*)_self;
	kdump_ctx_t *ctx = self->kdumpfile->ctx;

	kdump_attr_iter_end(ctx, &self->iter);
	PyObject_GC_UnTrack(self);
	Py_XDECREF((PyObject*)self->kdumpfile);
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static int
attr_iter_traverse(PyObject *_self, visitproc visit, void *arg)
{
	attr_iter_object *self = (attr_iter_object*)_self;

	Py_VISIT((PyObject*)self->kdumpfile);
	return 0;
}

static PyObject *
attr_iter_advance(attr_iter_object *self, PyObject *ret)
{
	kdump_ctx_t *ctx = self->kdumpfile->ctx;
	kdump_status status;

	status = kdump_attr_iter_next(ctx, &self->iter);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		Py_XDECREF(ret);
		ret = NULL;
	}

	return ret;
}

static PyObject *
attr_iterkey_next(PyObject *_self)
{
	attr_iter_object *self = (attr_iter_object*)_self;

	if (!self->iter.key)
		return NULL;

	return attr_iter_advance(self, PyString_FromString(self->iter.key));
}

static PyObject *
attr_itervalue_next(PyObject *_self)
{
	attr_iter_object *self = (attr_iter_object*)_self;
	kdump_ctx_t *ctx;
	kdump_attr_t attr;
	kdump_status status;
	PyObject *value;

	if (!self->iter.key)
		return NULL;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &self->iter.pos, &attr);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		return NULL;
	}

	value = attr_new(self->kdumpfile, &self->iter.pos, &attr);
	return attr_iter_advance(self, value);
}

static PyObject *
attr_iteritem_next(PyObject *_self)
{
	attr_iter_object *self = (attr_iter_object*)_self;
	kdump_ctx_t *ctx;
	kdump_attr_t attr;
	kdump_status status;
	PyObject *key, *value, *result;

	if (!self->iter.key)
		return NULL;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &self->iter.pos, &attr);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status), kdump_get_err(ctx));
		return NULL;
	}

	result = PyTuple_New(2);
	if (result == NULL)
		return NULL;
	key = PyString_FromString(self->iter.key);
	if (!key)
		goto err_result;
	value = attr_new(self->kdumpfile, &self->iter.pos, &attr);
	if (!value)
		goto err_key;

	PyTuple_SET_ITEM(result, 0, key);
	PyTuple_SET_ITEM(result, 1, value);
	return attr_iter_advance(self, result);

 err_key:
	Py_DECREF(key);
 err_result:
	Py_DECREF(result);
	return NULL;
}

static PyTypeObject attr_iterkey_object_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".attr_dir-keyiterator",
	sizeof(attr_iter_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	/* methods */
	attr_iter_dealloc,		/* tp_dealloc */
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
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC, /* tp_flags */
	0,				/* tp_doc */
	attr_iter_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	PyObject_SelfIter,		/* tp_iter */
	attr_iterkey_next,		/* tp_iternext */
};

static PyTypeObject attr_itervalue_object_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".attr_dir-valueiterator",
	sizeof(attr_iter_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	/* methods */
	attr_iter_dealloc,		/* tp_dealloc */
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
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC, /* tp_flags */
	0,				/* tp_doc */
	attr_iter_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	PyObject_SelfIter,		/* tp_iter */
	attr_itervalue_next,		/* tp_iternext */
};

static PyTypeObject attr_iteritem_object_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".attr_dir-itemiterator",
	sizeof(attr_iter_object),	/* tp_basicsize */
	0,				/* tp_itemsize */
	/* methods */
	attr_iter_dealloc,		/* tp_dealloc */
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
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC, /* tp_flags */
	0,				/* tp_doc */
	attr_iter_traverse,		/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	PyObject_SelfIter,		/* tp_iter */
	attr_iteritem_next,		/* tp_iternext */
};

typedef struct {
	PyObject_HEAD
	kdump_bmp_t *bmp;
} bmp_object;

PyDoc_STRVAR(bmp__doc__,
"bmp() -> dump bitmap");

static PyObject *
bmp_new(kdump_bmp_t *bmp)
{
	bmp_object *self;

	self = PyObject_New(bmp_object, &bmp_object_type);
	if (!self)
		return NULL;

	kdump_bmp_incref(bmp);
	self->bmp = bmp;

	return (PyObject*)self;
}

static void
bmp_dealloc(PyObject *_self)
{
	bmp_object *self = (bmp_object*)_self;

	if (self->bmp)
		kdump_bmp_decref(self->bmp);

	Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(bmp_get_bits__doc__,
"BMP.get_bits(first, last) -> byte array\n\
\n\
Get bitmap bits as a raw bitmap.");

static PyObject *
bmp_get_bits(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"first", "last", NULL};
	bmp_object *self = (bmp_object*)_self;
	unsigned long long first, last;
	PyObject *buffer;
	Py_ssize_t sz;
	kdump_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "KK:get_bits",
					 keywords, &first, &last))
		return NULL;

	buffer = PyByteArray_FromStringAndSize(NULL, 0);
	if (!buffer)
		return NULL;

	sz = (((last - first) | 7) + 1) / 8;
	if (PyByteArray_Resize(buffer, sz) < 0) {
		Py_DECREF(buffer);
		return NULL;
	}


	status = kdump_bmp_get_bits(
		self->bmp, first, last,
		(unsigned char*)PyByteArray_AS_STRING(buffer));
	if (status != KDUMP_OK) {
		Py_DECREF(buffer);
		PyErr_SetString(exception_map(status),
				kdump_bmp_get_err(self->bmp));
		return NULL;
	}

	return buffer;
}

PyDoc_STRVAR(bmp_find_set__doc__,
"BMP.find_set(idx) -> index\n\
\n\
Find the closest set bit in a bitmapm, starting at idx.");

static PyObject *
bmp_find_set(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"idx", NULL};
	bmp_object *self = (bmp_object*)_self;
	unsigned long long argidx;
	kdump_addr_t idx;
	kdump_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "K:find_set",
					 keywords, &argidx))
		return NULL;

	idx = argidx;
	status = kdump_bmp_find_set(self->bmp, &idx);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status),
				kdump_bmp_get_err(self->bmp));
		return NULL;
	}

	return PyLong_FromUnsignedLong(idx);
}

PyDoc_STRVAR(bmp_find_clear__doc__,
"BMP.find_clear(idx) -> index\n\
\n\
Find the closest zero bit in a bitmapm, starting at idx.");

static PyObject *
bmp_find_clear(PyObject *_self, PyObject *args, PyObject *kwargs)
{
	static char *keywords[] = {"idx", NULL};
	bmp_object *self = (bmp_object*)_self;
	unsigned long long argidx;
	kdump_addr_t idx;
	kdump_status status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "K:find_clear",
					 keywords, &argidx))
		return NULL;

	idx = argidx;
	status = kdump_bmp_find_clear(self->bmp, &idx);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status),
				kdump_bmp_get_err(self->bmp));
		return NULL;
	}

	return PyLong_FromUnsignedLong(idx);
}

static PyMethodDef bmp_methods[] = {
	{ "get_bits", (PyCFunction)bmp_get_bits,
	  METH_VARARGS | METH_KEYWORDS,
	  bmp_get_bits__doc__ },
	{ "find_set", (PyCFunction)bmp_find_set,
	  METH_VARARGS | METH_KEYWORDS,
	  bmp_find_set__doc__ },
	{ "find_clear", (PyCFunction)bmp_find_clear,
	  METH_VARARGS | METH_KEYWORDS,
	  bmp_find_clear__doc__ },
	{NULL,		NULL}	/* sentinel */
};

static PyTypeObject bmp_object_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".bmp",		/* tp_name */
	sizeof (bmp_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	bmp_dealloc,			/* tp_dealloc */
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
	bmp__doc__,			/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	bmp_methods,			/* tp_methods */
};

typedef struct {
	PyObject_HEAD
	kdump_blob_t *blob;
} blob_object;

PyDoc_STRVAR(blob__doc__,
"blob() -> dump blob");

static PyObject *
blob_new(kdump_blob_t *blob)
{
	blob_object *self;

	self = PyObject_New(blob_object, &blob_object_type);
	if (!self)
		return NULL;

	kdump_blob_incref(blob);
	self->blob = blob;

	return (PyObject*)self;
}

static void
blob_dealloc(PyObject *_self)
{
	blob_object *self = (blob_object*)_self;

	if (self->blob)
		kdump_blob_decref(self->blob);

	Py_TYPE(self)->tp_free((PyObject*)self);
}

PyDoc_STRVAR(blob_set__doc__,
"BLOB.set(buffer)\n\
\n\
Replace blob contents with a new value. The object given as\n\
argument must implement the buffer protocol.");

static PyObject *
blob_set(PyObject *_self, PyObject *args)
{
	blob_object *self = (blob_object*)_self;
	kdump_status status;
	Py_buffer view;
	PyObject *arg;
	void *buffer;

	if (!PyArg_ParseTuple(args, "O:set", &arg))
		return NULL;

	if (!PyObject_CheckBuffer(arg)) {
		PyErr_Format(PyExc_TypeError,
			     "Type %.100s doesn't support the buffer API",
			     Py_TYPE(arg)->tp_name);
		return NULL;
	}

	if (PyObject_GetBuffer(arg, &view, PyBUF_FULL_RO) < 0)
		return NULL;
	buffer = malloc(view.len);
	if (!buffer)
		goto buf_fail;
	if (PyBuffer_ToContiguous(buffer, &view, view.len, 'C') < 0)
		goto buf_fail;
	PyBuffer_Release(&view);

	status = kdump_blob_set(self->blob, buffer, view.len);
	if (status != KDUMP_OK) {
		PyErr_SetString(exception_map(status),
				kdump_strerror(status));
		free(buffer);
		return NULL;
	}
	return Py_None;

 buf_fail:
	PyBuffer_Release(&view);
	return NULL;
}

static PyMethodDef blob_methods[] = {
	{ "set", blob_set, METH_VARARGS,
	  blob_set__doc__ },
	{NULL,		NULL}	/* sentinel */
};

static int
blob_getbuffer(PyObject *_self, Py_buffer *view, int flags)
{
	blob_object *self = (blob_object*)_self;
	void *buffer;
	size_t size;
	int ret;

	buffer = kdump_blob_pin(self->blob);
	if (view == NULL)
		return 0;

	size = kdump_blob_size(self->blob);
	ret = PyBuffer_FillInfo(view, _self, buffer, size, 0, flags);
	if (ret < 0)
		kdump_blob_unpin(self->blob);
	return ret;
}

static void
blob_releasebuffer(PyObject *_self, Py_buffer *view)
{
	blob_object *self = (blob_object*)_self;
	kdump_blob_unpin(self->blob);
}

static PyBufferProcs blob_as_buffer = {
#if PY_MAJOR_VERSION < 3
    (readbufferproc)NULL,
    (writebufferproc)NULL,
    (segcountproc)NULL,
    (charbufferproc)NULL,
#endif
    blob_getbuffer,
    blob_releasebuffer,
};

static PyTypeObject blob_object_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
	MOD_NAME ".blob",		/* tp_name */
	sizeof (blob_object),		/* tp_basicsize */
	0,				/* tp_itemsize */
	blob_dealloc,			/* tp_dealloc */
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
	&blob_as_buffer,		/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT
#if PY_MAJOR_VERSION < 3
	    | Py_TPFLAGS_HAVE_NEWBUFFER
#endif
	    | Py_TPFLAGS_BASETYPE,	/* tp_flags */
	blob__doc__,			/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	blob_methods,			/* tp_methods */
};

struct constdef {
	const char *name;
	int value;
};

static const struct constdef kdumpfile_constants[] = {
	{ "KDUMP_KPHYSADDR", KDUMP_KPHYSADDR },
        { "KDUMP_MACHPHYSADDR", KDUMP_MACHPHYSADDR },
	{ "KDUMP_KVADDR", KDUMP_KVADDR },
	{ NULL, 0 }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef kdumpfile_moddef = {
        PyModuleDef_HEAD_INIT,
        MOD_NAME,            /* m_name */
        MOD_DOC,             /* m_doc */
        -1,                  /* m_size */
        NULL,                /* m_methods */
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
PyInit__kdumpfile (void)
#else
init_kdumpfile (void)
#endif
{
	PyObject *mod;
	const struct constdef *cdef;
	int ret;

	if (PyType_Ready(&kdumpfile_object_type) < 0)
		return MOD_ERROR_VAL;
	if (PyType_Ready(&attr_dir_object_type) < 0)
		return MOD_ERROR_VAL;
	if (PyType_Ready(&attr_iterkey_object_type) < 0)
		return MOD_ERROR_VAL;
	if (PyType_Ready(&attr_itervalue_object_type) < 0)
		return MOD_ERROR_VAL;
	if (PyType_Ready(&attr_iteritem_object_type) < 0)
		return MOD_ERROR_VAL;
	if (PyType_Ready(&bmp_object_type) < 0)
		return MOD_ERROR_VAL;
	if (PyType_Ready(&blob_object_type) < 0)
		return MOD_ERROR_VAL;

#if PY_MAJOR_VERSION >= 3
	mod = PyModule_Create(&kdumpfile_moddef);
#else
	mod = Py_InitModule3(MOD_NAME, NULL, MOD_DOC);
#endif
	if (!mod)
		goto fail;

	Py_INCREF((PyObject *)&kdumpfile_object_type);
	ret = PyModule_AddObject(mod, "kdumpfile",
				 (PyObject*)&kdumpfile_object_type);
	if (ret)
		goto fail;

	Py_INCREF((PyObject *)&attr_dir_object_type);
	ret = PyModule_AddObject(mod, "attr_dir",
				 (PyObject*)&attr_dir_object_type);
	if (ret)
		goto fail;

	Py_INCREF((PyObject *)&bmp_object_type);
	ret = PyModule_AddObject(mod, "bmp",
				 (PyObject*)&bmp_object_type);
	if (ret)
		goto fail;

	Py_INCREF((PyObject *)&blob_object_type);
	ret = PyModule_AddObject(mod, "blob",
				 (PyObject*)&blob_object_type);
	if (ret)
		goto fail;

	for (cdef = kdumpfile_constants; cdef->name; ++cdef)
		if (PyModule_AddIntConstant(mod, cdef->name, cdef->value))
			goto fail;

	ret = lookup_exceptions();
	if (ret)
		goto fail;

	ret = lookup_views();
	if (ret)
		goto fail;

	addrxlat_API = (struct addrxlat_CAPI*)
		PyCapsule_Import(addrxlat_CAPSULE_NAME, 0);
	if (!addrxlat_API)
		goto fail;
	if (addrxlat_API->ver < addrxlat_CAPI_VER) {
		PyErr_Format(PyExc_RuntimeError,
			     "addrxlat CAPI ver >= %lu needed, %lu found",
			     addrxlat_CAPI_VER, addrxlat_API->ver);
		goto fail;
	}

	return MOD_SUCCESS_VAL(mod);

fail:
	cleanup_exceptions();
	cleanup_views();
	Py_XDECREF(mod);
	return MOD_ERROR_VAL;
}
