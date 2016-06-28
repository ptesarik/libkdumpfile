#include <Python.h>
#include <kdumpfile.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
	PyObject_HEAD
	kdump_ctx *ctx;
	PyObject *file;
	PyObject *cb_get_symbol;
	PyObject *attr;
} kdumpfile_object;

static PyObject *SysErrException;
static PyObject *UnsupportedException;
static PyObject *NoDataException;
static PyObject *DataErrException;
static PyObject *InvalidException;
static PyObject *NoKeyException;
static PyObject *EOFException;

static PyTypeObject attr_dir_object_type;
static PyTypeObject attr_iterkey_object_type;
static PyTypeObject attr_itervalue_object_type;
static PyTypeObject attr_iteritem_object_type;

static PyObject *attr_dir_new(kdumpfile_object *kdumpfile,
			      const kdump_attr_ref_t *baseref);

static PyObject *
exception_map(kdump_status status)
{
	switch (status) {
	case kdump_syserr:      return SysErrException;
	case kdump_unsupported: return UnsupportedException;
	case kdump_nodata:      return NoDataException;
	case kdump_dataerr:     return DataErrException;
	case kdump_invalid:     return InvalidException;
	case kdump_nokey:       return NoKeyException;
	case kdump_eof:         return EOFException;
	/* If we raise an exception with status == kdump_ok, it's a bug. */
	case kdump_ok:
	default:                return PyExc_RuntimeError;
	};
}

static kdump_status cb_get_symbol(kdump_ctx *ctx, const char *name, kdump_addr_t *addr)
{
	kdumpfile_object *self;
	PyObject *ret;

	self = (kdumpfile_object*)kdump_get_priv(ctx);

	if (! self->cb_get_symbol) {
		PyErr_SetString(PyExc_RuntimeError, "Callback symbol-resolving function not set");
		return kdump_nodata;
	}

	ret = PyObject_CallFunction(self->cb_get_symbol, "s", name);

	if (! PyLong_Check(ret)) {
		PyErr_SetString(PyExc_RuntimeError, "Callback of symbol-resolving function returned no long");
		return kdump_nodata;
	}

	*addr = PyLong_AsUnsignedLongLong(ret);;

	Py_XDECREF(ret);

	return kdump_ok;
}

static PyObject *
kdumpfile_new (PyTypeObject *type, PyObject *args, PyObject *kw)
{
	kdumpfile_object *self = NULL;
	static char *keywords[] = {"file", NULL};
	kdump_attr_ref_t rootref;
	kdump_status status;
	PyObject *fo = NULL;
	int fd;

	if (!PyArg_ParseTupleAndKeywords (args, kw, "O!", keywords,
				    &PyFile_Type, &fo))
		    return NULL;

	self = (kdumpfile_object*) type->tp_alloc (type, 0);
	if (!self)
		return NULL;

	self->ctx = kdump_alloc();
	if (!self->ctx) {
		PyErr_SetString(PyExc_MemoryError,
				"Couldn't allocate kdump context");
		goto fail;
	}

	status = kdump_init(self->ctx);
	if (status != kdump_ok) {
		PyErr_Format(SysErrException,
			     "Couldn't initialize kdump context: %s",
			     kdump_err_str(self->ctx));
		goto fail;
	}

	fd = fileno(PyFile_AsFile(fo));
	status = kdump_set_fd(self->ctx, fd);
	if (status != kdump_ok) {
		PyErr_Format(exception_map(status),
			     "Cannot open dump: %s", kdump_err_str(self->ctx));
		goto fail;
	}

	self->file = fo;
	Py_INCREF(fo);

	self->cb_get_symbol = NULL;
	kdump_cb_get_symbol_val(self->ctx, cb_get_symbol);
	kdump_set_priv(self->ctx, self);

	status = kdump_attr_ref(self->ctx, NULL, &rootref);
	if (status != kdump_ok) {
		PyErr_Format(exception_map(status),
			     "Cannot reference root attribute: %s",
			     kdump_err_str(self->ctx));
		goto fail;
	}

	self->attr = attr_dir_new(self, &rootref);
	if (!self->attr) {
		kdump_attr_unref(self->ctx, &rootref);
		goto fail;
	}

	return (PyObject*)self;

fail:
	Py_XDECREF(self->attr);
	Py_XDECREF(self->file);
	Py_XDECREF(self);
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

	if (self->file) Py_XDECREF(self->file);
	Py_TYPE(self)->tp_free((PyObject*)self);
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
	status = kdump_readp(self->ctx, addrspace, addr,
			     PyByteArray_AS_STRING(obj), &r);
	if (status != kdump_ok) {
		Py_XDECREF(obj);
		PyErr_Format(exception_map(status), kdump_err_str(self->ctx));
		return NULL;
	}

	return obj;
}

static PyObject *
attr_new(kdumpfile_object *kdumpfile, kdump_attr_ref_t *ref, kdump_attr_t *attr)
{
	if (attr->type != kdump_directory)
		kdump_attr_unref(kdumpfile->ctx, ref);

	switch (attr->type) {
		case kdump_number:
			return PyLong_FromUnsignedLong(attr->val.number);
		case kdump_address:
			return PyLong_FromUnsignedLong(attr->val.address);
		case kdump_string:
			return PyString_FromString(attr->val.string);
		case kdump_directory:
			return attr_dir_new(kdumpfile, ref);
		default:
			PyErr_SetString(PyExc_RuntimeError, "Unhandled attr type");
			return NULL;
	}
}

PyDoc_STRVAR(vtop_init__doc__,
"Initialize virtual memory mapping");

static PyObject *kdumpfile_vtop_init(PyObject *_self, PyObject *args)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;

	kdump_vtop_init(self->ctx);

	Py_RETURN_NONE;
}

static PyMethodDef kdumpfile_object_methods[] = {
	{"read",      (PyCFunction) kdumpfile_read, METH_VARARGS | METH_KEYWORDS,
		read__doc__},
	{"vtop_init", (PyCFunction) kdumpfile_vtop_init, METH_NOARGS,
		vtop_init__doc__},
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

static PyObject *kdumpfile_get_symbol_func (PyObject *_self, void *_data)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;

	if (! self->cb_get_symbol)
		Py_RETURN_NONE;
	Py_INCREF(self->cb_get_symbol);

	return self->cb_get_symbol;
}

int kdumpfile_set_symbol_func(PyObject *_self, PyObject *_set, void *_data)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;

	if (! PyCallable_Check(_set)) {
		PyErr_SetString(PyExc_RuntimeError, "Argument must be callable");
		return 1;
	}

	if (self->cb_get_symbol)
		Py_XDECREF(self->cb_get_symbol);
	self->cb_get_symbol = _set;
	Py_INCREF(self->cb_get_symbol);
	return 0;
}

static void
cleanup_exceptions(void)
{
	Py_XDECREF(SysErrException);
	Py_XDECREF(UnsupportedException);
	Py_XDECREF(NoDataException);
	Py_XDECREF(DataErrException);
	Py_XDECREF(InvalidException);
	Py_XDECREF(NoKeyException);
	Py_XDECREF(EOFException);
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

	lookup_exception(SysErrException);
	lookup_exception(UnsupportedException);
	lookup_exception(NoDataException);
	lookup_exception(DataErrException);
	lookup_exception(InvalidException);
	lookup_exception(NoKeyException);
	lookup_exception(EOFException);
#undef lookup_exception

	Py_XDECREF(mod);
	return 0;
fail:
	cleanup_exceptions();
	Py_XDECREF(mod);
	return -1;
}


static PyGetSetDef kdumpfile_object_getset[] = {
	{ "attr", kdumpfile_getattr, NULL,
	  "Access to libkdumpfile attributes",
	  NULL },
	{ "symbol_func", kdumpfile_get_symbol_func, kdumpfile_set_symbol_func,
	  "Callback function called by libkdumpfile for symbol resolving",
	  NULL },
	{ NULL }
};

static PyTypeObject kdumpfile_object_type = 
{
	PyVarObject_HEAD_INIT(NULL, 0)
	"_kdumpfile.kdumpfile",         /* tp_name*/ 
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
	Py_TPFLAGS_DEFAULT,             /* tp_flags*/ 
	"kdumpfile",                    /* tp_doc */ 
	0,                              /* tp_traverse */ 
	0,                              /* tp_clear */ 
	0,                              /* tp_richcompare */ 
	0,                              /* tp_weaklistoffset */ 
	0,                              /* tp_iter */ 
	0,                              /* tp_iternext */ 
	kdumpfile_object_methods,       /* tp_methods */ 
	0,                              /* tp_members */ 
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
	char *keystr;
	int ret;

	if (!PyString_Check(key)) {
		stringkey = PyObject_Str(key);
		if (!stringkey)
			return -1;
	} else
		stringkey = key;

	ret = -1;

	keystr = PyString_AsString(stringkey);
	if (keystr) {
		kdump_ctx *ctx = self->kdumpfile->ctx;
		kdump_status status;

		status = kdump_sub_attr_ref(ctx, &self->baseref, keystr, ref);
		if (status == kdump_ok)
			ret = 1;
		else if (status == kdump_nokey)
			ret = 0;
		else
			PyErr_SetString(exception_map(status),
					kdump_err_str(ctx));
	}

	if (stringkey != key)
		Py_DECREF(stringkey);

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
		kdump_ctx *ctx = self->kdumpfile->ctx;
		kdump_attr_t attr;
		kdump_status status;

		status = kdump_attr_ref_get(ctx, &ref, &attr);
		kdump_attr_unref(ctx, &ref);
		if (status == kdump_nodata)
			ret = 0;
		else if (status != kdump_ok) {
			PyErr_SetString(exception_map(status),
					kdump_err_str(ctx));
			ret = -1;
		}
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
	kdump_ctx *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_status status;
	Py_ssize_t len = 0;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != kdump_ok)
		goto err;

	while (iter.key) {
		++len;
		status = kdump_attr_iter_next(ctx, &iter);
		if (status != kdump_ok)
			break;
	}
	kdump_attr_iter_end(ctx, &iter);
	if (status != kdump_ok)
		goto err;

	return len;

 err:
	PyErr_Format(exception_map(status), kdump_err_str(ctx));
	return -1;
}

static PyObject *
attr_dir_subscript(PyObject *_self, PyObject *key)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx *ctx;
	kdump_attr_t attr;
	kdump_attr_ref_t ref;
	kdump_status status;

	if (get_attribute(self, key, &ref) <= 0)
		return NULL;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &ref, &attr);
	if (status == kdump_ok)
		return attr_new(self->kdumpfile, &ref, &attr);

	if (status == kdump_nodata)
		PyErr_SetObject(PyExc_KeyError, key);
	else
		PyErr_SetString(exception_map(status), kdump_err_str(ctx));

	kdump_attr_unref(ctx, &ref);
	return NULL;
}

static PyObject *
object2attr(PyObject *value, kdump_attr_ref_t *ref, kdump_attr_t *attr)
{
	unsigned PY_LONG_LONG num;
	PyObject *conv;

	attr->type = value
		? kdump_attr_ref_type(ref)
		: kdump_nil;

	conv = value;
	switch (attr->type) {
	case kdump_nil:		/* used for deletions */
		break;

	case kdump_directory:
		/* TODO: We may want to enforce a specific type or even
		 * a specific value for directory instantiation.
		 */
		break;

	case kdump_number:
	case kdump_address:
		if (PyLong_Check(value)) {
			num = PyLong_AsUnsignedLongLong(value);
			if (PyErr_Occurred())
				return NULL;
		} else if (PyInt_Check(value)) {
			num = PyInt_AsLong(value);
			if (PyErr_Occurred())
				return NULL;
		} else {
			PyErr_Format(PyExc_TypeError,
				     "need an integer, not %.200s",
				     Py_TYPE(value)->tp_name);
			return NULL;
		}

		if (attr->type == kdump_number)
			attr->val.number = num;
		else
			attr->val.address = num;
		break;

	case kdump_string:
		if (!PyString_Check(value)) {
			conv = PyObject_Str(value);
			if (!conv)
				return NULL;
		}
		if (! (attr->val.string = PyString_AsString(conv)) )
			return NULL;
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
	kdump_ctx *ctx;
	kdump_attr_t attr;
	kdump_status status;

	conv = object2attr(value, ref, &attr);
	if (value && !conv)
		return -1;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_set(ctx, ref, &attr);
	if (conv != value)
		Py_XDECREF(conv);
	if (status != kdump_ok) {
		PyErr_SetString(exception_map(status), kdump_err_str(ctx));
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

	ret = PyObject_GenericGetAttr(_self, name);
	if (ret || !PyErr_ExceptionMatches(PyExc_AttributeError))
		return ret;

	PyErr_Clear();
	ret = attr_dir_subscript(_self, name);
	if (ret || !PyErr_ExceptionMatches(PyExc_KeyError))
		return ret;

	PyErr_Format(PyExc_AttributeError,
		     "'%.50s' object has no attribute '%.400s'",
		     Py_TYPE(_self)->tp_name, PyString_AS_STRING(name));
	return NULL;
}

static int
attr_dir_setattro(PyObject *_self, PyObject *name, PyObject *value)
{
	int ret;

	ret = PyObject_GenericSetAttr(_self, name, value);
	if (!ret || !PyErr_ExceptionMatches(PyExc_AttributeError))
		return ret;

	PyErr_Clear();
	ret = attr_dir_ass_subscript(_self, name, value);
	if (!ret || !PyErr_ExceptionMatches(PyExc_KeyError))
		return ret;

	PyErr_Format(PyExc_AttributeError,
		     "'%.50s' object has no attribute '%.400s'",
		     Py_TYPE(_self)->tp_name, PyString_AS_STRING(name));
	return -1;
}

PyDoc_STRVAR(get__doc__,
"D.get(k[,d]) -> D[k] if k in D, else d.  d defaults to None.");

static PyObject *
attr_dir_get(PyObject *_self, PyObject *args)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	PyObject *key, *failobj;
	kdump_ctx *ctx;
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
	if (status == kdump_ok)
		return attr_new(self->kdumpfile, &ref, &attr);

	if (status != kdump_nodata) {
		PyErr_SetString(exception_map(status), kdump_err_str(ctx));
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
	kdump_ctx *ctx;
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
	if (status == kdump_ok)
		val = attr_new(self->kdumpfile, &ref, &attr);
	else if (status == kdump_nodata)
		val = (set_attribute(self, &ref, failobj) == 0)
			? failobj
			: NULL;
	else {
		PyErr_SetString(exception_map(status), kdump_err_str(ctx));
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
	kdump_ctx *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_attr_t attr;
	kdump_status status;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != kdump_ok)
		goto err_noiter;

	attr.type = kdump_nil;
	while (iter.key) {
		status = kdump_attr_ref_set(ctx, &iter.pos, &attr);
		if (status != kdump_ok)
			goto err;
		status = kdump_attr_iter_next(ctx, &iter);
		if (status != kdump_ok)
			goto err;
	}

	kdump_attr_iter_end(ctx, &iter);
	Py_RETURN_NONE;

 err:
	kdump_attr_iter_end(ctx, &iter);
 err_noiter:
	PyErr_Format(exception_map(status), kdump_err_str(ctx));
	return NULL;
}

static PyObject *
attr_dir_repr(PyObject *_self)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_status status;
	PyObject *s, *temp;
	PyObject *colon = NULL, *pieces = NULL;
	PyObject *result = NULL;
	int res;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != kdump_ok) {
		PyErr_Format(exception_map(status), kdump_err_str(ctx));
		return NULL;
	}

	if (!iter.key) {
		result = PyString_FromString("{}");
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
		PyString_ConcatAndDel(&s, PyObject_Repr(temp));
		Py_DECREF(temp);
		if (!s)
			goto out;

		res = PyList_Append(pieces, s);
		Py_DECREF(s);
		if (res <0)
			goto out;

		status = kdump_attr_iter_next(ctx, &iter);
		if (status != kdump_ok) {
			PyErr_Format(exception_map(status), kdump_err_str(ctx));
			goto out;
		}
	}

	s = PyString_FromString("{");
	if (!s)
		goto out;
	temp = PyList_GET_ITEM(pieces, 0);
	PyString_ConcatAndDel(&s, temp);
	PyList_SET_ITEM(pieces, 0, s);
	if (!s)
		goto out;

	s = PyString_FromString("}");
	if (!s)
		goto out;
	temp = PyList_GET_ITEM(pieces, PyList_GET_SIZE(pieces) - 1);
	PyString_ConcatAndDel(&temp, s);
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

static int
attr_dir_print(PyObject *_self, FILE *fp, int flags)
{
	attr_dir_object *self = (attr_dir_object*)_self;
	kdump_ctx *ctx = self->kdumpfile->ctx;
	kdump_attr_iter_t iter;
	kdump_status status;
	PyObject *s, *temp;
	int res;

	status = kdump_attr_ref_iter_start(ctx, &self->baseref, &iter);
	if (status != kdump_ok) {
		PyErr_Format(exception_map(status), kdump_err_str(ctx));
		return -1;
	}

	Py_BEGIN_ALLOW_THREADS
	putc('{', fp);
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
		if (status != kdump_ok) {
			PyErr_Format(exception_map(status), kdump_err_str(ctx));
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
	putc('}', fp);
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
	{NULL,		NULL}	/* sentinel */
};

static PyTypeObject attr_dir_object_type =
{
	PyVarObject_HEAD_INIT (NULL, 0)
	"_kdumpfile.attribute-directory",
	sizeof(attr_dir_object),	/* tp_basicsize*/
	sizeof(char),			/* tp_itemsize*/
	/* methods */
	attr_dir_dealloc,		/* tp_dealloc*/
	attr_dir_print,			/* tp_print*/
	0,				/* tp_getattr*/
	0,				/* tp_setattr*/
	0,				/* tp_compare*/
	attr_dir_repr,			/* tp_repr */
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
	kdump_ctx *ctx = attr_dir->kdumpfile->ctx;
	kdump_status status;

	self = PyObject_GC_New(attr_iter_object, itertype);
	if (self == NULL)
		return NULL;

	status = kdump_attr_ref_iter_start(ctx, &attr_dir->baseref,
					   &self->iter);
	if (status != kdump_ok) {
		PyErr_Format(exception_map(status), kdump_err_str(ctx));
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
	kdump_ctx *ctx = self->kdumpfile->ctx;

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
	kdump_ctx *ctx = self->kdumpfile->ctx;
	kdump_status status;

	status = kdump_attr_iter_next(ctx, &self->iter);
	if (status != kdump_ok) {
		PyErr_Format(exception_map(status), kdump_err_str(ctx));
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
	kdump_ctx *ctx;
	kdump_attr_t attr;
	kdump_status status;
	PyObject *value;

	if (!self->iter.key)
		return NULL;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &self->iter.pos, &attr);
	if (status != kdump_ok) {
		PyErr_SetString(exception_map(status), kdump_err_str(ctx));
		return NULL;
	}

	value = attr_new(self->kdumpfile, &self->iter.pos, &attr);
	return attr_iter_advance(self, value);
}

static PyObject *
attr_iteritem_next(PyObject *_self)
{
	attr_iter_object *self = (attr_iter_object*)_self;
	kdump_ctx *ctx;
	kdump_attr_t attr;
	kdump_status status;
	PyObject *key, *value, *result;

	if (!self->iter.key)
		return NULL;

	ctx = self->kdumpfile->ctx;
	status = kdump_attr_ref_get(ctx, &self->iter.pos, &attr);
	if (status != kdump_ok) {
		PyErr_SetString(exception_map(status), kdump_err_str(ctx));
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
	"_kdumpfile.attribute-keyiterator",
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
	"_kdumpfile.attribute-valueiterator",
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
	"_kdumpfile.attribute-itemiterator",
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

struct constdef {
	const char *name;
	int value;
};

static const struct constdef kdumpfile_constants[] = {
	{ "KDUMP_KPHYSADDR", KDUMP_KPHYSADDR },
        { "KDUMP_MACHPHYSADDR", KDUMP_MACHPHYSADDR },
	{ "KDUMP_KVADDR", KDUMP_KVADDR },
	{ "KDUMP_XENVADDR", KDUMP_XENVADDR },
	{ NULL, 0 }
};

PyMODINIT_FUNC
init_kdumpfile (void)
{
	PyObject *mod;
	const struct constdef *cdef;
	int ret;

	if (PyType_Ready(&kdumpfile_object_type) < 0)
		return;
	if (PyType_Ready(&attr_dir_object_type) < 0)
		return;
	if (PyType_Ready(&attr_iterkey_object_type) < 0)
		return;
	if (PyType_Ready(&attr_itervalue_object_type) < 0)
		return;
	if (PyType_Ready(&attr_iteritem_object_type) < 0)
		return;

	ret = lookup_exceptions();
	if (ret)
		return;

	mod = Py_InitModule3("_kdumpfile", NULL,
			"kdumpfile - interface to libkdumpfile");
	if (!mod)
		goto fail;

	Py_INCREF((PyObject *)&kdumpfile_object_type);
	ret = PyModule_AddObject(mod, "kdumpfile",
				 (PyObject*)&kdumpfile_object_type);
	if (ret)
		goto fail;

	for (cdef = kdumpfile_constants; cdef->name; ++cdef)
		if (PyModule_AddIntConstant(mod, cdef->name, cdef->value))
			goto fail;

	return;
fail:
	cleanup_exceptions();
	Py_XDECREF(mod);
}
