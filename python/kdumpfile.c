#include "kdumpfile.h"
#include <stdio.h>
#include <stdlib.h>
#include <Python.h>

typedef struct {
	PyObject_HEAD
	kdump_ctx *ctx;
	PyObject *file;
} kdumpfile_object;

static PyObject *
kdumpfile_new (PyTypeObject *type, PyObject *args, PyObject *kw)
{
	kdumpfile_object *self = NULL;
	static char *keywords[] = {"file", NULL};
	const char *encoding = NULL, *user_encoding, *errors;
	int length = -1;
	PyObject *fo = NULL;
	FILE *f;
	int fd;

	if (!PyArg_ParseTupleAndKeywords (args, kw, "O!", keywords,
				    &PyFile_Type, &fo))
		    return NULL;

	Py_INCREF(fo);
	f = PyFile_AsFile(fo);

	if (! f || (fd = fileno(f)) < 0) {
		PyErr_SetString(PyExc_RuntimeError, "Not file");
		goto end;
	}
	self = (kdumpfile_object*) type->tp_alloc (type, 0);

	self->ctx = kdump_init();

	if (! self->ctx) {
		PyErr_SetString(PyExc_RuntimeError, "Cannot kdump_init()");
		Py_XDECREF(self);
		Py_XDECREF(fo);
		self = NULL;
		goto end;
	}

	if (kdump_set_fd(self->ctx, fd)) {
		PyErr_SetString(PyExc_RuntimeError, "Cannot kdump_set_fd()");
		kdump_free(self->ctx);
		Py_XDECREF(self);
		Py_XDECREF(fo);
		self = NULL;
		goto end;
	}
	self->file = fo;
end:
	return (PyObject*)self;
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
	self->ob_type->tp_free((PyObject*)self);
}


static PyObject *kdumpfile_read (PyObject *_self, PyObject *args, PyObject *kw)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;
	char *buff;
	kdump_paddr_t addr;
	int addrspace;
	unsigned long size;
	static char *keywords[] = {"addrspace", "address", "size", NULL};
	size_t r;
	
	if (! PyArg_ParseTupleAndKeywords(args, kw, "ikk:", keywords, &addrspace, &addr, &size)) {
		Py_RETURN_NONE;
	}

	if (! size) {
		PyErr_SetString(PyExc_RuntimeError, "Zero size");
		return NULL;
	}

	buff = malloc(size);

	if ((r = kdump_read(self->ctx, addrspace, addr, buff, size)) != size) {
		PyErr_SetString(PyExc_RuntimeError, "Cannot read");
		return NULL;
	}
	return PyByteArray_FromStringAndSize(buff, size);
}

static PyObject *kdumpfile_attr2obj(const struct kdump_attr *attr);

static int kdumpfile_dir2obj_it(void *data, const char *key, const struct kdump_attr *valp)
{
	PyObject *o = (PyObject*)data, *v = kdumpfile_attr2obj(valp);
	if (! v) return 1;
	PyDict_SetItem(data, PyString_FromString(key), v);
	return 0;
}

static PyObject *kdumpfile_dir2obj(const struct kdump_attr *attr)
{
	PyObject *dict;

	dict = PyDict_New();

	if (kdump_enum_attr_dir(attr, kdumpfile_dir2obj_it, dict)) {
		Py_XDECREF(dict);
		return NULL;
	}

	return dict;
}

static PyObject *kdumpfile_attr2obj(const struct kdump_attr *attr)
{
	switch (attr->type) {
		case kdump_number:
			return PyLong_FromUnsignedLong(attr->val.number);
		case kdump_address:
			return PyLong_FromUnsignedLong(attr->val.address);
		case kdump_string:
			return PyString_FromString(attr->val.string);
		case kdump_directory:
			return kdumpfile_dir2obj(attr);
		default:
			PyErr_SetString(PyExc_RuntimeError, "Unhandled attr type");
			return NULL;
	}
}

static PyObject *kdumpfile_getattr(PyObject *_self, PyObject *args, PyObject *kw)
{
	kdumpfile_object *self = (kdumpfile_object*)_self;
	static char *keywords[] = {"name", NULL};
	struct kdump_attr attr;
	const char *name;

	if (! PyArg_ParseTupleAndKeywords(args, kw, "s:", keywords, &name)) {
		Py_RETURN_NONE;
	}

	if (kdump_get_attr(self->ctx, name, &attr) != kdump_ok) {
		Py_RETURN_NONE;
	}

	return kdumpfile_attr2obj(&attr);

}
static PyMethodDef kdumpfile_object_methods[] = {
  { "read",(PyCFunction) kdumpfile_read, METH_VARARGS | METH_KEYWORDS,
    "read (addrtype, address) -> buffer.\n\
" },
    {"attr", (PyCFunction) kdumpfile_getattr, METH_VARARGS | METH_KEYWORDS,
	    "Get dump attribute: attr(name) -> value.\n"},
  {NULL}  
};

static PyObject *kdumpfile_getconst (PyObject *_self, void *_value)
{
	return PyInt_FromLong((long)_value);
}

static PyGetSetDef kdumpfile_object_getset[] = {
	{"KDUMP_KPHYSADDR", kdumpfile_getconst, NULL, 
		"KDUMP_KPHYSADDR - get by kernel physical address",
		(void*)KDUMP_KPHYSADDR},
	{"KDUMP_MACHPHYSADDR", kdumpfile_getconst, NULL, 
		"KDUMP_MACHPHYSADDR - get by machine physical address",
		(void*)KDUMP_MACHPHYSADDR},
	{"KDUMP_KVADDR", kdumpfile_getconst, NULL, 
		"KDUMP_KVADDR - get by kernel virtual address",
		(void*)KDUMP_KVADDR},
	{"KDUMP_XENVADDR", kdumpfile_getconst, NULL, 
		"KDUMP_XENKVADDR - get by xen virtual address",
		(void*)KDUMP_XENVADDR},

	{NULL}
};

PyTypeObject kdumpfile_object_type = 
{
	PyObject_HEAD_INIT (0) 
	0,
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

static PyMethodDef kdumpfile_module_methods[] = {
	{NULL}
};

PyMODINIT_FUNC
init_kdumpfile (void)
{
	PyObject *mod;

	if (PyType_Ready(&kdumpfile_object_type) < 0) 
		return;

	mod = Py_InitModule3("_kdumpfile", NULL,
			"kdumpfile - interface to libkdumpfile");

	if (!mod) return;

	Py_INCREF(&kdumpfile_object_type);
	PyModule_AddObject(mod, "kdumpfile", (PyObject*)&kdumpfile_object_type);
}
