#!/usr/bin/env python
# vim:sw=4 ts=4 et

from _addrxlat import *
from addrxlat.exceptions import *

class FullAddress(FullAddress):
    def __init__(self, addrspace=NOADDR, addr=0, *args, **kwargs):
        super(FullAddress, self).__init__(*args, **kwargs)
        self.addrspace = addrspace
        self.addr = addr

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.addrspace, self.addr)

    def conv(self, addrspace, ctx, sys):
        status = super(FullAddress, self).conv(addrspace, ctx, sys)
        if status != OK:
            raise get_exception(status, ctx.get_err())

    def copy(self):
        "make a copy of self"
        return type(self)(addrspace=self.addrspace, addr=self.addr)

class Context(Context):
    def __init__(self, *args, **kwargs):
        super(Context, self).__init__(*args, **kwargs)
        self.convert = convert

    def __repr__(self):
        return '%s()' % (self.__class__.__name__,)

class Method(Method):
    def __init__(self, kind, target_as=NOADDR, param=(), *args, **kwargs):
        super(Method, self).__init__(*args, **kwargs)
        self.convert = convert
        self.target_as = target_as
        self.param = param

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__,
            self.kind,
            self.target_as,
            self.param)

class CustomMethod(CustomMethod):
    def __init__(self, target_as=NOADDR, *args, **kwargs):
        super(CustomMethod, self).__init__(*args, **kwargs)
        self.convert = convert
        self.target_as = target_as

    def __repr__(self):
        return '%s(%r)' % (
            self.__class__.__name__,
            self.target_as)

class LinearMethod(LinearMethod):
    def __init__(self, target_as=NOADDR, off=0, *args, **kwargs):
        super(LinearMethod, self).__init__(*args, **kwargs)
        self.convert = convert
        self.target_as = target_as
        self.off = off

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.off)

class PageTableMethod(PageTableMethod):
    def __init__(self, target_as=NOADDR, root=None, pte_format=PTE_NONE, fields=(), *args, **kwargs):
        super(PageTableMethod, self).__init__(*args, **kwargs)
        self.convert = convert
        self.target_as = target_as
        self.root = root
        self.pte_format = pte_format
        self.fields = fields

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.root,
            self.pte_format,
            self.fields)

class LookupMethod(LookupMethod):
    def __init__(self, target_as=NOADDR, endoff=0, tbl=(), *args, **kwargs):
        super(LookupMethod, self).__init__(*args, **kwargs)
        self.convert = convert
        self.target_as = target_as
        self.endoff = endoff
        self.tbl = tbl

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.endoff,
            self.tbl)

class MemoryArrayMethod(MemoryArrayMethod):
    def __init__(self, target_as=NOADDR, base=None, shift=0, elemsz=0, valsz=0, *args, **kwargs):
        super(MemoryArrayMethod, self).__init__(*args, **kwargs)
        self.convert = convert
        self.target_as = target_as
        self.base = base
        self.shift = shift
        self.elemsz = elemsz
        self.valsz = valsz

    def __repr__(self):
        return '%s(%r, %r, %r, %r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.base,
            self.shift,
            self.elemsz,
            self.valsz)

class Range(Range):
    def __init__(self, endoff=0, meth=SYS_METH_NONE, *args, **kwargs):
        super(Range, self).__init__(*args, **kwargs)
        self.endoff = endoff
        self.meth = meth

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.endoff,
            self.meth)

class Map(Map):
    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        self.convert = convert

    def __repr__(self):
        return '%s()' % (self.__class__.__name__)

    def set(self, addr, range):
        status = super(Map, self).set(addr, range)
        if status != OK:
            raise get_exception(status)

class System(System):
    def __init__(self, *args, **kwargs):
        super(System, self).__init__(*args, **kwargs)
        self.convert = convert

    def __repr__(self):
        return '%s()' % (self.__class__.__name__)

    def os_init(self, ctx, arch, *args, **kwargs):
        status = super(System, self).os_init(ctx, arch, *args, **kwargs)
        if status != OK:
            raise get_exception(status, ctx.get_err())

class Step(Step):
    def __init__(self, ctx, sys=None, meth=None, *args, **kwargs):
        super(Step, self).__init__(*args, **kwargs)
        self.convert = convert
        if sys is not None:
            self.sys = sys
        if meth is not None:
            self.meth = meth

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__,
            self.ctx,
            self.sys,
            self.meth)

    def launch(self, *args, **kwargs):
        status = super(Step, self).launch(*args, **kwargs)
        if status != OK:
            raise get_exception(status, self.ctx.get_err())

    def step(self, *args, **kwargs):
        status = super(Step, self).step(*args, **kwargs)
        if status != OK:
            raise get_exception(status, self.ctx.get_err())

    def walk(self, *args, **kwargs):
        status = super(Step, self).walk(*args, **kwargs)
        if status != OK:
            raise get_exception(status, self.ctx.get_err())

class Operator(Operator):
    def __init__(self, ctx, sys=None, caps=None):
        super(Operator, self).__init__()
        self.convert = convert
        if sys is not None:
            self.sys = sys
        if caps is not None:
            self.caps = caps

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.ctx,
            self.sys)

    def __call__(self, *args, **kwargs):
        (status, result) = super(Operator, self).__call__(*args, **kwargs)
        if status != OK:
            raise get_exception(status, self.ctx.get_err())
        return result

convert = TypeConvert()
convert.FullAddress = FullAddress
convert.Context = Context
convert.Method = Method
convert.CustomMethod = CustomMethod
convert.LinearMethod = LinearMethod
convert.PageTableMethod = PageTableMethod
convert.LookupMethod = LookupMethod
convert.MemoryArrayMethod = MemoryArrayMethod
convert.Range = Range
convert.Map = Map
convert.System = System
convert.Step = Step
convert.Operator = Operator

import inspect as _inspect
_values = globals().values()
if sys.version_info.major >= 3:
    _values = list(_values)
for _cls in _values:
    if not _inspect.isclass(_cls):
        continue
    for _name, _method in _inspect.getmembers(_cls, _inspect.ismethod):
        if _method.__doc__:
            continue
        for _parent in _inspect.getmro(_cls)[1:]:
            if hasattr(_parent, _name):
                _method.__func__.__doc__ = getattr(_parent, _name).__doc__
                break

# Free up temporary variables
del _values, _cls, _name, _method, _parent, _inspect
