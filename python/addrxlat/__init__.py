#!/usr/bin/env python
# vim:sw=4 ts=4 et

from _addrxlat import *
from addrxlat.exceptions import *

class FullAddress(FullAddress):
    def __init__(self, addrspace=NOADDR, addr=0):
        super(FullAddress, self).__init__()
        self.addrspace = addrspace
        self.addr = addr

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.addrspace, self.addr)

    def conv(self, addrspace, ctx, sys):
        status = super(FullAddress, self).conv(addrspace, ctx, sys)
        if status != OK:
            raise get_exception(status, ctx.get_err())

class Context(Context):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(Context, cls).__new__(cls, *args, **kwargs)

    def __repr__(self):
        return '%s()' % (self.__class__.__name__,)

class Description(Description):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(Description, cls).__new__(cls, *args, **kwargs)

    def __init__(self, kind, target_as=NOADDR, param=()):
        super(Description, self).__init__(kind)
        self.target_as = target_as
        self.param = param

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__,
            self.kind,
            self.target_as,
            self.param)

class LinearDescription(LinearDescription):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(LinearDescription, cls).__new__(cls, *args, **kwargs)

    def __init__(self, target_as=NOADDR, off=0):
        super(LinearDescription, self).__init__()
        self.target_as = target_as
        self.off = off

    def __repr__(self):
        return '%s(%r)' % (
            self.__class__.__name__,
            self.target_as,
            self.off)

class PageTableDescription(PageTableDescription):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(PageTableDescription, cls).__new__(cls, *args, **kwargs)

    def __init__(self, target_as=NOADDR, root=None, pte_format=PTE_NONE, fields=()):
        super(PageTableDescription, self).__init__()
        self.target_as = target_as
        if root is not None:
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

class LookupDescription(LookupDescription):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(LookupDescription, cls).__new__(cls, *args, **kwargs)

    def __init__(self, target_as=NOADDR, endoff=0, tbl=()):
        super(LookupDescription, self).__init__()
        self.target_as = target_as
        self.endoff = endoff
        self.tbl = tbl

    def __repr__(self):
        return '%s(%r, %r, %r)' % (
            self.__class__.__name__,
            self.target_as,
            self.endoff,
            self.tbl)

class MemoryArrayDescription(MemoryArrayDescription):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(MemoryArrayDescription, cls).__new__(cls, *args, **kwargs)

    def __init__(self, target_as=NOADDR, base=None, shift=0, elemsz=0, valsz=0):
        super(MemoryArrayDescription, self).__init__()
        self.target_as = target_as
        if base is not None:
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

class Method(Method):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(Method, cls).__new__(cls, *args, **kwargs)

    def __init__(self, desc=None):
        super(Method, self).__init__()
        if desc is not None:
            status = self.set_desc(desc)
            if status != OK:
                raise get_exception(status)

    def __repr__(self):
        return '%s(%r)' % (
            self.__class__.__name__,
            self.get_desc())

class Range(Range):
    def __init__(self, endoff=0, meth=None):
        super(Range, self).__init__()
        self.endoff = endoff
        self.meth = meth

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.endoff,
            self.meth)

class Map(Map):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(Map, cls).__new__(cls, *args, **kwargs)

    def __init__(self):
        super(Map, self).__init__()

    def __repr__(self):
        return '%s()' % (self.__class__.__name__)

class System(System):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(System, cls).__new__(cls, *args, **kwargs)

    def __init__(self):
        super(System, self).__init__()

    def __repr__(self):
        return '%s()' % (self.__class__.__name__)

    def init(self, *args, **kwargs):
        status = super(System, self).init(*args, **kwargs)
        if status != OK:
            ctx = kwargs.get('ctx', args[0])
            raise get_exception(status, ctx.get_err())

class Step(Step):
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(Step, cls).__new__(cls, *args, **kwargs)

    def __init__(self, ctx, sys=None, meth=None):
        super(Step, self).__init__(ctx)
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

    def launch_map(self, *args, **kwargs):
        status = super(Step, self).launch_map(*args, **kwargs)
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
    def __new__(cls, *args, **kwargs):
        kwargs['convert'] = _convert
        return super(Operator, cls).__new__(cls, *args, **kwargs)

    def __init__(self, ctx, sys=None, caps=0):
        super(Operator, self).__init__(ctx)
        if sys is not None:
            self.sys = sys
        self.caps = caps

    def __repr__(self):
        return '%s(%r, %r)' % (
            self.__class__.__name__,
            self.ctx,
            self.sys)

    def __call__(self, *args, **kwargs):
        status = super(Operator, self).__call__(*args, **kwargs)
        if status != OK:
            raise get_exception(status, self.ctx.get_err())
        return self.result

_convert = TypeConvert()
_convert.FullAddress = FullAddress
_convert.Context = Context
_convert.Description = Description
_convert.LinearDescription = LinearDescription
_convert.PageTableDescription = PageTableDescription
_convert.LookupDescription = LookupDescription
_convert.MemoryArrayDescription = MemoryArrayDescription
_convert.Method = Method
_convert.Range = Range
_convert.Map = Map
_convert.System = System
_convert.Step = Step
_convert.Operator = Operator
