#!/usr/bin/env python
# vim:sw=4 ts=4 et

import sys

import _addrxlat
from _addrxlat import BaseException

_exceptions = (
    ('NotImplementedError', _addrxlat.ERR_NOTIMPL, (NotImplementedError,)),
    ('NotPresentError', _addrxlat.ERR_NOTPRESENT),
    ('InvalidError', _addrxlat.ERR_INVALID),
    ('MemoryError', _addrxlat.ERR_NOMEM, (MemoryError,)),
    ('NoDataError', _addrxlat.ERR_NODATA),
    ('NoMethodError', _addrxlat.ERR_NOMETH),
)

def _check_kwargs(kwargs):
    if 'status' in kwargs:
        raise TypeError("'status' is an invalid keyword argument for this function")

def new_exception(name, status, addbases=()):
    '''Create an addrxlat exception for a given status code.
    The new exception is derived from BaseException, but you may specify
    additional base classes with addbases.
    '''

    def __init__(self, *args, **kwargs):
        _check_kwargs(kwargs)
        BaseException.__init__(self, status, *args, **kwargs)

    def __repr__(self):
        "x.__repr__() <==> repr(x)"
        return "%s%r" % (self.__class__.__name__, self.args[1:])

    di = {
        '__doc__' : name + '([message])' + '''

        If message is not specified, use the default error message.
        ''',
        'status' : status,
        '__init__' : __init__,
        '__repr__' : __repr__,
    }

    return type(name, (BaseException,) + addbases, di)

def get_exception(status, *args, **kwargs):
    '''get_exception(status[, message])

    Get an appropriate exception for the given status. If there is no
    specific exception, make an instance of BaseException.
    '''
    _check_kwargs(kwargs)
    for exc in BaseException.__subclasses__():
        if status == exc.status:
            return exc(*args, **kwargs)
    return BaseException(status, *args, **kwargs)

for _exc in _exceptions:
    _cls = new_exception(*_exc)
    sys.modules[__name__].__dict__[_cls.__name__] = _cls

# Free up temporary variables
del _exc, _cls, _exceptions
