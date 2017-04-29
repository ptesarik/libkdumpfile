#!/usr/bin/env python
# vim:sw=4 ts=4 et

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

def new_exception(name, status, addbases=()):
    '''Create an addrxlat exception for a given status code.
    The new exception is derived from BaseException, but you may specify
    additional base classes with addbases.
    '''

    def __init__(self, *args, **kwargs):
        super(cls, self).__init__(status, *args, **kwargs)

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

    cls = type(name, (BaseException,) + addbases, di)
    return cls

def get_exception(status, *args, **kwargs):
    '''get_exception(status[, message])

    Get an appropriate exception for the given status. If there is no
    specific exception, make an instance of BaseException.
    '''
    for exc in BaseException.__subclasses__():
        if status == exc.status:
            return exc(*args, **kwargs)
    return BaseException(status, *args, **kwargs)

for _exc in _exceptions:
    _cls = new_exception(*_exc)
    globals()[_cls.__name__] = _cls

# Free up temporary variables
del _exc, _cls, _exceptions
