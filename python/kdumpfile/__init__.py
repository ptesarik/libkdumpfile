#!/usr/bin/env python

from _kdumpfile import *
from addrxlat import convert as _convert
import sys

class kdumpfile(kdumpfile):
    def __init__(self, *args, **kwargs):
        self.addrxlat_convert = _convert

import inspect as _inspect
_values = globals().values()
if sys.version_info.major >= 3:
    _values = list(_values)
for _cls in _values:
    if not _inspect.isclass(_cls):
        continue
    for _name, _method in _inspect.getmembers(_cls,
                                              lambda x:
                                              (_inspect.ismethod(x),
                                               _inspect.isfunction(x))
                                              [sys.version_info.major >= 3]):
        if _method.__doc__:
            continue
        for _parent in _inspect.getmro(_cls)[1:]:
            if hasattr(_parent, _name):
                if _inspect.ismethod(_method):
                    _method.__func__.__doc__ = getattr(_parent, _name).__doc__
                else:
                    _method.__doc__ = getattr(_parent, _name).__doc__
                break

# Free up temporary variables
del _values, _cls, _name, _method, _parent, _inspect
