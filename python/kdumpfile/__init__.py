#!/usr/bin/env python

from _kdumpfile import *
from addrxlat import convert as _convert

class kdumpfile(kdumpfile):
    def __init__(self, *args, **kwargs):
        super(kdumpfile, self).__init__(*args, **kwargs)
        self.addrxlat_convert = _convert

import inspect as _inspect
for _cls in globals().values():
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
del _cls, _name, _method, _parent, _inspect
