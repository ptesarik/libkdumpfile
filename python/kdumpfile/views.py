#!/usr/bin/env python
# vim:sw=4 ts=4 et

def issub(sub, other):
    for x in sub:
        if x not in other:
            return False
    return True

class attr_view(object):
    def __init__(self, dir):
        self.dir = dir

    def __repr__(self):
        return "%s(%s)" % (type(self).__name__, list(self).__repr__())

    def __len__(self):
        return len(self.dir)

class attr_setview(attr_view):
    def __eq__(self, other):
        return len(self) == len(other) and issub(other, self)

    def __ne__(self, other):
        return not __eq__(self, other)

    def __lt__(self, other):
        return len(self) < len(other) and issub(self, other)

    def __le__(self, other):
        return len(self) <= len(other) and issub(self, other)

    def __gt__(self, other):
        return len(self) > len(other) and issub(other, self)

    def __ge__(self, other):
        return len(self) >= len(other) and issub(other, self)

    def __or__(self, other):
        return set(self) | other

    def __and__(self, other):
        return set(self) & other

    def __sub__(self, other):
        return set(self) - other

    def __xor__(self, other):
        return set(self) ^ other

class attr_viewkeys(attr_setview):
    def __contains__(self, other):
        return other in self.dir

    def __iter__(self):
        return self.dir.iterkeys()

class attr_viewvalues(attr_view):
    def __iter__(self):
        return self.dir.itervalues()

class attr_viewitems(attr_setview):
    def __contains__(self, other):
        (key, val) = other
        return key in self.dir and self.dir[key] == val

    def __iter__(self):
        return self.dir.iteritems()
