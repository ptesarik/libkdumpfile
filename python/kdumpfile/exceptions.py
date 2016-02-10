#!/usr/bin/env python
# vim:sw=4 ts=4 et

KDUMP_OK          = 0
KDUMP_SYSERR      = 1
KDUMP_UNSUPPORTED = 2
KDUMP_NODATA      = 3
KDUMP_DATAERR     = 4
KDUMP_INVALID     = 5
KDUMP_NOKEY       = 6
KDUMP_EOF         = 7

class KDumpBaseException(Exception):
    error = None

class SysErrException(KDumpBaseException):
    error = KDUMP_SYSERR

class UnsupportedException(KDumpBaseException):
    error = KDUMP_UNSUPPORTED

class NoDataException(KDumpBaseException):
    error = KDUMP_NODATA

class DataErrException(KDumpBaseException):
    error = KDUMP_DATAERR

class InvalidException(KDumpBaseException):
    error = KDUMP_INVALID

class NoKeyException(KDumpBaseException):
    error = KDUMP_NOKEY

class EOFException(KDumpBaseException):
    error = KDUMP_EOF
