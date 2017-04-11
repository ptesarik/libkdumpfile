#!/usr/bin/env python
# vim:sw=4 ts=4 et

KDUMP_OK           = 0
KDUMP_ERR_SYSTEM   = 1
KDUMP_ERR_NOTIMPL  = 2
KDUMP_ERR_NODATA   = 3
KDUMP_ERR_CORRUPT  = 4
KDUMP_ERR_INVALID  = 5
KDUMP_ERR_EOF      = 6
KDUMP_ERR_NOKEY    = 7
KDUMP_ERR_BUSY     = 8
KDUMP_ERR_ADDRXLAT = 9

class KDumpBaseException(Exception):
    error = None

class OSErrorException(KDumpBaseException):
    error = KDUMP_ERR_SYSTEM

class NotImplementedException(KDumpBaseException):
    error = KDUMP_ERR_NOTIMPL

class NoDataException(KDumpBaseException):
    error = KDUMP_ERR_NODATA

class CorruptException(KDumpBaseException):
    error = KDUMP_ERR_CORRUPT

class InvalidException(KDumpBaseException):
    error = KDUMP_ERR_INVALID

class NoKeyException(KDumpBaseException):
    error = KDUMP_ERR_NOKEY

class EOFException(KDumpBaseException):
    error = KDUMP_ERR_EOF

class BusyException(KDumpBaseException):
    error = KDUMP_ERR_BUSY

class AddressTranslationException(KDumpBaseException):
    error = KDUMP_ERR_ADDRXLAT
