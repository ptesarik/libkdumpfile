## Process this file with automake to create Makefile.in
## Configure input file for libkdumpfile.
##
## Copyright (C) 2015 Ales Novak <alnovak@suse.cz>
##
## This file is part of libkdumpfile.
##
## This file is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## libkdumpfile is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
##

AM_CPPFLAGS = -I$(top_builddir)/include

pyexec_LTLIBRARIES = _addrxlat.la _kdumpfile.la

_addrxlat_la_SOURCES = addrxlat.c
_addrxlat_la_CFLAGS = $(PYTHON_CFLAGS)
_addrxlat_la_LDFLAGS = -module -avoid-version -export-symbols $(srcdir)/addrxlat.sym
_addrxlat_la_LIBADD = $(PYTHON_LIBS) $(top_builddir)/src/addrxlat/libaddrxlat.la

EXTRA__addrxlat_la_DEPENDENCIES = addrxlat.sym

_kdumpfile_la_SOURCES = kdumpfile.c
_kdumpfile_la_CFLAGS = $(PYTHON_CFLAGS) -I$(top_srcdir)/src
_kdumpfile_la_LDFLAGS = -module -avoid-version -export-symbols $(srcdir)/kdumpfile.sym
_kdumpfile_la_LIBADD = $(PYTHON_LIBS) $(top_builddir)/src/libkdumpfile.la

EXTRA__kdumpfile_la_DEPENDENCIES = kdumpfile.sym

dist_noinst_DATA = \
	addrxlat.sym \
	kdumpfile.sym \
	showxlat.py

noinst_HEADERS = \
	addrxlatmod.h

SUBDIRS = kdumpfile
