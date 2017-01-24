## Process this file with automake to create Makefile.in
## Automake input file for libaddrxlat.
##
## Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>
##
## This file is part of libaddrxlat.
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

AM_CFLAGS = -fvisibility=hidden

lib_LTLIBRARIES = libaddrxlat.la
libaddrxlat_la_SOURCES = \
	meth.c \
	ctx.c \
	vtop.c \
	map.c \
	opt.c \
	sys.c \
	ppc64.c \
	ia32.c \
	s390x.c \
	x86_64.c

EXTRA_libaddrxlat_la_DEPENDENCIES = libaddrxlat.map

libaddrxlat_la_LDFLAGS = -version-info 0:0:0
libaddrxlat_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libaddrxlat.map

include_HEADERS = \
	addrxlat.h

noinst_HEADERS = \
	addrxlat-priv.h

dist_noinst_DATA = \
	libaddrxlat.map
