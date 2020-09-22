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

AM_CPPFLAGS = -I$(top_builddir)/include
AM_CFLAGS = -fvisibility=hidden

lib_LTLIBRARIES = libaddrxlat.la
libaddrxlat_la_SOURCES = \
	ctx.c \
	map.c \
	opt.c \
	step.c \
	sys.c \
	aarch64.c \
	ia32.c \
	ppc64.c \
	s390x.c \
	x86_64.c

libaddrxlat_la_LDFLAGS = -version-info 1:0:0

if HAVE_LD_VERSION_SCRIPT
libaddrxlat_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libaddrxlat.map
EXTRA_libaddrxlat_la_DEPENDENCIES = libaddrxlat.map
endif

noinst_HEADERS = \
	addrxlat-priv.h

dist_noinst_DATA = \
	libaddrxlat.map
