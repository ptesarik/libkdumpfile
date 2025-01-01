## Process this file with automake to create Makefile.in
## Configure input file for libkdumpfile.
##
## Copyright (C) 2024 Petr Tesarik <ptesarik@suse.com>
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

AM_CPPFLAGS = -I$(top_builddir)/include \
	-DVER_MAJOR=$(KDUMPID_VER_MAJOR) \
	-DVER_MINOR=$(KDUMPID_VER_MINOR)

AM_CFLAGS = \
	$(ZLIB_CFLAGS)

LIBS = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la \
	$(top_builddir)/src/addrxlat/libaddrxlat.la \
	$(ZLIB_LIBS) \
	$(DIS_ASM_LIBS)

kdumpid_SOURCES = \
	main.c \
	util.c \
	search.c \
	ppc.c \
	ppc64.c \
	s390.c \
	x86.c

noinst_HEADERS = \
	kdumpid.h

bin_PROGRAMS = kdumpid

dist_man_MANS = kdumpid.1
