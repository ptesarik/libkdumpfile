## Process this file with automake to create Makefile.in
## Configure input file for libkdumpfile.
##
## Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>
##
## This file is part of elfutils.
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

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libkdumpfile.la
libkdumpfile_la_SOURCES = \
	context.c \
	devmem.c \
	diskdump.c \
	elfdump.c \
	lkcd.c \
	notes.c \
	open.c \
	read.c \
	todo.c \
	util.c \
	vtop.c \
	x86_64.c

EXTRA_libkdumpfile_la_DEPENDENCIES = libkdumpfile.map

libkdumpfile_la_LDFLAGS = -version-info 1:0:1
libkdumpfile_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libkdumpfile.map

include_HEADERS = \
	kdumpfile.h

noinst_HEADERS = \
	kdumpfile-priv.h

dist_noinst_DATA = \
	COPYING.GPLv2 \
	COPYING.GPLv3 \
	COPYING.LGPLv3 \
	README.md \
	libkdumpfile.map
