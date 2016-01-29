## Process this file with automake to create Makefile.in
## Configure input file for libkdumpfile.
##
## Copyright (C) 2015 Petr Tesarik <ptesarik@suse.com>
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

lib_LTLIBRARIES = libkdumpfile.la
libkdumpfile_la_SOURCES = \
	attr.c \
	context.c \
	devmem.c \
	diskdump.c \
	elfdump.c \
	ia32.c \
	lkcd.c \
	notes.c \
	open.c \
	read.c \
	s390x.c \
	s390dump.c \
	todo.c \
	util.c \
	vtop.c \
	ppc64.c \
	x86_64.c

EXTRA_libkdumpfile_la_DEPENDENCIES = libkdumpfile.map

libkdumpfile_la_LDFLAGS = -version-info 6:0:0
libkdumpfile_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libkdumpfile.map

include_HEADERS = \
	kdumpfile.h

noinst_HEADERS = \
	kdumpfile-priv.h \
	global-attr.def \
	static-attr.def

dist_noinst_DATA = \
	libkdumpfile.map
