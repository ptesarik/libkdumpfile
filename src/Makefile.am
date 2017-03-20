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

SUBDIRS = addrxlat

AM_CPPFLAGS = -I$(top_builddir)/include
AM_CFLAGS = -fvisibility=hidden

lib_LTLIBRARIES = libkdumpfile.la
libkdumpfile_la_SOURCES = \
	attr.c \
	cache.c \
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
	vmcoreinfo.c \
	vtop.c \
	ppc64.c \
	x86_64.c

libkdumpfile_la_LIBADD = addrxlat/libaddrxlat.la

libkdumpfile_la_LDFLAGS = -version-info 6:0:0

if HAVE_LD_VERSION_SCRIPT
libkdumpfile_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libkdumpfile.map
EXTRA_libkdumpfile_la_DEPENDENCIES = libkdumpfile.map
endif

noinst_HEADERS = \
	kdumpfile-priv.h \
	list.h \
	threads.h \
	global-attr.def \
	static-attr.def

dist_noinst_DATA = \
	libkdumpfile.map
