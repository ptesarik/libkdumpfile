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

AM_CPPFLAGS = -I$(top_builddir)/include
AM_CFLAGS = -fvisibility=hidden \
	$(ZLIB_CFLAGS)	\
	$(LZO_CFLAGS)	\
	$(SNAPPY_CFLAGS) \
	$(ZSTD_CFLAGS)

lib_LTLIBRARIES = libkdumpfile.la
libkdumpfile_la_SOURCES = \
	aarch64.c \
	arm.c \
	attr.c \
	bitmap.c \
	blob.c \
	cache.c \
	context.c \
	devmem.c \
	diskdump.c \
	elfdump.c \
	fcache.c \
	ia32.c \
	lkcd.c \
	notes.c \
	open.c \
	pfn.c \
	read.c \
	sadump.c \
	s390x.c \
	s390dump.c \
	todo.c \
	util.c \
	vmcoreinfo.c \
	vtop.c \
	ppc64.c \
	x86_64.c

libkdumpfile_la_LIBADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la	\
	$(ZLIB_LIBS)	\
	$(LZO_LIBS)	\
	$(SNAPPY_LIBS)	\
	$(ZSTD_LIBS)

libkdumpfile_la_LDFLAGS = -version-info 10:2:0

if HAVE_LD_VERSION_SCRIPT
libkdumpfile_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libkdumpfile.map
EXTRA_libkdumpfile_la_DEPENDENCIES = libkdumpfile.map
endif

noinst_HEADERS = \
	kdumpfile-priv.h \
	global-attr.def \
	static-attr.def

dist_noinst_DATA = \
	libkdumpfile.map

check_LTLIBRARIES = libcheck.la
libcheck_la_SOURCES = $(libkdumpfile_la_SOURCES)
libcheck_la_LIBADD = $(libkdumpfile_la_LIBADD)

check_PROGRAMS = \
	test-blob \
	test-clone-attr \
	test-cache \
	test-fcache

test_cache_LDADD = libcheck.la
test_fcache_LDADD = libcheck.la -ldl
test_blob_LDADD = libcheck.la
test_clone_attr_LDADD = libcheck.la

TESTS = \
	test-blob \
	test-clone-attr \
	test-cache \
	test-fcache

clean-local:
	-rm -f tmp.fcache.*
