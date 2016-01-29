## Process this file with automake to create Makefile.in
##
## Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>
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

AM_CPPFLAGS = -I$(top_srcdir)/src
LDADD = libtestutil.a

libtestutil_a_SOURCES = \
	data.c \
	param.c \
	rle.c

check_LIBRARIES = \
	libtestutil.a

check_HEADERS = \
	lkcd.h \
	testutil.h

checkattr_SOURCES = checkattr.c
checkattr_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/libkdumpfile.la

mklkcd_SOURCES = mklkcd.c

dumpdata_SOURCES = dumpdata.c
dumpdata_LDADD = $(top_builddir)/src/libkdumpfile.la

check_PROGRAMS = \
	checkattr \
	dumpdata \
	mklkcd

test_scripts = \
	lkcd-empty-i386 \
	lkcd-empty-ppc64 \
	lkcd-empty-x86_64 \
	lkcd-basic-raw \
	lkcd-basic-rle \
	lkcd-basic-gzip \
	lkcd-long-page-raw \
	lkcd-long-page-rle \
	lkcd-long-page-gzip \
	lkcd-short-page-raw \
	lkcd-short-page-rle \
	lkcd-short-page-gzip \
	lkcd-gap \
	lkcd-unordered \
	lkcd-unordered-faroff

dist_check_DATA = \
	lkcd-empty.data \
	lkcd-basic.expect

dist_check_SCRIPTS = \
	lkcd-empty \
	lkcd-basic \
	lkcd-wrong-page-size \
	$(test_scripts)

TESTS = $(test_scripts)

clean-local:
	-rm -rf out