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
LIBS = testutil.a

testutil_a_SOURCES = \
	param.c

check_LIBRARIES = \
	testutil.a

check_HEADERS = \
	lkcd.h \
	testutil.h

checkattr_SOURCES = checkattr.c
checkattr_LDADD = $(top_srcdir)/src/libkdumpfile.la

mklkcd_SOURCES = mklkcd.c

check_PROGRAMS = \
	checkattr \
	mklkcd

test_scripts = \
	lkcd-empty-i386 \
	lkcd-empty-ppc64 \
	lkcd-empty-x86_64

dist_check_SCRIPTS = \
	lkcd-empty \
	$(test_scripts)

TESTS = $(test_scripts)
