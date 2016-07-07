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

AM_CPPFLAGS = -I$(top_srcdir)/src -I$(top_srcdir)/src/addrxlat
LDADD = libtestutil.a

libtestutil_a_SOURCES = \
	data.c \
	param.c \
	rle.c \
	slurp.c

check_LIBRARIES = \
	libtestutil.a

check_HEADERS = \
	diskdump.h \
	lkcd.h \
	testutil.h

addrxlat_LDADD = $(top_builddir)/src/addrxlat/libaddrxlat.la

attriter_SOURCES = attriter.c
attriter_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/libkdumpfile.la

checkattr_SOURCES = checkattr.c
checkattr_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/libkdumpfile.la

clearattr_SOURCES = clearattr.c
clearattr_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/libkdumpfile.la

mkdiskdump_SOURCES = mkdiskdump.c
mkelf_SOURCES = mkelf.c
mklkcd_SOURCES = mklkcd.c

dumpdata_SOURCES = dumpdata.c
dumpdata_LDADD = $(top_builddir)/src/libkdumpfile.la

multiread_SOURCES = multiread.c
multiread_LDADD = $(top_builddir)/src/libkdumpfile.la

privptr_SOURCES = privptr.c
privptr_LDADD = $(top_builddir)/src/libkdumpfile.la

subattr_SOURCES = subattr.c
subattr_LDADD = $(top_builddir)/src/libkdumpfile.la

thread_errstr_LDADD = $(top_builddir)/src/libkdumpfile.la
vmci_cleanup_LDADD = $(top_builddir)/src/libkdumpfile.la
vmci_lines_post_LDADD = $(top_builddir)/src/libkdumpfile.la
vmci_post_LDADD = $(top_builddir)/src/libkdumpfile.la
vtop_LDADD = $(top_builddir)/src/libkdumpfile.la

check_PROGRAMS = \
	addrxlat \
	attriter \
	checkattr \
	clearattr \
	dumpdata \
	mkdiskdump \
	mkelf \
	mklkcd \
	multiread \
	privptr \
	subattr \
	thread-errstr \
	vmci-cleanup \
	vmci-lines-post \
	vmci-post \
	vtop

test_scripts = \
	addrxlat-identity \
	addrxlat-ia32 \
	diskdump-empty-i386 \
	diskdump-empty-ppc64 \
	diskdump-empty-s390x \
	diskdump-empty-x86_64 \
	diskdump-basic-raw \
	diskdump-basic-zlib \
	diskdump-basic-lzo \
	diskdump-basic-snappy \
	diskdump-multiread \
	elf-empty-i386 \
	elf-empty-i386-elf64 \
	elf-empty-s390 \
	elf-empty-s390x \
	elf-empty-x86_64 \
	elf-basic \
	elf-nonexistent \
	elf-partial \
	elf-fractional \
	elf-multiread \
	lkcd-empty-i386 \
	lkcd-empty-ppc64 \
	lkcd-empty-x86_64 \
	lkcd-basic-raw \
	lkcd-basic-rle \
	lkcd-basic-gzip \
	lkcd-multiread \
	lkcd-long-page-raw \
	lkcd-long-page-rle \
	lkcd-long-page-gzip \
	lkcd-short-page-raw \
	lkcd-short-page-rle \
	lkcd-short-page-gzip \
	lkcd-gap \
	lkcd-unordered \
	lkcd-unordered-faroff \
	lkcd-duplicate \
	lkcd-duplicate-middle

dist_check_DATA = \
	elf-empty.data \
	basic.expect \
	partial.expect

dist_check_SCRIPTS = \
	diskdump-empty \
	elf-empty \
	lkcd-empty \
	lkcd-basic \
	lkcd-wrong-page-size \
	$(test_scripts)

TESTS = $(test_scripts) \
	attriter \
	clearattr \
	privptr \
	subattr \
	thread-errstr \
	vmci-cleanup \
	vmci-lines-post \
	vmci-post

clean-local:
	-rm -rf out
