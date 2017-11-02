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

AM_CPPFLAGS = -I$(top_builddir)/include
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

addrmap_LDADD = $(top_builddir)/src/addrxlat/libaddrxlat.la
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

custom_meth_LDADD = $(top_builddir)/src/addrxlat/libaddrxlat.la

err_addrxlat_LDADD = $(top_builddir)/src/addrxlat/libaddrxlat.la

mkdiskdump_SOURCES = mkdiskdump.c
mkdiskdump_CFLAGS = \
	$(ZLIB_CFLAGS) \
	$(LZO_CFLAGS) \
	$(SNAPPY_CFLAGS)
mkdiskdump_LDADD = \
	$(LDADD) \
	$(ZLIB_LIBS) \
	$(LZO_LIBS) \
	$(SNAPPY_LIBS)

mkelf_SOURCES = mkelf.c

mklkcd_SOURCES = mklkcd.c
mklkcd_CFLAGS = \
	$(ZLIB_CFLAGS)
mklkcd_LDADD = \
	$(LDADD) \
	$(ZLIB_LIBS)

dumpdata_SOURCES = dumpdata.c
dumpdata_LDADD = $(top_builddir)/src/libkdumpfile.la

multiread_SOURCES = multiread.c
multiread_LDADD = $(top_builddir)/src/libkdumpfile.la

nometh_LDADD = $(top_builddir)/src/addrxlat/libaddrxlat.la

subattr_SOURCES = subattr.c
subattr_LDADD = $(top_builddir)/src/libkdumpfile.la

sys_xlat_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/libkdumpfile.la

thread_errstr_LDADD = $(top_builddir)/src/libkdumpfile.la
vmci_cleanup_LDADD = $(top_builddir)/src/libkdumpfile.la
vmci_lines_post_LDADD = $(top_builddir)/src/libkdumpfile.la
vmci_post_LDADD = $(top_builddir)/src/libkdumpfile.la
vtop_LDADD = $(top_builddir)/src/libkdumpfile.la
xlatmap_LDADD = $(top_builddir)/src/libkdumpfile.la -ldl
xlatop_LDADD = $(top_builddir)/src/libkdumpfile.la

xlat_os_SOURCES = xlat-os.c
xlat_os_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/libkdumpfile.la

check_PROGRAMS = \
	addrxlat \
	addrmap \
	attriter \
	checkattr \
	clearattr \
	custom-meth \
	dumpdata \
	err-addrxlat \
	mkdiskdump \
	mkelf \
	mklkcd \
	multiread \
	nometh \
	subattr \
	sys-xlat \
	thread-errstr \
	vmci-cleanup \
	vmci-lines-post \
	vmci-post \
	vtop \
	xlatmap \
	xlatop \
	xlat-os

test_scripts = \
	addrmap-single-begin \
	addrmap-single-middle \
	addrmap-single-end \
	addrmap-replace \
	addrmap-overlap-begin \
	addrmap-overlap-end \
	addrmap-reduce \
	addrxlat-identity \
	addrxlat-pfn32 \
	addrxlat-pfn64 \
	addrxlat-ia32 \
	addrxlat-ia32-pae \
	addrxlat-ppc64-64k \
	addrxlat-s390x-2l \
	addrxlat-s390x-3l \
	addrxlat-s390x-4l \
	addrxlat-s390x-5l \
	addrxlat-x86_64 \
	addrxlat-invalid-pfn32 \
	addrxlat-invalid-pfn64 \
	addrxlat-invalid-ia32 \
	addrxlat-invalid-ia32-pae \
	addrxlat-invalid-s390x-2l \
	addrxlat-invalid-s390x-5l \
	addrxlat-invalid-x86_64 \
	addrxlat-linear \
	addrxlat-table \
	addrxlat-memarr \
	diskdump-empty-i386 \
	diskdump-empty-ppc64 \
	diskdump-empty-s390x \
	diskdump-empty-x86_64 \
	diskdump-basic-raw \
	diskdump-basic-zlib \
	diskdump-basic-lzo \
	diskdump-basic-snappy \
	diskdump-multiread \
	early-version-code \
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
	lkcd-duplicate-middle \
	sys-xlat-x86_64-linux \
	sys-xlat-x86_64-linux-xen \
	xlatmap-check \
	xlat-os-ia32-none \
	xlat-os-ia32-pae-none \
	xlat-os-s390x-2l \
	xlat-os-s390x-3l \
	xlat-os-s390x-4l \
	xlat-os-s390x-5l \
	xlat-os-x86_64-none \
	xlat-linux-ia32 \
	xlat-linux-ia32-pae \
	xlat-linux-ppc64-64k \
	xlat-linux-s390x-2l \
	xlat-linux-s390x-3l \
	xlat-linux-s390x-4l \
	xlat-linux-x86_64-ktext-pgt \
	xlat-linux-x86_64-old \
	xlat-linux-x86_64-old-nover \
	xlat-linux-x86_64-2.6.11 \
	xlat-linux-x86_64-2.6.11-nover \
	xlat-linux-x86_64-2.6.27 \
	xlat-linux-x86_64-2.6.27-cr3-xen \
	xlat-linux-x86_64-2.6.27-nover \
	xlat-linux-x86_64-2.6.31 \
	xlat-linux-x86_64-2.6.31-cr3 \
	xlat-linux-x86_64-2.6.31-kvaddr \
	xlat-linux-x86_64-2.6.31-reloc \
	xlat-linux-x86_64-2.6.31-nover \
	xlat-linux-x86_64-2.6.31-nover-reloc \
	xlat-linux-x86_64-2.6.31-nover-xen \
	xlat-xen-ia32 \
	xlat-xen-ia32-pae \
	xlat-xen-x86_64-old \
	xlat-xen-x86_64-old-nover \
	xlat-xen-x86_64-3.2 \
	xlat-xen-x86_64-3.2-nover \
	xlat-xen-x86_64-4.0dev-nover \
	xlat-xen-x86_64-4.0 \
	xlat-xen-x86_64-4.0-nover \
	xlat-xen-x86_64-4.3 \
	xlat-xen-x86_64-4.3-nover \
	xlat-xen-x86_64-4.4 \
	xlat-xen-x86_64-4.4-nover \
	xlat-xen-x86_64-4.6-bigmem

dist_check_DATA = \
	addrmap-single-begin.expect \
	addrmap-single-middle.expect \
	addrmap-single-end.expect \
	addrmap-replace.expect \
	addrmap-overlap-begin.expect \
	addrmap-overlap-end.expect \
	addrmap-reduce.expect \
	early-version-code.data \
	early-version-code.expect \
	elf-empty.data \
	basic.expect \
	partial.expect \
	sys-xlat-x86_64-linux.expect \
	sys-xlat-x86_64-linux-xen.expect \
	xlatmap.expect \
	xlat-os-ia32-none.expect \
	xlat-os-ia32-pae-none.expect \
	xlat-os-s390x-2l.data \
	xlat-os-s390x-2l.expect \
	xlat-os-s390x-3l.data \
	xlat-os-s390x-3l.expect \
	xlat-os-s390x-4l.data \
	xlat-os-s390x-4l.expect \
	xlat-os-s390x-5l.data \
	xlat-os-s390x-5l.expect \
	xlat-os-x86_64-none.expect \
	xlat-linux-ia32.data \
	xlat-linux-ia32.expect \
	xlat-linux-ia32-pae.data \
	xlat-linux-ia32-pae.expect \
	xlat-linux-ppc64-64k.data \
	xlat-linux-ppc64-64k.expect \
	xlat-linux-ppc64-64k.sym \
	xlat-linux-s390x-2l.data \
	xlat-linux-s390x-2l.expect \
	xlat-linux-s390x-2l.sym \
	xlat-linux-s390x-3l.data \
	xlat-linux-s390x-3l.expect \
	xlat-linux-s390x-3l.sym \
	xlat-linux-s390x-4l.data \
	xlat-linux-s390x-4l.expect \
	xlat-linux-s390x-4l.sym \
	xlat-linux-x86_64-ktext-pgt.expect \
	xlat-linux-x86_64-ktext-pgt.sym \
	xlat-linux-x86_64-old.expect \
	xlat-linux-x86_64-old-nover.data \
	xlat-linux-x86_64-old-nover.expect \
	xlat-linux-x86_64-old-nover.sym \
	xlat-linux-x86_64-2.6.11.expect \
	xlat-linux-x86_64-2.6.11-nover.data \
	xlat-linux-x86_64-2.6.11-nover.expect \
	xlat-linux-x86_64-2.6.11-nover.sym \
	xlat-linux-x86_64-2.6.27.expect \
	xlat-linux-x86_64-2.6.27-cr3-xen.data \
	xlat-linux-x86_64-2.6.27-cr3-xen.expect \
	xlat-linux-x86_64-2.6.27-cr3-xen.sym \
	xlat-linux-x86_64-2.6.27-nover.data \
	xlat-linux-x86_64-2.6.27-nover.expect \
	xlat-linux-x86_64-2.6.27-nover.sym \
	xlat-linux-x86_64-2.6.31.expect \
	xlat-linux-x86_64-2.6.31-cr3.data \
	xlat-linux-x86_64-2.6.31-cr3.expect \
	xlat-linux-x86_64-2.6.31-cr3.sym \
	xlat-linux-x86_64-2.6.31-kvaddr.data \
	xlat-linux-x86_64-2.6.31-kvaddr.expect \
	xlat-linux-x86_64-2.6.31-kvaddr.sym \
	xlat-linux-x86_64-2.6.31-nover.data \
	xlat-linux-x86_64-2.6.31-nover.expect \
	xlat-linux-x86_64-2.6.31-nover.sym \
	xlat-linux-x86_64-2.6.31-nover-reloc.data \
	xlat-linux-x86_64-2.6.31-nover-reloc.expect \
	xlat-linux-x86_64-2.6.31-nover-reloc.sym \
	xlat-linux-x86_64-2.6.31-nover-xen.data \
	xlat-linux-x86_64-2.6.31-nover-xen.expect \
	xlat-linux-x86_64-2.6.31-nover-xen.sym \
	xlat-linux-x86_64-2.6.31-reloc.data \
	xlat-linux-x86_64-2.6.31-reloc.expect \
	xlat-linux-x86_64-2.6.31-reloc.sym \
	xlat-xen-ia32.data \
	xlat-xen-ia32.expect \
	xlat-xen-ia32-pae.data \
	xlat-xen-ia32-pae.expect \
	xlat-xen-x86_64-old.expect \
	xlat-xen-x86_64-old-nover.data \
	xlat-xen-x86_64-old-nover.expect \
	xlat-xen-x86_64-3.2.expect \
	xlat-xen-x86_64-3.2-nover.data \
	xlat-xen-x86_64-3.2-nover.expect \
	xlat-xen-x86_64-4.0dev-nover.data \
	xlat-xen-x86_64-4.0dev-nover.expect \
	xlat-xen-x86_64-4.0.expect \
	xlat-xen-x86_64-4.0-nover.data \
	xlat-xen-x86_64-4.0-nover.expect \
	xlat-xen-x86_64-4.3.expect \
	xlat-xen-x86_64-4.3-nover.data \
	xlat-xen-x86_64-4.3-nover.expect \
	xlat-xen-x86_64-4.4.expect \
	xlat-xen-x86_64-4.4-nover.data \
	xlat-xen-x86_64-4.4-nover.expect \
	xlat-xen-x86_64-4.6-bigmem.data \
	xlat-xen-x86_64-4.6-bigmem.expect

dist_check_SCRIPTS = \
	addrmap-common \
	addrxlat-common \
	addrxlat-invalid \
	diskdump-basic \
	diskdump-empty \
	elf-empty \
	lkcd-empty \
	lkcd-basic \
	lkcd-wrong-page-size \
	sys-xlat-common \
	xlat-os-common \
	$(test_scripts)

TESTS = $(test_scripts) \
	attriter \
	clearattr \
	custom-meth \
	err-addrxlat \
	nometh \
	subattr \
	thread-errstr \
	vmci-cleanup \
	vmci-lines-post \
	vmci-post \
	xlatop

clean-local:
	-rm -rf out
