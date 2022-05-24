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

export SIZEOF_OFF_T = @SIZEOF_OFF_T@

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

addrmap_LDADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la
addrxlat_LDADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la
attriter_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
checkattr_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
clearattr_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
custom_meth_LDADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la
elf_prstatus_mod_x86_64_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
err_addrxlat_LDADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la

mkdiskdump_CFLAGS = \
	$(ZLIB_CFLAGS) \
	$(LZO_CFLAGS) \
	$(SNAPPY_CFLAGS) \
	$(ZSTD_CFLAGS)
mkdiskdump_LDADD = \
	$(LDADD) \
	$(ZLIB_LIBS) \
	$(LZO_LIBS) \
	$(SNAPPY_LIBS) \
	$(ZSTD_LIBS)

mklkcd_CFLAGS = \
	$(ZLIB_CFLAGS)
mklkcd_LDADD = \
	$(LDADD) \
	$(ZLIB_LIBS)

dumpdata_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
multiread_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
multixlat_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
nometh_LDADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la
subattr_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
sys_xlat_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/addrxlat/libaddrxlat.la
thread_errstr_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
typed_attr_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
vmci_cleanup_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
vmci_lines_post_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
vmci_post_LDADD = \
	$(top_builddir)/src/kdumpfile/libkdumpfile.la
xlatmap_LDADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la \
	-ldl
xlatop_LDADD = \
	$(top_builddir)/src/addrxlat/libaddrxlat.la
xlat_os_LDADD = \
	$(LDADD) \
	$(top_builddir)/src/addrxlat/libaddrxlat.la

check_PROGRAMS = \
	addrxlat \
	addrmap \
	attriter \
	checkattr \
	clearattr \
	custom-meth \
	dumpdata \
	elf-prstatus-mod-x86_64 \
	err-addrxlat \
	mkdiskdump \
	mkelf \
	mklkcd \
	multiread \
	multixlat \
	nometh \
	subattr \
	sys-xlat \
	typed-attr \
	thread-errstr \
	vmci-cleanup \
	vmci-lines-post \
	vmci-post \
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
	addrxlat-aarch64-4k \
	addrxlat-aarch64-16k \
	addrxlat-aarch64-64k \
	addrxlat-ia32 \
	addrxlat-ia32-pae \
	addrxlat-ppc64-64k \
	addrxlat-s390x-2l \
	addrxlat-s390x-3l \
	addrxlat-s390x-4l \
	addrxlat-s390x-5l \
	addrxlat-x86_64-4l \
	addrxlat-x86_64-5l \
	addrxlat-x86_64-sme \
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
	diskdump-basic-zstd \
	diskdump-multiread \
	diskdump-excluded \
	early-version-code \
	elf-empty-aarch64 \
	elf-empty-i386 \
	elf-empty-i386-elf64 \
	elf-empty-ppc64 \
	elf-empty-ppc64le \
	elf-empty-s390 \
	elf-empty-s390x \
	elf-empty-x86_64 \
	elf-prstatus-aarch64 \
	elf-prstatus-i386 \
	elf-prstatus-ppc64 \
	elf-prstatus-x86_64 \
	elf-basic \
        elf-be \
        elf-le \
	elf-nonexistent \
	elf-partial \
	elf-fractional \
	elf-multiread \
	elf-virt-phys-clash \
	elf-vmcoreinfo \
	elf-dom0-no-phys_base \
	elf-xen_prstatus \
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
	multixlat-elf \
	multixlat-same \
	sys-xlat-x86_64-linux \
	sys-xlat-x86_64-linux-xen \
	xlatmap-check \
	xlat-os-aarch64-none \
	xlat-os-ia32-none \
	xlat-os-ia32-pae-none \
	xlat-os-s390x-2l \
	xlat-os-s390x-3l \
	xlat-os-s390x-4l \
	xlat-os-s390x-5l \
	xlat-os-x86_64-none \
	xlat-linux-aarch64-5.2-va39 \
	xlat-linux-aarch64-5.8-va39 \
	xlat-linux-aarch64-5.8-va48 \
	xlat-linux-aarch64-5.8-va48-nover \
	xlat-linux-aarch64-5.16-64k \
	xlat-linux-ia32 \
	xlat-linux-ia32-pae \
	xlat-linux-ppc64-64k \
	xlat-linux-s390x-2l \
	xlat-linux-s390x-3l \
	xlat-linux-s390x-4l \
	xlat-linux-x86_64-ktext-crosspage \
	xlat-linux-x86_64-ktext-pgt \
	xlat-linux-x86_64-ktext-1G \
	xlat-linux-x86_64-ktext-128M \
	xlat-linux-x86_64-ktext-130M \
	xlat-linux-x86_64-ktext-130M-nonlinear \
	xlat-linux-x86_64-ktext-40M \
	xlat-linux-x86_64-ktext-512M \
	xlat-linux-x86_64-ktext-520M \
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
	xlat-linux-x86_64-4.12-sme \
	xlat-linux-x86_64-4.13-nover \
	xlat-linux-x86_64-4.13-kaslr \
	xlat-linux-x86_64-5l \
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
	xlat-xen-x86_64-4.6-bigmem \
	zero-size

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
	elf-prstatus-aarch64.data \
	elf-prstatus-i386.data \
	elf-prstatus-ppc64.data \
	elf-prstatus-x86_64.data \
        elf-endian.data \
        elf-be16.expect \
        elf-be32.expect \
        elf-be64.expect \
        elf-le16.expect \
        elf-le32.expect \
        elf-le64.expect \
	elf-virt-phys-clash.expect \
	elf-vmcoreinfo.data \
	elf-vmcoreinfo.expect \
	elf-dom0-no-phys_base.data \
	elf-dom0-no-phys_base.expect \
	elf-xen_prstatus.data \
	elf-xen_prstatus.expect \
	basic.expect \
	partial.expect \
	multixlat.expect \
	multixlat-elf.data \
	multixlat-same.expect \
	diskdump-excluded.data \
	diskdump-excluded.expect \
	sys-xlat-x86_64-linux.expect \
	sys-xlat-x86_64-linux-xen.expect \
	xlatmap.expect \
	xlat-os-aarch64-none.expect \
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
	xlat-linux-aarch64-5.2-va39.data \
	xlat-linux-aarch64-5.2-va39.expect \
	xlat-linux-aarch64-5.2-va39.sym \
	xlat-linux-aarch64-5.8-va39.data \
	xlat-linux-aarch64-5.8-va39.expect \
	xlat-linux-aarch64-5.8-va39.sym \
	xlat-linux-aarch64-5.8-va48.data \
	xlat-linux-aarch64-5.8-va48.expect \
	xlat-linux-aarch64-5.8-va48.sym \
	xlat-linux-aarch64-5.8-va48-nover.data \
	xlat-linux-aarch64-5.8-va48-nover.expect \
	xlat-linux-aarch64-5.8-va48-nover.sym \
	xlat-linux-aarch64-5.16-64k.data \
	xlat-linux-aarch64-5.16-64k.expect \
	xlat-linux-aarch64-5.16-64k.sym \
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
	xlat-linux-x86_64-ktext-crosspage.data \
	xlat-linux-x86_64-ktext-crosspage.expect \
	xlat-linux-x86_64-ktext-crosspage.sym \
	xlat-linux-x86_64-ktext-pgt.expect \
	xlat-linux-x86_64-ktext-pgt.sym \
	xlat-linux-x86_64-ktext-1G.data \
	xlat-linux-x86_64-ktext-1G.expect \
	xlat-linux-x86_64-ktext-1G.sym \
	xlat-linux-x86_64-ktext-128M.data \
	xlat-linux-x86_64-ktext-128M.expect \
	xlat-linux-x86_64-ktext-128M.sym \
	xlat-linux-x86_64-ktext-130M.data \
	xlat-linux-x86_64-ktext-130M.expect \
	xlat-linux-x86_64-ktext-130M.sym \
	xlat-linux-x86_64-ktext-130M-nonlinear.data \
	xlat-linux-x86_64-ktext-130M-nonlinear.expect \
	xlat-linux-x86_64-ktext-130M-nonlinear.sym \
	xlat-linux-x86_64-ktext-40M.data \
	xlat-linux-x86_64-ktext-40M.expect \
	xlat-linux-x86_64-ktext-40M.sym \
	xlat-linux-x86_64-ktext-512M.data \
	xlat-linux-x86_64-ktext-512M.expect \
	xlat-linux-x86_64-ktext-512M.sym \
	xlat-linux-x86_64-ktext-520M.data \
	xlat-linux-x86_64-ktext-520M.expect \
	xlat-linux-x86_64-ktext-520M.sym \
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
	xlat-linux-x86_64-4.12-sme.data \
	xlat-linux-x86_64-4.12-sme.expect \
	xlat-linux-x86_64-4.12-sme.sym \
	xlat-linux-x86_64-4.13-nover.data \
	xlat-linux-x86_64-4.13-nover.expect \
	xlat-linux-x86_64-4.13-nover.sym \
	xlat-linux-x86_64-4.13-kaslr.data \
	xlat-linux-x86_64-4.13-kaslr.expect \
	xlat-linux-x86_64-4.13-kaslr.sym \
	xlat-linux-x86_64-5l.data \
	xlat-linux-x86_64-5l.expect \
	xlat-linux-x86_64-5l.sym \
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
	typed-attr \
	vmci-cleanup \
	vmci-lines-post \
	vmci-post \
	xlatop

clean-local:
	-rm -rf out
