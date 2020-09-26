## Process this file with automake to create Makefile.in
## Configure input file for libkdumpfile.
##
## Copyright (C) 2015 Ales Novak <alnovak@suse.cz>
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
AM_CFLAGS = $(PYTHON_CFLAGS)
AM_LDFLAGS = -module -avoid-version

installed_list = installed.list

setup.cfg: Makefile
	$(AM_V_GEN)
	$(AM_V_at)echo "[kdumpfile]" > $@
	$(AM_V_at)echo "version=$(VERSION)" >> $@
	$(AM_V_at)echo "srcdir=$(srcdir)" >> $@
	$(AM_V_at)echo "top_builddir=$(top_builddir)" >> $@
	$(AM_V_at)echo >> $@
	$(AM_V_at)echo "[build_ext]" >> $@
	$(AM_V_at)echo "libtool=$(LIBTOOL)" >> $@
	$(AM_V_at)echo "pyexecdir=$(pyexecdir)" >> $@
	$(AM_V_at)echo >> $@
	$(AM_V_at)echo "[install_lib]" >> $@
	$(AM_V_at)echo "libtool_install=$(LIBTOOL) --mode=install $(INSTALL)" >> $@

all-local: setup.cfg
	$(PYTHON) $(srcdir)/setup.py build

install-exec-local: setup.cfg
	$(PYTHON) $(srcdir)/setup.py install \
		--root "$(DESTDIR)"/ \
		--install-purelib $(pythondir) \
		--install-platlib $(pyexecdir) \
		--record $(installed_list)

uninstall-local: $(installed_list)
	while read f ; do \
	    $(LIBTOOL) --mode=uninstall rm -f "$(DESTDIR)/$$f" ; \
	done < $<

mostlyclean-local: setup.cfg
	$(PYTHON) $(srcdir)/setup.py clean --all
	rm $<

CLEANFILES = $(installed_list)

check_LTLIBRARIES = _test_addrxlat.la

_test_addrxlat_la_SOURCES = test_addrxlat.c
_test_addrxlat_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-export-symbols $(srcdir)/test_addrxlat.sym \
	-rpath $(abs_builddir)
_test_addrxlat_la_LIBADD = $(PYTHON_LIBS) $(top_builddir)/src/addrxlat/libaddrxlat.la
EXTRA__test_addrxlat_la_DEPENDENCIES = test_addrxlat.sym

dist_noinst_SCRIPTS = \
	setup.py \
	libtoolize.py \
	addrxlat/__init__.py \
	addrxlat/exceptions.py \
	kdumpfile/__init__.py \
	kdumpfile/exceptions.py \
	kdumpfile/views.py \
	showxlat.py \
	vtop.py

dist_noinst_DATA = \
	addrxlat.c \
	kdumpfile.c \
	test_addrxlat.sym

noinst_HEADERS = \
	addrxlatmod.h

test_scripts = \
	test_addrxlat.py

dist_check_SCRIPTS = \
	$(test_scripts)

TESTS = $(test_scripts)

LOG_COMPILER = $(PYTHON)

AM_TESTS_ENVIRONMENT = \
eval " $$($(LIBTOOL) --config)"; \
PYTHONPATH="$$srcdir:$$objdir"
