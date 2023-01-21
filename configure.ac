dnl Process this file with autoconf to produce a configure script.
dnl
dnl Copyright (C) 2014-2020 Petr Tesarik <ptesarik@suse.com>
dnl
dnl This file is part of libkdumpfile.
dnl
dnl  This file is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation; either version 3 of the License, or
dnl  (at your option) any later version.
dnl
dnl  libkdumpfile is distributed in the hope that it will be useful, but
dnl  WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program.  If not, see <http://www.gnu.org/licenses/>.

dnl Package release versioning
m4_define([pkg_major_version], [0])
m4_define([pkg_minor_version], [5])
m4_define([pkg_micro_version], [1])
m4_define([pkg_version],
          [pkg_major_version.pkg_minor_version.pkg_micro_version])

AC_INIT([libkdumpfile],[pkg_version],[petr@tesarici.cz])

AC_CONFIG_SRCDIR([src/kdumpfile/diskdump.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADER([config.h])

AM_INIT_AUTOMAKE([foreign dist-bzip2 -Wall])

PACKAGE_VER_MAJOR=pkg_major_version
PACKAGE_VER_MINOR=pkg_minor_version
PACKAGE_VER_MICRO=pkg_micro_version

AC_SUBST(PACKAGE_VER_MAJOR)
AC_SUBST(PACKAGE_VER_MINOR)
AC_SUBST(PACKAGE_VER_MICRO)

AC_PROG_CC
AM_PROG_AR

LT_INIT

check_ldvers

DX_INIT_DOXYGEN([$PACKAGE_NAME],[Doxyfile],[doc])

AC_ARG_ENABLE(internal-doc,
  [AS_HELP_STRING([--enable-internal-doc],
    [Generate documentation for internal APIs @<:@default=no@:>@])],
  [], [enable_internal_doc=no])
AS_IF([test "x$enable_internal_doc" != xno],
    [DX_ENV_APPEND(ENABLE_INTERNAL, YES)],
    [DX_ENV_APPEND(ENABLE_INTERNAL, NO)])

AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(off_t)
AC_SUBST(SIZEOF_OFF_T, $ac_cv_sizeof_off_t)

dnl This makes sure pkg.m4 is available.
m4_pattern_forbid([^_?PKG_[A-Z_]+$],[*** pkg.m4 missing, please install pkg-config])

kdump_COMPRESSION(zlib, ZLIB, z, uncompress)
kdump_COMPRESSION(lzo2, LZO, lzo2, lzo1x_decompress_safe)
kdump_COMPRESSION(snappy, SNAPPY, snappy, snappy_uncompress)
kdump_COMPRESSION(libzstd, ZSTD, zstd, ZSTD_decompress)

dnl check for pthread support
AC_ARG_WITH(pthread,
  [AS_HELP_STRING([--without-pthread],
    [pthread support @<:@default=check@:>@])],
  [],[with_pthread=check])
AS_IF([test "x$with_pthread" != xno],
  [AC_SEARCH_LIBS(pthread_create, pthread,
    [PTHREAD_LIBS="-lpthread"
     AS_VAR_APPEND(LIBS_PRIVATE, " -lpthread")
     have_pthread=yes
    ],[
     have_pthread=no
    ])
  ],[have_pthread=no])
AS_IF([test "x$have_pthread" = xyes],
  [AC_DEFINE(USE_PTHREAD, 1, Define if you have pthread)],
  [AS_IF([test "x$with_phtread" = xyes],
    [AC_MSG_ERROR([pthread support requested but not found])
    ])
  ])
AC_SUBST(PTHREAD_LIBS)

dnl check for useful debugging options
AC_ARG_ENABLE(debug,
  [AS_HELP_STRING([--enable-debug],
    [Make a build suitable for debugging @<:@default=no@:>@])],
  [], [enable_debug=no])
AS_IF([test "x$enable_debug" = xyes],
    [AC_DEFINE(ENABLE_DEBUG, 1, Define to enable extra debugging features)])

dnl check for Python
kdump_PYTHON([2.7.0])

AC_CONFIG_FILES([
	Makefile
	examples/Makefile
	include/Makefile
	include/libkdumpfile/Makefile
	src/Makefile
	src/addrxlat/Makefile
	src/kdumpfile/Makefile
	python/Makefile
	tests/Makefile
	libaddrxlat.pc
	libkdumpfile.pc
	include/libkdumpfile/kdumpfile.h
	include/libkdumpfile/addrxlat.h
])

AC_OUTPUT
