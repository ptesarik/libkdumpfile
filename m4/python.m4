AC_DEFUN([kdump_PYTHON],[dnl check for Python support
AC_ARG_WITH(python,[dnl
  AS_HELP_STRING([--with-python],
    [build Python bindings @<:@default=check@:>@])],
  [],[withval=check])
have_python=no
AS_IF([test "x$withval" != xno],[dnl
  AS_IF([test "x$withval" != xyes],[PYTHON="$withval"])
  AM_PATH_PYTHON([$1],[dnl
    case "$PYTHON_VERSION" in
    2.*) pkgname=python2 ;;
    3.*) pkgname=python3 ;;
    *)   pkgname=python  ;;
    esac
    PKG_CHECK_MODULES(PYTHON,$pkgname,[dnl
	AC_SUBST(PYTHON_CFLAGS)
	AC_SUBST(PYTHON_LIBS)
	have_python=yes
    ],[
	AS_IF([test $pkgname != python],[dnl
	  PKG_CHECK_MODULES(PYTHON,python,[dnl
	    AC_SUBST(PYTHON_CFLAGS)
	    AC_SUBST(PYTHON_LIBS)
	    have_python=yes
	  ])
	])
    ])
  ])
])
AS_IF([test "x$have_python" = xno],[dnl
  AS_IF([test "x$with_python" = xyes],[dnl
    AC_MSG_ERROR([Python support requested but not found])
  ])
])
AM_CONDITIONAL(BUILD_PYTHON_EXT, test "x$have_python" = xyes)
])
