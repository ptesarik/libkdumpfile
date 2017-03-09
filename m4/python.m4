AC_DEFUN([kdump_PYTHON],[dnl check for Python support
AC_ARG_WITH(python,[dnl
  AS_HELP_STRING([--with-python],
    [build Python bindings @<:@default=check@:>@])],
  [],[withval=check])
have_python=no
AS_IF([test "x$withval" != xno],[dnl
  AS_IF([test "x$withval" != xyes],[PYTHON="$withval"])
  AM_PATH_PYTHON([$1],[have_python=yes])
])
AS_IF([test "$have_python" = yes],[dnl
  AC_PATH_PROG(PYTHON_CONFIG,"$PYTHON-config",[])
  AS_IF([test -n "$PYTHON_CONFIG"],[dnl
    PYTHON_CFLAGS=`$PYTHON_CONFIG --cflags`
    PYTHON_LIBS=`$PYTHON_CONFIG --libs`
    AC_SUBST(PYTHON_CFLAGS)
    AC_SUBST(PYTHON_LIBS)
  ],[dnl
    AC_MSG_ERROR([Python found as $PYTHON, but there is no $PYTHON-config])
    have_python=no
  ])
],[dnl
  AS_IF([test "x$with_python" = xyes],[dnl
    AC_MSG_ERROR([Python support requested but not found])
  ])
])
AM_CONDITIONAL(BUILD_PYTHON_EXT, test "x$have_python" = xyes)
])
