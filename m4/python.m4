AC_DEFUN([kdump_PYTHON],[dnl check for Python support
AC_ARG_WITH(python,[dnl
  AS_HELP_STRING([--with-python],
    [build Python bindings @<:@default=check@:>@])],
  [],[withval=check])
have_python=no
AS_IF([test "x$withval" != xno],[dnl
  case "$withval" in
    yes|check)
      ;;
    *)
      AS_IF([test -x "$withval"],[PYTHON="$withval"],[dnl
        AC_PATH_PROG(PYTHON,"$withval")
        AS_IF([test -z "$PYTHON"],[dnl
          AC_MSG_ERROR([Requested Python interpreter ($withval) not found])
        ])
      ])
      ;;
  esac
  AM_PATH_PYTHON([$1],[have_python=yes],[:])
])
AS_IF([test "$have_python" = yes],[dnl
  PYTHON_CONFIG="$PYTHON-config"
  AS_IF([test -x "$PYTHON_CONFIG"],[],[dnl
    AC_PATH_PROG(PYTHON_CONFIG,"$PYTHON-config")
  ])
  AS_IF([test -x "$PYTHON_CONFIG"],[dnl
    PYTHON_CFLAGS=`$PYTHON_CONFIG --cflags`
    PYTHON_LIBS=`$PYTHON_CONFIG --libs`
    AC_SUBST(PYTHON_CFLAGS)
    AC_SUBST(PYTHON_LIBS)
  ],[dnl
    AC_MSG_ERROR([Python found as $PYTHON, but there is no $PYTHON_CONFIG])
    have_python=no
  ])
],[dnl
  AS_IF([test "x$with_python" = xyes],[dnl
    AC_MSG_ERROR([Python support requested but not found])
  ])
])
AM_CONDITIONAL(BUILD_PYTHON_EXT, test "x$have_python" = xyes)
])
