AC_DEFUN([kdump_COMPRESSION], [dnl
AC_ARG_WITH([$1],
  [AS_HELP_STRING([--with-$1],
    [support for $1 compression @<:@default=check@:>@])],
  [], [with_$1=check])
AS_IF([test "x$with_$1" != xno],
  [AC_SEARCH_LIBS([$4],[$3],
    [AC_DEFINE(USE_$2, 1,
      [Define to enable support for $1 compression using -l$3])
    ],[
      if test "x$with_$1" != xcheck; then
        AC_MSG_FAILURE([--with-$1 was given, but test for $1 failed])
      fi
    ])
  ])
])
