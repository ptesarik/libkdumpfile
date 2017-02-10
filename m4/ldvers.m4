AC_DEFUN([check_ldvers], [dnl
AC_MSG_CHECKING([if libraries can be versioned])
case "$host" in
    # Special case for PE/COFF platforms: ld reports
    # support for version-script, but doesn't actually
    # DO anything with it.
    *cygwin* | *mingw32* | *interix* )
	have_ld_version_script=no
	AC_MSG_RESULT(no)
	;;
    * )
	GLD=`$LD --help < /dev/null 2>/dev/null | $GREP version-script`
	if test -n "$GLD"; then
	    have_ld_version_script=yes
	    AC_MSG_RESULT(yes)
	else
	    have_ld_version_script=no
	    AC_MSG_RESULT(no)
	fi
	;;
esac

AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT, [test $have_ld_version_script = yes])
])
