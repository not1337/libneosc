AC_INIT([neosclib], [1.0.0])
AC_CONFIG_SRCDIR([src/pcsc.c])
AM_INIT_AUTOMAKE
LT_INIT
AM_CONFIG_HEADER(config.h)
AC_PROG_CC
AC_PROG_INSTALL
PKG_CHECK_MODULES([pcsclite],[libpcsclite])
PKG_CHECK_MODULES([libusb],[libusb-1.0])
LIBS=
if test ${libdir} = '${exec_prefix}/lib'
then
	case "`uname -m`" in
	    x86_64|ppc64|s390x|sparc64)
		libdir="${libdir}64" ;;
	esac
fi
AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_OUTPUT
