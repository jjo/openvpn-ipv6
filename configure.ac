dnl  OpenVPN -- An application to securely tunnel IP networks
dnl             over a single UDP port, with support for TLS-based
dnl             session authentication and key exchange,
dnl             packet encryption, packet authentication, and
dnl             packet compression.
dnl
dnl  Copyright (C) 2002 James Yonan <jim@yonan.net>
dnl
dnl  This program is free software; you can redistribute it and/or modify
dnl  it under the terms of the GNU General Public License as published by
dnl  the Free Software Foundation; either version 2 of the License, or
dnl  (at your option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful,
dnl  but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl  GNU General Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License
dnl  along with this program (see the file COPYING included with this
dnl  distribution); if not, write to the Free Software Foundation, Inc.,
dnl  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.50)

AC_INIT([OpenVPN], [1.2.0.4], [openvpn-users@lists.sourceforge.net], [openvpn])
AM_CONFIG_HEADER(config.h)

AC_ARG_ENABLE(lzo,
   [  --disable-lzo           Do not compile LZO compression support],
   [LZO="$enableval"],
   [LZO="yes"]
)

AC_ARG_ENABLE(crypto,
   [  --disable-crypto        Do not compile OpenSSL crypto support],
   [CRYPTO="$enableval"],
   [CRYPTO="yes"]
)

AC_ARG_ENABLE(ssl,
   [  --disable-ssl           Do not compile OpenSSL SSL support for TLS-based key exchange],
   [SSL="$enableval"],
   [SSL="yes"]
)

AC_ARG_ENABLE(pthread,
   [  --enable-pthread        Compile pthread support for improved SSL/TLS latency],
   [PTHREAD="$enableval"],
   [PTHREAD="no"]
)

AC_ARG_ENABLE(strict,
   [  --enable-strict         Enable strict compiler warnings],
   [STRICT="$enableval"],
   [STRICT="no"]
)

AC_ARG_WITH(ssl-headers,
   [  --with-ssl-headers=DIR  Crypto/SSL Include files location],
   [CS_HDR_DIR="$withval"]
   [CPPFLAGS="$CPPFLAGS -I$withval"] 
)

AC_ARG_WITH(ssl-lib,
   [  --with-ssl-lib=DIR      Crypto/SSL Library location],
   [LIBS="$LIBS -L$withval"] 
)

AC_ARG_WITH(lzo-headers,
   [  --with-lzo-headers=DIR  LZO Include files location],
   [LZO_HDR_DIR="$withval"]
   [CPPFLAGS="$CPPFLAGS -I$withval"] 
)

AC_ARG_WITH(lzo-lib,
   [  --with-lzo-lib=DIR      LZO Library location],
   [LIBS="$LIBS -L$withval"] 
)

AC_ARG_WITH(leak-check,
   [  --with-leak-check=TYPE  Build with memory leak checking  TYPE = dmalloc or ssl],
   [LEAK="$withval"]
)

dnl Guess host type.
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(openvpn, [$PACKAGE_VERSION])

dnl check target OS
openvpn_target=$target
if test $target_alias; then
  openvpn_target=$target_alias
fi
AC_DEFINE_UNQUOTED(TARGET_ALIAS, "$openvpn_target", [A string representing our target])
case "$target" in
*linux*)
	AC_DEFINE(TARGET_LINUX, 1, [Are we running on Linux?])
	;;
*solaris*)
	AC_DEFINE(TARGET_SOLARIS, 1, [Are we running on Solaris?])
	;;
*openbsd*)
	AC_DEFINE(TARGET_OPENBSD, 1, [Are we running on OpenBSD?])
	;;
*freebsd*)
	AC_DEFINE(TARGET_FREEBSD, 1, [Are we running on FreeBSD?])
	;;
*darwin*)
	dnl some Mac OS X tendering (we use vararg macros...)
	AC_DEFINE(TARGET_DARWIN, 1, [Are we running on Mac OS X?])
	CPPFLAGS="$CPPFLAGS -no-cpp-precomp"
	;;
esac

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_GCC_TRADITIONAL

dnl Checks for header files.
AC_HEADER_STDC

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Check for more header files.
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(sys/ioctl.h)
AC_CHECK_HEADERS(sys/stat.h)
AC_CHECK_HEADERS(sys/mman.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(stdlib.h)
AC_CHECK_HEADERS(stdint.h)
AC_CHECK_HEADERS(stdarg.h)
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(signal.h)
AC_CHECK_HEADERS(stdio.h)
AC_CHECK_HEADERS(string.h)
AC_CHECK_HEADERS(ctype.h)
AC_CHECK_HEADERS(errno.h)
AC_CHECK_HEADERS(syslog.h)
AC_CHECK_HEADERS(pwd.h)
AC_CHECK_HEADERS(net/if_tun.h)
AC_CHECK_HEADERS(net/if.h)
AC_CHECK_HEADERS(stropts.h)
AC_CHECK_HEADERS(sys/sockio.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(netinet/in_systm.h)
AC_CHECK_HEADERS(netinet/ip.h)
AC_CHECK_HEADERS(netinet/tcp.h)
AC_CHECK_HEADERS(resolv.h)
AC_CHECK_HEADERS(arpa/inet.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(sys/uio.h)
AC_CHECK_HEADERS(linux/if_tun.h)

dnl check that in_addr_t is defined
AC_CHECK_TYPE(
	[in_addr_t],
	[],
	[AC_DEFINE(in_addr_t, uint32_t, [Some systems don't define in_addr_t])],
	[#include "syshead.h"])

dnl check for basic types
AC_CHECK_TYPE(
	[uint8_t],
	[],
	[AC_DEFINE(uint8_t, unsigned char, [8-bit unsigned type])],
	[#include "syshead.h"])
AC_CHECK_TYPE(
	[uint32_t],
	[],
	[AC_DEFINE(uint32_t, unsigned long, [32-bit unsigned type])],
	[#include "syshead.h"])

dnl check for other types
TYPE_SOCKLEN_T
AC_TYPE_SIGNAL

dnl Check for libsocket
AC_SEARCH_LIBS(socket, socket)

dnl Check for libnsl
AC_SEARCH_LIBS(inet_ntoa, nsl)

dnl Check for libresolv
AC_SEARCH_LIBS(gethostbyname, resolv nsl)

dnl optional library functions
AC_FUNC_FORK
AC_CHECK_FUNCS(daemon)
AC_CHECK_FUNCS(chroot)
AC_CHECK_FUNCS(getpwnam)
AC_CHECK_FUNCS(setuid)
AC_CHECK_FUNCS(nice)
AC_CHECK_FUNCS(system)
AC_CHECK_FUNCS(getpid)
AC_CHECK_FUNCS(dup2)
AC_CHECK_FUNCS(getpass)
AC_CHECK_FUNCS(strerror)
AC_CHECK_FUNCS(syslog)
AC_CHECK_FUNCS(openlog)
AC_CHECK_FUNCS(mlockall)

dnl Required library functions
AC_FUNC_MEMCMP
AC_FUNC_MALLOC
AC_CHECK_FUNCS(gettimeofday select socket gethostbyname inet_ntoa memset vsnprintf, [],
	[AC_MSG_ERROR([Required library function not found])])

dnl
dnl check libraries
dnl

if test "$PTHREAD" = "yes"; then
   AC_CHECKING([for pthread support])
   ACX_PTHREAD(
	[
	    case "$target" in
	    *openbsd*)
		AC_MSG_RESULT([WARNING: pthread support on OpenBSD is still unstable!])
		CFLAGS="$CFLAGS -pthread"
		;;
	    esac
	    LIBS="$PTHREAD_LIBS $LIBS"
	    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
	    CC="$PTHREAD_CC"
	    AC_DEFINE(USE_PTHREAD, 1, [Use pthread-based multithreading])
	],
	[
	    AC_MSG_RESULT([I don't know how to build with pthread support on this platform.])
	    AC_MSG_ERROR([try ./configure --disable-pthread])
	])
fi

if test "$LEAK" = "dmalloc"; then
   AC_CHECKING([for dmalloc Library and Header files])
   AC_CHECK_HEADER(dmalloc.h, 
        [AC_CHECK_LIB(dmalloc, malloc,
	    [
               if test "$PTHREAD" = "yes"; then
                   OPENVPN_ADD_LIBS(-ldmallocth)
               else
                   OPENVPN_ADD_LIBS(-ldmalloc)
               fi
	       AC_DEFINE(DMALLOC, 1, [Use dmalloc memory debugging library])
	    ],
	    [AC_MSG_ERROR([dmalloc library not found.])]
	)],
        [AC_MSG_ERROR([dmalloc headers not found.])]
   )
fi

if test "$LZO" = "yes"; then
   AC_CHECKING([for LZO Library and Header files])
   AC_CHECK_HEADER(lzo1x.h, 
        [AC_CHECK_LIB(lzo, lzo1x_1_15_compress,
	    [
	       OPENVPN_ADD_LIBS(-llzo)
	       AC_DEFINE(USE_LZO, 1, [Use LZO compression library])
	    ],
	    [AC_MSG_ERROR([LZO headers were found but LZO library was not found.])]
	)],
	[
          AC_MSG_RESULT([LZO library and headers not found.])
	  AC_MSG_RESULT([LZO library available from http://www.oberhumer.com/opensource/lzo/])
	  AC_MSG_ERROR([Or try ./configure --disable-lzo])
	]
   )
fi

if test "$CRYPTO" = "yes"; then
   AC_CHECKING([for OpenSSL Crypto Library and Header files])
   AC_CHECK_HEADER(openssl/evp.h,
	[AC_CHECK_LIB(crypto, EVP_CIPHER_CTX_init,
            [
		   AC_CHECKING([that OpenSSL Library is at least version 0.9.5])
		   AC_EGREP_CPP(yes,
		     [
		       #include "openssl/evp.h"
		       #if SSLEAY_VERSION_NUMBER >= 0x00905000L
		         yes
		       #endif
		     ],
		     [
                       AC_DEFINE(USE_CRYPTO, 1, [Use OpenSSL crypto library])
                       OPENVPN_ADD_LIBS(-lcrypto)
                       AC_CHECK_FUNCS(EVP_CIPHER_CTX_set_key_length)
                     ],
		     [AC_MSG_ERROR([OpenSSL crypto Library is too old.])]
		   )
	    ],
	    [AC_MSG_ERROR([OpenSSL Crypto library not found.])]
	)],
	[AC_MSG_ERROR([OpenSSL Crypto headers not found.])]
   )

   if test "$SSL" = "yes"; then
      AC_CHECKING([for OpenSSL SSL Library and Header files])
      AC_CHECK_HEADER(openssl/ssl.h,
	   [AC_CHECK_LIB(ssl, SSL_CTX_new,
	       [
                  if test "$LEAK" = "ssl"; then
                     AC_CHECKING([for Memory Debugging Capabilities in OpenSSL Library])
                     AC_CHECK_LIB(ssl, CRYPTO_mem_ctrl,
                         [
                             AC_DEFINE(CRYPTO_MDEBUG, 1, [Use memory debugging function in OpenSSL])
			     AC_MSG_RESULT([NOTE: OpenSSL library must be compiled with CRYPTO_MDEBUG])
                         ],
                         [AC_MSG_ERROR([Memory Debugging function in OpenSSL library not found.])]
                     )
                  fi
	       ],
	       [AC_MSG_ERROR([OpenSSL SSL library not found.])]
	   )],
	   [AC_MSG_ERROR([OpenSSL SSL headers not found.])]
      )
      AC_DEFINE(USE_SSL, 1, [Use OpenSSL SSL library])
      OPENVPN_ADD_LIBS(-lssl)
   fi
fi

dnl enable strict compiler warnings
if test "$STRICT" = "yes"; then
   CFLAGS="$CFLAGS -Wall -W -Wpointer-arith -Wsign-compare -Winline"
fi

AC_OUTPUT(Makefile)
