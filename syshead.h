/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2004 James Yonan <jim@yonan.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef SYSHEAD_H
#define SYSHEAD_H

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifndef WIN32
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef TARGET_SOLARIS
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#else
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef TARGET_LINUX

#if defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#endif

#ifdef HAVE_LINUX_IF_TUN_H
#include <linux/if_tun.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#endif

#ifdef HAVE_LINUX_TYPES_H
#include <linux/types.h>
#endif

#ifdef HAVE_LINUX_ERRQUEUE_H
#include <linux/errqueue.h>
#endif

#endif /* TARGET_LINUX */

#ifdef TARGET_SOLARIS

#ifdef HAVE_STROPTS_H
#include <stropts.h>
#undef S_ERROR
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#endif /* TARGET_SOLARIS */

#ifdef TARGET_OPENBSD

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#endif /* TARGET_OPENBSD */

#ifdef TARGET_FREEBSD

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#endif /* TARGET_FREEBSD */

#ifdef TARGET_NETBSD

#ifdef HAVE_NET_IF_TUN_H
#include <net/if_tun.h>
#endif

#endif /* TARGET_NETBSD */

#ifdef WIN32
#include <iphlpapi.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#ifdef TARGET_DARWIN
#define _P1003_1B_VISIBLE
#endif /* TARGET_DARWIN */
#include <sys/mman.h>
#endif

#ifdef USE_PTHREAD
#include <pthread.h>
#endif

/*
 * Do we have the capability to support the --passtos option?
 */
#if defined(IPPROTO_IP) && defined(IP_TOS) && defined(HAVE_SETSOCKOPT)
#define PASSTOS_CAPABILITY 1
#else
#define PASSTOS_CAPABILITY 0
#endif

/*
 * Do we have the capability to report extended socket errors?
 */
#if defined(HAVE_LINUX_TYPES_H) && defined(HAVE_LINUX_ERRQUEUE_H) && defined(HAVE_SOCK_EXTENDED_ERR) && defined(HAVE_MSGHDR) && defined(HAVE_CMSGHDR) && defined(CMSG_FIRSTHDR) && defined(CMSG_NXTHDR) && defined(IP_RECVERR) && defined(MSG_ERRQUEUE) && defined(SOL_IP) && defined(HAVE_IOVEC) && defined(FRAGMENT_ENABLE)
#define EXTENDED_SOCKET_ERROR_CAPABILITY 1
#else
#define EXTENDED_SOCKET_ERROR_CAPABILITY 0
#endif

/*
 * Do we have a syslog capability?
 */
#if defined(HAVE_OPENLOG) && defined(HAVE_SYSLOG)
#define SYSLOG_CAPABILITY 1
#else
#define SYSLOG_CAPABILITY 0
#endif

/*
 * Does this OS draw a distinction between binary and ascii files?
 */
#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Directory separation char
 */
#ifdef WIN32
#define OS_SPECIFIC_DIRSEP '\\'
#else
#define OS_SPECIFIC_DIRSEP '/'
#endif

/*
 * Define a boolean value based
 * on Win32 status.
 */
#ifdef WIN32
#define WIN32_0_1 1
#else
#define WIN32_0_1 0
#endif

/*
 * Our socket descriptor type.
 */
#ifdef WIN32
typedef SOCKET socket_descriptor_t;
#else
typedef int socket_descriptor_t;
#endif

#endif
