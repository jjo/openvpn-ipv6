/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002 James Yonan <jim@yonan.net>
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

#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <netdb.h>		/* gethostbyname */
#include <pwd.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

#include <netinet/in.h>		/* struct sockaddr_in */

#include <arpa/inet.h>

#ifdef __linux__
 #include <linux/if.h>
#endif /* __linux */

#ifndef OLD_TUN_TAP
 #ifdef __OpenBSD__
  #include <net/if_tun.h>
 #endif /* __OpenBSD__ */
 #ifdef __linux__
  #include <linux/if_tun.h>
 #endif /* __linux */
#endif /* OLD_TUN_TAP */

#ifdef _POSIX_MEMLOCK
 #include <sys/mman.h>
#endif

#endif
