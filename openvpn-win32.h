/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
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

/*
 * Win32-specific OpenVPN code, targetted at the mingw
 * development environment.
 */

#include <windows.h>
#include <winsock.h>

#define sleep _sleep

#define SIGHUP 1
#define SIGUSR1 10

#define random rand
#define srandom srand

typedef unsigned int in_addr_t;
typedef unsigned int ssize_t;

void init_win32 (void);
void uninit_win32 (void);
int inet_aton (const char *name, struct in_addr *addr);
const char *strerror_win32 (int errnum);

#define openvpn_close_socket(s) closesocket(s)
#define openvpn_errno()         GetLastError()
#define openvpn_errno_socket()  WSAGetLastError()
#define openvpn_strerror(e)     strerror_win32(e)
