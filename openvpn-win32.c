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

#include "config-win32.h"
#include "syshead.h"
#include "error.h"

static struct WSAData wsa_state;

void
init_win32 (void)
{
  if (WSAStartup(0x0101, &wsa_state))
    {
      msg (M_ERR, "WSAStartup failed");
    }
}

void
uninit_win32 (void)
{
  WSACleanup ();
}

/* taken from stunnel */

const char *
strerror_win32 (int errnum)
{
  switch (errnum) {
  case 10004:
    return "Interrupted system call (WSAEINTR)";
  case 10009:
    return "Bad file number (WSAEBADF)";
  case 10013:
    return "Permission denied (WSAEACCES)";
  case 10014:
    return "Bad address (WSAEFAULT)";
  case 10022:
    return "Invalid argument (WSAEINVAL)";
  case 10024:
    return "Too many open files (WSAEMFILE)";
  case 10035:
    return "Operation would block (WSAEWOULDBLOCK)";
  case 10036:
    return "Operation now in progress (WSAEINPROGRESS)";
  case 10037:
    return "Operation already in progress (WSAEALREADY)";
  case 10038:
    return "Socket operation on non-socket (WSAENOTSOCK)";
  case 10039:
    return "Destination address required (WSAEDESTADDRREQ)";
  case 10040:
    return "Message too long (WSAEMSGSIZE)";
  case 10041:
    return "Protocol wrong type for socket (WSAEPROTOTYPE)";
  case 10042:
    return "Bad protocol option (WSAENOPROTOOPT)";
  case 10043:
    return "Protocol not supported (WSAEPROTONOSUPPORT)";
  case 10044:
    return "Socket type not supported (WSAESOCKTNOSUPPORT)";
  case 10045:
    return "Operation not supported on socket (WSAEOPNOTSUPP)";
  case 10046:
    return "Protocol family not supported (WSAEPFNOSUPPORT)";
  case 10047:
    return "Address family not supported by protocol family (WSAEAFNOSUPPORT)";
  case 10048:
    return "Address already in use (WSAEADDRINUSE)";
  case 10049:
    return "Can't assign requested address (WSAEADDRNOTAVAIL)";
  case 10050:
    return "Network is down (WSAENETDOWN)";
  case 10051:
    return "Network is unreachable (WSAENETUNREACH)";
  case 10052:
    return "Net dropped connection or reset (WSAENETRESET)";
  case 10053:
    return "Software caused connection abort (WSAECONNABORTED)";
  case 10054:
    return "Connection reset by peer (WSAECONNRESET)";
  case 10055:
    return "No buffer space available (WSAENOBUFS)";
  case 10056:
    return "Socket is already connected (WSAEISCONN)";
  case 10057:
    return "Socket is not connected (WSAENOTCONN)";
  case 10058:
    return "Can't send after socket shutdown (WSAESHUTDOWN)";
  case 10059:
    return "Too many references, can't splice (WSAETOOMANYREFS)";
  case 10060:
    return "Connection timed out (WSAETIMEDOUT)";
  case 10061:
    return "Connection refused (WSAECONNREFUSED)";
  case 10062:
    return "Too many levels of symbolic links (WSAELOOP)";
  case 10063:
    return "File name too long (WSAENAMETOOLONG)";
  case 10064:
    return "Host is down (WSAEHOSTDOWN)";
  case 10065:
    return "No Route to Host (WSAEHOSTUNREACH)";
  case 10066:
    return "Directory not empty (WSAENOTEMPTY)";
  case 10067:
    return "Too many processes (WSAEPROCLIM)";
  case 10068:
    return "Too many users (WSAEUSERS)";
  case 10069:
    return "Disc Quota Exceeded (WSAEDQUOT)";
  case 10070:
    return "Stale NFS file handle (WSAESTALE)";
  case 10091:
    return "Network SubSystem is unavailable (WSASYSNOTREADY)";
  case 10092:
    return "WINSOCK DLL Version out of range (WSAVERNOTSUPPORTED)";
  case 10093:
    return "Successful WSASTARTUP not yet performed (WSANOTINITIALISED)";
  case 10071:
    return "Too many levels of remote in path (WSAEREMOTE)";
  case 11001:
    return "Host not found (WSAHOST_NOT_FOUND)";
  case 11002:
    return "Non-Authoritative Host not found (WSATRY_AGAIN)";
  case 11003:
    return "Non-Recoverable errors: FORMERR, REFUSED, NOTIMP (WSANO_RECOVERY)";
  case 11004:
    return "Valid name, no data record of requested type (WSANO_DATA)";
  default:
    return strerror (errnum);
  }
}
