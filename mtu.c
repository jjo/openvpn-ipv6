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

#include "config.h"

#include "syshead.h"

#include "buffer.h"
#include "mtu.h"
#include "error.h"

#include "memdbg.h"

#define MTUDISC_NOT_SUPPORTED_MSG "--mtu-disc is not supported on this OS"

void
set_mtu_discover_type (int sd, int mtu_type)
{
  if (mtu_type >= 0)
    {
#if defined(HAVE_SETSOCKOPT) && defined(SOL_IP) && defined(IP_MTU_DISCOVER)
      if (setsockopt
	  (sd, SOL_IP, IP_MTU_DISCOVER, &mtu_type, sizeof (mtu_type)))
	msg (M_ERR, "Error setting IP_MTU_DISCOVER type=%d on UDP socket",
	     mtu_type);
#else
      msg (M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
#endif
    }
}

int
translate_mtu_discover_type_name (const char *name)
{
#if defined(IP_PMTUDISC_DONT) && defined(IP_PMTUDISC_WANT) && defined(IP_PMTUDISC_DO)
  if (!strcmp (name, "yes"))
    return IP_PMTUDISC_DO;
  if (!strcmp (name, "maybe"))
    return IP_PMTUDISC_WANT;
  if (!strcmp (name, "no"))
    return IP_PMTUDISC_DONT;
  msg (M_FATAL,
       "invalid --mtu-disc type: '%s' -- valid types are 'yes', 'maybe', or 'no'",
       name);
#else
  msg (M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
#endif
  return -1;			/* NOTREACHED */
}

#if EXTENDED_SOCKET_ERROR_CAPABILITY

/*
 *
 * The following code is adapted from tracepath
 * Copyright (C) Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>.
 */

struct probehdr
{
	__u32 ttl;
	struct timeval tv;
};

int
format_extended_socket_error (int fd, struct buffer *out)
{
  int res;
  struct probehdr rcvbuf;
  char cbuf[512];
  struct iovec iov;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct sock_extended_err *e;
  struct sockaddr_in addr;
  int mtu = 0;

restart:
  memset (&rcvbuf, -1, sizeof (rcvbuf));
  iov.iov_base = &rcvbuf;
  iov.iov_len = sizeof (rcvbuf);
  msg.msg_name = (__u8 *) & addr;
  msg.msg_namelen = sizeof (addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  msg.msg_control = cbuf;
  msg.msg_controllen = sizeof (cbuf);

  res = recvmsg (fd, &msg, MSG_ERRQUEUE);
  if (res < 0)
    return mtu;

  e = NULL;

  for (cmsg = CMSG_FIRSTHDR (&msg); cmsg; cmsg = CMSG_NXTHDR (&msg, cmsg))
    {
      if (cmsg->cmsg_level == SOL_IP)
	{
	  if (cmsg->cmsg_type == IP_RECVERR)
	    {
	      e = (struct sock_extended_err *) CMSG_DATA (cmsg);
	    }
	  else
	    {
	      buf_printf (out ,"CMSG=%d|", cmsg->cmsg_type);
	    }
	}
    }
  if (e == NULL)
    {
      buf_printf (out, "NO-INFO|");
      return 0;
    }

  switch (e->ee_errno)
    {
    case ETIMEDOUT:
      buf_printf (out, "ETIMEDOUT|");
      break;
    case EMSGSIZE:
      buf_printf (out, "EMSGSIZE Path-MTU=%d|", e->ee_info);
      mtu = e->ee_info;
      break;
    case ECONNREFUSED:
      buf_printf (out, "ECONNREFUSED|");
      break;
    case EPROTO:
      buf_printf (out, "EPROTO|");
      break;
    case EHOSTUNREACH:
      buf_printf (out, "EHOSTUNREACH|");
      break;
    case ENETUNREACH:
      buf_printf (out, "ENETUNREACH|");
      break;
    case EACCES:
      buf_printf (out, "EACCES|");
      break;
    default:
      buf_printf (out, "UNKNOWN|");
      break;
    }
  goto restart;
}

void
set_sock_extended_error_passing (int sd)
{
  int on = 1;
  if (setsockopt (sd, SOL_IP, IP_RECVERR, &on, sizeof (on)))
    msg (M_WARN | M_ERRNO,
	 "Note: enable extended error passing on UDP socket failed (IP_RECVERR)");
}

#else

void
set_sock_extended_error_passing (int sd)
{
}

int
format_extended_socket_error (int fd, struct buffer *out)
{
  return 0;
}

#endif /* EXTENDED_SOCKET_ERROR_CAPABILITY */
