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

#include "socket.h"
#include "mtu.h"
#include "fdmisc.h"
#include "error.h"
#include "thread.h"
#include "misc.h"

#include "memdbg.h"

#define INETD_SOCKET_DESCRIPTOR 0

/* begin check status */

unsigned int x_cs_info_level;
unsigned int x_cs_verbose_level;

void
reset_check_status ()
{
  x_cs_info_level = 0;
  x_cs_verbose_level = 0;
}

void
set_check_status (unsigned int info_level, unsigned int verbose_level)
{
  x_cs_info_level = info_level;
  x_cs_verbose_level = verbose_level;
}

void
x_check_status (int status, const char *description, struct udp_socket *sock)
{
  const int errno_save = errno;
  msg (x_cs_verbose_level, "%s returned %d", description, status);
  if (check_debug_level (x_cs_info_level))
    {
      const unsigned int lev = x_cs_info_level | EMBEDDED_ERRNO_MASK (errno_save);
      if (sock)
	{
	  struct buffer out = alloc_buf_gc (512);
	  const int mtu = format_extended_socket_error (sock->sd, &out);
	  if (mtu > 0)
	    sock->mtu = mtu;
	  if (out.len)
	      msg (lev, "%s [%s]", description, BPTR(&out));
	    else
	      msg (lev, "%s", description);
	}
      else
	{
	  msg (lev, "%s", description);
	}
    }
}

/* end check status */

static const char*
h_errno_msg(int h_errno_err)
{
  switch (h_errno_err)
    {
    case HOST_NOT_FOUND:
      return "[HOST_NOT_FOUND] The specified host is unknown.";
    case NO_DATA:
      return "[NO_DATA] The requested name is valid but does not have an IP address.";
    case NO_RECOVERY:
      return "[NO_RECOVERY] A non-recoverable name server error occurred.";
    case TRY_AGAIN:
      return "[TRY_AGAIN] A temporary error occurred on an authoritative name server.";
    }
  return "[unknown h_errno value]";
}

/*
 * Translate IP addr or hostname to in_addr_t.
 * If resolve error, try again for
 * resolve_retry_seconds seconds.
 */
static in_addr_t
getaddr (const char *hostname, int resolve_retry_seconds)
{
  struct in_addr ia;
  const int status = inet_aton (hostname, &ia);

  if (!status)
    {
      const int fail_wait_interval = 5; /* seconds */
      int resolve_retries = resolve_retry_seconds / fail_wait_interval;

      /*
       * Resolve hostname
       */
      struct hostent *h;
      while ( !(h = gethostbyname (hostname)) )
	{
	  msg ((resolve_retries > 0  ? D_RESOLVE_ERRORS : M_FATAL),
	       "Cannot resolve host address: %s: %s",
	       hostname, h_errno_msg (h_errno));
	  sleep (fail_wait_interval);
	  --resolve_retries;
	}

      /* potentially more than one address returned, but we take first */
      ia.s_addr = *(in_addr_t *) (h->h_addr_list[0]);

      if (ia.s_addr)
	{
	  if (h->h_addr_list[1])
	    msg (M_WARN, "Warning: %s has multiple addresses", hostname);
	}
    }
  return ia.s_addr;
}

/* Create a UDP socket */
void
udp_socket_init (struct udp_socket *sock,
		 const char *local_host,
		 const char *remote_host,
		 int local_port,
		 int remote_port,
		 bool bind_local,
		 bool remote_float,
		 bool inetd,
		 struct udp_socket_addr *usa,
		 const char *ipchange_command,
		 int resolve_retry_seconds,
		 int mtu_discover_type)
{
  CLEAR (*sock);

  sock->remote_float = remote_float;
  sock->addr = usa;
  sock->ipchange_command = ipchange_command;

  /* were we started by inetd or xinetd? */
  if (inetd)
    {
      sock->sd = INETD_SOCKET_DESCRIPTOR;
    }
  else
    {
      /* create socket */
      if ((sock->sd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	msg (M_ERR, "Cannot create socket");

      /* resolve local address if undefined */
      if (!addr_defined (&usa->local))
	{
	  usa->local.sin_family = AF_INET;
	  usa->local.sin_addr.s_addr =
	    (local_host ? getaddr (local_host, resolve_retry_seconds) : htonl (INADDR_ANY));
	  usa->local.sin_port = htons (local_port);
	}

      /* bind to local address/port */
      if (bind_local)
	{
	  if (bind (sock->sd, (struct sockaddr *) &usa->local, sizeof (usa->local)))
	    msg (M_ERR, "Socket bind failed on local address: %s",
		 print_sockaddr (&usa->local));
	}
    }

  /* resolve remote address if undefined */
  if (!addr_defined (&usa->remote))
    {
      usa->remote.sin_family = AF_INET;
      usa->remote.sin_addr.s_addr =
	(remote_host ? getaddr (remote_host, resolve_retry_seconds) : 0);
      usa->remote.sin_port = htons (remote_port);
    }

  /* should we re-use previous active remote address? */
  if (addr_defined (&usa->actual))
    msg (M_INFO, "Preserving recently used remote address: %s", print_sockaddr (&usa->actual));
  else
    usa->actual = usa->remote;

  /* set socket to non-blocking mode */
  set_nonblock (sock->sd);

  /* set socket file descriptor to not pass across execs, so that scripts don't have
     access to it */
  set_cloexec (sock->sd);

  /* set Path MTU discovery options on the socket */
  set_mtu_discover_type (sock->sd, mtu_discover_type);

  /* if the OS supports it, enable extended error passing on the socket */
  set_sock_extended_error_passing (sock->sd);

  /* print local and active remote address */
  if (sock->sd == INETD_SOCKET_DESCRIPTOR)
    msg (M_INFO, "UDP link local: [inetd]");
  else
    msg (M_INFO, "UDP link local%s: %s", (bind_local ? " (bound)" : ""),
	 print_sockaddr_ex (&usa->local, bind_local, ":"));
  msg (M_INFO, "UDP link remote: %s",
       print_sockaddr_ex (&usa->actual, addr_defined (&usa->actual), ":"));
}

void
udp_socket_set_outgoing_addr (const struct buffer *buf,
			      struct udp_socket *sock,
			      const struct sockaddr_in *addr)
{
  mutex_lock (L_SOCK);
  if (!buf || buf->len > 0)
    {
      struct udp_socket_addr *usa = sock->addr;
      ASSERT (addr_defined (addr));
      if ((sock->remote_float
	   || !addr_defined (&usa->remote)
	   || addr_match (addr, &usa->remote))
	  && (!addr_match (addr, &usa->actual)
	      || !sock->set_outgoing_initial))
	{
	  usa->actual = *addr;
	  sock->set_outgoing_initial = true;
	  mutex_unlock (L_SOCK);
	  msg (M_INFO, "Peer Connection Initiated with %s", print_sockaddr (&usa->actual));
	  if (sock->ipchange_command)
	    {
	      char command[256];
	      struct buffer out;
	      buf_set_write (&out, (uint8_t *)command, sizeof (command));
	      buf_printf (&out, "%s %s",
			  sock->ipchange_command,
			  print_sockaddr_ex (&usa->actual, true, " "));
	      msg (D_TLS_DEBUG, "executing ip-change command: %s", command);
	      system_check (command, "ip-change command failed", false);
	    }
	  mutex_lock (L_SOCK);
	}
    }
  mutex_unlock (L_SOCK);
}

void
udp_socket_incoming_addr (struct buffer *buf,
			  const struct udp_socket *sock,
			  const struct sockaddr_in *from_addr)
{
  mutex_lock (L_SOCK);
  if (buf->len > 0)
    {
      struct udp_socket_addr *usa = sock->addr;
      if (from_addr->sin_family != AF_INET)
	goto bad;
      if (!addr_defined (from_addr))
	goto bad;
      if (!addr_defined (&usa->remote) || sock->remote_float)
	goto good;
      if (addr_match (from_addr, &usa->remote))
	goto good;
    }
bad:
  msg (D_LINK_ERRORS,
       "IP Address failed from %s (allow this incoming address/port by removing --remote or adding --float)",
       print_sockaddr (from_addr));
  buf->len = 0;
  mutex_unlock (L_SOCK);
  return;

good:
  msg (D_READ_WRITE, "IP Address OK from %s",
       print_sockaddr (from_addr));
  mutex_unlock (L_SOCK);
  return;
}

void
udp_socket_get_outgoing_addr (struct buffer *buf,
			      const struct udp_socket *sock,
			      struct sockaddr_in *addr)
{
  mutex_lock (L_SOCK);
  if (buf->len > 0)
    {
      struct udp_socket_addr *usa = sock->addr;
      if (addr_defined (&usa->actual))
	{
	  *addr = usa->actual;
	}
      else
	{
	  msg (D_READ_WRITE, "No outgoing address to send packet");
	  buf->len = 0;
	}
    }
  mutex_unlock (L_SOCK);
}

void
udp_socket_close (struct udp_socket *sock)
{
  if (sock->sd >= 0 && sock->sd != INETD_SOCKET_DESCRIPTOR)
    {
      close (sock->sd);
      sock->sd = -1;
    }
}

const char *
print_sockaddr (const struct sockaddr_in *addr)
{
  return print_sockaddr_ex(addr, true, ":");
}

const char *
print_sockaddr_ex (const struct sockaddr_in *addr, bool do_port, const char* separator)
{
  struct buffer out = alloc_buf_gc (64);
  const int port = ntohs (addr->sin_port);

  mutex_lock (L_INET_NTOA);
  buf_printf (&out, "%s", (addr_defined (addr) ? inet_ntoa (addr->sin_addr) : "[undef]"));
  mutex_unlock (L_INET_NTOA);

  if (do_port && port)
    {
      if (separator)
	buf_printf (&out, "%s", separator);

      buf_printf (&out, "%d", port);
    }
  return (char *)out.data;
}
