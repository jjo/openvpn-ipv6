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

#include "config.h"

#include "syshead.h"

#include "socket.h"
#include "fdmisc.h"
#include "error.h"

#include "memdbg.h"

/* Translate IP addr or hostname to in_addr_t */
in_addr_t
getaddr (const char *hostname)
{
  in_addr_t ip = inet_addr (hostname);

  if (ip == -1)
    {
      struct hostent *h = gethostbyname (hostname);
      if (!h)
	msg (M_ERR, "Cannot resolve host address: %s", hostname);

      /* potentially more than one address returned, but we take first */
      ip = *(in_addr_t *) (h->h_addr_list[0]);

      if (ip)
	{
	  if (h->h_addr_list[1])
	    msg (M_WARN, "Warning: %s has multiple addresses", hostname);
	}
    }
  return ip;
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
		 struct sockaddr_in *actual, const char *ipchange_command)
{
  CLEAR (*sock);

  sock->remote_float = remote_float;
  sock->actual = actual;
  sock->ipchange_command = ipchange_command;

  /* create socket */
  if ((sock->sd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    msg (M_ERR, "Cannot create socket");

  /* parse local address */
  sock->local.sin_family = AF_INET;
  sock->local.sin_addr.s_addr =
    (local_host ? getaddr (local_host) : htonl (INADDR_ANY));
  sock->local.sin_port = htons (local_port);

  /* parse remote address */
  sock->remote.sin_family = AF_INET;
  sock->remote.sin_addr.s_addr = (remote_host ? getaddr (remote_host) : 0);
  sock->remote.sin_port = htons (remote_port);

  if (bind_local)
    {
      if (bind
	  (sock->sd, (struct sockaddr *) &sock->local, sizeof (sock->local)))
	msg (M_ERR, "Socket bind failed on local address: %s",
	     print_sockaddr (&sock->local));
    }

  set_nonblock (sock->sd);

  if (ADDR_P (sock->actual))
    msg (M_INFO, "Preserving recently used remote address: %s", print_sockaddr (sock->actual));
  else
    *sock->actual = sock->remote;

  msg (M_INFO, "UDP link local%s: %s", (bind_local ? " (bound)" : ""),
       print_sockaddr_ex (&sock->local, bind_local, ":"));
  msg (M_INFO, "UDP link remote: %s",
       print_sockaddr_ex (sock->actual, ADDR_P(sock->actual) != 0, ":"));
}

void
udp_socket_set_outgoing_addr (const struct buffer *buf,
			      struct udp_socket *sock,
			      const struct sockaddr_in *addr)
{
  if (buf->len > 0)
    {
      ASSERT (ADDR_P (addr));
      if ((sock->remote_float
	   || !ADDR (sock->remote)
	   || (ADDR_P (addr) == ADDR (sock->remote)))
	  && (ADDR_P (sock->actual) != ADDR_P (addr) || !sock->set_outgoing_initial))
	{
	  *sock->actual = *addr;
	  msg (D_HANDSHAKE, "Peer Connection Initiated with %s", print_sockaddr (sock->actual));
	  if (sock->ipchange_command)
	    {
	      char command[256];
	      struct buffer out;
	      buf_set_write (&out, command, sizeof (command));
	      buf_printf (&out, "%s %s",
			  sock->ipchange_command,
			  print_sockaddr_ex (sock->actual, true, " "));
	      msg (D_TLS_DEBUG, "executing ip-change command: %d", command);
	      system (command);
	    }
	  sock->set_outgoing_initial = true;
	}
    }
}

void
udp_socket_close (struct udp_socket *sock)
{
  if (sock->sd)
    {
      close (sock->sd);
      sock->sd = 0;
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

  buf_printf (&out, "%s", (ADDR_P(addr) ? inet_ntoa (addr->sin_addr) : "[undef]"));

  if (do_port && port)
    {
      if (separator)
	buf_printf (&out, "%s", separator);

      buf_printf (&out, "%d", port);
    }
  return out.data;
}
