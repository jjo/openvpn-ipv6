/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "socket.h"
#include "fdmisc.h"
#include "thread.h"
#include "misc.h"
#include "io.h"

#include "memdbg.h"

/*
 * Functions related to the translation of DNS names to IP addresses.
 */

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
in_addr_t
getaddr (unsigned int flags,
	 const char *hostname,
	 int resolve_retry_seconds,
	 bool *succeeded,
	 volatile int *signal_received)
{
  struct in_addr ia;
  int status;
  int sigrec = 0;

  CLEAR (ia);
  if (succeeded)
    *succeeded = false;

  if ((flags & (GETADDR_FATAL_ON_SIGNAL|GETADDR_WARN_ON_SIGNAL))
      && !signal_received)
    signal_received = &sigrec;

  status = inet_aton (hostname, &ia);

  if (!status)
    {
      const int fail_wait_interval = 5; /* seconds */
      int resolve_retries = resolve_retry_seconds / fail_wait_interval;
      struct hostent *h;
      const char *fmt;

      CLEAR (ia);

      fmt = "RESOLVE: Cannot resolve host address: %s: %s";
      if ((flags & GETADDR_MENTION_RESOLVE_RETRY)
	  && !resolve_retry_seconds)
	fmt = "RESOLVE: Cannot resolve host address: %s: %s (I would have retried this name query if you had specified the --resolv-retry option.)";

      if (!(flags & GETADDR_RESOLVE))
	{
	  if (flags & GETADDR_FATAL)
	    msg (M_FATAL, "RESOLVE: Cannot parse IP address: %s", hostname);
	  else
	    goto done;
	}

      /*
       * Resolve hostname
       */
      while (true)
	{
	  /* try hostname lookup */
	  h = gethostbyname (hostname);

	  if (signal_received)
	    {
	      GET_SIGNAL (*signal_received);
	      if (*signal_received)
	        goto done;
	    }

	  /* success? */
	  if (h)
	    break;

	  /* resolve lookup failed, should we
	     continue or fail? */
	  msg (((resolve_retries > 0
		 || !(flags & GETADDR_FATAL))
		? D_RESOLVE_ERRORS : M_FATAL),
	       fmt,
	       hostname,
	       h_errno_msg (h_errno));

	  if (--resolve_retries <= 0
	      && !(flags & GETADDR_FATAL))
	    goto done;

	  sleep (fail_wait_interval);
	}

      /* potentially more than one address returned, but we take first */
      ia.s_addr = *(in_addr_t *) (h->h_addr_list[0]);

      if (ia.s_addr)
	{
	  if (h->h_addr_list[1])
	    msg (D_RESOLVE_ERRORS, "RESOLVE: Warning: %s has multiple addresses", hostname);
	}

      /* hostname resolve succeeded */
      if (succeeded)
	*succeeded = true;
    }
  else
    {
      /* IP address parse succeeded */
      if (succeeded)
	*succeeded = true;
    }

 done:
  if (signal_received && *signal_received)
    {
      int level = 0;
      if (flags & GETADDR_FATAL_ON_SIGNAL)
	level = M_FATAL;
      else if (flags & GETADDR_WARN_ON_SIGNAL)
	level = M_WARN;
      msg (level, "RESOLVE: signal received during DNS resolution attempt");
    }

  return (flags & GETADDR_HOST_ORDER) ? ntohl (ia.s_addr) : ia.s_addr;
}

static void
update_remote (const char* host,
	       struct sockaddr_in *addr,
	       bool *changed)
{
  if (host && addr)
    {
      const in_addr_t new_addr = getaddr (
					  GETADDR_RESOLVE,
					  host,
					  1,
					  NULL,
					  NULL);
      if (new_addr && addr->sin_addr.s_addr != new_addr)
	{
	  addr->sin_addr.s_addr = new_addr;
	  *changed = true;
	}
    }
}

/*
 * SOCKET INITALIZATION CODE.
 * Create a TCP/UDP socket
 */

static socket_descriptor_t
create_socket_tcp (void)
{
  socket_descriptor_t sd;

  if ((sd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    msg (M_SOCKERR, "Cannot create TCP socket");

  /* set SO_REUSEADDR on socket */
  {
    int on = 1;
    if (setsockopt (sd, SOL_SOCKET, SO_REUSEADDR,
		    (void *) &on, sizeof (on)) < 0)
      msg (M_SOCKERR, "Cannot setsockopt SO_REUSEADDR on TCP socket");
  }

#if 0
  /* set socket linger options */
  {
    struct linger linger;
    linger.l_onoff = 1;
    linger.l_linger = 2;
    if (setsockopt (sd, SOL_SOCKET, SO_LINGER,
		    (void *) &linger, sizeof (linger)) < 0)
      msg (M_SOCKERR, "Cannot setsockopt SO_LINGER on TCP socket");
  }
#endif

  return sd;
}

static socket_descriptor_t
create_socket_udp (void)
{
  socket_descriptor_t sd;

  if ((sd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    msg (M_SOCKERR, "Cannot create UDP socket");
  return sd;
}

static void
create_socket (struct link_socket *sock)
{
  /* create socket */
  if (sock->proto == PROTO_UDPv4)
    {
      sock->sd = create_socket_udp ();

      if (sock->socks_proxy)
	{
	  sock->ctrl_sd = create_socket_tcp ();
	}
    }
  else if (sock->proto == PROTO_TCPv4_SERVER
	   || sock->proto == PROTO_TCPv4_CLIENT)
    {
      sock->sd = create_socket_tcp ();
    }
  else
    {
      ASSERT (0);
    }
}

/*
 * Functions used for establishing a TCP stream connection.
 */

static int
socket_listen_accept (socket_descriptor_t sd,
		      struct sockaddr_in *remote,
		      const char *remote_dynamic,
		      bool *remote_changed,
		      const struct sockaddr_in *local,
		      bool do_listen,
		      bool nowait,
		      volatile int *signal_received)
{
  socklen_t remote_len = sizeof (*remote);
  struct sockaddr_in remote_verify = *remote;
  int new_sd = -1;

  if (do_listen)
    {
      msg (M_INFO, "Listening for incoming TCP connection on %s", 
	   print_sockaddr (local));
      if (listen (sd, 1))
	msg (M_SOCKERR, "listen() failed");
    }

  /* set socket to non-blocking mode */
  set_nonblock (sd);

  while (true)
    {
      int status;
      fd_set reads;
      struct timeval tv;

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = 5;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      GET_SIGNAL (*signal_received);
      if (*signal_received)
	return sd;

      if (status < 0)
	msg (D_LINK_ERRORS | M_ERRNO_SOCK, "select() failed");

      if (status <= 0)
	continue;

#ifdef HAVE_GETPEERNAME
      if (nowait)
        {
	  new_sd = getpeername (sd, (struct sockaddr *) remote, &remote_len);

	  if (new_sd == -1)
	    msg (D_LINK_ERRORS | M_ERRNO_SOCK, "getpeername() failed");
	  else
	    new_sd = sd;
	}
#else
      if (nowait)
	msg (M_WARN, "WARNING: this OS does not provide the getpeername() function");
#endif
      else
        {
	  new_sd = accept (sd, (struct sockaddr *) remote, &remote_len);
	}

      if (new_sd == -1)
	{
	  msg (D_LINK_ERRORS | M_ERRNO_SOCK, "accept() failed");
	}
      else if (remote_len != sizeof (*remote))
	{
	  msg (D_LINK_ERRORS, "WARNING: Received strange incoming connection with unknown address length=%d", remote_len);
	}
      else
	{
	  update_remote (remote_dynamic, &remote_verify, remote_changed);
	  if (addr_defined (&remote_verify)
	      && !addr_match (&remote_verify, remote))
	    {
	      msg (M_WARN,
		   "NOTE: Rejected connection attempt from %s due to --remote setting",
		   print_sockaddr (remote));
	      if (openvpn_close_socket (new_sd))
		msg (M_SOCKERR, "close socket failed (new_sd)");
	    }
	  else
	    break;
	}
      sleep (1);
    }

  if (!nowait && openvpn_close_socket (sd))
    msg (M_SOCKERR, "close socket failed (sd)");
  msg (M_INFO, "TCP connection established with %s", 
       print_sockaddr (remote));
  return new_sd;
}

static void
socket_connect (socket_descriptor_t *sd,
		struct sockaddr_in *remote,
		const char *remote_dynamic,
		bool *remote_changed,
		const int connect_retry_seconds,
		volatile int *signal_received)
{
  msg (M_INFO, "Attempting to establish TCP connection with %s", 
       print_sockaddr (remote));
  while (true)
    {
      const int status = connect (*sd, (struct sockaddr *) remote,
				  sizeof (*remote));

      GET_SIGNAL (*signal_received);
      if (*signal_received)
	return;

      if (!status)
	break;

      msg (D_LINK_ERRORS | M_ERRNO_SOCK,
	   "connect() failed, will try again in %d seconds, error",
	   connect_retry_seconds);

      openvpn_close_socket (*sd);
      sleep (connect_retry_seconds);
      *sd = create_socket_tcp ();
      update_remote (remote_dynamic, remote, remote_changed);
    }

  msg (M_INFO, "TCP connection established with %s", 
       print_sockaddr (remote));
}

/* For stream protocols, allocate a buffer to build up packet.
   Called after frame has been finalized. */

static void
socket_frame_init (const struct frame *frame, struct link_socket *sock)
{
#ifdef WIN32
  overlapped_io_init (&sock->reads, frame, FALSE, false);
  overlapped_io_init (&sock->writes, frame, TRUE, false);
#endif

  if (link_socket_connection_oriented (sock))
    {
#ifdef WIN32
      stream_buf_init (&sock->stream_buf, &sock->reads.buf_init);
#else
      alloc_buf_sock_tun (&sock->stream_buf_data, frame, false);
      stream_buf_init (&sock->stream_buf, &sock->stream_buf_data);
#endif
    }
}

/*
 * Adjust frame structure based on a Path MTU value given
 * to us by the OS.
 */
void
frame_adjust_path_mtu (struct frame *frame, int pmtu, int proto)
{
  frame_set_mtu_dynamic (frame, pmtu - datagram_overhead (proto), SET_MTU_UPPER_BOUND);
}

static void
resolve_bind_local (struct link_socket *sock)
{
  /* resolve local address if undefined */
  if (!addr_defined (&sock->lsa->local))
    {
      sock->lsa->local.sin_family = AF_INET;
      sock->lsa->local.sin_addr.s_addr =
	(sock->local_host ? getaddr (
				     GETADDR_RESOLVE
				     | GETADDR_FATAL
				     | GETADDR_FATAL_ON_SIGNAL,
				     sock->local_host,
				     0,
				     NULL,
				     NULL)
	 : htonl (INADDR_ANY));
      sock->lsa->local.sin_port = htons (sock->local_port);
    }
  
  /* bind to local address/port */
  if (sock->bind_local)
    {
      if (bind (sock->sd, (struct sockaddr *) &sock->lsa->local,
		sizeof (sock->lsa->local)))
	{
	  const int errnum = openvpn_errno_socket ();
	  msg (M_FATAL, "Socket bind failed on local address %s: %s",
	       print_sockaddr (&sock->lsa->local),
	       strerror_ts (errnum));
	}
    }
}

static void
resolve_remote (struct link_socket *sock,
		int phase,
		const char **remote_dynamic,
		volatile int *signal_received)
{
  if (!sock->did_resolve_remote)
    {
      /* resolve remote address if undefined */
      if (!addr_defined (&sock->lsa->remote))
	{
	  sock->lsa->remote.sin_family = AF_INET;
	  sock->lsa->remote.sin_addr.s_addr = 0;

	  if (sock->remote_host)
	    {
	      unsigned int flags = 0;
	      int retry = 0;
	      bool status = false;

	      if (phase == 1)
		{
		  if (sock->resolve_retry_seconds)
		    {
		      flags = GETADDR_RESOLVE;
		      retry = 0;
		    }
		  else
		    {
		      flags = GETADDR_RESOLVE | GETADDR_FATAL | GETADDR_MENTION_RESOLVE_RETRY;
		      retry = 0;
		    }
		}
	      else if (phase == 2)
		{
		  if (sock->resolve_retry_seconds)
		    {
		      flags = GETADDR_RESOLVE | GETADDR_FATAL;
		      retry = sock->resolve_retry_seconds;
		    }
		  else
		    {
		      ASSERT (0);
		    }
		}
	      else
		{
		  ASSERT (0);
		}

	      sock->lsa->remote.sin_addr.s_addr = getaddr (
		    flags,
		    sock->remote_host,
		    retry,
		    &status,
		    signal_received);

	      if (!status || (signal_received && *signal_received))
		return;
	    }

	  sock->lsa->remote.sin_port = htons (sock->remote_port);
	}
  
      /* should we re-use previous active remote address? */
      if (addr_defined (&sock->lsa->actual))
	{
	  msg (M_INFO, "Preserving recently used remote address: %s",
	       print_sockaddr (&sock->lsa->actual));
	  if (remote_dynamic)
	    *remote_dynamic = NULL;
	}
      else
	sock->lsa->actual = sock->lsa->remote;

      /* remember that we finished */
      sock->did_resolve_remote = true;
    }
}

int
link_socket_read_socks_udp (struct link_socket *sock,
			    struct buffer *buf,
			    struct sockaddr_in *from)
{
  int atyp;

  if (BLEN(buf) < 10)
    goto error;

  buf_read_u16 (buf);
  if (buf_read_u8 (buf) != 0)
    goto error;

  atyp = buf_read_u8 (buf);
  if (atyp != 1)		/* ATYP == 1 (IP V4) */
    goto error;

  buf_read (buf, &from->sin_addr, sizeof (from->sin_addr));
  buf_read (buf, &from->sin_port, sizeof (from->sin_port));

  return BLEN(buf);

 error:
  return -1;
}

int
link_socket_write_socks_udp (struct link_socket *sock,
			     struct buffer *buf,
			     struct sockaddr_in *to)
{
  /* 
   * Get a 10 byte subset buffer prepended to buf --
   * we expect these bytes will be here because
   * we allocated frame space in socks_adjust_frame_parameters.
   */
  struct buffer head = buf_sub (buf, 10, true);

  /* crash if not enough headroom in buf */
  ASSERT (buf_defined (&head));

  buf_write_u16 (&head, 0);	/* RSV = 0 */
  buf_write_u8 (&head, 0);	/* FRAG = 0 */
  buf_write_u8 (&head, '\x01'); /* ATYP = 1 (IP V4) */
  buf_write (&head, &to->sin_addr, sizeof (to->sin_addr));
  buf_write (&head, &to->sin_port, sizeof (to->sin_port));

#ifdef WIN32
  return link_socket_write_win32 (sock, buf, &sock->socks_relay);
#else
  return link_socket_write_udp_posix (sock, buf, &sock->socks_relay);
#endif
}

void
link_socket_reset (struct link_socket *sock)
{
  CLEAR (*sock);
  sock->sd = -1;
  sock->ctrl_sd = -1;
}

/* bind socket if necessary */
void
link_socket_init_phase1 (struct link_socket *sock,
			 const char *local_host,
			 const char *remote_host,
			 int local_port,
			 int remote_port,
			 int proto,
			 struct http_proxy_info *http_proxy,
			 struct socks_proxy_info *socks_proxy,
			 bool bind_local,
			 bool remote_float,
			 int inetd,
			 struct link_socket_addr *lsa,
			 const char *ipchange_command,
			 int resolve_retry_seconds,
			 int connect_retry_seconds,
			 int mtu_discover_type)
{
  link_socket_reset (sock);
  sock->local_host = local_host;
  sock->local_port = local_port;
  sock->proto = proto;
  sock->http_proxy = http_proxy;
  sock->socks_proxy = socks_proxy;
  sock->bind_local = bind_local;
  sock->remote_float = remote_float;
  sock->inetd = inetd;
  sock->lsa = lsa;
  sock->ipchange_command = ipchange_command;
  sock->resolve_retry_seconds = resolve_retry_seconds;
  sock->connect_retry_seconds = connect_retry_seconds;
  sock->mtu_discover_type = mtu_discover_type;

  /* are we running in HTTP proxy mode? */
  if (sock->http_proxy)
    {
      ASSERT (sock->proto == PROTO_TCPv4_CLIENT);
      ASSERT (!sock->inetd);

      /* the proxy server */
      sock->remote_host = http_proxy->server;
      sock->remote_port = http_proxy->port;

      /* the OpenVPN server we will use the proxy to connect to */
      sock->proxy_dest_host = remote_host;
      sock->proxy_dest_port = remote_port;
    }
  /* or in Socks proxy mode? */
  else if (sock->socks_proxy)
    {
      ASSERT (!sock->inetd);

      /* the proxy server */
      sock->remote_host = socks_proxy->server;
      sock->remote_port = socks_proxy->port;

      /* the OpenVPN server we will use the proxy to connect to */
      sock->proxy_dest_host = remote_host;
      sock->proxy_dest_port = remote_port;
    }
  else
    {
      sock->remote_host = remote_host;
      sock->remote_port = remote_port;
    }

  /* bind behavior for TCP server vs. client */
  if (sock->proto == PROTO_TCPv4_SERVER)
    sock->bind_local = true;
  else if (sock->proto == PROTO_TCPv4_CLIENT)
    sock->bind_local = false;

  /* were we started by inetd or xinetd? */
  if (sock->inetd)
    {
      ASSERT (sock->proto != PROTO_TCPv4_CLIENT);
      ASSERT (inetd_socket_descriptor >= 0);
      sock->sd = inetd_socket_descriptor;
    }
  else
    {
      create_socket (sock);
      resolve_bind_local (sock);
      resolve_remote (sock, 1, NULL, NULL);
    }
}

/* finalize socket initialization */
void
link_socket_init_phase2 (struct link_socket *sock,
			 const struct frame *frame,
			 volatile int *signal_received)
{
  const char *remote_dynamic = NULL;
  bool remote_changed = false;

  /* initialize buffers */
  socket_frame_init (frame, sock);

  /*
   * Pass a remote name to connect/accept so that
   * they can test for dynamic IP address changes
   * and throw a SIGUSR1 if appropriate.
   */
  if (sock->resolve_retry_seconds)
    remote_dynamic = sock->remote_host;

  /* were we started by inetd or xinetd? */
  if (sock->inetd)
    {
      if (sock->proto == PROTO_TCPv4_SERVER)
	sock->sd =
	  socket_listen_accept (sock->sd,
				&sock->lsa->actual,
				remote_dynamic,
				&remote_changed,
				&sock->lsa->local,
				false,
				sock->inetd == INETD_NOWAIT,
				signal_received);
      ASSERT (!remote_changed);
      if (*signal_received)
	return;
    }
  else
    {
      resolve_remote (sock, 2, &remote_dynamic, signal_received);

      if (*signal_received)
	return;

      /* TCP client/server */
      if (sock->proto == PROTO_TCPv4_SERVER)
	{
	  sock->sd = socket_listen_accept (sock->sd,
					   &sock->lsa->actual,
					   remote_dynamic,
					   &remote_changed,
					   &sock->lsa->local,
					   true,
					   false,
					   signal_received);
	}
      else if (sock->proto == PROTO_TCPv4_CLIENT)
	{
	  socket_connect (&sock->sd, &sock->lsa->actual,
			  remote_dynamic, &remote_changed,
			  sock->connect_retry_seconds,
			  signal_received);

	  if (*signal_received)
	    return;

	  if (sock->http_proxy)
	    {
	      establish_http_proxy_passthru (sock->http_proxy,
					     sock->sd,
					     sock->proxy_dest_host,
					     sock->proxy_dest_port,
					     &sock->stream_buf.residual,
					     signal_received);
	    }
	  else if (sock->socks_proxy)
	    {
	      establish_socks_proxy_passthru (sock->socks_proxy,
					      sock->sd,
					      sock->proxy_dest_host,
					      sock->proxy_dest_port,
					      signal_received);
	    }
	}
      else if (sock->proto == PROTO_UDPv4 && sock->socks_proxy)
	{
	  socket_connect (&sock->ctrl_sd, &sock->lsa->actual,
			  remote_dynamic, &remote_changed,
			  sock->connect_retry_seconds,
			  signal_received);

	  if (*signal_received)
	    return;

	  establish_socks_proxy_udpassoc (sock->socks_proxy,
					  sock->ctrl_sd,
					  sock->sd, &sock->socks_relay,
					  signal_received);

	  if (*signal_received)
	    return;

	  sock->remote_host = sock->proxy_dest_host;
	  sock->remote_port = sock->proxy_dest_port;
	  sock->did_resolve_remote = false;
	  sock->lsa->actual.sin_addr.s_addr = 0;
	  sock->lsa->remote.sin_addr.s_addr = 0;

	  resolve_remote (sock, 1, NULL, signal_received);

	  if (*signal_received)
	    return;
	}
      
      if (*signal_received)
	return;

      if (remote_changed)
	{
	  msg (M_INFO, "Note: Dynamic remote address changed during TCP connection establishment");
	  sock->lsa->remote.sin_addr.s_addr = sock->lsa->actual.sin_addr.s_addr;
	}
    }

  /* set socket to non-blocking mode */
  set_nonblock (sock->sd);

  /* set socket file descriptor to not pass across execs, so that
     scripts don't have access to it */
  set_cloexec (sock->sd);
  if (sock->ctrl_sd != -1)
    set_cloexec (sock->ctrl_sd);

  /* set Path MTU discovery options on the socket */
  set_mtu_discover_type (sock->sd, sock->mtu_discover_type);

#if EXTENDED_SOCKET_ERROR_CAPABILITY
  /* if the OS supports it, enable extended error passing on the socket */
  set_sock_extended_error_passing (sock->sd);
#endif

  /* print local address */
  if (sock->inetd)
    msg (M_INFO, "%s link local: [inetd]", proto2ascii (sock->proto, true));
  else
    msg (M_INFO, "%s link local%s: %s",
	 proto2ascii (sock->proto, true),
	 (sock->bind_local ? " (bound)" : ""),
	 print_sockaddr_ex (&sock->lsa->local, sock->bind_local, ":"));

  /* print active remote address */
  msg (M_INFO, "%s link remote: %s",
       proto2ascii (sock->proto, true),
       print_sockaddr_ex (&sock->lsa->actual, addr_defined (&sock->lsa->actual), ":"));
}

/* for stream protocols, allow for packet length prefix */
void
socket_adjust_frame_parameters (struct frame *frame, int proto)
{
  if (link_socket_proto_connection_oriented (proto))
    frame_add_to_extra_frame (frame, sizeof (packet_size_type));
}

void
link_socket_set_outgoing_addr (const struct buffer *buf,
			       struct link_socket *sock,
			       const struct sockaddr_in *addr)
{
  mutex_lock (L_SOCK);
  if (!buf || buf->len > 0)
    {
      struct link_socket_addr *lsa = sock->lsa;
      ASSERT (addr_defined (addr));
      if ((sock->remote_float
	   || !addr_defined (&lsa->remote)
	   || addr_match_proto (addr, &lsa->remote, sock->proto))
	  && (!addr_match_proto (addr, &lsa->actual, sock->proto)
	      || !sock->set_outgoing_initial))
	{
	  lsa->actual = *addr;
	  sock->set_outgoing_initial = true;
	  mutex_unlock (L_SOCK);
	  setenv_sockaddr ("trusted", &lsa->actual);
	  msg (M_INFO, "Peer Connection Initiated with %s", print_sockaddr (&lsa->actual));
	  if (sock->ipchange_command)
	    {
	      char command[512];
	      struct buffer out;
	      setenv_str ("script_type", "ipchange");
	      buf_set_write (&out, (uint8_t *)command, sizeof (command));
	      buf_printf (&out, "%s %s",
			  sock->ipchange_command,
			  print_sockaddr_ex (&lsa->actual, true, " "));
	      msg (D_TLS_DEBUG, "executing ip-change command: %s", command);
	      system_check (command, "ip-change command failed", false);
	    }
	  mutex_lock (L_SOCK);
	}
    }
  mutex_unlock (L_SOCK);
}

in_addr_t
link_socket_current_remote (const struct link_socket *sock)
{
  if (addr_defined (&sock->lsa->actual))
    {
      return ntohl (sock->lsa->actual.sin_addr.s_addr);
    }
  else if (addr_defined (&sock->lsa->remote))
    {
      return ntohl (sock->lsa->remote.sin_addr.s_addr);
    }
  else
    return 0;
}

void
link_socket_incoming_addr (struct buffer *buf,
			   const struct link_socket *sock,
			   const struct sockaddr_in *from_addr)
{
  mutex_lock (L_SOCK);
  if (buf->len > 0)
    {
      if (from_addr->sin_family != AF_INET)
	goto bad;
      if (!addr_defined (from_addr))
	goto bad;
      if (sock->remote_float || !addr_defined (&sock->lsa->remote))
	goto good;
      if (addr_match_proto (from_addr, &sock->lsa->remote, sock->proto))
	goto good;
    }

bad:
  msg (D_LINK_ERRORS,
       "NOTE: Incoming packet rejected from %s[%d], expected peer address: %s (allow this incoming source address/port by removing --remote or adding --float)",
       print_sockaddr (from_addr),
       (int)from_addr->sin_family,
       print_sockaddr (&sock->lsa->remote));
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
link_socket_get_outgoing_addr (struct buffer *buf,
			      const struct link_socket *sock,
			      struct sockaddr_in *addr)
{
  mutex_lock (L_SOCK);
  if (buf->len > 0)
    {
      struct link_socket_addr *lsa = sock->lsa;
      if (addr_defined (&lsa->actual))
	{
	  *addr = lsa->actual;
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
link_socket_close (struct link_socket *sock)
{
  if (sock->sd != -1)
    {
#ifdef WIN32
      overlapped_io_close (&sock->reads);
      overlapped_io_close (&sock->writes);
#endif
      msg (D_CLOSE, "Closing TCP/UDP socket");
      if (openvpn_close_socket (sock->sd))
	msg (M_WARN | M_ERRNO_SOCK, "Warning: Close Socket failed");
      sock->sd = -1;
    }
  if (sock->ctrl_sd != -1)
    {
      if (openvpn_close_socket (sock->ctrl_sd))
	msg (M_WARN | M_ERRNO_SOCK, "Warning: Close Socket failed");
      sock->ctrl_sd = -1;
    }
  stream_buf_close (&sock->stream_buf);
  free_buf (&sock->stream_buf_data);
}

/*
 * Stream buffer functions, used to packetize a TCP
 * stream connection.
 */

static inline void
stream_buf_reset (struct stream_buf *sb)
{
  msg (D_STREAM_DEBUG, "STREAM: RESET");
  sb->residual_fully_formed = false;
  sb->buf = sb->buf_init;
  CLEAR (sb->next);
  sb->len = -1;
}

void
stream_buf_init (struct stream_buf *sb,
		 struct buffer *buf)
{
  sb->buf_init = *buf;
  sb->maxlen = sb->buf_init.len;
  sb->buf_init.len = 0;
  sb->residual = alloc_buf (sb->maxlen);
  sb->error = false;
  stream_buf_reset (sb);

  msg (D_STREAM_DEBUG, "STREAM: INIT maxlen=%d", sb->maxlen);
}

static inline void
stream_buf_set_next (struct stream_buf *sb)
{
  /* set up 'next' for next i/o read */
  sb->next = sb->buf;
  sb->next.offset = sb->buf.offset + sb->buf.len;
  sb->next.len = (sb->len >= 0 ? sb->len : sb->maxlen) - sb->buf.len;
  msg (D_STREAM_DEBUG, "STREAM: SET NEXT, buf=[%d,%d] next=[%d,%d] len=%d maxlen=%d",
       sb->buf.offset, sb->buf.len,
       sb->next.offset, sb->next.len,
       sb->len, sb->maxlen);
  ASSERT (sb->next.len > 0);
  ASSERT (buf_safe (&sb->buf, sb->next.len));
}

static inline void
stream_buf_get_final (struct stream_buf *sb, struct buffer *buf)
{
  msg (D_STREAM_DEBUG, "STREAM: GET FINAL len=%d",
       buf_defined (&sb->buf) ? sb->buf.len : -1);
  ASSERT (buf_defined (&sb->buf));
  *buf = sb->buf;
}

static inline void
stream_buf_get_next (struct stream_buf *sb, struct buffer *buf)
{
  msg (D_STREAM_DEBUG, "STREAM: GET NEXT len=%d",
       buf_defined (&sb->next) ? sb->next.len : -1);
  ASSERT (buf_defined (&sb->next));
  *buf = sb->next;
}

bool
stream_buf_read_setup (struct link_socket* sock)
{
  if (link_socket_connection_oriented (sock))
    {
      if (sock->stream_buf.residual.len && !sock->stream_buf.residual_fully_formed)
	{
	  ASSERT (buf_copy (&sock->stream_buf.buf, &sock->stream_buf.residual));
	  ASSERT (buf_init (&sock->stream_buf.residual, 0));
	  sock->stream_buf.residual_fully_formed = stream_buf_added (&sock->stream_buf, 0);
	  msg (D_STREAM_DEBUG, "STREAM: RESIDUAL FULLY FORMED [%s], len=%d",
	       sock->stream_buf.residual_fully_formed ? "YES" : "NO",
	       sock->stream_buf.residual.len);
	}
      if (!sock->stream_buf.residual_fully_formed)
	stream_buf_set_next (&sock->stream_buf);
      return !sock->stream_buf.residual_fully_formed;
    }
  else
    return true;
}

bool
stream_buf_added (struct stream_buf *sb,
		  int length_added)
{
  msg (D_STREAM_DEBUG, "STREAM: ADD length_added=%d", length_added);
  if (length_added > 0)
    sb->buf.len += length_added;

  /* if length unknown, see if we can get the length prefix from
     the head of the buffer */
  if (sb->len < 0 && sb->buf.len >= (int) sizeof (packet_size_type))
    {
      packet_size_type net_size;
      ASSERT (buf_read (&sb->buf, &net_size, sizeof (net_size)));
      sb->len = ntohps (net_size);

      if (sb->len < 1 || sb->len > sb->maxlen)
	{
	  msg (M_WARN, "WARNING: Bad encapsulated packet length from peer (%d), which must be > 0 and <= %d -- please ensure that --tun-mtu or --link-mtu is equal on both peers -- this condition could also indicate a possible active attack on the TCP link -- [Attemping restart...]", sb->len, sb->maxlen);
	  stream_buf_reset (sb);
	  sb->error = true;
	  return false;
	}
    }

  /* is our incoming packet fully read? */
  if (sb->len > 0 && sb->buf.len >= sb->len)
    {
      /* save any residual data that's part of the next packet */
      ASSERT (buf_init (&sb->residual, 0));
      if (sb->buf.len > sb->len)
	  ASSERT (buf_copy_excess (&sb->residual, &sb->buf, sb->len));
      msg (D_STREAM_DEBUG, "STREAM: ADD returned TRUE, buf_len=%d, residual_len=%d",
	   BLEN (&sb->buf),
	   BLEN (&sb->residual));
      return true;
    }
  else
    {
      msg (D_STREAM_DEBUG, "STREAM: ADD returned FALSE (have=%d need=%d)", sb->buf.len, sb->len);
      stream_buf_set_next (sb);
      return false;
    }
}

void
stream_buf_close (struct stream_buf* sb)
{
  free_buf (&sb->residual);
}

/*
 * Format IP addresses in ascii
 */

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
  return BSTR (&out);
}

/*
 * Convert an in_addr_t in host byte order
 * to an ascii dotted quad.
 */
const char *
print_in_addr_t (in_addr_t addr, bool empty_if_undef)
{
  struct in_addr ia;
  struct buffer out = alloc_buf_gc (64);

  if (addr || !empty_if_undef)
    {
      CLEAR (ia);
      ia.s_addr = htonl (addr);

      mutex_lock (L_INET_NTOA);
      buf_printf (&out, "%s", inet_ntoa (ia));
      mutex_unlock (L_INET_NTOA);
    }
  return BSTR (&out);
}

/* set environmental variables for ip/port in *addr */
void
setenv_sockaddr (const char *name_prefix, const struct sockaddr_in *addr)
{
  char name_buf[256];

  openvpn_snprintf (name_buf, sizeof (name_buf), "%s_ip", name_prefix);
  mutex_lock (L_INET_NTOA);
  setenv_str (name_buf, inet_ntoa (addr->sin_addr));
  mutex_unlock (L_INET_NTOA);

  openvpn_snprintf (name_buf, sizeof (name_buf), "%s_port", name_prefix);
  setenv_int (name_buf, ntohs (addr->sin_port));
}

/*
 * Convert protocol names between index and ascii form.
 */

struct proto_names {
  const char *short_form;
  const char *display_form;
};

/* Indexed by PROTO_x */
static const struct proto_names proto_names[] = {
  {"udp",        "UDPv4"},
  {"tcp-server", "TCPv4_SERVER"},
  {"tcp-client", "TCPv4_CLIENT"}
};

int
ascii2proto (const char* proto_name)
{
  int i;
  ASSERT (PROTO_N == SIZE (proto_names));
  for (i = 0; i < PROTO_N; ++i)
    if (!strcmp (proto_name, proto_names[i].short_form))
      return i;
  return -1;
}

const char *
proto2ascii (int proto, bool display_form)
{
  ASSERT (PROTO_N == SIZE (proto_names));
  if (proto < 0 || proto >= PROTO_N)
    return "[unknown protocol]";
  else if (display_form)
    return proto_names[proto].display_form;
  else
    return proto_names[proto].short_form;
}

const char *
proto2ascii_all ()
{
  struct buffer out = alloc_buf_gc (256);
  int i;

  ASSERT (PROTO_N == SIZE (proto_names));
  for (i = 0; i < PROTO_N; ++i)
    {
      if (i)
	buf_printf(&out, " ");
      buf_printf(&out, "[%s]", proto2ascii(i, false));
    }
  return BSTR (&out);
}

/*
 * Given a local proto, return local proto
 * if !remote, or compatible remote proto
 * if remote.
 *
 * This is used for options compatibility
 * checking.
 */
int
proto_remote (int proto, bool remote)
{
  ASSERT (proto >= 0 && proto < PROTO_N);
  if (remote)
    {
      if (proto == PROTO_TCPv4_SERVER)
	return PROTO_TCPv4_CLIENT;
      if (proto == PROTO_TCPv4_CLIENT)
	return PROTO_TCPv4_SERVER;
    }
  return proto;
}

/*
 * Bad incoming address lengths that differ from what
 * we expect are considered to be fatal errors.
 */
void
bad_address_length (int actual, int expected)
{
  msg (M_FATAL, "ERROR: received strange incoming packet with an address length of %d -- we only accept address lengths of %d.",
       actual,
       expected);
}

/*
 * Socket Read Routines
 */

int
link_socket_read_tcp (struct link_socket *sock,
		      struct buffer *buf)
{
  int len = 0;

  if (!sock->stream_buf.residual_fully_formed)
    {
#ifdef WIN32
      len = socket_finalize (sock->sd, &sock->reads, buf, NULL);
#else
      struct buffer frag;
      stream_buf_get_next (&sock->stream_buf, &frag);
      len = recv (sock->sd, BPTR (&frag), BLEN (&frag), MSG_NOSIGNAL);
#endif

      if (!len)
	sock->stream_reset = true;
      if (len <= 0)
	return buf->len = len;
    }

  if (sock->stream_buf.residual_fully_formed
      || stream_buf_added (&sock->stream_buf, len)) /* packet complete? */
    {
      stream_buf_get_final (&sock->stream_buf, buf);
      stream_buf_reset (&sock->stream_buf);
      return buf->len;
    }
  else
    return buf->len = 0; /* no error, but packet is still incomplete */
}

/*
 * Win32 overlapped socket I/O functions.
 */

#ifdef WIN32

int
socket_recv_queue (struct link_socket *sock, int maxsize)
{
  if (sock->reads.iostate == IOSTATE_INITIAL)
    {
      WSABUF wsabuf[1];
      int status;

      /* reset buf to its initial state */
      if (sock->proto == PROTO_UDPv4)
	{
	  sock->reads.buf = sock->reads.buf_init;
	}
      else if (sock->proto == PROTO_TCPv4_CLIENT || sock->proto == PROTO_TCPv4_SERVER)
	{
	  stream_buf_get_next (&sock->stream_buf, &sock->reads.buf);
	}
      else
	{
	  ASSERT (0);
	}

      /* Win32 docs say it's okay to allocate the wsabuf on the stack */
      wsabuf[0].buf = BPTR (&sock->reads.buf);
      wsabuf[0].len = maxsize ? maxsize : BLEN (&sock->reads.buf);

      /* check for buffer overflow */
      ASSERT (wsabuf[0].len <= BLEN (&sock->reads.buf));

      /* the overlapped read will signal this event on I/O completion */
      ASSERT (ResetEvent (sock->reads.overlapped.hEvent));
      sock->reads.flags = 0;

      if (sock->proto == PROTO_UDPv4)
	{
	  sock->reads.addr_defined = true;
	  sock->reads.addrlen = sizeof (sock->reads.addr);
	  status = WSARecvFrom(
			       sock->sd,
			       wsabuf,
			       1,
			       &sock->reads.size,
			       &sock->reads.flags,
			       (struct sockaddr *) &sock->reads.addr,
			       &sock->reads.addrlen,
			       &sock->reads.overlapped,
			       NULL);
	}
      else if (sock->proto == PROTO_TCPv4_CLIENT || sock->proto == PROTO_TCPv4_SERVER)
	{
	  sock->reads.addr_defined = false;
	  status = WSARecv(
			   sock->sd,
			   wsabuf,
			   1,
			   &sock->reads.size,
			   &sock->reads.flags,
			   &sock->reads.overlapped,
			   NULL);
	}
      else
	{
	  status = 0;
	  ASSERT (0);
	}

      if (!status) /* operation completed immediately? */
	{
	  if (sock->reads.addr_defined && sock->reads.addrlen != sizeof (sock->reads.addr))
	    bad_address_length (sock->reads.addrlen, sizeof (sock->reads.addr));

	  sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (sock->reads.overlapped.hEvent));
	  sock->reads.status = 0;

	  msg (D_WIN32_IO, "WIN32 I/O: Socket Receive immediate return [%d,%d]",
	       (int) wsabuf[0].len,
	       (int) sock->reads.size);	       
	}
      else
	{
	  status = WSAGetLastError (); 
	  if (status == WSA_IO_PENDING) /* operation queued? */
	    {
	      sock->reads.iostate = IOSTATE_QUEUED;
	      sock->reads.status = status;
	      msg (D_WIN32_IO, "WIN32 I/O: Socket Receive queued [%d]",
		   (int) wsabuf[0].len);
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (sock->reads.overlapped.hEvent));
	      sock->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	      sock->reads.status = status;
	      msg (D_WIN32_IO, "WIN32 I/O: Socket Receive error [%d]: %s",
		   (int) wsabuf[0].len,
		   strerror_win32 (status));
	    }
	}
    }
  return sock->reads.iostate;
}

int
socket_send_queue (struct link_socket *sock, struct buffer *buf, const struct sockaddr_in *to)
{
  if (sock->writes.iostate == IOSTATE_INITIAL)
    {
      WSABUF wsabuf[1];
      int status;
 
      /* make a private copy of buf */
      sock->writes.buf = sock->writes.buf_init;
      sock->writes.buf.len = 0;
      ASSERT (buf_copy (&sock->writes.buf, buf));

      /* Win32 docs say it's okay to allocate the wsabuf on the stack */
      wsabuf[0].buf = BPTR (&sock->writes.buf);
      wsabuf[0].len = BLEN (&sock->writes.buf);

      /* the overlapped write will signal this event on I/O completion */
      ASSERT (ResetEvent (sock->writes.overlapped.hEvent));
      sock->writes.flags = 0;

      if (sock->proto == PROTO_UDPv4)
	{
	  /* set destination address for UDP writes */
	  sock->writes.addr_defined = true;
	  sock->writes.addr = *to;
	  sock->writes.addrlen = sizeof (sock->writes.addr);

	  status = WSASendTo(
			       sock->sd,
			       wsabuf,
			       1,
			       &sock->writes.size,
			       sock->writes.flags,
			       (struct sockaddr *) &sock->writes.addr,
			       sock->writes.addrlen,
			       &sock->writes.overlapped,
			       NULL);
	}
      else if (sock->proto == PROTO_TCPv4_CLIENT || sock->proto == PROTO_TCPv4_SERVER)
	{
	  /* destination address for TCP writes was established on connection initiation */
	  sock->writes.addr_defined = false;

	  status = WSASend(
			   sock->sd,
			   wsabuf,
			   1,
			   &sock->writes.size,
			   sock->writes.flags,
			   &sock->writes.overlapped,
			   NULL);
	}
      else 
	{
	  status = 0;
	  ASSERT (0);
	}

      if (!status) /* operation completed immediately? */
	{
	  sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (sock->writes.overlapped.hEvent));

	  sock->writes.status = 0;

	  msg (D_WIN32_IO, "WIN32 I/O: Socket Send immediate return [%d,%d]",
	       (int) wsabuf[0].len,
	       (int) sock->writes.size);	       
	}
      else
	{
	  status = WSAGetLastError (); 
	  if (status == WSA_IO_PENDING) /* operation queued? */
	    {
	      sock->writes.iostate = IOSTATE_QUEUED;
	      sock->writes.status = status;
	      msg (D_WIN32_IO, "WIN32 I/O: Socket Send queued [%d]",
		   (int) wsabuf[0].len);
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (sock->writes.overlapped.hEvent));
	      sock->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
	      sock->writes.status = status;

	      msg (D_WIN32_IO, "WIN32 I/O: Socket Send error [%d]: %s",
		   (int) wsabuf[0].len,
		   strerror_win32 (status));
	    }
	}
    }
  return sock->writes.iostate;
}

int
socket_finalize (
		 SOCKET s,
		 struct overlapped_io *io,
		 struct buffer *buf,
		 struct sockaddr_in *from)
{
  int ret = -1;
  BOOL status;

  switch (io->iostate)
    {
    case IOSTATE_QUEUED:
      status = WSAGetOverlappedResult(
				      s,
				      &io->overlapped,
				      &io->size,
				      FALSE,
				      &io->flags
				      );
      if (status)
	{
	  /* successful return for a queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	  ASSERT (ResetEvent (io->overlapped.hEvent));

	  msg (D_WIN32_IO, "WIN32 I/O: Socket Completion success [%d]", ret);
	}
      else
	{
	  /* error during a queued operation */
	  ret = -1;
	  if (WSAGetLastError() != WSA_IO_INCOMPLETE)
	    {
	      /* if no error (i.e. just not finished yet), then DON'T execute this code */
	      io->iostate = IOSTATE_INITIAL;
	      ASSERT (ResetEvent (io->overlapped.hEvent));
	      msg (D_WIN32_IO | M_ERRNO_SOCK, "WIN32 I/O: Socket Completion error");
	    }
	}
      break;

    case IOSTATE_IMMEDIATE_RETURN:
      io->iostate = IOSTATE_INITIAL;
      ASSERT (ResetEvent (io->overlapped.hEvent));
      if (io->status)
	{
	  /* error return for a non-queued operation */
	  WSASetLastError (io->status);
	  ret = -1;
	  msg (D_WIN32_IO | M_ERRNO_SOCK, "WIN32 I/O: Socket Completion non-queued error");
	}
      else
	{
	  /* successful return for a non-queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  msg (D_WIN32_IO, "WIN32 I/O: Socket Completion non-queued success [%d]", ret);
	}
      break;

    case IOSTATE_INITIAL: /* were we called without proper queueing? */
      WSASetLastError (WSAEINVAL);
      ret = -1;
      msg (D_WIN32_IO, "WIN32 I/O: Socket Completion BAD STATE");
      break;

    default:
      ASSERT (0);
    }
  
  /* return from address if requested */
  if (from)
    {
      if (ret >= 0 && io->addr_defined)
	{
	  if (io->addrlen != sizeof (io->addr))
	    bad_address_length (io->addrlen, sizeof (io->addr));
	  *from = io->addr;
	}
      else
	CLEAR (*from);
    }
  
  if (buf)
    buf->len = ret;
  return ret;
}

#endif /* WIN32 */
