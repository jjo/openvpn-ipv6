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

#ifndef SOCKET_H
#define SOCKET_H

#include "buffer.h"
#include "common.h"
#include "error.h"
#include "mtu.h"
#include "io.h"
#include "proxy.h"
#include "socks.h"

/* 
 * packet_size_type is used communicate packet size
 * over the wire when stream oriented protocols are
 * being used
 */

typedef uint16_t packet_size_type;

/* convert a packet_size_type from host to network order */
#define htonps(x) htons(x)

/* convert a packet_size_type from network to host order */
#define ntohps(x) ntohs(x)

/* IP addresses which are persistant across SIGUSR1s */
struct link_socket_addr
{
  struct sockaddr_in local;
  struct sockaddr_in remote; /* initial remote */
  struct sockaddr_in actual; /* remote may change due to --float */
};

/*
 * Used to extract packets encapsulated in streams into a buffer,
 * in this case IP packets embedded in a TCP stream.
 */
struct stream_buf
{
  struct buffer buf_init;
  struct buffer residual;
  int maxlen;
  bool residual_fully_formed;

  struct buffer buf;
  struct buffer next;
  int len;     /* -1 if not yet known */

  bool error;  /* if true, fatal TCP error has occurred,
		  requiring that connection be restarted */
};

/*
 * This is the main socket structure used by OpenVPN.  The SOCKET_
 * defines try to abstract away our implementation differences between
 * using sockets on Posix vs. Win32.
 */
struct link_socket
{
  /* if true, indicates a stream protocol returned more than one encapsulated packet */
# define SOCKET_READ_RESIDUAL(sock) (sock.stream_buf.residual_fully_formed)

#ifdef WIN32
  /* these macros are called in the context of the openvpn() function */
# define SOCKET_SET_READ(sock) { if (stream_buf_read_setup (&sock)) { \
                                   wait_add (&event_wait, sock.reads.overlapped.hEvent); \
                                   socket_recv_queue (&sock, 0); }}
# define SOCKET_SET_WRITE(sock) { wait_add (&event_wait, sock.writes.overlapped.hEvent); }
# define SOCKET_ISSET(sock, set) ( wait_trigger (&event_wait, sock.set.overlapped.hEvent))
# define SOCKET_SETMAXFD(sock)
# define SOCKET_READ_STAT(sock)  (overlapped_io_state_ascii (&sock.reads,  "sr"))
# define SOCKET_WRITE_STAT(sock) (overlapped_io_state_ascii (&sock.writes, "sw"))
  struct overlapped_io reads;
  struct overlapped_io writes;
#else
  /* these macros are called in the context of the openvpn() function */
# define SOCKET_SET_READ(sock) {  if (stream_buf_read_setup (&sock)) \
                                    FD_SET (sock.sd, &event_wait.reads); }
# define SOCKET_SET_WRITE(sock) { FD_SET (sock.sd, &event_wait.writes); }
# define SOCKET_ISSET(sock, set) (FD_ISSET (sock.sd, &event_wait.set))
# define SOCKET_SETMAXFD(sock) { wait_update_maxfd (&event_wait, sock.sd); }
# define SOCKET_READ_STAT(sock)  (SOCKET_ISSET (sock, reads) ?  "SR" : "sr")
# define SOCKET_WRITE_STAT(sock) (SOCKET_ISSET (sock, writes) ? "SW" : "sw")
#endif

  socket_descriptor_t sd;
  socket_descriptor_t ctrl_sd;  /* only used for UDP over Socks */

  /* set on initial call to init phase 1 */
  const char *local_host;
  const char *remote_host;
  int local_port;
  int remote_port;
  int proto;                    /* Protocol (PROTO_x defined below) */
  bool bind_local;
  bool remote_float;

# define INETD_NONE   0
# define INETD_WAIT   1
# define INETD_NOWAIT 2
  int inetd;

  struct link_socket_addr *lsa;
  const char *ipchange_command;
  int resolve_retry_seconds;
  int connect_retry_seconds;
  int mtu_discover_type;

  int mtu;                      /* OS discovered MTU, or 0 if unknown */
  int mtu_changed;              /* Set to true when mtu value is changed */

  bool did_resolve_remote;

# define CONNECTION_ESTABLISHED(ls) ((ls)->set_outgoing_initial)
  bool set_outgoing_initial;

  /* for stream sockets */
  struct stream_buf stream_buf;
  struct buffer stream_buf_data;
  bool stream_reset;

  /* HTTP proxy */
  struct http_proxy_info *http_proxy;

  /* Socks proxy */
  struct socks_proxy_info *socks_proxy;
  struct sockaddr_in socks_relay; /* Socks UDP relay address */

  /* The OpenVPN server we will use the proxy to connect to */
  const char *proxy_dest_host;
  int proxy_dest_port;
};

/*
 * Some Posix/Win32 differences.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef WIN32

#define ECONNRESET WSAECONNRESET
#define openvpn_close_socket(s) closesocket(s)

int inet_aton (const char *name, struct in_addr *addr);

int socket_recv_queue (struct link_socket *sock, int maxsize);

int socket_send_queue (struct link_socket *sock,
		       struct buffer *buf,
		       const struct sockaddr_in *to);

int socket_finalize (
		     SOCKET s,
		     struct overlapped_io *io,
		     struct buffer *buf,
		     struct sockaddr_in *from);

#else

#define openvpn_close_socket(s) close(s)

#endif

int link_socket_read_socks_udp (struct link_socket *sock,
				struct buffer *buf,
				struct sockaddr_in *from);

int link_socket_write_socks_udp (struct link_socket *sock,
				 struct buffer *buf,
				 struct sockaddr_in *to);

void link_socket_reset (struct link_socket *sock);

void link_socket_init_phase1 (struct link_socket *sock,
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
			      int mtu_discover_type);


void link_socket_init_phase2 (struct link_socket *sock,
			      const struct frame *frame,
			      volatile int *signal_received);

void socket_adjust_frame_parameters (struct frame *frame, int proto);

void frame_adjust_path_mtu (struct frame *frame, int pmtu, int proto);

void link_socket_set_outgoing_addr (const struct buffer *buf,
				    struct link_socket *sock,
				    const struct sockaddr_in *addr);

void link_socket_incoming_addr (struct buffer *buf,
				const struct link_socket *sock,
				const struct sockaddr_in *from_addr);

void link_socket_get_outgoing_addr (struct buffer *buf,
				    const struct link_socket *sock,
				    struct sockaddr_in *addr);

void link_socket_close (struct link_socket *sock);

const char *print_sockaddr_ex (const struct sockaddr_in *addr,
			       bool do_port,
			       const char* separator);

const char *print_sockaddr (const struct sockaddr_in *addr);

const char *print_in_addr_t (in_addr_t addr, bool empty_if_undef);

void setenv_sockaddr (const char *name_prefix,
		      const struct sockaddr_in *addr);

void bad_address_length (int actual, int expected);

in_addr_t link_socket_current_remote (const struct link_socket *sock);

/*
 * DNS resolution
 */

#define GETADDR_RESOLVE               (1<<0)
#define GETADDR_FATAL                 (1<<1)
#define GETADDR_HOST_ORDER            (1<<2)
#define GETADDR_MENTION_RESOLVE_RETRY (1<<3)
#define GETADDR_FATAL_ON_SIGNAL       (1<<4)
#define GETADDR_WARN_ON_SIGNAL        (1<<5)

in_addr_t getaddr (unsigned int flags,
		   const char *hostname,
		   int resolve_retry_seconds,
		   bool *succeeded,
		   volatile int *signal_received);

/*
 * Transport protocol naming and other details.
 */

#define PROTO_UDPv4        0
#define PROTO_TCPv4_SERVER 1
#define PROTO_TCPv4_CLIENT 2
#define PROTO_N            3

int ascii2proto (const char* proto_name);
const char *proto2ascii (int proto, bool display_form);
const char *proto2ascii_all ();
int proto_remote (int proto, bool remote);

/*
 * Overhead added to packets by various protocols.
 */
#define IPv4_UDP_HEADER_SIZE              28
#define IPv4_TCP_HEADER_SIZE              40
#define IPv6_UDP_HEADER_SIZE              40

static const int proto_overhead[] = { /* indexed by PROTO_x */
  IPv4_UDP_HEADER_SIZE,
  IPv4_TCP_HEADER_SIZE,
  IPv4_TCP_HEADER_SIZE
};

static inline int
datagram_overhead (int proto)
{
  ASSERT (proto >= 0 && proto < PROTO_N);
  return proto_overhead [proto];
}

/*
 * Misc inline functions
 */

static inline bool
legal_ipv4_port (int port)
{
  return port > 0 && port < 65536;
}

static inline bool
link_socket_proto_connection_oriented (int proto)
{
  return proto == PROTO_TCPv4_SERVER || proto == PROTO_TCPv4_CLIENT;
}

static inline bool
link_socket_connection_oriented (const struct link_socket *sock)
{
  return link_socket_proto_connection_oriented (sock->proto);
}

static inline bool
addr_defined (const struct sockaddr_in *addr)
{
  return addr->sin_addr.s_addr != 0;
}

static inline bool
addr_match (const struct sockaddr_in *a1, const struct sockaddr_in *a2)
{
  return a1->sin_addr.s_addr == a2->sin_addr.s_addr;
}

static inline in_addr_t
addr_host (const struct sockaddr_in *s)
{
  return ntohl (s->sin_addr.s_addr);
}

static inline bool
addr_port_match (const struct sockaddr_in *a1, const struct sockaddr_in *a2)
{
  return a1->sin_addr.s_addr == a2->sin_addr.s_addr
    && a1->sin_port == a2->sin_port;
}

static inline bool
addr_match_proto (const struct sockaddr_in *a1,
		  const struct sockaddr_in *a2,
		  int proto)
{
  return link_socket_proto_connection_oriented (proto)
    ? addr_match (a1, a2)
    : addr_port_match (a1, a2);
}

static inline bool
socket_connection_reset (const struct link_socket *sock, int status)
{
  if (link_socket_connection_oriented (sock))
    {
      if (sock->stream_reset || sock->stream_buf.error)
	return true;
      else if (status < 0)
	{
	  const int err = openvpn_errno_socket ();
	  return err == ECONNRESET;
	}
    }
  return false;
}

/*
 * Stream buffer handling -- stream_buf is a helper class
 * to assist in the packetization of stream transport protocols
 * such as TCP.
 */

void stream_buf_init (struct stream_buf *sb, struct buffer *buf);
void stream_buf_close (struct stream_buf* sb);
bool stream_buf_added (struct stream_buf *sb, int length_added);

bool stream_buf_read_setup (struct link_socket* sock);

/*
 * Socket Read Routines
 */

int
link_socket_read_tcp (struct link_socket *sock,
		      struct buffer *buf);

#ifdef WIN32

static inline int
link_socket_read_udp_win32 (struct link_socket *sock,
			    struct buffer *buf,
			    struct sockaddr_in *from)
{
  return socket_finalize (sock->sd, &sock->reads, buf, from);
}

#else

static inline int
link_socket_read_udp_posix (struct link_socket *sock,
			    struct buffer *buf,
			    int maxsize,
			    struct sockaddr_in *from)
{
  socklen_t fromlen = sizeof (*from);
  CLEAR (*from);
  ASSERT (buf_safe (buf, maxsize));
  buf->len = recvfrom (sock->sd, BPTR (buf), maxsize, 0,
		       (struct sockaddr *) from, &fromlen);
  if (fromlen != sizeof (*from))
    bad_address_length (fromlen, sizeof (*from));
  return buf->len;
}

#endif

/* read a TCP or UDP packet from link */
static inline int
link_socket_read (struct link_socket *sock,
		  struct buffer *buf,
		  int maxsize,
		  struct sockaddr_in *from)
{
  if (sock->proto == PROTO_UDPv4)
    {
      int res;

#ifdef WIN32
      res = link_socket_read_udp_win32 (sock, buf, from);
#else
      res = link_socket_read_udp_posix (sock, buf, maxsize, from);
#endif

      if (sock->socks_proxy && res > 0)
	res = link_socket_read_socks_udp (sock, buf, from);

      return res;
    }
  else if (sock->proto == PROTO_TCPv4_SERVER || sock->proto == PROTO_TCPv4_CLIENT)
    {
      /* from address was returned by accept */
      *from = sock->lsa->actual;
      return link_socket_read_tcp (sock, buf);
    }
  else
    {
      ASSERT (0);
      return -1; /* NOTREACHED */
    }
}

/*
 * Socket Write routines
 */

int link_socket_read_tcp (struct link_socket *sock,
			  struct buffer *buf);

#ifdef WIN32

static inline int
link_socket_write_win32 (struct link_socket *sock,
			 struct buffer *buf,
			 struct sockaddr_in *to)
{
  int err = 0;
  int status = 0;
  if (overlapped_io_active (&sock->writes))
    {
      status = socket_finalize (sock->sd, &sock->writes, NULL, NULL);
      if (status < 0)
	err = WSAGetLastError ();
    }
  socket_send_queue (sock, buf, to);
  if (status < 0)
    {
      WSASetLastError (err);
      return status;
    }
  else
    return BLEN (buf);
}

#else

static inline int
link_socket_write_udp_posix (struct link_socket *sock,
			     struct buffer *buf,
			     struct sockaddr_in *to)
{
  return sendto (sock->sd, BPTR (buf), BLEN (buf), 0,
		 (struct sockaddr *) to,
		 (socklen_t) sizeof (*to));
}

static inline int
link_socket_write_tcp_posix (struct link_socket *sock,
			     struct buffer *buf,
			     struct sockaddr_in *to)
{
  return send (sock->sd, BPTR (buf), BLEN (buf), MSG_NOSIGNAL);
}

#endif

static inline int
link_socket_write_udp (struct link_socket *sock,
		       struct buffer *buf,
		       struct sockaddr_in *to)
{
  if (sock->socks_proxy)
    {
      return link_socket_write_socks_udp (sock, buf, to);
    }
  else
    {
#ifdef WIN32
      return link_socket_write_win32 (sock, buf, to);
#else
      return link_socket_write_udp_posix (sock, buf, to);
#endif
    }
}

static inline int
link_socket_write_tcp (struct link_socket *sock,
		       struct buffer *buf,
		       struct sockaddr_in *to)
{
  packet_size_type len = BLEN (buf);
  msg (D_STREAM_DEBUG, "STREAM: WRITE %d offset=%d", (int)len, buf->offset);
  ASSERT (len <= sock->stream_buf.maxlen);
  len = htonps (len);
  ASSERT (buf_write_prepend (buf, &len, sizeof (len)));
#ifdef WIN32
  return link_socket_write_win32 (sock, buf, to);
#else
  return link_socket_write_tcp_posix (sock, buf, to);  
#endif
}

/* write a TCP or UDP packet to link */
static inline int
link_socket_write (struct link_socket *sock,
		   struct buffer *buf,
		   struct sockaddr_in *to)
{
  if (sock->proto == PROTO_UDPv4)
    {
      return link_socket_write_udp (sock, buf, to);
    }
  else if (sock->proto == PROTO_TCPv4_SERVER || sock->proto == PROTO_TCPv4_CLIENT)
    {
      return link_socket_write_tcp (sock, buf, to);
    }
  else
    {
      ASSERT (0);
      return -1; /* NOTREACHED */
    }
}

#endif /* SOCKET_H */
