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

#include "common.h"
#include "buffer.h"
#include "misc.h"
#include "io.h"
#include "socket.h"
#include "fdmisc.h"
#include "proxy.h"

#include "memdbg.h"

static bool
recv_line (socket_descriptor_t sd,
	   char *buf,
	   int len,
	   const int timeout_sec,
	   const bool verbose,
	   struct buffer *lookahead,
	   volatile int *signal_received)
{
  struct buffer la;
  int lastc = 0;

  CLEAR (la);
  if (lookahead)
    la = *lookahead;

  while (true)
    {
      int status;
      ssize_t size;
      fd_set reads;
      struct timeval tv;
      uint8_t c;

      if (buf_defined (&la))
	{
	  ASSERT (buf_init (&la, 0));
	}

      FD_ZERO (&reads);
      FD_SET (sd, &reads);
      tv.tv_sec = timeout_sec;
      tv.tv_usec = 0;

      status = select (sd + 1, &reads, NULL, NULL, &tv);

      GET_SIGNAL (*signal_received);
      if (*signal_received)
	goto error;

      /* timeout? */
      if (status == 0)
	{
	  if (verbose)
	    msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: TCP port read timeout expired");
	  goto error;
	}

      /* error */
      if (status < 0)
	{
	  if (verbose)
	    msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: TCP port read failed on select()");
	  goto error;
	}

      /* read single char */
      size = recv (sd, &c, 1, MSG_NOSIGNAL);

      /* error? */
      if (size != 1)
	{
	  if (verbose)
	    msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: TCP port read failed on recv()");
	  goto error;
	}

#if 0
      if (isprint(c))
	msg (M_INFO, "PROXY: read '%c' (%d)", c, (int)c);
      else
	msg (M_INFO, "PROXY: read (%d)", (int)c);
#endif

      /* store char in buffer */
      if (len > 1)
	{
	  *buf++ = c;
	  --len;
	}

      /* also store char in lookahead buffer */
      if (buf_defined (&la))
	{
	  buf_write_u8 (&la, c);
	  if (!isprint(c) && !isspace(c)) /* not ascii? */
	    {
	      if (verbose)
		msg (D_LINK_ERRORS | M_ERRNO_SOCK, "recv_line: Non-ASCII character (%d) read on recv()", (int)c);
	      *lookahead = la;
	      return false;
	    }
	}

      /* end of line? */
      if (lastc == '\r' && c == '\n')
	break;

      lastc = c;
    }

  /* append trailing null */
  if (len > 0)
    *buf++ = '\0';

  return true;

 error:
  return false;
}

static bool
send_line (socket_descriptor_t sd,
	   const char *buf)
{
  const ssize_t size = send (sd, buf, strlen (buf), MSG_NOSIGNAL);
  if (size != (ssize_t) strlen (buf))
    {
      msg (D_LINK_ERRORS | M_ERRNO_SOCK, "send_line: TCP port write failed on send()");
      return false;
    }
  return true;
}

static bool
send_line_crlf (socket_descriptor_t sd,
		const char *src)
{
  bool ret;

  struct buffer buf = alloc_buf (strlen (src) + 3);
  ASSERT (buf_write (&buf, src, strlen (src)));
  ASSERT (buf_write (&buf, "\r\n", 3));
  ret = send_line (sd, BSTR (&buf));
  free_buf (&buf);
  return ret;
}

static bool
send_crlf (socket_descriptor_t sd)
{
  return send_line_crlf (sd, "");
}

static uint8_t *
make_base64_string (const uint8_t *str)
{
  static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  uint8_t *buf;
  const uint8_t *src;
  uint8_t *dst;
  int bits, data, src_len, dst_len;

  /* make base64 string */
  src_len = strlen (str);
  dst_len = (src_len + 2) / 3 * 4;
  buf = gc_malloc (dst_len + 1);
  bits = data = 0;
  src = str;
  dst = buf;
  while (dst_len--)
    {
      if (bits < 6)
	{
	  data = (data << 8) | *src;
	  bits += 8;
	  if (*src != 0)
	    src++;
	}
      *dst++ = base64_table[0x3F & (data >> (bits - 6))];
      bits -= 6;
    }
  *dst = '\0';

  /* fix-up tail padding */
  switch (src_len % 3)
    {
    case 1:
      *--dst = '=';
    case 2:
      *--dst = '=';
    }
  return buf;
}

static const char *
username_password_as_base64 (const struct http_proxy_info *p)
{
  struct buffer out = alloc_buf_gc (strlen (p->username) + strlen (p->password) + 2);
  ASSERT (strlen (p->username) > 0);
  buf_printf (&out, "%s:%s", p->username, p->password);
  return make_base64_string (BSTR (&out));
}

void
init_http_proxy (struct http_proxy_info *p,
		 const char *server,
		 int port,
		 bool retry,
		 const char *auth_method,
		 const char *auth_file)
{
  CLEAR (*p);
  ASSERT (server);
  ASSERT (legal_ipv4_port (port));

  strncpynt (p->server, server, sizeof (p->server));
  p->port = port;
  p->retry = retry;
  p->auth_method = HTTP_AUTH_NONE;

  /* parse authentication method */
  if (auth_method)
    {
      if (!strcmp (auth_method, "none"))
	p->auth_method = HTTP_AUTH_NONE;
      else if (!strcmp (auth_method, "basic"))
	p->auth_method = HTTP_AUTH_BASIC;
      else
	msg (M_FATAL, "ERROR: unknown HTTP authentication method: '%s' -- only the 'none' or 'basic' methods are currently supported",
	     auth_method);
    }

  /* only basic authentication supported so far */
  if (p->auth_method == HTTP_AUTH_BASIC)
    {
      FILE *fp;
      
      if (!auth_file)
	msg (M_FATAL, "ERROR: http proxy authentication requires a username/password file");

      p->auth_method = HTTP_AUTH_BASIC;
      warn_if_group_others_accessible (auth_file);
      fp = fopen (auth_file, "r");
      if (!fp)
	msg (M_ERR, "Error opening http proxy auth_file: %s", auth_file);
      
      if (fgets (p->username, sizeof (p->username), fp) == NULL
	  || fgets (p->password, sizeof (p->password), fp) == NULL)
	msg (M_FATAL, "Error reading username and password (must be on two consecutive lines) from http proxy authfile: %s", auth_file);
      
      fclose (fp);
      
      chomp (p->username);
      chomp (p->password);
      
      if (strlen (p->username) == 0)
	msg (M_FATAL, "ERROR: username from http proxy authfile '%s' is empty", auth_file);
    }

  p->defined = true;
}

void
establish_http_proxy_passthru (struct http_proxy_info *p,
			       socket_descriptor_t sd, /* already open to proxy */
			       const char *host,       /* openvpn server remote */
			       const int port,         /* openvpn server port */
			       struct buffer *lookahead,
			       volatile int *signal_received)
{
  char buf[128];
  int status;
  int nparms;

  /* format HTTP CONNECT message */
  openvpn_snprintf (buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0", host, port);
  msg (D_PROXY, "Send to HTTP proxy: '%s'", buf);

  /* send HTTP CONNECT message to proxy */
  if (!send_line_crlf (sd, buf))
    goto error;

  /* auth specified? */
  switch (p->auth_method)
    {
    case HTTP_AUTH_NONE:
      break;

    case HTTP_AUTH_BASIC:
      openvpn_snprintf (buf, sizeof(buf), "Proxy-Authorization: Basic %s",
			username_password_as_base64 (p));
      msg (D_PROXY, "Attempting Basic Proxy-Authorization");
      msg (D_SHOW_KEYS, "Send to HTTP proxy: '%s'", buf);
      sleep (1);
      if (!send_line_crlf (sd, buf))
	goto error;
      break;

    default:
      ASSERT (0);
    }

  /* send empty CR, LF */
  sleep (1);
  if (!send_crlf (sd))
    goto error;

  /* receive reply from proxy */
  if (!recv_line (sd, buf, sizeof(buf), 5, true, NULL, signal_received))
    goto error;

  /* remove trailing CR, LF */
  chomp (buf);

  msg (D_PROXY, "HTTP proxy returned: '%s'", buf);

  /* parse return string */
  nparms = sscanf (buf, "%*s %d", &status);

  /* check return code, success = 200 */
  if (nparms != 1 || status != 200)
    {
      msg (D_LINK_ERRORS, "HTTP proxy returned bad status");
#if 0
      /* DEBUGGING -- show a multi-line HTTP error response */
      while (true)
	{
	  if (!recv_line (sd, buf, sizeof (buf), 5, true, NULL, signal_received))
	    goto error;
	  chomp (buf);
	  msg (D_PROXY, "HTTP proxy returned: '%s'", buf);
	}
#endif
      goto error;
    }

  /* receive line from proxy and discard */
  if (!recv_line (sd, NULL, 0, 5, true, NULL, signal_received))
    goto error;

  /*
   * Toss out any extraneous chars, but don't throw away the
   * start of the OpenVPN data stream (put it in lookahead).
   */
  while (recv_line (sd, NULL, 0, 2, false, lookahead, signal_received))
    ;

#if 0
  if (lookahead && BLEN (lookahead))
    msg (M_INFO, "HTTP PROXY: lookahead: %s", format_hex (BPTR (lookahead), BLEN (lookahead), 0));
#endif

  return;

 error:
  /* on error, should we exit or restart? */
  if (!*signal_received)
    *signal_received = (p->retry ? SIGUSR1 : SIGTERM);
  return;
}
