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

#ifndef PROXY_H
#define PROXY_H

/* HTTP CONNECT authentication methods */
#define HTTP_AUTH_NONE  0
#define HTTP_AUTH_BASIC 1
#define HTTP_AUTH_N     2

struct http_proxy_info {
  bool defined;
  bool retry;

  char server[128];
  int port;

  int auth_method;
  char username[128];
  char password[128];
};

void init_http_proxy (struct http_proxy_info *p,
		      const char *server,
		      int port,
		      bool retry,
		      const char *auth_method,
		      const char *auth_file);

void establish_http_proxy_passthru (struct http_proxy_info *p,
				    socket_descriptor_t sd, /* already open to proxy */
				    const char *host,       /* openvpn server remote */
				    const int port,         /* openvpn server port */
				    struct buffer *lookahead,
				    volatile int *signal_received);

#endif
