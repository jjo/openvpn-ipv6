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

/*
 * Support routines for adding/deleting network routes.
 */

#ifndef ROUTE_H
#define ROUTE_H

#define MAX_ROUTES 50

struct route_special_addr
{
  in_addr_t remote_endpoint;
  bool remote_endpoint_defined;
  in_addr_t net_gateway;
  bool net_gateway_defined;
  in_addr_t remote_host;
  bool remote_host_defined;
};

struct route_option {
  const char *network;
  const char *netmask;
  const char *gateway;
  const char *metric;
};

struct route_option_list {
  int n;
  bool redirect_default_gateway;
  struct route_option routes[MAX_ROUTES];
};

struct route {
  bool defined;
  const struct route_option *option;
  in_addr_t network;
  in_addr_t netmask;
  in_addr_t gateway;
  bool metric_defined;
  int metric;
};

struct route_list {
  bool routes_added;
  struct route_special_addr spec;
  bool redirect_default_gateway;
  bool did_redirect_default_gateway;

  int n;
  struct route routes[MAX_ROUTES];
};

void add_route_to_option_list (struct route_option_list *l,
			       const char *network,
			       const char *netmask,
			       const char *gateway,
			       const char *metric);

void clear_route_list (struct route_list *rl);

bool init_route_list (struct route_list *rl,
		      const struct route_option_list *opt,
		      const char *remote_endpoint,
		      in_addr_t remote_host);

void add_routes (struct route_list *rl,
		 bool delete_first);

void delete_routes (struct route_list *rl);
void setenv_routes (const struct route_list *rl);

void print_route_options (const struct route_option_list *rol,
			  int level);

void print_routes (const struct route_list *rl, int level);


#endif
