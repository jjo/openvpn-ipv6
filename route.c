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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "common.h"
#include "buffer.h"
#include "error.h"
#include "route.h"
#include "misc.h"
#include "socket.h"
#include "tun.h"

#include "memdbg.h"

#if defined(TARGET_FREEBSD)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct {
  struct rt_msghdr m_rtm;
  char       m_space[512];
} m_rtmsg;

#endif

static void add_route (struct route *r);
static void delete_route (const struct route *r);
static bool get_default_gateway (in_addr_t *ret);

static const char *
route_string (const struct route *r)
{
  struct buffer out = alloc_buf_gc (256);
  buf_printf (&out, "ROUTE network %s netmask %s gateway %s",
	      print_in_addr_t (r->network, false),
	      print_in_addr_t (r->netmask, false),
	      print_in_addr_t (r->gateway, false)
	      );
  if (r->metric_defined)
    buf_printf (&out, " metric %d", r->metric);
  return BSTR (&out);
}

static bool
is_route_parm_defined (const char *parm)
{
  if (!parm)
    return false;
  if (!strcmp (parm, "default"))
    return false;
  return true;
}

static void
setenv_route_addr (const char *key, const in_addr_t addr, int i)
{
  char name[128];
  if (i >= 0)
    openvpn_snprintf (name, sizeof (name), "route_%s_%d", key, i);
  else
    openvpn_snprintf (name, sizeof (name), "route_%s", key);
  setenv_str (name, print_in_addr_t (addr, false));
}

static bool
get_special_addr (const struct route_special_addr *spec,
		  const char *string,
		  in_addr_t *out,
		  bool *status)
{
  *status = true;
  if (!strcmp (string, "vpn_gateway"))
    {
      if (spec->remote_endpoint_defined)
	*out = spec->remote_endpoint;
      else
	{
	  msg (M_INFO, PACKAGE_NAME " ROUTE: vpn_gateway undefined");
	  *status = false;
	}
      return true;
    }
  else if (!strcmp (string, "net_gateway"))
    {
      if (spec->net_gateway_defined)
	*out = spec->net_gateway;
      else
	{
	  msg (M_INFO, PACKAGE_NAME " ROUTE: net_gateway undefined -- unable to get default gateway from system");
	  *status = false;
	}
      return true;
    }
  else if (!strcmp (string, "remote_host"))
    {
      if (spec->remote_host_defined)
	*out = spec->remote_host;
      else
	{
	  msg (M_INFO, PACKAGE_NAME " ROUTE: remote_host undefined");
	  *status = false;
	}
      return true;
    }
  return false;
}

static bool
init_route (struct route *r,
	    const struct route_option *ro,
	    const struct route_special_addr *spec)
{
  const in_addr_t default_netmask = ~0;
  bool status;

  r->option = ro;
  r->defined = false;

  /* network */

  if (!is_route_parm_defined (ro->network))
    {
      goto fail;
    }
  
  if (!get_special_addr (spec, ro->network, &r->network, &status))
    {
      r->network = getaddr (
			    GETADDR_RESOLVE
			    | GETADDR_HOST_ORDER
			    | GETADDR_FATAL_ON_SIGNAL,
			    ro->network,
			    0,
			    &status,
			    NULL);
    }

  if (!status)
    goto fail;

  /* netmask */

  if (is_route_parm_defined (ro->netmask))
    {
      r->netmask = getaddr (
			    GETADDR_HOST_ORDER
			    | GETADDR_FATAL_ON_SIGNAL,
			    ro->netmask,
			    0,
			    &status,
			    NULL);
      if (!status)
	goto fail;
    }
  else
    r->netmask = default_netmask;

  /* gateway */

  if (is_route_parm_defined (ro->gateway))
    {
      if (!get_special_addr (spec, ro->gateway, &r->gateway, &status))
	{
	  r->gateway = getaddr (
				GETADDR_RESOLVE
				| GETADDR_HOST_ORDER
				| GETADDR_FATAL_ON_SIGNAL,
				ro->gateway,
				0,
				&status,
				NULL);
	}
      if (!status)
	goto fail;
    }
  else
    {
      if (spec->remote_endpoint_defined)
	r->gateway = spec->remote_endpoint;
      else
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: " PACKAGE_NAME " needs a gateway parameter for a --route option and no default was specified by either --route-gateway or --ifconfig options");
	  goto fail;
	}
    }

  /* metric */

  r->metric_defined = false;
  r->metric = 0;
  if (is_route_parm_defined (ro->metric))
    {
      r->metric = atoi (ro->metric);
      if (r->metric < 0)
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: route metric for network %s (%s) must be >= 0",
	       ro->network,
	       ro->metric);
	  goto fail;
	}
      r->metric_defined = true;
    }
  else
    {
      r->metric = 0;
      r->metric_defined = false;
    }

  r->defined = true;

  return true;

 fail:
  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve route for host/network: %s",
       ro->network);
  r->defined = false;
  return false;
}

void
add_route_to_option_list (struct route_option_list *l,
			  const char *network,
			  const char *netmask,
			  const char *gateway,
			  const char *metric)
{
  struct route_option *ro;
  if (l->n >= MAX_ROUTES)
    msg (M_FATAL, PACKAGE_NAME " ROUTE: cannot add more than %d routes",
	 MAX_ROUTES);
  ro = &l->routes[l->n];
  ro->network = network;
  ro->netmask = netmask;
  ro->gateway = gateway;
  ro->metric = metric;
  ++l->n;
}

void
clear_route_list (struct route_list *rl)
{
  CLEAR (*rl);
}

bool
init_route_list (struct route_list *rl,
		 const struct route_option_list *opt,
		 const char *remote_endpoint,
		 in_addr_t remote_host)
{
  int i;
  bool ret = true;

  clear_route_list (rl);

  if (remote_host)
    {
      rl->spec.remote_host = remote_host;
      rl->spec.remote_host_defined = true;
    }

  rl->spec.net_gateway_defined = get_default_gateway (&rl->spec.net_gateway);
  if (rl->spec.net_gateway_defined)
    {
      setenv_route_addr ("net_gateway", rl->spec.net_gateway, -1);
    }
  rl->redirect_default_gateway = opt->redirect_default_gateway;

  if (is_route_parm_defined (remote_endpoint))
    {
      rl->spec.remote_endpoint = getaddr (
				     GETADDR_RESOLVE
				     | GETADDR_HOST_ORDER
				     | GETADDR_FATAL_ON_SIGNAL,
				     remote_endpoint,
				     0,
				     &rl->spec.remote_endpoint_defined,
				     NULL);

      if (rl->spec.remote_endpoint_defined)
	{
	  setenv_route_addr ("vpn_gateway", rl->spec.remote_endpoint, -1);
	}
      else
	{
	  msg (M_WARN, PACKAGE_NAME " ROUTE: failed to parse/resolve default gateway: %s",
	       remote_endpoint);
	  ret = false;
	}
    }
  else
    rl->spec.remote_endpoint_defined = false;

  ASSERT (opt->n >= 0 && opt->n < MAX_ROUTES);

  for (i = 0; i < opt->n; ++i)
    {
      if (!init_route (&rl->routes[i],
		       &opt->routes[i],
		       &rl->spec))
	ret = false;
    }

  rl->n = i;
  return ret;
}

static void
add_route3 (in_addr_t network,
	    in_addr_t netmask,
	    in_addr_t gateway)
{
  struct route r;
  CLEAR (r);
  r.defined = true;
  r.network = network;
  r.netmask = netmask;
  r.gateway = gateway;
  add_route (&r);
}

static void
del_route3 (in_addr_t network,
	    in_addr_t netmask,
	    in_addr_t gateway)
{
  struct route r;
  CLEAR (r);
  r.defined = true;
  r.network = network;
  r.netmask = netmask;
  r.gateway = gateway;
  delete_route (&r);
}

static void
redirect_default_route_to_vpn (struct route_list *rl)
{
  const char err[] = "NOTE: unable to redirect default gateway --";

  if (rl->redirect_default_gateway)
    {
      if (!rl->spec.remote_endpoint_defined)
	{
	  msg (M_WARN, "%s VPN gateway parameter (--route-gateway or --ifconfig) is missing", err);
	}
      else if (!rl->spec.net_gateway_defined)
	{
	  msg (M_WARN, "%s Cannot read current default gateway from system", err);
	}
      else if (!rl->spec.remote_host_defined)
	{
	  msg (M_WARN, "%s Cannot obtain current remote host address", err);
	}
      else
	{
	  /* route remote host to original default gateway */
	  add_route3 (rl->spec.remote_host,
		      ~0,
		      rl->spec.net_gateway);

	  /* delete default route */
	  del_route3 (0,
		      0,
		      rl->spec.net_gateway);

	  /* add new default route */
	  add_route3 (0,
		      0,
		      rl->spec.remote_endpoint);

	  /* set a flag so we can undo later */
	  rl->did_redirect_default_gateway = true;
	}
    }
}

static void
undo_redirect_default_route_to_vpn (struct route_list *rl)
{
  if (rl->did_redirect_default_gateway)
    {
      /* delete remote host route */
      del_route3 (rl->spec.remote_host,
		  ~0,
		  rl->spec.net_gateway);

      /* delete default route */
      del_route3 (0,
		  0,
		  rl->spec.remote_endpoint);

      /* restore original default route */
      add_route3 (0,
		  0,
		  rl->spec.net_gateway);

      rl->did_redirect_default_gateway = false;
    }
}

void
add_routes (struct route_list *rl, bool delete_first)
{
  redirect_default_route_to_vpn (rl);
  if (!rl->routes_added)
    {
      int i;
      for (i = 0; i < rl->n; ++i)
	{
	  if (delete_first)
	    delete_route (&rl->routes[i]);
	  add_route (&rl->routes[i]);
	}
      rl->routes_added = true;
    }
}

void
delete_routes (struct route_list *rl)
{
  if (rl->routes_added)
    {
      int i;
      for (i = rl->n - 1; i >= 0; --i)
	{
	  const struct route *r = &rl->routes[i];
	  delete_route (r);
	}
      rl->routes_added = false;
    }
  undo_redirect_default_route_to_vpn (rl);
}

static const char *
show_opt (const char *option)
{
  if (!option)
    return "nil";
  else
    return option;
}

static void
print_route_option (const struct route_option *ro, int level)
{
  msg (level, "  route %s/%s/%s/%s",
       show_opt (ro->network),
       show_opt (ro->netmask),
       show_opt (ro->gateway),
       show_opt (ro->metric));
}

void
print_route_options (const struct route_option_list *rol,
		     int level)
{
  int i;
  if (rol->redirect_default_gateway)
    msg (level, "  [redirect_default_gateway]");
  for (i = 0; i < rol->n; ++i)
    print_route_option (&rol->routes[i], level);
}

static void
print_route (const struct route *r, int level)
{
  if (r->defined)
    msg (level, "%s", route_string (r));
}

void
print_routes (const struct route_list *rl, int level)
{
  int i;
  for (i = 0; i < rl->n; ++i)
    print_route (&rl->routes[i], level);
}

static void
setenv_route (const struct route *r, int i)
{
  if (r->defined)
    {
      setenv_route_addr ("network", r->network, i);
      setenv_route_addr ("netmask", r->netmask, i);
      setenv_route_addr ("gateway", r->gateway, i);

      if (r->metric_defined)
	{
	  char name[128];
	  openvpn_snprintf (name, sizeof (name), "route_metric_%d", i);
	  setenv_int (name, r->metric);
	}
    }
}

void
setenv_routes (const struct route_list *rl)
{
  int i;
  for (i = 0; i < rl->n; ++i)
    setenv_route (&rl->routes[i], i + 1);
}

static void
add_route (struct route *r)
{
  int gc_level;
  struct buffer buf;
  const char *network;
  const char *netmask;
  const char *gateway;
  bool status = false;

  if (!r->defined)
    return;

  gc_level = gc_new_level ();
  buf = alloc_buf_gc (256);
  network = print_in_addr_t (r->network, false);
  netmask = print_in_addr_t (r->netmask, false);
  gateway = print_in_addr_t (r->gateway, false);

#if defined(TARGET_LINUX)
#ifdef CONFIG_FEATURE_IPROUTE
  buf_printf (&buf, IPROUTE_PATH " route add %s/%d via %s",
	      network,
	      count_netmask_bits(netmask),
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " metric %d", r->metric);

#else
  buf_printf (&buf, ROUTE_PATH " add -net %s netmask %s gw %s",
	      network,
	      netmask,
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " metric %d", r->metric);
#endif  /*CONFIG_FEATURE_IPROUTE*/
  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: Linux route add command failed", false);

#elif defined (WIN32)

  buf_printf (&buf, ROUTE_PATH " ADD %s MASK %s %s",
	      network,
	      netmask,
	      gateway);
  if (r->metric_defined)
    buf_printf (&buf, " METRIC %d", r->metric);

  netcmd_semaphore_lock ();
  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: Windows route add command failed", false);
  netcmd_semaphore_release ();

#elif defined (TARGET_SOLARIS)

  /* example: route add 192.0.2.32 -netmask 255.255.255.224 somegateway */

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " %s -netmask %s %s",
	      network,
	      netmask,
	      gateway);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: Solaris route add command failed", false);

#elif defined(TARGET_FREEBSD)

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " -net %s %s %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: FreeBSD route add command failed", false);

#elif defined(TARGET_OPENBSD)

  buf_printf (&buf, ROUTE_PATH " add");

#if 0
  if (r->metric_defined)
    buf_printf (&buf, " -rtt %d", r->metric);
#endif

  buf_printf (&buf, " -net %s %s -netmask %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  status = system_check (BSTR (&buf), "ERROR: OpenBSD route add command failed", false);

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

  r->defined = status;
  gc_free_level (gc_level);
}

static void
delete_route (const struct route *r)
{
  int gc_level;
  struct buffer buf;
  const char *network;
  const char *netmask;
  const char *gateway;

  if (!r->defined)
    return;

  gc_level = gc_new_level ();
  buf = alloc_buf_gc (256);
  network = print_in_addr_t (r->network, false);
  netmask = print_in_addr_t (r->netmask, false);
  gateway = print_in_addr_t (r->gateway, false);

#if defined(TARGET_LINUX)
#ifdef CONFIG_FEATURE_IPROUTE
  buf_printf (&buf, IPROUTE_PATH " route del %s/%d",
	      network,
	      count_netmask_bits(netmask));
#else

  buf_printf (&buf, ROUTE_PATH " del -net %s netmask %s",
	      network,
	      netmask);
#endif /*CONFIG_FEATURE_IPROUTE*/
  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: Linux route delete command failed", false);

#elif defined (WIN32)

  buf_printf (&buf, ROUTE_PATH " DELETE %s",
	      network);

  netcmd_semaphore_lock ();
  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: Windows route delete command failed", false);
  netcmd_semaphore_release ();

#elif defined (TARGET_SOLARIS)

  buf_printf (&buf, ROUTE_PATH " delete %s -netmask %s %s",
	      network,
	      netmask,
	      gateway);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: Solaris route delete command failed", false);

#elif defined(TARGET_FREEBSD)

  buf_printf (&buf, ROUTE_PATH " delete -net %s %s %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: FreeBSD route delete command failed", false);

#elif defined(TARGET_OPENBSD)

  buf_printf (&buf, ROUTE_PATH " delete -net %s %s -netmask %s",
	      network,
	      gateway,
	      netmask);

  msg (D_ROUTE, "%s", BSTR (&buf));
  system_check (BSTR (&buf), "ERROR: OpenBSD route delete command failed", false);

#else
  msg (M_FATAL, "Sorry, but I don't know how to do 'route' commands on this operating system.  Try putting your routes in a --route-up script");
#endif

  gc_free_level (gc_level);
}

/*
 * The --redirect-gateway option requires OS-specific code below
 * to get the current default gateway.
 */

#if defined(WIN32)

static bool
get_default_gateway (in_addr_t *ret)
{
  ULONG size = 0;
  DWORD status;

  if ((status = GetIpForwardTable (NULL, &size, TRUE)) == ERROR_INSUFFICIENT_BUFFER)
    {
      int i;
      PMIB_IPFORWARDTABLE routes = (PMIB_IPFORWARDTABLE) gc_malloc (size);
      ASSERT (routes);
      if ((status = GetIpForwardTable (routes, &size, TRUE)) != NO_ERROR)
	return false;

      for (i = 0; i < routes->dwNumEntries; ++i)
	{
	  const MIB_IPFORWARDROW *row = &routes->table[i];
	  const in_addr_t net = ntohl (row->dwForwardDest);
	  const in_addr_t mask = ntohl (row->dwForwardMask);
	  const in_addr_t gw = ntohl (row->dwForwardNextHop);

#if 0
	  msg (M_INFO, "route[%d] %s %s %s",
	       i,
	       print_in_addr_t ((in_addr_t) net, false),
	       print_in_addr_t ((in_addr_t) mask, false),
	       print_in_addr_t ((in_addr_t) gw, false));
#endif

	  if (!net && !mask)
	    {
	      *ret = gw;
	      return true;
	    }
	}
    }
  return false;
}

#elif defined(TARGET_LINUX)

static bool
get_default_gateway (in_addr_t *ret)
{
  FILE *fp = fopen ("/proc/net/route", "r");
  if (fp)
    {
      char line[256];
      int count = 0;
      while (fgets (line, sizeof (line), fp) != NULL)
	{
	  if (count)
	    {
	      unsigned int net_x = 0;
	      unsigned int mask_x = 0;
	      unsigned int gw_x = 0;
	      const int np = sscanf (line, "%*s\t%x\t%x\t%*s\t%*s\t%*s\t%*s\t%x",
				     &net_x,
				     &gw_x,
				     &mask_x);
	      if (np == 3)
		{
		  const in_addr_t net = ntohl (net_x);
		  const in_addr_t mask = ntohl (mask_x);
		  const in_addr_t gw = ntohl (gw_x);
#if 0
		  msg (M_INFO, "route %s %s %s",
		       print_in_addr_t ((in_addr_t) net, false),
		       print_in_addr_t ((in_addr_t) mask, false),
		       print_in_addr_t ((in_addr_t) gw, false));
#endif
		  if (!net && !mask)
		    {
		      fclose (fp);
		      *ret = gw;
		      return true;
		    }
		}
	    }
	  ++count;
	}
      fclose (fp);
    }
  return false;
}

#elif defined(TARGET_FREEBSD)

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static bool
get_default_gateway (in_addr_t *ret)
{
  int s, seq, l, pid, rtm_addrs, i;
  struct sockaddr so_dst, so_mask;
  char *cp = m_rtmsg.m_space; 
  struct sockaddr *gate = NULL, *sa;
  struct  rt_msghdr *rtm_aux;

#define NEXTADDR(w, u) \
        if (rtm_addrs & (w)) {\
            l = ROUNDUP(u.sa_len); memmove(cp, &(u), l); cp += l;\
        }

#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

#define rtm m_rtmsg.m_rtm

  pid = getpid();
  seq = 0;
  rtm_addrs = RTA_DST | RTA_NETMASK;

  bzero(&so_dst, sizeof(so_dst));
  bzero(&so_mask, sizeof(so_mask));
  bzero(&rtm, sizeof(struct rt_msghdr));

  rtm.rtm_type = RTM_GET;
  rtm.rtm_flags = RTF_UP | RTF_GATEWAY;
  rtm.rtm_version = RTM_VERSION;
  rtm.rtm_seq = ++seq;
  rtm.rtm_addrs = rtm_addrs; 

  so_dst.sa_family = AF_INET;
  so_dst.sa_len = sizeof(struct sockaddr_in);
  so_mask.sa_family = AF_INET;
  so_mask.sa_len = sizeof(struct sockaddr_in);

  NEXTADDR(RTA_DST, so_dst);
  NEXTADDR(RTA_NETMASK, so_mask);

  rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

  s = socket(PF_ROUTE, SOCK_RAW, 0);

  if (write(s, (char *)&m_rtmsg, l) < 0) {
                warn("writing to routing socket");
                return false;
  }

  do {
        l = read(s, (char *)&m_rtmsg, sizeof(m_rtmsg));
  } while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
                        

  rtm_aux = &rtm;

  cp = ((char *)(rtm_aux + 1));
  if (rtm_aux->rtm_addrs) {
        for (i = 1; i; i <<= 1)
             if (i & rtm_aux->rtm_addrs) {
                   sa = (struct sockaddr *)cp;
		   if( i == RTA_GATEWAY )
                      gate = sa;
                   ADVANCE(cp, sa);
	     }
  }
  else
	return false;


  if( gate != NULL )
  {
	*ret = ntohl(((struct sockaddr_in *)gate)->sin_addr.s_addr);
#if 1
        msg (M_INFO, "gw %s",
                 print_in_addr_t ((in_addr_t) *ret, false));
#endif

	return true;
  }
  else
	return false;
}


#else

static bool
get_default_gateway (in_addr_t *ret)
{
  return false;
}

#endif
