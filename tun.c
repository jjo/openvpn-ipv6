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
 * Support routines for configuring and accessing TUN/TAP
 * virtual network adapters.
 *
 * This file is based on the TUN/TAP driver interface routines
 * from VTun by Maxim Krasnyansky <max_mk@yahoo.com>.
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "tun.h"
#include "fdmisc.h"
#include "common.h"
#include "misc.h"
#include "socket.h"

#include "memdbg.h"

bool
is_dev_type (const char *dev, const char *dev_type, const char *match_type)
{
  ASSERT (match_type);
  if (!dev)
    return false;
  if (dev_type)
    return !strcmp (dev_type, match_type);
  else
    return !strncmp (dev, match_type, strlen (match_type));
}

int
dev_type_enum (const char *dev, const char *dev_type)
{
  if (is_dev_type (dev, dev_type, "tun"))
    return DEV_TYPE_TUN;
  else if (is_dev_type (dev, dev_type, "tap"))
    return DEV_TYPE_TAP;
  else if (is_dev_type (dev, dev_type, "null"))
    return DEV_TYPE_NULL;
  else
    return DEV_TYPE_UNDEF;
}

const char *
dev_type_string (const char *dev, const char *dev_type)
{
  switch (dev_type_enum (dev, dev_type))
    {
    case DEV_TYPE_TUN:
      return "tun";
    case DEV_TYPE_TAP:
      return "tap";
    case DEV_TYPE_NULL:
      return "null";
    default:
      return "[unknown-dev-type]";
    }
}

const char *
dev_component_in_dev_node (const char *dev_node)
{
  const char *ret;
  const int dirsep = OS_SPECIFIC_DIRSEP;

  if (dev_node)
    {
      ret = strrchr (dev_node, dirsep);
      if (ret && *ret)
	++ret;
      else
	ret = dev_node;
      if (*ret)
	return ret;
    }
  return NULL;
}

/*
 * Try to predict the actual TUN/TAP device instance name,
 * before the device is actually opened.
 */
const char *
guess_tuntap_dev (const char *dev, const char *dev_type, const char *dev_node)
{
#ifdef WIN32

  struct buffer out = alloc_buf_gc (256);
  int op = GET_DEV_UID_NORMAL; 

  if (!dev_node)
    op = GET_DEV_UID_DEFAULT; 

  get_device_guid (dev_node, BPTR (&out), buf_forward_capacity (&out), op);
  return BSTR (&out);

#else
/* default case */
  return dev;
#endif
}

/*
 * Called by the open_tun function of OSes to check if we
 * explicitly support IPv6.
 *
 * In this context, explicit means that the OS expects us to
 * do something special to the tun socket in order to support
 * IPv6, i.e. it is not transparent.
 *
 * ipv6_explicitly_supported should be set to false if we don't
 * have any explicit IPv6 code in the tun device handler.
 *
 * If ipv6_explicitly_supported is true, then we have explicit
 * OS-specific tun dev code for handling IPv6.  If so, tt->ipv6
 * is set according to the --tun-ipv6 command line option.
 */
static void
ipv6_support (bool ipv6, bool ipv6_explicitly_supported, struct tuntap* tt)
{
  tt->ipv6 = false;
  if (ipv6_explicitly_supported)
    tt->ipv6 = ipv6;
  else if (ipv6)
    msg (M_WARN, "NOTE: explicit support for IPv6 tun devices is not provided for this OS");
}

/*
 * If !tun, make sure ifconfig_remote_netmask looks
 *  like a netmask.
 *
 * If tun, make sure ifconfig_remote_netmask looks
 *  like an IPv4 address.
 */
static void
ifconfig_sanity_check (bool tun, in_addr_t addr)
{
  const bool looks_like_netmask = ((addr & 0xFF000000) == 0xFF000000);
  if (tun)
    {
      if (looks_like_netmask)
	msg (M_WARN, "WARNING: Since you are using --dev tun, the second argument to --ifconfig must be an IP address.  You are using something (%s) that looks more like a netmask.", print_in_addr_t (addr, false));
    }
  else /* tap */
    {
      if (!looks_like_netmask)
	msg (M_WARN, "WARNING: Since you are using --dev tap, the second argument to --ifconfig must be a netmask, for example something like 255.255.255.0.");
    }
}

/*
 * For TAP-style devices, generate a broadcast address.
 */
static in_addr_t
generate_ifconfig_broadcast_addr (in_addr_t local,
				  in_addr_t netmask)
{
  return local | ~netmask;
}

/*
 * Check that --local and --remote addresses do not
 * clash with ifconfig addresses or subnet.
 */
static void
check_addr_clash (const char *name,
		  int type,
		  in_addr_t public,
		  in_addr_t local,
		  in_addr_t remote_netmask)
{
#if 0
  msg (M_INFO, "CHECK_ADDR_CLASH type=%d public=%s local=%s, remote_netmask=%s",
       type,
       print_in_addr_t (public, false),
       print_in_addr_t (local, false),
       print_in_addr_t (remote_netmask, false));
#endif

  if (public)
    {
      if (type == DEV_TYPE_TUN)
	{
	  const in_addr_t test_netmask = 0xFFFFFF00;
	  const in_addr_t public_net = public & test_netmask;
	  const in_addr_t local_net = local & test_netmask;
	  const in_addr_t remote_net = remote_netmask & test_netmask;

	  if (public == local || public == remote_netmask)
	    msg (M_WARN,
		 "WARNING: --%s address [%s] conflicts with --ifconfig address pair [%s, %s]",
		 name,
		 print_in_addr_t (public, false),
		 print_in_addr_t (local, false),
		 print_in_addr_t (remote_netmask, false));

	  if (public_net == local_net || public_net == remote_net)
	    msg (M_WARN,
		 "WARNING: potential conflict between --%s address [%s] and --ifconfig address pair [%s, %s] -- this is a warning only that is triggered when local/remote addresses exist within the same /24 subnet as --ifconfig endpoints",
		 name,
		 print_in_addr_t (public, false),
		 print_in_addr_t (local, false),
		 print_in_addr_t (remote_netmask, false));
	}
      else if (type == DEV_TYPE_TAP)
	{
	  const in_addr_t public_network = public & remote_netmask;
	  const in_addr_t virtual_network = local & remote_netmask;
	  if (public_network == virtual_network)
	    msg (M_WARN,
		 "WARNING: --%s address [%s] conflicts with --ifconfig subnet [%s, %s] -- local and remote addresses cannot be inside of the --ifconfig subnet",
		 name,
		 print_in_addr_t (public, false),
		 print_in_addr_t (local, false),
		 print_in_addr_t (remote_netmask, false));
	}
    }
}

/*
 * Complain if --dev tap and --ifconfig is used on an OS for which
 * we don't have a custom tap ifconfig template below.
 */
static void
no_tap_ifconfig ()
{
  msg (M_FATAL, "Sorry but you cannot use --dev tap and --ifconfig together on this OS because I have not yet been programmed to understand the appropriate ifconfig syntax to use for TAP-style devices on this OS.  Your best alternative is to use an --up script and do the ifconfig command manually.");
}

/*
 * Return a string to be used for options compatibility check
 * between peers.
 */
const char *
ifconfig_options_string (const struct tuntap* tt, bool remote, bool disable)
{
  struct buffer out = alloc_buf_gc (256);
  if (tt->did_ifconfig_setup && !disable)
    {
      if (tt->type == DEV_TYPE_TUN)
	{
	  const char *l, *r;
	  if (remote)
	    {
	      r = print_in_addr_t (tt->local, false);
	      l = print_in_addr_t (tt->remote_netmask, false);
	    }
	  else
	    {
	      l = print_in_addr_t (tt->local, false);
	      r = print_in_addr_t (tt->remote_netmask, false);
	    }
	  buf_printf (&out, "%s %s", r, l);
	}
      else if (tt->type == DEV_TYPE_TAP)
	{
	  buf_printf (&out, "%s %s",
		      print_in_addr_t (tt->local & tt->remote_netmask, false),
		      print_in_addr_t (tt->remote_netmask, false));
	}
      else
	buf_printf (&out, "[undef]");
    }
  return BSTR (&out);
}

/*
 * Init tun/tap object.
 *
 * Set up tuntap structure for ifconfig,
 * but don't execute yet.
 */
void
init_tun (struct tuntap *tt,
	  const char *dev,       /* --dev option */
	  const char *dev_type,  /* --dev-type option */
	  const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	  const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	  in_addr_t local_public,
	  in_addr_t remote_public,
	  const struct frame *frame,
	  const struct tuntap_options *options)
{
#ifdef WIN32
  overlapped_io_init (&tt->reads, frame, FALSE, true);
  overlapped_io_init (&tt->writes, frame, TRUE, true);
#endif

  tt->type = dev_type_enum (dev, dev_type);
  tt->options = *options;

  if (ifconfig_local_parm && ifconfig_remote_netmask_parm)
    {
      bool tun = false;
      const char *ifconfig_local = NULL;
      const char *ifconfig_remote_netmask = NULL;
      const char *ifconfig_broadcast = NULL;

      /*
       * We only handle TUN/TAP devices here, not --dev null devices.
       */
      if (tt->type == DEV_TYPE_TUN)
	tun = true;
      else if (tt->type == DEV_TYPE_TAP)
	tun = false;
      else
	msg (M_FATAL, "'%s' is not a TUN/TAP device.  The --ifconfig option works only for TUN/TAP devices.", dev);

      /*
       * Convert arguments to binary IPv4 addresses.
       */

      tt->local = getaddr (
			   GETADDR_RESOLVE
			   | GETADDR_FATAL
			   | GETADDR_HOST_ORDER
			   | GETADDR_FATAL_ON_SIGNAL,
			   ifconfig_local_parm,
			   0,
			   NULL,
			   NULL);

      tt->remote_netmask = getaddr (
				    (tun ? GETADDR_RESOLVE : 0)
				    | GETADDR_FATAL
				    | GETADDR_HOST_ORDER
				    | GETADDR_FATAL_ON_SIGNAL,
				    ifconfig_remote_netmask_parm,
				    0,
				    NULL,
				    NULL);

      ifconfig_sanity_check (tun, tt->remote_netmask);

      /*
       * If local_public or remote_public addresses are defined,
       * make sure they do not clash with our virtual subnet.
       */

      check_addr_clash ("local",
			tt->type,
			local_public,
			tt->local,
			tt->remote_netmask);

      check_addr_clash ("remote",
			tt->type,
			remote_public,
			tt->local,
			tt->remote_netmask);

      /*
       * Set ifconfig parameters
       */
      ifconfig_local = print_in_addr_t (tt->local, false);
      ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, false);

      /*
       * If TAP-style device, generate broadcast address.
       */
      if (!tun)
	{
	  tt->broadcast = generate_ifconfig_broadcast_addr (tt->local, tt->remote_netmask);
	  ifconfig_broadcast = print_in_addr_t (tt->broadcast, false);
	}

      /*
       * Set environmental variables with ifconfig parameters.
       */
      setenv_str ("ifconfig_local", ifconfig_local);
      if (tun)
	{
	  setenv_str ("ifconfig_remote", ifconfig_remote_netmask);
	}
      else
	{
	  setenv_str ("ifconfig_netmask", ifconfig_remote_netmask);
	  setenv_str ("ifconfig_broadcast", ifconfig_broadcast);
	}

      tt->did_ifconfig_setup = true;
    }
}


/* execute the ifconfig command through the shell */
void
do_ifconfig (struct tuntap *tt,
	     const char *actual,    /* actual device name */
	     int tun_mtu)
{
  if (tt->did_ifconfig_setup)
    {
      bool tun = false;
      const char *ifconfig_local = NULL;
      const char *ifconfig_remote_netmask = NULL;
      const char *ifconfig_broadcast = NULL;
      char command_line[512];

      /*
       * We only handle TUN/TAP devices here, not --dev null devices.
       */
      if (tt->type == DEV_TYPE_TUN)
	tun = true;
      else if (tt->type == DEV_TYPE_TAP)
	tun = false;
      else
	ASSERT (0); /* should have been caught in init_tun */

      /*
       * Set ifconfig parameters
       */
      ifconfig_local = print_in_addr_t (tt->local, false);
      ifconfig_remote_netmask = print_in_addr_t (tt->remote_netmask, false);

      /*
       * If TAP-style device, generate broadcast address.
       */
      if (!tun)
	ifconfig_broadcast = print_in_addr_t (tt->broadcast, false);

#if defined(TARGET_LINUX)
#ifdef CONFIG_FEATURE_IPROUTE
	/*
	 * Set the MTU for the device
	 */
	openvpn_snprintf (command_line, sizeof (command_line),
			  IPROUTE_PATH " link set dev %s up mtu %d",
			  actual,
			  tun_mtu
			  );
	  msg (M_INFO, "%s", command_line);
	  system_check (command_line, "Linux ip link set failed", true);


	if (tun) {

		/*
		 * Set the address for the device
		 */
		openvpn_snprintf (command_line, sizeof (command_line),
				  IPROUTE_PATH " addr add dev %s local %s peer %s",
				  actual,
				  ifconfig_local,
				  ifconfig_remote_netmask
				  );
		  msg (M_INFO, "%s", command_line);
		  system_check (command_line, "Linux ip addr add failed", true);
	} else {
		openvpn_snprintf (command_line, sizeof (command_line),
				  IPROUTE_PATH " addr add dev %s %s/%d broadcast %s",
				  actual,
				  ifconfig_local,
				  count_netmask_bits(ifconfig_remote_netmask),
				  ifconfig_broadcast
				  );
		  msg (M_INFO, "%s", command_line);
		  system_check (command_line, "Linux ip addr add failed", true);

	}
	tt->did_ifconfig = true;
#else
      if (tun)
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s pointopoint %s mtu %d",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s netmask %s mtu %d broadcast %s",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu,
			  ifconfig_broadcast
			  );
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "Linux ifconfig failed", true);
      tt->did_ifconfig = true;
#endif /*CONFIG_FEATURE_IPROUTE*/
#elif defined(TARGET_SOLARIS)

      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      if (tun)
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	no_tap_ifconfig ();
      msg (M_INFO, "%s", command_line);
      if (!system_check (command_line, "Solaris ifconfig failed", false))
	{
	  openvpn_snprintf (command_line, sizeof (command_line),
			    IFCONFIG_PATH " %s unplumb",
			    actual
			    );
	  msg (M_INFO, "%s", command_line);
	  system_check (command_line, "Solaris ifconfig unplumb failed", false);
	  msg (M_FATAL, "ifconfig failed");
	}
      tt->did_ifconfig = true;

#elif defined(TARGET_OPENBSD)

      /*
       * OpenBSD tun devices appear to be persistent by default.  It seems in order
       * to make this work correctly, we need to delete the previous instance
       * (if it exists), and re-ifconfig.  Let me know if you know a better way.
       */

      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s delete",
			actual);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, NULL, false);
      msg (M_INFO, "NOTE: Tried to delete pre-existing tun/tap instance -- No Problem if failure");

      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      if (tun)
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	no_tap_ifconfig ();
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "OpenBSD ifconfig failed", true);
      tt->did_ifconfig = true;

#elif defined(TARGET_NETBSD)

      if (tun)
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	no_tap_ifconfig ();
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "NetBSD ifconfig failed", true);
      tt->did_ifconfig = true;

#elif defined(TARGET_DARWIN)

      /*
       * Darwin (i.e. Mac OS X) seems to exhibit similar behaviour to OpenBSD...
       */

      openvpn_snprintf (command_line, sizeof (command_line),
			IFCONFIG_PATH " %s delete",
			actual);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, NULL, false);
      msg (M_INFO, "NOTE: Tried to delete pre-existing tun/tap instance -- No Problem if failure");


      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      if (tun)
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	no_tap_ifconfig ();
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "Mac OS X ifconfig failed", true);
      tt->did_ifconfig = true;

#elif defined(TARGET_FREEBSD)

      /* example: ifconfig tun2 10.2.0.2 10.2.0.1 mtu 1450 netmask 255.255.255.255 up */
      if (tun)
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s %s mtu %d netmask 255.255.255.255 up",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
      else
	openvpn_snprintf (command_line, sizeof (command_line),
			  IFCONFIG_PATH " %s %s netmask %s mtu %d up",
			  actual,
			  ifconfig_local,
			  ifconfig_remote_netmask,
			  tun_mtu
			  );
	
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "FreeBSD ifconfig failed", true);
      tt->did_ifconfig = true;

#elif defined (WIN32)
      {
	const char *netmask;

	/*
	 * Make sure that both ifconfig addresses are part of the
	 * same .252 subnet.
	 */
	if (tun)
	  {
	    verify_255_255_255_252 (tt->local, tt->remote_netmask);
	    tt->adapter_netmask = ~3;
	    netmask = print_in_addr_t (tt->adapter_netmask, false);
	  }
	else
	  {
	    netmask = ifconfig_remote_netmask;
	    tt->adapter_netmask = tt->remote_netmask;
	  }

	/* example: netsh interface ip set address my-tap static 10.3.0.1 255.255.255.0 */
	openvpn_snprintf (command_line, sizeof (command_line),
			  "netsh interface ip set address \"%s\" static %s %s",
			  actual,
			  ifconfig_local,
			  netmask);
	
	switch (tt->options.ip_win32_type)
	  {
	  case IPW32_SET_MANUAL:
	    msg (M_INFO, "******** NOTE:  Please manually set the IP/netmask of '%s' to %s/%s (if it is not already set)",
		 actual,
		 ifconfig_local,
		 netmask);
	    break;
	  case IPW32_SET_NETSH:
	    netcmd_semaphore_lock ();
	    msg (M_INFO, "%s", command_line);
	    system_check (command_line, "ERROR: netsh command failed", true);
	    netcmd_semaphore_release ();
	    break;
	  }
	tt->did_ifconfig = true;
      }

#else
      msg (M_FATAL, "Sorry, but I don't know how to do 'ifconfig' commands on this operating system.  You should ifconfig your TUN/TAP device manually or use an --up script.");
#endif
    }
}

void
clear_tuntap (struct tuntap *tuntap)
{
  CLEAR (*tuntap);
#ifdef WIN32
  tuntap->hand = NULL;
#else
  tuntap->fd = -1;
#endif
#ifdef TARGET_SOLARIS
  tuntap->ip_fd = -1;
#endif
  tuntap->ipv6 = false;
}

static void
open_null (struct tuntap *tt)
{
  strncpynt (tt->actual, "null", sizeof (tt->actual));
}

#ifndef WIN32
static void
open_tun_generic (const char *dev, const char *dev_type, const char *dev_node,
		  bool ipv6, bool ipv6_explicitly_supported, bool dynamic,
		  struct tuntap *tt)
{
  char tunname[256];
  char dynamic_name[256];
  bool dynamic_opened = false;

  ipv6_support (ipv6, ipv6_explicitly_supported, tt);

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
    }
  else
    {
      /*
       * --dev-node specified, so open an explicit device node
       */
      if (dev_node)
	{
	  openvpn_snprintf (tunname, sizeof (tunname), "%s", dev_node);
	}
      else
	{
	  /*
	   * dynamic open is indicated by --dev specified without
	   * explicit unit number.  Try opening /dev/[dev]n
	   * where n = [0, 255].
	   */
	  if (dynamic && !has_digit(dev))
	    {
	      int i;
	      for (i = 0; i < 256; ++i)
		{
		  openvpn_snprintf (tunname, sizeof (tunname),
				    "/dev/%s%d", dev, i);
		  openvpn_snprintf (dynamic_name, sizeof (dynamic_name),
				    "%s%d", dev, i);
		  if ((tt->fd = open (tunname, O_RDWR)) > 0)
		    {
		      dynamic_opened = true;
		      break;
		    }
		  msg (D_READ_WRITE | M_ERRNO, "Tried opening %s (failed)", tunname);
		}
	      if (!dynamic_opened)
		msg (M_FATAL, "Cannot allocate TUN/TAP dev dynamically");
	    }
	  /*
	   * explicit unit number specified
	   */
	  else
	    {
	      openvpn_snprintf (tunname, sizeof (tunname), "/dev/%s", dev);
	    }
	}

      if (!dynamic_opened)
	{
	  if ((tt->fd = open (tunname, O_RDWR)) < 0)
	    msg (M_ERR, "Cannot open TUN/TAP dev %s", tunname);
	}

      set_nonblock (tt->fd);
      set_cloexec (tt->fd); /* don't pass fd to scripts */
      msg (M_INFO, "TUN/TAP device %s opened", tunname);

      /* tt->actual is passed to up and down scripts and used as the ifconfig dev name */
      strncpynt (tt->actual, (dynamic_opened ? dynamic_name : dev), sizeof (tt->actual));
    }
}

static void
close_tun_generic (struct tuntap *tt)
{
  if (tt->fd >= 0)
    close (tt->fd);
  clear_tuntap (tt);
}

#endif

#if defined(TARGET_LINUX)

#ifdef HAVE_LINUX_IF_TUN_H	/* New driver support */

#ifndef HAVE_LINUX_SOCKIOS_H
#error header file linux/sockios.h required
#endif

#if defined(HAVE_TUN_PI) && defined(HAVE_IPHDR) && defined(HAVE_IOVEC) && defined(ETH_P_IPV6) && defined(ETH_P_IP) && defined(HAVE_READV) && defined(HAVE_WRITEV)
#define LINUX_IPV6 1
/* #warning IPv6 ON */
#else
#define LINUX_IPV6 0
/* #warning IPv6 OFF */
#endif

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  struct ifreq ifr;

  /*
   * Set tt->ipv6 to true if
   * (a) we have the capability of supporting --tun-ipv6, and
   * (b) --tun-ipv6 was specified.
   */
  ipv6_support (ipv6, LINUX_IPV6, tt);

  /*
   * We handle --dev null specially, we do not open /dev/null for this.
   */
  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
    }
  else
    {
      /*
       * Process --dev-node
       */
      const char *node = dev_node;
      if (!node)
	node = "/dev/net/tun";
      if ((tt->fd = open (node, O_RDWR)) < 0)
	{
	  msg (M_WARN | M_ERRNO, "Note: Cannot open TUN/TAP dev %s", node);
	  goto linux_2_2_fallback;
	}

      /*
       * Process --tun-ipv6
       */
      CLEAR (ifr);
      if (!tt->ipv6)
	ifr.ifr_flags = IFF_NO_PI;

      /*
       * Figure out if tun or tap device
       */
      if (tt->type == DEV_TYPE_TUN)
	{
	  ifr.ifr_flags |= IFF_TUN;
	}
      else if (tt->type == DEV_TYPE_TAP)
	{
	  ifr.ifr_flags |= IFF_TAP;
	}
      else
	{
	  msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	       dev);
	}

      /*
       * Set an explicit name, if --dev is not tun or tap
       */
      if (strcmp(dev, "tun") && strcmp(dev, "tap"))
	strncpynt (ifr.ifr_name, dev, IFNAMSIZ);

      /*
       * Use special ioctl that configures tun/tap device with the parms
       * we set in ifr
       */
      if (ioctl (tt->fd, TUNSETIFF, (void *) &ifr) < 0)
	{
	  msg (M_WARN | M_ERRNO, "Note: Cannot ioctl TUNSETIFF %s", dev);
	  goto linux_2_2_fallback;
	}

      set_nonblock (tt->fd);
      set_cloexec (tt->fd);
      msg (M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);
      strncpynt (tt->actual, ifr.ifr_name, sizeof (tt->actual));
    }
  return;

 linux_2_2_fallback:
  msg (M_INFO, "Note: Attempting fallback to kernel 2.2 TUN/TAP interface");
  close_tun_generic (tt);
  open_tun_generic (dev, dev_type, dev_node, ipv6, false, true, tt);
}

#else

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, ipv6, false, true, tt);
}

#endif /* HAVE_LINUX_IF_TUN_H */

#ifdef TUNSETPERSIST

void
tuncfg (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, int persist_mode)
{
  struct tuntap tt;

  clear_tuntap (&tt);
  tt.type = dev_type_enum (dev, dev_type);
  open_tun (dev, dev_type, dev_node, ipv6, &tt);
  if (ioctl (tt.fd, TUNSETPERSIST, persist_mode) < 0)
    msg (M_ERR, "Cannot ioctl TUNSETPERSIST(%d) %s", persist_mode, dev);
  close_tun (&tt);
  msg (M_INFO, "Persist state set to: %s", (persist_mode ? "ON" : "OFF"));
}

#endif /* TUNSETPERSIST */

void
close_tun (struct tuntap *tt)
{
  close_tun_generic (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
#if LINUX_IPV6
  if (tt->ipv6)
    {
      struct tun_pi pi;
      struct iphdr *iph;
      struct iovec vect[2];
      int ret;

      iph = (struct iphdr *)buf;

      pi.flags = 0;

      if(iph->version == 6)
	pi.proto = htons(ETH_P_IPV6);
      else
	pi.proto = htons(ETH_P_IP);

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = writev(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
#endif
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
#if LINUX_IPV6
  if (tt->ipv6)
    {
      struct iovec vect[2];
      struct tun_pi pi;
      int ret;

      vect[0].iov_len = sizeof(pi);
      vect[0].iov_base = &pi;
      vect[1].iov_len = len;
      vect[1].iov_base = buf;

      ret = readv(tt->fd, vect, 2);
      return(ret - sizeof(pi));
    }
  else
#endif
    return read (tt->fd, buf, len);
}

#elif defined(TARGET_SOLARIS)

#ifndef TUNNEWPPA
#error I need the symbol TUNNEWPPA from net/if_tun.h
#endif

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  int if_fd, muxid, ppa = -1;
  struct ifreq ifr;
  const char *ptr;
  const char *ip_node;
  const char *dev_tuntap_type;
  int link_type;
  bool is_tun;

  ipv6_support (ipv6, false, tt);

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
      return;
    }

  if (tt->type == DEV_TYPE_TUN)
    {
      ip_node = "/dev/udp";
      if (!dev_node)
	dev_node = "/dev/tun";
      dev_tuntap_type = "tun";
      link_type = I_PLINK;
      is_tun = true;
    }
  else if (tt->type == DEV_TYPE_TAP)
    {
      ip_node = "/dev/ip";
      if (!dev_node)
	dev_node = "/dev/tap";
      dev_tuntap_type = "tap";
      link_type = I_PLINK; /* was: I_LINK */
      is_tun = false;
    }
  else
    {
      msg (M_FATAL, "I don't recognize device %s as a tun or tap device",
	   dev);
    }
  
  /* get unit number */
  if (*dev)
    {
      ptr = dev;
      while (*ptr && !isdigit ((int) *ptr))
	ptr++;
      ppa = atoi (ptr);
    }

  if ((tt->ip_fd = open (ip_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", ip_node);

  if ((tt->fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s", dev_node);

  /* Assign a new PPA and get its unit number. */
  if ((ppa = ioctl (tt->fd, TUNNEWPPA, ppa)) < 0)
    msg (M_ERR, "Can't assign new interface");

  if ((if_fd = open (dev_node, O_RDWR, 0)) < 0)
    msg (M_ERR, "Can't open %s (2)", dev_node);

  if (ioctl (if_fd, I_PUSH, "ip") < 0)
    msg (M_ERR, "Can't push IP module");

  /* Assign ppa according to the unit number returned by tun device */
  if (ioctl (if_fd, IF_UNITSEL, (char *) &ppa) < 0)
    msg (M_ERR, "Can't set PPA %d", ppa);

  if ((muxid = ioctl (tt->ip_fd, link_type, if_fd)) < 0)
    msg (M_ERR, "Can't link %s device to IP", dev_tuntap_type);

  close (if_fd);

  openvpn_snprintf (tt->actual, sizeof (tt->actual),
		    "%s%d", dev_tuntap_type, ppa);

  CLEAR (ifr);
  strncpynt (ifr.ifr_name, tt->actual, sizeof (ifr.ifr_name));
  ifr.ifr_ip_muxid = muxid;

  if (ioctl (tt->ip_fd, SIOCSIFMUXID, &ifr) < 0)
    {
      ioctl (tt->ip_fd, I_PUNLINK, muxid);
      msg (M_ERR, "Can't set multiplexor id");
    }

  set_nonblock (tt->fd);
  set_cloexec (tt->fd);
  set_cloexec (tt->ip_fd);

  msg (M_INFO, "TUN/TAP device %s opened", tt->actual);
}

/*
 * Close TUN device. 
 */
void
close_tun (struct tuntap* tt)
{
  if (tt->fd >= 0)
    {
      struct ifreq ifr;

      CLEAR (ifr);
      strncpynt (ifr.ifr_name, tt->actual, sizeof (ifr.ifr_name));

     if (ioctl (tt->ip_fd, SIOCGIFFLAGS, &ifr) < 0)
	msg (M_WARN | M_ERRNO, "Can't get iface flags");

      if (ioctl (tt->ip_fd, SIOCGIFMUXID, &ifr) < 0)
	msg (M_WARN | M_ERRNO, "Can't get multiplexor id");

      if (ioctl (tt->ip_fd, I_PUNLINK, ifr.ifr_ip_muxid) < 0)
	msg (M_WARN | M_ERRNO, "Can't unlink interface");

      close (tt->ip_fd);
      close (tt->fd);
    }
  clear_tuntap (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  struct strbuf sbuf;
  sbuf.len = len;
  sbuf.buf = (char *)buf;
  return putmsg (tt->fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1;
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  struct strbuf sbuf;
  int f = 0;

  sbuf.maxlen = len;
  sbuf.buf = (char *)buf;
  return getmsg (tt->fd, NULL, &sbuf, &f) >= 0 ? sbuf.len : -1;
}

#elif defined(TARGET_OPENBSD)

#if !defined(HAVE_READV) || !defined(HAVE_WRITEV)
#error openbsd build requires readv & writev library functions
#endif

/*
 * OpenBSD has a slightly incompatible TUN device from
 * the rest of the world, in that it prepends a
 * uint32 to the beginning of the IP header
 * to designate the protocol (why not just
 * look at the version field in the IP header to
 * determine v4 or v6?).
 *
 * We strip off this field on reads and
 * put it back on writes.
 *
 * I have not tested TAP devices on OpenBSD,
 * but I have conditionalized the special
 * TUN handling code described above to
 * go away for TAP devices.
 */

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, ipv6, true, true, tt);
}

void
close_tun (struct tuntap* tt)
{
  close_tun_generic (tt);
}

static inline int
openbsd_modify_read_write_return (int len)
{
 if (len > 0)
    return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
  else
    return len;
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];
      struct ip *iph;

      iph = (struct ip *) buf;

      if (tt->ipv6 && iph->ip_v == 6)
	type = htonl (AF_INET6);
      else 
	type = htonl (AF_INET);

      iv[0].iov_base = &type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return openbsd_modify_read_write_return (writev (tt->fd, iv, 2));
    }
  else
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];

      iv[0].iov_base = &type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return openbsd_modify_read_write_return (readv (tt->fd, iv, 2));
    }
  else
    return read (tt->fd, buf, len);
}

#elif defined(TARGET_NETBSD)

/*
 * NetBSD does not support IPv6 on tun out of the box,
 * but there exists a patch. When this patch is applied,
 * only two things are left to openvpn:
 * 1. Activate multicasting (this has already been done
 *    before by the kernel, but we make sure that nobody
 *    has deactivated multicasting inbetween.
 * 2. Deactivate "link layer mode" (otherwise NetBSD 
 *    prepends the address family to the packet, and we
 *    would run into the same trouble as with OpenBSD.
 */

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
    open_tun_generic (dev, dev_type, dev_node, ipv6, true, true, tt);
    if (tt->fd >= 0)
      {
        int i = IFF_POINTOPOINT|IFF_MULTICAST;
        ioctl (tt->fd, TUNSIFMODE, &i);  /* multicast on */
        i = 0;
        ioctl (tt->fd, TUNSLMODE, &i);   /* link layer mode off */
      }
}

void
close_tun (struct tuntap* tt)
{
  close_tun_generic (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
    return read (tt->fd, buf, len);
}

#elif defined(TARGET_FREEBSD)

static inline int
freebsd_modify_read_write_return (int len)
{
  if (len > 0)
    return len > sizeof (u_int32_t) ? len - sizeof (u_int32_t) : 0;
  else
    return len;
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, ipv6, true, true, tt);

  if (tt->fd >= 0)
    {
      int i = 0;

      /* Disable extended modes */
      ioctl (tt->fd, TUNSLMODE, &i);
      i = 1;
      ioctl (tt->fd, TUNSIFHEAD, &i);
    }
}

void
close_tun (struct tuntap* tt)
{
  close_tun_generic (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];
      struct ip *iph;

      iph = (struct ip *) buf;

      if (tt->ipv6 && iph->ip_v == 6)
        type = htonl (AF_INET6);
      else 
        type = htonl (AF_INET);

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return freebsd_modify_read_write_return (writev (tt->fd, iv, 2));
    }
  else
    return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  if (tt->type == DEV_TYPE_TUN)
    {
      u_int32_t type;
      struct iovec iv[2];

      iv[0].iov_base = (char *)&type;
      iv[0].iov_len = sizeof (type);
      iv[1].iov_base = buf;
      iv[1].iov_len = len;

      return freebsd_modify_read_write_return (readv (tt->fd, iv, 2));
    }
  else
    return read (tt->fd, buf, len);
}

#elif defined(WIN32)

int
tun_read_queue (struct tuntap *tt, int maxsize)
{
  if (tt->reads.iostate == IOSTATE_INITIAL)
    {
      DWORD len;
      BOOL status;
      int err;

      /* reset buf to its initial state */
      tt->reads.buf = tt->reads.buf_init;

      len = maxsize ? maxsize : BLEN (&tt->reads.buf);
      ASSERT (len <= BLEN (&tt->reads.buf));

      /* the overlapped read will signal this event on I/O completion */
      ASSERT (ResetEvent (tt->reads.overlapped.hEvent));

      status = ReadFile(
		      tt->hand,
		      BPTR (&tt->reads.buf),
		      len,
		      &tt->reads.size,
		      &tt->reads.overlapped
		      );

      if (status) /* operation completed immediately? */
	{
	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (tt->reads.overlapped.hEvent));

	  tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	  tt->reads.status = 0;

	  msg (D_WIN32_IO, "WIN32 I/O: TAP Read immediate return [%d,%d]",
	       (int) len,
	       (int) tt->reads.size);	       
	}
      else
	{
	  err = GetLastError (); 
	  if (err == ERROR_IO_PENDING) /* operation queued? */
	    {
	      tt->reads.iostate = IOSTATE_QUEUED;
	      tt->reads.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Read queued [%d]",
		   (int) len);
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (tt->reads.overlapped.hEvent));
	      tt->reads.iostate = IOSTATE_IMMEDIATE_RETURN;
	      tt->reads.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Read error [%d] : %s",
		   (int) len,
		   strerror_win32 (status));
	    }
	}
    }
  return tt->reads.iostate;
}

int
tun_write_queue (struct tuntap *tt, struct buffer *buf)
{
  if (tt->writes.iostate == IOSTATE_INITIAL)
    {
      BOOL status;
      int err;
 
      /* make a private copy of buf */
      tt->writes.buf = tt->writes.buf_init;
      tt->writes.buf.len = 0;
      ASSERT (buf_copy (&tt->writes.buf, buf));

      /* the overlapped write will signal this event on I/O completion */
      ASSERT (ResetEvent (tt->writes.overlapped.hEvent));

      status = WriteFile(
			tt->hand,
			BPTR (&tt->writes.buf),
			BLEN (&tt->writes.buf),
			&tt->writes.size,
			&tt->writes.overlapped
			);

      if (status) /* operation completed immediately? */
	{
	  tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;

	  /* since we got an immediate return, we must signal the event object ourselves */
	  ASSERT (SetEvent (tt->writes.overlapped.hEvent));

	  tt->writes.status = 0;

	  msg (D_WIN32_IO, "WIN32 I/O: TAP Write immediate return [%d,%d]",
	       BLEN (&tt->writes.buf),
	       (int) tt->writes.size);	       
	}
      else
	{
	  err = GetLastError (); 
	  if (err == ERROR_IO_PENDING) /* operation queued? */
	    {
	      tt->writes.iostate = IOSTATE_QUEUED;
	      tt->writes.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Write queued [%d]",
		   BLEN (&tt->writes.buf));
	    }
	  else /* error occurred */
	    {
	      ASSERT (SetEvent (tt->writes.overlapped.hEvent));
	      tt->writes.iostate = IOSTATE_IMMEDIATE_RETURN;
	      tt->writes.status = err;
	      msg (D_WIN32_IO, "WIN32 I/O: TAP Write error [%d] : %s",
		   BLEN (&tt->writes.buf),
		   strerror_win32 (err));
	    }
	}
    }
  return tt->writes.iostate;
}

int
tun_finalize (
	      HANDLE h,
	      struct overlapped_io *io,
	      struct buffer *buf)
{
  int ret = -1;
  BOOL status;

  switch (io->iostate)
    {
    case IOSTATE_QUEUED:
      status = GetOverlappedResult(
				   h,
				   &io->overlapped,
				   &io->size,
				   FALSE
				   );
      if (status)
	{
	  /* successful return for a queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  io->iostate = IOSTATE_INITIAL;
	  ASSERT (ResetEvent (io->overlapped.hEvent));
	  msg (D_WIN32_IO, "WIN32 I/O: TAP Completion success [%d]", ret);
	}
      else
	{
	  /* error during a queued operation */
	  ret = -1;
	  if (GetLastError() != ERROR_IO_INCOMPLETE)
	    {
	      /* if no error (i.e. just not finished yet),
		 then DON'T execute this code */
	      io->iostate = IOSTATE_INITIAL;
	      ASSERT (ResetEvent (io->overlapped.hEvent));
	      msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion error");
	    }
	}
      break;

    case IOSTATE_IMMEDIATE_RETURN:
      io->iostate = IOSTATE_INITIAL;
      ASSERT (ResetEvent (io->overlapped.hEvent));
      if (io->status)
	{
	  /* error return for a non-queued operation */
	  SetLastError (io->status);
	  ret = -1;
	  msg (D_WIN32_IO | M_ERRNO, "WIN32 I/O: TAP Completion non-queued error");
	}
      else
	{
	  /* successful return for a non-queued operation */
	  if (buf)
	    *buf = io->buf;
	  ret = io->size;
	  msg (D_WIN32_IO, "WIN32 I/O: TAP Completion non-queued success [%d]", ret);
	}
      break;

    case IOSTATE_INITIAL: /* were we called without proper queueing? */
      SetLastError (ERROR_INVALID_FUNCTION);
      ret = -1;
      msg (D_WIN32_IO, "WIN32 I/O: TAP Completion BAD STATE");
      break;

    default:
      ASSERT (0);
    }

  if (buf)
    buf->len = ret;
  return ret;
}

static bool
is_tap_win32_dev (const char* guid)
{
  HKEY netcard_key;
  LONG status;
  DWORD len;
  int i = 0;

  status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			NETCARD_REG_KEY_2000,
			0,
			KEY_READ,
			&netcard_key);

  if (status != ERROR_SUCCESS)
    msg (M_FATAL, "Error opening registry key: %s", NETCARD_REG_KEY_2000);

  while (true)
    {
      char enum_name[256];
      char unit_string[256];
      HKEY unit_key;
      char component_id_string[] = "ComponentId";
      char component_id[256];
      char net_cfg_instance_id_string[] = "NetCfgInstanceId";
      char net_cfg_instance_id[256];
      DWORD data_type;

      len = sizeof (enum_name);
      status = RegEnumKeyEx(
			    netcard_key,
			    i,
			    enum_name,
			    &len,
			    NULL,
			    NULL,
			    NULL,
			    NULL);
      if (status == ERROR_NO_MORE_ITEMS)
	break;
      else if (status != ERROR_SUCCESS)
	msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
	     NETCARD_REG_KEY_2000);

      openvpn_snprintf (unit_string, sizeof(unit_string), "%s\\%s",
			NETCARD_REG_KEY_2000, enum_name);

      status = RegOpenKeyEx(
			    HKEY_LOCAL_MACHINE,
			    unit_string,
			    0,
			    KEY_READ,
			    &unit_key);

      if (status != ERROR_SUCCESS)
	msg (D_REGISTRY, "Error opening registry key: %s", unit_string);
      else
	{
	  len = sizeof (component_id);
	  status = RegQueryValueEx(
				   unit_key,
				   component_id_string,
				   NULL,
				   &data_type,
				   component_id,
				   &len);

	  if (status != ERROR_SUCCESS || data_type != REG_SZ)
	    msg (D_REGISTRY, "Error opening registry key: %s\\%s",
		 unit_string, component_id_string);
	  else
	    {	      
	      len = sizeof (net_cfg_instance_id);
	      status = RegQueryValueEx(
				       unit_key,
				       net_cfg_instance_id_string,
				       NULL,
				       &data_type,
				       net_cfg_instance_id,
				       &len);

	      if (status == ERROR_SUCCESS && data_type == REG_SZ)
		{
		  msg (D_REGISTRY, "cid=%s netcfg=%s guid=%s",
		       component_id, net_cfg_instance_id, guid);
		  if (!strcmp (component_id, "tap")
		      && !strcmp (net_cfg_instance_id, guid))
		    {
		      RegCloseKey (unit_key);
		      RegCloseKey (netcard_key);
		      return true;
		    }
		}
	    }
	  RegCloseKey (unit_key);
	}
      ++i;
    }

  RegCloseKey (netcard_key);
  return false;
}


/*
 * The caller should set name to the name
 * of a TAP-Win32 adapter on this system.
 * The GUID that is associated with the
 * device node will be returned.
 *
 * The caller can set op == GET_DEV_UID_DEFAULT
 * to return the sole TAP device on this system.
 * If there is more than one TAP device, and
 * GET_DEV_UID_DEFAULT is
 * specified, throw an error.  If actual_name
 * non-NULL, then return a pointer to the
 * found name there.
 *
 * Set op == GET_DEV_UID_ENUMERATE
 * to print all TAP devices
 * via the msg function.
 */

const char *
get_device_guid (const char *name,
		 char *actual_name,
		 int actual_name_size,
		 int op)
{
  struct buffer out = alloc_buf_gc (256);
  LONG status;
  HKEY control_net_key;
  DWORD len;
  int i = 0;
  int dev_count = 0;

  ASSERT (op >= 0 && op < GET_DEV_UID_MAX); 

  if (op == GET_DEV_UID_ENUMERATE)
    msg (M_INFO|M_NOPREFIX, "Available TAP-WIN32 devices:");

  status = RegOpenKeyEx(
			HKEY_LOCAL_MACHINE,
			REG_CONTROL_NET,
			0,
			KEY_READ,
			&control_net_key);

  if (status != ERROR_SUCCESS)
    msg (M_FATAL, "Error opening registry key: %s", REG_CONTROL_NET);

  while (true)
    {
      char enum_name[256];
      char connection_string[256];
      HKEY connection_key;
      char name_data[256];
      DWORD name_type;
      const char name_string[] = "Name";

      len = sizeof (enum_name);
      status = RegEnumKeyEx(
			    control_net_key,
			    i,
			    enum_name,
			    &len,
			    NULL,
			    NULL,
			    NULL,
			    NULL);
      if (status == ERROR_NO_MORE_ITEMS)
	break;
      else if (status != ERROR_SUCCESS)
	msg (M_FATAL, "Error enumerating registry subkeys of key: %s",
	     REG_CONTROL_NET);

      openvpn_snprintf (connection_string, sizeof(connection_string),
			"%s\\%s\\Connection",
			REG_CONTROL_NET, enum_name);

      status = RegOpenKeyEx(
			    HKEY_LOCAL_MACHINE,
			    connection_string,
			    0,
			    KEY_READ,
			    &connection_key);

      if (status != ERROR_SUCCESS)
	msg (D_REGISTRY, "Error opening registry key: %s", connection_string);
      else
	{
	  len = sizeof (name_data);
	  status = RegQueryValueEx(
				   connection_key,
				   name_string,
				   NULL,
				   &name_type,
				   name_data,
				   &len);

	  if (status != ERROR_SUCCESS || name_type != REG_SZ)
	    msg (D_REGISTRY, "Error opening registry key: %s\\%s\\%s",
		 REG_CONTROL_NET, connection_string, name_string);
	  else
	    {
	      if (is_tap_win32_dev (enum_name))
		{
		  ++dev_count;
		  if (op == GET_DEV_UID_ENUMERATE)
		    {
		      msg (M_INFO|M_NOPREFIX, "[%d] '%s'", dev_count, name_data);
		    }
		  else if (op == GET_DEV_UID_DEFAULT)
		    {
		      if (dev_count > 1)
			{
			  msg (M_FATAL, "You have more than one TAP-Win32 adapter on this system.  You must use the --dev-node option to tell me which one to use.");
			}
		      else
			{
			  buf_printf (&out, "%s", enum_name);
			  if (actual_name)
			    openvpn_snprintf (actual_name, actual_name_size, "%s", name_data);
			}
		    }
		  else if (!strcmp (name_data, name))
		    {
		      buf_printf (&out, "%s", enum_name);
		      if (actual_name)
			openvpn_snprintf (actual_name, actual_name_size, "%s", name_data);
		      RegCloseKey (connection_key);
		      RegCloseKey (control_net_key);
		      return BSTR (&out); /* successful return of explicitly
					     specified TAP-Win32 adapter */
		    }
		}
	    }

	  RegCloseKey (connection_key);
	}
      ++i;
    }

  RegCloseKey (control_net_key);

  if (op == GET_DEV_UID_ENUMERATE)
    return NULL; /* successful return in enumerated list mode */

  if (op == GET_DEV_UID_NORMAL) 
    msg (M_FATAL|M_NOPREFIX, "TAP-Win32 adapter '%s' not found -- run with --show-adapters to show a list of TAP-WIN32 adapters on this system", name);

  if (!dev_count)
    msg (M_FATAL|M_NOPREFIX, "There are no TAP-Win32 adapters on this system.  You should be able to create a TAP-Win32 adapter by going to Start -> All Programs -> " PACKAGE_NAME " -> Add a new TAP-Win32 virtual ethernet adapter.");

  ASSERT (dev_count == 1);
 
  return BSTR (&out); /* successful return of default TAP-Win32 adapter */
}

/*
 * Check that two addresses are part of the same 255.255.255.252 subnet.
 */
void
verify_255_255_255_252 (in_addr_t local, in_addr_t remote)
{
  const unsigned int mask = 3;
  const char *err = NULL;

  if (local == remote)
    {
      err = "must be different";
      goto error;
    }
  if ((local & (~mask)) != (remote & (~mask)))
    {
      err = "must exist within the same 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
      goto error;
    }
  if ((local & mask) == 0
      || (local & mask) == 3
      || (remote & mask) == 0
      || (remote & mask) == 3)
    {
      err = "cannot use the first or last address within a given 255.255.255.252 subnet.  This is a limitation of --dev tun when used with the TAP-WIN32 driver";
      goto error;
    }

  return;

 error:
  msg (M_FATAL, "There is a problem in your selection of --ifconfig endpoints [local=%s, remote=%s].  The local and remote VPN endpoints %s.  Try '" PACKAGE " --show-valid-subnets' option for more info.",
       print_in_addr_t (local, false),
       print_in_addr_t (remote, false),
       err);
}

void show_valid_win32_tun_subnets (void)
{
  int i;
  int col = 0;

  printf ("On Windows, point-to-point IP support (i.e. --dev tun)\n");
  printf ("is emulated by the TAP-Win32 driver.  The major limitation\n");
  printf ("imposed by this approach is that the --ifconfig local and\n");
  printf ("remote endpoints must be part of the same 255.255.255.252\n");
  printf ("subnet.  The following list shows examples of endpoint\n");
  printf ("pairs which satisfy this requirement.  Only the final\n");
  printf ("component of the IP address pairs is at issue.\n\n");
  printf ("As an example, the following option would be correct:\n");
  printf ("    --ifconfig 10.7.0.5 10.7.0.6 (on host A)\n");
  printf ("    --ifconfig 10.7.0.6 10.7.0.5 (on host B)\n");
  printf ("because [5,6] is part of the below list.\n\n");

  for (i = 0; i < 256; i += 4)
    {
      printf("[%3d,%3d] ", i+1, i+2);
      if (++col > 4)
	{
	  col = 0;
	  printf ("\n");
	}
    }
  if (col)
    printf ("\n");
}

void
show_tap_win32_adapters (void)
{
  get_device_guid (NULL, NULL, 0, GET_DEV_UID_ENUMERATE);
}

/*
 * Given an adapter index, return a pointer to the
 * IP_ADAPTER_INFO structure for that adapter.
 */
static PIP_ADAPTER_INFO
get_adapt_info (DWORD index)
{
  ULONG size = 0;
  DWORD status;

  if (index != ~0)
    {
      if ((status = GetAdaptersInfo (NULL, &size)) != ERROR_BUFFER_OVERFLOW)
	{
	  msg (M_INFO, "GetAdaptersInfo #1 failed [%u] (status=%u) : %s",
	       (unsigned int)index,
	       (unsigned int)status,
	       strerror_win32 (status));
	}
      else
	{
	  PIP_ADAPTER_INFO pi = (PIP_ADAPTER_INFO) gc_malloc (size);
	  ASSERT (pi);
	  if ((status = GetAdaptersInfo (pi, &size)) != NO_ERROR)
	    {
	      msg (M_INFO, "GetAdaptersInfo #2 failed [%u] (status=%u) : %s",
		   (unsigned int)index,
		   (unsigned int)status,
		   strerror_win32 (status));
	      return NULL;
	    }

	  /* find index in the linked list */
	  {
	    PIP_ADAPTER_INFO a;
	    for (a = pi; a != NULL; a = a->Next)
	      {
		if (a->Index == index)
		  return a;
	      }
	  }
	}
    }
  return NULL;
}

/*
 * Given an adapter index, return true if the adapter
 * is DHCP disabled.
 */
static bool
dhcp_disabled (DWORD index)
{
  PIP_ADAPTER_INFO a = get_adapt_info (index);
  if (a)
    {
      if (!a->DhcpEnabled)
	return true;
    }
  return false;
}

/*
 * Delete all temporary address/netmask pairs which were added
 * to adapter (given by index) by previous calls to AddIPAddress.
 */
static void
delete_temp_addresses (DWORD index)
{
  PIP_ADAPTER_INFO a = get_adapt_info (index);
  if (a)
    {
      PIP_ADDR_STRING ip = &a->IpAddressList;
      while (ip)
	{
	  DWORD status;
	  const DWORD context = ip->Context;

	  if ((status = DeleteIPAddress ((ULONG) context)) == NO_ERROR)
	    {
	      msg (M_INFO, "Successfully deleted previously set dynamic IP/netmask: %s/%s",
		   ip->IpAddress.String,
		   ip->IpMask.String);
	    }
	  else
	    {
	      const char *empty = "0.0.0.0";
	      if (strcmp (ip->IpAddress.String, empty)
		  || strcmp (ip->IpMask.String, empty))
		msg (M_INFO, "NOTE: could not delete previously set dynamic IP/netmask: %s/%s (status=%u)",
		     ip->IpAddress.String,
		     ip->IpMask.String,
		     (unsigned int)status);
	    }
	  ip = ip->Next;
	}
    }
}

/*
 * Get interface index for use with IP Helper API functions.
 */
static DWORD
get_interface_index (const char *guid)
{
  ULONG index;
  DWORD status;
  wchar_t wbuf[256];
  snwprintf (wbuf, SIZE (wbuf), L"\\DEVICE\\TCPIP_%S", guid);
  wbuf [SIZE(wbuf) - 1] = 0;
  if ((status = GetAdapterIndex (wbuf, &index)) != NO_ERROR)
    {
      msg (M_INFO, "NOTE: could not get adapter index for %S, status=%u : %s",
	   wbuf,
	   (unsigned int)status,
	   strerror_win32 (status));
      return ~0;
    }
  else
    {
      return index;
    }
}

/*
 * Convert DHCP options from the command line / config file
 * into a raw DHCP-format options string.
 */

static void
write_dhcp_u8 (struct buffer *buf, const int type, const int data)
{
  if (!buf_safe (buf, 3))
    msg (M_FATAL, "write_dhcp_u8: buffer overflow building DHCP options");
  buf_write_u8 (buf, type);
  buf_write_u8 (buf, 1);
  buf_write_u8 (buf, data);
}

static void
write_dhcp_u32_array (struct buffer *buf, const int type, const uint32_t *data, const unsigned int len)
{
  if (len > 0)
    {
      int i;
      const int size = len * sizeof (uint32_t);

      if (!buf_safe (buf, 2 + size))
	msg (M_FATAL, "write_dhcp_u32_array: buffer overflow building DHCP options");
      if (size < 1 || size > 255)
	msg (M_FATAL, "write_dhcp_u32_array: size (%d) must be > 0 and <= 255", size);
      buf_write_u8 (buf, type);
      buf_write_u8 (buf, size);
      for (i = 0; i < len; ++i)
	buf_write_u32 (buf, data[i]);
    }
}

static void
write_dhcp_str (struct buffer *buf, const int type, const char *str)
{
  const int len = strlen (str);
  if (!buf_safe (buf, 2 + len))
    msg (M_FATAL, "write_dhcp_str: buffer overflow building DHCP options");
  if (len < 1 || len > 255)
    msg (M_FATAL, "write_dhcp_str: string '%s' must be > 0 bytes and <= 255 bytes", str);
  buf_write_u8 (buf, type);
  buf_write_u8 (buf, len);
  buf_write (buf, str, len);
}

static void
build_dhcp_options_string (struct buffer *buf, const struct tuntap_options *o)
{
  if (o->domain)
    write_dhcp_str (buf, 15, o->domain);

  if (o->netbios_scope)
    write_dhcp_str (buf, 47, o->netbios_scope);

  if (o->netbios_node_type)
    write_dhcp_u8 (buf, 46, o->netbios_node_type);

  write_dhcp_u32_array (buf, 6, o->dns, o->dns_len);
  write_dhcp_u32_array (buf, 44, o->wins, o->wins_len);
  write_dhcp_u32_array (buf, 42, o->ntp, o->ntp_len);
  write_dhcp_u32_array (buf, 45, o->nbdd, o->nbdd_len);
}

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  char device_path[256];
  const char *device_guid = NULL;
  DWORD len;

  netcmd_semaphore_lock ();

  ipv6_support (ipv6, false, tt);

  if (tt->type == DEV_TYPE_NULL)
    {
      open_null (tt);
      netcmd_semaphore_release ();
      return;
    }
  else if (tt->type == DEV_TYPE_TAP || tt->type == DEV_TYPE_TUN)
    {
      ;
    }
  else
    {
      msg (M_FATAL|M_NOPREFIX, "Unknown virtual device type: '%s'", dev);
    }

  /*
   * Lookup the device name in the registry, using the --dev-node high level name.
   */
  {
    int op = GET_DEV_UID_NORMAL; 

    if (!dev_node)
      op = GET_DEV_UID_DEFAULT; 

    /* translate high-level device name into a device instance
       GUID using the registry */
    device_guid = get_device_guid (dev_node, tt->actual, sizeof (tt->actual), op);
  }

  /*
   * Open Windows TAP-Win32 adapter
   */

  openvpn_snprintf (device_path, sizeof(device_path), "%s%s%s",
		    USERMODEDEVICEDIR,
		    device_guid,
		    TAPSUFFIX);

  tt->hand = CreateFile (
			 device_path,
			 GENERIC_READ | GENERIC_WRITE,
			 0, /* was: FILE_SHARE_READ */
			 0,
			 OPEN_EXISTING,
			 FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			 0
			 );

  if (tt->hand == INVALID_HANDLE_VALUE)
    msg (M_ERR, "CreateFile failed on TAP device: %s", device_path);

  msg (M_INFO, "TAP-WIN32 device [%s] opened: %s", tt->actual, device_path);

  /* get driver version info */
  {
    ULONG info[3];
    CLEAR (info);
    if (DeviceIoControl (tt->hand, TAP_IOCTL_GET_VERSION,
			 &info, sizeof (info),
			 &info, sizeof (info), &len, NULL))
      {
	msg (D_TUNTAP_INFO, "TAP-Win32 Driver Version %d.%d %s",
	     (int) info[0],
	     (int) info[1],
	     (info[2] ? "(DEBUG)" : ""));

      }
    if ( !(info[0] > TAP_WIN32_MIN_MAJOR
	   || (info[0] == TAP_WIN32_MIN_MAJOR && info[1] >= TAP_WIN32_MIN_MINOR)) )
      msg (M_FATAL, "ERROR:  This version of " PACKAGE_NAME " requires a TAP-Win32 driver that is at least version %d.%d -- If you recently upgraded your " PACKAGE_NAME " distribution, a reboot is probably required at this point to get Windows to see the new driver.",
	   TAP_WIN32_MIN_MAJOR,
	   TAP_WIN32_MIN_MINOR);
  }

  /* get driver MTU */
  {
    ULONG mtu;
    if (DeviceIoControl (tt->hand, TAP_IOCTL_GET_MTU,
			 &mtu, sizeof (mtu),
			 &mtu, sizeof (mtu), &len, NULL))
      {
	tt->post_open_mtu = (int) mtu;
	msg (D_MTU_INFO, "TAP-Win32 MTU=%d", (int) mtu);
      }
  }

  /* set point-to-point mode if TUN device */

  if (tt->type == DEV_TYPE_TUN)
    {
      in_addr_t ep[2];
      ep[0] = htonl (tt->local);
      ep[1] = htonl (tt->remote_netmask);
      if (!tt->did_ifconfig_setup)
	{
	  msg (M_FATAL, "ERROR: --dev tun also requires --ifconfig");
	}
      if (!DeviceIoControl (tt->hand, TAP_IOCTL_CONFIG_POINT_TO_POINT,
			    ep, sizeof (ep),
			    ep, sizeof (ep), &len, NULL))
	msg (M_FATAL, "ERROR: The TAP-Win32 driver rejected a DeviceIoControl call to set Point-to-Point mode, which is required for --dev tun");
    }

  /* should we tell the TAP-Win32 driver to masquerade as a DHCP server as a means
     of setting the adapter address? */
  if (tt->did_ifconfig_setup && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ)
    {
      uint32_t ep[4];

      /* We will answer DHCP requests with a reply to set IP/subnet to these values */
      ep[0] = htonl (tt->local);
      ep[1] = htonl (tt->adapter_netmask);

      /* At what IP address should the DHCP server masquerade at? */
      if (tt->type == DEV_TYPE_TUN)
	{
	  ep[2] = htonl (tt->remote_netmask);
	  if (tt->options.dhcp_masq_custom_offset)
	    msg (M_WARN, "WARNING: because you are using '--dev tun' mode, the '--ip-win32 dynamic [offset]' option is ignoring the offset parameter");
	}
      else
	{
	  in_addr_t dsa; /* DHCP server addr */

	  ASSERT (tt->type == DEV_TYPE_TAP);

	  if (tt->options.dhcp_masq_offset < 0)
	    dsa = (tt->local | (~tt->adapter_netmask)) + tt->options.dhcp_masq_offset;
	  else
	    dsa = (tt->local & tt->adapter_netmask) + tt->options.dhcp_masq_offset;

	  if (dsa == tt->local)
	    msg (M_FATAL, "ERROR: There is a clash between the --ifconfig local address and the internal DHCP server address -- both are set to %s -- please use the --ip-win32 dynamic option to choose a different free address from the --ifconfig subnet for the internal DHCP server", print_in_addr_t (dsa, false));

	  if ((tt->local & tt->adapter_netmask) != (dsa & tt->adapter_netmask))
	    msg (M_FATAL, "ERROR: --tap-win32 dynamic [offset] : offset is outside of --ifconfig subnet");

	  ep[2] = htonl (dsa);
	}

      /* lease time in seconds */
      ep[3] = (uint32_t) tt->options.dhcp_lease_time;

      ASSERT (ep[3] > 0);

      if (!DeviceIoControl (tt->hand, TAP_IOCTL_CONFIG_DHCP_MASQ,
			    ep, sizeof (ep),
			    ep, sizeof (ep), &len, NULL))
	msg (M_FATAL, "ERROR: The TAP-Win32 driver rejected a DeviceIoControl call to set TAP_IOCTL_CONFIG_DHCP_MASQ mode");

      msg (M_INFO, "Notified TAP-Win32 driver to set a DHCP IP/netmask of %s/%s on interface %s [DHCP-serv: %s, lease-time: %d]",
	   print_in_addr_t (tt->local, false),
	   print_in_addr_t (tt->adapter_netmask, false),
	   device_guid,
	   print_in_addr_t (ntohl(ep[2]), false),
	   ep[3]
	   );

      /* user-supplied DHCP options capability */
      if (tt->options.dhcp_options)
	{
	  struct buffer buf = alloc_buf (256);
	  build_dhcp_options_string (&buf, &tt->options);
	  msg (D_DHCP_OPT, "DHCP option string: %s", format_hex (BPTR (&buf), BLEN (&buf), 0));
	  if (!DeviceIoControl (tt->hand, TAP_IOCTL_CONFIG_DHCP_SET_OPT,
				BPTR (&buf), BLEN (&buf),
				BPTR (&buf), BLEN (&buf), &len, NULL))
	    msg (M_FATAL, "ERROR: The TAP-Win32 driver rejected a TAP_IOCTL_CONFIG_DHCP_SET_OPT DeviceIoControl call");
	  free_buf (&buf);
	}
    }

#if 1
  /* set driver media status to 'connected' */
  {
    ULONG status = TRUE;
    if (!DeviceIoControl (tt->hand, TAP_IOCTL_SET_MEDIA_STATUS,
			  &status, sizeof (status),
			  &status, sizeof (status), &len, NULL))
      msg (M_WARN, "WARNING: The TAP-Win32 driver rejected a TAP_IOCTL_SET_MEDIA_STATUS DeviceIoControl call.");
  }
#endif

  /* possible wait for adapter to come up */
  {
    int s = tt->options.tap_sleep;
    if (s)
      {
	msg (M_INFO, "Sleeping for %d seconds...", s);
	sleep (s);
      }
  }

  /* possibly use IP Helper API to set IP address on adapter */
  {
    DWORD index = get_interface_index (device_guid);
    
    /* flush arp cache */
    if (index != ~0)
      {
	DWORD status;

	if ((status = FlushIpNetTable (index)) == NO_ERROR)
	  msg (M_INFO, "Successful ARP Flush on interface [%u] %s",
	       (unsigned int)index,
	       device_guid);
	else
	  msg (M_WARN, "NOTE: FlushIpNetTable failed on interface [%u] %s (status=%u) : %s",
	       (unsigned int)index,
	       device_guid,
	       (unsigned int)status,
	       strerror_win32 (status));
      }

    /*
     * If the TAP-Win32 driver is masquerading as a DHCP server
     * make sure the TCP/IP properties for the adapter are
     * set correctly.
     */
    if (tt->did_ifconfig_setup && tt->options.ip_win32_type == IPW32_SET_DHCP_MASQ)
      {
	/* check dhcp enable status */
	if (dhcp_disabled (index))
	  msg (M_WARN, "WARNING: You have selected '--ip-win32 dynamic', which will not work unless the TAP-Win32 TCP/IP properties are set to 'Obtain an IP address automatically'");
      }

    if (tt->did_ifconfig_setup && tt->options.ip_win32_type == IPW32_SET_IPAPI)
      {
	DWORD status;
	const char *error_suffix = "I am having trouble using the Windows 'IP helper API' to automatically set the IP address -- consider using other --ip-win32 methods (not 'ipapi')";

	/* couldn't get adapter index */
	if (index == ~0)
	  {
	    msg (M_FATAL, "ERROR: unable to get adapter index for interface %s -- %s",
		 device_guid,
		 error_suffix);
	  }

	/* check dhcp enable status */
	if (dhcp_disabled (index))
	  msg (M_WARN, "NOTE: You have selected (explicitly or by default) '--ip-win32 ipapi', which has a better chance of working correctly if the TAP-Win32 TCP/IP properties are set to 'Obtain an IP address automatically'");

	/* delete previously added IP addresses which were not
	   correctly deleted */
	delete_temp_addresses (index);

	/* add a new IP address */
	if ((status = AddIPAddress (htonl(tt->local),
				    htonl(tt->adapter_netmask),
				    index,
				    &tt->ipapi_context,
				    &tt->ipapi_instance)) == NO_ERROR)
	  msg (M_INFO, "Succeeded in adding a temporary IP/netmask of %s/%s to interface %s using the Win32 IP Helper API",
	       print_in_addr_t (tt->local, false),
	       print_in_addr_t (tt->adapter_netmask, false),
	       device_guid
	       );
	else
	  msg (M_FATAL, "ERROR: AddIPAddress %s/%s failed on interface %s, index=%u, status=%u (windows error: '%s') -- %s",
	       print_in_addr_t (tt->local, false),
	       print_in_addr_t (tt->adapter_netmask, false),
	       device_guid,
	       (unsigned int)index,
	       (unsigned int)status,
	       strerror_win32 (status),
	       error_suffix);
	tt->ipapi_context_defined = true;
      }
  }
  netcmd_semaphore_release ();
}

const char *
tap_win32_getinfo (struct tuntap *tt)
{
  if (tt && tt->hand != NULL)
    {
      struct buffer out = alloc_buf_gc (256);
      DWORD len;
      if (DeviceIoControl (tt->hand, TAP_IOCTL_GET_INFO,
			   BSTR (&out), BCAP (&out),
			   BSTR (&out), BCAP (&out),
			   &len, NULL))
	{
	  return BSTR (&out);
	}
    }
  return NULL;
}

#ifdef TAP_WIN32_DEBUG

void
tun_show_debug (struct tuntap *tt)
{
  if (tt && tt->hand != NULL)
    {
      struct buffer out = alloc_buf (1024);
      DWORD len;
      while (DeviceIoControl (tt->hand, TAP_IOCTL_GET_LOG_LINE,
			      BSTR (&out), BCAP (&out),
			      BSTR (&out), BCAP (&out),
			      &len, NULL))
	{
	  msg (D_TAP_WIN32_DEBUG, "TAP-Win32: %s", BSTR (&out));
	}
      free_buf (&out);
    }
}

#endif

void
close_tun (struct tuntap *tt)
{
#if 1
  if (tt->ipapi_context_defined)
    {
      DWORD status;
      if ((status = DeleteIPAddress (tt->ipapi_context)) != NO_ERROR)
	{
	  msg (M_WARN, "Warning: DeleteIPAddress[%u] failed on TAP-Win32 adapter, status=%u : %s",
	       (unsigned int)tt->ipapi_context,
	       (unsigned int)status,
	       strerror_win32 (status));
	}
    }
#endif

  if (tt->hand != NULL)
    {
      msg (D_WIN32_IO_LOW, "Attempting CancelIO on TAP-Win32 adapter");
      if (!CancelIo (tt->hand))
	msg (M_WARN | M_ERRNO, "Warning: CancelIO failed on TAP-Win32 adapter");
    }

  msg (D_WIN32_IO_LOW, "Attempting close of overlapped read event on TAP-Win32 adapter");
  overlapped_io_close (&tt->reads);

  msg (D_WIN32_IO_LOW, "Attempting close of overlapped write event on TAP-Win32 adapter");
  overlapped_io_close (&tt->writes);

  if (tt->hand != NULL)
    {
      msg (D_WIN32_IO_LOW, "Attempting CloseHandle on TAP-Win32 adapter");
      if (!CloseHandle (tt->hand))
	msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on TAP-Win32 adapter");
    }
  clear_tuntap (tt);
}

/*
 * Convert --ip-win32 constants between index and ascii form.
 */

struct ipset_names {
  const char *short_form;
};

/* Indexed by IPW32_SET_x */
static const struct ipset_names ipset_names[] = {
  {"manual"},
  {"netsh"},
  {"ipapi"},
  {"dynamic"}
};

int
ascii2ipset (const char* name)
{
  int i;
  ASSERT (IPW32_SET_N == SIZE (ipset_names));
  for (i = 0; i < IPW32_SET_N; ++i)
    if (!strcmp (name, ipset_names[i].short_form))
      return i;
  return -1;
}

const char *
ipset2ascii (int index)
{
  ASSERT (IPW32_SET_N == SIZE (ipset_names));
  if (index < 0 || index >= IPW32_SET_N)
    return "[unknown --ip-win32 type]";
  else
    return ipset_names[index].short_form;
}

const char *
ipset2ascii_all ()
{
  struct buffer out = alloc_buf_gc (256);
  int i;

  ASSERT (IPW32_SET_N == SIZE (ipset_names));
  for (i = 0; i < IPW32_SET_N; ++i)
    {
      if (i)
	buf_printf(&out, " ");
      buf_printf(&out, "[%s]", ipset2ascii(i));
    }
  return BSTR (&out);
}

#else /* generic */

void
open_tun (const char *dev, const char *dev_type, const char *dev_node, bool ipv6, struct tuntap *tt)
{
  open_tun_generic (dev, dev_type, dev_node, ipv6, false, true, tt);
}

void
close_tun (struct tuntap* tt)
{
  close_tun_generic (tt);
}

int
write_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return write (tt->fd, buf, len);
}

int
read_tun (struct tuntap* tt, uint8_t *buf, int len)
{
  return read (tt->fd, buf, len);
}

#endif
