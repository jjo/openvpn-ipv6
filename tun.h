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

#ifndef TUN_H
#define TUN_H

#ifdef WIN32
#include <winioctl.h>
#include "tap-win32/common.h"
#endif

#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "io.h"
#include "proto.h"

#ifdef WIN32

struct tuntap_options {
  /* --ip-win32 options */
  bool ip_win32_defined;

# define IPW32_SET_MANUAL       0  /* "--ip-win32 manual" */
# define IPW32_SET_NETSH        1  /* "--ip-win32 netsh" */
# define IPW32_SET_IPAPI        2  /* "--ip-win32 ipapi" */
# define IPW32_SET_DHCP_MASQ    3  /* "--ip-win32 dynamic" */
# define IPW32_SET_N            4
  int ip_win32_type;

  /* --ip-win32 dynamic options */
  bool dhcp_masq_custom_offset;
  int dhcp_masq_offset;
  int dhcp_lease_time;

  /* --tap-sleep option */
  int tap_sleep;

  /* --dhcp-option options */

  bool dhcp_options;

  const char *domain;        /* DOMAIN (15) */

  const char *netbios_scope; /* NBS (47) */

  int netbios_node_type;     /* NBT 1,2,4,8 (46) */

#define N_DHCP_ADDR 4        /* Max # of addresses allowed for
			        DNS, WINS, etc. */

  /* DNS (6) */
  in_addr_t dns[N_DHCP_ADDR];
  int dns_len;

  /* WINS (44) */
  in_addr_t wins[N_DHCP_ADDR];
  int wins_len;

  /* NTP (42) */
  in_addr_t ntp[N_DHCP_ADDR];
  int ntp_len;

  /* NBDD (45) */
  in_addr_t nbdd[N_DHCP_ADDR];
  int nbdd_len;
};

#else

struct tuntap_options {
  int dummy; /* not used */
};

#endif

/*
 * Define a TUN/TAP dev.
 */

struct tuntap
{
  int type; /* DEV_TYPE_x as defined in proto.h */

  bool did_ifconfig_setup;
  bool did_ifconfig;

  bool ipv6;

  struct tuntap_options options; /* options set on command line */

  char actual[256]; /* actual name of TUN/TAP dev, usually including unit number */

  /* ifconfig parameters */
  in_addr_t local;
  in_addr_t remote_netmask;
  in_addr_t broadcast;

#ifdef WIN32
  HANDLE hand;
  struct overlapped_io reads;
  struct overlapped_io writes;

  /* used for setting interface address via IP Helper API
     or DHCP masquerade */
  bool ipapi_context_defined;
  ULONG ipapi_context;
  ULONG ipapi_instance;
  in_addr_t adapter_netmask;
#else
  int fd;   /* file descriptor for TUN/TAP dev */
#endif

#ifdef TARGET_SOLARIS
  int ip_fd;
#endif

  /* Some TUN/TAP drivers like to be ioctled for mtu
   after open */
  int post_open_mtu;
};

/*
 * These macros are called in the context of the openvpn() function,
 * and help to abstract away the differences between Win32 and Posix.
 */

#ifdef WIN32

#define TUNTAP_SET_READ(tt)  \
  { if (tt->hand != NULL) { \
      wait_add (&event_wait, tt->reads.overlapped.hEvent); \
      tun_read_queue (tt, 0); }}

#define TUNTAP_SET_WRITE(tt) \
  { if (tt->hand != NULL) \
      wait_add (&event_wait, tt->writes.overlapped.hEvent); }

#define TUNTAP_ISSET(tt, set) \
  (tt->hand != NULL \
  && wait_trigger (&event_wait, tt->set.overlapped.hEvent))

#define TUNTAP_SETMAXFD(tt)

#define TUNTAP_READ_STAT(tt) \
   (tt->hand != NULL \
   ? overlapped_io_state_ascii (&tt->reads,  "tr") : "trX")

#define TUNTAP_WRITE_STAT(tt) \
   (tt->hand != NULL \
   ? overlapped_io_state_ascii (&tt->writes, "tw") : "twX")

#else

#define TUNTAP_SET_READ(tt)   { if (tt->fd >= 0)   FD_SET   (tt->fd, &event_wait.reads); }
#define TUNTAP_SET_WRITE(tt)  { if (tt->fd >= 0)   FD_SET   (tt->fd, &event_wait.writes); }
#define TUNTAP_ISSET(tt, set)      (tt->fd >= 0 && FD_ISSET (tt->fd, &event_wait.set))
#define TUNTAP_SETMAXFD(tt)   { if (tt->fd >= 0)   wait_update_maxfd (&event_wait, tt->fd); }
#define TUNTAP_READ_STAT(tt)  (TUNTAP_ISSET (tt, reads) ?  "TR" : "tr")
#define TUNTAP_WRITE_STAT(tt) (TUNTAP_ISSET (tt, writes) ? "TW" : "tw")

#endif

/*
 * Function prototypes
 */

void clear_tuntap (struct tuntap *tuntap);

void open_tun (const char *dev, const char *dev_type, const char *dev_node,
	       bool ipv6, struct tuntap *tt);

void close_tun (struct tuntap *tt);

int write_tun (struct tuntap* tt, uint8_t *buf, int len);

int read_tun (struct tuntap* tt, uint8_t *buf, int len);

void tuncfg (const char *dev, const char *dev_type, const char *dev_node,
	     bool ipv6, int persist_mode);

const char *guess_tuntap_dev (const char *dev, const char *dev_type,
			      const char *dev_node);

void init_tun (struct tuntap *tt,
	       const char *dev,       /* --dev option */
	       const char *dev_type,  /* --dev-type option */
	       const char *ifconfig_local_parm,          /* --ifconfig parm 1 */
	       const char *ifconfig_remote_netmask_parm, /* --ifconfig parm 2 */
	       in_addr_t local_public,
	       in_addr_t remote_public,
	       const struct frame *frame,
	       const struct tuntap_options *options);

void do_ifconfig (struct tuntap *tt,
		  const char *actual,    /* actual device name */
		  int tun_mtu);

const char *dev_component_in_dev_node (const char *dev_node);

bool is_dev_type (const char *dev, const char *dev_type, const char *match_type);
int dev_type_enum (const char *dev, const char *dev_type);
const char *dev_type_string (const char *dev, const char *dev_type);

const char *ifconfig_options_string (const struct tuntap* tt,
				     bool remote,
				     bool disable);

/*
 * Inline functions
 */

static inline bool
tuntap_defined (const struct tuntap* tt)
{
#ifdef WIN32
  return tt->hand != NULL;
#else
  return tt->fd >= 0;
#endif
}

static inline void
tun_adjust_frame_parameters (struct frame* frame, int size)
{
  frame_add_to_extra_tun (frame, size);
}

/*
 * Should ifconfig be called before or after
 * tun dev open?
 */

#define IFCONFIG_BEFORE_TUN_OPEN 0
#define IFCONFIG_AFTER_TUN_OPEN  1
#define IFCONFIG_DEFAULT         1

static inline int
ifconfig_order(void)
{
#if defined(TARGET_LINUX)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_SOLARIS)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_OPENBSD)
  return IFCONFIG_BEFORE_TUN_OPEN;
#elif defined(TARGET_DARWIN)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_NETBSD)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(WIN32)
  return IFCONFIG_BEFORE_TUN_OPEN;
#else
  return IFCONFIG_DEFAULT;
#endif
}

#ifdef WIN32

#define TUN_PASS_BUFFER

int ascii2ipset (const char* name);
const char *ipset2ascii (int index);
const char *ipset2ascii_all (void);

/* op for get_device_guid */

#define GET_DEV_UID_NORMAL           0
#define GET_DEV_UID_DEFAULT          1
#define GET_DEV_UID_ENUMERATE        2
#define GET_DEV_UID_MAX              3

const char *get_device_guid (const char *name,
			     char *actual_name,
			     int actual_name_size,
			     int op);

void verify_255_255_255_252 (in_addr_t local, in_addr_t remote);

void show_tap_win32_adapters (void);
void show_valid_win32_tun_subnets (void);
const char *tap_win32_getinfo (struct tuntap *tt);
void tun_show_debug (struct tuntap *tt);

int tun_read_queue (struct tuntap *tt, int maxsize);
int tun_write_queue (struct tuntap *tt, struct buffer *buf);
int tun_finalize (HANDLE h, struct overlapped_io *io, struct buffer *buf);

static inline bool
tuntap_stop (int status)
{
  /*
   * This corresponds to the STATUS_NO_SUCH_DEVICE
   * error in tapdrvr.c.
   */
  if (status < 0)
    {
      return openvpn_errno () == ERROR_FILE_NOT_FOUND;
    }
  return false;
}

static inline int
tun_write_win32 (struct tuntap *tt, struct buffer *buf)
{
  int err = 0;
  int status = 0;
  if (overlapped_io_active (&tt->writes))
    {
      status = tun_finalize (tt->hand, &tt->writes, NULL);
      if (status < 0)
	err = GetLastError ();
    }
  tun_write_queue (tt, buf);
  if (status < 0)
    {
      SetLastError (err);
      return status;
    }
  else
    return BLEN (buf);
}

static inline int
read_tun_buffered (struct tuntap *tt, struct buffer *buf, int maxsize)
{
  return tun_finalize (tt->hand, &tt->reads, buf);
}

static inline int
write_tun_buffered (struct tuntap *tt, struct buffer *buf)
{
  return tun_write_win32 (tt, buf);
}

#else

static inline bool
tuntap_stop (int status)
{
  return false;
}

#endif

#endif /* TUN_H */
