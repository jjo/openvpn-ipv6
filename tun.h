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

#include "buffer.h"
#include "error.h"
#include "mtu.h"

/*
 * Define a tun/tap dev.
 */

struct tuntap
{
  int fd;
#ifdef TARGET_SOLARIS
  int ip_fd;
#endif
  char actual[64]; /* actual name of tun/tap dev, usually including unit number */
};

void clear_tuntap (struct tuntap *tuntap);

void open_tun (const char *dev, const char *dev_type, const char *dev_node, struct tuntap *tt);
void close_tun (struct tuntap *tt);

int write_tun (struct tuntap* tt, uint8_t *buf, int len);
int read_tun (struct tuntap* tt, uint8_t *buf, int len);

void tuncfg (const char *dev, const char *dev_type, const char *dev_node, int persist_mode);

void do_ifconfig (const char *dev, const char *dev_type,
		  const char *ifconfig_local, const char *ifconfig_remote,
		  int tun_mtu);

const char *dev_component_in_dev_node(const char *dev_node);

const char *dev_type_string(const char *dev, const char *dev_type);

/*
 * Inline functions
 */

static inline bool
tuntap_defined (const struct tuntap* tt)
{
  return tt->fd >= 0;
}

static inline void
tun_adjust_frame_parameters (struct frame* frame, int size)
{
  frame->extra_tun += size;
}

/*
 * Should ifconfig be called before or after
 * tun dev open?
 */

#define IFCONFIG_BEFORE_TUN_OPEN 0
#define IFCONFIG_AFTER_TUN_OPEN  1
#define IFCONFIG_DEFAULT         1

static inline int
ifconfig_order()
{
#if defined(TARGET_LINUX)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_SOLARIS)
  return IFCONFIG_AFTER_TUN_OPEN;
#elif defined(TARGET_OPENBSD)
  return IFCONFIG_BEFORE_TUN_OPEN;
#elif defined(TARGET_DARWIN)
  return IFCONFIG_AFTER_TUN_OPEN;
#else
  return IFCONFIG_DEFAULT;
#endif
}
