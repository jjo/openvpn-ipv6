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
#include "common.h"

struct tuntap
{
  int fd;
#ifdef TARGET_SOLARIS
  int ip_fd;
#endif
  char actual[64]; /* actual name of tun/tap dev, usually including unit number */
};

void clear_tuntap (struct tuntap *tuntap);

void open_tun (const char *dev, const char* dev_type, struct tuntap *tt);
void close_tun (struct tuntap *tt);

int write_tun (struct tuntap* tt, uint8_t *buf, int len);
int read_tun (struct tuntap* tt, uint8_t *buf, int len);

void tuncfg (const char *dev, const char *dev_type, int persist_mode);

void do_ifconfig (const char *dev, const char* dev_type,
		  const char *ifconfig_local, const char* ifconfig_remote,
		  int tun_mtu);

/*
 * Inline functions
 */
static inline void
tun_adjust_frame_parameters (struct frame* frame, int size)
{
  frame->extra_tun += size;
}
