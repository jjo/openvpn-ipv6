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

#include "config.h"

#include "syshead.h"

#include "tun.h"
#include "fdmisc.h"
#include "error.h"
#include "buffer.h"
#include "common.h"

#include "memdbg.h"

static int
open_null (char *actual, int size)
{
  strncpynt (actual, "null", size);
  return -1;
}

/* Open a TUN device */
#ifdef OLD_TUN_TAP

int
open_tun (const char *dev, char *actual, int size)
{
  char tunname[64];
  int fd;

  if (!strcmp(dev, "null"))
      return open_null(actual, size);

  /* NOTE: we don't support dynamic devices with linux 2.2 */
  snprintf (tunname, sizeof (tunname), "/dev/%s", dev);
  if ((fd = open (tunname, O_RDWR)) < 0)
    msg (M_ERR, "Cannot open TUN/TAP dev %s", tunname);
  set_nonblock (fd);
  msg (M_INFO, "TUN/TAP device %s opened", tunname);
  strncpynt (actual, dev, size);
  return fd;
}

#else

int
open_tun (const char *dev, char *actual, int size)
{
  struct ifreq ifr;
  int fd;
  const char device[] = "/dev/net/tun";

  if (!strcmp(dev, "null"))
      return open_null(actual, size);

  if ((fd = open (device, O_RDWR)) < 0)
    msg (M_ERR, "Cannot open TUN/TAP dev %s", device);

  memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_flags = IFF_NO_PI;
  if (IS_TUN (dev))
    {
      ifr.ifr_flags |= IFF_TUN;
    }
  else if (IS_TAP (dev))
    {
      ifr.ifr_flags |= IFF_TAP;
    }
  else
    {
      msg (M_FATAL, "I don't recognize device %s as a TUN or TAP device",
	   dev);
    }
  if (strlen (dev) > 3)		/* unit number specified? */
    strncpy (ifr.ifr_name, dev, IFNAMSIZ);

  if (ioctl (fd, TUNSETIFF, (void *) &ifr) < 0)
    msg (M_ERR, "Cannot ioctl TUNSETIFF %s", dev);

  set_nonblock (fd);
  msg (M_INFO, "TUN/TAP device %s opened", ifr.ifr_name);
  strncpynt (actual, ifr.ifr_name, size);
  return fd;
}

#ifdef TUNSETPERSIST

void
tuncfg (const char *dev, int persist_mode)
{
  int td;
  char actual_name[64];

  td = open_tun (dev, actual_name, sizeof (actual_name));
  if (ioctl (td, TUNSETPERSIST, persist_mode) < 0)
    msg (M_ERR, "Cannot ioctl TUNSETPERSIST(%d) %s", persist_mode, dev);
  close (td);
  msg (M_INFO, "Persist state set to: %s", (persist_mode ? "ON" : "OFF"));
}

#endif /* TUNSETPERSIST */

#endif /* OLD_TUN_TAP */
