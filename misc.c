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

#include <pwd.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include "error.h"

#include "memdbg.h"

/* Redefine the top level directory of the filesystem
   to restrict access to files for security */
void
do_chroot (const char *path)
{
  const char *top = "/";
  if (path)
    {
      if (chroot (path))
	msg (M_ERR, "chroot to '%s' failed", path);
      if (chdir (top))
	msg (M_ERR, "cd to '%s' failed", top);
      msg (M_INFO, "chroot to '%s' and cd to '%s' succeeded", path, top);
    }
}

/* Set UID of process */
void
set_user (const char *username)
{
  if (username)
    {
      struct passwd *pw;

      pw = getpwnam (username);
      if (!pw)
	msg (M_ERR, "failed to find UID for user %s", username);
      if (setuid (pw->pw_uid))
	msg (M_ERR, "setuid('%s') failed", username);
      msg (M_INFO, "UID set to %s", username);
    }
}

/* Change process priority */
void
set_nice (int niceval)
{
  if (niceval)
    {
      if (nice (niceval) < 0)
	msg (M_ERR, "nice %d failed", niceval);
      msg (M_INFO, "nice %d succeeded", niceval);
    }
}

/* Run a shell script with one arg */
void
run_script (const char *command, const char *arg, int tun_mtu, int udp_mtu)
{
  if (command)
    {
      char command_line[256];

      ASSERT (arg);
      snprintf (command_line, sizeof (command_line), "%s %s %d %d",
		command, arg, tun_mtu, udp_mtu);
      msg (M_INFO, "%s", command_line);
      if (system (command_line) != 0)
	msg (M_ERR, "script failed");
    }
}
