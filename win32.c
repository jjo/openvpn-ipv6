/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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
 * Win32-specific OpenVPN code, targetted at the mingw
 * development environment.
 */

#ifdef WIN32

#include "config-win32.h"

#include "syshead.h"
#include "buffer.h"
#include "error.h"
#include "io.h"
#include "win32.h"

#include "memdbg.h"

static struct WSAData wsa_state;
static bool pause_exit_enabled = false;

void
init_win32 (void)
{
  if (WSAStartup(0x0101, &wsa_state))
    {
      msg (M_ERR, "WSAStartup failed");
    }
  win32_signal_init ();
  save_window_title ();
  netcmd_semaphore_init ();
}

void
uninit_win32 (void)
{
  netcmd_semaphore_close ();
  if (pause_exit_enabled)
    win32_pause ();
  restore_window_title ();
  win32_signal_close ();
  WSACleanup ();
}

void
set_pause_exit_win32 (void)
{
  pause_exit_enabled = true;
}

#endif
