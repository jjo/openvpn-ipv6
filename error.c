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

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include "error.h"

#ifdef USE_CRYPTO
#include <openssl/err.h>
#endif

#include "memdbg.h"

/* Globals */
bool _is_daemon;
int _debug_level;
int _cs_info_level;
int _cs_verbose_level;

void
set_debug_level (int level)
{
  _debug_level = level;
}

void
error_reset ()
{
  _is_daemon = false;
  _debug_level = 1;
  _cs_info_level = 0;
  _cs_verbose_level = 0;
}

void
set_check_status (int info_level, int verbose_level)
{
  _cs_info_level = info_level;
  _cs_verbose_level = verbose_level;
}

#define SWAP { tmp = m1; m1 = m2; m2 = tmp; }
#define ERR_BUF_SIZE 1024

int msg_line_num;

void
_msg (unsigned int flags, const char *format, ...)
{
  va_list arglist;
  int level;
  char msg1[ERR_BUF_SIZE];
  char msg2[ERR_BUF_SIZE];
  char *m1 = msg1;
  char *m2 = msg2;
  char *tmp;
  int e = errno;

  va_start (arglist, format);
  vsnprintf (m1, ERR_BUF_SIZE, format, arglist);
  va_end (arglist);

  if ((flags & M_ERRNO) && e)
    {
      snprintf (m2, ERR_BUF_SIZE, "%s: %s (errno=%d)", m1, strerror (e), e);
      SWAP;
    }

#ifdef USE_CRYPTO
  if (flags & M_SSL)
    {
      int nerrs = 0;
      int err;
      while (err = ERR_get_error ())
	{
	  snprintf (m2, ERR_BUF_SIZE, "%s: %s", m1, ERR_error_string (err, NULL));
	  SWAP;
	  ++nerrs;
	}
      if (!nerrs)
	{
	  snprintf (m2, ERR_BUF_SIZE, "%s (OpenSSL)", m1);
	  SWAP;
	}
    }
#endif

  if (flags & M_FATAL)
    level = LOG_ERR;
  else if (flags & M_WARN)
    level = LOG_WARNING;
  else if ((flags & M_DEBUG) > 0)
    level = LOG_INFO;
  else
    level = LOG_INFO;

  if (_is_daemon)
    {
      syslog (level, "%s", m1);
    }
  else
    {
      printf ("%d: %s\n", msg_line_num, m1);
      ++msg_line_num;
      fflush(stdout);
    }
  if (flags & M_FATAL)
    {
      msg (M_INFO, "Exiting");
      exit (1);
    }
}

void
assert_failed (const char *filename, int line)
{
  msg (M_FATAL, "Assertion failed at %s:%d", filename, line);
}

void
become_daemon (bool daemon_flag)
{
  if (daemon_flag)
    {
      if (daemon (0, 0) < 0)
	msg (M_ERR, "daemon() failed");
      openlog ("openvpn", LOG_PID, 0);
      _is_daemon = true;
    }
}
