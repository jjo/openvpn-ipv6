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

#include "error.h"
#include "thread.h"
#include "misc.h"
#include "openvpn.h"

#ifdef USE_CRYPTO
#include <openssl/err.h>
#endif

#include "memdbg.h"

/* Globals */
int _debug_level;
int _cs_info_level;
int _cs_verbose_level;

/* Mute state */
static int mute_cutoff;
static int mute_count;
static int mute_category;

/* Should messages be written to the syslog? */
static bool use_syslog;

/* If non-null, messages should be written here */
static FILE *msgfp;

void
set_debug_level (int level)
{
  _debug_level = level;
}

void
set_mute_cutoff (int cutoff)
{
  mute_cutoff = cutoff;
}

void
error_reset ()
{
  use_syslog = false;
  _debug_level = 1;
  _cs_info_level = 0;
  _cs_verbose_level = 0;
  mute_cutoff = 0;
  mute_count = 0;
  mute_category = 0;

#ifdef OPENVPN_DEBUG_COMMAND_LINE
  msgfp = fopen (OPENVPN_DEBUG_FILE, "w");
  if (!msgfp)
    exit (OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
#else
  msgfp = NULL;
#endif
}

void
set_check_status (int info_level, int verbose_level)
{
  _cs_info_level = info_level;
  _cs_verbose_level = verbose_level;
}

/*
 * Return a file to print messages to before syslog is opened.
 */
FILE *
msg_fp()
{
  FILE *fp = msgfp;
  if (!fp)
    fp = OPENVPN_MSG_FP;
  if (!fp)
    exit (OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
  return fp;
}


#define SWAP { tmp = m1; m1 = m2; m2 = tmp; }
#define ERR_BUF_SIZE 1024

int msg_line_num;

#ifdef HAVE_VARARG_MACROS
void _msg (unsigned int flags, const char *format, ...)
#else
void msg (unsigned int flags, const char *format, ...)
#endif
{
  va_list arglist;
  int level;
  char msg1[ERR_BUF_SIZE];
  char msg2[ERR_BUF_SIZE];
  char *m1;
  char *m2;
  char *tmp;
  int e;

#ifndef HAVE_VARARG_MACROS
  if (!MSG_TEST(flags))
    return;
#endif

  e = errno;

  if (!(flags & M_NOLOCK))
    mutex_lock (L_MSG);

  /*
   * Apply muting filter.
   */
  if (mute_cutoff > 0 && !(flags & M_NOMUTE))
    {
      const int mute_level = DECODE_MUTE_LEVEL(flags);
      if (mute_level > 0 && mute_level == mute_category)
	{
	  if (++mute_count > mute_cutoff)
	    {
	      if (!(flags & M_NOLOCK))
		mutex_unlock (L_MSG);
	      return;
	    }
	}
      else
	{
	  const int suppressed = mute_count - mute_cutoff;
	  if (suppressed > 0)
	    msg (M_INFO | M_NOLOCK | M_NOMUTE,
		 "%d variation(s) on previous %d message(s) suppressed by --mute",
		 suppressed,
		 mute_cutoff);
	  mute_count = 1;
	  mute_category = mute_level;
	}
    }

  m1 = msg1;
  m2 = msg2;

  va_start (arglist, format);
  vsnprintf (m1, ERR_BUF_SIZE, format, arglist);
  va_end (arglist);

  if ((flags & M_ERRNO) && e)
    {
#ifdef HAVE_STRERROR
      snprintf (m2, ERR_BUF_SIZE, "%s: %s (errno=%d)", m1, strerror (e), e);
#else
      snprintf (m2, ERR_BUF_SIZE, "%s (errno=%d)", m1, e);
#endif
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

  if (flags & (M_FATAL|M_NONFATAL))
    level = LOG_ERR;
  else if (flags & M_WARN)
    level = LOG_WARNING;
  else
    level = LOG_NOTICE;

  if (use_syslog)
    {
#if defined(HAVE_OPENLOG) && defined(HAVE_SYSLOG)
      syslog (level, "%s", m1);
#endif
    }
  else
    {
      FILE *fp = msg_fp();
#ifdef USE_PTHREAD
      fprintf (fp, "%d[%d]: %s\n", msg_line_num, thread_number (), m1);
#else
      fprintf (fp, "%d: %s\n", msg_line_num, m1);
#endif
      fflush(fp);
      ++msg_line_num;
    }

  if (flags & M_FATAL)
    msg (M_INFO | M_NOLOCK, "Exiting");

  if (!(flags & M_NOLOCK))
    mutex_unlock (L_MSG);
  
  if (flags & M_FATAL)
    exit (OPENVPN_EXIT_STATUS_ERROR); /* exit point */
}

void
assert_failed (const char *filename, int line)
{
  msg (M_FATAL, "Assertion failed at %s:%d", filename, line);
}

void
become_daemon (const char *cd)
{
#if defined(HAVE_OPENLOG) && defined(HAVE_SYSLOG)
  if (daemon (cd != NULL, 0) < 0)
    msg (M_ERR, "daemon() failed");
  if (!msgfp)
    {
      openlog ("openvpn", LOG_PID, LOG_DAEMON);
      use_syslog = true;
    }
#else
  msg (M_WARN, "Warning on use of --daemon: this operating system lacks daemon logging features, therefore when I become a daemon, I won't be able to log status or error messages");
  if (daemon (cd != NULL, 0) < 0)
    msg (M_ERR, "daemon() failed");
#endif
}

void
become_inetd_server ()
{
#if defined(HAVE_OPENLOG) && defined(HAVE_SYSLOG)
  if (!msgfp)
    {
      openlog ("openvpn", LOG_PID, LOG_DAEMON);
      use_syslog = true;
    }
#else
  msg (M_WARN, "Warning on use of --inetd: this operating system lacks syslog logging features, therefore I won't be able to log status or error messages as an inetd server");
#endif
}
