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

#ifndef ERROR_H
#define ERROR_H

/* String and Error functions */

#include "basic.h"

/*
 * These globals should not be accessed directly,
 * but rather through macros or inline functions defined below.
 */
extern bool _is_daemon;
extern int _debug_level;
extern int _cs_info_level;
extern int _cs_verbose_level;

extern int msg_line_num;

/* msg() flags */

#define M_INFO    0		/* default behavior */
#define M_DEBUG   (0x0F)	/* debug level mask */
#define M_FATAL   (1<<4)	/* exit program */
#define M_WARN	  (1<<5)	/* call syslog with LOG_WARNING, otherwise use LOG_INFO,
				   or LOG_ERR if E_FATAL is defined, or LOG_DEBUG if debug
				   level > 0 */
#define M_ERRNO   (1<<6)	/* show errno description */
#define M_SSL     (1<<7)	/* show SSL error */

#define M_ERR     (M_FATAL | M_ERRNO)
#define M_SSLERR  (M_FATAL | M_SSL)

#define msg(flags, args...) \
    do { if (((flags) & M_DEBUG) < _debug_level || ((flags) & M_FATAL)) \
    _msg((flags), args); } while (false)

void _msg (unsigned int flags, const char *format, ...); /* should be called via msg above */

void error_reset ();
void set_check_status (int info_level, int verbose_level);
void set_debug_level (int level);

/* Fatal logic errors */
#define ASSERT(x) do { if (!(x)) assert_failed(__FILE__, __LINE__); } while (false)

void assert_failed (const char *filename, int line);

/* Inline functions */

static inline bool
check_debug_level (int level)
{
  return level < _debug_level;
}

static inline void
check_status (int status, const char *description)
{
  msg (_cs_verbose_level, "%s returned %d", description, status);
  if (status < 0)
    msg (_cs_info_level | M_ERRNO, "%s", description);
}

static inline bool
is_daemon ()
{
  return _is_daemon;
}

void become_daemon (bool daemon_flag, const char *cd);

#endif /* ERROR_H */
