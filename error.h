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
extern int _debug_level;
extern int _cs_info_level;
extern int _cs_verbose_level;

extern int msg_line_num;

/* msg() flags */

#define M_DEBUG_LEVEL     (0x0F)	 /* debug level mask */

#define M_FATAL           (1<<4)	 /* exit program */
#define M_NONFATAL        (1<<5)	 /* non-fatal error */
#define M_WARN	          (1<<6)	 /* call syslog with LOG_WARNING */
#define M_DEBUG           (1<<7)

#define M_ERRNO           (1<<8)	 /* show errno description */
#define M_SSL             (1<<9)	 /* show SSL error */
#define M_NOLOCK          (1<<10)        /* don't lock/unlock mutex */      
#define M_NOMUTE          (1<<11)        /* don't do mute processing */      

#define M_ERR     (M_FATAL | M_ERRNO)
#define M_SSLERR  (M_FATAL | M_SSL)

/*
 * Mute levels are designed to avoid large numbers of
 * mostly similar messages clogging the log file.
 *
 * A mute level of 0 is always printed.
 */
#define MUTE_LEVEL_SHIFT 16
#define MUTE_LEVEL_MASK 0xFF

#define ENCODE_MUTE_LEVEL(mute_level) (((mute_level) & MUTE_LEVEL_MASK) << MUTE_LEVEL_SHIFT)
#define DECODE_MUTE_LEVEL(flags) (((flags) >> MUTE_LEVEL_SHIFT) & MUTE_LEVEL_MASK)

/*
 * log_level:  verbosity level n (--verb n) must be >= log_level to print.
 * mute_level: don't print more than n (--mute n) consecutive messages at
 *             a given mute level, or if 0 disable muting and print everything.
 */
#define LOGLEV(log_level, mute_level, other) (((log_level)-1) | ENCODE_MUTE_LEVEL(mute_level) | other)

#define msg(flags, args...) \
    do { if (((flags) & M_DEBUG_LEVEL) < _debug_level || ((flags) & M_FATAL)) \
    _msg((flags), args); } while (false)

void _msg (unsigned int flags, const char *format, ...); /* should be called via msg above */

void error_reset ();
void set_check_status (int info_level, int verbose_level);
void set_debug_level (int level);
void set_mute_cutoff (int cutoff);

/*
 * File to print messages to before syslog is opened.
 */
FILE *msg_fp();

/* Fatal logic errors */
#define ASSERT(x) do { if (!(x)) assert_failed(__FILE__, __LINE__); } while (false)

void assert_failed (const char *filename, int line);

/* Inline functions */

static inline bool
check_debug_level (int level)
{
  return (level & M_DEBUG_LEVEL) < _debug_level;
}

static inline void
check_status (int status, const char *description)
{
  msg (_cs_verbose_level, "%s returned %d", description, status);
  if (status < 0)
    msg (_cs_info_level | M_ERRNO, "%s", description);
}

void become_daemon (const char *cd);
void become_inetd_server ();

#include "errlevel.h"

#endif
