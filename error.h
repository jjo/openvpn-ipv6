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

#ifndef ERROR_H
#define ERROR_H

/* String and Error functions */

#include "basic.h"

#ifdef WIN32
# define openvpn_errno()         GetLastError()
# define openvpn_errno_socket()  WSAGetLastError()
# define openvpn_strerror(e)     strerror_win32(e)
  const char *strerror_win32 (DWORD errnum);
#else
# define openvpn_errno()         errno
# define openvpn_errno_socket()  errno
# define openvpn_strerror(x)     strerror(x)
#endif

/*
 * These globals should not be accessed directly,
 * but rather through macros or inline functions defined below.
 */
extern unsigned int x_debug_level;
extern int msg_line_num;

/* msg() flags */

#define M_DEBUG_LEVEL     (0x0F)	 /* debug level mask */

#define M_FATAL           (1<<4)	 /* exit program */
#define M_NONFATAL        (1<<5)	 /* non-fatal error */
#define M_WARN	          (1<<6)	 /* call syslog with LOG_WARNING */
#define M_DEBUG           (1<<7)

#define M_ERRNO           (1<<8)	 /* show errno description */
#define M_ERRNO_SOCK      (1<<9)	 /* show socket errno description */
#define M_SSL             (1<<10)	 /* show SSL error */
#define M_NOLOCK          (1<<11)        /* don't lock/unlock mutex */      
#define M_NOMUTE          (1<<12)        /* don't do mute processing */
#define M_NOPREFIX        (1<<13)        /* don't show date/time prefix */
#define M_USAGE_SMALL     (1<<14)        /* fatal options error, call usage_small */

/* flag combinations which are frequently used */
#define M_ERR     (M_FATAL | M_ERRNO)
#define M_SOCKERR (M_FATAL | M_ERRNO_SOCK)
#define M_SSLERR  (M_FATAL | M_SSL)
#define M_USAGE   (M_USAGE_SMALL | M_NOPREFIX)

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

/*
 * If compiler supports variable arguments in macros, define
 * msg() as a macro for optimization win.
 */

#define MSG_TEST(flags) ((((unsigned int)flags) & M_DEBUG_LEVEL) < x_debug_level || ((flags) & M_FATAL))

#if defined(HAVE_CPP_VARARG_MACRO_ISO) && !defined(__LCLINT__)
#define HAVE_VARARG_MACROS
#define msg(flags, ...) do { if (MSG_TEST(flags)) x_msg((flags), __VA_ARGS__); } while (false)
#elif defined(HAVE_CPP_VARARG_MACRO_GCC) && !defined(__LCLINT__)
#define HAVE_VARARG_MACROS
#define msg(flags, args...) do { if (MSG_TEST(flags)) x_msg((flags), args); } while (false)
#else
#warning this compiler appears to lack vararg macros which will cause a significant degradation in efficiency (you can ignore this warning if you are using LCLINT)
#define msg x_msg
#endif

void x_msg (unsigned int flags, const char *format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ; /* should be called via msg above */

/*
 * Function prototypes
 */

void error_reset (void);
void set_debug_level (int level);
void set_mute_cutoff (int cutoff);

/*
 * File to print messages to before syslog is opened.
 */
FILE *msg_fp(void);

/* Fatal logic errors */
#define ASSERT(x) do { if (!(x)) assert_failed(__FILE__, __LINE__); } while (false)

void assert_failed (const char *filename, int line);

/* Inline functions */

static inline bool
check_debug_level (unsigned int level)
{
  return (level & M_DEBUG_LEVEL) < x_debug_level;
}

/* syslog output */

void open_syslog (const char *pgmname);
void close_syslog ();

/* log file output */
void redirect_stdout_stderr (const char *file, bool append);

/* exit program */
void openvpn_exit (int status);

/*
 * Check the return status of read/write routines.
 */

struct link_socket;
struct tuntap;

extern unsigned int x_cs_info_level;
extern unsigned int x_cs_verbose_level;

void reset_check_status (void);
void set_check_status (unsigned int info_level, unsigned int verbose_level);

void x_check_status (int status,
		     const char *description,
		     struct link_socket *sock,
		     struct tuntap *tt);

static inline void
check_status (int status, const char *description, struct link_socket *sock, struct tuntap *tt)
{
  if (status < 0 || check_debug_level (x_cs_verbose_level))
    x_check_status (status, description, sock, tt);
}

#include "errlevel.h"

#endif
