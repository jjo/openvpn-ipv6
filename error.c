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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "error.h"
#include "buffer.h"
#include "thread.h"
#include "misc.h"
#include "openvpn.h"
#include "win32.h"
#include "socket.h"
#include "tun.h"

#ifdef USE_CRYPTO
#include <openssl/err.h>
#endif

#include "memdbg.h"

/* Globals */
unsigned int x_debug_level;

/* Mute state */
static int mute_cutoff;
static int mute_count;
static int mute_category;

/*
 * Output mode priorities are as follows:
 *
 *  (1) --log-x overrides everything
 *  (2) syslog is used if --daemon or --inetd is defined and not --log-x
 *  (3) if OPENVPN_DEBUG_COMMAND_LINE is defined, output
 *      to constant logfile name defined in openvpn.h (for debugging only).
 *  (4) Output to stdout.
 */

/* If true, indicates that stdin/stdout/stderr
   have been redirected due to --log */
static bool std_redir;

/* Should messages be written to the syslog? */
static bool use_syslog;

/* If non-null, messages should be written here (used for debugging only) */
static FILE *msgfp;

void
set_debug_level (int level)
{
  x_debug_level = level;
}

void
set_mute_cutoff (int cutoff)
{
  mute_cutoff = cutoff;
}

void
error_reset ()
{
  use_syslog = std_redir = false;
  x_debug_level = 1;
  mute_cutoff = 0;
  mute_count = 0;
  mute_category = 0;

#ifdef OPENVPN_DEBUG_COMMAND_LINE
  msgfp = fopen (OPENVPN_DEBUG_FILE, "w");
  if (!msgfp)
    openvpn_exit (OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
#else
  msgfp = NULL;
#endif
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
    openvpn_exit (OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE); /* exit point */
  return fp;
}

#define SWAP { tmp = m1; m1 = m2; m2 = tmp; }
#define ERR_BUF_SIZE 1024

int msg_line_num;

void x_msg (unsigned int flags, const char *format, ...)
{
  va_list arglist;
#if SYSLOG_CAPABILITY
  int level;
#endif
  char msg1[ERR_BUF_SIZE];
  char msg2[ERR_BUF_SIZE];
  char *m1;
  char *m2;
  char *tmp;
  int e;

  void usage_small (void);

#ifndef HAVE_VARARG_MACROS
  /* the macro has checked this otherwise */
  if (!MSG_TEST(flags))
    return;
#endif

  if (flags & M_ERRNO_SOCK)
    e = openvpn_errno_socket ();
  else
    e = openvpn_errno ();

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
  m1[ERR_BUF_SIZE - 1] = 0; /* windows vsnprintf needs this */

  if ((flags & (M_ERRNO|M_ERRNO_SOCK)) && e)
    {
      openvpn_snprintf (m2, ERR_BUF_SIZE, "%s: %s (errno=%d)",
			m1, strerror_ts (e), e);
      SWAP;
    }

#ifdef USE_CRYPTO
  if (flags & M_SSL)
    {
      int nerrs = 0;
      int err;
      while ((err = ERR_get_error ()))
	{
	  openvpn_snprintf (m2, ERR_BUF_SIZE, "%s: %s",
			    m1, ERR_error_string (err, NULL));
	  SWAP;
	  ++nerrs;
	}
      if (!nerrs)
	{
	  openvpn_snprintf (m2, ERR_BUF_SIZE, "%s (OpenSSL)", m1);
	  SWAP;
	}
    }
#endif

#if SYSLOG_CAPABILITY
  if (flags & (M_FATAL|M_NONFATAL|M_USAGE_SMALL))
    level = LOG_ERR;
  else if (flags & M_WARN)
    level = LOG_WARNING;
  else
    level = LOG_NOTICE;
#endif

  if (use_syslog && !std_redir)
    {
#if SYSLOG_CAPABILITY
      syslog (level, "%s", m1);
#endif
    }
  else
    {
      FILE *fp = msg_fp();
      const bool show_usec = check_debug_level (DEBUG_LEVEL_USEC_TIME);
      if (flags & M_NOPREFIX)
	{
	  fprintf (fp, "%s\n", m1);
	}
      else
	{
#ifdef USE_PTHREAD
	  fprintf (fp, "%s %d[%d]: %s\n",
		   time_string (0, show_usec),
		   msg_line_num,
		   thread_number (),
		   m1);
#else
	  fprintf (fp, "%s %d: %s\n",
		   time_string (0, show_usec),
		   msg_line_num,
		   m1);
#endif
	}
      fflush(fp);
      ++msg_line_num;
    }

  if (flags & M_FATAL)
    msg (M_INFO | M_NOLOCK, "Exiting");

  if (!(flags & M_NOLOCK))
    mutex_unlock (L_MSG);
  
  if (flags & M_FATAL)
    openvpn_exit (OPENVPN_EXIT_STATUS_ERROR); /* exit point */

  if (flags & M_USAGE_SMALL)
    usage_small ();
}

void
assert_failed (const char *filename, int line)
{
  msg (M_FATAL, "Assertion failed at %s:%d", filename, line);
}

void
open_syslog (const char *pgmname)
{
#if SYSLOG_CAPABILITY
  if (!msgfp && !std_redir)
    {
      if (!use_syslog)
	{
	  openlog ((pgmname ? pgmname : PACKAGE), LOG_PID, LOG_DAEMON);
	  use_syslog = true;

	  /* Better idea: somehow pipe stdout/stderr output to msg() */
	  set_std_files_to_null (false);
	}
    }
#else
  msg (M_WARN, "Warning on use of --daemon/--inetd: this operating system lacks daemon logging features, therefore when I become a daemon, I won't be able to log status or error messages");
#endif
}

void
close_syslog ()
{
#if SYSLOG_CAPABILITY
  if (use_syslog)
    {
      closelog();
      use_syslog = false;
    }
#endif
}

void
redirect_stdout_stderr (const char *file, bool append)
{
#if defined(WIN32)
  msg (M_WARN, "WARNING: The --log option is not directly supported on Windows, however you can use the " PACKAGE_NAME " service wrapper (" PACKAGE "serv.exe) to accomplish the same function -- see the Windows README.");
#elif defined(HAVE_DUP2)
  if (!std_redir)
    {
      int out  = open (file,
		   O_CREAT | O_WRONLY | (append ? O_APPEND : O_TRUNC),
		   S_IRUSR | S_IWUSR);

      if (out < 0)
	msg (M_ERR, "Error redirecting stdout/stderr to --log file: %s", file);
      if (dup2 (out, 1) == -1)
	msg (M_ERR, "--log file redirection error on stdout");
      if (dup2 (out, 2) == -1)
	msg (M_ERR, "--log file redirection error on stderr");

      if (out > 2)
	close (out);

      std_redir = true;
    }

#else
  msg (M_WARN, "WARNING: The --log option is not supported on this OS because it lacks the dup2 function");
#endif
}

/*
 * Functions used to check return status
 * of I/O operations.
 */

unsigned int x_cs_info_level;
unsigned int x_cs_verbose_level;

void
reset_check_status ()
{
  x_cs_info_level = 0;
  x_cs_verbose_level = 0;
}

void
set_check_status (unsigned int info_level, unsigned int verbose_level)
{
  x_cs_info_level = info_level;
  x_cs_verbose_level = verbose_level;
}

/*
 * Called after most socket or tun/tap operations, via the inline
 * function check_status().
 *
 * Decide if we should print an error message, and see if we can
 * extract any useful info from the error, such as a Path MTU hint
 * from the OS.
 */
void
x_check_status (int status,
		const char *description,
		struct link_socket *sock,
		struct tuntap *tt)
{
  const int my_errno = (sock ? openvpn_errno_socket () : openvpn_errno ());
  const char *extended_msg = NULL;

  msg (x_cs_verbose_level, "%s %s returned %d",
       sock ? proto2ascii (sock->proto, true) : "",
       description,
       status);

  if (status < 0)
    {
#if EXTENDED_SOCKET_ERROR_CAPABILITY
      /* get extended socket error message and possible PMTU hint from OS */
      if (sock)
	{
	  int mtu;
	  extended_msg = format_extended_socket_error (sock->sd, &mtu);
	  if (mtu > 0 && sock->mtu != mtu)
	    {
	      sock->mtu = mtu;
	      sock->mtu_changed = true;
	    }
	}
#elif defined(WIN32)
      /* get possible driver error from TAP-Win32 driver */
      extended_msg = tap_win32_getinfo (tt);
#endif
      if (my_errno != EAGAIN)
	{
	  if (extended_msg)
	    msg (x_cs_info_level, "%s %s [%s]: %s (code=%d)",
		 description,
		 sock ? proto2ascii (sock->proto, true) : "",
		 extended_msg,
		 strerror_ts (my_errno),
		 my_errno);
	  else
	    msg (x_cs_info_level, "%s %s: %s (code=%d)",
		 description,
		 sock ? proto2ascii (sock->proto, true) : "",
		 strerror_ts (my_errno),
		 my_errno);

#ifdef WIN32
	  Sleep (100); /* 100 milliseconds */
#else
	  sleep (0);   /* not enough granularity, so just relinquish time slice */
#endif
	}
    }
}

void
openvpn_exit (int status)
{
#ifdef WIN32
  uninit_win32 ();
#endif
  exit (status);
}

#ifdef WIN32

const char *
strerror_win32 (DWORD errnum)
{
  /*
   * This code can be omitted, though often the Windows
   * WSA error messages are less informative than the
   * Posix equivalents.
   */
#if 1
  switch (errnum) {
    /*
     * When the TAP-Win32 driver returns STATUS_UNSUCCESSFUL, this code
     * gets returned to user space.
     */
  case ERROR_GEN_FAILURE:
    return "General failure (ERROR_GEN_FAILURE)";
  case ERROR_IO_PENDING:
    return "I/O Operation in progress (ERROR_IO_PENDING)";
  case WSA_IO_INCOMPLETE:
    return "I/O Operation in progress (WSA_IO_INCOMPLETE)";
  case WSAEINTR:
    return "Interrupted system call (WSAEINTR)";
  case WSAEBADF:
    return "Bad file number (WSAEBADF)";
  case WSAEACCES:
    return "Permission denied (WSAEACCES)";
  case WSAEFAULT:
    return "Bad address (WSAEFAULT)";
  case WSAEINVAL:
    return "Invalid argument (WSAEINVAL)";
  case WSAEMFILE:
    return "Too many open files (WSAEMFILE)";
  case WSAEWOULDBLOCK:
    return "Operation would block (WSAEWOULDBLOCK)";
  case WSAEINPROGRESS:
    return "Operation now in progress (WSAEINPROGRESS)";
  case WSAEALREADY:
    return "Operation already in progress (WSAEALREADY)";
  case WSAEDESTADDRREQ:
    return "Destination address required (WSAEDESTADDRREQ)";
  case WSAEMSGSIZE:
    return "Message too long (WSAEMSGSIZE)";
  case WSAEPROTOTYPE:
    return "Protocol wrong type for socket (WSAEPROTOTYPE)";
  case WSAENOPROTOOPT:
    return "Bad protocol option (WSAENOPROTOOPT)";
  case WSAEPROTONOSUPPORT:
    return "Protocol not supported (WSAEPROTONOSUPPORT)";
  case WSAESOCKTNOSUPPORT:
    return "Socket type not supported (WSAESOCKTNOSUPPORT)";
  case WSAEOPNOTSUPP:
    return "Operation not supported on socket (WSAEOPNOTSUPP)";
  case WSAEPFNOSUPPORT:
    return "Protocol family not supported (WSAEPFNOSUPPORT)";
  case WSAEAFNOSUPPORT:
    return "Address family not supported by protocol family (WSAEAFNOSUPPORT)";
  case WSAEADDRINUSE:
    return "Address already in use (WSAEADDRINUSE)";
  case WSAENETDOWN:
    return "Network is down (WSAENETDOWN)";
  case WSAENETUNREACH:
    return "Network is unreachable (WSAENETUNREACH)";
  case WSAENETRESET:
    return "Net dropped connection or reset (WSAENETRESET)";
  case WSAECONNABORTED:
    return "Software caused connection abort (WSAECONNABORTED)";
  case WSAECONNRESET:
    return "Connection reset by peer (WSAECONNRESET)";
  case WSAENOBUFS:
    return "No buffer space available (WSAENOBUFS)";
  case WSAEISCONN:
    return "Socket is already connected (WSAEISCONN)";
  case WSAENOTCONN:
    return "Socket is not connected (WSAENOTCONN)";
  case WSAETIMEDOUT:
    return "Connection timed out (WSAETIMEDOUT)";
  case WSAECONNREFUSED:
    return "Connection refused (WSAECONNREFUSED)";
  case WSAELOOP:
    return "Too many levels of symbolic links (WSAELOOP)";
  case WSAENAMETOOLONG:
    return "File name too long (WSAENAMETOOLONG)";
  case WSAEHOSTDOWN:
    return "Host is down (WSAEHOSTDOWN)";
  case WSAEHOSTUNREACH:
    return "No Route to Host (WSAEHOSTUNREACH)";
  case WSAENOTEMPTY:
    return "Directory not empty (WSAENOTEMPTY)";
  case WSAEPROCLIM:
    return "Too many processes (WSAEPROCLIM)";
  case WSAEUSERS:
    return "Too many users (WSAEUSERS)";
  case WSAEDQUOT:
    return "Disc Quota Exceeded (WSAEDQUOT)";
  case WSAESTALE:
    return "Stale NFS file handle (WSAESTALE)";
  case WSASYSNOTREADY:
    return "Network SubSystem is unavailable (WSASYSNOTREADY)";
  case WSAVERNOTSUPPORTED:
    return "WINSOCK DLL Version out of range (WSAVERNOTSUPPORTED)";
  case WSANOTINITIALISED:
    return "Successful WSASTARTUP not yet performed (WSANOTINITIALISED)";
  case WSAEREMOTE:
    return "Too many levels of remote in path (WSAEREMOTE)";
  case WSAHOST_NOT_FOUND:
    return "Host not found (WSAHOST_NOT_FOUND)";
  default:
    break;
  }
#endif

  /* format a windows error message */
  {
    char message[256];
    struct buffer out = alloc_buf_gc (256);
    const int status =  FormatMessage (
				       FORMAT_MESSAGE_IGNORE_INSERTS
				       | FORMAT_MESSAGE_FROM_SYSTEM
				       | FORMAT_MESSAGE_ARGUMENT_ARRAY,
				       NULL,
				       errnum,
				       0,
				       message,
				       sizeof (message),
				       NULL);
    if (!status)
      {
	buf_printf (&out, "[Unknown Win32 Error]");
      }
    else
      {
	char *cp;
	for (cp = message; *cp != '\0'; ++cp)
	  {
	    if (*cp == '\n' || *cp == '\r')
	      *cp = ' ';
	  }
	
	buf_printf(&out, "%s", message);
      }
    
    return BSTR (&out);
  }
}

#endif
