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

/*
 * I/O functionality used by both the sockets and TUN/TAP I/O layers.
 *
 * We also try to abstract away the differences between Posix and Win32
 * for the benefit of openvpn.c.
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "io.h"

#include "memdbg.h"

/* allocate a buffer for socket or tun layer */
void
alloc_buf_sock_tun (struct buffer *buf, const struct frame *frame, bool tuntap_buffer)
{
  /* allocate buffer for overlapped I/O */
  *buf = alloc_buf (BUF_SIZE (frame));
  ASSERT (buf_init (buf, FRAME_HEADROOM (frame)));
  buf->len = tuntap_buffer ? MAX_RW_SIZE_TUN (frame) : MAX_RW_SIZE_LINK (frame);
  ASSERT (buf_safe (buf, 0));
}

#ifdef ENABLE_PROFILING
int
profile_select(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
  return select (n, readfds, writefds, exceptfds, timeout);
}
#endif

#ifdef WIN32

void
overlapped_io_init (struct overlapped_io *o,
		    const struct frame *frame,
		    BOOL event_state,
		    bool tuntap_buffer) /* if true: tuntap buffer, if false: socket buffer */
{
  CLEAR (*o);

  /* manual reset event, initially set according to event_state */
  o->overlapped.hEvent = CreateEvent (NULL, TRUE, event_state, NULL);
  if (o->overlapped.hEvent == NULL)
    msg (M_ERR, "CreateEvent failed");

  /* allocate buffer for overlapped I/O */
  alloc_buf_sock_tun (&o->buf_init, frame, tuntap_buffer);
}

void
overlapped_io_close (struct overlapped_io *o)
{
  if (o->overlapped.hEvent)
    {
      if (!CloseHandle (o->overlapped.hEvent))
	msg (M_WARN | M_ERRNO, "Warning: CloseHandle failed on overlapped I/O event object");
    }
  free_buf (&o->buf_init);
}

const char *
overlapped_io_state_ascii (const struct overlapped_io *o, const char* prefix)
{
  struct buffer out = alloc_buf_gc (16);
  buf_printf (&out, "%s", prefix);
  switch (o->iostate)
    {
    case IOSTATE_INITIAL:
      buf_printf (&out, "0");
      break;
    case IOSTATE_QUEUED:
      buf_printf (&out, "Q");
      break;
    case IOSTATE_IMMEDIATE_RETURN:
      buf_printf (&out, "R");
      break;
    }
  return BSTR (&out);
}

/*
 * win32_signal is used to get input from the keyboard
 * if we are running in a console, or get input from an
 * event object if we are running as a service.
 */

struct win32_signal win32_signal;

static void
win32_signal_open (struct win32_signal *ws)
{
  ws->service = false;

  /*
   * Try to open console.
   */
  ws->in = GetStdHandle (STD_INPUT_HANDLE);
  if (ws->in != INVALID_HANDLE_VALUE)
    {
      DWORD console_mode;
      if (GetConsoleMode (ws->in, &console_mode))
	{
	  /* running on a console */
	  console_mode &= ~(ENABLE_WINDOW_INPUT
			    | ENABLE_PROCESSED_INPUT
			    | ENABLE_LINE_INPUT
			    | ENABLE_ECHO_INPUT 
			    | ENABLE_MOUSE_INPUT);

	  if (!SetConsoleMode(ws->in, console_mode))
	    msg (M_ERR, "SetConsoleMode failed");
	}
      else
	ws->in = INVALID_HANDLE_VALUE; /* probably running as a service */
    }

  /*
   * If console open failed, assume we are running
   * as a service.
   */
  if (ws->in == INVALID_HANDLE_VALUE)
    {
      ws->service = true;
      ws->in = CreateEvent (NULL, TRUE, TRUE, EXIT_EVENT_NAME);
      if (ws->in == NULL)
	msg (M_ERR, "I seem to be running as a service, but CreateEvent '%s' failed on my exit event object", EXIT_EVENT_NAME);
      if (WaitForSingleObject (ws->in, 0) != WAIT_TIMEOUT)
	msg (M_FATAL, "I seem to be running as a service, but my exit event object is telling me to exit immediately");
    }
}

static bool
keyboard_input_available (struct win32_signal *ws)
{
  ASSERT (!ws->service);
  if (ws->in != INVALID_HANDLE_VALUE)
    {
      DWORD n;
      if (GetNumberOfConsoleInputEvents (ws->in, &n))
	return n > 0;
    }
  return false;
}

static unsigned int
keyboard_ir_to_key (INPUT_RECORD *ir)
{
  if (ir->Event.KeyEvent.uChar.AsciiChar == 0)
    return ir->Event.KeyEvent.wVirtualScanCode;

  if ((ir->Event.KeyEvent.dwControlKeyState
       & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED))
      && (ir->Event.KeyEvent.wVirtualKeyCode != 18))
    return ir->Event.KeyEvent.wVirtualScanCode * 256;

  return ir->Event.KeyEvent.uChar.AsciiChar;
}

unsigned int
keyboard_get (struct win32_signal *ws)
{
  ASSERT (!ws->service);
  if (ws->in != INVALID_HANDLE_VALUE)
    {
      INPUT_RECORD ir;
      do {
	DWORD n;
	if (!keyboard_input_available (ws))
	  return 0;
	if (!ReadConsoleInput (ws->in, &ir, 1, &n))
	  return 0;
      } while (ir.EventType != KEY_EVENT || ir.Event.KeyEvent.bKeyDown != TRUE);

      return keyboard_ir_to_key (&ir);
    }
  else
    return 0;
}

void
win32_signal_init (void)
{
  win32_signal_open (&win32_signal);
}

void
win32_signal_close (void)
{
  if (win32_signal.service
      && win32_signal.in
      && win32_signal.in != INVALID_HANDLE_VALUE)
    {
      CloseHandle (win32_signal.in);
    }
  CLEAR (win32_signal);
}

int
win32_signal_get (struct win32_signal *ws)
{
  if (ws->service)
    {
      if (WaitForSingleObject (ws->in, 0) == WAIT_OBJECT_0)
	return SIGTERM;
      else
	return 0;
    }
  else
    {
      switch (keyboard_get (ws)) {
      case 0x3B: /* F1 -> USR1 */
	return SIGUSR1;
      case 0x3C: /* F2 -> USR2 */
	return SIGUSR2;
      case 0x3D: /* F3 -> HUP */
	return SIGHUP;
      case 0x3E: /* F4 -> TERM */
	return SIGTERM;
      default:
	return 0;
      }
    }
}

void
win32_pause (void)
{
  if (!win32_signal.service
      && win32_signal.in
      && win32_signal.in != INVALID_HANDLE_VALUE)
    {
      int status;
      msg (M_INFO|M_NOPREFIX, "Press any key to continue...");
      do {
	status = WaitForSingleObject (win32_signal.in, INFINITE);
      } while (!keyboard_get (&win32_signal));
    }
}

/* window functions */

static char old_window_title [256] = { 0 };

void
save_window_title ()
{
  if (!win32_signal.service)
    {
      if (!GetConsoleTitle (old_window_title, sizeof (old_window_title)))
	old_window_title[0] = 0;
    }
}

void
restore_window_title ()
{
  if (!win32_signal.service)
    {
      if (strlen (old_window_title))
	SetConsoleTitle (old_window_title);
    }
}

void
generate_window_title (const char *title)
{
  if (!win32_signal.service)
    {
      struct buffer out = alloc_buf_gc (256);
      buf_printf (&out, "[%s] " PACKAGE_NAME " " VERSION " F4:EXIT F1:USR1 F2:USR2 F3:HUP", title);
      SetConsoleTitle (BSTR (&out));
    }
}

/* semaphore functions */

void
semaphore_clear (struct semaphore *s)
{
  CLEAR (*s);
}

void
semaphore_open (struct semaphore *s, const char *name)
{
  s->locked = false;
  s->name = name;
  s->hand = CreateSemaphore(NULL, 1, 1, name);
  if (s->hand == NULL)
    msg (M_ERR, "Cannot create Win32 semaphore '%s'", name);
  msg (D_SEMAPHORE, "Created Win32 semaphore '%s'", s->name);
}

bool
semaphore_lock (struct semaphore *s, int timeout_milliseconds)
{
  DWORD status;
  bool ret;

  ASSERT (s->hand);
  ASSERT (!s->locked);

  msg (D_SEMAPHORE_LOW, "Attempting to lock Win32 semaphore '%s' prior to net shell command (timeout = %d sec)",
       s->name,
       timeout_milliseconds / 1000);
  status = WaitForSingleObject (s->hand, timeout_milliseconds);
  if (status == WAIT_FAILED)
    msg (M_ERR, "Wait failed on Win32 semaphore '%s'", s->name);
  ret = (status == WAIT_TIMEOUT) ? false : true;
  if (ret)
    {
      msg (D_SEMAPHORE, "Locked Win32 semaphore '%s'", s->name);
      s->locked = true;
    }
  else
    {
      msg (D_SEMAPHORE, "Wait on Win32 semaphore '%s' timed out after %d milliseconds",
	   s->name,
	   timeout_milliseconds);
    }
  return ret;
}

void
semaphore_release (struct semaphore *s)
{
  ASSERT (s->hand);
  ASSERT (s->locked);
  msg (D_SEMAPHORE, "Releasing Win32 semaphore '%s'", s->name);
  if (!ReleaseSemaphore(s->hand, 1, NULL))
    msg (M_WARN | M_ERRNO, "ReleaseSemaphore failed on Win32 semaphore '%s'",
	 s->name);
  s->locked = false;
}

void
semaphore_close (struct semaphore *s)
{
  if (s->hand)
    {
      if (s->locked)
	semaphore_release (s);
      msg (D_SEMAPHORE, "Closing Win32 semaphore '%s'", s->name);
      CloseHandle (s->hand);
      s->hand = NULL;
    }
}

/*
 * Special global semaphore used to protect network
 * shell commands from simultaneous instantiation.
 */

struct semaphore netcmd_semaphore;

void
netcmd_semaphore_init (void)
{
  semaphore_open (&netcmd_semaphore, PACKAGE "_netcmd");
}

void
netcmd_semaphore_close (void)
{
  semaphore_close (&netcmd_semaphore);
}

void
netcmd_semaphore_lock (void)
{
  const int timeout_seconds = 600;
  if (!semaphore_lock (&netcmd_semaphore, timeout_seconds * 1000))
    msg (M_FATAL, "Cannot lock net command semaphore"); 
}

void
netcmd_semaphore_release (void)
{
  semaphore_release (&netcmd_semaphore);
}

/* get password from console */

char *
getpass (const char *prompt)
{
  static char input[256];
  HANDLE in;
  HANDLE err;
  DWORD  count;

  input[0] = '\0';

  in = GetStdHandle (STD_INPUT_HANDLE);
  err = GetStdHandle (STD_ERROR_HANDLE);

  if (in == INVALID_HANDLE_VALUE || err == INVALID_HANDLE_VALUE)
    return NULL;

  if (WriteFile (err, prompt, strlen (prompt), &count, NULL))
    {
      int istty = (GetFileType (in) == FILE_TYPE_CHAR);
      DWORD old_flags;
      int rc;

      if (istty)
	{
	  if (GetConsoleMode (in, &old_flags))
	    SetConsoleMode (in, ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
	  else
	    istty = 0;
	}
      rc = ReadFile (in, input, sizeof (input), &count, NULL);
      if (count >= 2 && input[count - 2] == '\r')
	input[count - 2] = '\0';
      else
	{
	  /* deplete excess input */
	  char buf[256];
	  while (ReadFile (in, buf, sizeof (buf), &count, NULL) > 0)
	    if (count >= 2 && buf[count - 2] == '\r')
	      break;
	}
      WriteFile (err, "\r\n", 2, &count, NULL);
      if (istty)
	SetConsoleMode (in, old_flags);
      if (rc)
	return input;
    }

  return NULL;
}

#endif
