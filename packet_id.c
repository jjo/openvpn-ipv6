/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
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
 * These routines are designed to catch replay attacks,
 * where a man-in-the-middle captures packets and then
 * attempts to replay them back later.
 *
 * We use the "sliding-window" algorithm, similar
 * to IPSec.
 */

#include "config.h"

#ifdef USE_CRYPTO

#include "syshead.h"

#include "packet_id.h"
#include "misc.h"

#include "memdbg.h"

void
packet_id_add (struct packet_id_rec *p, const struct packet_id_net *pin)
{
  packet_id_type diff;

  /*
   * If time value increases, start a new
   * sequence number sequence.
   */
  if (!CIRC_LIST_SIZE (p->id_list)
      || pin->time > p->time
      || (pin->id >= PACKET_BACKTRACK_MAX
	  && pin->id - PACKET_BACKTRACK_MAX > p->id))
    {
      p->time = pin->time;
      p->id = 0;
      if (pin->id > PACKET_BACKTRACK_MAX)
	p->id = pin->id - PACKET_BACKTRACK_MAX;
      CLEAR (p->id_list);
    }

  while (p->id < pin->id)
    {
      CIRC_LIST_PUSH (p->id_list, false);
      ++p->id;
    }

  diff = p->id - pin->id;
  if (diff < (packet_id_type) CIRC_LIST_SIZE (p->id_list))
    CIRC_LIST_ITEM (p->id_list, diff) = true;
}

/*
 * Return true if packet id is ok, or false if
 * it is a replay.
 */
bool
packet_id_test (const struct packet_id_rec *p, const struct packet_id_net *pin)
{
  packet_id_type diff;

  msg (D_PID_DEBUG,
       "PID TEST " time_format ":" packet_id_format " " time_format ":" packet_id_format "",
       (time_type)p->time, (packet_id_print_type)p->id, (time_type)pin->time,
       (packet_id_print_type)pin->id);

  if (!pin->id)
    return false;

  if (pin->time == p->time)
    {
      /* is packet-id greater than any one we've seen yet? */
      if (pin->id > p->id)
	return true;

      /* check packet-id sliding window for original/replay status */
      diff = p->id - pin->id;
      if (diff >= (packet_id_type) CIRC_LIST_SIZE (p->id_list))
	return false;

      return !CIRC_LIST_ITEM (p->id_list, diff);
    }
  else if (pin->time < p->time) /* if time goes back, reject */
    return false;
  else                          /* time moved forward */
    return true;
}

const char*
packet_id_net_print (const struct packet_id_net *pin, bool print_timestamp)
{
  struct buffer out = alloc_buf_gc (256);

  buf_printf (&out, "[ #" packet_id_format, (packet_id_print_type)pin->id);
  if (print_timestamp && pin->time)
      buf_printf (&out, " / time = (" packet_id_format ") %s", (packet_id_print_type)pin->time, time_string (pin->time));

  buf_printf (&out, " ]");
  return BSTR (&out);
}

/* initialize the packet_id_persist structure in a disabled state */
void
packet_id_persist_init (struct packet_id_persist *p)
{
  p->filename = NULL;
  p->fd = -1;
  p->time = p->time_last_written = 0;
  p->id = p->id_last_written = 0;
  p->last_flush = 0;
}

/* close the file descriptor if it is open, and switch to disabled state */
void
packet_id_persist_close (struct packet_id_persist *p)
{
  if (packet_id_persist_enabled (p))
    {
      if (close (p->fd))
	msg (D_PID_PERSIST | M_ERRNO, "Close error on --replay-persist file %s", p->filename);
      packet_id_persist_init (p);
    }
}

/* load persisted rec packet_id (time and id) only once from file, and set state to enabled */
void
packet_id_persist_load (struct packet_id_persist *p, const char *filename)
{
  if (!packet_id_persist_enabled (p))
    {
      /* open packet-id persist file for both read and write */
      p->fd = open (filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
      if (p->fd == -1)
	{
	  msg (D_PID_PERSIST | M_ERRNO,
	       "Cannot open --replay-persist file %s for read/write",
	       filename);
	}
      else
	{
	  struct packet_id_persist_file_image image;
	  ssize_t n;

#if defined(HAVE_FLOCK) && defined(LOCK_EX) && defined(LOCK_NB)
	  if (flock (p->fd, LOCK_EX | LOCK_NB))
	    msg (M_ERR, "Cannot obtain exclusive lock on --replay-persist file %s", filename);
#endif

	  p->filename = filename;
	  n = read (p->fd, &image, sizeof(image));
	  if (n == sizeof(image))
	    {
	      p->time = p->time_last_written = image.time;
	      p->id = p->id_last_written = image.id;
	      msg (D_PID_PERSIST_DEBUG, "PID Persist Read from %s: %s",
		   p->filename, packet_id_persist_print(p));
	    }
	  else if (n == -1)
	    {
	      msg (D_PID_PERSIST | M_ERRNO,
		   "Read error on --replay-persist file %s",
		   p->filename);
	    }
	}
    }
}

/* save persisted rec packet_id (time and id) to file (only if enabled state) */
void
packet_id_persist_save (struct packet_id_persist *p)
{
  if (packet_id_persist_enabled (p) && p->time && (p->time != p->time_last_written ||
						   p->id != p->id_last_written))
    {
      struct packet_id_persist_file_image image;
      ssize_t n;
      off_t seek_ret;

      image.time = p->time;
      image.id = p->id;
      seek_ret = lseek(p->fd, (off_t)0, SEEK_SET);
      if (seek_ret == (off_t)0)
	{
	  n = write(p->fd, &image, sizeof(image));
	  if (n == sizeof(image))
	    {
	      p->time_last_written = p->time;
	      p->id_last_written = p->id;
	      msg (D_PID_PERSIST_DEBUG, "PID Persist Write to %s: %s",
		   p->filename, packet_id_persist_print(p));
	    }
	  else
	    {
	      msg (D_PID_PERSIST | M_ERRNO,
		   "Cannot write to --replay-persist file %s",
		   p->filename);
	    }
	}
      else
	{
	  msg (D_PID_PERSIST | M_ERRNO,
	       "Cannot seek to beginning of --replay-persist file %s",
	       p->filename);
	}
    }
}

/* transfer packet_id_persist -> packet_id */
void
packet_id_persist_load_obj (const struct packet_id_persist *p, struct packet_id *pid)
{
  if (p && pid && packet_id_persist_enabled (p) && p->time)
    {
      pid->rec.time = p->time;
      pid->rec.id = p->id;
    }
}

const char*
packet_id_persist_print (const struct packet_id_persist *p)
{
  struct buffer out = alloc_buf_gc (256);

  buf_printf (&out, "[");

  if (packet_id_persist_enabled (p))
    {
      buf_printf (&out, " #" packet_id_format, (packet_id_print_type)p->id);
      if (p->time)
	buf_printf (&out, " / time = (" packet_id_format ") %s", (packet_id_print_type)p->time, time_string (p->time));
    }

  buf_printf (&out, " ]");
  return (char *)out.data;
}

#ifdef PID_TEST

void packet_id_interactive_test ()
{
  struct packet_id_rec p;
  struct packet_id_send s;
  struct packet_id_net pin;
  bool long_form;
  bool count = 0;
  bool test;

  CLEAR (p);
  CLEAR (s);
  while (true) {
    char buf[80];
    if (!fgets(buf, sizeof(buf), stdin))
      break;
    if (sscanf (buf, "%u,%u", &pin.time, &pin.id) == 2)
      {
	test = packet_id_test (&p, &pin);
	printf ("packet_id_test (" packet_id_format ", " packet_id_format ") returned %d\n",
		pin.time,
		pin.id,
		test);
	if (test)
	  packet_id_add (&p, &pin);
      }
    else
      {
	long_form = (count < 20);
	packet_id_alloc_outgoing (&s, &pin, long_form);
	printf ("(" time_format "(" packet_id_format "), " time_format "(" packet_id_format "), %d)\n",
		pin.time,
		pin.time,
		pin.id,
		pin.id,
		long_form);
	if (s.id == 10)
	  s.id = 0xFFFFFFF8;
	++count;
      }
  }
}
#endif

#endif /* USE_CRYPTO */
