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
  if (diff < CIRC_LIST_SIZE (p->id_list))
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

  if (!pin->id)
    return false;

  if (pin->time == p->time)
    {
      /* is packet-id greater than any one we've seen yet? */
      if (pin->id > p->id)
	return true;

      /* check packet-id sliding window for original/replay status */
      diff = p->id - pin->id;
      if (diff >= CIRC_LIST_SIZE (p->id_list))
	return false;

      return !CIRC_LIST_ITEM (p->id_list, diff);
    }
  else if (pin->time < p->time) /* if time goes back, reject */
    return false;
  else                          /* time moved forward */
    return true;
}

const char*
packet_id_net_print (const struct packet_id_net *pin)
{
  struct buffer out = alloc_buf_gc (256);
  
  buf_printf (&out, "[ #" packet_id_format, pin->id);
  if (pin->time)
    {
      buf_printf (&out, " / %s", ctime (&pin->time));
      if (*BLAST (&out) =='\n')
	--out.len;
    }

  buf_printf (&out, " ]");
  return out.data;
}

//#ifdef PID_TEST
#if 1

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
