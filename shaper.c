/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for TLS-based
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

#include "config.h"
#include "syshead.h"
#include "common.h"
#include "error.h"
#include "shaper.h"
#include "memdbg.h"

void
shaper_init (struct shaper *s, int bytes_per_second)
{
  s->bytes_per_second = bytes_per_second;
  CLEAR (s->wakeup);
  msg (M_INFO, "Output Traffic Shaping initialized at %d bytes per second", bytes_per_second);
}

/*
 * Returns traffic shaping delay in microseconds relative to current
 * time, or 0 if no delay.
 */
int
shaper_delay (struct shaper* s)
{
  struct timeval tv;
  int delay = 0;

  if (s->wakeup.tv_sec || s->wakeup.tv_usec)
    {
      if (gettimeofday (&tv, NULL))
	msg (M_ERR, "call to gettimeofday for traffic shaping failed");
      if (s->wakeup.tv_sec < tv.tv_sec)
	{
	  s->wakeup.tv_sec = 0;
	  s->wakeup.tv_usec = 0;
	}
      else if (s->wakeup.tv_sec <= tv.tv_sec + (MAX_TIMEOUT * 1000000))
	{
	  const int secdiff = (int) s->wakeup.tv_sec - tv.tv_sec;
	  delay = (int) s->wakeup.tv_usec - tv.tv_usec;
	  if (secdiff == 1)
	    delay += 1000000;
	  else if (secdiff > 1)
	    delay += secdiff * 1000000;
	}
      else
	{
	  delay = MAX_TIMEOUT * 1000000;
	}
      msg (D_SHAPER, "shaper_delay delay=%d", delay);
    }
  return delay > 0 ? delay : 0;
}

/*
 * We want to wake up in delay microseconds.  If timeval is 0 (undefined) or larger
 * than delay, set timeval to delay.
 */
void
shaper_soonest_event (struct timeval *tv, int delay)
{
  if (!tv->tv_usec && delay < 1000000)
    {
      tv->tv_usec = delay;
      tv->tv_sec = 0;
    }
  else
    {
      const int sec = delay / 1000000;
      const int usec = delay % 1000000;

      if ((!tv->tv_sec && !tv->tv_usec) || (sec < tv->tv_sec))
	{
	  tv->tv_sec = sec;
	  tv->tv_usec = usec;
	}
      else if (sec == tv->tv_sec)
	{
	  if (usec < tv->tv_usec)
	    {
	      tv->tv_usec = usec;
	    }
	}
    }
  msg (D_SHAPER, "shaper_soonest_event sec=%d usec=%d",
       tv->tv_sec, tv->tv_usec);
}

/*
 * We are about to send a datagram of nbytes bytes.
 *
 * Compute when we can send another datagram,
 * based on target throughput (s->bytes_per_second).
 */
void
shaper_wrote_bytes (struct shaper* s, int nbytes)
{
  const int delay = (1000000 / s->bytes_per_second) * nbytes; /* delay in microseconds */
  
  if (gettimeofday (&s->wakeup, NULL))
    msg (M_ERR, "call to gettimeofday for traffic shaping failed");
  s->wakeup.tv_usec += delay;
  while (s->wakeup.tv_usec >= 1000000)
    {
      ++s->wakeup.tv_sec;
      s->wakeup.tv_usec -= 1000000;
    }
  msg (D_SHAPER, "shaper_wrote_bytes bytes=%d delay=%d sec=%d usec=%d",
       nbytes, delay, s->wakeup.tv_sec, s->wakeup.tv_usec);
}
