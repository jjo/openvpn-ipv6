/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifndef SHAPER_H
#define SHAPER_H

#define SHAPER_DEBUG 0

#ifdef HAVE_GETTIMEOFDAY

#include "basic.h"
#include "integer.h"
#include "misc.h"
#include "error.h"

/*
 * A simple traffic shaper for
 * the output direction.
 */

#define SHAPER_MIN 100          /* bytes per second */
#define SHAPER_MAX 100000000

#define SHAPER_MAX_TIMEOUT 10          /* seconds */

struct shaper 
{
  int bytes_per_second;
  struct timeval wakeup;
};

void shaper_msg (struct shaper *s);

/*
 * inline functions
 */

static inline void
shaper_reset (struct shaper *s, int bytes_per_second)
{
  s->bytes_per_second = bytes_per_second ? constrain_int (bytes_per_second, SHAPER_MIN, SHAPER_MAX) : 0;
}

static inline void
shaper_reset_wakeup (struct shaper *s)
{
  CLEAR (s->wakeup);
}

static inline void
shaper_init (struct shaper *s, int bytes_per_second)
{
  shaper_reset (s, bytes_per_second);
  shaper_reset_wakeup (s);
}

static inline int
shaper_current_bandwidth (struct shaper *s)
{
  return s->bytes_per_second;
}

/*
 * Returns traffic shaping delay in microseconds relative to current
 * time, or 0 if no delay.
 */
static inline int
shaper_delay (struct shaper* s)
{
  struct timeval tv;
  int delay = 0;

  if (tv_defined (&s->wakeup))
    {
      ASSERT (!gettimeofday (&tv, NULL));
      delay = tv_subtract (&s->wakeup, &tv, SHAPER_MAX_TIMEOUT);
#if SHAPER_DEBUG
      msg (D_SHAPER_DEBUG, "SHAPER shaper_delay delay=%d", delay);
#endif
    }

  return delay > 0 ? delay : 0;
}

/*
 * We want to wake up in delay microseconds.  If timeval is 0 (undefined) or larger
 * than delay, set timeval to delay.
 */
static inline void
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
#if SHAPER_DEBUG
  msg (D_SHAPER_DEBUG, "SHAPER shaper_soonest_event sec=%d usec=%d",
       (int)tv->tv_sec, (int)tv->tv_usec);
#endif
}

/*
 * We are about to send a datagram of nbytes bytes.
 *
 * Compute when we can send another datagram,
 * based on target throughput (s->bytes_per_second).
 */
static inline void
shaper_wrote_bytes (struct shaper* s, int nbytes)
{
  /* delay in microseconds */
  const int delay = s->bytes_per_second
    ? min_int (((1000000 / s->bytes_per_second) * max_int (nbytes, 200)), (SHAPER_MAX_TIMEOUT*1000000))
    : 0;
  
  if (delay)
    {
      ASSERT (!gettimeofday (&s->wakeup, NULL));
      s->wakeup.tv_usec += delay;
      while (s->wakeup.tv_usec >= 1000000)
	{
	  ++s->wakeup.tv_sec;
	  s->wakeup.tv_usec -= 1000000;
	}
#if SHAPER_DEBUG
      msg (D_SHAPER_DEBUG, "SHAPER shaper_wrote_bytes bytes=%d delay=%d sec=%d usec=%d",
	   nbytes, delay, (int)s->wakeup.tv_sec, (int)s->wakeup.tv_usec);
#endif
    }
}

/*
 * Increase/Decrease bandwidth by a percentage.
 *
 * Return true if bandwidth changed.
 */
static inline bool
shaper_change_pct (struct shaper *s, int pct)
{
  const int orig_bandwidth = s->bytes_per_second;
  const int new_bandwidth = orig_bandwidth + (orig_bandwidth * pct / 100);
  ASSERT (s->bytes_per_second);
  shaper_reset (s, new_bandwidth);
  return s->bytes_per_second != orig_bandwidth;
}

#endif /* HAVE_GETTIMEOFDAY */

#endif
