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
 * These routines are designed to optimize the calling of a routine
 * (normally used for tls_multi_process())
 * which can be called less frequently between triggers.
 *
 * We won't optimize if we are within I_HORIZON seconds
 * of a trigger.
 *
 * If we are optimizing, we will call routine at least once
 * per I_REFRESH seconds.
 */

#ifndef INTERVAL_H
#define INTERVAL_H

#include "error.h"
#include "misc.h"

/*
 * Used to determine in how many seconds we should be
 * called again.
 */
static inline void
interval_earliest_wakeup (interval_t *wakeup, time_t at, time_t current) {
  if (at > current)
    {
      const interval_t delta = at - current;
      if (!*wakeup || delta < *wakeup)
	*wakeup = delta;
    }
}

/*
 * Designed to limit calls to expensive functions that need to be called
 * regularly.
 */

struct interval
{
  interval_t refresh;
  interval_t horizon;
  time_t future_trigger;
  time_t last_action;
  time_t last_test_true;
};

static inline void
interval_init (struct interval *top, int horizon, int refresh)
{
  CLEAR (*top);
  top->refresh = refresh;
  top->horizon = horizon;
}

/*
 * IF
 *   last_action less than horizon seconds ago
 *   OR last_test_true more than refresh seconds ago
 *   OR hit future_trigger
 * THEN
 *   return true
 * ELSE
 *   set wakeup to the number of seconds until a true return
 *   return false
 */

static inline bool
interval_test (struct interval* top, time_t current)
{
  bool trigger = false;


  if (top->future_trigger && current >= top->future_trigger)
    {
      trigger = true;
      top->future_trigger = 0;
    }

  if (top->last_action + top->horizon > current ||
      top->last_test_true + top->refresh <= current ||
      trigger)
    {
      top->last_test_true = current;
      msg (D_INTERVAL, "INTERVAL interval_test true");
      return true;
    }
  else
    {
      return false;
    }
}

static inline void
interval_schedule_wakeup (struct interval* top, time_t current, interval_t *wakeup)
{
  interval_earliest_wakeup (wakeup, top->last_test_true + top->refresh, current);
  interval_earliest_wakeup (wakeup, top->future_trigger, current);
  msg (D_INTERVAL, "INTERVAL interval_schedule wakeup=%d", (int)*wakeup);
}

/*
 * In wakeup seconds, interval_test will return true once.
 */
static inline void
interval_future_trigger (struct interval* top, interval_t wakeup, time_t current) {
  if (wakeup)
    {
      msg (D_INTERVAL, "INTERVAL interval_future_trigger %d", (int)wakeup);
      top->future_trigger = current + wakeup;
    }
}

/*
 * Once an action is triggered, interval_test will remain true for
 * horizon seconds.
 */
static inline void
interval_action (struct interval* top, time_t current)
{
  msg (D_INTERVAL, "INTERVAL action");
  top->last_action = current;
}

/*
 * Measure when n seconds past an event have elapsed
 */

struct event_timeout
{
  interval_t n;
  time_t last; /* time of last event */
};

static inline void
event_timeout_init (struct event_timeout* et, time_t current, interval_t n)
{
  et->n = n;
  et->last = current;
}

static inline void
event_timeout_reset (struct event_timeout* et, time_t current)
{
  et->last = current;
}

static inline bool
event_timeout_trigger (struct event_timeout* et, time_t current)
{
  if (et->n && et->last + et->n <= current)
    {
      msg (D_INTERVAL, "EVENT event_timeout_trigger (%d)", et->n);
      et->last = current;
      return true;
    }
  return false;
}

static inline void
event_timeout_wakeup (struct event_timeout* et, time_t current, struct timeval* tv)
{
  if (et->n)
    {
      const int wakeup = et->last + et->n - current;
      if (wakeup > 0 && (!tv->tv_sec || wakeup < tv->tv_sec))
	{
	  msg (D_INTERVAL, "EVENT event_timeout_wakeup (%d/%d)", wakeup, et->n);
	  tv->tv_sec = wakeup;
	}
    }
}

/*
 * Measure time intervals in microseconds
 */

#define USEC_TIMER_MAX      60 /* maximum interval size in seconds */

#define USEC_TIMER_MAX_USEC (USEC_TIMER_MAX * 1000000)

struct usec_timer {
  struct timeval start;
  struct timeval end;
};

static inline void
usec_timer_start (struct usec_timer *obj)
{
  CLEAR (*obj);
  gettimeofday (&obj->start, NULL);
}

static inline void
usec_timer_end (struct usec_timer *obj)
{
  gettimeofday (&obj->end, NULL);
}

static inline bool
usec_timer_interval_defined (struct usec_timer *obj)
{
  return obj->start.tv_sec && obj->end.tv_sec;
}

static inline int
usec_timer_interval (struct usec_timer *obj)
{
  return tv_subtract (&obj->end, &obj->start, USEC_TIMER_MAX);
}

#endif /* INTERVAL_H */
