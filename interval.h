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
 * per I_INTERVAL seconds.
 */

/* TLS time constants */

#define TLS_MULTI_REFRESH 15    /* seconds */
#define TLS_MULTI_HORIZON 60    /* seconds */

/*
 * Interval test is true at least once per n seconds.
 */
#define I_INTERVAL TLS_MULTI_REFRESH

/*
 * Seconds after last trigger or before next timeout,
 */
#define I_HORIZON  TLS_MULTI_HORIZON

struct interval
{
  time_t last_trigger;
  time_t last_call;
  bool select_timeout;
};

static inline bool
interval_test (struct interval* top, time_t current)
{
  if (top->last_trigger + I_HORIZON < current &&
      !(top->select_timeout || top->last_call + I_INTERVAL < current))
    return false;

  msg (D_TLS_DEBUG, "INTERVAL TEST SUCCEEDED");
  top->select_timeout = false;
  top->last_call = current;
  return true;
}

static inline void
interval_trigger (struct interval* top, time_t at) {
  msg (D_TLS_DEBUG, "INTERVAL TRIGGER");
  top->last_trigger = at;
}

static inline void
interval_select_timeout (struct interval* top) {
  top->select_timeout = true;
}

static inline void
interval_set_timeout (struct interval* top, time_t current, time_t* timeout) {
  const int to = *timeout;
  if (to && to < I_HORIZON)
    interval_trigger (top, current + to);
  if (!to || to > I_INTERVAL)
    *timeout = I_INTERVAL;
}

/*
 * Measure when n seconds past an event have elapsed
 */

struct event_timeout
{
  int n;
  time_t last; /* time of last event */
};

static inline void
event_timeout_init (struct event_timeout* et, time_t current, int n)
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
      msg (D_TLS_DEBUG, "ELAPSED TRIGGER (%d)", et->n);
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
	  msg (D_TLS_DEBUG, "ELAPSED SOONEST (%d/%d)", wakeup, et->n);
	  tv->tv_sec = wakeup;
	}
    }
}
