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

#if defined(USE_CRYPTO) && defined(USE_SSL)

/*
 * Interval test is true at least once per n seconds.
 */
#define I_INTERVAL 15

/*
 * Seconds after last trigger or before next timeout,
 */
#define I_HORIZON 60

struct interval {
  time_t last_trigger;
  time_t last_call;
  bool select_timeout;
};

static inline interval_test(struct interval* top, time_t current)
{
  if (top->last_trigger + I_HORIZON < current &&
      !(top->select_timeout || top->last_call + I_INTERVAL < current))
    return false;

  msg (D_TLS_DEBUG, "INTERVAL TEST SUCCEEDED");
  top->select_timeout = false;
  top->last_call = current;
  return true;
}

static inline interval_trigger(struct interval* top, time_t at) {
  msg (D_TLS_DEBUG, "INTERVAL TRIGGER");
  top->last_trigger = at;
}

static inline interval_select_timeout(struct interval* top) {
  top->select_timeout = true;
}

static inline interval_set_timeout(struct interval* top, time_t current, time_t* timeout) {
  const int to = *timeout;
  if (to && to < I_HORIZON)
    interval_trigger (top, current + to);
  if (!to || to > I_INTERVAL)
    *timeout = I_INTERVAL;
}

#endif
