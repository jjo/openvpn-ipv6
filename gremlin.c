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

/*
 * Test protocol robustness by simulating dropped packets and
 * network outages when the --gremlin option is enabled.
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "error.h"
#include "common.h"
#include "misc.h"
#include "gremlin.h"

#include "memdbg.h"

#if 1

#define CORRUPT_ENABLE
#define UP_DOWN_ENABLE
#define DROP_ENABLE

/*
 * Probability that we will drop a packet is 1 / DROP_FREQ
 */
#define DROP_FREQ 50

/*
 * Probability that we will corrupt a packet is 1 / CORRUPT_FREQ
 */
#define CORRUPT_FREQ 50

/*
 * When network goes up, it will be up for between
 * UP_LOW and UP_HIGH seconds.
 */
#define UP_LOW    10
#define UP_HIGH   300

/*
 * When network goes down, it will be down for between
 * DOWN_LOW and DOWN_HIGH seconds.
 */
#define DOWN_LOW  10
#define DOWN_HIGH 60

#else

#define CORRUPT_ENABLE
#define CORRUPT_FREQ 10

#endif

/*
 * Return true with probability 1/n
 */
static bool flip(int n) {
  return (get_random() % n) == 0;
}

/*
 * Return uniformly distributed random number between
 * low and high.
 */
static int roll(int low, int high) {
  int ret;
  ASSERT (low <= high);
  ret = low + (get_random() % (high - low + 1));
  ASSERT (ret >= low && ret <= high);
  return ret;
}

static bool initialized;
static bool up;
static time_t next;

/*
 * Return false if we should drop a packet.
 */
bool
ask_gremlin(void)
{
  const time_t current = time (NULL);

  if (!initialized)
    {
      initialized = true;
#ifdef UP_DOWN_ENABLE
      up = false;
#else
      up = true;
#endif
      next = current;
    }

#ifdef UP_DOWN_ENABLE
/* change up/down state? */
  if (current >= next)
    {
      int delta;
      if (up)
	{
	  delta = roll (DOWN_LOW, DOWN_HIGH);
	  up = false;
	}
      else
	{
	  delta = roll (UP_LOW, UP_HIGH);
	  up = true;
	}
      
      msg (D_GREMLIN,
	   "GREMLIN: CONNECTION GOING %s FOR %d SECONDS",
	   (up ? "UP" : "DOWN"),
	   delta);
      next = current + delta;
    }
#endif

#ifdef DROP_ENABLE
  if (up && flip (DROP_FREQ))
    {
      msg (D_GREMLIN_VERBOSE, "GREMLIN: Random packet drop");
      return false;
    }
#endif

  return up;
}

/*
 * Possibly corrupt a packet.
 */
void corrupt_gremlin(struct buffer* buf) {
#ifdef CORRUPT_ENABLE
  if (flip (CORRUPT_FREQ))
    {
      do
	{
	  if (buf->len > 0)
	    {
	      uint8_t r = roll (0, 255);
	      int method = roll (0, 5);

	      switch (method) {
	      case 0: /* corrupt the first byte */
		*BPTR (buf) = r;
		break;
	      case 1: /* corrupt the last byte */
		*(BPTR (buf) + buf->len - 1) = r;
		break;
	      case 2: /* corrupt a random byte */
		*(BPTR(buf) + roll (0, buf->len - 1)) = r;
		break;
	      case 3: /* append a random byte */
		buf_write (buf, &r, 1);
		break;
	      case 4: /* reduce length by 1 */
		--buf->len;
		break;
	      case 5: /* reduce length by a random amount */
		buf->len -= roll (0, buf->len - 1);
		break;
	      }
	      msg (D_GREMLIN_VERBOSE, "GREMLIN: Packet Corruption, method=%d", method);
	    }
	  else
	    break;
	} while (flip (2)); /* a 50% chance we will corrupt again */
    }
#endif
}
