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
 */

#include "config.h"

#ifdef USE_CRYPTO

#include "packet_id.h"

#include "memdbg.h"

void
packet_id_add (struct packet_id_rec *p, packet_id_type id)
{
  int i;
  packet_id_type diff;

  while (p->id < id)
    {
      CIRC_LIST_PUSH (p->id_list, false);
      ++p->id;
    }
  diff = p->id - id;
  if (diff < CIRC_LIST_SIZE (p->id_list))
    CIRC_LIST_ITEM (p->id_list, diff) = true;
}

/*
 * Return true if packet id is ok, or false if
 * it is a replay.
 */
bool
packet_id_test (const struct packet_id_rec *p, packet_id_type id)
{
  packet_id_type diff;

  /* replay test */

  if (id > p->id)
    return true;

  diff = p->id - id;
  if (diff >= CIRC_LIST_SIZE (p->id_list))
    return false;

  return !CIRC_LIST_ITEM (p->id_list, diff);
}

#endif /* USE_CRYPTO */
