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

#ifdef USE_CRYPTO

#ifndef PACKET_ID_H
#define PACKET_ID_H

#include "circ_list.h"
#include "error.h"

/*
 * Routines to catch replay attacks.
 */

typedef unsigned long packet_id_type;

/* convert a packet_id_type to and from network order */
#define htonpid(x) htonl(x)
#define ntohpid(x) ntohl(x)

/*
 * Maximum allowed backtrack in
 * packet ID due to packets arriving
 * out of order.
 */
#define PACKET_BACKTRACK_MAX   1024

CIRC_LIST (pkt_id, char, PACKET_BACKTRACK_MAX);

struct packet_id_rec
{
  packet_id_type id;
  struct pkt_id id_list;
};

struct packet_id_send
{
  packet_id_type id;
};

struct packet_id
{
  struct packet_id_send send;
  struct packet_id_rec rec;
};

void packet_id_add (struct packet_id_rec *p, packet_id_type id);
bool packet_id_test (const struct packet_id_rec *p, packet_id_type id);

static inline packet_id_type
packet_id_get (struct packet_id_send *p)
{
  packet_id_type ret = ++p->id;
  ASSERT (p->id);		/* packet ID wraparound is fatal */
  return ret;
}

static inline bool
packet_id_close_to_wrapping (const struct packet_id_send *p)
{
  return p->id >= 0xF0000000;
}

#endif /* PACKET_ID_H */
#endif /* USE_CRYPTO */
