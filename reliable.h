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
 * This routines implement a reliability layer on top of UDP,
 * so that TLS can be run over UDP.
 */

#if defined(USE_CRYPTO) && defined(USE_SSL)

#ifndef RELIABLE_H
#define RELIABLE_H

#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "session_id.h"

#define RELIABLE_ACK_SIZE 8

struct reliable_ack
{
  int len;
  packet_id_type packet_id[RELIABLE_ACK_SIZE];
};

/* no active buffers? */
static inline bool
reliable_ack_empty (struct reliable_ack *ack)
{
  return !ack->len;
}

/* add the packet ID of buf to ack, advance buf ptr, and return packet ID */
packet_id_type reliable_ack_read_packet_id (struct reliable_ack *ack,
					   struct buffer *buf);

/* read a packet ID acknowledgement record from buf */
bool
reliable_ack_read (struct reliable_ack *ack,
		   struct buffer *buf, const struct session_id *sid);

/* write a packet ID acknowledgement record to buf */
bool
reliable_ack_write (struct reliable_ack *ack,
		    struct buffer *buf,
		    const struct session_id *sid, int max, bool prepend);

/* print a reliable ACK record coming off the wire */
const char *reliable_ack_print(struct buffer* buf);

/* add to extra_frame the maximum number of bytes we will need for reliable_ack_write */
void reliable_ack_adjust_frame_parameters (struct frame* frame, int max);

void reliable_ack_debug_print (const struct reliable_ack *ack, char *desc);

#define RELIABLE_SIZE 8

struct reliable_entry
{
  bool active;
  time_t next_try;
  packet_id_type packet_id;
  int opcode;
  struct buffer buf;
};

struct reliable
{
  int timeout;
  packet_id_type packet_id;
  time_t current;
  int offset;
  struct reliable_entry array[RELIABLE_SIZE];
};

void reliable_debug_print (const struct reliable *rel, char *desc);

/* set sending timeout (after this time we send again until ACK) */
static inline void
reliable_set_timeout (struct reliable *rel, int timeout)
{
  rel->timeout = timeout;
}

static inline void
reliable_set_current_time (struct reliable *rel, time_t current)
{
  rel->current = current;
}

void reliable_init (struct reliable *rel, int size, int offset);

void reliable_free (struct reliable *rel);

/* no active buffers? */
bool reliable_empty (const struct reliable *rel);

/* in how many seconds should we wake up to check for timeout */
int reliable_send_timeout (const struct reliable *rel);

/* del acknowledged items from send buf */
void reliable_send_purge (struct reliable *rel, struct reliable_ack *ack);

/* true if at least one free buffer available */
bool reliable_can_get (const struct reliable *rel);

/* grab a free buffer */
struct buffer *reliable_get_buf (struct reliable *rel);

/* get active buffer for next sequentially increasing key ID */
struct buffer *reliable_get_buf_sequenced (struct reliable *rel);

/* return true if reliable_send would return a non-NULL result */
bool reliable_can_send (const struct reliable *rel);

/* return next buffer to send to remote */
struct buffer *reliable_send (struct reliable *rel, int *opcode);

/* schedule all pending packets for immediate retransmit */
void reliable_schedule_now (struct reliable *rel);

/* enable a buffer previously returned by a get function as active */
void reliable_mark_active (struct reliable *rel, struct buffer *buf, int pid, int opcode);

/* delete a buffer previously activated by reliable_mark_active() */
void reliable_mark_deleted (struct reliable *rel, struct buffer *buf, bool inc_pid);

#endif /* RELIABLE_H */
#endif /* USE_CRYPTO && USE_SSL */
