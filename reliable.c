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
 * These routines implement a reliability layer on top of UDP,
 * so that SSL/TLS can be run over UDP.
 */

#include "config.h"

#if defined(USE_CRYPTO) && defined(USE_SSL)

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "common.h"
#include "reliable.h"

#include "memdbg.h"

/* add the packet ID of buf to ack, advance buf ptr, and return packet ID */
packet_id_type
reliable_ack_read_packet_id (struct reliable_ack *ack, struct buffer *buf)
{
  packet_id_type net_pid;
  packet_id_type ret = -1;

  if (buf_read (buf, &net_pid, sizeof (net_pid)))
    {
      if (ack->len < RELIABLE_ACK_SIZE)
	ret = ack->packet_id[ack->len++] = ntohpid (net_pid);
    }

  msg (D_REL_DEBUG, "ACK ID %d (buf->len=%d, ack->len=%d)", ret, buf->len,
       ack->len);
  return ret;
}

/* read a packet ID acknowledgement record from buf into ack */
bool
reliable_ack_read (struct reliable_ack * ack,
		   struct buffer * buf, const struct session_id * sid)
{
  int i;
  unsigned char count;
  packet_id_type net_pid;
  packet_id_type pid;
  struct session_id session_id_remote;

  if (!buf_read (buf, &count, sizeof (count)))
    goto error;
  for (i = 0; i < count; ++i)
    {
      if (!buf_read (buf, &net_pid, sizeof (net_pid)))
	goto error;
      if (ack->len >= RELIABLE_ACK_SIZE)
	goto error;
      pid = ntohpid (net_pid);
      ack->packet_id[ack->len++] = pid;
    }
  if (count)
    {
      if (!session_id_read (&session_id_remote, buf))
	goto error;
      if (!session_id_defined (&session_id_remote) ||
	  !session_id_equal (&session_id_remote, sid))
	{
	  msg (D_REL_DEBUG,
	       "ACK read BAD SESSION-ID FROM REMOTE, local=%s, remote=%s",
	       session_id_print (sid), session_id_print (&session_id_remote));
	  goto error;
	}
    }
  return true;

error:
  return false;
}

#define ACK_SIZE(n) (sizeof (unsigned char) + ((n) ? SID_SIZE : 0) + sizeof (packet_id_type) * (n))

/* write a packet ID acknowledgement record to buf, */
/* removing all acknowledged entries from ack */
bool
reliable_ack_write (struct reliable_ack * ack,
		    struct buffer * buf,
		    const struct session_id * sid, int max, bool prepend)
{
  int i, j;
  unsigned char n;
  struct buffer sub;

  n = ack->len;
  if (n > max)
    n = max;
  sub = buf_sub (buf, ACK_SIZE(n), prepend);
  if (!BDEF (&sub))
    goto error;
  ASSERT (buf_write (&sub, &n, sizeof (n)));
  for (i = 0; i < n; ++i)
    {
      packet_id_type pid = ack->packet_id[i];
      packet_id_type net_pid = htonpid (pid);
      ASSERT (buf_write (&sub, &net_pid, sizeof (net_pid)));
      msg (D_REL_DEBUG, "ACK write %u (ack->len=%d, n=%d)", pid, ack->len, n);
    }
  if (n)
    {
      ASSERT (session_id_defined (sid));
      ASSERT (session_id_write (sid, &sub));
      for (i = 0, j = n; j < ack->len;)
	ack->packet_id[i++] = ack->packet_id[j++];
      ack->len = i;
    }

  return true;

error:
  return false;
}

/* add to extra_frame the maximum number of bytes we will need for reliable_ack_write */
void
reliable_ack_adjust_frame_parameters (struct frame* frame, int max)
{
  frame->extra_frame += ACK_SIZE(max);
}

/* print a reliable ACK record coming off the wire */
const char*
reliable_ack_print(struct buffer* buf)
{
  int i;
  unsigned char n_ack;
  struct session_id sid_ack;
  packet_id_type pid;
  struct buffer out = alloc_buf_gc (256);

  buf_printf (&out, "[");
  if (!buf_read (buf, &n_ack, sizeof (n_ack)))
    goto done;
  for (i = 0; i < n_ack; ++i)
    {
      if (!buf_read (buf, &pid, sizeof (pid)))
	goto done;
      pid = ntohpid (pid);
      buf_printf (&out, " %u", pid);
    }
  if (n_ack)
    {
      if (!session_id_read (&sid_ack, buf))
	goto done;
      buf_printf (&out, " sid=%s", session_id_print (&sid_ack));
    }

 done:
  buf_printf (&out, " ]");
  return out.data;
}

/*
 * struct reliable member functions.
 */

void
reliable_init (struct reliable *rel, int size, int offset)
{
  int i;

  CLEAR (*rel);
  rel->offset = offset;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      e->buf = alloc_buf (size);
      ASSERT (buf_init (&e->buf, offset));
    }
}

void
reliable_free (struct reliable *rel)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      free_buf (&e->buf);
    }
}

/* no active buffers? */
bool
reliable_empty (const struct reliable *rel)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      const struct reliable_entry *e = &rel->array[i];
      if (e->active)
	return false;
    }
  return true;
}

/* in how many seconds should we wake up to check for timeout */
/* if we return 0, nothing to wait for */
int
reliable_send_timeout (const struct reliable *rel, time_t current)
{
  int ret = 0;
  int i;

  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      const struct reliable_entry *e = &rel->array[i];
      if (e->active && e->next_try)
	{
	  int wake = e->next_try - current;
	  if (wake < 1)
	    wake = 1;
	  if (!ret || wake < ret)
	    ret = wake;
	}
    }
  return ret;
}

/* del acknowledged items from send buf */
void
reliable_send_purge (struct reliable *rel, struct reliable_ack *ack)
{
  int i, j;
  for (i = 0; i < ack->len; ++i)
    {
      packet_id_type pid = ack->packet_id[i];
      for (j = 0; j < RELIABLE_SIZE; ++j)
	{
	  struct reliable_entry *e = &rel->array[j];
	  if (e->active && e->packet_id == pid)
	    {
	      msg (D_REL_DEBUG, "ACK received for pid %d, deleting from send buffer", pid);
#if 0
	      /* DEBUGGING -- how close were we timing out on ACK failure and resending? */
	      {
		const int wake = e->next_try - time(NULL);
		msg (M_INFO, "ACK %d, wake=%d", pid, wake);
	      }
#endif
	      e->active = false;
	      break;
	    }
	}
    }
}

/* true if at least one free buffer available */
bool
reliable_can_get (const struct reliable *rel)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      const struct reliable_entry *e = &rel->array[i];
      if (!e->active)
	return true;
    }
  return false;
}

/* grab a free buffer */
struct buffer *
reliable_get_buf (struct reliable *rel)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      if (!e->active)
	{
	  ASSERT (buf_init (&e->buf, rel->offset));
	  return &e->buf;
	}
    }
  return NULL;
}

/* get active buffer for next sequentially increasing key ID */
struct buffer *
reliable_get_buf_sequenced (struct reliable *rel)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      if (e->active && e->packet_id == rel->packet_id)
	{
	  return &e->buf;
	}
    }
  return NULL;
}

/* return true if reliable_send would return a non-NULL result */
bool
reliable_can_send (const struct reliable *rel, time_t current)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      const struct reliable_entry *e = &rel->array[i];
      if (e->active && current >= e->next_try)
	return true;
    }
  return false;
}

/* return next buffer to send to remote */
struct buffer *
reliable_send (struct reliable *rel, int *opcode, time_t current)
{
  int i;
  struct reliable_entry *best = NULL;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      if (e->active && current >= e->next_try)
	{
	  if (!best || e->packet_id < best->packet_id)
	    best = e;
	}
    }
  if (best)
    {
      best->next_try = current + rel->timeout;
      *opcode = best->opcode;
      return &best->buf;
    }
  return NULL;
}

/* schedule all pending packets for immediate retransmit */
void
reliable_schedule_now (struct reliable *rel, time_t current)
{
  int i;
  msg (D_REL_DEBUG, "reliable_schedule_now");
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      if (e->active)
	e->next_try = current;
    }
}

/* enable a buffer previously returned by a get function as active */
void
reliable_mark_active (struct reliable *rel, struct buffer *buf, int pid, int opcode)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      if (buf == &e->buf)
	{
	  /* Read mode, packets may not arrive in sequential order */
	  if (pid >= 0)
	    {
	      e->packet_id = pid;

	      /* throw away old, previously received packets */
	      e->active = (pid >= rel->packet_id);
	    }
	  else
	    {
	      /* Write mode, increment packet_id (i.e. sequence number)
		 linearly and prepend id to packet */
	      packet_id_type net_pid;
	      e->packet_id = rel->packet_id++;
	      net_pid = htonpid (e->packet_id);
	      ASSERT (buf_write_prepend (buf, &net_pid, sizeof (net_pid)));
	      e->active = true;
	    }
	  e->opcode = opcode;
	  e->next_try = 0;
	  msg (D_REL_DEBUG, "ACK Mark Active ID %d", e->packet_id);
	  return;
	}
    }
  ASSERT (0);			/* buf not found in rel */
}

/* delete a buffer previously activated by reliable_mark_active() */
void
reliable_mark_deleted (struct reliable *rel, struct buffer *buf, bool inc_pid)
{
  int i;
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      struct reliable_entry *e = &rel->array[i];
      if (buf == &e->buf)
	{
	  e->active = false;
	  if (inc_pid)
	    rel->packet_id = e->packet_id + 1;
	  return;
	}
    }
  ASSERT (0);
}

#if 0

void
reliable_ack_debug_print (const struct reliable_ack *ack, char *desc)
{
  int i;
  time_t current = time (NULL);

  printf ("********* struct reliable_ack %s\n", desc);
  for (i = 0; i < ack->len; ++i)
    {
      printf ("  %d: %d\n", i, ack->packet_id[i]);
    }
}

void
reliable_debug_print (const struct reliable *rel, char *desc)
{
  int i;
  time_t current = time (NULL);

  printf ("********* struct reliable %s\n", desc);
  printf ("  timeout=%d\n", rel->timeout);
  printf ("  packet_id=%d\n", rel->packet_id);
  printf ("  current=%u\n", current);
  for (i = 0; i < RELIABLE_SIZE; ++i)
    {
      const struct reliable_entry *e = &rel->array[i];
      if (e->active)
	{
	  printf ("  %d: packet_id=%d len=%d", i, e->packet_id, e->buf.len);
	  printf (" next_try=%u", e->next_try);
	  printf ("\n");
	}
    }
}

#endif

#endif /* USE_CRYPTO && USE_SSL*/
