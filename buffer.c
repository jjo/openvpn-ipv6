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

#include "config.h"

#include "syshead.h"

#include "buffer.h"
#include "error.h"

#include "memdbg.h"

struct buffer
alloc_buf (size_t size)
{
  struct buffer buf;
  buf.capacity = size;
  buf.offset = 0;
  buf.len = 0;
  buf.data = (uint8_t *) malloc (size);
  ASSERT (buf.data);
  if (size)
    *buf.data = 0;
  return buf;
}

struct buffer
alloc_buf_gc (size_t size)
{
  struct buffer buf;
  buf.capacity = size;
  buf.offset = 0;
  buf.len = 0;
  buf.data = (uint8_t *) gc_malloc (size);
  if (size)
    *buf.data = 0;
  return buf;
}

struct buffer
clone_buf (const struct buffer* buf)
{
  struct buffer ret;
  ret.capacity = buf->capacity;
  ret.offset = buf->offset;
  ret.len = buf->len;
  ret.data = (uint8_t *) malloc (buf->capacity);
  ASSERT (ret.data);
  memcpy (BPTR (&ret), BPTR (buf), BLEN (buf));
  return ret;
}

struct buffer
clear_buf ()
{
  struct buffer buf;
  CLEAR (buf);
  return buf;
}

void
free_buf (struct buffer *buf)
{
  if (buf->data)
    free (buf->data);
  CLEAR (*buf);
}

/*
 * Return a buffer for write that is a subset of another buffer
 */
struct buffer
buf_sub (struct buffer *buf, int size, bool prepend)
{
  struct buffer ret;
  uint8_t *data;

  CLEAR (ret);
  data = prepend ? buf_prepend (buf, size) : buf_write_alloc (buf, size);
  if (data)
    {
      ret.capacity = size;
      ret.data = data;
    }
  return ret;
}

/*
 * printf append to a buffer with overflow check
 */
void
buf_printf (struct buffer *buf, char *format, ...)
{
  va_list arglist;

  char *ptr = BEND (buf);
  int cap = buf_forward_capacity (buf);

  va_start (arglist, format);
  vsnprintf (ptr, cap, format, arglist);
  va_end (arglist);

  buf->len += strlen (ptr);
}

/*
 * write a string to the end of a buffer that was
 * truncated by buf_printf
 */
void
buf_catrunc (struct buffer *buf, const char *str)
{
  if (buf_forward_capacity (buf) <= 1)
    {
      int len = strlen (str) + 1;
      if (len < buf_forward_capacity_total (buf))
	{
	  strncpynt (buf->data + buf->capacity - len, str, len);
	}
    }
}

/*
 * Garbage collection
 */

struct gc_thread _gc_thread[N_THREADS];

void *
gc_malloc (size_t size)
{
  struct gc_thread* thread = &_gc_thread[thread_number()];
  size_t s = sizeof (struct gc_entry) + size;
  struct gc_entry *e = (struct gc_entry *) malloc (s);
  ++thread->gc_count;
  ASSERT (e);
  e->level = thread->gc_level;
  e->back = thread->gc_stack;
  thread->gc_stack = e;
  /*printf("GC MALLOC 0x%08zx size=%d lev=%d\n", e, s, e->level); */
  return (void *) e + sizeof (struct gc_entry);
}

void
gc_collect (int level)
{
  struct gc_entry *e;
  struct gc_thread* thread = &_gc_thread[thread_number()];

  while (e = thread->gc_stack)
    {
      if (e->level < level)
	break;
      /*printf("GC FREE 0x%08zx lev=%d\n", e, e->level); */
      --thread->gc_count;
      thread->gc_stack = e->back;
      _gc_free (e);
    }
}

void _gc_free (void *p) {
  free (p);
}

#if 0
void
debug_gc_check_corrupt (const char *file, int line)
{
  struct gc_thread* thread = &_gc_thread[thread_number()];
  const struct gc_entry *stack = thread->gc_stack;
  const struct gc_entry *e;
  while (e = stack)
    {
      if (e->level > thread->gc_level)
	printf ("GC CORRUPT 0x%08zx lev=%d back=0x%08zx file=%s line=%d\n", e,
		e->level, e->back, file, line);
      stack = e->back;
    }
}
#endif

/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */

char *
format_hex_ex (const uint8_t *data, int size, int maxoutput,
	       int space_break, char* separator)
{
  struct buffer out = alloc_buf_gc (maxoutput ? maxoutput :
				    ((size * 2) + (size / space_break) + 2));
  int i;
  for (i = 0; i < size; ++i)
    {
      if (separator && i && !(i % space_break))
	buf_printf (&out, "%s", separator);
      buf_printf (&out, "%02x", data[i]);
    }
  buf_catrunc (&out, "[more...]");
  return out.data;
}
