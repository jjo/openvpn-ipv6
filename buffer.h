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

#ifndef BUFFER_H
#define BUFFER_H

#include "basic.h"
#include "string.h"

struct buffer
{
  int capacity;	   /* size of buffer allocated by malloc */
  int offset;	   /* data starts at data + offset, offset > 0 to allow for efficient prepending */
  int len;	   /* length of data that starts at data + offset */
  unsigned char *data;
};

#define BPTR(buf)  ((buf)->data + (buf)->offset)
#define BEND(buf)  (BPTR(buf) + (buf)->len)
#define BLAST(buf) ((buf)->len ? BPTR(buf) + (buf)->len - 1 : NULL)
#define BLEN(buf)  ((buf)->len)
#define BDEF(buf)  ((buf)->data != NULL)

struct buffer alloc_buf (size_t size);
struct buffer alloc_buf_gc (size_t size);	/* allocate buffer with garbage collection */
struct buffer clear_buf ();
void free_buf (struct buffer *buf);

static inline bool
buf_init (struct buffer *buf, int offset)
{
  if (offset < 0 || offset > buf->capacity || buf->data == NULL)
    return false;
  buf->len = 0;
  buf->offset = offset;
  return true;
}

static inline void
buf_set_write (struct buffer *buf, unsigned char *data, int size)
{
  buf->len = 0;
  buf->offset = 0;
  buf->capacity = size;
  buf->data = data;
}

static inline void
buf_set_read (struct buffer *buf, unsigned char *data, int size)
{
  buf->len = buf->capacity = size;
  buf->offset = 0;
  buf->data = data;
}

/* Like strncpy but makes sure dest is always null terminated */
static inline void
strncpynt (char *dest, const char *src, int maxlen)
{
  strncpy (dest, src, maxlen);
  if (maxlen > 0)
    dest[maxlen - 1] = 0;
}

/*
 * printf append to a buffer with overflow check
 */
void buf_printf (struct buffer *buf, char *format, ...);

/*
 * write a string to the end of a buffer that was
 * truncated by buf_printf
 */
void buf_catrunc (struct buffer *buf, const char *str);

/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */
char *
format_hex_ex (const unsigned char *data, int size, int maxoutput,
	       int space_break, char* separator);

static inline char *
format_hex (const unsigned char *data, int size, int maxoutput)
{
  return format_hex_ex(data, size, maxoutput, 4, " ");
}

/*
 * Return a buffer that is a subset of another buffer.
 */
struct buffer buf_sub (struct buffer *buf, int size, bool prepend);

/*
 * Check if sufficient space to append to buffer.
 */

static inline bool
buf_safe (struct buffer *buf, int len)
{
  return buf->offset + buf->len + len <= buf->capacity;
}

static inline int
buf_forward_capacity (struct buffer *buf)
{
  int ret = buf->capacity - (buf->offset + buf->len);
  if (ret < 0)
    ret = 0;
  return ret;
}

static inline int
buf_forward_capacity_total (struct buffer *buf)
{
  int ret = buf->capacity - buf->offset;
  if (ret < 0)
    ret = 0;
  return ret;
}

static inline int
buf_reverse_capacity (struct buffer *buf)
{
  return buf->offset;
}

/*
 * Make space to prepend to a buffer.
 * Return NULL if no space.
 */

static inline unsigned char *
buf_prepend (struct buffer *buf, int size)
{
  if (size > buf->offset)
    return NULL;
  buf->offset -= size;
  buf->len += size;
  return BPTR (buf);
}

static inline bool
buf_advance (struct buffer *buf, int size)
{
  if (buf->len < size)
    return false;
  buf->offset += size;
  buf->len -= size;
  return true;
}

/*
 * Return a pointer to allocated space inside a buffer.
 * Return NULL if no space.
 */

static inline unsigned char *
buf_write_alloc (struct buffer *buf, int size)
{
  unsigned char *ret;
  if (!buf_safe (buf, size))
    return NULL;
  ret = BPTR (buf) + buf->len;
  buf->len += size;
  return ret;
}

static inline unsigned char *
buf_write_alloc_prepend (struct buffer *buf, int size, bool prepend)
{
  return prepend ? buf_prepend (buf, size) : buf_write_alloc (buf, size);
}

static inline unsigned char *
buf_read_alloc (struct buffer *buf, int size)
{
  unsigned char *ret;
  if (buf->len < size)
    return NULL;
  ret = BPTR (buf);
  buf->offset += size;
  buf->len -= size;
  return ret;
}

static inline bool
buf_write (struct buffer *dest, const void *src, int size)
{
  unsigned char *cp = buf_write_alloc (dest, size);
  if (!cp)
    return false;
  memcpy (cp, src, size);
  return true;
}

static inline bool
buf_write_prepend (struct buffer *dest, const void *src, int size)
{
  unsigned char *cp = buf_prepend (dest, size);
  if (!cp)
    return false;
  memcpy (cp, src, size);
  return true;
}

static inline bool
buf_copy (struct buffer *dest, const struct buffer *src)
{
  return buf_write (dest, BPTR (src), BLEN (src));
}

static inline bool
buf_read (struct buffer *src, void *dest, int size)
{
  unsigned char *cp = buf_read_alloc (src, size);
  if (!cp)
    return false;
  memcpy (dest, cp, size);
  return true;
}

/*
 * Very basic garbage collection, mostly for routines that return
 * char ptrs to malloced strings.  Not multi-thread safe unless you
 * make _gc_level and _gc_stack thread-local.
 */

struct gc_entry
{
  struct gc_entry *back;
  int level;
};

extern int gc_count;

extern int _gc_level;
extern struct gc_entry *_gc_stack;

void *gc_malloc (size_t size);

void _gc_free (void *p);

static inline int
gc_new_level ()
{
  return ++_gc_level;
}

static inline void
gc_collect (int level)
{
  struct gc_entry *e;
  while (e = _gc_stack)
    {
      if (e->level < level)
	break;
      /*printf("GC FREE 0x%08x lev=%d\n", e, e->level); */
      --gc_count;
      _gc_stack = e->back;
      _gc_free (e);
    }
}

static inline void
gc_free_level (int level)
{
  gc_collect (level);
  _gc_level = level - 1;
}

#if 0
#define GCCC debug_gc_check_corrupt(__FILE__, __LINE__)
void debug_gc_check_corrupt (const char *file, int line);
#endif

#endif /* BUFFER_H */
