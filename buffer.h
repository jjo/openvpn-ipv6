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

#ifndef BUFFER_H
#define BUFFER_H

#include "basic.h"
#include "thread.h"

struct buffer
{
  int capacity;	   /* size of buffer allocated by malloc */
  int offset;	   /* data starts at data + offset, offset > 0 to allow for efficient prepending */
  int len;	   /* length of data that starts at data + offset */
  uint8_t *data;
};

#define BPTR(buf)  ((buf)->data + (buf)->offset)
#define BEND(buf)  (BPTR(buf) + (buf)->len)
#define BLAST(buf) (((buf)->data && (buf)->len) ? (BPTR(buf) + (buf)->len - 1) : NULL)
#define BLEN(buf)  ((buf)->len)
#define BDEF(buf)  ((buf)->data != NULL)
#define BSTR(buf)  (char *)BPTR(buf)

struct buffer alloc_buf (size_t size);
struct buffer clone_buf (const struct buffer* buf);
struct buffer alloc_buf_gc (size_t size);	/* allocate buffer with garbage collection */
struct buffer clear_buf (void);
void free_buf (struct buffer *buf);

/* inline functions */

static inline bool
buf_init (struct buffer *buf, int offset)
{
  if (offset < 0 || offset > buf->capacity || buf->data == NULL)
    return false;
  buf->len = 0;
  buf->offset = offset;
  return true;
}

static inline bool
buf_defined (struct buffer *buf)
{
  return buf->data != NULL;
}

static inline void
buf_clear (struct buffer *buf)
{
  memset (buf->data, 0, buf->capacity);
  buf->len = 0;
  buf->offset = 0;
}

static inline void
buf_set_write (struct buffer *buf, uint8_t *data, int size)
{
  buf->len = 0;
  buf->offset = 0;
  buf->capacity = size;
  buf->data = data;
}

static inline void
buf_set_read (struct buffer *buf, uint8_t *data, int size)
{
  buf->len = buf->capacity = size;
  buf->offset = 0;
  buf->data = data;
}

/* Like strncpy but makes sure dest is always null terminated */
static inline void
strncpynt (char *dest, const char *src, size_t maxlen)
{
  strncpy (dest, src, maxlen);
  if (maxlen > 0)
    dest[maxlen - 1] = 0;
}

/* return true if string contains at least one numerical digit */
static inline bool
has_digit (const char* src)
{
  char c;
  while ((c = *src++))
    {
      if (isdigit(c))
	return true;
    }
  return false;
}

/*
 * printf append to a buffer with overflow check
 */
void buf_printf (struct buffer *buf, const char *format, ...)
#ifdef __GNUC__
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

/*
 * remove trailing newline
 */
static inline void
buf_chomp (struct buffer *buf, uint8_t remove)
{
  uint8_t *cp = BLAST(buf);
  if (cp && *cp == remove)
    {
      *cp = '\0'; 
      --buf->len;
    }
}

/*
 * write a string to the end of a buffer that was
 * truncated by buf_printf
 */
void buf_catrunc (struct buffer *buf, const char *str);

/*
 * convert a multi-line output to one line
 */
void convert_to_one_line (struct buffer *buf);


/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */
char *
format_hex_ex (const uint8_t *data, int size, int maxoutput,
	       int space_break, const char* separator);

static inline char *
format_hex (const uint8_t *data, int size, int maxoutput)
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

static inline uint8_t *
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

static inline uint8_t *
buf_write_alloc (struct buffer *buf, int size)
{
  uint8_t *ret;
  if (!buf_safe (buf, size))
    return NULL;
  ret = BPTR (buf) + buf->len;
  buf->len += size;
  return ret;
}

static inline uint8_t *
buf_write_alloc_prepend (struct buffer *buf, int size, bool prepend)
{
  return prepend ? buf_prepend (buf, size) : buf_write_alloc (buf, size);
}

static inline uint8_t *
buf_read_alloc (struct buffer *buf, int size)
{
  uint8_t *ret;
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
  uint8_t *cp = buf_write_alloc (dest, size);
  if (!cp)
    return false;
  memcpy (cp, src, size);
  return true;
}

static inline bool
buf_write_prepend (struct buffer *dest, const void *src, int size)
{
  uint8_t *cp = buf_prepend (dest, size);
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
buf_copy_n (struct buffer *dest, struct buffer *src, int n)
{
  uint8_t *cp = buf_read_alloc (src, n);
  if (!cp)
    return false;
  return buf_write (dest, cp, n);
}

static inline bool
buf_copy_range (struct buffer *dest,
		int dest_index,
		const struct buffer *src,
		int src_index,
		int src_len)
{
  if (src_index < 0
      || src_len < 0
      || src_index + src_len > src->len
      || dest_index < 0
      || dest->offset + dest_index + src_len > dest->capacity)
    return false;
  memcpy (dest->data + dest->offset + dest_index, src->data + src->offset + src_index, src_len);
  if (dest_index + src_len > dest->len)
    dest->len = dest_index + src_len;
  return true;
}

static inline bool
buf_read (struct buffer *src, void *dest, int size)
{
  uint8_t *cp = buf_read_alloc (src, size);
  if (!cp)
    return false;
  memcpy (dest, cp, size);
  return true;
}

static inline bool
buf_string_match (struct buffer *src, const void *match, int size)
{
  if (size != src->len)
    return false;
  return memcmp (BPTR (src), match, size) == 0;
}

/*
 * Very basic garbage collection, mostly for routines that return
 * char ptrs to malloced strings.
 */

struct gc_entry
{
  struct gc_entry *back;
  int level;
};

struct gc_thread
{
  int gc_count;
  int gc_level;
  struct gc_entry *gc_stack;
};

extern struct gc_thread x_gc_thread[N_THREADS];

void *gc_malloc (size_t size);
void gc_collect (int level);

void x_gc_free (void *p);

static inline int
gc_new_level (void)
{
  struct gc_thread* thread = &x_gc_thread[thread_number()];
  return ++thread->gc_level;
}

static inline void
gc_free_level (int level)
{
  struct gc_thread* thread = &x_gc_thread[thread_number()];

  gc_collect (level);
  thread->gc_level = level - 1;
}

#if 0
#define GCCC debug_gc_check_corrupt(__FILE__, __LINE__)
void debug_gc_check_corrupt (const char *file, int line);
#endif

#endif /* BUFFER_H */
