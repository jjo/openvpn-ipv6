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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"

#include "memdbg.h"

struct buffer
alloc_buf (size_t size)
{
  struct buffer buf;
  buf.capacity = (int)size;
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
  buf.capacity = (int)size;
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
buf_printf (struct buffer *buf, const char *format, ...)
{
  va_list arglist;

  uint8_t *ptr = BEND (buf);
  int cap = buf_forward_capacity (buf);

  if (cap > 0)
    {
      va_start (arglist, format);
      vsnprintf ((char *)ptr, cap, format, arglist);
      va_end (arglist);
      *(buf->data + buf->capacity - 1) = 0; /* windows vsnprintf needs this */
      buf->len += (int) strlen ((char *)ptr);
    }
}

/*
 * This is necessary due to certain buggy implementations of snprintf,
 * that don't guarantee null termination for size > 0.
 */

int openvpn_snprintf(char *str, size_t size, const char *format, ...)
{
  va_list arglist;
  int ret = 0;
  if (size > 0)
    {
      va_start (arglist, format);
      ret = vsnprintf (str, size, format, arglist);
      va_end (arglist);
      str[size - 1] = 0;
    }
  return ret;
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
      int len = (int) strlen (str) + 1;
      if (len < buf_forward_capacity_total (buf))
	{
	  strncpynt ((char *)(buf->data + buf->capacity - len), str, len);
	}
    }
}

/*
 * convert a multi-line output to one line
 */
void
convert_to_one_line (struct buffer *buf)
{
  uint8_t *cp = BPTR(buf);
  int len = BLEN(buf);
  while (len--)
    {
      if (*cp == '\n')
	*cp = '|';
      ++cp;
    }
}

/* NOTE: requires that string be null terminated */
void
buf_write_string_file (const struct buffer *buf, const char *filename, int fd)
{
  const int len = strlen (BPTR (buf));
  const int size = write (fd, BPTR (buf), len);
  if (size != len)
    msg (M_ERR, "Write error on file '%s'", filename);
}

/*
 * Garbage collection
 */

struct gc_thread x_gc_thread[N_THREADS];

void *
gc_malloc (size_t size)
{
  struct gc_thread* thread = &x_gc_thread[thread_number()];
  size_t s = sizeof (struct gc_entry) + size;
  struct gc_entry *e = (struct gc_entry *) malloc (s);
  ++thread->gc_count;
  ASSERT (e);
  e->level = thread->gc_level;
  e->back = thread->gc_stack;
  thread->gc_stack = e;
  /*printf("GC MALLOC " ptr_format " size=%d lev=%d\n", e, s, e->level); */
  return (char *) e + sizeof (struct gc_entry);
}

#if 0
void
debug_gc_check_corrupt (const char *file, int line)
{
  struct gc_thread* thread = &x_gc_thread[thread_number()];
  const struct gc_entry *stack = thread->gc_stack;
  const struct gc_entry *e;
  while (e = stack)
    {
      if (e->level > thread->gc_level)
	printf ("GC CORRUPT " ptr_format " lev=%d back=" ptr_format " file=%s line=%d\n",
		e, e->level, e->back, file, line);
      stack = e->back;
    }
}
#endif

/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */

char *
format_hex_ex (const uint8_t *data, int size, int maxoutput,
	       int space_break, const char* separator)
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
  return (char *)out.data;
}

/*
 * remove specific trailing character
 */

void
buf_rmtail (struct buffer *buf, uint8_t remove)
{
  uint8_t *cp = BLAST(buf);
  if (cp && *cp == remove)
    {
      *cp = '\0';
      --buf->len;
    }
}

/*
 * Remove trailing \r and \n chars.
 */
void
chomp (char *str)
{
  bool modified;
  do {
    const int len = strlen (str);
    modified = false;
    if (len > 0)
      {
	char *cp = str + (len - 1);
	if (*cp == '\n' || *cp == '\r')
	  {
	    *cp = '\0';
	    modified = true;
	  }
      }
  } while (modified);
}
