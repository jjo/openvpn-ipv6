/* malloc.c -- GNU libc compatible malloc replacement
 *
 * Taken from automake.info which is (C) Copyright 1992, 1993, 1994, 1995,
 * 1996, 1998, 1999, 2000, 2001, 2002 by the Free Software Foundation, Inc.
 *
 * To be used in conjunction with autoconf's AC_FUNC_MALLOC.
 *
 * Modified 2003 by Matthias Andree <matthias.andree@gmx.de>.
 */

#ifndef WIN32

#if HAVE_CONFIG_H
# include <config.h>
#endif
#undef malloc

#include <sys/types.h>

void *malloc (size_t);

/* Allocate an N-byte block of memory from the heap.
   If N is zero, allocate a 1-byte block.  */

void *
rpl_malloc (size_t n)
{
	if (n == 0)
		n = 1;
	return malloc (n);
}

#endif
