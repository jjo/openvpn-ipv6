/* inet_aton.c -- Emulate BSD inet_aton via inet_addr.
 *
 * Useful on systems that don't have inet_aton, such as Solaris,
 * to let your code use the better inet_aton interface and use autoconf
 * and AC_REPLACE_FUNCS([inet_aton]).
 *
 * Copyright (C) 2003 Matthias Andree <matthias.andree@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING included with this
 * distribution); if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#ifndef HAVE_INET_ATON

int
inet_aton (const char *name, struct in_addr *addr)
{
  if (!strcmp (name, "255.255.255.255"))
    {
      addr->s_addr = ~0;
      return 1;
    }
  else
    {
      in_addr_t a = inet_addr (name);
      addr->s_addr = a;
      return a != (in_addr_t)-1;
    }
}

#endif
