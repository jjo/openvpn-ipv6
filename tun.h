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

#include "buffer.h"
#include "error.h"
#include "common.h"

#define IS_TUN(dev) (!strncmp (dev, "tun", 3)) 
#define IS_TAP(dev) (!strncmp (dev, "tap", 3)) 

int open_tun (const char *dev, char *actual, int size);
void tuncfg (const char *dev, int persist_mode);

/*
 * Inline functions
 */
static inline void
tun_adjust_frame_parameters (struct frame* frame, int size)
{
  frame->extra_tun += size;
}

static inline void
tun_add_head (struct buffer* buf, u_int32_t value)
{
  u_int32_t *p = (u_int32_t*) buf_prepend (buf, sizeof (u_int32_t));
  *p = htonl(value);
}

static inline void
tun_rm_head (struct buffer* buf, u_int32_t value)
{
  u_int32_t found = ntohl (*(u_int32_t*) BPTR (buf));
  if (found == value)
    ASSERT (buf_advance (buf, sizeof (u_int32_t)));
  else
    {
      msg (D_LINK_ERRORS,
	   "Failed to match TUN packet leading u_int32_t (expected=0x%08x, found=0x%08x)",
	   value, found);
      buf->len = 0;
    }
}
