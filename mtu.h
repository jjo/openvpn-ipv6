/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
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

#ifndef MTU_H
#define MTU_H

/*
 * 
 * Packet maninipulation routes such as encrypt, decrypt, compress, decompress
 * are passed a frame buffer that looks like this:
 *
 *    [extra_frame bytes] [mtu bytes] [extra_frame_bytes] [compression overflow bytes]
 *                         ^
 *                   Pointer passed to function points here so that routine
 *                   can make use of extra_frame bytes before pointer
 *                   to prepend headers, etc.
 *
 *    extra_frame bytes is large enough for all encryption related overhead.
 *
 *    mtu bytes will be the MTU size set in the ifconfig statement that configures
 *      the TUN or TAP device such as:
 *
 *      ifconfig $1 10.1.0.2 pointopoint 10.1.0.1 mtu 1450
 *
 *    Compression overflow bytes is the worst-case size expansion that would be
 *    expected if we tried to compress mtu + extra_frame bytes of uncompressible data.
 */

/*
 * Standard ethernet MTU
 */
#define ETHERNET_MTU       1500

/*
 * It is a fatal error if mtu is less than
 * this value for tun device.
 */
#define TUN_MTU_MIN        100

/*
 * Default MTU of network over which tunnel data will pass by TCP/UDP.
 */
#define LINK_MTU_DEFAULT   1300

/*
 * Default MTU of tunnel device.
 */
#define TUN_MTU_DEFAULT    1300

/*
 * MTU Defaults for TAP devices
 */
#define TAP_MTU_DEFAULT        ETHERNET_MTU
#define TAP_MTU_EXTRA_DEFAULT  32

struct frame {
  /*
   * Maximum datagram size to be sent over the tunnel TCP/UDP channel.
   */
  int link_mtu;
  int link_mtu_dynamic;

  /*
   * extra_frame: How many extra bytes might each subsystem (crypto, TLS, or, compression)
   * add to frame in worst case?
   *
   * mtu + extra_frame = MTU of TCP/UDP transport
   */
  int extra_frame;

  /*
   * extra_buffer: Worst case size added to internal buffer due to functions
   * such as compression which can potentially expand the size of uncompressible
   * data.
   */
  int extra_buffer;

  /*
   * extra_tun: max number of bytes in excess of tun mtu size that we might read
   * or write from TUN/TAP device.
   */
  int extra_tun;

  /*
   * extra_link: max number of bytes in excess on link mtu size that we might read
   * or write from UDP/TCP link.
   */
  int extra_link;
};

/* Routines which read struct frame should use the macros below */

/*
 * Overhead added to packet payload due to encapsulation
 */
#define EXTRA_FRAME(f)           ((f)->extra_frame)

/*
 * Delta between tun payload size and final TCP/UDP datagram size
 * (not including extra_link additions)
 */
#define TUN_LINK_DELTA(f)        ((f)->extra_frame + (f)->extra_tun)

/*
 * This is the size to "ifconfig" the tun or tap device.
 */
#define TUN_MTU_SIZE(f)          ((f)->link_mtu - TUN_LINK_DELTA(f))
#define TUN_MTU_SIZE_DYNAMIC(f)  ((f)->link_mtu_dynamic - TUN_LINK_DELTA(f))

/*
 * This is the maximum packet size that we need to be able to
 * read from or write to a tun or tap device.  For example,
 * a tap device ifconfiged to an MTU of 1200 might actually want
 * to return a packet size of 1214 on a read().
 */
#define PAYLOAD_SIZE(f)          ((f)->link_mtu - (f)->extra_frame)
#define PAYLOAD_SIZE_DYNAMIC(f)  ((f)->link_mtu_dynamic - (f)->extra_frame)

/*
 * Max size of a payload packet after encryption, compression, etc.
 * overhead is added.
 */
#define EXPANDED_SIZE(f)         ((f)->link_mtu)
#define EXPANDED_SIZE_DYNAMIC(f) ((f)->link_mtu_dynamic)
#define EXPANDED_SIZE_MIN(f)     (TUN_MTU_MIN + TUN_LINK_DELTA(f))

/*
 * These values are used as maximum size constraints
 * on read() or write() from TUN/TAP device or TCP/UDP port.
 */
#define MAX_RW_SIZE_TUN(f)       (PAYLOAD_SIZE(f))
#define MAX_RW_SIZE_LINK(f)      (EXPANDED_SIZE(f) + (f)->extra_link)

/*
 * In general, OpenVPN packet building routines set the initial
 * buffer store point this many bytes into the data buffer to
 * allow for efficient prepending.
 */
#define FRAME_HEADROOM(f)        (TUN_LINK_DELTA(f) + (f)->extra_buffer + (f)->extra_link)

/*
 * Max size of a buffer used to build a packet for output to
 * the TCP/UDP port.
 */
#define BUF_SIZE(f)              (TUN_MTU_SIZE(f) + FRAME_HEADROOM(f) * 2)

/*
 * Function prototypes.
 */

void frame_finalize (struct frame *frame,
		     bool link_mtu_defined,
		     int link_mtu,
		     bool tun_mtu_defined,
		     int tun_mtu);

void frame_subtract_extra (struct frame *frame, const struct frame *src);
void frame_print (const struct frame *frame, int level, const char *prefix);

void set_mtu_discover_type (int sd, int mtu_type);
int translate_mtu_discover_type_name (const char *name);

/*
 * frame_set_mtu_dynamic and flags
 */

#define SET_MTU_TUN         (1<<0) /* use tun/tap rather than link sizing */
#define SET_MTU_UPPER_BOUND (1<<1) /* only decrease dynamic MTU */

void frame_set_mtu_dynamic (struct frame *frame, int mtu, unsigned int flags);

/*
 * EXTENDED_SOCKET_ERROR_CAPABILITY functions -- print extra error info
 * on socket errors, such as PMTU size.  As of 2003.05.11, only works
 * on Linux 2.4+.
 */

#if EXTENDED_SOCKET_ERROR_CAPABILITY

void set_sock_extended_error_passing (int sd);
const char *format_extended_socket_error (int fd, int* mtu);

#endif

/*
 * Inline functions
 */

static inline void
frame_add_to_extra_frame (struct frame *frame, int increment)
{
  frame->extra_frame += increment;
}

static inline void
frame_add_to_extra_tun (struct frame *frame, int increment)
{
  frame->extra_tun += increment;
}

static inline void
frame_add_to_extra_link (struct frame *frame, int increment)
{
  frame->extra_link += increment;
}

static inline void
frame_add_to_extra_buffer (struct frame *frame, int increment)
{
  frame->extra_buffer += increment;
}

static inline bool
frame_defined (const struct frame *frame)
{
  return frame->link_mtu > 0;
}

#endif
