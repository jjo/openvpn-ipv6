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
 * It is a fatal error if mtu is less than
 * this value for tun device.
 */
#define TUN_MTU_MIN       100

/*
 * Default MTU of network over which tunnel data will pass by UDP.
 * TODO: DEFAULT_UDP_MTU = 1500 is probably too big...
 */
#define UDP_MTU_DEFAULT   1300

/*
 * Default MTU of tunnel device.
 */
#define TUN_MTU_DEFAULT   1300

/*
 * Dynamic MTU parameters (based on frame.udp_mtu).
 *
 * MIN_TUN_MTU + TUN_UDP_DELTA <= udp_mtu_min <= udp_mtu_dynamic <= udp_mtu_max <= mtu
 */
struct frame_dynamic {
  /* control parameters */
# define MTU_INITIAL_UNDEF -1
  int mtu_min_initial;
  int mtu_max_initial;

# define MTU_SET_TO_MIN -1
# define MTU_SET_TO_MAX -2
  int mtu_initial;

  /* derived from control parameters, set by frame_dynamic_finalize */
  int mtu_min;
  int mtu_max;
  int mtu;
};

struct frame {
  /*
   * Maximum datagram size to be sent over the tunnel UDP channel.
   */
  int udp_mtu;

  /*
   * extra_frame: How many extra bytes might each subsystem (crypto, TLS, or, compression)
   * add to frame in worst case?
   *
   * mtu + extra_frame = MTU of UDP transport
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
   * An MTU value that can dynamically change during the life of the session
   * in order to reduce packet fragmentation.
   */
  struct frame_dynamic dynamic;
};

/* Routines which read struct frame should use the macros below */

/*
 * In general, OpenVPN packet building routines set the initial
 * buffer store point this many bytes into the data buffer to
 * allow for efficient prepending.
 */
#define EXTRA_FRAME(f)           ((f)->extra_frame)

/*
 * Delta between tun payload size and final UDP datagram size
 */
#define TUN_UDP_DELTA(f)         (EXTRA_FRAME(f) + (f)->extra_tun)

/*
 * This is the size to "ifconfig" the tun or tap device.
 */
#define TUN_MTU_SIZE(f)          ((f)->udp_mtu - TUN_UDP_DELTA(f))

/*
 * This is the maximum packet size that we need to be able to
 * read from or write to a tun or tap device.  For example,
 * a tap device ifconfiged to an MTU of 1200 might actually want
 * to return a packet size of 1214 on a read().
 */
#define PAYLOAD_SIZE(f)          ((f)->udp_mtu - EXTRA_FRAME(f))
#define PAYLOAD_SIZE_DYNAMIC(f)  ((f)->dynamic.mtu - EXTRA_FRAME(f))

/*
 * Max size of a payload packet after encryption, compression, etc.
 * overhead is added.
 */
#define EXPANDED_SIZE(f)         ((f)->udp_mtu)
#define EXPANDED_SIZE_DYNAMIC(f) ((f)->dynamic.mtu)

/*
 * Max size of a buffer used to build a packet for output to
 * the UDP port.
 */
#define BUF_SIZE(f)              (EXPANDED_SIZE(f) + TUN_UDP_DELTA(f) + (f)->extra_buffer)

/*
 * These values are used as maximum size constraints
 * on read() or write() from TUN/TAP device or UDP port.
 */
#define MAX_RW_SIZE_TUN(f)       (PAYLOAD_SIZE(f))
#define MAX_RW_SIZE_UDP(f)       (EXPANDED_SIZE(f))

/*
 * Function prototypes.
 */

void frame_finalize (struct frame *frame,
		     bool udp_mtu_defined,
		     int udp_mtu,
		     bool tun_mtu_defined,
		     int tun_mtu,
		     bool udp_mtu_min_defined,
		     int udp_mtu_min,
		     bool udp_mtu_max_defined,
		     int udp_mtu_max);

void frame_finalize_derivative (struct frame *frame, const struct frame *src);
void frame_dynamic_finalize (struct frame *frame);
void frame_set_mtu_dynamic (struct frame *frame, int mtu_dynamic);
bool frame_mtu_change_pct (struct frame *frame, int pct);
void frame_subtract_extra (struct frame *frame, const struct frame *src);
void frame_print (const struct frame *frame, int level, const char *prefix);

void set_mtu_discover_type (int sd, int mtu_type);
int translate_mtu_discover_type_name (const char *name);

/*
 * EXTENDED_SOCKET_ERROR_CAPABILITY functions -- print extra error info
 * on socket errors, such as PMTU size.  As of 2003.05.11, only works
 * on Linux 2.4.
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
frame_add_to_extra_buffer (struct frame *frame, int increment)
{
  frame->extra_buffer += increment;
}

/*
 * Delta between UDP datagram size and total IP packet size.
 */
#define IPv4_UDP_HEADER_SIZE              28
#define IPv6_UDP_HEADER_SIZE              40

static inline int
datagram_overhead (bool ipv6)
{
  if (ipv6)
    return IPv6_UDP_HEADER_SIZE;
  else
    return IPv4_UDP_HEADER_SIZE;
}

/*
 * Adjust frame structure based on a Path MTU value given
 * to us by the OS.
 */
static inline void
frame_adjust_path_mtu (struct frame *frame, int pmtu, bool ipv6)
{
  frame_set_mtu_dynamic (frame, pmtu - datagram_overhead (ipv6));
  frame_dynamic_finalize (frame);
}

static inline bool
frame_defined (const struct frame *frame)
{
  return frame->udp_mtu > 0;
}

#endif
