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
#define MIN_TUN_MTU     100

/*
 * Default MTU of network over which tunnel data will pass by UDP.
 * TODO: DEFAULT_UDP_MTU = 1500 is probably too big...
 */
#define DEFAULT_UDP_MTU 1300

/*
 * Default MTU of tunnel device.
 */
#define DEFAULT_TUN_MTU 1300

struct frame {
  int mtu;       /* MTU of tun/tap device, set by ifconfig */

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
   * extra_tun: max number of bytes in excess of mtu size that we might read
   * or write from tun/tap device.
   */
  int extra_tun;
};

/* Routines which read struct frame should use the macros below */

/*
 * This is the size to "ifconfig" the tun or tap device.
 */
#define MTU_SIZE(f)          ((f)->mtu)

/*
 * This is the maximum packet size that we need to be able to
 * read from or write to a tun or tap device.  For example,
 * a tap device ifconfiged to an MTU of 1200 might actually want
 * to return a packet size of 1214 on a read().
 */
#define PAYLOAD_SIZE(f)      ((f)->mtu + (f)->extra_tun)

/*
 * In general, OpenVPN packet building routines set the initial
 * buffer store point this many bytes into the data buffer to
 * allow for efficient prepending.
 */
#define EXTRA_FRAME(f)       ((f)->extra_frame)

/*
 * Max size of a payload packet after encryption, compression, etc.
 * overhead is added.
 */
#define EXPANDED_SIZE(f)     (PAYLOAD_SIZE(f) + EXTRA_FRAME(f))

/*
 * Max size of a buffer used to build a packet for output to
 * the UDP port.
 */
#define BUF_SIZE(f)          (EXPANDED_SIZE(f) + (f)->extra_buffer)

/*
 * These values are used as maximum size constraints
 * on read() or write() from tun/tap device or UDP port.
 */
#define MAX_RW_SIZE_TUN(f)   (PAYLOAD_SIZE(f))
#define MAX_RW_SIZE_UDP(f)   (EXPANDED_SIZE(f))

#endif
