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

#ifndef COMMON_H
#define COMMON_H

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
 */
#define DEFAULT_UDP_MTU 1500

/*
 * Default MTU of tunnel device.
 */
#define DEFAULT_TUN_MTU 1450

struct frame {
  int mtu;       /* MTU of TUN/TAP device */

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
   * extra_tun: max number of bytes that might be removed from head
   * of incoming packet from tun device, or prepended to outgoing
   * tun packet.
   */
  int extra_tun;
};

/* Routines which read struct frame should use the macros below */

#define BUF_SIZE(f)          ((f)->mtu + (f)->extra_frame + (f)->extra_buffer + (f)->extra_tun)
#define EXTRA_FRAME(f)       ((f)->extra_frame + (f)->extra_tun)
#define MTU_SIZE(f)          ((f)->mtu)
#define MTU_EXTRA_SIZE(f)    ((f)->mtu + (f)->extra_frame)

/*
 * These values are used as maximum size constraints
 * on read() or write() from TUN/TAP device or UDP port.
 */
#define MAX_RW_SIZE_TUN(f)   ((f)->mtu + (f)->extra_tun)
#define MAX_RW_SIZE_UDP(f)   ((f)->mtu + (f)->extra_frame)

#ifdef USE_CRYPTO

/*
 * Max size in bytes of any cipher key that might conceivably be used.
 *
 * This value is checked at compile time in crypto.c to make sure
 * it is always at least EVP_MAX_KEY_LENGTH.
 *
 * We define our own value, since this parameter
 * is used to control the size of static key files.
 * If the OpenSSL library increases EVP_MAX_KEY_LENGTH,
 * we don't want our key files to be suddenly rendered
 * unusable.
 */
#define MAX_CIPHER_KEY_LENGTH 64 

/*
 * Max size in bytes of any HMAC key that might conceivably be used.
 *
 * This value is checked at compile time in crypto.c to make sure
 * it is always at least EVP_MAX_MD_SIZE.  We define our own value
 * for the same reason as above.
 */
#define MAX_HMAC_KEY_LENGTH 64

#endif /* USE_CRYPTO */

/*
 * Debugging levels for various kinds
 * of output.
 *
 * Debug level as specified by --verb n must be at least one greater
 * than a value below in order for that category to be output.
 */

#define D_LINK_ERRORS        0	/* show non-fatal link errors from main event loop */
#define D_CRYPT_ERRORS       0	/* show non-fatal errors from encrypt/decrypt */
#define D_TLS_ERRORS         0	/* show non-fatal TLS control channel errors */

#define D_SHOW_PARMS         1	/* show all parameters on program initiation */

#define D_HANDSHAKE          2	/* show data & control channel handshakes */
#define D_GREMLIN            2  /* show simulated outage info from gremlin module */

#define D_TLS_DEBUG_LOW      3	/* low frequency info from tls_session routines */

#define D_COMP_LOW           4	/* show adaptive compression state changes */

#define D_SHOW_KEYS          5	/* show data channel encryption keys */

#define D_HANDSHAKE_VERBOSE  6	/* show detailed description of each handshake */

#define D_TLS_DEBUG          7	/* show detailed info from tls_session routines */
#define D_CRYPTO_DEBUG       7  /* show detailed info from crypto.c routines */
#define D_COMP               7	/* show compression info */
#define D_READ_WRITE         7	/* verbose account of all tun/UDP reads/writes */
#define D_REL_DEBUG          7	/* show detailed info from reliable routines */
#define D_PACKET_CONTENT     7	/* show before/after encryption packet content */
#define D_GREMLIN_VERBOSE    7  /* show verbose info from gremlin module */
#define D_TLS_NO_SEND_KEY    7  /* show when no data channel send-key is available */
#define D_THREAD_DEBUG       7  /* show debug information from the pthread code */

#define D_SHAPER             8  /* show traffic shaper info */

#define D_OPENSSL_LOCK       9  /* show OpenSSL locks */

/*
 * OpenVPN static mutex locks, by mutex type
 */
#define L_MSG       0
#define L_INET_NTOA 1
#define L_TLS       2
#define L_SOCK      3
#define N_MUTEXES   4

/* TLS time constants */

#define TLS_MULTI_REFRESH 15    /* seconds */
#define TLS_MULTI_HORIZON 60    /* seconds */

#endif
