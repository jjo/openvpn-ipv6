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

#ifndef PROTO_H
#define PROTO_H

#include "buffer.h"

/*
 * Tunnel types
 */
#define DEV_TYPE_UNDEF 0
#define DEV_TYPE_NULL  1
#define DEV_TYPE_TUN   2    /* point-to-point IP tunnel */
#define DEV_TYPE_TAP   3    /* ethernet (802.3) tunnel */

/*
 * IP and Ethernet protocol structs.  For portability,
 * OpenVPN needs its own definitions of these structs, and
 * names have been adjusted to avoid collisions with
 * native structs.
 */

#define OPENVPN_ETH_ALEN 6            /* ethernet address length */
struct openvpn_ethhdr 
{
  uint8_t dest[OPENVPN_ETH_ALEN];     /* destination eth addr	*/
  uint8_t source[OPENVPN_ETH_ALEN];   /* source ether addr	*/

# define OPENVPN_ETH_P_IP   0x0800    /* IPv4 protocol */
  uint16_t proto;                     /* packet type ID field	*/
};

struct openvpn_iphdr {
# define OPENVPN_IPH_GET_VER(v) (((v) >> 4) & 0x0F)
# define OPENVPN_IPH_GET_LEN(v) (((v) & 0x0F) << 2)
  uint8_t    version_len;

  uint8_t    tos;
  uint16_t   tot_len;
  uint16_t   id;

# define OPENVPN_IP_OFFMASK 0x1fff
  uint16_t   frag_off;

  uint8_t    ttl;

# define OPENVPN_IPPROTO_UDP 17 /* UDP protocol */
# define OPENVPN_IPPROTO_TCP 6  /* TCP protocol */
  uint8_t    protocol;

  uint16_t   check;
  uint32_t   saddr;
  uint32_t   daddr;
  /*The options start here. */
};

/*
 * UDP header
 */
struct openvpn_udphdr {
  uint16_t   source;
  uint16_t   dest;
  uint16_t   len;
  uint16_t   check;
};

/*
 * TCP header, per RFC 793.
 */
struct openvpn_tcphdr {
  uint16_t      source;    /* source port */
  uint16_t      dest;      /* destination port */
  uint32_t      seq;       /* sequence number */
  uint32_t      ack_seq;   /* acknowledgement number */

# define OPENVPN_TCPH_GET_DOFF(d) (((d) & 0xF0) >> 2)
  uint8_t       doff_res;

# define OPENVPN_TCPH_FIN_MASK (1<<0)
# define OPENVPN_TCPH_SYN_MASK (1<<1)
# define OPENVPN_TCPH_RST_MASK (1<<2)
# define OPENVPN_TCPH_PSH_MASK (1<<3)
# define OPENVPN_TCPH_ACK_MASK (1<<4)
# define OPENVPN_TCPH_URG_MASK (1<<5)
# define OPENVPN_TCPH_ECE_MASK (1<<6)
# define OPENVPN_TCPH_CWR_MASK (1<<7)
  uint8_t       flags;

  uint16_t      window;
  uint16_t      check;
  uint16_t      urg_ptr;
};

#define	OPENVPN_TCPOPT_EOL     0
#define	OPENVPN_TCPOPT_NOP     1
#define	OPENVPN_TCPOPT_MAXSEG  2
#define OPENVPN_TCPOLEN_MAXSEG 4

/*
 * Alignment-safe version of ntohs
 * and htons.
 */

static inline uint16_t
ntohs_as (const uint16_t *src)
{
  return (uint16_t) (((uint8_t*)src)[0] << 8) | ((uint8_t*)src)[1];
}

static inline void
htons_as (uint16_t *dest, const uint16_t src)
{
  ((uint8_t*)dest)[0] = (uint8_t) (src >> 8);
  ((uint8_t*)dest)[1] = (uint8_t) (src & 0xFF);
}

static inline uint16_t
get_u16_as (const uint16_t *src)
{
  uint16_t ret;
  ((uint8_t*)&ret)[0] = ((uint8_t*)src)[0];
  ((uint8_t*)&ret)[1] = ((uint8_t*)src)[1];
  return ret;
}

static inline void
put_u16_as (uint16_t *dest, const uint16_t src)
{
  ((uint8_t*)dest)[0] = ((uint8_t*)&src)[0];
  ((uint8_t*)dest)[1] = ((uint8_t*)&src)[1];
}

/*
 * The following macro is used to update an
 * internet checksum.  "acc" is a 32-bit
 * accumulation of all the changes to the
 * checksum (adding in old 16-bit words and
 * subtracting out new words), and "cksum"
 * is the checksum value to be updated.
 */
#define ADJUST_CHECKSUM(acc, cksum) { \
  acc += get_u16_as (&cksum); \
  if (acc < 0) { \
    acc = -acc; \
    acc = (acc >> 16) + (acc & 0xffff); \
    acc += acc >> 16; \
    put_u16_as (&cksum, (uint16_t) ~acc); \
  } else { \
    acc = (acc >> 16) + (acc & 0xffff); \
    acc += acc >> 16; \
    put_u16_as (&cksum, (uint16_t) acc); \
  } \
}

/*
 * We are in a "liberal" position with respect to MSS,
 * i.e. we assume that MSS can be calculated from MTU
 * by subtracting out only the IP and TCP header sizes
 * without options.
 *
 * (RFC 879, section 7).
 */
#define MTU_TO_MSS(mtu) (mtu - sizeof(struct openvpn_iphdr) \
                             - sizeof(struct openvpn_tcphdr))

/*
 * If raw tunnel packet is IPv4, return true and increment
 * buffer offset to start of IP header.
 */
static inline bool
is_ipv4 (int tunnel_type, struct buffer *buf)
{
  int offset;
  const struct openvpn_iphdr *ih;

  if (tunnel_type == DEV_TYPE_TUN)
    {
      if (BLEN (buf) < (int) sizeof (struct openvpn_iphdr))
	return false;
      offset = 0;
    }
  else if (tunnel_type == DEV_TYPE_TAP)
    {
      const struct openvpn_ethhdr *eh;
      if (BLEN (buf) < (int)(sizeof (struct openvpn_ethhdr)
	  + sizeof (struct openvpn_iphdr)))
	return false;
      eh = (const struct openvpn_ethhdr *) BPTR (buf);
      if (ntohs_as (&eh->proto) != OPENVPN_ETH_P_IP)
	return false;
      offset = sizeof (struct openvpn_ethhdr);
    }
  else
    return false;

  ih = (const struct openvpn_iphdr *)
    (BPTR (buf) + offset);

  if (OPENVPN_IPH_GET_VER (ih->version_len) == 4)
    return buf_advance (buf, offset);
  else
    return false;
}

#endif
