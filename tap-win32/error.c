/*
 *  TAP-Win32 -- A kernel driver to provide virtual tap device functionality
 *               on Windows.  Originally derived from the CIPE-Win32
 *               project by Damion K. Wilson, with extensive modifications by
 *               James Yonan.
 *
 *  All source code which derives from the CIPE-Win32 project is
 *  Copyright (C) Damion K. Wilson, 2003, and is released under the
 *  GPL version 2 (see below).
 *
 *  All other source code is Copyright (C) James Yonan, 2003-2004,
 *  and is released under the GPL version 2 (see below).
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

//-----------------
// DEBUGGING OUTPUT
//-----------------

#if DBG

VOID
MyAssert (const unsigned char *file, int line)
{
      DEBUGP (("MYASSERT failed %s/%d\n", file, line));
      KeBugCheckEx (0x0F00BABA,
		    (ULONG_PTR) line,
		    (ULONG_PTR) 0,
		    (ULONG_PTR) 0,
		    (ULONG_PTR) 0);
}

VOID
PrMac (const MACADDR mac)
{
  DbgPrint ("%x:%x:%x:%x:%x:%x",
	    mac[0], mac[1], mac[2],
	    mac[3], mac[4], mac[5]);
}

VOID
PrIP (IPADDR ip_addr)
{
  const unsigned char *ip = (const unsigned char *) &ip_addr;

  DbgPrint ("%d.%d.%d.%d",
	    ip[0], ip[1], ip[2], ip[3]);
}

const char *
PrIPProto (int proto)
{
  switch (proto)
    {
    case IPPROTO_UDP:
      return "UDP";
    case IPPROTO_TCP:
      return "TCP";
    case IPPROTO_ICMP:
      return "ICMP";
    case IPPROTO_IGMP:
      return "IGMP";
    default:
      return "???";
    }
}

VOID
DumpARP (const char *prefix, const ARP_PACKET *arp)
{
  DbgPrint ("%s ARP src=", prefix);
  PrMac (arp->m_MAC_Source);
  DbgPrint (" dest=");
  PrMac (arp->m_MAC_Destination);
  DbgPrint (" OP=0x%04x",
	    (int)ntohs(arp->m_ARP_Operation));
  DbgPrint (" M=0x%04x(%d)",
	    (int)ntohs(arp->m_MAC_AddressType),
	    (int)arp->m_MAC_AddressSize);
  DbgPrint (" P=0x%04x(%d)",
	    (int)ntohs(arp->m_PROTO_AddressType),
	    (int)arp->m_PROTO_AddressSize);

  DbgPrint (" MacSrc=");
  PrMac (arp->m_ARP_MAC_Source);
  DbgPrint (" MacDest=");
  PrMac (arp->m_ARP_MAC_Destination);

  DbgPrint (" IPSrc=");
  PrIP (arp->m_ARP_IP_Source);
  DbgPrint (" IPDest=");
  PrIP (arp->m_ARP_IP_Destination);

  DbgPrint ("\n");
}

struct ethpayload {
  ETH_HEADER eth;
  UCHAR payload[DEFAULT_PACKET_LOOKAHEAD];
};

VOID DumpPacket2 (const char *prefix,
		  const ETH_HEADER *eth,
		  const unsigned char *data,
		  unsigned int len)
{
  struct ethpayload *ep = (struct ethpayload *) MemAllocZeroed (sizeof (struct ethpayload));
  if (ep)
    {
      if (len > DEFAULT_PACKET_LOOKAHEAD)
	len = DEFAULT_PACKET_LOOKAHEAD;
      ep->eth = *eth;
      NdisMoveMemory (ep->payload, data, len);
      DumpPacket (prefix, (unsigned char *) ep, sizeof (ETH_HEADER) + len);
      MemFree (ep, sizeof (struct ethpayload));
    }
}

VOID
DumpPacket (const char *prefix,
	    const unsigned char *data,
	    unsigned int len)
{
  const ETH_HEADER *eth = (const ETH_HEADER *) data;
  const IPHDR *ip = (const IPHDR *) (data + sizeof (ETH_HEADER));

  if (len < sizeof (ETH_HEADER))
    {
      DbgPrint ("%s TRUNCATED PACKET LEN=%d\n", prefix, len);
      return;
    }

  // ARP Packet?
  if (len >= sizeof (ARP_PACKET) && eth->proto == htons (ETH_P_ARP))
    {
      DumpARP (prefix, (const ARP_PACKET *) data);
      return;
    }

  // IPv4 packet?
  if (len >= (sizeof (IPHDR) + sizeof (ETH_HEADER))
      && eth->proto == htons (ETH_P_IP)
      && IPH_GET_VER (ip->version_len) == 4)
    {
      const int hlen = IPH_GET_LEN (ip->version_len);
      const int blen = len - sizeof (ETH_HEADER);
      BOOLEAN did = FALSE;

      DbgPrint ("%s IPv4 %s[%d]", prefix, PrIPProto (ip->protocol), len);

      if (!(ntohs (ip->tot_len) == blen && hlen <= blen))
	{
	  DbgPrint (" XXX");
	  return;
	}
      
      // TCP packet?
      if (ip->protocol == IPPROTO_TCP
	  && blen - hlen >= (sizeof (TCPHDR)))
	{
	  const TCPHDR *tcp = (TCPHDR *) (data + sizeof (ETH_HEADER) + hlen);
	  DbgPrint (" ");
	  PrIP (ip->saddr);
	  DbgPrint (":%d", ntohs (tcp->source));
	  DbgPrint (" -> ");
	  PrIP (ip->daddr);
	  DbgPrint (":%d", ntohs (tcp->dest));
	  did = TRUE;
	}

      // UDP packet?
      else if ((ntohs (ip->frag_off) & IP_OFFMASK) == 0
	       && ip->protocol == IPPROTO_UDP
	       && blen - hlen >= (sizeof (UDPHDR)))
	{
	  const UDPHDR *udp = (UDPHDR *) (data + sizeof (ETH_HEADER) + hlen);
	  
	  // DHCP packet?
	  if ((udp->dest == htons (BOOTPC_PORT) || udp->dest == htons (BOOTPS_PORT))
	      && blen - hlen >= (sizeof (UDPHDR) + sizeof (DHCP)))
	    {
	      const DHCP *dhcp = (DHCP *) (data
					   + hlen
					   + sizeof (ETH_HEADER)
					   + sizeof (UDPHDR));
	      
	      int optlen = len
		- sizeof (ETH_HEADER)
		- hlen
		- sizeof (UDPHDR)
		- sizeof (DHCP);

	      if (optlen < 0)
		optlen = 0;

	      DumpDHCP (eth, ip, udp, dhcp, optlen);
	      did = TRUE;
	    }

	  if (!did)
	    {
	      DbgPrint (" ");
	      PrIP (ip->saddr);
	      DbgPrint (":%d", ntohs (udp->source));
	      DbgPrint (" -> ");
	      PrIP (ip->daddr);
	      DbgPrint (":%d", ntohs (udp->dest));
	      did = TRUE;
	    }
	}

      if (!did)
	{
	  DbgPrint (" ipproto=%d ", ip->protocol);
	  PrIP (ip->saddr);
	  DbgPrint (" -> ");
	  PrIP (ip->daddr);
	}

      DbgPrint ("\n");
      return;
    }

  {
    DbgPrint ("%s ??? src=", prefix);
    PrMac (eth->src);
    DbgPrint (" dest=");
    PrMac (eth->dest);
    DbgPrint (" proto=0x%04x len=%d\n",
	      (int) ntohs(eth->proto),
	      len);
  }
}

#endif
