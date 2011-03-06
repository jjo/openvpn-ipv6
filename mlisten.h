/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2011 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *                     2011 JuanJo Ciarlante <juanjosec@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
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


#ifndef MSOCK_H
#define MSOCK_H

#if P2MP_SERVER

#include "event.h"

/*
 * Extra state info needed for MSOCK mode
 */
struct multi_sock
{
  struct event_set *es;
  struct event_set_return *esr;
  int n_esr;
  int maxevents;
  unsigned int tun_rwflags;
#ifdef ENABLE_MANAGEMENT
  unsigned int management_persist_flags;
#endif
};

struct multi_instance;
struct context;

#endif
#endif /* MSOCK_H */
