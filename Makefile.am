#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002 James Yonan <jim@yonan.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program (see the file COPYING included with this
#  distribution); if not, write to the Free Software Foundation, Inc.,
#  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

sbin_PROGRAMS = openvpn
openvpn_SOURCES = acconfig.h buffer.h crypto.c error.h gremlin.c lzo.c misc.c openvpn.h reliable.c session_id.h ssl.c tun.h basic.h circ_list.h crypto.h fdmisc.c gremlin.h lzo.h misc.h packet_id.c reliable.h shaper.c socket.c ssl.h buffer.c common.h error.c fdmisc.h interval.h memdbg.h openvpn.c packet_id.h session_id.c socket.h syshead.h tun.c shaper.h

KEY_FILES = dh1024.pem client.crt client.key server.crt server.key tmp-ca.crt tmp-ca.key

man_MANS = openvpn.8
EXTRA_DIST = $(KEY_FILES)
