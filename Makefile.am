#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
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

# This option prevents autoreconf from overriding our COPYING and
# INSTALL targets:
AUTOMAKE_OPTIONS = foreign

sbin_PROGRAMS = openvpn
nodist_openvpn_SOURCES = config.h
openvpn_SOURCES = basic.h buffer.c buffer.h circ_list.h common.h \
		  crypto.c crypto.h errlevel.h error.c error.h \
		  fdmisc.c fdmisc.h fragment.c fragment.h gremlin.c gremlin.h interval.h \
		  lzo.c lzo.h memdbg.h misc.c misc.h mtu.c mtu.h openvpn.c \
		  openvpn.h options.c options.h packet_id.c \
		  packet_id.h reliable.c reliable.h session_id.c \
		  session_id.h shaper.c shaper.h socket.c socket.h \
		  ssl.c ssl.h syshead.h thread.c thread.h tun.c tun.h
LDADD = @LIBOBJS@

man_MANS = openvpn.8
EXTRA_DIST = $(man_MANS) \
	     COPYRIGHT.GPL PORTS openvpn.spec \
	     easy-rsa sample-config-files sample-keys \
	     sample-scripts openvpn.spec.in \
	     config-win32.h \
	     openvpn-win32.h \
	     openvpn-win32.c \
	     makefile.w32

dist-hook:
	cd $(distdir) && for i in $(EXTRA_DIST) ; do find $$i -name CVS -type d -prune -exec rm -r '{}' ';' ; rm -f `find $$i -type f | grep -E '(^|\/)\.?\#|\~$$'` ; done
