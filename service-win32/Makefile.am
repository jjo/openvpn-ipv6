#
#  OpenVPN -- An application to securely tunnel IP networks
#             over a single UDP port, with support for SSL/TLS-based
#             session authentication and key exchange,
#             packet encryption, packet authentication, and
#             packet compression.
#
#  Copyright (C) 2002-2005 OpenVPN Solutions LLC <info@openvpn.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License version 2
#  as published by the Free Software Foundation.
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

EXTRA_DIST = service.patch

dist_noinst_SCRIPTS = mkpatch

if ENABLE_WIN32_SERVICE

sbin_PROGRAMS = openvpnserv

openvpnserv_SOURCES = \
	openvpnserv.c
nodist_openvpnserv_SOURCES = \
	service.h service.c

else

dist_noinst_DATA = openvpnserv.c

endif

# msys sed does not accept \r
service.c:	$(srcdir)/service.patch
	sed 's/\xd//g' "${WIN32_SDK_SERVICE}/service.c" > service.c
	sed 's/\xd//g' "${WIN32_SDK_SERVICE}/service.h" > service.h
	$(PATCH) < $(srcdir)/service.patch

service.h:	service.c
openvpnserv.c:	service.h
