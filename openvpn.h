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

#ifndef OPENVPN_H
#define OPENVPN_H

/*
 * Where should messages be printed before syslog is opened?
 * Not used if OPENVPN_DEBUG_COMMAND_LINE is defined.
 */
#define OPENVPN_MSG_FP stdout

/*
 * Exit status codes
 */

#define OPENVPN_EXIT_STATUS_GOOD                    0
#define OPENVPN_EXIT_STATUS_ERROR                   1
#define OPENVPN_EXIT_STATUS_USAGE                   1
#define OPENVPN_EXIT_STATUS_CANNOT_OPEN_DEBUG_FILE  1

/*
 * When should we daemonize?
 *
 * Level 0 -- after option parsing (early)
 * Level 1 -- after all initialization (late)
 */
#define DAEMONIZATION_LEVEL 1

/*
 * Special command line debugging mode.
 * If OPENVPN_DEBUG_COMMAND_LINE
 * is defined, contents of argc/argv will
 * be dumped to OPENVPN_DEBUG_FILE as well
 * as all other OpenVPN messages.
 */

/* #define OPENVPN_DEBUG_COMMAND_LINE */
#define OPENVPN_DEBUG_FILE PACKAGE ".log"

/*
 * At exactly --verb 5 (not less or greater), print 'R' and 'W' chars
 * to stdout for each packet read/write on TCP/UDP port.
 */
#define LOG_RW

#endif
