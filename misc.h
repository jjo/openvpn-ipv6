/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for TLS-based
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

#include "basic.h"

void set_user (const char *username);
void set_group (const char *groupname);
void set_nice (int niceval);
void do_chroot (const char *path);

void run_script (const char *command, const char *arg, int tun_mtu, int udp_mtu,
		 const char *ifconfig_local, const char* ifconfig_remote);

void write_pid (const char* filename);

void do_mlockall (bool print_msg); /* Disable paging */

#ifndef HAVE_DAEMON
int daemon (int nochdir, int noclose);
#endif

/* check file protections */
void warn_if_group_others_accessible(const char* filename);

/* wrapper around the system() call. */
int openvpn_system (const char *command);

/* interpret the status code returned by system() */
bool system_ok(int stat);
const char *system_error_message (int stat);

/* run system() with error check */
void system_check (const char* command, const char* error_message, bool fatal);
