/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifndef MISC_H
#define MISC_H

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
bool system_ok(int);
const char *system_error_message (int);

/* run system() with error check, return true if success,
   false if error, exit if error and fatal==true */
bool system_check (const char* command, const char* error_message, bool fatal);

/* format a time_t as ascii, or use current time if 0 */
const char* time_string (time_t t);

/* init random() function, only used as source for weak random numbers, when !USE_CRYPTO */
void init_random_seed(void);

/* an analogue to the random() function, but use OpenSSL functions if available */
#ifdef USE_CRYPTO
long int get_random(void);
#else
#define get_random random
#endif

#endif
