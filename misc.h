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

#ifndef MISC_H
#define MISC_H

#include "basic.h"
#include "common.h"
#include "integer.h"

/* socket descriptor passed by inetd/xinetd server to us */
#define INETD_SOCKET_DESCRIPTOR 0

/* Get/Set UID of process */

struct user_state {
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
  const char *username;
  struct passwd *pw;
#else
  int dummy;
#endif
};

void get_user (const char *username, struct user_state *state);
void set_user (const struct user_state *state);

/* Get/Set GID of process */

struct group_state {
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
  const char *groupname;
  struct group *gr;
#else
  int dummy;
#endif
};

void get_group (const char *groupname, struct group_state *state);
void set_group (const struct group_state *state);

void set_nice (int niceval);
void do_chroot (const char *path);

void run_script (const char *command,
		 const char *arg,
		 int tun_mtu,
		 int link_mtu,
		 const char *ifconfig_local,
		 const char* ifconfig_remote,
		 const char *context,
		 const char *signal_text,
		 const char *script_type);

/* remove non-parameter environmental vars except for signal */
void del_env_nonparm (int n_tls_id);

/* workspace for get_pid_file/write_pid */
struct pid_state {
#ifdef HAVE_GETPID
  FILE *fp;
  const char *filename;
#else
  int dummy;
#endif
};

void get_pid_file (const char* filename, struct pid_state *state);
void write_pid (const struct pid_state *state);

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
int system_executed (int stat);
const char *system_error_message (int);

/* run system() with error check, return true if success,
   false if error, exit if error and fatal==true */
bool system_check (const char* command, const char* error_message, bool fatal);

/* format a time_t as ascii, or use current time if 0 */
const char* time_string (time_t t, bool show_usec);

#ifdef HAVE_STRERROR
/* a thread-safe version of strerror */
const char* strerror_ts (int errnum);
#endif

/* Set standard file descriptors to /dev/null */
void set_std_files_to_null (bool stdin_only);

/* Wrapper for chdir library function */
int openvpn_chdir (const char* dir);

/* dup inetd/xinetd socket descriptor and save */
extern int inetd_socket_descriptor;
void save_inetd_socket_descriptor (void);

/* init random() function, only used as source for weak random numbers, when !USE_CRYPTO */
void init_random_seed(void);

/* set/delete environmental variable */
#define MAX_ENV_STRINGS 200
void setenv_str (const char *name, const char *value);
void setenv_int (const char *name, int value);
void setenv_del (const char *name);

/* convert netmasks for iproute2 */
int count_netmask_bits(const char *);
unsigned int count_bits(unsigned int );

/* make cp safe to be passed to system() or set as an environmental variable */
void safe_string (char *cp);

/* an analogue to the random() function, but use OpenSSL functions if available */
#ifdef USE_CRYPTO
long int get_random(void);
#else
#define get_random random
#endif

/* struct timeval functions */

static inline bool
tv_defined (const struct timeval *tv)
{
  return tv->tv_sec > 0;
}

/* return tv1 - tv2 in usec, constrained by max_seconds */
static inline int
tv_subtract (const struct timeval *tv1, const struct timeval *tv2, bool max_seconds)
{
  const int max_usec = max_seconds * 1000000;
  const int sec_diff = tv1->tv_sec - tv2->tv_sec;

  if (sec_diff > (max_seconds + 10))
    return max_usec;
  else if (sec_diff < -(max_seconds + 10))
    return -max_usec;
  return constrain_int (sec_diff * 1000000 + (tv1->tv_usec - tv2->tv_usec), -max_usec, max_usec);
}

#endif

