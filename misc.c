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

#include "config.h"

#include "syshead.h"

#include "buffer.h"
#include "misc.h"
#include "tun.h"
#include "error.h"
#include "openvpn.h"
#include "thread.h"

#include "memdbg.h"

/* Redefine the top level directory of the filesystem
   to restrict access to files for security */
void
do_chroot (const char *path)
{
  if (path)
    {
#ifdef HAVE_CHROOT
      const char *top = "/";
      if (chroot (path))
	msg (M_ERR, "chroot to '%s' failed", path);
      if (openvpn_chdir (top))
	msg (M_ERR, "cd to '%s' failed", top);
      msg (M_INFO, "chroot to '%s' and cd to '%s' succeeded", path, top);
#else
      msg (M_FATAL, "Sorry but I can't chroot to '%s' because this operating system doesn't appear to support the chroot() system call", path);
#endif
    }
}

/* Get/Set UID of process */

void
get_user (const char *username, struct user_state *state)
{
  CLEAR (*state);
  if (username)
    {
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
      state->pw = getpwnam (username);
      if (!state->pw)
	msg (M_ERR, "failed to find UID for user %s", username);
      state->username = username;
#else
      msg (M_FATAL, "Sorry but I can't setuid to '%s' because this operating system doesn't appear to support the getpwname() or setuid() system calls", username);
#endif
    }
}

void
set_user (const struct user_state *state)
{
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
  if (state->username && state->pw)
    {
      if (setuid (state->pw->pw_uid))
	msg (M_ERR, "setuid('%s') failed", state->username);
      msg (M_INFO, "UID set to %s", state->username);
    }
#endif
}

/* Get/Set GID of process */

void
get_group (const char *groupname, struct group_state *state)
{
  CLEAR (*state);
  if (groupname)
    {
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
      state->gr = getgrnam (groupname);
      if (!state->gr)
	msg (M_ERR, "failed to find GID for group %s", groupname);
      state->groupname = groupname;
#else
      msg (M_FATAL, "Sorry but I can't setgid to '%s' because this operating system doesn't appear to support the getgrnam() or setgid() system calls", groupname);
#endif
    }
}

void
set_group (const struct group_state *state)
{
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
  if (state->groupname && state->gr)
    {
      if (setgid (state->gr->gr_gid))
	msg (M_ERR, "setgid('%s') failed", state->groupname);
      msg (M_INFO, "GID set to %s", state->groupname);
#ifdef HAVE_SETGROUPS
      {
        gid_t gr_list[1];
	gr_list[0] = state->gr->gr_gid;
	if (setgroups (1, gr_list))
	  msg (M_ERR, "setgroups('%s') failed", state->groupname);
      }
#endif
    }
#endif
}

/* Change process priority */
void
set_nice (int niceval)
{
  if (niceval)
    {
#ifdef HAVE_NICE
      if (nice (niceval) < 0)
	msg (M_WARN | M_ERRNO, "WARNING: nice %d failed", niceval);
      else
	msg (M_INFO, "nice %d succeeded", niceval);
#else
      msg (M_WARN, "WARNING: nice %d failed (function not implemented)", niceval);
#endif
    }
}

/* Pass tunnel endpoint and MTU parms to a user-supplied script */
void
run_script (const char *command, const char *arg, int tun_mtu, int udp_mtu,
	    const char *ifconfig_local, const char* ifconfig_remote)
{
  if (command)
    {
      char command_line[256];

      ASSERT (arg);

      if (!ifconfig_local)
	ifconfig_local = "";
      if (!ifconfig_remote)
	ifconfig_remote = "";

      snprintf (command_line, sizeof (command_line), "%s %s %d %d %s %s",
		command, arg, tun_mtu, udp_mtu,
		ifconfig_local, ifconfig_remote);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "script failed", true);
    }
}

/* Get the file we will later write our process ID to */
void
get_pid_file (const char* filename, struct pid_state *state)
{
  CLEAR (*state);
  if (filename)
    {
#ifdef HAVE_GETPID
      state->fp = fopen (filename, "w");
      if (!state->fp)
	msg (M_ERR, "Open error on pid file %s", filename);
      state->filename = filename;
#else
      msg (M_FATAL, "Sorry but I can't write my pid to '%s' because this operating system doesn't appear to support the getpid() system call", filename);
#endif
    }
}

/* Write our PID to a file */
void
write_pid (const struct pid_state *state)
{
#ifdef HAVE_GETPID
  if (state->filename && state->fp)
    {
      const pid_t pid = getpid (); 
      fprintf(state->fp, "%d\n", pid);
      if (fclose (state->fp))
	msg (M_ERR, "Close error on pid file %s", state->filename);
    }
#endif
}

/* Disable paging */
void
do_mlockall(bool print_msg)
{
#ifdef HAVE_MLOCKALL
  if (mlockall (MCL_CURRENT | MCL_FUTURE))
    msg (M_WARN | M_ERRNO, "WARNING: mlockall call failed");
  else if (print_msg)
    msg (M_INFO, "mlockall call succeeded");
#else
  msg (M_WARN, "WARNING: mlockall call failed (function not implemented)");
#endif
}

#ifndef HAVE_DAEMON

int
daemon(int nochdir, int noclose)
{
#if defined(HAVE_FORK) && defined(HAVE_SETSID)
  switch (fork())
    {
    case -1:
      return (-1);
    case 0:
      break;
    default:
      _exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }

  if (setsid() == -1)
    return (-1);

  if (!nochdir)
    openvpn_chdir ("/");

  if (!noclose)
    set_std_files_to_null ();
#else
  msg (M_FATAL, "Sorry but I can't become a daemon because this operating system doesn't appear to support either the daemon() or fork() system calls");
#endif
  return (0);
}

#endif

/*
 * Set standard file descriptors to /dev/null
 */
void
set_std_files_to_null ()
{
#if defined(HAVE_DUP) && defined(HAVE_DUP2)
  int fd;
  if ((fd = open ("/dev/null", O_RDWR, 0)) != -1)
    {
      dup2 (fd, 0);
      dup2 (fd, 1);
      dup2 (fd, 2);
      if (fd > 2)
	close (fd);
    }
#endif
}

/*
 * Wrapper for chdir library function
 */
int
openvpn_chdir (const char* dir)
{
#ifdef HAVE_CHDIR
  return chdir (dir);
#else
  return -1;
#endif
}

/*
 *  dup inetd/xinetd socket descriptor and save
 */

int inetd_socket_descriptor = -1;

void
save_inetd_socket_descriptor ()
{
  inetd_socket_descriptor = INETD_SOCKET_DESCRIPTOR;
#if defined(HAVE_DUP) && defined(HAVE_DUP2)
  /* use handle passed by inetd/xinetd */
  if ((inetd_socket_descriptor = dup (INETD_SOCKET_DESCRIPTOR)) < 0)
    msg (M_ERR, "dup(%d) failed", INETD_SOCKET_DESCRIPTOR);
#endif
}

/*
 * Wrapper around the system() call.
 */
int
openvpn_system (const char *command)
{
#ifdef HAVE_SYSTEM
  return system (command);
#else
  msg (M_FATAL, "Sorry but I can't execute the shell command '%s' because this operating system doesn't appear to support the system() call", command);
  return -1; /* NOTREACHED */
#endif
}

/*
 * Warn if a given file is group/others accessible.
 */
void
warn_if_group_others_accessible(const char* filename)
{
#ifdef HAVE_STAT
  struct stat st;
  if (stat (filename, &st))
    {
      msg (M_WARN | M_ERRNO, "WARNING: cannot stat file '%s'", filename);
    }
  else
    {
      if (st.st_mode & (S_IRWXG|S_IRWXO))
	msg (M_WARN, "WARNING: file '%s' is group or others accessible", filename);
    }
#else
  msg (M_WARN, "WARNING: cannot stat file '%s' (stat function missing)", filename);
#endif
}

/*
 * convert system() return into a success/failure value
 */
bool
system_ok(int stat)
{
  return stat != -1 && WIFEXITED (stat) && WEXITSTATUS (stat) == 0;
}

/*
 * Print an error message based on the status code returned by system().
 */
const char *
system_error_message (int stat)
{
  struct buffer out = alloc_buf_gc (512);
  if (stat == -1)
    buf_printf (&out, "shell command fork failed");
  else if (!WIFEXITED (stat))
    buf_printf (&out, "shell command did not exit normally");
  else
    {
      const int cmd_ret = WEXITSTATUS (stat);
      if (!cmd_ret)
	buf_printf (&out, "shell command exited normally");
      else if (cmd_ret == 127)
	buf_printf (&out, "could not execute shell command");
      else
	buf_printf (&out, "shell command exited with error status: %d", cmd_ret);
    }
  return (const char *)out.data;
}

/*
 * Run system(), exiting on error.
 */
bool
system_check (const char* command, const char* error_message, bool fatal)
{
  const int stat = openvpn_system (command);
  if (system_ok (stat))
    return true;
  else
    {
      if (error_message)
	msg ((fatal ? M_FATAL : M_WARN), "%s: %s", error_message, system_error_message (stat));
      return false;
    }
}

/*
 * Initialize random number seed.  random() is only used when "weak" random numbers
 * are acceptable.  OpenSSL routines are always used when cryptographically strong
 * random numbers are required.
 */

void
init_random_seed()
{
#ifndef USE_CRYPTO
  struct timeval tv;

  if (!gettimeofday (&tv, NULL))
    {
      const unsigned int seed = (unsigned int) tv.tv_sec ^ tv.tv_usec;
      srandom (seed);
    }
#endif
}

/* format a time_t as ascii, or use current time if 0 */

const char*
time_string (time_t t)
{
  struct buffer out = alloc_buf_gc (64);

  if (!t)
    t = time (NULL);

  mutex_lock (L_CTIME);
  buf_printf (&out, "%s", ctime (&t));
  mutex_unlock (L_CTIME);
  buf_chomp (&out, '\n');

  return BSTR (&out);
}
