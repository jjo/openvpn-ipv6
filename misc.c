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

#include "memdbg.h"

/* Redefine the top level directory of the filesystem
   to restrict access to files for security */
void
do_chroot (const char *path)
{
#ifdef HAVE_CHROOT
  const char *top = "/";
  if (path)
    {
      if (chroot (path))
	msg (M_ERR, "chroot to '%s' failed", path);
      if (chdir (top))
	msg (M_ERR, "cd to '%s' failed", top);
      msg (M_INFO, "chroot to '%s' and cd to '%s' succeeded", path, top);
    }
#else
  msg (M_FATAL, "Sorry but I can't chroot to '%s' because this operating system doesn't appear to support the chroot() system call", path);
#endif
}

/* Set UID of process */
void
set_user (const char *username)
{
#if defined(HAVE_GETPWNAM) && defined(HAVE_SETUID)
  if (username)
    {
      struct passwd *pw;

      pw = getpwnam (username);
      if (!pw)
	msg (M_ERR, "failed to find UID for user %s", username);
      if (setuid (pw->pw_uid))
	msg (M_ERR, "setuid('%s') failed", username);
      msg (M_INFO, "UID set to %s", username);
    }
#else
  msg (M_FATAL, "Sorry but I can't setuid to '%s' because this operating system doesn't appear to support the getpwname() or setuid() system calls", username);
#endif
}

/* Set GID of process */
void
set_group (const char *groupname)
{
#if defined(HAVE_GETGRNAM) && defined(HAVE_SETGID)
  if (groupname)
    {
      struct group *gr;
      gr = getgrnam (groupname);
      if (!gr)
	msg (M_ERR, "failed to find GID for group %s", groupname);
      if (setgid (gr->gr_gid))
	msg (M_ERR, "setgid('%s') failed", groupname);
      msg (M_INFO, "GID set to %s", groupname);
#ifdef HAVE_SETGROUPS
      {
        gid_t gr_list[1];
	gr_list[0] = gr->gr_gid;
	if (setgroups (1, gr_list))
	  msg (M_ERR, "setgroups('%s') failed", groupname);
      }
#endif
    }
#else
  msg (M_FATAL, "Sorry but I can't setgid to '%s' because this operating system doesn't appear to support the getgrnam() or setgid() system calls", groupname);
#endif
}

/* Change process priority */
void
set_nice (int niceval)
{
#ifdef HAVE_NICE
  if (niceval)
    {
      if (nice (niceval) < 0)
	msg (M_ERR, "nice %d failed", niceval);
      msg (M_INFO, "nice %d succeeded", niceval);
    }
#else
  msg (M_FATAL, "Sorry but I can't set nice priority to '%d' because this operating system doesn't appear to support the nice() system call", niceval);
#endif
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

/* Write our PID to a file */
void
write_pid (const char* filename)
{
#ifdef HAVE_GETPID
  if (filename)
    {
      FILE* fp = fopen (filename, "w");
      const pid_t pid = getpid ();

      if (!fp)
	msg (M_ERR, "Open error on pid file %s", filename);
      fprintf(fp, "%d\n", pid);
      if (fclose (fp))
	msg (M_ERR, "Close error on pid file %s", filename);
    }
#else
  msg (M_FATAL, "Sorry but I can't write my pid to '%s' because this operating system doesn't appear to support the getpid() system call", filename);
#endif
}

/* Disable paging */
void
do_mlockall(bool print_msg)
{
#ifdef HAVE_MLOCKALL
  if (mlockall (MCL_CURRENT | MCL_FUTURE))
    msg (M_ERR, "mlockall failed");
  if (print_msg)
    msg (M_INFO, "mlockall() succeeded");
#else
  msg (M_FATAL, "Sorry but this operating system doesn't appear to support the mlockall() system call");
#endif
}

#ifndef HAVE_DAEMON

int
daemon(int nochdir, int noclose)
{
#if defined(HAVE_FORK) && defined(HAVE_DUP2)
  int fd;

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
    chdir ("/");

  if (!noclose && (fd = open ("/dev/null", O_RDWR, 0)) != -1)
    {
      dup2 (fd, 0);
      dup2 (fd, 1);
      dup2 (fd, 2);
      if (fd > 2)
	close (fd);
    }
#else
  msg (M_FATAL, "Sorry but I can't become a daemon because this operating system doesn't appear to support either the daemon(), fork() or dup2() system calls");
#endif
  return (0);
}

#endif

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
      msg (M_WARN, "WARNING: cannot stat %s", filename);
    }
  else
    {
      if (st.st_mode & (S_IRWXG|S_IRWXO))
	msg (M_WARN, "WARNING: file %s is group or others accessible", filename);
    }
#else
  msg (M_WARN, "WARNING: cannot stat %s (stat function missing)", filename);
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
  return out.data;
}

/*
 * Run system(), exiting on error.
 */
void
system_check (const char* command, const char* error_message, bool fatal)
{
  const int stat = openvpn_system (command);
  if (error_message && !system_ok (stat))
    msg ((fatal ? M_FATAL : M_WARN), "%s: %s", error_message, system_error_message (stat));
}
