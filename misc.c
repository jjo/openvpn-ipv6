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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

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
      errno = 0;
      nice (niceval);
      if (errno != 0)
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
run_script (const char *command,
	    const char *arg,
	    int tun_mtu,
	    int link_mtu,
	    const char *ifconfig_local,
	    const char* ifconfig_remote,
	    const char *context,
	    const char *signal_text,
	    const char *script_type)
{
  if (signal_text)
    setenv_str ("signal", signal_text);
  setenv_str ("script_context", context);
  setenv_int ("tun_mtu", tun_mtu);
  setenv_int ("link_mtu", link_mtu);
  setenv_str ("dev", arg);

  if (command)
    {
      char command_line[512];

      ASSERT (arg);

      if (!ifconfig_local)
	ifconfig_local = "";
      if (!ifconfig_remote)
	ifconfig_remote = "";
      if (!context)
	context = "";

      setenv_str ("script_type", script_type);

      openvpn_snprintf (command_line, sizeof (command_line),
			"%s %s %d %d %s %s %s",
			command,
			arg,
			tun_mtu, link_mtu,
			ifconfig_local, ifconfig_remote,
			context);
      msg (M_INFO, "%s", command_line);
      system_check (command_line, "script failed", true);
    }
}

/* remove non-parameter environmental vars except for signal */
void
del_env_nonparm (int n_tls_id)
{
  setenv_del ("script_context");
  setenv_del ("tun_mtu");
  setenv_del ("link_mtu");
  setenv_del ("dev");
  
  setenv_del ("ifconfig_remote");
  setenv_del ("ifconfig_netmask");
  setenv_del ("ifconfig_broadcast");

  setenv_del ("untrusted_ip");
  setenv_del ("untrusted_port");
  setenv_del ("trusted_ip");
  setenv_del ("trusted_port");

  /* delete tls_id_{n} values */
  {
    int i;
    char buf[64];
    for (i = 0; i < n_tls_id; ++i)
      {
	openvpn_snprintf (buf, sizeof (buf), "tls_id_%d", i);
	setenv_del (buf);
      }
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
      openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    }

  if (setsid() == -1)
    return (-1);

  if (!nochdir)
    openvpn_chdir ("/");

  if (!noclose)
    set_std_files_to_null (false);
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
set_std_files_to_null (bool stdin_only)
{
#if defined(HAVE_DUP) && defined(HAVE_DUP2)
  int fd;
  if ((fd = open ("/dev/null", O_RDWR, 0)) != -1)
    {
      dup2 (fd, 0);
      if (!stdin_only)
	{
	  dup2 (fd, 1);
	  dup2 (fd, 2);
	}
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
save_inetd_socket_descriptor (void)
{
  inetd_socket_descriptor = INETD_SOCKET_DESCRIPTOR;
#if defined(HAVE_DUP) && defined(HAVE_DUP2)
  /* use handle passed by inetd/xinetd */
  if ((inetd_socket_descriptor = dup (INETD_SOCKET_DESCRIPTOR)) < 0)
    msg (M_ERR, "INETD_SOCKET_DESCRIPTOR dup(%d) failed", INETD_SOCKET_DESCRIPTOR);
  set_std_files_to_null (true);
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
warn_if_group_others_accessible (const char* filename)
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
#endif
}

/*
 * convert system() return into a success/failure value
 */
bool
system_ok (int stat)
{
#ifdef WIN32
  return stat == 0;
#else
  return stat != -1 && WIFEXITED (stat) && WEXITSTATUS (stat) == 0;
#endif
}

/*
 * did system() call execute the given command?
 */
bool
system_executed (int stat)
{
#ifdef WIN32
  return stat != -1;
#else
  return stat != -1 && WEXITSTATUS (stat) != 127;
#endif
}

/*
 * Print an error message based on the status code returned by system().
 */
const char *
system_error_message (int stat)
{
  struct buffer out = alloc_buf_gc (512);
#ifdef WIN32
  if (stat == -1)
    buf_printf (&out, "shell command did not execute -- ");
  buf_printf (&out, "system() returned error code %d", stat);
#else
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
#endif
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
	msg ((fatal ? M_FATAL : M_WARN), "%s: %s",
	     error_message,
	     system_error_message (stat));
      return false;
    }
}

/*
 * Initialize random number seed.  random() is only used
 * when "weak" random numbers are acceptable.
 * OpenSSL routines are always used when cryptographically
 * strong random numbers are required.
 */

void
init_random_seed(void)
{
#ifndef USE_CRYPTO
#ifdef HAVE_GETTIMEOFDAY
  struct timeval tv;

  if (!gettimeofday (&tv, NULL))
    {
      const unsigned int seed = (unsigned int) tv.tv_sec ^ tv.tv_usec;
      srandom (seed);
    }
#else /* HAVE_GETTIMEOFDAY */
  const time_t current = time (NULL);
  srandom ((unsigned int)current);
#endif /* HAVE_GETTIMEOFDAY */
#endif /* USE_CRYPTO */
}

/* format a time_t as ascii, or use current time if 0 */

const char*
time_string (time_t t, bool show_usec)
{
  struct buffer out = alloc_buf_gc (64);
  struct timeval tv;

  if (t)
    {
      tv.tv_sec = t;
      tv.tv_usec = 0;
    }
  else
    {
#ifdef HAVE_GETTIMEOFDAY
      if (gettimeofday (&tv, NULL))
#endif
	{
	  tv.tv_sec = time (NULL);
	  tv.tv_usec = 0;
	}
    }

  mutex_lock (L_CTIME);
  buf_printf (&out, "%s", ctime ((const time_t *)&tv.tv_sec));
  mutex_unlock (L_CTIME);
  buf_rmtail (&out, '\n');

  if (show_usec && tv.tv_usec)
    buf_printf (&out, " us=%d", (int)tv.tv_usec);

  return BSTR (&out);
}

/* thread-safe strerror */

const char*
strerror_ts (int errnum)
{
#ifdef HAVE_STRERROR
  struct buffer out = alloc_buf_gc (256);

  mutex_lock (L_STRERR);
  buf_printf (&out, "%s", openvpn_strerror (errnum));
  mutex_unlock (L_STRERR);
  return BSTR (&out);
#else
  return "[error string unavailable]";
#endif
}

/*
 * Set environmental variable (int or string).
 *
 * On Posix, we use putenv for portability,
 * and put up with its painful semantics
 * that require all the support code below.
 */

#ifdef HAVE_PUTENV
static char *estrings[MAX_ENV_STRINGS];

static bool
env_string_equal (const char *s1, const char *s2)
{
  int c;
  ASSERT (s1);
  ASSERT (s2);

  while ((c = *s1++) == *s2++)
    {
      ASSERT (c);
      if (c == '=')
	return true;
    }
  return false;
}

static void
remove_env (char *str)
{
  int i;
  for (i = 0; i < (int) SIZE (estrings); ++i)
    {
      if (estrings[i] && env_string_equal (estrings[i], str))
	{
	  free (estrings[i]);
	  estrings[i] = NULL;
	}
    }
}

static void
add_env (char *str)
{
  int i;
  for (i = 0; i < (int) SIZE (estrings); ++i)
    {
      if (!estrings[i])
	{
	  estrings[i] = str;
	  return;
	}
    }
  msg (M_FATAL, PACKAGE_NAME " environmental variable cache is full (a maximum of %d variables is allowed) -- try increasing MAX_ENV_STRINGS size in misc.h", MAX_ENV_STRINGS);
}

static void
manage_env (char *str)
{
  remove_env (str);
  add_env (str);
}

#endif

void
setenv_int (const char *name, int value)
{
  char buf[64];
  openvpn_snprintf (buf, sizeof(buf), "%d", value);
  setenv_str (name, buf);
}

void
setenv_str (const char *name, const char *value)
{
  ASSERT (name && strlen(name) > 1);
  if (!value)
    value = "";

#if defined(WIN32)
 {
   char buf[256];

   strncpynt (buf, value, sizeof (buf));
   safe_string (buf);
   if (!SetEnvironmentVariable (name, buf))
     msg (M_WARN | M_ERRNO, "SetEnvironmentVariable failed, name='%s', value='%s'", name, buf);
 }
#elif defined(HAVE_PUTENV)
 {
   const int len = strlen(name) + strlen(value) + 2;
   struct buffer out = alloc_buf (len);
   char *str = out.data;
   int status;
   
   buf_printf (&out, "%s %s", name, value);
   safe_string (str);
   str[strlen(name)] = '=';
   mutex_lock (L_PUTENV);
   status = putenv (str);
   mutex_unlock (L_PUTENV);
   if (status)
     msg (M_WARN | M_ERRNO, "putenv('%s') failed", str);
   manage_env (str);
 }
#endif
}

void
setenv_del (const char *name)
{
  ASSERT (name);
#if defined(WIN32)
  SetEnvironmentVariable (name, NULL);
#elif defined(HAVE_PUTENV)
  setenv_str (name, NULL);
#endif
}

/* make cp safe to be passed to system() or set as an environmental variable */
void
safe_string (char *cp)
{
  int c;
  while ((c = *cp))
    {
      if (isalnum (c)
	  || c == '/'
	  || c == '.' || c == '@' || c == '_' || c == '-' || c == '=')
	;
      else
	*cp = '.';
      ++cp;
    }
}


/*
 * taken from busybox networking/ifupdown.c
 */
unsigned int
count_bits(unsigned int a)
{
  unsigned int result;
  result = (a & 0x55) + ((a >> 1) & 0x55);
  result = (result & 0x33) + ((result >> 2) & 0x33);
  return((result & 0x0F) + ((result >> 4) & 0x0F));
}

int
count_netmask_bits(const char *dotted_quad)
{
  unsigned int result, a, b, c, d;
  /* Found a netmask...  Check if it is dotted quad */
  if (sscanf(dotted_quad, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
    return -1;
  result = count_bits(a);
  result += count_bits(b);
  result += count_bits(c);
  result += count_bits(d);
  return ((int)result);
}
