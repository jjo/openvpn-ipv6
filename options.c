/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002 James Yonan <jim@yonan.net>
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
#include "error.h"
#include "openvpn.h"
#include "common.h"
#include "mtu.h"
#include "shaper.h"
#include "crypto.h"
#include "options.h"

#include "memdbg.h"

static const char usage_message[] =
  "%s\n"
  "\n"
  "General Options:\n"
  "--help          : Show options.\n"
  "--version       : Show copyright and version information.\n"
  "--config file   : Read configuration options from file.\n"
  "\n"
  "Tunnel Options:\n"
  "--local host    : Local host name or ip address.\n"
  "--remote host   : Remote host name or ip address.\n"
  "--resolv-retry n: If hostname resolve fails for --local or --remote, retry\n"
  "                  resolve for n seconds before failing (disabled by default).\n"
  "--float         : Allow remote to change its IP address/port, such as through\n"
  "                  DHCP (this is the default if --remote is not used).\n"
  "--ipchange cmd  : Execute shell command cmd on remote ip address initial\n"
  "                  setting or change -- execute as: cmd ip-address port#\n"
  "                  (',' may be used to separate multiple args in cmd)\n"
  "--port port     : UDP port # for both local and remote.\n"
  "--lport port    : UDP port # for local (default=%d).\n"
  "--rport port    : UDP port # for remote (default=%d).\n"
  "--nobind        : Do not bind to local address and port.\n"
  "--dev tunX|tapX : tun/tap device (X can be omitted for dynamic device in\n"
  "                  Linux 2.4+).\n"
  "--dev-type dt   : Which device type are we using? (dt = tun or tap) Use\n"
  "                  this option only if the tun/tap device used with --dev\n"
  "                  does not begin with \"tun\" or \"tap\".\n"
  "--dev-node node : Explicitly set the device node rather than using\n"
  "                  /dev/net/tun, /dev/tun, /dev/tap, etc.\n"
  "--tun-ipv6      : Build tun link capable of forwarding IPv6 traffic.\n"
  "--ifconfig l r  : Configure tun device to use IP address l as a local\n"
  "                  endpoint and r as a remote endpoint.  l & r should be\n"
  "                  swapped on the other peer.  l & r must be private\n"
  "                  addresses outside of the subnets used by either peer.\n"
  "                  Implies --udp-mtu %d if neither --udp-mtu or --tun-mtu\n"
  "                  explicitly specified.\n"
  "--shaper n      : Restrict output to peer to n bytes per second.\n"
  "--inactive n    : Exit after n seconds of inactivity on tun/tap device.\n"
  "--ping-exit n   : Exit if n seconds pass without reception of remote ping.\n"
  "--ping-restart n: Restart if n seconds pass without reception of remote ping.\n"
  "--ping-timer-rem: Run the --ping-exit/--ping-restart timer only if we have a\n"
  "                  remote address.\n"
  "--ping n        : Ping remote once every n seconds over UDP port.\n"
  "--persist-tun   : Keep tun/tap device open across SIGUSR1 or --ping-restart.\n"
  "--persist-remote-ip : Keep remote IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-local-ip  : Keep local IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-key   : Don't re-read key files across SIGUSR1 or --ping-restart.\n"
  "--tun-mtu n     : Take the tun/tap device MTU to be n and derive the\n"
  "                  UDP MTU from it (default=%d).\n"
  "--tun-mtu-extra n : Assume that tun/tap device might return as many as n bytes\n"
  "                  more than the tun-mtu size on read (default=%d).\n"
  "--udp-mtu n     : Take the UDP device MTU to be n and derive the tun MTU\n"
  "                  from it (disabled by default).\n"
  "--mlock         : Disable Paging -- ensures key material and tunnel\n"
  "                  data will never be written to disk.\n"
  "--up cmd        : Shell cmd to execute after successful tun device open.\n"
  "                  Execute as: cmd tun/tap-dev tun-mtu udp-mtu \\\n"
  "                              ifconfig-local-ip ifconfig-remote-ip\n"
  "                  (pre --user or --group UID/GID change)\n"
  "--down cmd      : Shell cmd to run after tun device close.\n"
  "                  (post --user/--group UID/GID change and/or --chroot)\n"
  "                  (script parameters are same as --up option)\n"
  "--user user     : Set UID to user after initialization.\n"
  "--group group   : Set GID to group after initialization.\n"
  "--chroot dir    : Chroot to this directory before initialization.\n"
  "--cd dir        : Change to this directory before initialization.\n"
  "--daemon        : Become a daemon.\n"
  "--inetd         : Run as an inetd or xinetd server.\n"
  "--writepid file : Write main process ID to file.\n"
  "--nice n        : Change process priority (>0 = lower, <0 = higher).\n"
#ifdef USE_PTHREAD
  "--nice-work n   : Change thread priority of work thread.  The work\n"
  "                  thread is used for background processing such as\n"
  "                  RSA key number crunching.\n"
#endif
  "--verb n        : Set output verbosity to n (default=%d):\n"
  "                  (Level 5 is recommended if you want a good summary\n"
  "                  of what's happening without being swamped by output).\n"
  "                : 0 -- no output except fatal errors\n"
  "                : 1 -- startup info + connection initiated messages +\n"
  "                       non-fatal encryption & net errors\n"
  "                : 2 -- show all parameter settings\n"
  "                : 3 -- show key negotiations + --gremlin net outages\n"
  "                : 4 -- show partial TLS debug info\n"
  "                : 5 -- show adaptive compress info\n"
  "                : 6 -- show keys\n"
  "                : 7 -- show verbose key negotiations\n"
  "                : 8 -- show all debug info\n"
  "--mute n        : Log at most n consecutive messages in the same category.\n"
  "--gremlin       : Simulate dropped & corrupted packets + network outages\n"
  "                  to test robustness of protocol (for debugging only).\n"
#ifdef USE_LZO
  "--comp-lzo      : Use fast LZO compression -- may add up to 1 byte per\n"
  "                  packet for uncompressible data.\n"
  "--comp-noadapt  : Don't use adaptive compression when --comp-lzo\n"
  "                  is specified.\n"
#endif
#ifdef USE_CRYPTO
  "\n"
  "Data Channel Encryption Options (must be compatible between peers):\n"
  "(These options are meaningful for both Static Key & TLS-mode)\n"
  "--secret file   : Enable Static Key encryption mode (non-TLS),\n"
  "                  use shared secret file, generate with --genkey.\n"
  "--auth alg      : Authenticate packets with HMAC using message\n"
  "                  digest algorithm alg (default=%s).\n"
  "                  (usually adds 16 or 20 bytes per packet)\n"
  "                  Set alg=none to disable authentication.\n"
  "--cipher alg    : Encrypt packets with cipher algorithm alg\n"
  "                  (default=%s).\n"
  "                  Set alg=none to disable encryption.\n"
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  "--keysize n     : Size of cipher key in bits (optional).\n"
  "                  If unspecified, defaults to cipher-specific default.\n"
#endif
  "--no-replay     : Disable replay protection.\n"
  "--no-iv         : Disable cipher IV -- only allowed with CBC mode ciphers.\n"
  "--replay-persist file : Persist replay-protection state across sessions\n"
  "                  using file.\n"
  "--test-crypto   : Run a self-test of crypto features enabled.\n"
  "                  For debugging only.\n"
#ifdef USE_SSL
  "\n"
  "TLS Key Negotiation Options:\n"
  "(These options are meaningful only for TLS-mode)\n"
  "--tls-server    : Enable TLS and assume server role during TLS handshake.\n"
  "--tls-client    : Enable TLS and assume client role during TLS handshake.\n"
  "--ca file       : Certificate authority file in .pem format containing\n"
  "                  root certificate.\n"
  "--dh file       : File containing Diffie Hellman parameters\n"
  "                  in .pem format (for --tls-server only).\n"
  "                  Use \"openssl dhparam -out dh1024.pem 1024\" to generate.\n"
  "--cert file     : Local certificate in .pem format -- must be signed\n"
  "                  by a Certificate Authority in --ca file.\n"
  "--key file      : Local private key in .pem format.\n"
  "--tls-cipher l  : A list l of allowable TLS ciphers separated by | (optional).\n"
  "                : Use --show-tls to see a list of supported TLS ciphers.\n"
  "--tls-timeout n : Packet retransmit timeout on TLS control channel\n"
  "                  if no ACK from remote within n seconds (default=%d).\n"
  "--reneg-bytes n : Renegotiate data chan. key after n bytes sent and recvd.\n"
  "--reneg-pkts n  : Renegotiate data chan. key after n packets sent and recvd.\n"
  "--reneg-sec n   : Renegotiate data chan. key after n seconds (default=%d).\n"
  "--hand-window n : Data channel key exchange must finalize within n seconds\n"
  "                  of handshake initiation by any peer (default=%d).\n"
  "--tran-window n : Transition window -- old key can live this many seconds\n"
  "                  after new key renegotiation begins (default=%d).\n"
  "--single-session: Allow only one session (reset state on restart).\n"
  "--tls-auth f    : Add an additional layer of authentication on top of the TLS\n"
  "                  control channel to protect against DoS attacks.\n"
  "                  f (required) is a shared-secret passphrase file.\n"
  "--askpass       : Get PEM password from controlling tty before we daemonize.\n"
  "--tls-verify cmd: Execute shell command cmd to verify the X509 name of a\n"
  "                  pending TLS connection that has otherwise passed all other\n"
  "                  tests of certification.  cmd should return 0 to allow\n"
  "                  TLS handshake to proceed, or 1 to fail.  (cmd is\n"
  "                  executed as 'cmd certificate_depth X509_NAME_oneline')\n"
  "                  (',' may be used to separate multiple args in cmd)\n"
  "--disable-occ   : Disable options compatibility check between peers.\n"
#endif				/* USE_SSL */
  "\n"
  "SSL Library information:\n"
  "--show-ciphers  : Show all cipher algorithms to use with --cipher option.\n"
  "--show-digests  : Show all message digest algorithms to use with --auth option.\n"
#ifdef USE_SSL
  "--show-tls      : Show all TLS ciphers (TLS used only as a control channel).\n"
#endif
  "\n"
  "Generate a random key (only for non-TLS static key encryption mode):\n"
  "--genkey        : Generate a random key to be used as a shared secret,\n"
  "                  for use with the --secret option.\n"
  "--secret file   : Write key to file.\n"
#endif				/* USE_CRYPTO */
#ifdef TUNSETPERSIST
  "\n"
  "Tun/Tap config mode (available with linux 2.4+):\n"
  "--mktun         : Create a persistent tunnel.\n"
  "--rmtun         : Remove a persistent tunnel.\n"
  "--dev tunX|tapX : tun/tap device\n"
  "--dev-type dt   : Device type.  See tunnel options above for details.\n"
#endif
 ;

/*
 * This is where the options defaults go.
 * Any option not explicitly set here
 * will be set to 0.
 */
void
init_options (struct options *o)
{
  CLEAR (*o);
#ifdef TUNSETPERSIST
  o->persist_mode = 1;
#endif
  o->local_port = o->remote_port = 5000;
  o->verbosity = 1;
  o->bind_local = true;
  o->tun_mtu = DEFAULT_TUN_MTU;
  o->udp_mtu = DEFAULT_UDP_MTU;
#ifdef USE_LZO
  o->comp_lzo_adaptive = true;
#endif
#ifdef USE_CRYPTO
  o->ciphername = "BF-CBC";
  o->ciphername_defined = true;
  o->authname = "SHA1";
  o->authname_defined = true;
  o->packet_id = true;
  o->iv = true;
#ifdef USE_SSL
  o->tls_timeout = 5;
  o->renegotiate_seconds = 3600;
  o->handshake_window = 60;
  o->transition_window = 3600;
#endif
#endif
}

#define SHOW_PARM(name, value, format) msg(D_SHOW_PARMS, "  " #name " = " format, (value))
#define SHOW_STR(var)  SHOW_PARM(var, (o->var ? o->var : "[UNDEF]"), "'%s'")
#define SHOW_INT(var)  SHOW_PARM(var, o->var, "%d")
#define SHOW_BOOL(var) SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s");

void
show_settings (const struct options *o)
{
  msg (D_SHOW_PARMS, "Current Parameter Settings:");

#ifdef TUNSETPERSIST
  SHOW_BOOL (persist_config);
  SHOW_INT (persist_mode);
#endif

#ifdef USE_CRYPTO
  SHOW_BOOL (show_ciphers);
  SHOW_BOOL (show_digests);
  SHOW_BOOL (genkey);
#ifdef USE_SSL
  SHOW_BOOL (askpass);
  SHOW_BOOL (show_tls_ciphers);
#endif
#endif

  SHOW_STR (local);
  SHOW_STR (remote);

  SHOW_INT (local_port);
  SHOW_INT (remote_port);
  SHOW_BOOL (remote_float);
  SHOW_STR (ipchange);
  SHOW_BOOL (bind_local);
  SHOW_STR (dev);
  SHOW_STR (dev_type);
  SHOW_STR (dev_node);
  SHOW_BOOL (tun_ipv6);
  SHOW_STR (ifconfig_local);
  SHOW_STR (ifconfig_remote);
  SHOW_INT (shaper);
  SHOW_INT (tun_mtu);
  SHOW_BOOL (tun_mtu_defined);
  SHOW_INT (udp_mtu);
  SHOW_BOOL (udp_mtu_defined);
  SHOW_INT (tun_mtu_extra);
  SHOW_BOOL (mlock);
  SHOW_INT (inactivity_timeout);
  SHOW_INT (ping_send_timeout);
  SHOW_INT (ping_rec_timeout);
  SHOW_INT (ping_rec_timeout_action);
  SHOW_BOOL (ping_timer_remote);

  SHOW_BOOL (persist_tun);
  SHOW_BOOL (persist_local_ip);
  SHOW_BOOL (persist_remote_ip);
  SHOW_BOOL (persist_key);

  SHOW_INT (resolve_retry_seconds);

  SHOW_STR (username);
  SHOW_STR (groupname);
  SHOW_STR (chroot_dir);
  SHOW_STR (cd_dir);
  SHOW_STR (writepid);
  SHOW_STR (up_script);
  SHOW_STR (down_script);
  SHOW_BOOL (daemon);
  SHOW_BOOL (inetd);
  SHOW_INT (nice);
  SHOW_INT (verbosity);
  SHOW_INT (mute);
  SHOW_BOOL (gremlin);

#ifdef USE_LZO
  SHOW_BOOL (comp_lzo);
  SHOW_BOOL (comp_lzo_adaptive);
#endif

#ifdef USE_CRYPTO
  SHOW_STR (shared_secret_file);
  SHOW_BOOL (ciphername_defined);
  SHOW_STR (ciphername);
  SHOW_BOOL (authname_defined);
  SHOW_STR (authname);
  SHOW_INT (keysize);
  SHOW_BOOL (packet_id);
  SHOW_STR (packet_id_file);
  SHOW_BOOL (iv);
  SHOW_BOOL (test_crypto);

#ifdef USE_SSL
  SHOW_BOOL (tls_server);
  SHOW_BOOL (tls_client);
  SHOW_STR (ca_file);
  SHOW_STR (dh_file);
  SHOW_STR (cert_file);
  SHOW_STR (priv_key_file);
  SHOW_STR (cipher_list);
  SHOW_STR (tls_verify);

  SHOW_INT (tls_timeout);

  SHOW_INT (renegotiate_bytes);
  SHOW_INT (renegotiate_packets);
  SHOW_INT (renegotiate_seconds);

  SHOW_INT (handshake_window);
  SHOW_INT (transition_window);

  SHOW_BOOL (single_session);
  SHOW_BOOL (disable_occ);

  SHOW_STR (tls_auth_file);
#endif
#endif
}

#undef SHOW_PARM
#undef SHOW_STR
#undef SHOW_INT
#undef SHOW_BOOL

#if defined(USE_CRYPTO) && defined(USE_SSL)

/*
 * Build an options string to represent data channel encryption options.
 * This string must match exactly between peers.  The keysize is checked
 * separately by read_key().
 *
 * TODO: add --dev-type tun|tap|null to TLS negotiation string using dev_type_string()
 */
char *
options_string (const struct options *o)
{
  struct buffer out = alloc_buf (256);
  buf_printf (&out, "V1");
  if (o->ciphername_defined)
    buf_printf (&out, " --cipher %s", o->ciphername);
  if (o->authname_defined)
    buf_printf (&out, " --auth %s", o->authname);

  if (!o->packet_id)
    buf_printf (&out, " --no-replay");
  if (!o->iv)
    buf_printf (&out, " --no-iv");
#ifdef USE_LZO
  if (o->comp_lzo)
    buf_printf (&out, " --comp-lzo");
#endif
  return out.data;
}

#endif

static char *
comma_to_space (const char *src)
{
  char *ret = (char *) gc_malloc (strlen (src) + 1);
  char *dest = ret;
  char c;

  do
    {
      c = *src++;
      if (c == ',')
	c = ' ';
      *dest++ = c;
    }
  while (c);
  return ret;
}

static void
usage ()
{
  struct options o;
  init_options (&o);
#if defined(USE_CRYPTO) && defined(USE_SSL)
  printf (usage_message,
	  TITLE, o.local_port, o.remote_port, o.udp_mtu, o.tun_mtu, o.tun_mtu_extra,
	  o.verbosity, o.authname, o.ciphername, o.tls_timeout,
	  o.renegotiate_seconds, o.handshake_window, o.transition_window);
#elif defined(USE_CRYPTO)
  printf (usage_message,
	  TITLE, o.local_port, o.remote_port, o.udp_mtu, o.tun_mtu, o.tun_mtu_extra,
	  o.verbosity, o.authname, o.ciphername);
#else
  printf (usage_message,
	  TITLE, o.local_port, o.remote_port, o.udp_mtu, o.tun_mtu, o.tun_mtu_extra,
	  o.verbosity);
#endif

  exit (1);
}

void
usage_small ()
{
  msg (M_WARN, "Use --help for more information");
  exit (1);
}

void
usage_version ()
{
  printf ("%s\nCopyright (C) 2002 James Yonan <jim@yonan.net>\n", TITLE);
  exit (1);
}

void
notnull (const char *arg, const char *description)
{
  if (!arg)
    {
      msg (M_WARN, "Options error: You must define %s", description);
      usage_small ();
    }
}

bool
string_defined_equal (const char *s1, const char *s2)
{
  if (s1 && s2)
    return !strcmp (s1, s2);
  else
    return false;
}

static void
ping_rec_err ()
{
  msg (M_WARN, "Options error: only one of --ping-exit or --ping-restart options may be specified");
  usage_small ();
}

static int
positive (int i)
{
  return i < 0 ? 0 : i;
}

static bool
space (char c)
{
  return c == '\0' || isspace (c);
}

static int
parse_line (char *line, char *p[], int n, const char *file, int line_num)
{
  int ret = 0;
  char *c = line;
  char *start = NULL;

  /*
   * Parse states:
   * 0 -- Initial
   * 1 -- Reading non-quoted parm
   * 2 -- Leading quote
   * 3 -- Reading quoted parm
   * 4 -- First char after parm
   */
  int state = 0;

  do
    {
      if (state == 0)
	{
	  if (!space (*c))
	    {
	      if (*c == ';' || *c == '#') /* comment */
		break;
	      if (*c == '\"')
		state = 2;
	      else
		{
		  start = c;
		  state = 1;
		}
	    }
	}
      else if (state == 1)
	{
	  if (space (*c))
	    state = 4;
	}
      else if (state == 2)
	{
	  start = c;
	  state = 3;
	}
      else if (state == 3)
	{
	  if (*c == '\"')
	    state = 4;
	}
      if (state == 4)
	{
	  const int len = c - start;
	  ASSERT (len > 0);
	  p[ret] = gc_malloc (len + 1);
	  memcpy (p[ret], start, len);
	  p[ret][len] = '\0';
	  state = 0;
	  if (++ret >= n)
	    break;
	}
    } while (*c++ != '\0');

  if (state == 2 || state == 3)
	msg (M_FATAL, "No closing quotation (\") in %s:%d", file, line_num);
  if (state)
	msg (M_FATAL, "Residual parse state (%d) in %s:%d", state, file, line_num);
#if 0
  {
    int i;
    for (i = 0; i < ret; ++i)
      {
	msg (M_INFO, "%s:%d ARG[%d] '%s'", file, line_num, i, p[i]);
      }
  }
#endif
    return ret;
}

static int
add_option (struct options *options, int i, char *p1, char *p2, char *p3,
	    const char* file, int line, int level);

static void
read_config_file (struct options *options, const char* file, int level,
		  const char* top_file, int top_line)
{
  const int max_recursive_levels = 10;
  FILE *fp;
  int line_num;
  char line[256];

  ++level;
  if (level > max_recursive_levels)
    msg (M_FATAL, "In %s:%d: Maximum recursive include levels exceeded in include attempt of file %s -- probably you have a configuration file that tries to include itself.", top_file, top_line, file);

  fp = fopen (file, "r");
  if (!fp)
    msg (M_ERR, "In %s:%d: Error opening configuration file: %s", top_file, top_line, file);

  line_num = 0;
  while (fgets(line, sizeof (line), fp))
    {
      char *p[3];
      int nargs;
      CLEAR (p);
      ++line_num;
      nargs = parse_line (line, p, 3, file, line_num);
      if (nargs)
	{
	  char *p0 = p[0];
	  if (strlen (p0) >= 3 && !strncmp (p0, "--", 2))
	    p0 += 2;
	  add_option (options, 0, p0, p[1], p[2], file, line_num, level);
	}
    }
  fclose (fp);
}

static int
add_option (struct options *options, int i, char *p1, char *p2, char *p3,
	    const char* file, int line, int level)
{
  if (!file)
    {
      file = "[CMD-LINE]";
      line = 1;
    }
  if (streq (p1, "help"))
    {
      usage ();
    }
  if (streq (p1, "version"))
    {
      usage_version ();
    }
  else if (streq (p1, "config") && p2)
    {
      ++i;
      read_config_file (options, p2, level, file, line);
    }
  else if (streq (p1, "dev") && p2)
    {
      ++i;
      options->dev = p2;
    }
  else if (streq (p1, "dev-type") && p2)
    {
      ++i;
      options->dev_type = p2;
    }
  else if (streq (p1, "dev-node") && p2)
    {
      ++i;
      options->dev_node = p2;
    }
  else if (streq (p1, "tun-ipv6"))
    {
      options->tun_ipv6 = true;
    }
  else if (streq (p1, "ifconfig") && p2 && p3)
    {
      options->ifconfig_local = p2;
      options->ifconfig_remote = p3;
      i += 2;
    }
  else if (streq (p1, "local") && p2)
    {
      ++i;
      options->local = p2;
    }
  else if (streq (p1, "remote") && p2)
    {
      ++i;
      options->remote = p2;
    }
  else if (streq (p1, "resolv-retry") && p2)
    {
      ++i;
      options->resolve_retry_seconds = positive (atoi (p2));
    }
  else if (streq (p1, "ipchange") && p2)
    {
      ++i;
      options->ipchange = comma_to_space (p2);
    }
  else if (streq (p1, "float"))
    {
      options->remote_float = true;
    }
  else if (streq (p1, "gremlin"))
    {
      options->gremlin = true;
    }
  else if (streq (p1, "user") && p2)
    {
      ++i;
      options->username = p2;
    }
  else if (streq (p1, "group") && p2)
    {
      ++i;
      options->groupname = p2;
    }
  else if (streq (p1, "chroot") && p2)
    {
      ++i;
      options->chroot_dir = p2;
    }
  else if (streq (p1, "cd") && p2)
    {
      ++i;
      options->cd_dir = p2;
      if (chdir (p2))
	msg (M_ERR, "cd to '%s' failed", p2);
    }
  else if (streq (p1, "writepid") && p2)
    {
      ++i;
      options->writepid = p2;
    }
  else if (streq (p1, "up") && p2)
    {
      ++i;
      options->up_script = p2;
    }
  else if (streq (p1, "down") && p2)
    {
      ++i;
      options->down_script = p2;
    }
  else if (streq (p1, "daemon"))
    {
      options->daemon = true;
    }
  else if (streq (p1, "inetd"))
    {
      if (!options->inetd)
	{
	  options->inetd = true;
	  become_inetd_server ();
	}
    }
  else if (streq (p1, "mlock"))
    {
      options->mlock = true;
    }
  else if (streq (p1, "verb") && p2)
    {
      ++i;
      options->verbosity = positive (atoi (p2));
    }
  else if (streq (p1, "mute") && p2)
    {
      ++i;
      options->mute = positive (atoi (p2));
    }
  else if (streq (p1, "udp-mtu") && p2)
    {
      ++i;
      options->udp_mtu = positive (atoi (p2));
      options->udp_mtu_defined = true;
    }
  else if (streq (p1, "tun-mtu") && p2)
    {
      ++i;
      options->tun_mtu = positive (atoi (p2));
      options->tun_mtu_defined = true;
    }
  else if (streq (p1, "tun-mtu-extra") && p2)
    {
      ++i;
      options->tun_mtu_extra = positive (atoi (p2));
    }
  else if (streq (p1, "nice") && p2)
    {
      ++i;
      options->nice = atoi (p2);
    }
#ifdef USE_PTHREAD
  else if (streq (p1, "nice-work") && p2)
    {
      ++i;
      options->nice_work = atoi (p2);
    }
#endif
  else if (streq (p1, "shaper") && p2)
    {
      ++i;
      options->shaper = atoi (p2);
      if (options->shaper < SHAPER_MIN || options->shaper > SHAPER_MAX)
	{
	  msg (M_WARN, "bad shaper value, must be between %d and %d",
	       SHAPER_MIN, SHAPER_MAX);
	  usage_small ();
	}
    }
  else if (streq (p1, "port") && p2)
    {
      ++i;
      options->local_port = options->remote_port = atoi (p2);
      if (options->local_port <= 0 || options->remote_port <= 0)
	{
	  msg (M_WARN, "Bad port number: %s", p2);
	  usage_small ();
	}
    }
  else if (streq (p1, "lport") && p2)
    {
      ++i;
      options->local_port = atoi (p2);
      if (options->local_port <= 0)
	{
	  msg (M_WARN, "Bad local port number: %s", p2);
	  usage_small ();
	}
    }
  else if (streq (p1, "rport") && p2)
    {
      ++i;
      options->remote_port = atoi (p2);
      if (options->remote_port <= 0)
	{
	  msg (M_WARN, "Bad remote port number: %s", p2);
	  usage_small ();
	}
    }
  else if (streq (p1, "nobind"))
    {
      options->bind_local = false;
    }
  else if (streq (p1, "inactive") && p2)
    {
      ++i;
      options->inactivity_timeout = positive (atoi (p2));
    }
  else if (streq (p1, "ping") && p2)
    {
      ++i;
      options->ping_send_timeout = positive (atoi (p2));
    }
  else if (streq (p1, "ping-exit") && p2)
    {
      ++i;
      if (options->ping_rec_timeout_action)
	ping_rec_err();
      options->ping_rec_timeout = positive (atoi (p2));
      options->ping_rec_timeout_action = PING_EXIT;
    }
  else if (streq (p1, "ping-restart") && p2)
    {
      ++i;
      if (options->ping_rec_timeout_action)
	ping_rec_err();
      options->ping_rec_timeout = positive (atoi (p2));
      options->ping_rec_timeout_action = PING_RESTART;
    }
  else if (streq (p1, "ping-timer-rem"))
    {
      options->ping_timer_remote = true;
    }
  else if (streq (p1, "persist-tun"))
    {
      options->persist_tun = true;
    }
  else if (streq (p1, "persist-key"))
    {
      options->persist_key = true;
    }
  else if (streq (p1, "persist-local-ip"))
    {
      options->persist_local_ip = true;
    }
  else if (streq (p1, "persist-remote-ip"))
    {
      options->persist_remote_ip = true;
    }
#ifdef USE_LZO
  else if (streq (p1, "comp-lzo"))
    {
      options->comp_lzo = true;
    }
  else if (streq (p1, "comp-noadapt"))
    {
      options->comp_lzo_adaptive = false;
    }
#endif /* USE_LZO */
#ifdef USE_CRYPTO
  else if (streq (p1, "show-ciphers"))
    {
      options->show_ciphers = true;
    }
  else if (streq (p1, "show-digests"))
    {
      options->show_digests = true;
    }
  else if (streq (p1, "secret") && p2)
    {
      ++i;
      options->shared_secret_file = p2;
    }
  else if (streq (p1, "genkey"))
    {
      options->genkey = true;
    }
  else if (streq (p1, "auth") && p2)
    {
      ++i;
      options->authname_defined = true;
      options->authname = p2;
      if (streq (options->authname, "none"))
	{
	  options->authname_defined = false;
	  options->authname = NULL;
	}
    }
  else if (streq (p1, "auth"))
    {
      options->authname_defined = true;
    }
  else if (streq (p1, "cipher") && p2)
    {
      ++i;
      options->ciphername_defined = true;
      options->ciphername = p2;
      if (streq (options->ciphername, "none"))
	{
	  options->ciphername_defined = false;
	  options->ciphername = NULL;
	}
    }
  else if (streq (p1, "cipher"))
    {
      options->ciphername_defined = true;
    }
  else if (streq (p1, "no-replay"))
    {
      options->packet_id = false;
    }
  else if (streq (p1, "no-iv"))
    {
      options->iv = false;
    }
  else if (streq (p1, "replay-persist") && p2)
    {
      ++i;
      options->packet_id_file = p2;
    }
  else if (streq (p1, "test-crypto"))
    {
      options->test_crypto = true;
    }
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  else if (streq (p1, "keysize") && p2)
    {
      ++i;
      options->keysize = atoi (p2) / 8;
      if (options->keysize < 0 || options->keysize > MAX_CIPHER_KEY_LENGTH)
	{
	  msg (M_WARN, "Bad keysize: %s", p2);
	  usage_small ();
	}
    }
#endif
#ifdef USE_SSL
  else if (streq (p1, "show-tls"))
    {
      options->show_tls_ciphers = true;
    }
  else if (streq (p1, "tls-server"))
    {
      options->tls_server = true;
    }
  else if (streq (p1, "tls-client"))
    {
      options->tls_client = true;
    }
  else if (streq (p1, "ca") && p2)
    {
      ++i;
      options->ca_file = p2;
    }
  else if (streq (p1, "dh") && p2)
    {
      ++i;
      options->dh_file = p2;
    }
  else if (streq (p1, "cert") && p2)
    {
      ++i;
      options->cert_file = p2;
    }
  else if (streq (p1, "key") && p2)
    {
      ++i;
      options->priv_key_file = p2;
    }
  else if (streq (p1, "askpass"))
    {
      options->askpass = true;
    }
  else if (streq (p1, "single-session"))
    {
      options->single_session = true;
    }
  else if (streq (p1, "disable-occ"))
    {
      options->disable_occ = true;
    }
  else if (streq (p1, "tls-cipher") && p2)
    {
      ++i;
      options->cipher_list = p2;
    }
  else if (streq (p1, "tls-verify") && p2)
    {
      ++i;
      options->tls_verify = comma_to_space (p2);
    }
  else if (streq (p1, "tls_timeout") && p2)
    {
      ++i;
      options->tls_timeout = positive (atoi (p2));
    }
  else if (streq (p1, "reneg-bytes") && p2)
    {
      ++i;
      options->renegotiate_bytes = positive (atoi (p2));
    }
  else if (streq (p1, "reneg-pkts") && p2)
    {
      ++i;
      options->renegotiate_packets = positive (atoi (p2));
    }
  else if (streq (p1, "reneg-sec") && p2)
    {
      ++i;
      options->renegotiate_seconds = positive (atoi (p2));
    }
  else if (streq (p1, "hand-window") && p2)
    {
      ++i;
      options->handshake_window = positive (atoi (p2));
    }
  else if (streq (p1, "tran-window") && p2)
    {
      ++i;
      options->transition_window = positive (atoi (p2));
    }
  else if (streq (p1, "tls-auth") && p2)
    {
      ++i;
      options->tls_auth_file = p2;
    }
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
#ifdef TUNSETPERSIST
  else if (streq (p1, "rmtun"))
    {
      options->persist_config = true;
      options->persist_mode = 0;
    }
  else if (streq (p1, "mktun"))
    {
      options->persist_config = true;
      options->persist_mode = 1;
    }
#endif
  else
    {
      if (file)
	msg (M_WARN, "Unrecognized option or missing parameter(s) in %s:%d: %s", file, line, p1);
      else
	msg (M_WARN, "Unrecognized option or missing parameter(s): --%s", p1);
      usage_small ();
    }
  return i;
}

void
parse_argv (struct options* options, int argc, char *argv[])
{
  int i;

  /* usage message */
  if (argc <= 1)
    usage ();

  /* parse command line */
  for (i = 1; i < argc; ++i)
    {
      char *p1 = argv[i];
      char *p2 = NULL;
      char *p3 = NULL;

      if (strncmp(p1, "--", 2))
	{
	  msg (M_WARN, "I'm trying to parse \"%s\" as an --option parameter but I don't see a leading '--'", p1);
	  usage_small ();
	}
      p1 += 2;
      if (i + 1 < argc)
	{
	  p2 = argv[i + 1];
	  if (!strncmp (p2, "--", 2))
	    p2 = NULL;
	}
      if (i + 2 < argc)
	{
	  p3 = argv[i + 2];
	  if (!strncmp (p3, "--", 2))
	    p3 = NULL;
	}
      i = add_option (options, i, p1, p2, p3, NULL, 0, 0);
    }
}
