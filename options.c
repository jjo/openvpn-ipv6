/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

/*
 * 2004-01-28: Added Socks5 proxy support
 *   (Christof Meerwald, http://cmeerw.org)
 */

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#include "buffer.h"
#include "error.h"
#include "openvpn.h"
#include "common.h"
#include "shaper.h"
#include "crypto.h"
#include "ssl.h"
#include "options.h"
#include "openvpn.h"
#include "misc.h"
#include "socket.h"
#include "packet_id.h"
#include "win32.h"

#include "memdbg.h"

const char title_string[] =
  PACKAGE_STRING
  " " TARGET_ALIAS
#ifdef USE_CRYPTO
#ifdef USE_SSL
  " [SSL]"
#else
  " [CRYPTO]"
#endif
#endif
#ifdef USE_LZO
  " [LZO]"
#endif
#ifdef USE_PTHREAD
  " [PTHREAD]"
#endif
  " built on " __DATE__
;

static const char usage_message[] =
  "%s\n"
  "\n"
  "General Options:\n"
  "--config file   : Read configuration options from file.\n"
  "--help          : Show options.\n"
  "--version       : Show copyright and version information.\n"
  "\n"
  "Tunnel Options:\n"
  "--local host    : Local host name or ip address.\n"
  "--remote host   : Remote host name or ip address.\n"
  "--proto p       : Use protocol p for communicating with peer.\n"
  "                  p = udp (default), tcp-server, or tcp-client\n"
  "--connect-retry n : For --proto tcp-client, number of seconds to wait\n"
  "                  between connection retries (default=%d).\n"
  "--http-proxy s p [up]: Connect to remote host through an HTTP proxy at address\n"
  "                  s and port p.  If proxy authentication is required, up is a\n"
  "                  file containing username/password on 2 lines.\n"
  "--http-proxy-retry : Retry indefinitely on HTTP proxy errors.\n"
  "--socks-proxy s [p]: Connect to remote host through a Socks5 proxy at address\n"
  "                  s and port p (default port = 1080).\n"
  "--socks-proxy-retry : Retry indefinitely on Socks proxy errors.\n"
  "--resolv-retry n: If hostname resolve fails for --remote, retry\n"
  "                  resolve for n seconds before failing (disabled by default).\n"
  "                  Set n=\"infinite\" to retry indefinitely.\n"
  "--float         : Allow remote to change its IP address/port, such as through\n"
  "                  DHCP (this is the default if --remote is not used).\n"
  "--ipchange cmd  : Execute shell command cmd on remote ip address initial\n"
  "                  setting or change -- execute as: cmd ip-address port#\n"
  "--port port     : TCP/UDP port # for both local and remote.\n"
  "--lport port    : TCP/UDP port # for local (default=%d).\n"
  "--rport port    : TCP/UDP port # for remote (default=%d).\n"
  "--nobind        : Do not bind to local address and port.\n"
  "--dev tunX|tapX : TUN/TAP device (X can be omitted for dynamic device.\n"
  "--dev-type dt   : Which device type are we using? (dt = tun or tap) Use\n"
  "                  this option only if the TUN/TAP device used with --dev\n"
  "                  does not begin with \"tun\" or \"tap\".\n"
  "--dev-node node : Explicitly set the device node rather than using\n"
  "                  /dev/net/tun, /dev/tun, /dev/tap, etc.\n"
  "--tun-ipv6      : Build tun link capable of forwarding IPv6 traffic.\n"
  "--ifconfig l rn : TUN: configure device to use IP address l as a local\n"
  "                  endpoint and rn as a remote endpoint.  l & rn should be\n"
  "                  swapped on the other peer.  l & rn must be private\n"
  "                  addresses outside of the subnets used by either peer.\n"
  "                  TAP: configure device to use IP address l as a local\n"
  "                  endpoint and rn as a subnet mask.\n"
  "--ifconfig-noexec : Don't actually execute ifconfig/netsh command, instead\n"
  "                    pass --ifconfig parms by environment to scripts.\n"
  "--ifconfig-nowarn : Don't warn if the --ifconfig option on this side of the\n"
  "                    connection doesn't match the remote side.\n"
  "--route network [netmask] [gateway] [metric] :\n"
  "                  Add route to routing table after connection\n"
  "                  is established.  Multiple routes can be specified.\n"
  "                  netmask default: 255.255.255.255\n"
  "                  gateway default: taken from --route-gateway or --ifconfig\n"
  "                  Specify default by leaving blank or setting to \"nil\".\n"
  "--route-gateway gw : Specify a default gateway for use with --route.\n"
  "--route-delay n : Delay n seconds after connection initiation before\n"
  "                  adding routes (may be 0).  If not specified, routes will\n"
  "                  be added immediately after tun/tap open.\n"
  "--route-up cmd  : Execute shell cmd after routes are added.\n"
  "--route-noexec  : Don't add routes automatically.  Instead pass routes to\n"
  "                  --route-up script using environmental variables.\n"
  "--redirect-gateway : (Experimental) Automatically execute routing commands to\n"
  "                     redirect all outgoing IP traffic through the VPN.\n"
  "--setenv name value : Set a custom environmental variable to pass to script.\n"
  "--shaper n      : Restrict output to peer to n bytes per second.\n"
  "--inactive n    : Exit after n seconds of inactivity on TUN/TAP device.\n"
  "--ping-exit n   : Exit if n seconds pass without reception of remote ping.\n"
  "--ping-restart n: Restart if n seconds pass without reception of remote ping.\n"
  "--ping-timer-rem: Run the --ping-exit/--ping-restart timer only if we have a\n"
  "                  remote address.\n"
  "--ping n        : Ping remote once every n seconds over TCP/UDP port.\n"
  "--persist-tun   : Keep TUN/TAP device open across SIGUSR1 or --ping-restart.\n"
  "--persist-remote-ip : Keep remote IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-local-ip  : Keep local IP address across SIGUSR1 or --ping-restart.\n"
  "--persist-key   : Don't re-read key files across SIGUSR1 or --ping-restart.\n"
#if PASSTOS_CAPABILITY
  "--passtos       : TOS passthrough (applies to IPv4 only).\n"
#endif
  "--tun-mtu n     : Take the TUN/TAP device MTU to be n and derive the\n"
  "                  TCP/UDP MTU from it (default TAP=%d).\n"
  "--tun-mtu-extra n : Assume that TUN/TAP device might return as many\n"
  "                  as n bytes more than the tun-mtu size on read\n"
  "                  (default TUN=0 TAP=%d).\n"
  "--link-mtu n    : Take the TCP/UDP device MTU to be n and derive the tun MTU\n"
  "                  from it (default TUN=%d).\n"
  "--mtu-disc type : Should we do Path MTU discovery on TCP/UDP channel?\n"
  "                  'no'    -- Never send DF (Don't Fragment) frames\n"
  "                  'maybe' -- Use per-route hints\n"
  "                  'yes'   -- Always DF (Don't Fragment)\n"
  "--mtu-test      : Empirically measure and report MTU.\n"
#ifdef FRAGMENT_ENABLE
  "--fragment max  : Enable internal datagram fragmentation so that no UDP\n"
  "                  datagrams are sent which are larger than max bytes.\n"
  "                  Adds 4 bytes of overhead per datagram.\n"
#endif
  "--mssfix [n]    : Set upper bound on TCP MSS, default = tun-mtu size\n"
  "                  or --fragment max value, whichever is lower.\n"
  "--mlock         : Disable Paging -- ensures key material and tunnel\n"
  "                  data will never be written to disk.\n"
  "--up cmd        : Shell cmd to execute after successful tun device open.\n"
  "                  Execute as: cmd TUN/TAP-dev tun-mtu link-mtu \\\n"
  "                              ifconfig-local-ip ifconfig-remote-ip\n"
  "                  (pre --user or --group UID/GID change)\n"
  "--up-delay      : Delay TUN/TAP open and possible --up script execution\n"
  "                  until after TCP/UDP connection establishment with peer.\n"
  "--down cmd      : Shell cmd to run after tun device close.\n"
  "                  (post --user/--group UID/GID change and/or --chroot)\n"
  "                  (script parameters are same as --up option)\n"
  "--up-restart    : Run up/down scripts for all restarts including those\n"
  "                  caused by --ping-restart or SIGUSR1\n"
  "--user user     : Set UID to user after initialization.\n"
  "--group group   : Set GID to group after initialization.\n"
  "--chroot dir    : Chroot to this directory after initialization.\n"
  "--cd dir        : Change to this directory before initialization.\n"
  "--daemon [name] : Become a daemon after initialization.\n"
  "                  The optional 'name' parameter will be passed\n"
  "                  as the program name to the system logger.\n"
  "--inetd [name] ['wait'|'nowait'] : Run as an inetd or xinetd server.\n"
  "                  See --daemon above for a description of the 'name' parm.\n"
  "--log file      : Output log to file which is created/truncated on open.\n"
  "--log-append file : Append log to file, or create file if nonexistent.\n"
  "--writepid file : Write main process ID to file.\n"
  "--nice n        : Change process priority (>0 = lower, <0 = higher).\n"
#ifdef USE_PTHREAD
  "--nice-work n   : Change thread priority of work thread.  The work\n"
  "                  thread is used for background processing such as\n"
  "                  RSA key number crunching.\n"
#endif
  "--verb n        : Set output verbosity to n (default=%d):\n"
  "                  (Level 3 is recommended if you want a good summary\n"
  "                  of what's happening without being swamped by output).\n"
  "                : 0 -- no output except fatal errors\n"
  "                : 1 -- startup info + connection initiated messages +\n"
  "                       non-fatal encryption & net errors\n"
  "                : 2 -- show TLS negotiations\n"
  "                : 3 -- show extra TLS info + --gremlin net outages +\n"
  "                       adaptive compress info\n"
  "                : 4 -- show parameters\n"
  "                : 5 -- show 'RrWw' chars on console for each packet sent\n"
  "                       and received from TCP/UDP (caps) or TUN/TAP (lc)\n"
  "                : 6 to 11 -- debug messages of increasing verbosity\n"
  "--mute n        : Log at most n consecutive messages in the same category.\n"
  "--gremlin       : Simulate dropped & corrupted packets + network outages\n"
  "                  to test robustness of protocol (for debugging only).\n"
  "--disable-occ   : Disable options consistency check between peers.\n"
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
  "--secret f [d]  : Enable Static Key encryption mode (non-TLS).\n"
  "                  Use shared secret file f, generate with --genkey.\n"
  "                  The optional d parameter controls key directionality.\n"
  "                  If d is specified, use separate keys for each\n"
  "                  direction, set d=0 on one side of the connection,\n"
  "                  and d=1 on the other side.\n"
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
  "--replay-window n [t] : Use a replay protection sliding window of size n\n"
  "                        and a time window of t seconds.\n"
  "                        Default n=%d t=%d\n"
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
  "--key-method m  : Data channel key exchange method.  m should be a method\n"
  "                  number, such as 1 (default), 2, etc.\n"
  "--ca file       : Certificate authority file in .pem format containing\n"
  "                  root certificate.\n"
  "--dh file       : File containing Diffie Hellman parameters\n"
  "                  in .pem format (for --tls-server only).\n"
  "                  Use \"openssl dhparam -out dh1024.pem 1024\" to generate.\n"
  "--cert file     : Local certificate in .pem format -- must be signed\n"
  "                  by a Certificate Authority in --ca file.\n"
  "--key file      : Local private key in .pem format.\n"
  "--tls-cipher l  : A list l of allowable TLS ciphers separated by : (optional).\n"
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
  "--tls-auth f [d]: Add an additional layer of authentication on top of the TLS\n"
  "                  control channel to protect against DoS attacks.\n"
  "                  f (required) is a shared-secret passphrase file.\n"
  "                  The optional d parameter controls key directionality,\n"
  "                  see --secret option for more info.\n"
  "--askpass       : Get PEM password from controlling tty before we daemonize.\n"
  "--crl-verify crl: Check peer certificate against a CRL.\n"
  "--tls-verify cmd: Execute shell command cmd to verify the X509 name of a\n"
  "                  pending TLS connection that has otherwise passed all other\n"
  "                  tests of certification.  cmd should return 0 to allow\n"
  "                  TLS handshake to proceed, or 1 to fail.  (cmd is\n"
  "                  executed as 'cmd certificate_depth X509_NAME_oneline')\n"
  "--tls-remote x509name: Accept connections only from a host with X509 name\n"
  "                  x509name. The remote host must also pass all other tests\n"
  "                  of verification.\n"
#endif				/* USE_SSL */
  "\n"
  "SSL Library information:\n"
  "--show-ciphers  : Show cipher algorithms to use with --cipher option.\n"
  "--show-digests  : Show message digest algorithms to use with --auth option.\n"
#ifdef USE_SSL
  "--show-tls      : Show all TLS ciphers (TLS used only as a control channel).\n"
#endif
#ifdef WIN32
  "\n"
  "Windows Specific:\n"
  "--show-adapters : Show all TAP-Win32 adapters.\n"
  "--ip-win32 method : When using --ifconfig on Windows, set TAP-Win32 adapter\n"
  "                    IP address using method = manual, netsh, ipapi, or\n"
  "                    dynamic (default = dynamic).\n"
  "                    Dynamic method allows two optional parameters:\n"
  "                    offset: DHCP server address offset (> -256 and < 256).\n"
  "                            If 0, use network address, if >0, take nth\n"
  "                            address forward from network address, if <0,\n"
  "                            take nth address backward from broadcast\n"
  "                            address.\n"
  "                            Default is 0.\n"
  "                    lease-time: Lease time in seconds.\n"
  "                                Default is one year.\n"
  "--dhcp-option type [parm] : Set extended TAP-Win32 properties, must\n"
  "                    be used with --ip-win32 dynamic.  For options\n"
  "                    which allow multiple addresses,\n"
  "                    --dhcp-option must be repeated.\n"
  "                    DOMAIN name : Set DNS suffix\n"
  "                    DNS addr    : Set domain name server address(es)\n"
  "                    NTP         : Set NTP server address(es)\n"
  "                    NBDD        : Set NBDD server address(es)\n"
  "                    WINS addr   : Set WINS server address(es)\n"
  "                    NBT type    : Set NetBIOS over TCP/IP Node type\n"
  "                                  1: B, 2: P, 4: M, 8: H\n"
  "                    NBS id      : Set NetBIOS scope ID\n"
  "--tap-sleep n   : Sleep for n seconds after TAP adapter open before\n"
  "                  attempting to set adapter properties.\n"
  "--show-valid-subnets : Show valid subnets for --dev tun emulation.\n" 
  "--pause-exit    : When run from a console window, pause before exiting.\n"
#endif
  "\n"
  "Generate a random key (only for non-TLS static key encryption mode):\n"
  "--genkey        : Generate a random key to be used as a shared secret,\n"
  "                  for use with the --secret option.\n"
  "--secret file   : Write key to file.\n"
#endif				/* USE_CRYPTO */
#ifdef TUNSETPERSIST
  "\n"
  "TUN/TAP config mode (available with linux 2.4+):\n"
  "--mktun         : Create a persistent tunnel.\n"
  "--rmtun         : Remove a persistent tunnel.\n"
  "--dev tunX|tapX : TUN/TAP device\n"
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
  o->proto = PROTO_UDPv4;
  o->connect_retry_seconds = 5;
#ifdef TUNSETPERSIST
  o->persist_mode = 1;
#endif
  o->local_port = o->remote_port = 5000;
  o->verbosity = 1;
  o->bind_local = true;
  o->tun_mtu = TUN_MTU_DEFAULT;
  o->link_mtu = LINK_MTU_DEFAULT;
  o->mtu_discover_type = -1;
  o->occ = true;
#ifdef USE_LZO
  o->comp_lzo_adaptive = true;
#endif
#ifdef WIN32
  o->tuntap_options.ip_win32_type = IPW32_SET_DHCP_MASQ;
  o->tuntap_options.dhcp_lease_time = 31536000; /* one year */
  o->tuntap_options.dhcp_masq_offset = 0;       /* use network address as internal DHCP server address */
#endif
#ifdef USE_CRYPTO
  o->ciphername = "BF-CBC";
  o->ciphername_defined = true;
  o->authname = "SHA1";
  o->authname_defined = true;
  o->replay = true;
  o->replay_window = DEFAULT_SEQ_BACKTRACK;
  o->replay_time = DEFAULT_TIME_BACKTRACK;
  o->use_iv = true;
  o->key_direction = KEY_DIRECTION_BIDIRECTIONAL;
#ifdef USE_SSL
#ifdef KEY_METHOD_DEFAULT_2
  o->key_method = 2;
#else
  o->key_method = 1;
#endif
  o->tls_timeout = 2;
  o->renegotiate_seconds = 3600;
  o->handshake_window = 60;
  o->transition_window = 3600;
#endif
#endif
}

#define SHOW_PARM(name, value, format) msg(D_SHOW_PARMS, "  " #name " = " format, (value))
#define SHOW_STR(var)  SHOW_PARM(var, (o->var ? o->var : "[UNDEF]"), "'%s'")
#define SHOW_INT(var)  SHOW_PARM(var, o->var, "%d")
#define SHOW_UINT(var)  SHOW_PARM(var, o->var, "%u")
#define SHOW_UNSIGNED(var)  SHOW_PARM(var, o->var, "0x%08x")
#define SHOW_BOOL(var) SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s");

void
setenv_settings (const struct options *o)
{
  setenv_str ("config", o->config);
  setenv_str ("proto", proto2ascii (o->proto, false));
  setenv_str ("local", o->local);
  setenv_int ("local_port", o->local_port);
  setenv_str ("remote", o->remote);
  setenv_int ("remote_port", o->remote_port);
}

#ifdef WIN32

static void
show_dhcp_option_addrs (const char *name, const in_addr_t *array, int len)
{
  int i;
  for (i = 0; i < len; ++i)
    {
      msg (D_SHOW_PARMS, "  %s[%d] = %s",
	   name,
	   i,
	   print_in_addr_t (array[i], false));
    }
}

static void
show_tuntap_options (const struct tuntap_options *o)
{
  SHOW_BOOL (ip_win32_defined);
  SHOW_INT (ip_win32_type);
  SHOW_INT (dhcp_masq_offset);
  SHOW_INT (dhcp_lease_time);
  SHOW_INT (tap_sleep);
  SHOW_BOOL (dhcp_options);
  SHOW_STR (domain);
  SHOW_STR (netbios_scope);
  SHOW_INT (netbios_node_type);

  show_dhcp_option_addrs ("DNS", o->dns, o->dns_len);
  show_dhcp_option_addrs ("WINS", o->wins, o->wins_len);
  show_dhcp_option_addrs ("NTP", o->ntp, o->ntp_len);
  show_dhcp_option_addrs ("NBDD", o->nbdd, o->nbdd_len);
}

static void
dhcp_option_address_parse (const char *name, const char *parm, in_addr_t *array, int *len)
{
  if (*len >= N_DHCP_ADDR)
    msg (M_USAGE, "--dhcp-option %s: maximum of %d %s servers can be specified",
	 name,
	 N_DHCP_ADDR,
	 name);

  array[(*len)++] = getaddr (GETADDR_FATAL
			   | GETADDR_HOST_ORDER
			   | GETADDR_FATAL_ON_SIGNAL,
			   parm,
			   0,
			   NULL,
			   NULL);
}

#endif

void
show_settings (const struct options *o)
{
  msg (D_SHOW_PARMS, "Current Parameter Settings:");

  SHOW_STR (config);

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

  SHOW_INT (proto);
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
  SHOW_STR (ifconfig_remote_netmask);
  SHOW_BOOL (ifconfig_noexec);
  SHOW_BOOL (ifconfig_nowarn);

#ifdef HAVE_GETTIMEOFDAY
  SHOW_INT (shaper);
#endif
  SHOW_INT (tun_mtu);
  SHOW_BOOL (tun_mtu_defined);
  SHOW_INT (link_mtu);
  SHOW_BOOL (link_mtu_defined);
  SHOW_INT (tun_mtu_extra);
  SHOW_BOOL (tun_mtu_extra_defined);
#ifdef FRAGMENT_ENABLE
  SHOW_INT (fragment);
#endif
  SHOW_INT (mtu_discover_type);
  SHOW_INT (mtu_test);

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

  SHOW_BOOL (mssfix_defined);
  SHOW_INT (mssfix);
  
#if PASSTOS_CAPABILITY
  SHOW_BOOL (passtos);
#endif

  SHOW_INT (resolve_retry_seconds);
  SHOW_INT (connect_retry_seconds);

  SHOW_STR (username);
  SHOW_STR (groupname);
  SHOW_STR (chroot_dir);
  SHOW_STR (cd_dir);
  SHOW_STR (writepid);
  SHOW_STR (up_script);
  SHOW_STR (down_script);
  SHOW_BOOL (up_restart);
  SHOW_BOOL (daemon);
  SHOW_INT (inetd);
  SHOW_BOOL (log);
  SHOW_INT (nice);
  SHOW_INT (verbosity);
  SHOW_INT (mute);
  SHOW_BOOL (gremlin);

  SHOW_BOOL (occ);

  SHOW_STR (http_proxy_server);
  SHOW_INT (http_proxy_port);
  SHOW_STR (http_proxy_auth_method);
  SHOW_STR (http_proxy_auth_file);
  SHOW_BOOL (http_proxy_retry);

  SHOW_STR (socks_proxy_server);
  SHOW_INT (socks_proxy_port);
  SHOW_BOOL (socks_proxy_retry);

#ifdef USE_LZO
  SHOW_BOOL (comp_lzo);
  SHOW_BOOL (comp_lzo_adaptive);
#endif

  SHOW_STR (route_script);
  SHOW_STR (route_default_gateway);
  SHOW_BOOL (route_noexec);
  SHOW_INT (route_delay);
  SHOW_BOOL (route_delay_defined);
  print_route_options (&o->routes, D_SHOW_PARMS);

#ifdef USE_CRYPTO
  SHOW_STR (shared_secret_file);
  SHOW_INT (key_direction);
  SHOW_BOOL (ciphername_defined);
  SHOW_STR (ciphername);
  SHOW_BOOL (authname_defined);
  SHOW_STR (authname);
  SHOW_INT (keysize);
  SHOW_BOOL (replay);
  SHOW_INT (replay_window);
  SHOW_INT (replay_time);
  SHOW_STR (packet_id_file);
  SHOW_BOOL (use_iv);
  SHOW_BOOL (test_crypto);

#ifdef USE_SSL
  SHOW_BOOL (tls_server);
  SHOW_BOOL (tls_client);
  SHOW_INT (key_method);
  SHOW_STR (ca_file);
  SHOW_STR (dh_file);
  SHOW_STR (cert_file);
  SHOW_STR (priv_key_file);
  SHOW_STR (cipher_list);
  SHOW_STR (tls_verify);
  SHOW_STR (tls_remote);
  SHOW_STR (crl_file);

  SHOW_INT (tls_timeout);

  SHOW_INT (renegotiate_bytes);
  SHOW_INT (renegotiate_packets);
  SHOW_INT (renegotiate_seconds);

  SHOW_INT (handshake_window);
  SHOW_INT (transition_window);

  SHOW_BOOL (single_session);

  SHOW_STR (tls_auth_file);
#endif
#endif

#ifdef WIN32
  show_tuntap_options (&o->tuntap_options);
#endif
}

#undef SHOW_PARM
#undef SHOW_STR
#undef SHOW_INT
#undef SHOW_BOOL

/*
 * Build an options string to represent data channel encryption options.
 * This string must match exactly between peers.  The keysize is checked
 * separately by read_key().
 *
 * The following options must match on both peers:
 *
 * Tunnel options:
 *
 * --dev tun|tap [unit number need not match]
 * --dev-type tun|tap
 * --link-mtu
 * --udp-mtu
 * --tun-mtu
 * --proto udp
 * --proto tcp-client [matched with --proto tcp-server
 *                     on the other end of the connection]
 * --proto tcp-server [matched with --proto tcp-client on
 *                     the other end of the connection]
 * --tun-ipv6
 * --ifconfig x y [matched with --ifconfig y x on
 *                 the other end of the connection]
 *
 * --comp-lzo
 * --mtu-dynamic
 *
 * Crypto Options:
 *
 * --cipher
 * --auth
 * --keysize
 * --secret
 * --no-replay
 * --no-iv
 *
 * SSL Options:
 *
 * --tls-auth
 * --tls-client [matched with --tls-server on
 *               the other end of the connection]
 * --tls-server [matched with --tls-client on
 *               the other end of the connection]
 */

char *
options_string (const struct options *o,
		const struct frame *frame,
		const struct tuntap *tt,
		bool remote)
{
  struct buffer out = alloc_buf (256);

  buf_printf (&out, "V3");

  /*
   * Tunnel Options
   */

  buf_printf (&out, ",dev-type %s", dev_type_string (o->dev, o->dev_type));
  buf_printf (&out, ",link-mtu %d", EXPANDED_SIZE (frame));
  buf_printf (&out, ",tun-mtu %d", PAYLOAD_SIZE (frame));
  buf_printf (&out, ",proto %s", proto2ascii (proto_remote (o->proto, remote), true));
  if (o->tun_ipv6)
    buf_printf (&out, ",tun-ipv6");
  if (tt)
    buf_printf (&out,
		",ifconfig %s",
		ifconfig_options_string (tt, remote, o->ifconfig_nowarn));

#ifdef USE_LZO
  if (o->comp_lzo)
    buf_printf (&out, ",comp-lzo");
#endif

#ifdef FRAGMENT_ENABLE
  if (o->fragment)
    buf_printf (&out, ",mtu-dynamic");
#endif

#ifdef USE_CRYPTO

#ifdef USE_SSL
#define TLS_CLIENT (o->tls_client)
#define TLS_SERVER (o->tls_server)
#else
#define TLS_CLIENT (false)
#define TLS_SERVER (false)
#endif

  /*
   * Key direction
   */
  {
    const char *kd = keydirection2ascii (o->key_direction, remote);
    if (kd)
      buf_printf (&out, ",keydir %s", kd);
  }

  /*
   * Crypto Options
   */
    if (o->shared_secret_file || TLS_CLIENT || TLS_SERVER)
      {
	struct key_type kt;

	ASSERT ((o->shared_secret_file != NULL)
		+ (TLS_CLIENT == true)
		+ (TLS_SERVER == true)
		<= 1);

	init_key_type (&kt, o->ciphername, o->ciphername_defined,
		       o->authname, o->authname_defined,
		       o->keysize, true, false);

	buf_printf (&out, ",cipher %s", kt_cipher_name (&kt));
	buf_printf (&out, ",auth %s", kt_digest_name (&kt));
	buf_printf (&out, ",keysize %d", kt_key_size (&kt));
	if (o->shared_secret_file)
	  buf_printf (&out, ",secret");
	if (!o->replay)
	  buf_printf (&out, ",no-replay");
	if (!o->use_iv)
	  buf_printf (&out, ",no-iv");
      }

#ifdef USE_SSL
  /*
   * SSL Options
   */
  {
    if (o->tls_auth_file)
      buf_printf (&out, ",tls-auth");

    if (o->key_method > 1)
      buf_printf (&out, ",key-method %d", o->key_method);

    if (remote)
      {
	if (TLS_CLIENT)
	  buf_printf (&out, ",tls-server");
	else if (TLS_SERVER)
	  buf_printf (&out, ",tls-client");
      }
    else
      {
	if (TLS_CLIENT)
	  buf_printf (&out, ",tls-client");
	else if (TLS_SERVER)
	  buf_printf (&out, ",tls-server");
      }
  }
#endif /* USE_SSL */

#undef TLS_CLIENT
#undef TLS_SERVER

#endif /* USE_CRYPTO */

  return BSTR (&out);
}

/*
 * Compare option strings for equality.
 * If the first two chars of the strings differ, it means that
 * we are looking at different versions of the options string,
 * therefore don't compare them and return true.
 */
bool
options_cmp_equal (char *actual, const char *expected, size_t actual_n)
{
  if (actual_n > 0)
    {
      actual[actual_n - 1] = 0;
#ifndef STRICT_OPTIONS_CHECK
      if (strncmp (actual, expected, 2))
	{
	  msg (D_SHOW_OCC, "NOTE: failed to perform options consistency check between peers because of " PACKAGE_NAME " version differences -- you can disable the options consistency check with --disable-occ (Required for TLS connections between " PACKAGE_NAME " 1.3.x and later versions).  Actual Remote Options: '%s'.  Expected Remote Options: '%s'", actual, expected);
	  return true;
	}
      else
#endif
	return !strcmp (actual, expected);
    }
  else
    return true;
}

void
options_warning (char *actual, const char *expected, size_t actual_n)
{
  if (actual_n > 0)
    {
      actual[actual_n - 1] = 0;
      msg (M_WARN,
	   "WARNING: Actual Remote Options ('%s') are inconsistent with Expected Remote Options ('%s')",
	   actual,
	   expected);
    }
}

const char *
options_string_version (const char* s)
{
  struct buffer out = alloc_buf (4);
  strncpynt (BPTR (&out), s, 3);
  return BSTR (&out);
}

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
usage (void)
{
  struct options o;
  FILE *fp = msg_fp();

  init_options (&o);

#if defined(USE_CRYPTO) && defined(USE_SSL)
  fprintf (fp, usage_message,
	   title_string,
	   o.connect_retry_seconds,
	   o.local_port, o.remote_port,
	   TAP_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT, LINK_MTU_DEFAULT,
	   o.verbosity,
	   o.authname, o.ciphername,
           o.replay_window, o.replay_time,
	   o.tls_timeout, o.renegotiate_seconds,
	   o.handshake_window, o.transition_window);
#elif defined(USE_CRYPTO)
  fprintf (fp, usage_message,
	   title_string,
	   o.connect_retry_seconds,
	   o.local_port, o.remote_port,
	   TAP_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT, LINK_MTU_DEFAULT,
	   o.verbosity,
	   o.authname, o.ciphername,
           o.replay_window, o.replay_time);
#else
  fprintf (fp, usage_message,
	   title_string,
	   o.connect_retry_seconds,
	   o.local_port, o.remote_port,
	   TAP_MTU_DEFAULT, TAP_MTU_EXTRA_DEFAULT, LINK_MTU_DEFAULT,
	   o.verbosity);
#endif
  fflush(fp);
  
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
usage_small (void)
{
  msg (M_WARN|M_NOPREFIX, "Use --help for more information.");
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

static void
usage_version (void)
{
  msg (M_INFO|M_NOPREFIX, "%s", title_string);
  msg (M_INFO|M_NOPREFIX, "Copyright (C) 2002-2004 James Yonan <jim@yonan.net>");
  openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
}

void
notnull (const char *arg, const char *description)
{
  if (!arg)
    msg (M_USAGE, "Options error: You must define %s", description);
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
ping_rec_err (void)
{
  msg (M_USAGE, "Options error: only one of --ping-exit or --ping-restart options may be specified");
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
  const int STATE_INITIAL = 0;
  const int STATE_READING_QUOTED_PARM = 1;
  const int STATE_READING_UNQUOTED_PARM = 2;
  const int STATE_DONE = 3;

  int ret = 0;
  char *c = line;
  int state = STATE_INITIAL;
  bool backslash = false;
  char in, out;

  char parm[256];
  unsigned int parm_len = 0;

  do
    {
      in = *c;
      out = 0;

      if (!backslash && in == '\\')
	{
	  backslash = true;
	}
      else
	{
	  if (state == STATE_INITIAL)
	    {
	      if (!space (in))
		{
		  if (in == ';' || in == '#') /* comment */
		    break;
		  if (!backslash && in == '\"')
		    state = STATE_READING_QUOTED_PARM;
		  else
		    {
		      out = in;
		      state = STATE_READING_UNQUOTED_PARM;
		    }
		}
	    }
	  else if (state == STATE_READING_UNQUOTED_PARM)
	    {
	      if (!backslash && space (in))
		state = STATE_DONE;
	      else
		out = in;
	    }
	  else if (state == STATE_READING_QUOTED_PARM)
	    {
	      if (!backslash && in == '\"')
		state = STATE_DONE;
	      else
		out = in;
	    }
	  if (state == STATE_DONE)
	    {
	      ASSERT (parm_len > 0);
	      p[ret] = gc_malloc (parm_len + 1);
	      memcpy (p[ret], parm, parm_len);
	      p[ret][parm_len] = '\0';
	      state = 0;
	      parm_len = 0;
	      ++ret;
	    }
	  backslash = false;
	}

      /* store parameter character */
      if (out)
	{
	  if (parm_len >= SIZE (parm))
	    {
	      parm[SIZE (parm) - 1] = 0;
	      msg (M_USAGE, "Parameter at %s:%d is too long (%d chars max): %s",
		   file, line_num, (int) SIZE (parm), parm);
	    }
	  parm[parm_len++] = out;
	}

      /* avoid overflow if too many parms in one config file line */
      if (ret >= n)
	break;

    } while (*c++ != '\0');

  if (state == STATE_READING_QUOTED_PARM)
	msg (M_FATAL, "No closing quotation (\") in %s:%d", file, line_num);
  if (state != STATE_INITIAL)
	msg (M_FATAL, "Residual parse state (%d) in %s:%d", state, file, line_num);
#if 0
  {
    int i;
    for (i = 0; i < ret; ++i)
      {
	msg (M_INFO|M_NOPREFIX, "%s:%d ARG[%d] '%s'", file, line_num, i, p[i]);
      }
  }
#endif
    return ret;
}

static int
add_option (struct options *options, int i, char *p[],
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
      char *p[MAX_PARMS];
      CLEAR (p);
      ++line_num;
      if (parse_line (line, p, SIZE (p), file, line_num))
	{
	  if (strlen (p[0]) >= 3 && !strncmp (p[0], "--", 2))
	    p[0] += 2;
	  add_option (options, 0, p, file, line_num, level);
	}
    }
  fclose (fp);
}

void
parse_argv (struct options* options, int argc, char *argv[])
{
  int i, j;

  /* usage message */
  if (argc <= 1)
    usage ();

  /* parse command line */
  for (i = 1; i < argc; ++i)
    {
      char *p[MAX_PARMS];
      CLEAR (p);
      p[0] = argv[i];
      if (strncmp(p[0], "--", 2))
	msg (M_USAGE, "I'm trying to parse \"%s\" as an --option parameter but I don't see a leading '--'", p[0]);
      p[0] += 2;

      for (j = 1; j < MAX_PARMS; ++j)
	{
	  if (i + j < argc)
	    {
	      char *arg = argv[i + j];
	      if (strncmp (arg, "--", 2))
		p[j] = arg;
	      else
		break;
	    }
	}
      i = add_option (options, i, p, NULL, 0, 0);
    }
}

static int
add_option (struct options *options, int i, char *p[],
	    const char* file, int line, int level)
{
  ASSERT (MAX_PARMS >= 5);

  if (!file)
    {
      file = "[CMD-LINE]";
      line = 1;
    }
  if (streq (p[0], "help"))
    {
      usage ();
    }
  if (streq (p[0], "version"))
    {
      usage_version ();
    }
  else if (streq (p[0], "config") && p[1])
    {
      ++i;

      /* save first config file only in options */
      if (!options->config)
	options->config = p[1];

      read_config_file (options, p[1], level, file, line);
    }
  else if (streq (p[0], "dev") && p[1])
    {
      ++i;
      options->dev = p[1];
    }
  else if (streq (p[0], "dev-type") && p[1])
    {
      ++i;
      options->dev_type = p[1];
    }
  else if (streq (p[0], "dev-node") && p[1])
    {
      ++i;
      options->dev_node = p[1];
    }
  else if (streq (p[0], "tun-ipv6"))
    {
      options->tun_ipv6 = true;
    }
  else if (streq (p[0], "ifconfig") && p[1] && p[2])
    {
      options->ifconfig_local = p[1];
      options->ifconfig_remote_netmask = p[2];
      i += 2;
    }
  else if (streq (p[0], "ifconfig-noexec"))
    {
      options->ifconfig_noexec = true;
    }
  else if (streq (p[0], "ifconfig-nowarn"))
    {
      options->ifconfig_nowarn = true;
    }
  else if (streq (p[0], "local") && p[1])
    {
      ++i;
      options->local = p[1];
    }
  else if (streq (p[0], "remote") && p[1])
    {
      ++i;
      options->remote = p[1];
    }
  else if (streq (p[0], "resolv-retry") && p[1])
    {
      ++i;
      if (streq (p[1], "infinite"))
	options->resolve_retry_seconds = 1000000000;
      else
	options->resolve_retry_seconds = positive (atoi (p[1]));
    }
  else if (streq (p[0], "connect-retry") && p[1])
    {
      ++i;
      options->connect_retry_seconds = positive (atoi (p[1]));
      options->connect_retry_defined = true;
    }
  else if (streq (p[0], "ipchange") && p[1])
    {
      ++i;
      options->ipchange = comma_to_space (p[1]);
    }
  else if (streq (p[0], "float"))
    {
      options->remote_float = true;
    }
  else if (streq (p[0], "gremlin"))
    {
      options->gremlin = true;
    }
  else if (streq (p[0], "user") && p[1])
    {
      ++i;
      options->username = p[1];
    }
  else if (streq (p[0], "group") && p[1])
    {
      ++i;
      options->groupname = p[1];
    }
  else if (streq (p[0], "chroot") && p[1])
    {
      ++i;
      options->chroot_dir = p[1];
    }
  else if (streq (p[0], "cd") && p[1])
    {
      ++i;
      options->cd_dir = p[1];
      if (openvpn_chdir (p[1]))
	msg (M_ERR, "cd to '%s' failed", p[1]);
    }
  else if (streq (p[0], "writepid") && p[1])
    {
      ++i;
      options->writepid = p[1];
    }
  else if (streq (p[0], "up") && p[1])
    {
      ++i;
      options->up_script = p[1];
    }
  else if (streq (p[0], "down") && p[1])
    {
      ++i;
      options->down_script = p[1];
    }
  else if (streq (p[0], "up-delay"))
    {
      options->up_delay = true;
    }
  else if (streq (p[0], "up-restart"))
    {
      options->up_restart = true;
    }
  else if (streq (p[0], "daemon"))
    {
      if (!options->daemon) {
	options->daemon = true;
	open_syslog (p[1]);
	if (p[1])
	  ++i;
      }
    }
  else if (streq (p[0], "inetd"))
    {
      if (!options->inetd)
	{
	  int z;
	  const char *name = NULL;
	  const char *opterr = "Options Error: when --inetd is used with two parameters, one of them must be 'wait' or 'nowait' and the other must be a daemon name to use for system logging";

	  options->inetd = -1;

	  for (z = 1; z <= 2; ++z)
	    {
	      if (p[z])
		{
		  ++i;
		  if (streq (p[z], "wait"))
		    {
		      if (options->inetd != -1)
			msg (M_USAGE, opterr);
		      else
			options->inetd = INETD_WAIT;
		    }
		  else if (streq (p[z], "nowait"))
		    {
		      if (options->inetd != -1)
			msg (M_USAGE, opterr);
		      else
			options->inetd = INETD_NOWAIT;
		    }
		  else
		    {
		      if (name != NULL)
			msg (M_USAGE, opterr);
		      name = p[z];
		    }
		}
	    }

	  /* default */
	  if (options->inetd == -1)
	    options->inetd = INETD_WAIT;

	  save_inetd_socket_descriptor ();
	  open_syslog (name);
	}
    }
  else if (streq (p[0], "log") && p[1])
    {
      ++i;
      options->log = true;
      redirect_stdout_stderr (p[1], false);
    }
  else if (streq (p[0], "log-append") && p[1])
    {
      ++i;
      options->log = true;
      redirect_stdout_stderr (p[1], true);
    }
  else if (streq (p[0], "mlock"))
    {
      options->mlock = true;
    }
  else if (streq (p[0], "verb") && p[1])
    {
      ++i;
      options->verbosity = positive (atoi (p[1]));
    }
  else if (streq (p[0], "mute") && p[1])
    {
      ++i;
      options->mute = positive (atoi (p[1]));
    }
  else if ((streq (p[0], "link-mtu") || streq (p[0], "udp-mtu")) && p[1])
    {
      ++i;
      options->link_mtu = positive (atoi (p[1]));
      options->link_mtu_defined = true;
    }
  else if (streq (p[0], "tun-mtu") && p[1])
    {
      ++i;
      options->tun_mtu = positive (atoi (p[1]));
      options->tun_mtu_defined = true;
    }
  else if (streq (p[0], "tun-mtu-extra") && p[1])
    {
      ++i;
      options->tun_mtu_extra = positive (atoi (p[1]));
      options->tun_mtu_extra_defined = true;
    }
#ifdef FRAGMENT_ENABLE
  else if (streq (p[0], "mtu-dynamic"))
    {
      msg (M_USAGE, "--mtu-dynamic has been replaced by --fragment");
    }
  else if (streq (p[0], "fragment") && p[1])
    {
      ++i;
      options->fragment = positive (atoi (p[1]));
    }
#endif
  else if (streq (p[0], "mtu-disc") && p[1])
    {
      ++i;
      options->mtu_discover_type = translate_mtu_discover_type_name (p[1]);
    }
  else if (streq (p[0], "mtu-test"))
    {
      options->mtu_test = true;
    }
  else if (streq (p[0], "nice") && p[1])
    {
      ++i;
      options->nice = atoi (p[1]);
    }
#ifdef USE_PTHREAD
  else if (streq (p[0], "nice-work") && p[1])
    {
      ++i;
      options->nice_work = atoi (p[1]);
    }
#endif
  else if (streq (p[0], "shaper") && p[1])
    {
#ifdef HAVE_GETTIMEOFDAY
      ++i;
      options->shaper = atoi (p[1]);
      if (options->shaper < SHAPER_MIN || options->shaper > SHAPER_MAX)
	{
	  msg (M_USAGE, "bad shaper value, must be between %d and %d",
	       SHAPER_MIN, SHAPER_MAX);
	}
#else /* HAVE_GETTIMEOFDAY */
      msg (M_USAGE, "--shaper requires the gettimeofday() function which is missing");
#endif /* HAVE_GETTIMEOFDAY */
    }
  else if (streq (p[0], "port") && p[1])
    {
      ++i;
      options->local_port = options->remote_port = atoi (p[1]);
      if (!legal_ipv4_port (options->local_port))
	msg (M_USAGE, "Bad port number: %s", p[1]);
    }
  else if (streq (p[0], "lport") && p[1])
    {
      ++i;
      options->local_port = atoi (p[1]);
      if (!legal_ipv4_port (options->local_port))
	msg (M_USAGE, "Bad local port number: %s", p[1]);
    }
  else if (streq (p[0], "rport") && p[1])
    {
      ++i;
      options->remote_port = atoi (p[1]);
      if (!legal_ipv4_port (options->remote_port))
	msg (M_USAGE, "Bad remote port number: %s", p[1]);
    }
  else if (streq (p[0], "nobind"))
    {
      options->bind_local = false;
    }
  else if (streq (p[0], "inactive") && p[1])
    {
      ++i;
      options->inactivity_timeout = positive (atoi (p[1]));
    }
  else if (streq (p[0], "proto") && p[1])
    {
      ++i;
      options->proto = ascii2proto (p[1]);
      if (options->proto < 0)
	msg (M_USAGE, "Bad protocol: '%s'.  Allowed protocols with --proto option: %s",
	     p[1],
	     proto2ascii_all());
    }
  else if (streq (p[0], "http-proxy") && p[1] && p[2])
    {
      i += 2;
      options->http_proxy_server = p[1];
      options->http_proxy_port = atoi (p[2]);
      if (options->http_proxy_port <= 0)
	msg (M_USAGE, "Bad http-proxy port number: %s", p[2]);

      if (p[3])
	{
	  ++i;
	  options->http_proxy_auth_method = "basic";
	  options->http_proxy_auth_file = p[3];
	}
      else
	{
	  options->http_proxy_auth_method = "none";
	}
    }
  else if (streq (p[0], "http-proxy-retry"))
    {
      options->http_proxy_retry = true;
    }
  else if (streq (p[0], "socks-proxy") && p[1])
    {
      ++i;
      options->socks_proxy_server = p[1];

      if (p[2])
	{
	  ++i;
          options->socks_proxy_port = atoi (p[2]);
          if (options->socks_proxy_port <= 0)
	    msg (M_USAGE, "Bad socks-proxy port number: %s", p[2]);
	}
      else
	{
	  options->socks_proxy_port = 1080;
	}
    }
  else if (streq (p[0], "socks-proxy-retry"))
    {
      options->socks_proxy_retry = true;
    }
  else if (streq (p[0], "ping") && p[1])
    {
      ++i;
      options->ping_send_timeout = positive (atoi (p[1]));
    }
  else if (streq (p[0], "ping-exit") && p[1])
    {
      ++i;
      if (options->ping_rec_timeout_action)
	ping_rec_err();
      options->ping_rec_timeout = positive (atoi (p[1]));
      options->ping_rec_timeout_action = PING_EXIT;
    }
  else if (streq (p[0], "ping-restart") && p[1])
    {
      ++i;
      if (options->ping_rec_timeout_action)
	ping_rec_err();
      options->ping_rec_timeout = positive (atoi (p[1]));
      options->ping_rec_timeout_action = PING_RESTART;
    }
  else if (streq (p[0], "ping-timer-rem"))
    {
      options->ping_timer_remote = true;
    }
  else if (streq (p[0], "persist-tun"))
    {
      options->persist_tun = true;
    }
  else if (streq (p[0], "persist-key"))
    {
      options->persist_key = true;
    }
  else if (streq (p[0], "persist-local-ip"))
    {
      options->persist_local_ip = true;
    }
  else if (streq (p[0], "persist-remote-ip"))
    {
      options->persist_remote_ip = true;
    }
  else if (streq (p[0], "route") && p[1])
    {
      ++i;
      if (p[2])
	++i;
      if (p[3])
	++i;
      if (p[4])
	++i;
      add_route_to_option_list (&options->routes, p[1], p[2], p[3], p[4]);
    }
  else if (streq (p[0], "route-gateway") && p[1])
    {
      ++i;
      options->route_default_gateway = p[1];      
    }
  else if (streq (p[0], "route-delay"))
    {
      options->route_delay_defined = true;
      if (p[1])
	{
	  ++i;
	  options->route_delay = positive (atoi (p[1]));
	}
      else
	{
	  options->route_delay = 0;
	}
    }
  else if (streq (p[0], "route-up") && p[1])
    {
      ++i;
      options->route_script = p[1];
    }
  else if (streq (p[0], "route-noexec"))
    {
      options->route_noexec = true;
    }
  else if (streq (p[0], "redirect-gateway"))
    {
      options->routes.redirect_default_gateway = true;
    }
  else if (streq (p[0], "setenv") && p[1] && p[2])
    {
      i += 2;
      setenv_str (p[1], p[2]);
    }
  else if (streq (p[0], "mssfix"))
    {
      options->mssfix_defined = true;
      if (p[1])
	{
	  ++i;
	  options->mssfix = positive (atoi (p[1]));
	}
    }
  else if (streq (p[0], "disable-occ"))
    {
      options->occ = false;
    }
#ifdef WIN32
  else if (streq (p[0], "ip-win32") && p[1])
    {
      const int index = ascii2ipset (p[1]);
      struct tuntap_options *to = &options->tuntap_options;
      ++i;

      to->ip_win32_defined = true;
 
      if (index < 0)
	msg (M_USAGE,
	     "Bad --ip-win32 method: '%s'.  Allowed methods: %s",
	     p[1],
	     ipset2ascii_all());

      to->ip_win32_type = index;

      if (to->ip_win32_type == IPW32_SET_DHCP_MASQ)
	{
	  if (p[2])
	    {
	      const int min_lease = 30;
	      int offset = atoi (p[2]);

	      ++i;
	      to->dhcp_masq_custom_offset = true;

	      if (!(offset > -256 && offset < 256))
		msg (M_USAGE, "--ip-win32 dynamic [offset] [lease-time]: offset (%d) must be > -256 and < 256", offset);

	      to->dhcp_masq_offset = offset;

	      if (p[3])
		{
		  const int min_lease = 30;
		  int lease_time;
		  ++i;
		  lease_time = atoi (p[3]);
		  if (lease_time < min_lease)
		    msg (M_USAGE, "--ip-win32 dynamic [offset] [lease-time]: lease time parameter (%d) must be at least %d seconds", lease_time, min_lease);
		  to->dhcp_lease_time = lease_time;
		}
	    }
	}
    }
  else if (streq (p[0], "dhcp-option") && p[1])
    {
      struct tuntap_options *o = &options->tuntap_options;
      ++i;
      o->dhcp_options = true;

      if (streq (p[1], "DOMAIN") && p[2])
	{
	  ++i;
	  o->domain = p[2];
	}
      else if (streq (p[1], "NBS") && p[2])
	{
	  ++i;
	  o->netbios_scope = p[2];
	}
      else if (streq (p[1], "NBT") && p[2])
	{
	  int t;
	  ++i;
	  t = atoi (p[2]);
	  if (!(t == 1 || t == 2 || t == 4 || t == 8))
	    msg (M_USAGE, "--dhcp-option NBT: parameter (%d) must be 1, 2, 4, or 8", t);
	  o->netbios_node_type = t;
	}
      else if (streq (p[1], "DNS") && p[2])
	{
	  ++i;
	  dhcp_option_address_parse ("DNS", p[2], o->dns, &o->dns_len);
	}
      else if (streq (p[1], "WINS") && p[2])
	{
	  ++i;
	  dhcp_option_address_parse ("WINS", p[2], o->wins, &o->wins_len);
	}
      else if (streq (p[1], "NTP") && p[2])
	{
	  ++i;
	  dhcp_option_address_parse ("NTP", p[2], o->ntp, &o->ntp_len);
	}
      else if (streq (p[1], "NBDD") && p[2])
	{
	  ++i;
	  dhcp_option_address_parse ("NBDD", p[2], o->nbdd, &o->nbdd_len);
	}
      else
	{
	  msg (M_USAGE, "--dhcp-option: unknown option type '%s' or missing parameter", p[1]);
	}
    }
  else if (streq (p[0], "show-adapters"))
    {
      show_tap_win32_adapters ();
      openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
    }
  else if (streq (p[0], "tap-sleep") && p[1])
    {
      int s;
      ++i;
      s = atoi (p[1]);
      if (s < 0 || s >= 256)
	msg (M_FATAL, "--tap-sleep parameter must be between 0 and 255");
      options->tuntap_options.tap_sleep = s;
    }
  else if (streq (p[0], "show-valid-subnets"))
    {
      show_valid_win32_tun_subnets ();
      openvpn_exit (OPENVPN_EXIT_STATUS_USAGE); /* exit point */
    }
  else if (streq (p[0], "pause-exit"))
    {
      set_pause_exit_win32 ();
    }
#endif
#if PASSTOS_CAPABILITY
  else if (streq (p[0], "passtos"))
    {
      options->passtos = true;
    }
#endif
#ifdef USE_LZO
  else if (streq (p[0], "comp-lzo"))
    {
      options->comp_lzo = true;
    }
  else if (streq (p[0], "comp-noadapt"))
    {
      options->comp_lzo_adaptive = false;
    }
#endif /* USE_LZO */
#ifdef USE_CRYPTO
  else if (streq (p[0], "show-ciphers"))
    {
      options->show_ciphers = true;
    }
  else if (streq (p[0], "show-digests"))
    {
      options->show_digests = true;
    }
  else if (streq (p[0], "secret") && p[1])
    {
      ++i;
      options->shared_secret_file = p[1];
      if (p[2])
	{
	  options->key_direction = ascii2keydirection (p[2]);
	  ++i;
	}
    }
  else if (streq (p[0], "genkey"))
    {
      options->genkey = true;
    }
  else if (streq (p[0], "auth") && p[1])
    {
      ++i;
      options->authname_defined = true;
      options->authname = p[1];
      if (streq (options->authname, "none"))
	{
	  options->authname_defined = false;
	  options->authname = NULL;
	}
    }
  else if (streq (p[0], "auth"))
    {
      options->authname_defined = true;
    }
  else if (streq (p[0], "cipher") && p[1])
    {
      ++i;
      options->ciphername_defined = true;
      options->ciphername = p[1];
      if (streq (options->ciphername, "none"))
	{
	  options->ciphername_defined = false;
	  options->ciphername = NULL;
	}
    }
  else if (streq (p[0], "cipher"))
    {
      options->ciphername_defined = true;
    }
  else if (streq (p[0], "no-replay"))
    {
      options->replay = false;
    }
  else if (streq (p[0], "replay-window"))
    {
      if (p[1])
	{
	  ++i;
	  options->replay_window = atoi (p[1]);
	  if (!(MIN_SEQ_BACKTRACK <= options->replay_window && options->replay_window <= MAX_SEQ_BACKTRACK))
	    msg (M_USAGE, "replay-window window size parameter (%d) must be between %d and %d",
		 options->replay_window,
		 MIN_SEQ_BACKTRACK,
		 MAX_SEQ_BACKTRACK);

	  if (p[2])
	    {
	      ++i;
	      options->replay_time = atoi (p[2]);
	      if (!(MIN_TIME_BACKTRACK <= options->replay_time && options->replay_time <= MAX_TIME_BACKTRACK))
		msg (M_USAGE, "replay-window time window parameter (%d) must be between %d and %d",
		     options->replay_time,
		     MIN_TIME_BACKTRACK,
		     MAX_TIME_BACKTRACK);
	    }
	}
      else
	{
	  msg (M_USAGE, "replay-window option is missing window size parameter");
	}
    }
  else if (streq (p[0], "no-iv"))
    {
      options->use_iv = false;
    }
  else if (streq (p[0], "replay-persist") && p[1])
    {
      ++i;
      options->packet_id_file = p[1];
    }
  else if (streq (p[0], "test-crypto"))
    {
      options->test_crypto = true;
    }
#ifdef HAVE_EVP_CIPHER_CTX_SET_KEY_LENGTH
  else if (streq (p[0], "keysize") && p[1])
    {
      ++i;
      options->keysize = atoi (p[1]) / 8;
      if (options->keysize < 0 || options->keysize > MAX_CIPHER_KEY_LENGTH)
	msg (M_USAGE, "Bad keysize: %s", p[1]);
    }
#endif
#ifdef USE_SSL
  else if (streq (p[0], "show-tls"))
    {
      options->show_tls_ciphers = true;
    }
  else if (streq (p[0], "tls-server"))
    {
      options->tls_server = true;
    }
  else if (streq (p[0], "tls-client"))
    {
      options->tls_client = true;
    }
  else if (streq (p[0], "ca") && p[1])
    {
      ++i;
      options->ca_file = p[1];
    }
  else if (streq (p[0], "dh") && p[1])
    {
      ++i;
      options->dh_file = p[1];
    }
  else if (streq (p[0], "cert") && p[1])
    {
      ++i;
      options->cert_file = p[1];
    }
  else if (streq (p[0], "key") && p[1])
    {
      ++i;
      options->priv_key_file = p[1];
    }
  else if (streq (p[0], "askpass"))
    {
      options->askpass = true;
    }
  else if (streq (p[0], "single-session"))
    {
      options->single_session = true;
    }
  else if (streq (p[0], "tls-cipher") && p[1])
    {
      ++i;
      options->cipher_list = p[1];
    }
  else if (streq (p[0], "crl-verify") && p[1])
    {
      ++i;
      options->crl_file = p[1];
    }
  else if (streq (p[0], "tls-verify") && p[1])
    {
      ++i;
      options->tls_verify = comma_to_space (p[1]);
    }
  else if (streq (p[0], "tls-remote") && p[1])
    {
      ++i;
      options->tls_remote = p[1];
    }
  else if (streq (p[0], "tls_timeout") && p[1])
    {
      ++i;
      options->tls_timeout = positive (atoi (p[1]));
    }
  else if (streq (p[0], "reneg-bytes") && p[1])
    {
      ++i;
      options->renegotiate_bytes = positive (atoi (p[1]));
    }
  else if (streq (p[0], "reneg-pkts") && p[1])
    {
      ++i;
      options->renegotiate_packets = positive (atoi (p[1]));
    }
  else if (streq (p[0], "reneg-sec") && p[1])
    {
      ++i;
      options->renegotiate_seconds = positive (atoi (p[1]));
    }
  else if (streq (p[0], "hand-window") && p[1])
    {
      ++i;
      options->handshake_window = positive (atoi (p[1]));
    }
  else if (streq (p[0], "tran-window") && p[1])
    {
      ++i;
      options->transition_window = positive (atoi (p[1]));
    }
  else if (streq (p[0], "tls-auth") && p[1])
    {
      ++i;
      options->tls_auth_file = p[1];
      if (p[2])
	{
	  options->key_direction = ascii2keydirection (p[2]);
	  ++i;
	}
    }
  else if (streq (p[0], "key-method") && p[1])
    {
      ++i;
      options->key_method = atoi (p[1]);
      if (options->key_method < KEY_METHOD_MIN || options->key_method > KEY_METHOD_MAX)
	msg (M_USAGE, "key_method parameter (%d) must be >= %d and <= %d",
	     options->key_method,
	     KEY_METHOD_MIN,
	     KEY_METHOD_MAX);
    }
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
#ifdef TUNSETPERSIST
  else if (streq (p[0], "rmtun"))
    {
      options->persist_config = true;
      options->persist_mode = 0;
    }
  else if (streq (p[0], "mktun"))
    {
      options->persist_config = true;
      options->persist_mode = 1;
    }
#endif
  else
    {
      if (file)
	msg (M_USAGE, "Unrecognized option or missing parameter(s) in %s:%d: %s", file, line, p[0]);
      else
	msg (M_USAGE, "Unrecognized option or missing parameter(s): --%s", p[0]);
    }
  return i;
}
