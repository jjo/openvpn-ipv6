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

#ifndef OPTIONS_H
#define OPTIONS_H

#include "basic.h"
#include "mtu.h"
#include "route.h"
#include "tun.h"

/*
 * Maximum number of parameters to an options,
 * including the option name itself.
 */
#define MAX_PARMS 5

extern const char title_string[];

/* Command line options */
struct options
{
  /* first config file */
  const char *config;

  /* mode parms */
  bool persist_config;
  int persist_mode;

#ifdef USE_CRYPTO
  bool askpass;
  bool show_ciphers;
  bool show_digests;
#ifdef USE_SSL
  bool show_tls_ciphers;
#endif
  bool genkey;
#endif

  /* Networking parms */
  const char *local;
  const char *remote;
  int local_port;
  int remote_port;
  bool remote_float;
  const char *ipchange;
  bool bind_local;
  const char *dev;
  const char *dev_type;
  const char *dev_node;
  const char *ifconfig_local;
  const char *ifconfig_remote_netmask;
  bool ifconfig_noexec;
  bool ifconfig_nowarn;
#ifdef HAVE_GETTIMEOFDAY
  int shaper;
#endif
  int tun_mtu;           /* MTU of tun device */
  int tun_mtu_extra;
  bool tun_mtu_extra_defined;
  int link_mtu;          /* MTU of device over which tunnel packets pass via TCP/UDP */
  bool tun_mtu_defined;  /* true if user overriding parm with command line option */
  bool link_mtu_defined; /* true if user overriding parm with command line option */

  /* Protocol type (PROTO_UDP or PROTO_TCP) */
  int proto;
  int connect_retry_seconds;
  bool connect_retry_defined;

  /* Advanced MTU negotiation and datagram fragmentation options */
  int mtu_discover_type; /* used if OS supports setting Path MTU discovery options on socket */
  bool mtu_test;

#ifdef FRAGMENT_ENABLE
  int fragment;          /* internal fragmentation size */
#endif

  bool mlock;
  int inactivity_timeout;
  int ping_send_timeout;        /* Send a TCP/UDP ping to remote every n seconds */
  int ping_rec_timeout;         /* Expect a TCP/UDP ping from remote at least once every n seconds */
  bool ping_timer_remote;       /* Run ping timer only if we have a remote address */
  bool tun_ipv6;                /* Build tun dev that supports IPv6 */

# define PING_UNDEF   0
# define PING_EXIT    1
# define PING_RESTART 2
  int ping_rec_timeout_action;  /* What action to take on ping_rec_timeout (exit or restart)? */

  bool persist_tun;             /* Don't close/reopen TUN/TAP dev on SIGUSR1 or PING_RESTART */
  bool persist_local_ip;        /* Don't re-resolve local address on SIGUSR1 or PING_RESTART */
  bool persist_remote_ip;       /* Don't re-resolve remote address on SIGUSR1 or PING_RESTART */
  bool persist_key;             /* Don't re-read key files on SIGUSR1 or PING_RESTART */

  int mssfix;                   /* Upper bound on TCP MSS */
  bool mssfix_defined;

#if PASSTOS_CAPABILITY
  bool passtos;                  
#endif

  int resolve_retry_seconds;    /* If hostname resolve fails, retry for n seconds */

  struct tuntap_options tuntap_options;

  /* Misc parms */
  const char *username;
  const char *groupname;
  const char *chroot_dir;
  const char *cd_dir;
  const char *writepid;
  const char *up_script;
  const char *down_script;
  bool up_delay;
  bool up_restart;
  bool daemon;

  /* inetd modes defined in socket.h */
  int inetd;

  bool log;
  int nice;
#ifdef USE_PTHREAD
  int nice_work;
#endif
  int verbosity;
  int mute;
  bool gremlin;

#ifdef USE_LZO
  bool comp_lzo;
  bool comp_lzo_adaptive;
#endif

  /* route management */
  const char *route_script;
  const char *route_default_gateway;
  bool route_noexec;
  int route_delay;
  bool route_delay_defined;
  struct route_option_list routes;

  /* http proxy */
  const char *http_proxy_server;
  int http_proxy_port;
  const char *http_proxy_auth_method;
  const char *http_proxy_auth_file;
  bool http_proxy_retry;

  /* socks proxy */
  const char *socks_proxy_server;
  int socks_proxy_port;
  bool socks_proxy_retry;

  /* Enable options consistency check between peers */
  bool occ;

#ifdef USE_CRYPTO
  /* Cipher parms */
  const char *shared_secret_file;
  int key_direction;
  bool ciphername_defined;
  const char *ciphername;
  bool authname_defined;
  const char *authname;
  int keysize;
  bool replay;
  int replay_window;
  int replay_time;
  const char *packet_id_file;
  bool use_iv;
  bool test_crypto;

#ifdef USE_SSL
  /* TLS (control channel) parms */
  bool tls_server;
  bool tls_client;
  const char *ca_file;
  const char *dh_file;
  const char *cert_file;
  const char *priv_key_file;
  const char *cipher_list;
  const char *tls_verify;
  const char *tls_remote;
  const char *crl_file;

  /* data channel key exchange method */
  int key_method;

  /* Per-packet timeout on control channel */
  int tls_timeout;

  /* Data channel key renegotiation parameters */
  int renegotiate_bytes;
  int renegotiate_packets;
  int renegotiate_seconds;

  /* Data channel key handshake must finalize
     within n seconds of handshake initiation. */
  int handshake_window;

  /* Old key allowed to live n seconds after new key goes active */
  int transition_window;

  /* Special authentication MAC for TLS control channel */
  const char *tls_auth_file;		/* shared secret */

  /* Allow only one session */
  bool single_session;

#endif /* USE_SSL */
#endif /* USE_CRYPTO */
};

#define streq(x, y) (!strcmp((x), (y)))

void notnull (const char *arg, const char *description);

void usage_small (void);

void init_options (struct options *o);
void setenv_settings (const struct options *o);
void show_settings (const struct options *o);

void parse_argv (struct options* options, int argc, char *argv[]);

bool string_defined_equal (const char *s1, const char *s2);

const char *options_string_version (const char* s);

char *options_string (const struct options *o,
		      const struct frame *frame,
		      const struct tuntap *tt,
		      bool remote);

int options_cmp_equal (char *actual, const char *expected, size_t actual_n);

void options_warning (char *actual, const char *expected, size_t actual_n);

#endif
