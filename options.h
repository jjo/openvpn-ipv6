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

#include "basic.h"

extern const char title_string[];

/* Command line options */
struct options
{
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
  const char *ifconfig_remote;
#ifdef HAVE_GETTIMEOFDAY
  int shaper;
#endif
  int tun_mtu;          /* MTU of tun device */
  int tun_mtu_extra;
  int udp_mtu;          /* MTU of device over which tunnel packets pass via UDP */
  bool tun_mtu_defined; /* true if user overriding parm with command line option */
  bool udp_mtu_defined; /* true if user overriding parm with command line option */

  /* Advanced MTU negotiation and datagram fragmentation options */
  int mtu_discover_type; /* used if OS supports setting Path MTU discovery options on socket */
#ifdef FRAGMENT_ENABLE
  bool mtu_dynamic;             /* should we fragment and reassemble packets? */
  int mtu_min;
  bool mtu_min_defined;
  int mtu_max;
  bool mtu_max_defined;
  bool mtu_icmp;         /* if fragment=true, bounce back "fragmentation needed but DF set" ICMPs */
#endif

  bool mlock;
  int inactivity_timeout;
  int ping_send_timeout;        /* Send a UDP ping to remote every n seconds */
  int ping_rec_timeout;         /* Expect a UDP ping from remote at least once every n seconds */
  bool ping_timer_remote;       /* Run ping timer only if we have a remote address */
  bool tun_ipv6;                /* Build tun dev that supports IPv6 */

  #define PING_UNDEF   0
  #define PING_EXIT    1
  #define PING_RESTART 2
  int ping_rec_timeout_action;  /* What action to take on ping_rec_timeout (exit or restart)? */

  bool persist_tun;             /* Don't close/reopen TUN/TAP dev on SIGUSR1 or PING_RESTART */
  bool persist_local_ip;        /* Don't re-resolve local address on SIGUSR1 or PING_RESTART */
  bool persist_remote_ip;       /* Don't re-resolve remote address on SIGUSR1 or PING_RESTART */
  bool persist_key;             /* Don't re-read key files on SIGUSR1 or PING_RESTART */

#if PASSTOS_CAPABILITY
  bool passtos;                  
#endif

  int resolve_retry_seconds;    /* If hostname resolve fails, retry for n seconds */

  /* Misc parms */
  const char *username;
  const char *groupname;
  const char *chroot_dir;
  const char *cd_dir;
  const char *writepid;
  const char *up_script;
  const char *down_script;
  bool daemon;
  bool inetd;
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

#ifdef USE_CRYPTO
  /* Cipher parms */
  const char *shared_secret_file;
  bool ciphername_defined;
  const char *ciphername;
  bool authname_defined;
  const char *authname;
  int keysize;
  bool packet_id;
  const char *packet_id_file;
  bool iv;
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

  /* Disable options check between peers */
  bool disable_occ;
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
};

#define streq(x, y) (!strcmp((x), (y)))

void notnull (const char *arg, const char *description);

void usage_small (void);

void init_options (struct options *o);
void show_settings (const struct options *o);
char *options_string (const struct options *o);

void parse_argv (struct options* options, int argc, char *argv[]);

bool string_defined_equal (const char *s1, const char *s2);

int options_cmp_equal (const char *s1, const char *s2, size_t n);
