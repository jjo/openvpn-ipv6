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

#include "basic.h"

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
  char *local;
  char *remote;
  int local_port;
  int remote_port;
  bool remote_float;
  char *ipchange;
  bool bind_local;
  char *dev;
  char *dev_type;
  char *ifconfig_local;
  char *ifconfig_remote;
  int shaper;
  int tun_mtu;          /* MTU of tun device */
  int udp_mtu;          /* MTU of device over which tunnel packets pass via UDP */
  bool tun_mtu_defined; /* true if user overriding parm with command line option */
  bool udp_mtu_defined; /* true if user overriding parm with command line option */
  bool mlock;
  int inactivity_timeout;
  int ping_send_timeout;        /* Send a UDP ping to remote every n seconds */
  int ping_rec_timeout;         /* Expect a UDP ping from remote at least once every n seconds */

  #define PING_UNDEF   0
  #define PING_EXIT    1
  #define PING_RESTART 2
  int ping_rec_timeout_action;  /* What action to take on ping_rec_timeout (exit or restart)? */

  bool persist_tun;             /* Don't close/reopen tun/tap dev on SIGUSR1 or PING_RESTART */
  bool persist_local_ip;        /* Don't re-resolve local address on SIGUSR1 or PING_RESTART */
  bool persist_remote_ip;       /* Don't re-resolve remote address on SIGUSR1 or PING_RESTART */
  bool persist_key;             /* Don't re-read key files on SIGUSR1 or PING_RESTART */

  int resolve_retry_seconds;    /* If hostname resolve fails, retry for n seconds */

  /* Misc parms */
  char *username;
  char *chroot_dir;
  char *cd_dir;
  char *writepid;
  char *up_script;
  char *down_script;
  bool daemon;
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
  char *shared_secret_file;
  bool ciphername_defined;
  char *ciphername;
  bool authname_defined;
  char *authname;
  int keysize;
  bool packet_id;
  bool iv;
  bool test_crypto;

#ifdef USE_SSL
  /* TLS (control channel) parms */
  bool tls_server;
  bool tls_client;
  char *ca_file;
  char *dh_file;
  char *cert_file;
  char *priv_key_file;
  char *cipher_list;
  char *tls_verify;

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
  char *tls_auth_file;		/* shared secret */
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
};

#define streq(x, y) (!strcmp((x), (y)))

void notnull (char *arg, char *description);

void usage_small ();

void init_options (struct options *o);
void show_settings (const struct options *o);
char *options_string (const struct options *o);

void parse_argv (struct options* options, int argc, char *argv[]);
