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

#define TITLE "OpenVPN " VERSION " Built On " __DATE__

/* Command line options */
struct options
{
  /* Networking parms */
  char *local;
  char *remote;
  int local_port;
  int remote_port;
  bool remote_float;
  char *ipchange;
  bool bind_local;
  char *dev;
  char *ifconfig_local;
  char *ifconfig_remote;
  int shaper;
  int tun_mtu;          /* MTU of tun device */
  int udp_mtu;          /* MTU of device over which tunnel packets pass via UDP */
  bool tun_mtu_defined; /* true if user overriding parm with command line option */
  bool udp_mtu_defined; /* true if user overriding parm with command line option */
  bool tun_af_inet;
#ifdef _POSIX_MEMLOCK
  bool mlock;
#endif
  int inactivity_timeout;
  int ping_send_timeout;        /* Send a UDP ping to remote every n seconds */
  int ping_rec_timeout;         /* Expect a UDP ping from remote at least once every n seconds */

  /* Misc parms */
  char *username;
  char *chroot_dir;
  char *up_script;
  char *down_script;
  bool daemon;
  int nice;
  int verbosity;
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
