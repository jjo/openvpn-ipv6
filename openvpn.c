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

#include "error.h"
#include "socket.h"
#include "openvpn.h"
#include "common.h"
#include "buffer.h"
#include "crypto.h"
#include "ssl.h"
#include "misc.h"
#include "lzo.h"
#include "tun.h"
#include "gremlin.h"
#include "interval.h"
#include "shaper.h"

#include "memdbg.h"

#define max(a,b) ((a) > (b) ? (a) : (b))

static const char usage_message[] =
  "%s\n"
  "\n"
  "Tunnel Options:\n"
  "--help          : Show options.\n"
  "--local host    : Local host name or ip address.\n"
  "--remote host   : Remote host name or ip address.\n"
  "--float         : Allow remote to change its IP address, such as through\n"
  "                  DHCP (this is the default if --remote is not used).\n"
  "--ipchange cmd  : Execute shell command cmd on remote ip address initial\n"
  "                  setting or change -- execute as: cmd ip-address port#\n"
  "                  (',' may be used to separate multiple args in cmd)\n"
  "--port port     : UDP port # for both local and remote.\n"
  "--lport port    : UDP port # for local (default=%d).\n"
  "--rport port    : UDP port # for remote (default=%d).\n"
  "--nobind        : Do not bind to local address and port.\n"
  "--dev tunX|tapX : TUN/TAP device (X can be omitted for dynamic device in\n"
  "                  Linux 2.4+).\n"
  "--ifconfig l r  : Configure TUN device to use IP address l as a local\n"
  "                  endpoint and r as a remote endpoint.  l & r should be\n"
  "                  swapped on the other peer.  l & r must be private\n"
  "                  addresses outside of the subnets used by either peer.\n"
  "                  Implies --udp-mtu %d if neither --udp-mtu or --tun-mtu\n"
  "                  explicitly specified.\n"
  "--shaper n      : Restrict output to peer to n bytes per second.\n"
  "--inactive n    : Exit after n seconds of inactivity on TUN/TAP device.\n"
  "--ping-exit n   : Exit if n seconds pass without reception of remote ping.\n"
  "--ping n        : Ping remote once every n seconds over UDP port.\n"
  "--tun-mtu n     : Take the TUN/TAP device MTU to be n and derive the\n"
  "                  UDP MTU from it (default=%d).\n"
  "--udp-mtu n     : Take the UDP device MTU to be n and derive the TUN MTU\n"
  "                  from it (disabled by default).\n"
  "--tun-af-inet   : Remove a leading htonl(AF_INET) from incoming tunnel\n"
  "                  data and add it onto outgoing tunnel data.\n"
  "                  This option should be used on the OpenBSD side of an\n"
  "                  OpenBSD <-> Linux tunnel (Experimental).\n"
#ifdef _POSIX_MEMLOCK
  "--mlock         : Disable Paging -- ensures key material and tunnel\n"
  "                  data will never be written to disk.\n"
#endif
  "--up cmd        : Shell cmd to execute after successful tun device open.\n"
  "                  Execute as: cmd tun/tap-dev tun-mtu udp-mtu \\\n"
  "                              ifconfig-local-ip ifconfig-remote-ip\n"              
  "                  (pre --user UID change)\n"
  "--down cmd      : Shell cmd to run after tun device close.\n"
  "                  (post --user UID change and/or --chroot)\n"
  "                  (script parameters are same as --up option)\n"
  "--user user     : Drop privileges to user after initialization.\n"
  "--chroot dir    : Chroot to this directory before initialization.\n"
  "--daemon        : Become a daemon.\n"
  "--nice n        : Change process priority (>0 = lower, <0 = higher).\n"
  "--verb n        : Set output verbosity to n (default=%d):\n"
  "                  (Level 5 is recommended if you want a good summary\n"
  "                  of what's happening without being swamped by output).\n"
  "                : 0 -- no output except fatal errors\n"
  "                : 1 -- startup header + non-fatal encryption & net errors\n"
  "                : 2 -- show all parameter settings\n"
  "                : 3 -- show key negotiations + gremlin net outages\n"
  "                : 4 -- show partial TLS debug info\n"
  "                : 5 -- show adaptive compress info\n"
  "                : 6 -- show keys\n"
  "                : 7 -- show verbose key negotiations\n"
  "                : 8 -- show all debug info\n"
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
  "--keysize n     : Size of cipher key in bits (optional).\n"
  "                  If unspecified, defaults to cipher-specific default.\n"
  "--no-replay     : Disable replay protection.\n"
  "--no-iv         : Disable cipher IV -- only allowed with CBC mode ciphers.\n"
  "--test-crypto   : Run a self-test of crypto features enabled.\n"
  "                  For debugging only.\n"
#ifdef USE_SSL
  "\n"
  "TLS Key Negotiation Options:\n"
  "(These options are meaningful only for TLS-mode)\n"
  "--tls-server    : Enable TLS and assume server role during TLS handshake.\n"
  "--tls-client    : Enable TLS and assume client role during TLS handshake.\n"
  "--ca file       : Certificate authority file in .pem format.\n"
  "--dh file       : File containing Diffie Hellman parameters\n"
  "                  in .pem format (for --tls-server only).\n"
  "                  Use \"openssl dhparam -out dh1024.pem 1024\" to generate.\n"
  "--cert file     : My signed certificate in .pem format -- must be signed\n"
  "                  by a Certificate Authority in --ca file.\n"
  "--key file      : My private key in .pem format.\n"
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
  "--tls-auth f    : Add an additional layer of authentication on top of the TLS\n"
  "                  control channel to protect against DOS attacks.\n"
  "                  f (required) is a shared-secret passphrase file.\n"
  "--askpass       : Get PEM password from controlling tty before we daemonize.\n"
  "--tls-verify cmd: Execute shell command cmd to verify the X509 name of a\n"
  "                  pending TLS connection that has otherwise passed all other\n"
  "                  tests of certification.  cmd should return 0 to allow\n"
  "                  TLS handshake to proceed, or 1 to fail.  (cmd is\n"
  "                  executed as 'cmd certificate_depth X509_NAME_oneline')\n"
  "                  (',' may be used to separate multiple args in cmd)\n"
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
#if !defined(OLD_TUN_TAP) && defined(TUNSETPERSIST)
  "\n"
  "TUN/TAP config mode (available with linux 2.4+):\n"
  "--mktun         : Create a persistent tunnel.\n"
  "--rmtun         : Remove a persistent tunnel.\n"
  "--dev tunX|tapX : tun/tap device\n"
#endif
 ;

/* Handle signals */

static volatile bool signal_received = 0;

static void
signal_handler (int signum)
{
  signal_received = signum;
  signal (signum, signal_handler);
}

/*
 * This is where the options defaults go.
 * Any option not explicitly set here
 * will be set to 0.
 */
static void
init_options (struct options *o)
{
  CLEAR (*o);
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
#define SHOW_STR(var)  SHOW_PARM(var, o->var, "'%s'")
#define SHOW_INT(var)  SHOW_PARM(var, o->var, "%d")
#define SHOW_BOOL(var) SHOW_PARM(var, (o->var ? "ENABLED" : "DISABLED"), "%s");

static void
show_settings (const struct options *o)
{
  msg (D_SHOW_PARMS, "Current Parameter Settings:");
  SHOW_STR (local);
  SHOW_STR (remote);

  SHOW_INT (local_port);
  SHOW_INT (remote_port);
  SHOW_BOOL (remote_float);
  SHOW_STR (ipchange);
  SHOW_BOOL (bind_local);
  SHOW_STR (dev);
  SHOW_STR (ifconfig_local);
  SHOW_STR (ifconfig_remote);
  SHOW_INT (shaper);
  SHOW_INT (tun_mtu);
  SHOW_BOOL (tun_mtu_defined);
  SHOW_INT (udp_mtu);
  SHOW_BOOL (udp_mtu_defined);
  SHOW_BOOL (tun_af_inet);
#ifdef _POSIX_MEMLOCK
  SHOW_BOOL (mlock);
#endif
  SHOW_INT (inactivity_timeout);
  SHOW_INT (ping_send_timeout);
  SHOW_INT (ping_rec_timeout);

  SHOW_STR (username);
  SHOW_STR (chroot_dir);
  SHOW_STR (up_script);
  SHOW_STR (down_script);
  SHOW_BOOL (daemon);
  SHOW_INT (nice);
  SHOW_INT (verbosity);
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

  SHOW_STR (tls_auth_file);
#endif
#endif
}

#if defined(USE_CRYPTO) && defined(USE_SSL)

/*
 * Build an options string to represent data channel encryption options.
 * This string must match exactly between peers.  The keysize is checked
 * separately by read_key().
 */
static char *
options_string (const struct options *o)
{
  struct buffer out = alloc_buf (128);
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

static char* comma_to_space(const char* src)
{
  char* ret = (char*) gc_malloc(strlen(src) + 1);
  char* dest = ret;
  char c;

  do {
    c = *src++;
    if (c == ',')
      c = ' ';
    *dest++ = c;
  } while (c);
  return ret;
}

static void
usage ()
{
  struct options o;
  init_options (&o);
#if defined(USE_CRYPTO) && defined(USE_SSL)
  printf (usage_message,
	  TITLE, o.local_port, o.remote_port, o.udp_mtu, o.tun_mtu, o.verbosity,
	  o.authname, o.ciphername, o.tls_timeout, o.renegotiate_seconds,
	  o.handshake_window, o.transition_window);
#elif defined(USE_CRYPTO)
  printf (usage_message,
	  TITLE, o.local_port, o.remote_port, o.udp_mtu, o.tun_mtu, o.verbosity,
	  o.authname, o.ciphername);
#else
  printf (usage_message,
	  TITLE, o.local_port, o.remote_port, o.udp_mtu, o.tun_mtu, o.verbosity);
#endif

  exit (1);
}

static void
usage_small ()
{
  printf ("Use --help for more information\n");
  exit (1);
}

static void
notnull (char *arg, char *description)
{
  if (!arg)
    {
      msg (M_WARN, "You must define %s", description);
      usage_small ();
    }
}

/*
 * For debugging, dump a packet in
 * nominally human-readable form.
 */
#if defined(USE_CRYPTO) && defined(USE_SSL)
#define TLS_MODE (tls_multi != NULL)
#define PROTO_DUMP(buf) protocol_dump(buf, \
				      PD_SHOW_DATA | \
				      (tls_multi ? PD_TLS : 0) | \
				      (options->tls_auth_file ? key_type.hmac_length : 0) \
				      )
#else
#define TLS_MODE (false)
#define PROTO_DUMP(buf) format_hex (BPTR (buf), BLEN (buf), 80)
#endif

static void print_frame_parms(int level, const struct frame *frame, const char* prefix)
{
  msg (level, "%s: mtu=%d extra_frame=%d extra_buffer=%d extra_tun=%d",
       prefix,
       frame->mtu,
       frame->extra_frame,
       frame->extra_buffer,
       frame->extra_tun);
}

static void frame_finalize(struct frame *frame, const struct options *options)
{
  if (options->tun_mtu_defined)
    {
      frame->mtu = options->tun_mtu;
    }
  else
    {
      ASSERT (options->udp_mtu_defined);
      frame->mtu = options->udp_mtu - frame->extra_frame;
    }

  if (frame->mtu < MIN_TUN_MTU)
    {
      msg (M_WARN, "TUN MTU value must be at least %d", MIN_TUN_MTU);
      print_frame_parms (M_FATAL, frame, "MTU is too small");
    }

  frame->extra_buffer += frame->extra_frame + frame->extra_tun;
}

/*
 * Do the work.  Initialize and enter main event loop.
 * Called after command line has been parsed.
 */
static int
openvpn (const struct options *options, struct sockaddr_in *remote_addr,
	 bool * one_time_init)
{
  int td, fm;

  const int gc_level = gc_new_level ();

  struct buffer to_tun = clear_buf ();
  struct buffer to_udp = clear_buf ();
  struct buffer buf = clear_buf ();
  struct buffer nullbuf = clear_buf ();

  fd_set reads, writes;

  struct udp_socket udp_socket;
  struct sockaddr_in to_udp_addr;

  int max_rw_size_udp = 0;

  char actual_dev[64];

  struct frame frame;

  time_t current;

  struct shaper shaper;

  struct event_timeout inactivity_interval;
  struct event_timeout ping_send_interval;
  struct event_timeout ping_rec_interval;

  /*
   * This string identifies a ping packet.
   * It should be of sufficient length and randomness
   * so as not to collide with other tunnel data.
   */
  static const unsigned char ping_string[] = {
    0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
    0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
  };

#ifdef USE_CRYPTO

#ifdef USE_SSL
  SSL_CTX *ssl_ctx = NULL;
  struct tls_multi *tls_multi = NULL;
  char *data_channel_options = NULL;
  struct interval tmp_int;
#endif

  struct key_type key_type;
  struct key_ctx_bi key_ctx_bi;

  struct buffer encrypt_buf = clear_buf ();
  struct buffer decrypt_buf = clear_buf ();

  struct crypto_options crypto_options;
  struct packet_id packet_id;
  unsigned char iv[EVP_MAX_IV_LENGTH];
#endif

#ifdef USE_LZO
  struct buffer lzo_compress_buf = clear_buf ();
  struct buffer lzo_decompress_buf = clear_buf ();
  struct lzo_compress_workspace lzo_compwork;
#endif

  struct buffer read_udp_buf = clear_buf ();
  struct buffer read_tun_buf = clear_buf ();

  msg (M_INFO, "%s", TITLE);

  CLEAR (udp_socket);
  CLEAR (frame);

#ifdef USE_CRYPTO
  if (!options->test_crypto)
    {
#endif
      if (!*one_time_init)
	{
#ifdef _POSIX_MEMLOCK
	  if (options->mlock) /* should we disable paging? */
	    do_mlockall(true);
#endif
	  /* chroot if requested */
	  do_chroot (options->chroot_dir);
	}

      /* open the UDP socket */
      udp_socket_init (&udp_socket, options->local, options->remote,
		       options->local_port, options->remote_port,
		       options->bind_local, options->remote_float,
		       remote_addr, options->ipchange);
#ifdef USE_CRYPTO
    }
#endif

#ifdef USE_CRYPTO

  /* Initialize crypto options */

  CLEAR (crypto_options);
  CLEAR (packet_id);
  CLEAR (iv);

  /* Start with a random IV and carry forward the residuals */
  if (options->iv)
    {
      randomize_iv (iv);
      crypto_options.iv = iv;
    }

  if (options->shared_secret_file)
    {
      /*
       * Static Key Mode
       */
      struct key key;

      /* Initialize packet ID tracking */
      if (options->packet_id)
	{
	  crypto_options.packet_id = &packet_id;
	  crypto_options.packet_id_long_form = true;
	}

      /* Get cipher & hash algorithms */
      init_key_type (&key_type, options->ciphername,
		     options->ciphername_defined, options->authname,
		     options->authname_defined, options->keysize);

      /* Compute MTU parameters */
      crypto_adjust_frame_parameters(&frame,
				     &key_type,
				     options->ciphername_defined,
				     options->iv,
				     options->packet_id,
				     true);

      check_replay_iv_consistency(&key_type, options->packet_id, options->iv);

      /* Read cipher and hmac keys from shared secret file */
      read_key_file (&key, options->shared_secret_file);

      /* Fix parity for DES keys and make sure not a weak key */
      fixup_key (&key, &key_type);
      if (!check_key (&key, &key_type)) /* This should be a very improbable failure */
	msg (M_FATAL, "Key in %s is bad.  Try making a new key with --genkey.",
	     options->shared_secret_file);

      /* Init cipher & hmac */
      init_key_ctx (&key_ctx_bi.encrypt, &key, &key_type, DO_ENCRYPT, "Static Encrypt");
      init_key_ctx (&key_ctx_bi.decrypt, &key, &key_type, DO_DECRYPT, "Static Decrypt");
      crypto_options.key_ctx_bi = &key_ctx_bi;

      /* Erase the key */
      CLEAR (key);

      if (options->test_crypto)
	{
	  frame_finalize (&frame, options);
	  test_crypto (&crypto_options, &frame);
	  signal_received = 0;
	  goto done;
	}
    }
#ifdef USE_SSL
  else if (options->tls_server || options->tls_client)
    {
      /*
       * TLS-based dynamic key exchange
       */
      struct tls_options to;
      struct key tls_auth_key;
      bool packet_id_long_form;

      ASSERT (!options->test_crypto);

      /* Get cipher & hash algorithms */
      init_key_type (&key_type, options->ciphername,
		     options->ciphername_defined, options->authname,
		     options->authname_defined, options->keysize);

      check_replay_iv_consistency(&key_type, options->packet_id, options->iv);

      /* In short form, unique datagram identifier is 32 bits, in long form 64 bits */
      packet_id_long_form = cfb_ofb_mode (&key_type);

      /* Compute MTU parameters */
      crypto_adjust_frame_parameters(&frame,
				     &key_type,
				     options->ciphername_defined,
				     options->iv,
				     options->packet_id,
				     packet_id_long_form);

      tls_adjust_frame_parameters(&frame);

      ASSERT (options->tls_server == !options->tls_client);

      tls_set_verify_command (options->tls_verify);

      CLEAR (to);
      to.key_type = key_type;
      to.server = options->tls_server;
      to.options = data_channel_options = options_string (options);
      to.packet_id = options->packet_id;
      to.packet_id_long_form = packet_id_long_form;
      to.transition_window = options->transition_window;
      to.handshake_window = options->handshake_window;
      to.packet_timeout = options->tls_timeout;
      to.renegotiate_bytes = options->renegotiate_bytes;
      to.renegotiate_packets = options->renegotiate_packets;
      to.renegotiate_seconds = options->renegotiate_seconds;

      /* TLS handshake authentication */
      if (options->tls_auth_file)
	{
	  get_tls_handshake_key (&key_type, &to.tls_auth_key,
				 options->tls_auth_file);
	  to.tls_auth.packet_id_long_form = true;
	  crypto_adjust_frame_parameters(&to.frame,
					 &key_type,
					 false,
					 false,
					 true,
					 true);
	}

      to.ssl_ctx = ssl_ctx = init_ssl (options->tls_server,
				       options->ca_file,
				       options->dh_file,
				       options->cert_file,
				       options->priv_key_file,
				       options->cipher_list);

      tls_multi = tls_multi_init (&to, &udp_socket);
    }
#endif
  else
    {
      /*
       * No encryption or authentication.
       */
      ASSERT (!options->test_crypto);
      CLEAR (key_ctx_bi);
      crypto_options.key_ctx_bi = &key_ctx_bi;
      msg (M_WARN,
	   "******* WARNING *******: all encryption and authentication features disabled -- all data will be tunnelled as cleartext");
    }

#else /* USE_CRYPTO */

  msg (M_WARN,
       "******* WARNING *******: OpenVPN built without OpenSSL -- encryption and authentication features disabled -- all data will be tunnelled as cleartext");

#endif /* USE_CRYPTO */

#ifdef USE_LZO
  if (options->comp_lzo)
    {
      lzo_compress_init (&lzo_compwork, options->comp_lzo_adaptive);
      lzo_adjust_frame_parameters (&frame);
    }
#endif

  /*
   * Make space for a uint32 to be removed from incoming TUN packets
   * and added to outgoing TUN packets.
   */
  if (options->tun_af_inet)
    tun_adjust_frame_parameters (&frame, sizeof (u_int32_t));

  /*
   * Fill in the blanks in the frame parameters structure,
   * make sure values are rational, etc.
   */
  frame_finalize (&frame, options);
  max_rw_size_udp = MAX_RW_SIZE_UDP (&frame);
  print_frame_parms (D_SHOW_PARMS, &frame, "Data Channel MTU parms");

#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (tls_multi)
    {
      int size;

      tls_multi_init_finalize (tls_multi, &frame);
      size = MAX_RW_SIZE_UDP (&tls_multi->opt.frame);
      if (size > max_rw_size_udp)
	max_rw_size_udp = size;
      print_frame_parms (D_SHOW_PARMS, &tls_multi->opt.frame, "Control Channel MTU parms");
    }
#endif

  /*
   * Now that we know all frame parameters, initialize
   * our buffers.
   */

  read_udp_buf = alloc_buf (BUF_SIZE (&frame));
  read_tun_buf = alloc_buf (BUF_SIZE (&frame));

#ifdef USE_CRYPTO
  encrypt_buf = alloc_buf (BUF_SIZE (&frame));
  decrypt_buf = alloc_buf (BUF_SIZE (&frame));
#endif

#ifdef USE_LZO
  if (options->comp_lzo)
    {
      lzo_compress_buf = alloc_buf (BUF_SIZE (&frame));
      lzo_decompress_buf = alloc_buf (BUF_SIZE (&frame));
    }
#endif

  /* open the tun device */
  td = open_tun (options->dev, actual_dev, sizeof (actual_dev));

  /* initialize traffic shaper */
  if (options->shaper)
    shaper_init (&shaper, options->shaper);

  /* do ifconfig */
  do_ifconfig (actual_dev,
	       options->ifconfig_local, options->ifconfig_remote,
	       MAX_RW_SIZE_TUN (&frame));

  /* run the up script */
  run_script (options->up_script, actual_dev, MAX_RW_SIZE_TUN (&frame), max_rw_size_udp,
	       options->ifconfig_local, options->ifconfig_remote);

  if (!*one_time_init)
    {
      /* change scheduling priority if requested */
      set_nice (options->nice);

      /* drop privileges if requested */
      set_user (options->username);
    }

  /* catch signals */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGHUP, signal_handler);
  signal (SIGPIPE, SIG_IGN);

  /*
   * MAIN EVENT LOOP
   *
   * Pipe UDP -> tun and tun -> UDP using nonblocked i/o.
   *
   * If multi_state is defined, multiplex a TLS
   * control channel over the UDP connection which
   * will be used for secure key exchange with our peer.
   *
   */

  fm = max (udp_socket.sd, td) + 1;
  current = time (NULL);

  /* initialize inactivity timeout */
  if (options->inactivity_timeout)
    event_timeout_init (&inactivity_interval, current, options->inactivity_timeout);

  /* initialize pings */

  if (options->ping_send_timeout)
    event_timeout_init (&ping_send_interval, 0, options->ping_send_timeout);

  if (options->ping_rec_timeout)
    event_timeout_init (&ping_rec_interval, current, options->ping_rec_timeout);

#if defined(USE_CRYPTO) && defined(USE_SSL)
  /* initialize tmp_int optimization that limits the number of times we call
     tls_multi_process in the main event loop */
  CLEAR (tmp_int);
  interval_trigger (&tmp_int, current);
#endif

  while (true)
    {
      int stat;
      struct timeval *tv = NULL;
      struct timeval timeval;

      /* initialize select() timeout */
      timeval.tv_sec = 0;
      timeval.tv_usec = 0;

#if defined(USE_CRYPTO) && defined(USE_SSL)
      /*
       * In TLS mode, let TLS level respond to any control-channel packets which were
       * received, or prepare any packets for transmission.
       *
       * tmp_int is purely an optimization that allows us to call tls_multi_process
       * less frequently when there's not much traffic on the control-channel.
       *
       */
      if (tls_multi)
	{
	  time_t t = 0;

	  if (interval_test (&tmp_int, current))
	    {
	      if (tls_multi_process (tls_multi, &to_udp, &to_udp_addr, &udp_socket, &t, current))
		interval_trigger(&tmp_int, current);
	    }
	  interval_set_timeout (&tmp_int, current, &t);

	  tv = &timeval;
	  timeval.tv_sec = t;
	  timeval.tv_usec = 0;
	}
#endif

      /*
       * Should we exit due to inactivity timeout?
       */
      if (options->inactivity_timeout)
	{
	  if (event_timeout_trigger (&inactivity_interval, current)) 
	    {
	      msg (M_INFO, "Inactivity timeout (--inactive), exiting");
	      signal_received = 0;
	      break;
	    }
	  event_timeout_wakeup (&inactivity_interval, current, &timeval);
	  tv = &timeval;
	}

      /*
       * Should we exit due to ping (or other authenticated packet)
       * not received in n seconds?
       */
      if (options->ping_rec_timeout)
	{
	  if (event_timeout_trigger (&ping_rec_interval, current)) 
	    {
	      msg (M_INFO, "Inactivity timeout (--ping-exit), exiting");
	      signal_received = 0;
	      break;
	    }
	  event_timeout_wakeup (&ping_rec_interval, current, &timeval);
	  tv = &timeval;
	}

      /*
       * Should we ping the remote?
       */
      if (options->ping_send_timeout)
	{
	  if (!to_udp.len)
	    {
	      if (event_timeout_trigger (&ping_send_interval, current))
		{
		  buf = read_tun_buf;
		  ASSERT (buf_init (&buf, EXTRA_FRAME (&frame)));
		  ASSERT (buf_safe (&buf, MAX_RW_SIZE_TUN (&frame)));
		  ASSERT (buf_write (&buf, ping_string, sizeof (ping_string)));

		  /*
		   * We will treat the ping like any other outgoing packet,
		   * encrypt, authenticate, etc.
		   */
#ifdef USE_LZO
		  if (options->comp_lzo)
		    lzo_compress (&buf, lzo_compress_buf, &lzo_compwork, &frame, current);
#endif
#ifdef USE_CRYPTO
#ifdef USE_SSL
		  if (tls_multi)
		    tls_pre_encrypt (tls_multi, &buf, &crypto_options);
#endif
		  openvpn_encrypt (&buf, encrypt_buf, &crypto_options, &frame, current);
#endif
		  udp_socket_get_outgoing_addr (&buf, &udp_socket,
						&to_udp_addr);
#ifdef USE_CRYPTO
#ifdef USE_SSL
		  if (tls_multi)
		    tls_post_encrypt (tls_multi, &buf);
#endif
#endif
		  to_udp = buf;
		  msg (D_PACKET_CONTENT, "SENT PING");
		}
	      event_timeout_wakeup (&ping_send_interval, current, &timeval);
	      tv = &timeval;
	    }
	}

      /* do a quick garbage collect */
      gc_collect (gc_level);

      /*
       * Set up for select call.
       */
      FD_ZERO (&reads);
      FD_ZERO (&writes);

      if (to_udp.len > 0)
	{
	  if (options->shaper)
	    {
	      const int delay = shaper_delay (&shaper); /* traffic shaping delay in microseconds */
	      if (delay)
		{
		  bool changed;
		  shaper_soonest_event (&timeval, delay);
		  tv = &timeval;
		}
	      else
		{
		  FD_SET (udp_socket.sd, &writes);
		}
	    }
	  else
	    {
	      FD_SET (udp_socket.sd, &writes);
	    }
	}
      else
	{
	  FD_SET (td, &reads);
	}

      if (to_tun.len > 0)
	FD_SET (td, &writes);
      else
	FD_SET (udp_socket.sd, &reads);

      /*
       * Possible scenarios:
       *  (1) udp port has data available to read
       *  (2) udp port is ready to accept more data to write
       *  (3) tun dev has data available to read
       *  (4) tun dev is ready to accept more data to write
       *  (5) we received a SIGINT or SIGTERM (handler sets signal_received)
       *  (6) timeout (tv) expired (timeout is set by either TLS level or traffic shaper)
       */
      stat = select (fm, &reads, &writes, NULL, tv);
      if (signal_received)
	break;
      current = time (NULL);

#if defined(USE_CRYPTO) && defined(USE_SSL)
      if (!stat) /* timeout? */
	continue;
#endif
      check_status (stat, "select");
      if (stat > 0)
	{
	  /* Incoming data on UDP port */
	  if (FD_ISSET (udp_socket.sd, &reads))
	    {
	      struct sockaddr_in from;
	      socklen_t fromlen = sizeof (from);
	      ASSERT (!to_tun.len);
	      buf = read_udp_buf;
	      ASSERT (buf_init (&buf, EXTRA_FRAME (&frame)));
	      ASSERT (buf_safe (&buf, max_rw_size_udp));
	      fromlen = sizeof (from);
	      buf.len = recvfrom (udp_socket.sd, BPTR (&buf), max_rw_size_udp, 0,
				  (struct sockaddr *) &from, &fromlen);
	      ASSERT (fromlen == sizeof (from));
	      check_status (buf.len, "read from udp");
	      if (options->gremlin) {
		if (!ask_gremlin())
		  buf.len = 0;
		corrupt_gremlin(&buf);
	      }
	      msg (D_PACKET_CONTENT, "UDP READ from %s: %s",
		   print_sockaddr (&from), PROTO_DUMP (&buf));
	      if (buf.len > 0)
		{
		  udp_socket_incoming_addr (&buf, &udp_socket, &from);
#ifdef USE_CRYPTO
#ifdef USE_SSL
		  if (tls_multi)
		    {
		      if (tls_pre_decrypt (tls_multi, &from, &buf, &crypto_options, current))
			{
			  interval_trigger(&tmp_int, current);
			  if (options->ping_rec_timeout)
			    event_timeout_reset (&ping_rec_interval, current);
			}
		    }
#endif
		  openvpn_decrypt (&buf, decrypt_buf, &crypto_options, &frame, current);
#endif
#ifdef USE_LZO
		  if (options->comp_lzo)
		    lzo_decompress (&buf, lzo_decompress_buf, &lzo_compwork, &frame);
#endif
		  if (!TLS_MODE)
		    udp_socket_set_outgoing_addr (&buf, &udp_socket, &from);

		  if (options->ping_rec_timeout && buf.len > 0)
		    event_timeout_reset (&ping_rec_interval, current);

		  if (buf_string_match (&buf, ping_string, sizeof (ping_string)))
		    {
		      msg (D_PACKET_CONTENT, "RECEIVED PING");
		      buf.len = 0;
		    }

		  to_tun = buf;
		}
	      else
		{
		  to_tun = nullbuf;
		}
	    }

	  /* Incoming data on TUN device */
	  if (FD_ISSET (td, &reads))
	    {
	      ASSERT (!to_udp.len);
	      buf = read_tun_buf;
	      ASSERT (buf_init (&buf, EXTRA_FRAME (&frame)));
	      ASSERT (buf_safe (&buf, MAX_RW_SIZE_TUN (&frame)));
	      buf.len = read (td, BPTR (&buf), MAX_RW_SIZE_TUN (&frame));
	      check_status (buf.len, "read from tun");
	      if (buf.len > 0)
		{
		  if (options->tun_af_inet)
		    tun_rm_head (&buf, AF_INET);
#ifdef USE_LZO
		  if (options->comp_lzo)
		    lzo_compress (&buf, lzo_compress_buf, &lzo_compwork, &frame, current);
#endif
#ifdef USE_CRYPTO
#ifdef USE_SSL
		  if (tls_multi)
		    tls_pre_encrypt (tls_multi, &buf, &crypto_options);
#endif
		  openvpn_encrypt (&buf, encrypt_buf, &crypto_options, &frame, current);
#endif
		  udp_socket_get_outgoing_addr (&buf, &udp_socket,
						&to_udp_addr);
#ifdef USE_CRYPTO
#ifdef USE_SSL
		  if (tls_multi)
		    tls_post_encrypt (tls_multi, &buf);
#endif
#endif
		  to_udp = buf;
		}
	      else
		{
		  to_udp = nullbuf;
		}
	    }

	  /* TUN device ready to accept write */
	  if (FD_ISSET (td, &writes))
	    {
	      ASSERT (to_tun.len > 0);
	      if (options->tun_af_inet)
		tun_add_head (&to_tun, AF_INET);
	      if (to_tun.len <= MAX_RW_SIZE_TUN(&frame))
		{
		  const int size = write (td, BPTR (&to_tun), BLEN (&to_tun));
		  check_status (size, "write to tun");
		}
	      else
		{
		  msg (D_LINK_ERRORS, "TUN packet too large on write (%d,%d)",
		       to_tun.len,
		       MAX_RW_SIZE_TUN(&frame));
		}

	      /*
	       * Putting the --inactive timeout reset here, ensures that we will timeout
	       * if the remote goes away, even if we are trying to send data to the
	       * remote and failing.
	       */
	      if (options->inactivity_timeout)
		event_timeout_reset (&inactivity_interval, current);

	      to_tun = nullbuf;
	    }

	  /* UDP port ready to accept write */
	  if (FD_ISSET (udp_socket.sd, &writes))
	    {
	      if (to_udp.len > 0 && to_udp.len <= max_rw_size_udp)
		{
		  int size;
		  ASSERT (ADDR (to_udp_addr));
		  if (!options->gremlin || ask_gremlin())
		    {
		      if (options->shaper)
			shaper_wrote_bytes (&shaper, BLEN (&to_udp));
		      if (options->ping_send_timeout)
			event_timeout_reset (&ping_send_interval, current);
		      size = sendto (udp_socket.sd, BPTR (&to_udp), BLEN (&to_udp), 0,
				     (struct sockaddr *) &to_udp_addr,
				     (socklen_t) sizeof (to_udp_addr));
		    }
		  else
		    size = 0;
		  check_status (size, "write to udp");

		  if (size > 0)
		    {
		      if (size != BLEN (&to_udp))
			msg (D_LINK_ERRORS, "UDP packet was fragmented on write to %s",
			     print_sockaddr (&to_udp_addr));
		    }

		  msg (D_PACKET_CONTENT, "UDP WRITE to %s: %s",
		       print_sockaddr (&to_udp_addr), PROTO_DUMP (&to_udp));
		}
	      else
		{
		  msg (D_LINK_ERRORS, "UDP packet too large on write to %s (%d,%d)",
		       print_sockaddr (&to_udp_addr),
		       to_udp.len,
		       max_rw_size_udp);
		}
	      to_udp = nullbuf;
	    }
	}
    }

  if (signal_received)
    msg (M_INFO, "Signal %d received, exiting", signal_received);

  /* cleanup */
  udp_socket_close (&udp_socket);
  close (td);
  free_buf (&read_udp_buf);
  free_buf (&read_tun_buf);

#ifdef USE_LZO
  if (options->comp_lzo)
    {
      lzo_compress_uninit (&lzo_compwork);
      free_buf (&lzo_compress_buf);
      free_buf (&lzo_decompress_buf);
    }
#endif

#ifdef USE_CRYPTO
  if (options->shared_secret_file)
    free_key_ctx_bi (&key_ctx_bi);

  free_buf (&encrypt_buf);
  free_buf (&decrypt_buf);

#ifdef USE_SSL
  if (tls_multi)
    tls_multi_free (tls_multi, true);

  if (data_channel_options)
    free (data_channel_options);

  if (ssl_ctx)
    SSL_CTX_free (ssl_ctx);
#endif
#endif /* USE_CRYPTO */

  /* Run the down script -- note that it will run at reduced
     privilege if, for example, "--user nobody" was used. */
  run_script (options->down_script, actual_dev, MAX_RW_SIZE_TUN (&frame), max_rw_size_udp,
	      options->ifconfig_local, options->ifconfig_remote);

 done:
  /* pop our garbage collection level */
  gc_free_level (gc_level);

  /* if we get called again due to SIGHUP, this tells us
     that it's not the first time */
  *one_time_init = true;

  /* return the signal that brought us here */
  {
    int s = signal_received;
    signal_received = 0;
    return s;
  }
}

#define streq(x, y) (!strcmp((x), (y)))

#define OPTMIN(opt, min) if (opt > min) opt = min

static inline int
positive (int i)
{
  return i < 0 ? 0 : i;
}

int
main (int argc, char *argv[])
{
  bool persist_config = false;
  int persist_mode = 1;
  int i;

#ifdef USE_CRYPTO
  bool askpass = false;
  bool show_ciphers = false;
  bool show_digests = false;
#ifdef USE_SSL
  bool show_tls_ciphers = false;
#endif
  bool genkey = false;
#endif

  const int gc_level = gc_new_level ();

  struct options options;
  init_options (&options);

  error_reset ();

#ifdef PID_TEST
  packet_id_interactive_test();
  return 0;
#endif

  /* usage message */
  if (argc <= 1)
    usage ();

  /* parse command line */
  for (i = 1; i < argc; ++i)
    {
      char *p1 = argv[i];
      char *p2 = NULL;
      char *p3 = NULL;
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
      if (streq (p1, "--help"))
	{
	  usage ();
	}
      else if (streq (p1, "--dev") && p2)
	{
	  ++i;
	  options.dev = p2;
	}
      else if (streq (p1, "--ifconfig") && p2 && p3)
	{
	  options.ifconfig_local = p2;
	  options.ifconfig_remote = p3;
	  options.udp_mtu_defined = true;
	  i += 2;
	}
      else if (streq (p1, "--local") && p2)
	{
	  ++i;
	  options.local = p2;
	}
      else if (streq (p1, "--remote") && p2)
	{
	  ++i;
	  options.remote = p2;
	}
      else if (streq (p1, "--ipchange") && p2)
	{
	  ++i;
	  options.ipchange = comma_to_space(p2);
	}
      else if (streq (p1, "--float"))
	{
	  options.remote_float = true;
	}
      else if (streq (p1, "--gremlin"))
	{
	  options.gremlin = true;
	}
      else if (streq (p1, "--user") && p2)
	{
	  ++i;
	  options.username = p2;
	}
      else if (streq (p1, "--chroot") && p2)
	{
	  ++i;
	  options.chroot_dir = p2;
	}
      else if (streq (p1, "--up") && p2)
	{
	  ++i;
	  options.up_script = p2;
	}
      else if (streq (p1, "--down") && p2)
	{
	  ++i;
	  options.down_script = p2;
	}
      else if (streq (p1, "--daemon"))
	{
	  options.daemon = true;
	}
#ifdef _POSIX_MEMLOCK
      else if (streq (p1, "--mlock"))
	{
	  options.mlock = true;
	  do_mlockall(false);
	}
#endif
      else if (streq (p1, "--verb") && p2)
	{
	  ++i;
	  options.verbosity = positive (atoi (p2));
	}
      else if (streq (p1, "--udp-mtu") && p2)
	{
	  ++i;
	  options.udp_mtu = positive (atoi (p2));
	  options.udp_mtu_defined = true;
	}
      else if (streq (p1, "--tun-mtu") && p2)
	{
	  ++i;
	  options.tun_mtu = positive (atoi (p2));
	  options.tun_mtu_defined = true;
	}
      else if (streq (p1, "--tun-af-inet"))
	{
	  options.tun_af_inet = true;
	}
      else if (streq (p1, "--nice") && p2)
	{
	  ++i;
	  options.nice = atoi (p2);
	}
      else if (streq (p1, "--shaper") && p2)
	{
	  ++i;
	  options.shaper = atoi (p2);
	  if (options.shaper < SHAPER_MIN || options.shaper > SHAPER_MAX)
	    {
	      msg (M_WARN, "bad --shaper value, must be between %d and %d",
		   SHAPER_MIN, SHAPER_MAX);
	      usage_small ();
	    }
	}
      else if (streq (p1, "--port") && p2)
	{
	  ++i;
	  options.local_port = options.remote_port = atoi (p2);
	  if (options.local_port <= 0 || options.remote_port <= 0)
	    {
	      msg (M_WARN, "Bad port number: %s", p2);
	      usage_small ();
	    }
	}
      else if (streq (p1, "--lport") && p2)
	{
	  ++i;
	  options.local_port = atoi (p2);
	  if (options.local_port <= 0)
	    {
	      msg (M_WARN, "Bad local port number: %s", p2);
	      usage_small ();
	    }
	}
      else if (streq (p1, "--rport") && p2)
	{
	  ++i;
	  options.remote_port = atoi (p2);
	  if (options.remote_port <= 0)
	    {
	      msg (M_WARN, "Bad remote port number: %s", p2);
	      usage_small ();
	    }
	}
      else if (streq (p1, "--nobind"))
	{
	  options.bind_local = false;
	}
      else if (streq (p1, "--inactive") && p2)
	{
	  ++i;
	  options.inactivity_timeout = positive (atoi (p2));
	}
      else if (streq (p1, "--ping") && p2)
	{
	  ++i;
	  options.ping_send_timeout = positive (atoi (p2));
	}
      else if (streq (p1, "--ping-exit") && p2)
	{
	  ++i;
	  options.ping_rec_timeout = positive (atoi (p2));
	}
#ifdef USE_LZO
      else if (streq (p1, "--comp-lzo"))
	{
	  options.comp_lzo = true;
	}
      else if (streq (p1, "--comp-noadapt"))
	{
	  options.comp_lzo_adaptive = false;
	}
#endif /* USE_LZO */
#ifdef USE_CRYPTO
      else if (streq (p1, "--show-ciphers"))
	{
	  show_ciphers = true;
	}
      else if (streq (p1, "--show-digests"))
	{
	  show_digests = true;
	}
      else if (streq (p1, "--secret") && p2)
	{
	  ++i;
	  options.shared_secret_file = p2;
	}
      else if (streq (p1, "--genkey"))
	{
	  genkey = true;
	}
      else if (streq (p1, "--auth") && p2)
	{
	  ++i;
	  options.authname_defined = true;
	  options.authname = p2;
	  if (streq (options.authname, "none"))
	    {
	      options.authname_defined = false;
	      options.authname = NULL;
	    }
	}
      else if (streq (p1, "--auth"))
	{
	  options.authname_defined = true;
	}
      else if (streq (p1, "--cipher") && p2)
	{
	  ++i;
	  options.ciphername_defined = true;
	  options.ciphername = p2;
	  if (streq (options.ciphername, "none"))
	    {
	      options.ciphername_defined = false;
	      options.ciphername = NULL;
	    }
	}
      else if (streq (p1, "--cipher"))
	{
	  options.ciphername_defined = true;
	}
      else if (streq (p1, "--no-replay"))
	{
	  options.packet_id = false;
	}
      else if (streq (p1, "--no-iv"))
	{
	  options.iv = false;
	}
      else if (streq (p1, "--test-crypto"))
	{
	  options.test_crypto = true;
	}
      else if (streq (p1, "--keysize") && p2)
	{
	  ++i;
	  options.keysize = atoi (p2) / 8;
	  if (options.keysize < 0 || options.keysize > MAX_CIPHER_KEY_LENGTH)
	    {
	      msg (M_WARN, "Bad keysize: %s", p2);
	      usage_small ();
	    }
	}
#ifdef USE_SSL
      else if (streq (p1, "--show-tls"))
	{
	  show_tls_ciphers = true;
	}
      else if (streq (p1, "--tls-server"))
	{
	  options.tls_server = true;
	}
      else if (streq (p1, "--tls-client"))
	{
	  options.tls_client = true;
	}
      else if (streq (p1, "--ca") && p2)
	{
	  ++i;
	  options.ca_file = p2;
	}
      else if (streq (p1, "--dh") && p2)
	{
	  ++i;
	  options.dh_file = p2;
	}
      else if (streq (p1, "--cert") && p2)
	{
	  ++i;
	  options.cert_file = p2;
	}
      else if (streq (p1, "--key") && p2)
	{
	  ++i;
	  options.priv_key_file = p2;
	}
      else if (streq (p1, "--askpass"))
	{
	  askpass = true;
	}
      else if (streq (p1, "--tls-cipher") && p2)
	{
	  ++i;
	  options.cipher_list = p2;
	}
      else if (streq (p1, "--tls-verify") && p2)
	{
	  ++i;
	  options.tls_verify = comma_to_space(p2);
	}
      else if (streq (p1, "--tls_timeout") && p2)
	{
	  ++i;
	  options.tls_timeout = positive (atoi (p2));
	}
      else if (streq (p1, "--reneg-bytes") && p2)
	{
	  ++i;
	  options.renegotiate_bytes = positive (atoi (p2));
	}
      else if (streq (p1, "--reneg-pkts") && p2)
	{
	  ++i;
	  options.renegotiate_packets = positive (atoi (p2));
	}
      else if (streq (p1, "--reneg-sec") && p2)
	{
	  ++i;
	  options.renegotiate_seconds = positive (atoi (p2));
	}
      else if (streq (p1, "--hand-window") && p2)
	{
	  ++i;
	  options.handshake_window = positive (atoi (p2));
	}
      else if (streq (p1, "--tran-window") && p2)
	{
	  ++i;
	  options.transition_window = positive (atoi (p2));
	}
      else if (streq (p1, "--tls-auth") && p2)
	{
	  ++i;
	  options.tls_auth_file = p2;
	}
      else if (streq (p1, "--sizeof"))
	{
	  printf("sizeof (struct tls_multi) = %d\n", sizeof(struct tls_multi));
	  goto exit;
	}

#endif /* USE_SSL */
#endif /* USE_CRYPTO */
#if !defined(OLD_TUN_TAP) && defined(TUNSETPERSIST)
      else if (streq (p1, "--rmtun"))
	{
	  persist_config = true;
	  persist_mode = 0;
	}
      else if (streq (p1, "--mktun"))
	{
	  persist_config = true;
	  persist_mode = 1;
	}
#endif
      else
	{
	  msg (M_WARN, "Unrecognized option or missing parameter(s): %s", p1);
	  usage_small ();
	}
    }

#ifdef USE_CRYPTO
  if (show_ciphers || show_digests
#ifdef USE_SSL
      || show_tls_ciphers
#endif
    )
    {
      init_ssl_lib ();
      if (show_ciphers)
	show_available_ciphers ();
      if (show_digests)
	show_available_digests ();
#ifdef USE_SSL
      if (show_tls_ciphers)
	show_available_tls_ciphers ();
#endif
      free_ssl_lib ();
      goto exit;
    }
  if (genkey)
    {
      struct key key;
      notnull (options.shared_secret_file,
	       "shared secret output file (--secret)");
      generate_key_random (&key, NULL);
      write_key_file (&key, options.shared_secret_file);
      CLEAR (key);
      goto exit;
    }
#endif
#if !defined(OLD_TUN_TAP) && defined(TUNSETPERSIST)
  if (persist_config)
    {
      notnull (options.dev, "tun/tap device (--dev)");
      tuncfg (options.dev, persist_mode);
    }
  else
#endif
    {
#ifdef USE_CRYPTO
      if (options.test_crypto)
	{
	  notnull (options.shared_secret_file, "key file (--secret)");
	}
      else
#endif
      notnull (options.dev, "tun/tap device (--dev)");

      if (options.tun_mtu_defined && options.udp_mtu_defined)
	{
	  printf ("only one of --tun-mtu or --udp-mtu may be defined (note that --ifconfig implies --udp-mtu %d)\n", DEFAULT_UDP_MTU);
	  usage_small ();
	}

      if (!options.tun_mtu_defined && !options.udp_mtu_defined)
	options.tun_mtu_defined = true;

#ifdef USE_CRYPTO

      init_ssl_lib ();

#ifdef USE_SSL
      if (options.tls_server + options.tls_client +
	  (options.shared_secret_file != NULL) > 1)
	{
	  printf ("specify only one of --tls-server, --tls-client, or --secret\n");
	  usage_small ();
	}
      if (options.tls_server)
	{
	  notnull (options.dh_file, "DH file (--dh)");
	}
      if (options.tls_server || options.tls_client)
	{
	  notnull (options.ca_file, "CA file (--ca)");
	  notnull (options.cert_file, "certificate file (--cert)");
	  notnull (options.priv_key_file, "private key file (--key)");
	  if (askpass)
	    pem_password_callback (NULL, 0, 0, NULL);
	}
      else
	{
	  /*
	   * Make sure user doesn't specify any TLS options
	   * when in non-TLS mode.
	   */

          #define MUST_BE_UNDEF(parm) if (options.parm != def.parm) msg (M_FATAL, err, #parm);

	  const char err[] = "Parameter %s can only be specified in TLS-mode, i.e. where --tls-server or --tls-client is also specified.";
	  struct options def;
	  init_options (&def);
	  MUST_BE_UNDEF (ca_file);
	  MUST_BE_UNDEF (dh_file);
	  MUST_BE_UNDEF (cert_file);
	  MUST_BE_UNDEF (priv_key_file);
	  MUST_BE_UNDEF (cipher_list);
	  MUST_BE_UNDEF (tls_verify);
	  MUST_BE_UNDEF (tls_timeout);
	  MUST_BE_UNDEF (renegotiate_bytes);
	  MUST_BE_UNDEF (renegotiate_packets);
	  MUST_BE_UNDEF (renegotiate_seconds);
	  MUST_BE_UNDEF (handshake_window);
	  MUST_BE_UNDEF (transition_window);
	  MUST_BE_UNDEF (tls_auth_file);
	}
        #undef MUST_BE_UNDEF
#endif
#endif

      set_check_status (D_LINK_ERRORS, D_READ_WRITE);
      set_debug_level (options.verbosity);

      /* Become a daemon if requested */
      become_daemon (options.daemon);

      show_settings (&options);

      /* Do Work */
      {
	bool one_time_init = false;
	struct sockaddr_in remote_addr;
	CLEAR (remote_addr);
	while (openvpn (&options, &remote_addr, &one_time_init) == SIGHUP)
	  msg (M_WARN, "SIGHUP received, restarting");
      }

#ifdef USE_CRYPTO
      free_ssl_lib ();
#endif
    }

 exit:
  /* pop our garbage collection level */
  gc_free_level (gc_level);

  return 0;
}
