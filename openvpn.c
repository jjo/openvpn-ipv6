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

#include "common.h"
#include "error.h"
#include "integer.h"
#include "options.h"
#include "socket.h"
#include "buffer.h"
#include "crypto.h"
#include "ssl.h"
#include "misc.h"
#include "lzo.h"
#include "tun.h"
#include "mss.h"
#include "gremlin.h"
#include "shaper.h"
#include "thread.h"
#include "interval.h"
#include "io.h"
#include "fragment.h"
#include "proxy.h"
#include "socks.h"
#include "openvpn.h"
#include "win32.h"

#include "memdbg.h"

/*
 * This random string identifies an OpenVPN ping packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 */
static const uint8_t ping_string[] = {
  0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
  0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

/*
 * This random string identifies an OpenVPN
 * options consistency check packet.
 * It should be of sufficient length and randomness
 * so as not to collide with other tunnel data.
 *
 * The OCC protocol is as follows:
 *
 * occ_magic -- (16 octets)
 *
 * type [OCC_REQUEST | OCC_REPLY] (1 octet)
 * null terminated options string if OCC_REPLY (variable)
 *
 * When encryption is used, the OCC packet
 * is encapsulated within the encrypted
 * envelope.
 */

static const uint8_t occ_magic[] = {
  0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
  0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c
};

/*
 * OCC protocol opcodes used for options consistency checks.
 */

#define OCC_REQUEST   0  /* request options string from peer */
#define OCC_REPLY     1  /* deliver options string to peer */

/*
 * Send an OCC_REQUEST once every OCC_INTERVAL
 * seconds until a reply is received.
 *
 * If we haven't received a reply after
 * OCC_N_TRIES, give up.
 */
#define OCC_INTERVAL_SECONDS 10
#define OCC_N_TRIES          12

/*
 * Other OCC protocol opcodes used to estimate the MTU empirically.
 */
#define OCC_MTU_LOAD_REQUEST   2 /* Ask peer to send a big packet to us */
#define OCC_MTU_LOAD           3 /* Send a big packet to peer */
#define OCC_MTU_REQUEST        4 /* Ask peer to tell us the largest
				    packet it has received from us so far */
#define OCC_MTU_REPLY          5 /* Send largest packet size to peer */

/*
 * Process one command from mtu_load_test_sequence
 * once every n seconds, if --mtu-test is specified.
 */
#define OCC_MTU_LOAD_INTERVAL_SECONDS 3

/*
 * Used to conduct a load test command sequence
 * of UDP connection for empirical MTU measurement.
 */
struct mtu_load_test
{
  int op;     /* OCC opcode to send to peer */
  int delta;  /* determine packet size to send by using
		 this delta against currently
	         configured MTU */
};

static const struct mtu_load_test mtu_load_test_sequence[] = {

  { OCC_MTU_LOAD_REQUEST, -1000 },
  { OCC_MTU_LOAD,         -1000 },
  { OCC_MTU_LOAD_REQUEST, -1000 },
  { OCC_MTU_LOAD,         -1000 },
  { OCC_MTU_LOAD_REQUEST, -1000 },
  { OCC_MTU_LOAD,         -1000 },

  { OCC_MTU_LOAD_REQUEST, -500 },
  { OCC_MTU_LOAD,         -500 },
  { OCC_MTU_LOAD_REQUEST, -500 },
  { OCC_MTU_LOAD,         -500 },
  { OCC_MTU_LOAD_REQUEST, -500 },
  { OCC_MTU_LOAD,         -500 },

  { OCC_MTU_LOAD_REQUEST, -750 },
  { OCC_MTU_LOAD,         -750 },
  { OCC_MTU_LOAD_REQUEST, -750 },
  { OCC_MTU_LOAD,         -750 },
  { OCC_MTU_LOAD_REQUEST, -750 },
  { OCC_MTU_LOAD,         -750 },

  { OCC_MTU_LOAD_REQUEST, -400 },
  { OCC_MTU_LOAD,         -400 },
  { OCC_MTU_LOAD_REQUEST, -400 },
  { OCC_MTU_LOAD,         -400 },
  { OCC_MTU_LOAD_REQUEST, -400 },
  { OCC_MTU_LOAD,         -400 },

  { OCC_MTU_LOAD_REQUEST, -300 },
  { OCC_MTU_LOAD,         -300 },
  { OCC_MTU_LOAD_REQUEST, -300 },
  { OCC_MTU_LOAD,         -300 },
  { OCC_MTU_LOAD_REQUEST, -300 },
  { OCC_MTU_LOAD,         -300 },

  { OCC_MTU_LOAD_REQUEST, -200 },
  { OCC_MTU_LOAD,         -200 },
  { OCC_MTU_LOAD_REQUEST, -200 },
  { OCC_MTU_LOAD,         -200 },
  { OCC_MTU_LOAD_REQUEST, -200 },
  { OCC_MTU_LOAD,         -200 },

  { OCC_MTU_LOAD_REQUEST, -150 },
  { OCC_MTU_LOAD,         -150 },
  { OCC_MTU_LOAD_REQUEST, -150 },
  { OCC_MTU_LOAD,         -150 },
  { OCC_MTU_LOAD_REQUEST, -150 },
  { OCC_MTU_LOAD,         -150 },

  { OCC_MTU_LOAD_REQUEST, -100 },
  { OCC_MTU_LOAD,         -100 },
  { OCC_MTU_LOAD_REQUEST, -100 },
  { OCC_MTU_LOAD,         -100 },
  { OCC_MTU_LOAD_REQUEST, -100 },
  { OCC_MTU_LOAD,         -100 },

  { OCC_MTU_LOAD_REQUEST, -50 },
  { OCC_MTU_LOAD,         -50 },
  { OCC_MTU_LOAD_REQUEST, -50 },
  { OCC_MTU_LOAD,         -50 },
  { OCC_MTU_LOAD_REQUEST, -50 },
  { OCC_MTU_LOAD,         -50 },

  { OCC_MTU_LOAD_REQUEST, 0 },
  { OCC_MTU_LOAD,         0 },
  { OCC_MTU_LOAD_REQUEST, 0 },
  { OCC_MTU_LOAD,         0 },
  { OCC_MTU_LOAD_REQUEST, 0 },
  { OCC_MTU_LOAD,         0 },

  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },
  { OCC_MTU_REQUEST,      0 },

  { -1, 0 }
};

/*
 * Should we become a daemon?
 *  level == 0 after parameters have been parsed but before any initialization
 *  level == 1 after initialization but before any SSL/TLS negotiation or
 *    tunnel data is forwarded
 *  first_time is true until first exit of openvpn() function
 *
 * Return true if we did it.
 */
static bool
possibly_become_daemon (int level, const struct options* options, const bool first_time)
{
  bool ret = false;
  if (first_time && options->daemon)
    {
      ASSERT (!options->inetd);
      if (level == DAEMONIZATION_LEVEL)
	{
	  if (daemon (options->cd_dir != NULL, options->log) < 0)
	    msg (M_ERR, "daemon() failed");
	  ret = true;
	}
    }
  return ret;
}

/*
 * Initialize the route list, resolving any DNS names in route
 * options and saving routes in the environment.
 */
static void
do_init_route_list (const struct options *options,
		    struct route_list *route_list,
		    struct link_socket *link_socket,
		    bool fatal)
{
  const char *gw = NULL;
  int dev = dev_type_enum (options->dev, options->dev_type);

  if (dev == DEV_TYPE_TUN)
    gw = options->ifconfig_remote_netmask;
  if (options->route_default_gateway)
    gw = options->route_default_gateway;

  if (!init_route_list (route_list,
			&options->routes,
			gw,
			link_socket_current_remote (link_socket)))
    {
      if (fatal)
	openvpn_exit (OPENVPN_EXIT_STATUS_ERROR); /* exit point */
    }
  else
    {  
      /* copy routes to environment */
      setenv_routes (route_list);
    }
}

/*
 * Possibly add routes and/or call route-up script
 * based on options.
 */
static void
do_route (const struct options* options,
	  struct route_list *route_list)
{
  if (!options->route_noexec)
    add_routes (route_list, false);
  if (options->route_script)
    {
      setenv_str ("script_type", "route-up");
      system_check (options->route_script, "Route script failed", false);
    }
}

/*
 * Open tun/tap device, ifconfig, call up script, etc.
 */

static bool
do_open_tun (const struct options *options,
	     struct frame *frame,
	     struct link_socket *link_socket,
	     struct tuntap *tuntap,
	     struct route_list *route_list)
{
  bool ret = false;

  if (!tuntap_defined (tuntap))
    {
      /* parse and resolve the route option list */
      do_init_route_list (options, route_list, link_socket, true);

      /* do ifconfig */
      if (!options->ifconfig_noexec
	  && ifconfig_order() == IFCONFIG_BEFORE_TUN_OPEN)
	{
	  /* guess actual tun/tap unit number that will be returned
	     by open_tun */
	  const char *guess = guess_tuntap_dev (options->dev,
						options->dev_type,
						options->dev_node);
	  do_ifconfig (tuntap,
		       guess,
		       TUN_MTU_SIZE (frame));
	}

      /* open the tun device */
      open_tun (options->dev, options->dev_type, options->dev_node,
		options->tun_ipv6, tuntap);

      /* do ifconfig */  
      if (!options->ifconfig_noexec
	  && ifconfig_order() == IFCONFIG_AFTER_TUN_OPEN)
	do_ifconfig (tuntap,
		     tuntap->actual,
		     TUN_MTU_SIZE (frame));

      /* run the up script */
      run_script (options->up_script,
		  tuntap->actual,
		  TUN_MTU_SIZE (frame),
		  EXPANDED_SIZE (frame),
		  print_in_addr_t (tuntap->local, true),
		  print_in_addr_t (tuntap->remote_netmask, true),
		  "init",
		  NULL,
		  "up");

      /* possibly add routes */
      if (!options->route_delay_defined)
	do_route (options, route_list);

      /*
       * Did tun/tap driver give us an MTU?
       */
      if (tuntap->post_open_mtu)
	frame_set_mtu_dynamic (
			       frame,
			       tuntap->post_open_mtu,
			       SET_MTU_TUN | SET_MTU_UPPER_BOUND);

      /*
       * On Windows, it is usually wrong if --tun-mtu != 1500.
       */
#ifdef WIN32
      if (TUN_MTU_SIZE (frame) != 1500)
	msg (M_WARN, "WARNING: in general you should use '--tun-mtu 1500 --mssfix 1400' on both sides of the connection if at least one side is running Windows, unless you have explicitly modified the TAP-Win32 driver properties");
#endif
      ret = true;
    }
  else
    {
      msg (M_INFO, "Preserving previous TUN/TAP instance: %s", tuntap->actual);

      /* run the up script if user specified --up-restart */
      if (options->up_restart)
	run_script (options->up_script,
		    tuntap->actual,
		    TUN_MTU_SIZE (frame),
		    EXPANDED_SIZE (frame),
		    print_in_addr_t (tuntap->local, true),
		    print_in_addr_t (tuntap->remote_netmask, true),
		    "restart",
		    NULL,
		    "up");
    }
  return ret;
}

/*
 * Depending on protocol, sleep before restart to prevent
 * TCP race.
 */
static void
socket_restart_pause (int proto, bool http_proxy, bool socks_proxy)
{
  int sec = 0;
  switch (proto)
    {
    case PROTO_UDPv4:
      sec = socks_proxy ? 3 : 0;
      break;
    case PROTO_TCPv4_SERVER:
      sec = 1;
      break;
    case PROTO_TCPv4_CLIENT:
      sec = (http_proxy || socks_proxy) ? 10 : 3;
      break;
    }
  if (sec)
    {
      msg (D_RESTART, "Restart pause, %d second(s)", sec);
      sleep (sec);
    }
}

/* Handle signals */

static volatile int signal_received = 0;

static const char *
signal_description (int signum, const char *sigtext)
{
  if (sigtext)
    return sigtext;
  else
    {
      switch (signum) {
      case SIGUSR1:
	return "sigusr1";
      case SIGUSR2:
	return "sigusr2";
      case SIGHUP:
	return "sighup";
      case SIGTERM:
	return "sigterm";
      case SIGINT:
	return "sigint";
      default:
	return "unknown";
      }
    }
}

static void
print_signal (int signum)
{
  switch (signum)
    {
    case SIGINT:
      msg (M_INFO, "SIGINT received, exiting");
      break;
    case SIGTERM:
      msg (M_INFO, "SIGTERM received, exiting");
      break;
    case SIGHUP:
      msg (M_INFO, "SIGHUP received, restarting");
      break;
    case SIGUSR1:
      msg (M_INFO, "SIGUSR1 received, restarting");
      break;
    default:
      msg (M_INFO, "Unknown signal %d received", signal_received);
      break;
    }
}

#ifdef HAVE_SIGNAL_H

/* normal signal handler, when we are in event loop */
static void
signal_handler (int signum)
{
  signal_received = signum;
  signal (signum, signal_handler);
}

/* temporary signal handler, before we are fully initialized */
static void
signal_handler_exit (int signum)
{
  msg (M_FATAL | M_NOLOCK,
       "Signal %d (%s) received during initialization, exiting",
       signum,
       signal_description (signum, NULL));
}

#endif /* HAVE_SIGNAL_H */

/*
 * For debugging, dump a packet in
 * nominally human-readable form.
 */
#if defined(USE_CRYPTO) && defined(USE_SSL)
#define TLS_MODE (tls_multi != NULL)
#define PROTO_DUMP_FLAGS (check_debug_level (D_LINK_RW_VERBOSE) ? (PD_SHOW_DATA|PD_VERBOSE) : 0)
#define PROTO_DUMP(buf) protocol_dump(buf, \
				      PROTO_DUMP_FLAGS | \
				      (tls_multi ? PD_TLS : 0) | \
				      (options->tls_auth_file ? ks->key_type.hmac_length : 0) \
				      )
#else
#define TLS_MODE (false)
#define PROTO_DUMP(buf) format_hex (BPTR (buf), BLEN (buf), 80)
#endif

#ifdef USE_CRYPTO
#define MD5SUM(buf, len) md5sum(buf, len, 0)
#else
#define MD5SUM(buf, len) "[unavailable]"
#endif

#if defined(USE_PTHREAD) && defined(USE_CRYPTO)
static void *test_crypto_thread (void *arg);
#endif

/*
 * Our global key schedules, packaged thusly
 * to facilitate --persist-key.
 */

struct key_schedule
{
#ifdef USE_CRYPTO
  /* which cipher, HMAC digest, and key sizes are we using? */
  struct key_type   key_type;

  /* pre-shared static key, read from a file */
  struct key_ctx_bi static_key;

#ifdef USE_SSL
  /* our global SSL context */
  SSL_CTX           *ssl_ctx;

  /* optional authentication HMAC key for TLS control channel */
  struct key_ctx_bi tls_auth_key;

#endif /* USE_SSL */
#else /* USE_CRYPTO */
  int dummy;
#endif /* USE_CRYPTO */
};

static void
key_schedule_free(struct key_schedule* ks)
{
#ifdef USE_CRYPTO
  free_key_ctx_bi (&ks->static_key);
#ifdef USE_SSL
  if (ks->ssl_ctx)
    SSL_CTX_free (ks->ssl_ctx);
  free_key_ctx_bi (&ks->tls_auth_key);
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
  CLEAR (*ks);
}

/*
 * struct packet_id_persist should be empty if we are not
 * building with crypto.
 */
#ifndef PACKET_ID_H
struct packet_id_persist { int dummy; };
static inline void packet_id_persist_init (struct packet_id_persist *p) {}
#endif

/*
 * Finalize MTU parameters based on command line or config file options.
 */
static void
frame_finalize_options (struct frame *frame, const struct options *options)
{

  frame_finalize (frame,
		  options->link_mtu_defined,
		  options->link_mtu,
		  options->tun_mtu_defined,
		  options->tun_mtu);
}

/*
 * Do the work.  Initialize and enter main event loop.
 * Called after command line has been parsed.
 *
 * first_time is true during our first call -- we may
 * be called multiple times due to SIGHUP or SIGUSR1.
 */
static int
openvpn (const struct options *options,
	 struct link_socket_addr *link_socket_addr,
	 struct tuntap *tuntap,
	 struct key_schedule *ks,
	 struct packet_id_persist *pid_persist,
	 struct route_list *route_list,
	 struct http_proxy_info *http_proxy,
	 struct socks_proxy_info *socks_proxy,
	 bool first_time)
{
  /*
   * Initialize garbage collection level.
   * When we pop the level at the end
   * of the routine, everything we
   * allocated with gc_malloc at our level
   * or recursively lower levels will
   * automatically be freed.
   */
  const int gc_level = gc_new_level ();

  /* our global wait event */
  struct event_wait event_wait;

#if PASSTOS_CAPABILITY
  /* used to get/set TOS. */
  uint8_t ptos;
  bool ptos_defined = false;
#endif

  /* declare various buffers */
  struct buffer to_tun = clear_buf ();
  struct buffer to_link = clear_buf ();
  struct buffer buf = clear_buf ();
  struct buffer aux_buf = clear_buf ();
  struct buffer nullbuf = clear_buf ();

  /* tells us to free to_link buffer after it has been written to TCP/UDP port */
  bool free_to_link = false;

  struct link_socket link_socket;  /* socket used for TCP/UDP connection to remote */
  struct sockaddr_in to_link_addr; /* IP address of remote */

  /* MTU frame parameters */
  struct frame frame;

#ifdef FRAGMENT_ENABLE
  /* Object to handle advanced MTU negotiation and datagram fragmentation */
  struct fragment_master *fragment = NULL;
  struct frame frame_fragment;
  struct frame frame_fragment_omit;
#endif

  /* Always set to current time. */
  time_t current;

#ifdef HAVE_GETTIMEOFDAY
  /*
   * Traffic shaper object.
   */
  struct shaper shaper;
#endif

  /*
   * Statistics
   */
  counter_type tun_read_bytes = 0;
  counter_type tun_write_bytes = 0;
  counter_type link_read_bytes = 0;
  counter_type link_read_bytes_auth = 0;
  counter_type link_write_bytes = 0;

  /*
   * Timer objects for ping and inactivity
   * timeout features.
   */
  struct event_timeout wait_for_connect = event_timeout_clear_ret ();
  struct event_timeout inactivity_interval = event_timeout_clear_ret ();
  struct event_timeout ping_send_interval = event_timeout_clear_ret ();
  struct event_timeout ping_rec_interval = event_timeout_clear_ret ();

  /* the option strings must match across peers */
  char *options_string_local = NULL;
  char *options_string_remote = NULL;

  int occ_op = -1;               /* OCC request code received from remote */
  int occ_n_tries = 0;
  struct event_timeout occ_interval = event_timeout_clear_ret ();

  /*
   * Keep track of maximum packet size received so far
   * (of authenticated packets).
   */
  int original_recv_size = 0;    /* temporary */
  int max_recv_size_local = 0;   /* max packet size received */
  int max_recv_size_remote = 0;  /* max packet size received by remote */
  int max_send_size_local = 0;   /* max packet size sent */
  int max_send_size_remote = 0;  /* max packet size sent by remote */

  /* remote wants us to send back a load test packet of this size */
  int occ_mtu_load_size = 0;

  struct event_timeout occ_mtu_load_test_interval = event_timeout_clear_ret ();
  int occ_mtu_load_n_tries = 0;

#ifdef USE_CRYPTO

  /*
   * TLS-mode crypto objects.
   */
#ifdef USE_SSL

  /* master OpenVPN SSL/TLS object */
  struct tls_multi *tls_multi = NULL;

#ifdef USE_PTHREAD

  /* object containing TLS thread state */
  struct thread_parms thread_parms;

  /* object sent to us by TLS thread */
  struct tt_ret tt_ret;

  /* did we open TLS thread? */
  bool thread_opened = false;

#else

  /* used to optimize calls to tls_multi_process
     in single-threaded mode */
  struct interval tmp_int;

#endif
#endif

  /* workspace buffers used by crypto routines */
  struct buffer encrypt_buf = clear_buf ();
  struct buffer decrypt_buf = clear_buf ();

  /* passed to encrypt or decrypt, contains all
     crypto-related command line options related
     to data channel encryption/decryption */
  struct crypto_options crypto_options;

  /* used to keep track of data channel packet sequence numbers */
  struct packet_id packet_id;
#endif

  /*
   * LZO compression library objects.
   */
#ifdef USE_LZO
  struct buffer lzo_compress_buf = clear_buf ();
  struct buffer lzo_decompress_buf = clear_buf ();
  struct lzo_compress_workspace lzo_compwork;
#endif

  /*
   * Buffers used to read from TUN device
   * and TCP/UDP port.
   */
  struct buffer read_link_buf = clear_buf ();
  struct buffer read_tun_buf = clear_buf ();

  /*
   * IPv4 TUN device?
   */
  bool ipv4_tun = (!options->tun_ipv6 && is_dev_type (options->dev, options->dev_type, "tun"));

  /* workspace for get_pid_file/write_pid */
  struct pid_state pid_state;

  /* workspace for --user/--group */
  struct user_state user_state;
  struct group_state group_state;

  /* temporary variable */
  bool did_we_daemonize = false;

  /* description of signal */
  const char *signal_text = NULL;

#ifdef LOG_RW
  /* should we print R|W|r|w to console on packet transfers? */
  const bool log_rw = (check_debug_level (D_LOG_RW) && !check_debug_level (D_LOG_RW + 1));
#endif

  /* route stuff */
  struct event_timeout route_wakeup = event_timeout_clear_ret ();

  /* did we open tun/tap dev during this cycle? */
  bool did_open_tun = false;

  /* ------------- */

#ifdef HAVE_SIGNAL_H
  /*
   * Special handling if signal arrives before
   * we are properly initialized.
   */
  signal (SIGINT, signal_handler_exit);
  signal (SIGTERM, signal_handler_exit);
  signal (SIGHUP, signal_handler_exit);
  signal (SIGUSR1, signal_handler_exit);
  signal (SIGUSR2, signal_handler_exit);
  signal (SIGPIPE, SIG_IGN);
#endif /* HAVE_SIGNAL_H */

  if (!first_time)
    socket_restart_pause (options->proto, options->http_proxy_server != NULL,
			  options->socks_proxy_server != NULL);

  wait_init (&event_wait);
  link_socket_reset (&link_socket);

  CLEAR (frame);

#ifdef FRAGMENT_ENABLE
  CLEAR (frame_fragment_omit);
#endif

  /* should we disable paging? */
  if (first_time && options->mlock)
    do_mlockall (true);

  /*
   * Initialize advanced MTU negotiation and datagram fragmentation
   */
#ifdef FRAGMENT_ENABLE
  if (options->fragment)
    fragment = fragment_init (&frame);
#endif

#ifdef USE_CRYPTO
  /* init PRNG used for IV generation */
  prng_init ();

  /* load a persisted packet-id for cross-session replay-protection */
  if (options->packet_id_file)
    packet_id_persist_load (pid_persist, options->packet_id_file);

  /* Initialize crypto options */

  CLEAR (crypto_options);
  CLEAR (packet_id);
  crypto_options.use_iv = options->use_iv;

  if (options->shared_secret_file)
    {
      /*
       * Static Key Mode (using a pre-shared key)
       */

      /* Initialize packet ID tracking */
      if (options->replay)
	{
	  packet_id_init (&packet_id, options->replay_window, options->replay_time);
	  crypto_options.packet_id = &packet_id;
	  crypto_options.pid_persist = pid_persist;
	  crypto_options.packet_id_long_form = true;
	  packet_id_persist_load_obj (pid_persist, crypto_options.packet_id);
	}

      if (!key_ctx_bi_defined (&ks->static_key))
	{
	  struct key2 key2;
	  struct key_direction_state kds;

	  /* Get cipher & hash algorithms */
	  init_key_type (&ks->key_type, options->ciphername,
			 options->ciphername_defined, options->authname,
			 options->authname_defined, options->keysize,
			 options->test_crypto, true);

	  /* Read cipher and hmac keys from shared secret file */
	  read_key_file (&key2, options->shared_secret_file, true);

	  /* Check for and fix highly unlikely key problems */
	  verify_fix_key2 (&key2, &ks->key_type, options->shared_secret_file);

	  /* Initialize OpenSSL key objects */
	  key_direction_state_init (&kds, options->key_direction);
	  must_have_n_keys (options->shared_secret_file, "secret", &key2, kds.need_keys);
	  init_key_ctx (&ks->static_key.encrypt, &key2.keys[kds.out_key], &ks->key_type, DO_ENCRYPT, "Static Encrypt");
	  init_key_ctx (&ks->static_key.decrypt, &key2.keys[kds.in_key], &ks->key_type, DO_DECRYPT, "Static Decrypt");

	  /* Erase the temporary copy of key */
	  CLEAR (key2);
	}
      else
	{
	  msg (M_INFO, "Re-using pre-shared static key");
	}

      /* Get key schedule */
      crypto_options.key_ctx_bi = &ks->static_key;

      /* Compute MTU parameters */
      crypto_adjust_frame_parameters(&frame,
				     &ks->key_type,
				     options->ciphername_defined,
				     options->use_iv,
				     options->replay,
				     true);

      /* Sanity check on IV, sequence number, and cipher mode options */
      check_replay_iv_consistency(&ks->key_type, options->replay, options->use_iv);

      /*
       * Test-crypto is a debugging tool
       * that basically does a loopback test
       * on the crypto subsystem.
       */
      if (options->test_crypto)
	{
#ifdef USE_PTHREAD
	  if (first_time)
	    {
	      thread_init();
	      work_thread_create(test_crypto_thread, (void*) options);
	    }
#endif
	  frame_finalize_options (&frame, options);

	  test_crypto (&crypto_options, &frame);
	  key_schedule_free (ks);
	  signal_received = 0;
#ifdef USE_PTHREAD
	  if (first_time)
	    work_thread_join ();
#endif
	  goto done;
	}
    }
#ifdef USE_SSL
  else if (options->tls_server || options->tls_client)
    {
      /*
       * TLS-based dynamic key exchange mode
       */
      struct tls_options to;
      bool packet_id_long_form;

      ASSERT (!options->test_crypto);

      /* Make sure we are either a TLS client or server but not both */
      ASSERT (options->tls_server == !options->tls_client);

      /* Let user specify a script to verify the incoming certificate */
      tls_set_verify_command (options->tls_verify);
      
      /* Verify the X509 name of the incoming host */
      tls_set_verify_x509name (options->tls_remote);

      /* Let user specify a certificate revocation list to
	 check the incoming certificate */
      tls_set_crl_verify (options->crl_file);

      if (!ks->ssl_ctx)
	{
	  /*
	   * Initialize the OpenSSL library's global
	   * SSL context.
	   */
	  ks->ssl_ctx = init_ssl (options->tls_server,
				  options->ca_file,
				  options->dh_file,
				  options->cert_file,
				  options->priv_key_file,
				  options->cipher_list);

	  /* Get cipher & hash algorithms */
	  init_key_type (&ks->key_type, options->ciphername,
			 options->ciphername_defined, options->authname,
			 options->authname_defined, options->keysize,
			 true, true);

	  /* TLS handshake authentication (--tls-auth) */
	  if (options->tls_auth_file)
	    get_tls_handshake_key (&ks->key_type,
				   &ks->tls_auth_key,
				   options->tls_auth_file,
				   options->key_direction);
	}
      else
	{
	  msg (M_INFO, "Re-using SSL/TLS context");
	}

      /* Sanity check on IV, sequence number, and cipher mode options */
      check_replay_iv_consistency(&ks->key_type, options->replay, options->use_iv);

      /* In short form, unique datagram identifier is 32 bits, in long form 64 bits */
      packet_id_long_form = cfb_ofb_mode (&ks->key_type);

      /* Compute MTU parameters */
      crypto_adjust_frame_parameters(&frame,
				     &ks->key_type,
				     options->ciphername_defined,
				     options->use_iv,
				     options->replay,
				     packet_id_long_form);
      tls_adjust_frame_parameters(&frame);

      /* Set all command-line TLS-related options */
      CLEAR (to);
      to.ssl_ctx = ks->ssl_ctx;
      to.key_type = ks->key_type;
      to.server = options->tls_server;
      to.key_method = options->key_method;
      to.replay = options->replay;
      to.packet_id_long_form = packet_id_long_form;
      to.replay_window = options->replay_window;
      to.replay_time = options->replay_time;
      to.transition_window = options->transition_window;
      to.handshake_window = options->handshake_window;
      to.packet_timeout = options->tls_timeout;
      to.renegotiate_bytes = options->renegotiate_bytes;
      to.renegotiate_packets = options->renegotiate_packets;
      to.renegotiate_seconds = options->renegotiate_seconds;
      to.single_session = options->single_session;
      to.disable_occ = !options->occ;

      /* TLS handshake authentication (--tls-auth) */
      if (options->tls_auth_file)
	{
	  to.tls_auth_key = ks->tls_auth_key;
	  to.tls_auth.pid_persist = pid_persist;
	  to.tls_auth.packet_id_long_form = true;
	  crypto_adjust_frame_parameters(&to.frame,
					 &ks->key_type,
					 false,
					 false,
					 true,
					 true);
	}

      /* If we are running over TCP, allow for
	 length prefix */
      socket_adjust_frame_parameters (&to.frame, options->proto);

      /*
       * Initialize OpenVPN's master TLS-mode object.
       */
      tls_multi = tls_multi_init (&to);
    }
#endif
  else
    {
      /*
       * No encryption or authentication.
       */
      ASSERT (!options->test_crypto);
      free_key_ctx_bi (&ks->static_key);
      crypto_options.key_ctx_bi = &ks->static_key;
      msg (M_WARN,
	   "******* WARNING *******: all encryption and authentication features disabled -- all data will be tunnelled as cleartext");
    }

#else /* USE_CRYPTO */

  msg (M_WARN,
       "******* WARNING *******: " PACKAGE_NAME " built without OpenSSL -- encryption and authentication features disabled -- all data will be tunnelled as cleartext");

#endif /* USE_CRYPTO */

#ifdef USE_LZO
  /*
   * Initialize LZO compression library.
   */
  if (options->comp_lzo)
    {
      lzo_compress_init (&lzo_compwork, options->comp_lzo_adaptive);
      lzo_adjust_frame_parameters (&frame);
#ifdef FRAGMENT_ENABLE
      lzo_adjust_frame_parameters (&frame_fragment_omit); /* omit LZO frame delta from final frame_fragment */
#endif
    }
#endif

  /*
   * Adjust frame size for UDP Socks support.
   */
  if (options->socks_proxy_server)
    socks_adjust_frame_parameters (&frame, options->proto);

  /*
   * Adjust frame size based on the --tun-mtu-extra parameter.
   */
  if (options->tun_mtu_extra_defined)
    tun_adjust_frame_parameters (&frame, options->tun_mtu_extra);

  /*
   * Adjust frame size based on link socket parameters.
   * (Since TCP is a stream protocol, we need to insert
   * a packet length uint16_t in the buffer.)
   */
  socket_adjust_frame_parameters (&frame, options->proto);

  /*
   * Fill in the blanks in the frame parameters structure,
   * make sure values are rational, etc.
   */
  frame_finalize_options (&frame, options);

  /*
   * Set frame parameter for fragment code.  This is necessary because
   * the fragmentation code deals with payloads which have already been
   * passed through the compression code.
   */
#ifdef FRAGMENT_ENABLE
  frame_fragment = frame;
  frame_subtract_extra (&frame_fragment, &frame_fragment_omit);
#endif

#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (tls_multi)
    {
      tls_multi_init_finalize (tls_multi, &frame);
      ASSERT (EXPANDED_SIZE (&tls_multi->opt.frame) <= EXPANDED_SIZE (&frame));
      frame_print (&tls_multi->opt.frame, D_MTU_INFO, "Control Channel MTU parms");
    }
#endif

  /*
   * Now that we know all frame parameters, initialize
   * our buffers.
   */

  read_link_buf = alloc_buf (BUF_SIZE (&frame));
  read_tun_buf = alloc_buf (BUF_SIZE (&frame));
  aux_buf = alloc_buf (BUF_SIZE (&frame));

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

#ifdef FRAGMENT_ENABLE
  /* fragmenting code has buffers to initialize
     once frame parameters are known */
  if (fragment)
    {
      ASSERT (options->fragment);
      frame_set_mtu_dynamic (
			     &frame_fragment,
			     options->fragment,
			     SET_MTU_UPPER_BOUND
			     );
      fragment_frame_init (fragment, &frame_fragment);
    }
#endif

  /*
   * Set the dynamic MTU parameter, used by the --mssfix
   * option.  If --mssfix is supplied without a parameter,
   * then default to --fragment size.  Otherwise default
   * to udp_mtu or (on Windows) TAP-Win32 mtu size which
   * is set in the adapter advanced properties dialog.
   */
  if (options->mssfix_defined)
    {
      if (options->mssfix)
	{
	  frame_set_mtu_dynamic (
	      &frame,
	      options->mssfix,
	      SET_MTU_UPPER_BOUND
	  );
	}
#ifdef FRAGMENT_ENABLE
      else if (fragment)
	{
	  frame_set_mtu_dynamic (
	      &frame,
	      EXPANDED_SIZE_DYNAMIC (&frame_fragment),
	      SET_MTU_UPPER_BOUND
	  );
	}
#endif
    }

#ifdef FRAGMENT_ENABLE

  if (options->fragment && options->mtu_test)
    msg (M_WARN, "WARNING: using --fragment and --mtu-test together may produce an inaccurate MTU test result");

  if ((options->mssfix || options->fragment) && TUN_MTU_SIZE (&frame_fragment) != ETHERNET_MTU)
     msg (M_WARN, "WARNING: normally if you use --mssfix and/or --fragment, you should also set --tun-mtu %d (currently it is %d)",
	  ETHERNET_MTU,
	  TUN_MTU_SIZE (&frame_fragment));

#endif

  /* bind the TCP/UDP socket */

  link_socket_init_phase1 (&link_socket,
			   options->local, options->remote,
			   options->local_port, options->remote_port,
			   options->proto,
			   http_proxy->defined ? http_proxy : NULL,
			   socks_proxy->defined ? socks_proxy : NULL,
			   options->bind_local,
			   options->remote_float,
			   options->inetd,
			   link_socket_addr,
			   options->ipchange,
			   options->resolve_retry_seconds,
			   options->connect_retry_seconds,
			   options->mtu_discover_type);

  /* initialize tun/tap device object */

  init_tun (tuntap,
	    options->dev,
	    options->dev_type,
	    options->ifconfig_local,
	    options->ifconfig_remote_netmask,
	    addr_host (&link_socket.lsa->local),
	    addr_host (&link_socket.lsa->remote),
	    &frame,
	    &options->tuntap_options);

  /* open tun/tap device, ifconfig, run up script, etc. */
  
  if (!options->up_delay)
    did_open_tun = do_open_tun (options, &frame, &link_socket, tuntap, route_list);

  /*
   * Print MTU INFO
   */
  frame_print (&frame, D_MTU_INFO, "Data Channel MTU parms");
#ifdef FRAGMENT_ENABLE
  if (fragment)
    frame_print (&frame_fragment, D_MTU_INFO, "Fragmentation MTU parms");
#endif

  /*
   * Get local and remote options compatibility strings.
   */
  options_string_local = options_string (options, &frame, tuntap, false);
  options_string_remote = options_string (options, &frame, tuntap, true);

  msg (D_SHOW_OCC, "Local Options String: '%s'", options_string_local);
  msg (D_SHOW_OCC, "Expected Remote Options String: '%s'", options_string_remote);

#ifdef USE_CRYPTO
  msg (D_SHOW_OCC_HASH, "Local Options hash (VER=%s): '%s'",
       options_string_version (options_string_local),
       md5sum (options_string_local, strlen(options_string_local), 9));
  msg (D_SHOW_OCC_HASH, "Expected Remote Options hash (VER=%s): '%s'",
       options_string_version (options_string_remote),
       md5sum (options_string_remote, strlen (options_string_remote), 9));
#endif

#if defined(USE_CRYPTO) && defined(USE_SSL)
  if (tls_multi)
    tls_multi_init_set_options(tls_multi,
			       options_string_local,
			       options_string_remote);
#endif

#ifdef HAVE_GETTIMEOFDAY
  /* initialize traffic shaper (i.e. transmit bandwidth limiter) */
  if (options->shaper)
    {
      shaper_init (&shaper, options->shaper);
      shaper_msg (&shaper);
    }
#endif

  if (first_time)
    {
      /* get user and/or group that we want to setuid/setgid to */
      get_group (options->groupname, &group_state);
      get_user (options->username, &user_state);

      /* get --writepid file descriptor */
      get_pid_file (options->writepid, &pid_state);

      /* chroot if requested */
      if (options->chroot_dir)
        {
#if 0
	  /* not needed because gethostbyname is now called in
	     link_socket_init_phase1 even if --resolv-retry is also specified. */

          /* do a dummy DNS lookup before entering the chroot jail
             to load the resolver libraries */
          if (options->remote)
            (void) gethostbyname (options->remote);
#endif    
          do_chroot (options->chroot_dir);
        }
    }

  /* become a daemon if --daemon */
  did_we_daemonize = possibly_become_daemon (1, options, first_time);

#ifdef HAVE_SIGNAL_H
  /* catch signals */
  signal (SIGINT, signal_handler);
  signal (SIGTERM, signal_handler);
  signal (SIGHUP, signal_handler);
  signal (SIGUSR1, signal_handler);
  signal (SIGUSR2, signal_handler);
#endif /* HAVE_SIGNAL_H */

  if (first_time)
    {
      /* should we disable paging? */
      if (options->mlock && did_we_daemonize)
	do_mlockall (true); /* call again in case we daemonized */

      /* should we change scheduling priority? */
      set_nice (options->nice);

      /* set user and/or group that we want to setuid/setgid to */
      set_group (&group_state);
      set_user (&user_state);

      /* save process ID in a file */
      write_pid (&pid_state);

      /* initialize threading if pthread configure option enabled */
      thread_init();
    }

  /* finalize the TCP/UDP socket */
  link_socket_init_phase2 (&link_socket, &frame, &signal_received);
  if (signal_received)
    {
      signal_text = "socket";
      print_signal (signal_received);
      goto cleanup;
    }
  
  /* start the TLS thread */
#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
  if (tls_multi)
    {
      tls_thread_create (&thread_parms, tls_multi, &link_socket,
			 options->nice_work, options->mlock);
      thread_opened = true;
    }
#endif

  /*
   * MAIN EVENT LOOP
   *
   * Pipe TCP/UDP -> tun and tun -> TCP/UDP using nonblocked i/o.
   *
   * If tls_multi is defined, multiplex a TLS
   * control channel over the TCP/UDP connection which
   * will be used for secure key exchange with our peer.
   *
   */

  /* select wants maximum fd + 1 (why doesn't it just figure it out for itself?) */
  SOCKET_SETMAXFD(link_socket);
  TUNTAP_SETMAXFD(tuntap);

  current = time (NULL);

  /* initialize connection establishment timer */
  event_timeout_init (&wait_for_connect, current, 5);

  /* initialize inactivity timeout */
  if (options->inactivity_timeout)
    event_timeout_init (&inactivity_interval, current, options->inactivity_timeout);

  /* initialize pings */

  if (options->ping_send_timeout)
    event_timeout_init (&ping_send_interval, 0, options->ping_send_timeout);

  if (options->ping_rec_timeout)
    event_timeout_init (&ping_rec_interval, current, options->ping_rec_timeout);

  /* initialize occ timers */

  if (options->occ
      && !TLS_MODE
      && options_string_local
      && options_string_remote)
    event_timeout_init (&occ_interval, current, OCC_INTERVAL_SECONDS);

  if (options->mtu_test)
    event_timeout_init (&occ_mtu_load_test_interval, current, OCC_MTU_LOAD_INTERVAL_SECONDS);

#if defined(USE_CRYPTO) && defined(USE_SSL)
#ifdef USE_PTHREAD
  TLS_THREAD_SOCKET_SETMAXFD (thread_parms);
#else
  /* initialize tmp_int optimization that limits the number of times we call
     tls_multi_process in the main event loop */
  interval_init (&tmp_int, TLS_MULTI_HORIZON, TLS_MULTI_REFRESH);
#endif
#endif

  /* this flag is true for buffers coming from the TLS background thread */
  free_to_link = false;

  while (true)
    {
      int stat = 0;
      struct timeval *tv = NULL;
      struct timeval timeval;

      signal_text = NULL;

      /* initialize select() timeout */
      timeval.tv_sec = BIG_TIMEOUT;
      timeval.tv_usec = 0;
      tv = &timeval;

#if defined(WIN32) && defined(TAP_WIN32_DEBUG)
      timeval.tv_sec = 1;
      if (check_debug_level (D_TAP_WIN32_DEBUG))
	tun_show_debug (tuntap);
#endif

#ifdef USE_CRYPTO
      /* flush current packet-id to file once per 60
	 seconds if --replay-persist was specified */
      packet_id_persist_flush (pid_persist, current, 60);
#endif

#if defined(USE_CRYPTO) && defined(USE_SSL) && !defined(USE_PTHREAD)
      /*
       * In TLS mode, let TLS level respond to any control-channel
       * packets which were received, or prepare any packets for
       * transmission.
       *
       * tmp_int is purely an optimization that allows us to call
       * tls_multi_process less frequently when there's not much
       * traffic on the control-channel.
       *
       */
      if (tls_multi)
	{
	  interval_t wakeup = BIG_TIMEOUT;

	  if (interval_test (&tmp_int, current))
	    {
	      if (tls_multi_process (tls_multi, &to_link, &to_link_addr,
				     &link_socket, &wakeup, current))
		interval_action (&tmp_int, current);

	      interval_future_trigger (&tmp_int, wakeup, current);
	      free_to_link = false;
	    }

	  interval_schedule_wakeup (&tmp_int, current, &wakeup);

	  if (wakeup)
	    {
	      timeval.tv_sec = wakeup;
	      timeval.tv_usec = 0;
	    }
	}
#endif

      current = time (NULL);

#if defined(USE_CRYPTO) && defined(USE_SSL)
      if (tls_multi && link_socket_connection_oriented (&link_socket) && tls_multi->n_errors)
	{
	  /* TLS errors are fatal in TCP mode */
	  signal_received = SIGUSR1;
	  msg (D_STREAM_ERRORS, "Fatal decryption error, restarting");
	  signal_text = "tls-error";
	  break;
	}
#endif

      /*
       * Things that need to happen immediately after connection initiation should go here.
       */
      if (event_timeout_defined (&wait_for_connect))
	{
	  if (event_timeout_trigger (&wait_for_connect, current, &timeval))
	    {
	      if (CONNECTION_ESTABLISHED (&link_socket))
		{
		  /* if --up-delay specified, open tun, do ifconfig, and run up script now */
		  if (options->up_delay)
		    {
		      did_open_tun = do_open_tun (options, &frame, &link_socket, tuntap, route_list);
		      TUNTAP_SETMAXFD(tuntap);
		      current = time (NULL);
		    }

		  if (did_open_tun)
		    {
		      /* if --route-delay was specified, start timer */
		      if (options->route_delay_defined)
			event_timeout_init (&route_wakeup, current, options->route_delay);
		    }

		  event_timeout_clear (&wait_for_connect);
		}
	    }
	}

      /*
       * Should we add routes?
       */
      if (event_timeout_trigger (&route_wakeup, current, &timeval))
	{
	  do_route (options, route_list);
	  current = time (NULL);
	  event_timeout_clear (&route_wakeup);
	}

      /*
       * Should we exit due to inactivity timeout?
       */
      if (options->inactivity_timeout)
	{
	  if (event_timeout_trigger (&inactivity_interval, current, &timeval)) 
	    {
	      msg (M_INFO, "Inactivity timeout (--inactive), exiting");
	      signal_received = 0;
	      signal_text = "inactive";
	      break;
	    }
	}

      /*
       * Should we exit or restart due to ping (or other authenticated packet)
       * not received in n seconds?
       */
      if (options->ping_rec_timeout &&
	  (!options->ping_timer_remote || addr_defined (&link_socket_addr->actual)))
	{
	  if (event_timeout_trigger (&ping_rec_interval, current, &timeval)) 
	    {
	      switch (options->ping_rec_timeout_action)
		{
		case PING_EXIT:
		  msg (M_INFO, "Inactivity timeout (--ping-exit), exiting");
		  signal_received = 0;
		  signal_text = "ping-exit";
		  break;
		case PING_RESTART:
		  msg (M_INFO, "Inactivity timeout (--ping-restart), restarting");
		  signal_received = SIGUSR1;
		  signal_text = "ping-restart";
		  break;
		default:
		  ASSERT (0);
		}
	      break;
	    }
	}

      /*
       * Should we send an OCC_REQUEST message?
       */
      if (event_timeout_defined (&occ_interval)
	  && !to_link.len
	  && occ_op < 0)
	{
	  if (event_timeout_trigger (&occ_interval, current, &timeval))
	    {
	      if (++occ_n_tries >= OCC_N_TRIES)
		{
		  if (options->remote)
		    /*
		     * No OCC_REPLY from peer after repeated attempts.
		     * Give up.
		     */
		    msg (D_SHOW_OCC, "NOTE: failed to obtain options consistency info from peer -- this could occur if the remote peer is running a version of " PACKAGE_NAME " before 1.5-beta8 or if there is a network connectivity problem, and will not necessarily prevent " PACKAGE_NAME " from running (%u bytes received from peer, %u bytes authenticated data channel traffic) -- you can disable the options consistency check with --disable-occ.", (unsigned int) link_read_bytes, (unsigned int) link_read_bytes_auth);
		  event_timeout_clear (&occ_interval);
		}
	      else
		{
		  occ_op = OCC_REQUEST;

		  /*
		   * If we don't hear back from peer, send another
		   * OCC_REQUEST in OCC_INTERVAL_SECONDS.
		   */
		  event_timeout_reset (&occ_interval, current);
		}
	    }
	}

      /*
       * Should we send an MTU load test?
       */
      if (event_timeout_defined (&occ_mtu_load_test_interval)
	  && !to_link.len
	  && occ_op < 0)
	{
	  if (event_timeout_trigger (&occ_mtu_load_test_interval, current, &timeval))
	    {
	      if (CONNECTION_ESTABLISHED (&link_socket))
		{
		  const struct mtu_load_test *entry;

		  if (!occ_mtu_load_n_tries)
		    msg (M_INFO, "NOTE: Beginning empirical MTU test -- results should be available in 3 to 4 minutes.");

		  entry = &mtu_load_test_sequence[occ_mtu_load_n_tries++];
		  if (entry->op >= 0)
		    {
		      occ_op = entry->op;
		      occ_mtu_load_size = EXPANDED_SIZE (&frame) + entry->delta;
		    }
		  else
		    {
		      msg (M_INFO,  "NOTE: failed to empirically measure MTU (requires 1.5-beta8 or higher at other end of connection).");
		      event_timeout_clear (&occ_mtu_load_test_interval);
		      occ_mtu_load_n_tries = 0;
		    }
		}
	    }
	}

      /*
       * Should we send an OCC message?
       */
      if (occ_op >= 0 && !to_link.len
#ifdef FRAGMENT_ENABLE
	  && (!fragment || !fragment_outgoing_defined (fragment))
#endif
	  )
	{
	  bool doit = false;

	  buf = aux_buf;
	  ASSERT (buf_init (&buf, FRAME_HEADROOM (&frame)));
	  ASSERT (buf_safe (&buf, MAX_RW_SIZE_TUN (&frame)));
	  ASSERT (buf_write (&buf, occ_magic, sizeof (occ_magic)));

	  switch (occ_op)
	    {
	    case OCC_REQUEST:
	      if (!buf_write_u8 (&buf, OCC_REQUEST))
		break;
	      msg (D_PACKET_CONTENT, "SENT OCC_REQUEST");
	      doit = true;
	      break;

	    case OCC_REPLY:
	      if (!options_string_local)
		break;
	      if (!buf_write_u8 (&buf, OCC_REPLY))
		break;
	      if (!buf_write (&buf, options_string_local,
			      strlen (options_string_local) + 1))
		break;
	      msg (D_PACKET_CONTENT, "SENT OCC_REPLY");
	      doit = true;
	      break;

	    case OCC_MTU_REQUEST:
	      if (!buf_write_u8 (&buf, OCC_MTU_REQUEST))
		break;
	      msg (D_PACKET_CONTENT, "SENT OCC_MTU_REQUEST");
	      doit = true;
	      break;

	    case OCC_MTU_REPLY:
	      if (!buf_write_u8 (&buf, OCC_MTU_REPLY))
		break;
	      if (!buf_write_u16 (&buf, max_recv_size_local))
		break;
	      if (!buf_write_u16 (&buf, max_send_size_local))
		break;
	      msg (D_PACKET_CONTENT, "SENT OCC_MTU_REPLY");
	      doit = true;
	      break;

	    case OCC_MTU_LOAD_REQUEST:
	      if (!buf_write_u8 (&buf, OCC_MTU_LOAD_REQUEST))
		break;
	      if (!buf_write_u16 (&buf, occ_mtu_load_size))
		break;
	      msg (D_PACKET_CONTENT, "SENT OCC_MTU_LOAD_REQUEST");
	      doit = true;
	      break;

	    case OCC_MTU_LOAD:
	      {
		int need_to_add;

		if (!buf_write_u8 (&buf, OCC_MTU_LOAD))
		  break;
		need_to_add = min_int (
				       occ_mtu_load_size
				       - sizeof (occ_magic)
				       - sizeof (uint8_t)
				       - EXTRA_FRAME (&frame),
				       EXPANDED_SIZE (&frame)); 
		while (need_to_add > 0)
		  {
		    /*
		     * Fill the load test packet with pseudo-random bytes.
		     */
		    if (!buf_write_u8 (&buf, get_random() & 0xFF))
		      break;
		    --need_to_add;
		  }
		msg (D_PACKET_CONTENT, "SENT OCC_MTU_LOAD %d", occ_mtu_load_size);
		doit = true;
	      }
	      break;
	    }

	  if (doit)
	    {
	      /*
	       * We will treat the packet like any other outgoing packet,
	       * compress, encrypt, sign, etc.
	       */
#             include "encrypt_sign.h"
	    }

	  occ_op = -1;
	}

#ifdef FRAGMENT_ENABLE
      /*
       * Should we deliver a datagram fragment to remote?
       */
      if (fragment)
	{
	  /* OS MTU Hint? */
	  if (link_socket.mtu_changed && ipv4_tun)
	    {
	      frame_adjust_path_mtu (&frame_fragment, link_socket.mtu, options->proto);
	      link_socket.mtu_changed = false;
	    }
	  if (!to_link.len
	      && fragment_outgoing_defined (fragment)
	      && fragment_ready_to_send (fragment, &buf, &frame_fragment))
	    {
#             define NO_COMP_FRAG
#             include "encrypt_sign.h"
	    }
	  fragment_housekeeping (fragment, &frame_fragment, current, &timeval);
	  tv = &timeval;
	}
#endif /* FRAGMENT_ENABLE */

      /*
       * Should we ping the remote?
       */
      if (options->ping_send_timeout)
	{
	  if (!to_link.len)
	    {
	      if (event_timeout_trigger (&ping_send_interval, current, &timeval))
		{
		  buf = aux_buf;
		  ASSERT (buf_init (&buf, FRAME_HEADROOM (&frame)));
		  ASSERT (buf_safe (&buf, MAX_RW_SIZE_TUN (&frame)));
		  ASSERT (buf_write (&buf, ping_string, sizeof (ping_string)));

		  /*
		   * We will treat the ping like any other outgoing packet,
		   * encrypt, sign, etc.
		   */
#                 include "encrypt_sign.h"
		  msg (D_PACKET_CONTENT, "SENT PING");
		}
	    }
	}

      /* do a quick garbage collect */
      gc_collect (gc_level);

      /*
       * Set up for select call.
       *
       * Decide what kind of events we want to wait for.
       */
      wait_reset (&event_wait);

      /*
       * On win32 we use the keyboard or an event object as a source
       * of asynchronous signals.
       */
      WAIT_SIGNAL (&event_wait);

      /*
       * If outgoing data (for TCP/UDP port) pending, wait for ready-to-send
       * status from TCP/UDP port. Otherwise, wait for incoming data on
       * TUN/TAP device.
       */
      if (to_link.len > 0)
	{
	  /*
	   * If sending this packet would put us over our traffic shaping
	   * quota, don't send -- instead compute the delay we must wait
	   * until it will be OK to send the packet.
	   */

#ifdef HAVE_GETTIMEOFDAY
	  int delay = 0;

	  /* set traffic shaping delay in microseconds */
	  if (options->shaper)
	    delay = max_int (delay, shaper_delay (&shaper));

	  if (delay < 1000)
	    {
	      SOCKET_SET_WRITE (link_socket);
	    }
	  else
	    {
	      shaper_soonest_event (&timeval, delay);
	      tv = &timeval;
	    }
#else /* HAVE_GETTIMEOFDAY */
	  SOCKET_SET_WRITE (link_socket);
#endif /* HAVE_GETTIMEOFDAY */
	}
#ifdef FRAGMENT_ENABLE
      else if (!fragment || !fragment_outgoing_defined (fragment))
#else
      else
#endif
	{
	  TUNTAP_SET_READ (tuntap);
#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
	  TLS_THREAD_SOCKET_SET (thread_parms, reads);
#endif
	}

      /*
       * If outgoing data (for TUN/TAP device) pending, wait for ready-to-send status
       * from device.  Otherwise, wait for incoming data on TCP/UDP port.
       */
      if (to_tun.len > 0)
	{
	  TUNTAP_SET_WRITE (tuntap);
	}
      else
	{
	  SOCKET_SET_READ (link_socket);
	}

      /*
       * Possible scenarios:
       *  (1) tcp/udp port has data available to read
       *  (2) tcp/udp port is ready to accept more data to write
       *  (3) tun dev has data available to read
       *  (4) tun dev is ready to accept more data to write
       *  (5) tls background thread has data available to forward to
       *      tcp/udp port
       *  (6) we received a signal (handler sets signal_received)
       *  (7) timeout (tv) expired (from TLS, shaper, inactivity
       *      timeout, or ping timeout)
       */

      /*
       * Wait for something to happen.
       */
      stat = 1; /* this will be our return "status" if select doesn't get called */
      if (!signal_received && !SOCKET_READ_RESIDUAL (link_socket)) {
	msg (D_SELECT, "SELECT %s|%s|%s|%s %d/%d",
	     TUNTAP_READ_STAT (tuntap), 
	     TUNTAP_WRITE_STAT (tuntap), 
	     SOCKET_READ_STAT (link_socket),
	     SOCKET_WRITE_STAT (link_socket),
	     tv ? (int)tv->tv_sec : -1,
	     tv ? (int)tv->tv_usec : -1
	     );

	stat = SELECT ();
	check_status (stat, "select", NULL, NULL);
      }

      /* current should always be a reasonably up-to-date timestamp */
      current = time (NULL);

      /* set signal_received if a signal was received */
      SELECT_SIGNAL_RECEIVED ();

      /*
       * Did we get a signal before or while we were waiting
       * in select() ?
       */
      if (signal_received)
	{
	  if (signal_received == SIGUSR2)
	    {
	      msg (M_INFO, "Current " PACKAGE_NAME " Statistics:");
	      msg (M_INFO, " TUN/TAP read bytes:   " counter_format, tun_read_bytes);
	      msg (M_INFO, " TUN/TAP write bytes:  " counter_format, tun_write_bytes);
	      msg (M_INFO, " TCP/UDP read bytes:   " counter_format, link_read_bytes);
	      msg (M_INFO, " TCP/UDP write bytes:  " counter_format, link_write_bytes);
	      msg (M_INFO, " Auth read bytes:      " counter_format, link_read_bytes_auth);
#ifdef USE_LZO
	      if (options->comp_lzo)
		  lzo_print_stats (&lzo_compwork);		  
#endif
#ifdef WIN32
	      msg (M_INFO, " TAP-WIN32 driver status: %s", tap_win32_getinfo (tuntap));
#endif
	      signal_received = 0;
	      continue;
	    }

	  print_signal (signal_received);

	  /* for all other signals (INT, TERM, HUP, USR1) we break */
	  break;
	}

      if (!stat) /* timeout? */
	continue;

      if (stat > 0)
	{
	  /* Incoming data on TCP/UDP port */
	  if (SOCKET_READ_RESIDUAL (link_socket) || SOCKET_ISSET (link_socket, reads))
	    {
	      /*
	       * Set up for recvfrom call to read datagram
	       * sent to our TCP/UDP port.
	       */
	      struct sockaddr_in from;
	      int status;

	      ASSERT (!to_tun.len);
	      buf = read_link_buf;
	      ASSERT (buf_init (&buf, FRAME_HEADROOM (&frame)));

	      status = link_socket_read (&link_socket, &buf, MAX_RW_SIZE_LINK (&frame), &from);

	      if (socket_connection_reset (&link_socket, status))
		{
		  /* received a disconnect from a connection-oriented protocol */
		  if (options->inetd)
		    {
		      signal_received = SIGTERM;
		      msg (D_STREAM_ERRORS, "Connection reset, inetd/xinetd exit [%d]", status);
		    }
		  else
		    {
		      signal_received = SIGUSR1;
		      msg (D_STREAM_ERRORS, "Connection reset, restarting [%d]", status);
		    }
		  signal_text = "connection-reset";
		  break;		  
		}

	      if (buf.len > 0)
		{
		  link_read_bytes += buf.len;
		  original_recv_size = buf.len;
		}
	      else
		original_recv_size = 0;

	      /* check recvfrom status */
	      check_status (status, "read", &link_socket, NULL);

	      /* take action to corrupt packet if we are in gremlin test mode */
	      if (options->gremlin) {
		if (!ask_gremlin())
		  buf.len = 0;
		corrupt_gremlin(&buf);
	      }

	      /* log incoming packet */
#ifdef LOG_RW
	      if (log_rw)
		fprintf (stderr, "R");
#endif
	      msg (D_LINK_RW, "%s READ [%d] from %s: %s",
		   proto2ascii (link_socket.proto, true),
		   BLEN (&buf),
		   print_sockaddr (&from),
		   PROTO_DUMP (&buf));

	      /*
	       * Good, non-zero length packet received.
	       * Commence multi-stage processing of packet,
	       * such as authenticate, decrypt, decompress.
	       * If any stage fails, it sets buf.len to 0 or -1,
	       * telling downstream stages to ignore the packet.
	       */
	      if (buf.len > 0)
		{
		  link_socket_incoming_addr (&buf, &link_socket, &from);
#ifdef USE_CRYPTO
#ifdef USE_SSL
		  mutex_lock (L_TLS);
		  if (tls_multi)
		    {
		      /*
		       * If tls_pre_decrypt returns true, it means the incoming
		       * packet was a good TLS control channel packet.  If so, TLS code
		       * will deal with the packet and set buf.len to 0 so downstream
		       * stages ignore it.
		       *
		       * If the packet is a data channel packet, tls_pre_decrypt
		       * will load crypto_options with the correct encryption key
		       * and return false.
		       */
		      if (tls_pre_decrypt (tls_multi, &from, &buf, &crypto_options, current))
			{
#ifdef USE_PTHREAD
			  /* tell TLS thread a packet is waiting */
			  if (tls_thread_process (&thread_parms) == -1)
			    {
			      msg (M_WARN, "TLS thread is not responding, exiting (1)");
			      signal_received = 0;
			      signal_text = "error";
			      mutex_unlock (L_TLS);
			      break;
			    }
#else
			  interval_action (&tmp_int, current);
#endif /* USE_PTHREAD */
			  /* reset packet received timer if TLS packet */
			  if (options->ping_rec_timeout)
			    event_timeout_reset (&ping_rec_interval, current);
			}
		    }
#endif /* USE_SSL */
		  /* authenticate and decrypt the incoming packet */
		  if (!openvpn_decrypt (&buf, decrypt_buf, &crypto_options, &frame, current))
		    {
		      if (link_socket_connection_oriented (&link_socket))
			{
			  /* decryption errors are fatal in TCP mode */
			  signal_received = SIGUSR1;
			  msg (D_STREAM_ERRORS, "Fatal decryption error, restarting");
			  signal_text = "decryption-error";
			  mutex_unlock (L_TLS);
			  break;
			}
		    }
#ifdef USE_SSL
		  mutex_unlock (L_TLS);
#endif /* USE_SSL */
#endif /* USE_CRYPTO */
#ifdef FRAGMENT_ENABLE
		  if (fragment)
		    fragment_incoming (fragment, &buf, &frame_fragment, current);
#endif
#ifdef USE_LZO
		  /* decompress the incoming packet */
		  if (options->comp_lzo)
		    lzo_decompress (&buf, lzo_decompress_buf, &lzo_compwork, &frame);
#endif
		  /*
		   * Set our "official" outgoing address, since
		   * if buf.len is non-zero, we know the packet
		   * authenticated.  In TLS mode we do nothing
		   * because TLS mode takes care of source address
		   * authentication.
		   *
		   * Also, update the persisted version of our packet-id.
		   */
		  if (!TLS_MODE)
		    link_socket_set_outgoing_addr (&buf, &link_socket, &from);

		  /* reset packet received timer */
		  if (options->ping_rec_timeout && buf.len > 0)
		    event_timeout_reset (&ping_rec_interval, current);

		  /* increment authenticated receive byte count */
		  if (buf.len > 0)
		    {
		      link_read_bytes_auth += buf.len;
		      max_recv_size_local = max_int (original_recv_size, max_recv_size_local);
		    }

		  /* Did we just receive an openvpn ping packet? */
		  if (buf_string_match (&buf, ping_string, sizeof (ping_string)))
		    {
		      msg (D_PACKET_CONTENT, "RECEIVED PING PACKET");
		      buf.len = 0; /* drop packet */
		    }

		  /* Did we just receive an OCC packet? */
		  if (buf_string_match_head (&buf, occ_magic, sizeof (occ_magic)))
		    {
		      ASSERT (buf_advance (&buf, sizeof (occ_magic)));
		      switch (buf_read_u8 (&buf))
			{
			case OCC_REQUEST:
			  msg (D_PACKET_CONTENT, "RECEIVED OCC_REQUEST");
			  occ_op = OCC_REPLY;
			  break;

			case OCC_MTU_REQUEST:
			  msg (D_PACKET_CONTENT, "RECEIVED OCC_MTU_REQUEST");
			  occ_op = OCC_MTU_REPLY;
			  break;

			case OCC_MTU_LOAD_REQUEST:
			  msg (D_PACKET_CONTENT, "RECEIVED OCC_MTU_LOAD_REQUEST");
			  occ_mtu_load_size = buf_read_u16 (&buf);
			  if (occ_mtu_load_size >= 0)
			    occ_op = OCC_MTU_LOAD;
			  break;

			case OCC_REPLY:
			  msg (D_PACKET_CONTENT, "RECEIVED OCC_REPLY");
			  if (options->occ && !TLS_MODE && options_string_remote)
			    {
			      if (!options_cmp_equal (BPTR (&buf),
						      options_string_remote,
						      buf.len))
				{
				  options_warning (BPTR (&buf),
						   options_string_remote,
						   buf.len);
				}
			    }
			  event_timeout_clear (&occ_interval);
			  break;

			case OCC_MTU_REPLY:
			  msg (D_PACKET_CONTENT, "RECEIVED OCC_MTU_REPLY");
			  max_recv_size_remote = buf_read_u16 (&buf);
			  max_send_size_remote = buf_read_u16 (&buf);
			  if (options->mtu_test
			      && max_recv_size_remote > 0
			      && max_send_size_remote > 0)
			    {
			      msg (M_INFO, "NOTE: Empirical MTU test completed [Tried,Actual] local->remote=[%d,%d] remote->local=[%d,%d]",
				   max_send_size_local,
				   max_recv_size_remote,
				   max_send_size_remote,
				   max_recv_size_local);
			      if (!options->mssfix_defined
#ifdef FRAGMENT_ENABLE
				  && !options->fragment
#endif
				  && options->proto == PROTO_UDPv4
				  && max_send_size_local > TUN_MTU_MIN
				  && (max_recv_size_remote < max_send_size_local
				      || max_recv_size_local < max_send_size_remote))
				msg (M_INFO, "NOTE: This connection is unable to accomodate a UDP packet size of %d. Consider using --fragment or --mssfix options as a workaround.",
				     max_send_size_local);
			    }
			  event_timeout_clear (&occ_mtu_load_test_interval);
			  break;
			}
		      buf.len = 0; /* don't pass packet on */
		    }

		  to_tun = buf;
		}
	      else
		{
		  to_tun = nullbuf;
		}
	    }

#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
	  /* Incoming data from TLS background thread */
	  else if (TLS_THREAD_SOCKET_ISSET (thread_parms, reads))
	    {
	      int s;
	      ASSERT (!to_link.len);

	      s = tls_thread_rec_buf (&thread_parms, &tt_ret, true);
	      if (s == 1)
		{
		  /*
		   * TLS background thread has a control channel
		   * packet to send to remote.
		   */
		  to_link = tt_ret.to_link;
		  to_link_addr = tt_ret.to_link_addr;
		
		  /* tell TCP/UDP packet writer to free buffer after write */
		  free_to_link = true;
		}

	      /* remote died? */
	      else if (s == -1)
		{
		  msg (M_WARN, "TLS thread is not responding, exiting (2)");
		  signal_received = 0;
		  signal_text = "error";
		  break;
		}
	    }
#endif

	  /* Incoming data on TUN device */
	  else if (TUNTAP_ISSET (tuntap, reads))
	    {
	      /*
	       * Setup for read() call on TUN/TAP device.
	       */
	      ASSERT (!to_link.len);
	      buf = read_tun_buf;

#ifdef TUN_PASS_BUFFER
	      read_tun_buffered (tuntap, &buf, MAX_RW_SIZE_TUN (&frame));
#else
	      ASSERT (buf_init (&buf, FRAME_HEADROOM (&frame)));
	      ASSERT (buf_safe (&buf, MAX_RW_SIZE_TUN (&frame)));
	      buf.len = read_tun (tuntap, BPTR (&buf), MAX_RW_SIZE_TUN (&frame));
#endif

	      if (buf.len > 0)
		tun_read_bytes += buf.len;

	      /* Was TUN/TAP interface stopped? */
	      if (tuntap_stop (buf.len))
		{
		  signal_received = SIGTERM;
		  signal_text = "tun-stop";
		  msg (M_INFO, "TUN/TAP interface has been stopped, exiting");
		  break;		  
		}

	      /* Check the status return from read() */
	      check_status (buf.len, "read from TUN/TAP", NULL, tuntap);

#ifdef LOG_RW
	      if (log_rw)
		fprintf (stderr, "r");
#endif

	      /* Show packet content */
	      msg (D_TUN_RW, "TUN READ [%d]: %s md5=%s",
		   BLEN (&buf),
		   format_hex (BPTR (&buf), BLEN (&buf), 80),
		   MD5SUM (BPTR (&buf), BLEN (&buf)));

	      if (buf.len > 0)
		{
		  /*
		   * The --passtos and --mssfix options require
		   * us to examine the IPv4 header.
		   */
		  if (options->mssfix_defined
#if PASSTOS_CAPABILITY
		      || options->passtos
#endif
		      )
		    {
		      struct buffer ipbuf = buf;
		      if (is_ipv4 (tuntap->type, &ipbuf))
			{
#if PASSTOS_CAPABILITY
			  /* extract TOS from IP header */
			  if (options->passtos)
			    {
			      struct openvpn_iphdr *iph = 
				(struct openvpn_iphdr *) BPTR (&ipbuf);
			      ptos = iph->tos;
			      ptos_defined = true;
			    }
#endif
			  
			  /* possibly alter the TCP MSS */
			  if (options->mssfix_defined)
			    mss_fixup (&ipbuf, MTU_TO_MSS (TUN_MTU_SIZE_DYNAMIC (&frame)));
			}
		    }
#                   include "encrypt_sign.h"
		}
	      else
		{
		  to_link = nullbuf;
		  free_to_link = false;
		}
	    }

	  /* TUN device ready to accept write */
	  else if (TUNTAP_ISSET (tuntap, writes))
	    {
	      /*
	       * Set up for write() call to TUN/TAP
	       * device.
	       */
	      ASSERT (to_tun.len > 0);

	      /*
	       * The --mssfix option requires
	       * us to examine the IPv4 header.
	       */
	      if (options->mssfix_defined)
		{
		  struct buffer ipbuf = to_tun;

		  if (is_ipv4 (tuntap->type, &ipbuf))
		    {
		      /* possibly alter the TCP MSS */
		      if (options->mssfix_defined)
			mss_fixup (&ipbuf, MTU_TO_MSS (TUN_MTU_SIZE_DYNAMIC (&frame)));
		    }
		}
	      
	      if (to_tun.len <= MAX_RW_SIZE_TUN(&frame))
		{
		  /*
		   * Write to TUN/TAP device.
		   */
		  int size;

#ifdef LOG_RW
		  if (log_rw)
		    fprintf (stderr, "w");
#endif
		  msg (D_TUN_RW, "TUN WRITE [%d]: %s md5=%s",
		       BLEN (&to_tun),
		       format_hex (BPTR (&to_tun), BLEN (&to_tun), 80),
		       MD5SUM (BPTR (&to_tun), BLEN (&to_tun)));

#ifdef TUN_PASS_BUFFER
		  size = write_tun_buffered (tuntap, &to_tun);
#else
		  size = write_tun (tuntap, BPTR (&to_tun), BLEN (&to_tun));
#endif

		  if (size > 0)
		    tun_write_bytes += size;
		  check_status (size, "write to TUN/TAP", NULL, tuntap);

		  /* check written packet size */
		  if (size > 0)
		    {
		      /* Did we write a different size packet than we intended? */
		      if (size != BLEN (&to_tun))
			msg (D_LINK_ERRORS,
			     "TUN/TAP packet was fragmented on write to %s (tried=%d,actual=%d)",
			     tuntap->actual,
			     BLEN (&to_tun),
			     size);
		    }
		}
	      else
		{
		  /*
		   * This should never happen, probably indicates some kind
		   * of MTU mismatch.
		   */
		  msg (D_LINK_ERRORS, "tun packet too large on write (tried=%d,max=%d)",
		       to_tun.len,
		       MAX_RW_SIZE_TUN (&frame));
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

	  /* TCP/UDP port ready to accept write */
	  else if (SOCKET_ISSET (link_socket, writes))
	    {
	      if (to_link.len > 0 && to_link.len <= EXPANDED_SIZE (&frame))
		{
		  /*
		   * Setup for call to send/sendto which will send
		   * packet to remote over the TCP/UDP port.
		   */
		  int size;
		  ASSERT (addr_defined (&to_link_addr));

		  /* In gremlin-test mode, we may choose to drop this packet */
		  if (!options->gremlin || ask_gremlin())
		    {
		      /*
		       * Let the traffic shaper know how many bytes
		       * we wrote.
		       */
#ifdef HAVE_GETTIMEOFDAY
		      if (options->shaper)
			shaper_wrote_bytes (&shaper, BLEN (&to_link)
					    + datagram_overhead (options->proto));
#endif
		      /*
		       * Let the pinger know that we sent a packet.
		       */
		      if (options->ping_send_timeout)
			event_timeout_reset (&ping_send_interval, current);

#if PASSTOS_CAPABILITY
		      /* Set TOS */
		      if (ptos_defined)
			setsockopt(link_socket.sd, IPPROTO_IP, IP_TOS, &ptos, sizeof(ptos));
#endif

		      /* Log packet send */
#ifdef LOG_RW
		      if (log_rw)
			fprintf (stderr, "W");
#endif
		      msg (D_LINK_RW, "%s WRITE [%d] to %s: %s",
			   proto2ascii (link_socket.proto, true),
			   BLEN (&to_link),
			   print_sockaddr (&to_link_addr),
			   PROTO_DUMP (&to_link));

		      /* Send packet */
		      size = link_socket_write (&link_socket, &to_link, &to_link_addr);

		      if (size > 0)
			{
			  max_send_size_local = max_int (size, max_send_size_local);
			  link_write_bytes += size;
			}
		    }
		  else
		    size = 0;

		  /* Check return status */
		  check_status (size, "write", &link_socket, NULL);

		  if (size > 0)
		    {
		      /* Did we write a different size packet than we intended? */
		      if (size != BLEN (&to_link))
			msg (D_LINK_ERRORS,
			     "TCP/UDP packet was truncated/expanded on write to %s (tried=%d,actual=%d)",
			     print_sockaddr (&to_link_addr),
			     BLEN (&to_link),
			     size);
		    }
		}
	      else
		{
		  msg (D_LINK_ERRORS, "TCP/UDP packet too large on write to %s (tried=%d,max=%d)",
		       print_sockaddr (&to_link_addr),
		       to_link.len,
		       EXPANDED_SIZE (&frame));
		}

	      /*
	       * The free_to_link flag means that we should free the packet buffer
	       * after send.  This flag is usually set when the TLS background
	       * thread generated the packet buffer.
	       */
	      if (free_to_link)
		{
		  free_to_link = false;
		  free_buf (&to_link);
		}
	      to_link = nullbuf;
	    }
	}
    }

  /*
   *  Do Cleanup
   */

 cleanup:

  /*
   * If xinetd/inetd mode, don't allow restart.
   */
  if (options->inetd && (signal_received == SIGHUP || signal_received == SIGUSR1))
    {
      signal_received = SIGTERM;
      msg (M_INFO, PACKAGE_NAME " started by inetd/xinetd cannot restart... Exiting.");
    }

  if (free_to_link)
    free_buf (&to_link);
    
#if defined(USE_CRYPTO) && defined(USE_SSL) && defined(USE_PTHREAD)
  if (thread_opened)
    tls_thread_close (&thread_parms);
#endif

  free_buf (&read_link_buf);
  free_buf (&read_tun_buf);
  free_buf (&aux_buf);

#ifdef USE_LZO
  if (options->comp_lzo)
    {
      lzo_compress_uninit (&lzo_compwork);
      free_buf (&lzo_compress_buf);
      free_buf (&lzo_decompress_buf);
    }
#endif

#ifdef USE_CRYPTO

  packet_id_free (&packet_id);

  free_buf (&encrypt_buf);
  free_buf (&decrypt_buf);

#ifdef USE_SSL
  if (tls_multi)
    tls_multi_free (tls_multi, true);

  /* free options compatibility strings */
  if (options_string_local)
    free (options_string_local);
  if (options_string_remote)
    free (options_string_remote);

#endif
#endif /* USE_CRYPTO */

  /*
   * Free key schedules
   */
  if ( !(signal_received == SIGUSR1 && options->persist_key) )
    key_schedule_free (ks);

  /*
   * Close TCP/UDP connection
   */
  link_socket_close (&link_socket);
  if ( !(signal_received == SIGUSR1 && options->persist_remote_ip) )
    {
      CLEAR (link_socket_addr->remote);
      CLEAR (link_socket_addr->actual);
    }
  if ( !(signal_received == SIGUSR1 && options->persist_local_ip) )
    CLEAR (link_socket_addr->local);

  /*
   * Close TUN/TAP device
   */
  if (tuntap_defined (tuntap))
    {
      if ( !(signal_received == SIGUSR1 && options->persist_tun) )
	{
	  char* tuntap_actual = (char *) gc_malloc (sizeof (tuntap->actual));
	  strcpy (tuntap_actual, tuntap->actual);

	  /* delete any routes we added */
	  delete_routes (route_list);

	  msg (D_CLOSE, "Closing TUN/TAP device");
	  close_tun (tuntap);

	  /* Run the down script -- note that it will run at reduced
	     privilege if, for example, "--user nobody" was used. */
	  run_script (options->down_script,
		      tuntap_actual,
		      TUN_MTU_SIZE (&frame),
		      EXPANDED_SIZE (&frame),
		      print_in_addr_t (tuntap->local, true),
		      print_in_addr_t (tuntap->remote_netmask, true),
		      "init",
		      signal_description (signal_received, signal_text),
		      "down");
	}
      else
	{
	  /* run the down script on this restart if --up-restart was specified */
	  if (options->up_restart)
	    run_script (options->down_script,
			tuntap->actual,
			TUN_MTU_SIZE (&frame),
			EXPANDED_SIZE (&frame),
			print_in_addr_t (tuntap->local, true),
			print_in_addr_t (tuntap->remote_netmask, true),
			"restart",
			signal_description (signal_received, signal_text),
			"down");
	}
    }

  /* remove non-parameter environmental vars except for signal */
  del_env_nonparm (
#if defined(USE_CRYPTO) && defined(USE_SSL)
		   get_max_tls_verify_id ()
#else
		   0
#endif
		   );

#ifdef USE_CRYPTO
  /*
   * Close packet-id persistance file
   */
  packet_id_persist_save (pid_persist);
  if ( !(signal_received == SIGUSR1) )
    packet_id_persist_close (pid_persist);
#endif

  /*
   * Close fragmentation handler.
   */
#ifdef FRAGMENT_ENABLE
  if (fragment)
    fragment_free (fragment);
#endif

 done:
  /* pop our garbage collection level */
  gc_free_level (gc_level);

  /* return the signal that brought us here */
  {
    const int s = signal_received;
    signal_received = 0;
    return s;
  }
}

int
main (int argc, char *argv[])
{
  const int gc_level = gc_new_level ();
  bool first_time = true;
  int sig;

  init_random_seed();                  /* init random() function, only used as
					  source for weak random numbers */
  error_reset ();                      /* initialize error.c */
  reset_check_status ();               /* initialize status check code in socket.c */

#ifdef PID_TEST
  packet_id_interactive_test();  /* test the sequence number code */
  goto exit;
#endif

#ifdef WIN32
  init_win32 ();
#endif

#ifdef OPENVPN_DEBUG_COMMAND_LINE
  {
    int i;
    for (i = 0; i < argc; ++i)
      msg (M_INFO, "argv[%d] = '%s'", i, argv[i]);
  }
#endif

  del_env_nonparm (0);

  /*
   * This loop is initially executed on startup and then
   * once per SIGHUP.
   */
  do {
    struct options options;
    struct options defaults;
    int dev = DEV_TYPE_UNDEF;

    init_options (&options);
    init_options (&defaults);

    /*
     * Parse command line options,
     * and read configuration file.
     */
    parse_argv (&options, argc, argv);

    /* set verbosity and mute levels */
    set_check_status (D_LINK_ERRORS, D_READ_WRITE);
    set_debug_level (options.verbosity);
    set_mute_cutoff (options.mute);

    /*
     * Possibly set --dev based on --dev-node.
     * For example, if --dev-node /tmp/foo/tun, and --dev undefined,
     * set --dev to tun.
     */
    if (!options.dev)
      options.dev = dev_component_in_dev_node (options.dev_node);

    /*
     * OpenSSL info print mode?
     */
#ifdef USE_CRYPTO
    if (options.show_ciphers || options.show_digests
#ifdef USE_SSL
	|| options.show_tls_ciphers
#endif
	)
      {
	if (first_time)
	  init_ssl_lib ();
	if (options.show_ciphers)
	  show_available_ciphers ();
	if (options.show_digests)
	  show_available_digests ();
#ifdef USE_SSL
	if (options.show_tls_ciphers)
	  show_available_tls_ciphers ();
#endif
	free_ssl_lib ();
	goto exit;
      }

    /*
     * Static pre-shared key generation mode?
     */
    if (options.genkey)
      {
	int nbits_written;

	notnull (options.shared_secret_file,
		 "shared secret output file (--secret)");

	if (options.mlock)    /* should we disable paging? */
	  do_mlockall(true);

	nbits_written = write_key_file (2, options.shared_secret_file);

	msg (D_GENKEY|M_NOPREFIX, "Randomly generated %d bit key written to %s",
	     nbits_written,
	     options.shared_secret_file);
	goto exit;
      }
#endif /* USE_CRYPTO */

    /*
     * Persistent TUN/TAP device management mode?
     */
#ifdef TUNSETPERSIST
    if (options.persist_config)
      {
	/* sanity check on options for --mktun or --rmtun */
	notnull (options.dev, "TUN/TAP device (--dev)");
	if (options.remote || options.ifconfig_local || options.ifconfig_remote_netmask
#ifdef USE_CRYPTO
	    || options.shared_secret_file
#ifdef USE_SSL
	    || options.tls_server || options.tls_client
#endif
#endif
	    )
	  msg (M_FATAL, "Options error: options --mktun or --rmtun should only be used together with --dev");
	tuncfg (options.dev, options.dev_type, options.dev_node,
		options.tun_ipv6, options.persist_mode);
	goto exit;
      }
#endif

    /*
     * Main OpenVPN block -- tunnel generation mode
     */
    {
#ifdef USE_CRYPTO
      if (options.test_crypto)
	{
	  notnull (options.shared_secret_file, "key file (--secret)");
	}
      else
#endif
	notnull (options.dev, "TUN/TAP device (--dev)");

      /*
       * Get tun/tap/null device type
       */
      dev = dev_type_enum (options.dev, options.dev_type);

      /*
       * Sanity check on daemon/inetd modes
       */

      if (options.daemon && options.inetd)
	msg (M_USAGE, "Options error: only one of --daemon or --inetd may be specified");

      if (options.inetd && (options.local || options.remote))
	msg (M_USAGE, "Options error: --local or --remote cannot be used with --inetd");

      if (options.inetd && options.proto == PROTO_TCPv4_CLIENT)
	msg (M_USAGE, "Options error: --proto tcp-client cannot be used with --inetd");

      if (options.inetd == INETD_NOWAIT && options.proto != PROTO_TCPv4_SERVER)
	msg (M_USAGE, "Options error: --inetd nowait can only be used with --proto tcp-server");

      if (options.inetd == INETD_NOWAIT
#if defined(USE_CRYPTO) && defined(USE_SSL)
	  && !(options.tls_server || options.tls_client)
#endif
	  )
	msg (M_USAGE, "Options error: --inetd nowait can only be used in TLS mode");

      if (options.inetd == INETD_NOWAIT && dev != DEV_TYPE_TAP)
	msg (M_USAGE, "Options error: --inetd nowait only makes sense in --dev tap mode");

      /*
       * In forking TCP server mode, you don't need to ifconfig
       * the tap device (the assumption is that it will be bridged).
       */
      if (options.inetd == INETD_NOWAIT)
	options.ifconfig_noexec = true;

      /*
       * Sanity check on TCP mode options
       */

      if (options.connect_retry_defined && options.proto != PROTO_TCPv4_CLIENT)
	msg (M_USAGE, "Options error: --connect-retry doesn't make sense unless also used with --proto tcp-client");

      /*
       * Sanity check on MTU parameters
       */
      if (options.tun_mtu_defined && options.link_mtu_defined)
	msg (M_USAGE, "Options error: only one of --tun-mtu or --link-mtu may be defined (note that --ifconfig implies --link-mtu %d)", LINK_MTU_DEFAULT);

      if (options.proto != PROTO_UDPv4 && options.mtu_test)
	msg (M_USAGE, "Options error: --mtu-test only makes sense with --proto udp");

      /*
       * Set MTU defaults
       */
      {
	if (!options.tun_mtu_defined && !options.link_mtu_defined)
	  {
	    if ((dev == DEV_TYPE_TAP) || WIN32_0_1)
	      {
		options.tun_mtu_defined = true;
		options.tun_mtu = TAP_MTU_DEFAULT;
	      }
	    else
	      {
		if (options.ifconfig_local || options.ifconfig_remote_netmask)
		  options.link_mtu_defined = true;
		else
		  options.tun_mtu_defined = true;
	      }
	  }
	if ((dev == DEV_TYPE_TAP) && !options.tun_mtu_extra_defined)
	  {
	    options.tun_mtu_extra_defined = true;
	    options.tun_mtu_extra = TAP_MTU_EXTRA_DEFAULT;
	  }
      }

      /*
       * Sanity check on --local, --remote, and ifconfig
       */
      if (string_defined_equal (options.local, options.remote)
	  && options.local_port == options.remote_port)
	msg (M_USAGE, "Options error: --remote and --local addresses are the same");
	
      if (string_defined_equal (options.local, options.ifconfig_local)
	  || string_defined_equal (options.local, options.ifconfig_remote_netmask)
	  || string_defined_equal (options.remote, options.ifconfig_local)
	  || string_defined_equal (options.remote, options.ifconfig_remote_netmask))
	msg (M_USAGE, "Options error: --local and --remote addresses must be distinct from --ifconfig addresses");

      if (string_defined_equal (options.ifconfig_local, options.ifconfig_remote_netmask))
	msg (M_USAGE, "Options error: local and remote/netmask --ifconfig addresses must be different");

#ifdef WIN32
      if (dev == DEV_TYPE_TUN && !(options.ifconfig_local && options.ifconfig_remote_netmask))
	msg (M_USAGE, "Options error: On Windows, --ifconfig is required when --dev tun is used");

      if ((options.tuntap_options.ip_win32_defined)
	  && !(options.ifconfig_local && options.ifconfig_remote_netmask))
	msg (M_USAGE, "Options error: On Windows, --ip-win32 doesn't make sense unless --ifconfig is also used");

      if (options.tuntap_options.dhcp_options &&
	  options.tuntap_options.ip_win32_type != IPW32_SET_DHCP_MASQ)
	msg (M_USAGE, "Options error: --dhcp-options requires --ip-win32 dynamic");

      if (options.tuntap_options.ip_win32_type == IPW32_SET_DHCP_MASQ
	  && !options.route_delay_defined)
	{
	  options.route_delay_defined = true;
	  options.route_delay = 10;
	}

      if (options.ifconfig_noexec)
	{
	  options.tuntap_options.ip_win32_type = IPW32_SET_MANUAL;
	  options.ifconfig_noexec = false;
	}
#endif

      /*
       * Check that protocol options make sense.
       */

#ifdef FRAGMENT_ENABLE
      if (options.proto != PROTO_UDPv4 && options.fragment)
	msg (M_USAGE, "Options error: --fragment can only be used with --proto udp");
#endif
      if (!options.remote && options.proto == PROTO_TCPv4_CLIENT)
	msg (M_USAGE, "Options error: --remote MUST be used in TCP Client mode");

      if (options.http_proxy_server && options.proto != PROTO_TCPv4_CLIENT)
	msg (M_USAGE, "Options error: --http-proxy MUST be used in TCP Client mode (i.e. --proto tcp-client)");

      if (options.http_proxy_server && options.socks_proxy_server)
	msg (M_USAGE, "Options error: --http-proxy can not be used together with --socks-proxy");

      if (options.socks_proxy_server && options.proto == PROTO_TCPv4_SERVER)
	msg (M_USAGE, "Options error: --socks-proxy can not be used in TCP Server mode");

#ifdef USE_CRYPTO

      if (first_time)
	init_ssl_lib ();

      /*
       * Check consistency of replay options
       */
      if ((options.proto != PROTO_UDPv4)
	  && (options.replay_window != defaults.replay_window
	      || options.replay_time != defaults.replay_time))
	msg (M_USAGE, "Options error: --replay-window only makes sense with --proto udp");

      if (!options.replay
	  && (options.replay_window != defaults.replay_window
	      || options.replay_time != defaults.replay_time))
	msg (M_USAGE, "Options error: --replay-window doesn't make sense when replay protection is disabled with --no-replay");

      /* Don't use replay window for TCP mode (i.e. require that packets
	 be strictly in sequence). */
      if (link_socket_proto_connection_oriented (options.proto))
	options.replay_window = options.replay_time = 0;

#ifdef USE_SSL
      if (options.tls_server + options.tls_client +
	  (options.shared_secret_file != NULL) > 1)
	msg (M_USAGE, "specify only one of --tls-server, --tls-client, or --secret");

      if (options.tls_server)
	{
	  notnull (options.dh_file, "DH file (--dh)");
	}
      if (options.tls_server || options.tls_client)
	{
	  notnull (options.ca_file, "CA file (--ca)");
	  notnull (options.cert_file, "certificate file (--cert)");
	  notnull (options.priv_key_file, "private key file (--key)");
	  if (first_time && options.askpass)
	    pem_password_callback (NULL, 0, 0, NULL);
	}
      else
	{
	  /*
	   * Make sure user doesn't specify any TLS options
	   * when in non-TLS mode.
	   */

#define MUST_BE_UNDEF(parm) if (options.parm != defaults.parm) msg (M_USAGE, err, #parm);

	  const char err[] = "Parameter %s can only be specified in TLS-mode, i.e. where --tls-server or --tls-client is also specified.";

	  MUST_BE_UNDEF (ca_file);
	  MUST_BE_UNDEF (dh_file);
	  MUST_BE_UNDEF (cert_file);
	  MUST_BE_UNDEF (priv_key_file);
	  MUST_BE_UNDEF (cipher_list);
	  MUST_BE_UNDEF (tls_verify);
	  MUST_BE_UNDEF (tls_remote);
	  MUST_BE_UNDEF (tls_timeout);
	  MUST_BE_UNDEF (renegotiate_bytes);
	  MUST_BE_UNDEF (renegotiate_packets);
	  MUST_BE_UNDEF (renegotiate_seconds);
	  MUST_BE_UNDEF (handshake_window);
	  MUST_BE_UNDEF (transition_window);
	  MUST_BE_UNDEF (tls_auth_file);
	  MUST_BE_UNDEF (single_session);
	  MUST_BE_UNDEF (crl_file);
	  MUST_BE_UNDEF (key_method);
	}
#undef MUST_BE_UNDEF
#endif /* USE_CRYPTO */
#endif /* USE_SSL */

      /* Become a daemon if requested */
      possibly_become_daemon (0, &options, first_time);

      /* show all option settings */
      show_settings (&options);

      /* set certain options as environmental variables */
      setenv_settings (&options);

#ifdef WIN32
      /* put a title on the top window bar */
      generate_window_title (options.config ? options.config : "");
#endif

      /* Do Work */
      {
	/* these objects are potentially persistent across SIGUSR1 resets */
	struct link_socket_addr usa;
	struct key_schedule ks;
	struct tuntap tuntap;
	struct packet_id_persist pid_persist;
	struct route_list route_list;
	struct http_proxy_info http_proxy;
	struct socks_proxy_info socks_proxy;

	/* print version number */
	msg (M_INFO, "%s", title_string);

	CLEAR (usa);
	CLEAR (ks);
	clear_tuntap (&tuntap);
	packet_id_persist_init (&pid_persist);
	clear_route_list (&route_list);
	CLEAR (http_proxy);
	CLEAR (socks_proxy);
	if (options.http_proxy_server)
	  {
	    init_http_proxy (&http_proxy,
			     options.http_proxy_server,
			     options.http_proxy_port,
			     options.http_proxy_retry,
			     options.http_proxy_auth_method,
			     options.http_proxy_auth_file);
	  }

	if (options.socks_proxy_server)
	  {
	    init_socks_proxy (&socks_proxy,
			      options.socks_proxy_server,
			      options.socks_proxy_port,
			      options.socks_proxy_retry);
	  }

	do {
	  sig = openvpn (&options, &usa, &tuntap, &ks, &pid_persist, &route_list, &http_proxy, &socks_proxy, first_time);
	  first_time = false;
	} while (sig == SIGUSR1);
      }
    }
    gc_collect (gc_level);
    close_syslog ();
  } while (sig == SIGHUP);

  thread_cleanup();

#ifdef USE_CRYPTO
  free_ssl_lib ();
#endif

 exit:

#if defined(MEASURE_TLS_HANDSHAKE_STATS) && defined(USE_CRYPTO) && defined(USE_SSL)
  show_tls_performance_stats();
#endif

  /* pop our garbage collection level */
  gc_free_level (gc_level);

  openvpn_exit (OPENVPN_EXIT_STATUS_GOOD); /* exit point */
  return 0; /* NOTREACHED */
}

/*
 * Basic threading test.
 */
#if defined(USE_PTHREAD) && defined(USE_CRYPTO)
static void*
test_crypto_thread (void *arg)
{
  struct link_socket_addr usa;
  struct tuntap tuntap;
  struct key_schedule ks;
  struct packet_id_persist pid_persist;
  struct route_list route_list;
  struct http_proxy_info http_proxy;
  struct socks_proxy_info socks_proxy;
  const struct options *opt = (struct options*) arg;

  /* print version number */
  msg (M_INFO, "%s", title_string);

  set_nice (opt->nice_work);
  CLEAR (usa);
  CLEAR (ks);
  clear_tuntap (&tuntap);
  packet_id_persist_init (&pid_persist);
  clear_route_list (&route_list);
  CLEAR (http_proxy);
  CLEAR (socks_proxy);
  openvpn (opt, &usa, &tuntap, &ks, &pid_persist, &route_list, &http_proxy, &socks_proxy, false);
  return NULL;
}
#endif
