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

#ifndef OPENVPN_SSL_H
#define OPENVPN_SSL_H

#if defined(USE_CRYPTO) && defined(USE_SSL)

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#include "basic.h"
#include "crypto.h"
#include "packet_id.h"
#include "session_id.h"
#include "reliable.h"
#include "socket.h"
#include "mtu.h"
#include "thread.h"
#include "options.h"
#include "plugin.h"

/*
 * OpenVPN TLS-over-UDP Protocol.
 *
 * TCP/UDP Packet:
 *   packet length (16 bits, unsigned) -- TCP only, always sent as plaintext
 *   packet opcode (high 5 bits, see P_ constants below)
 *   key_id (low 3 bits, see key_id in struct tls_session below for comment)
 *   payload (n bytes)
 *
 * P_CONTROL* and P_ACK Payload:
 *   session_id (random 64 bit value to identify session)
 *   hmac for authentication (usually 16 or 20 bytes)
 *   packet-id for replay protection (4 or 8 bytes, includes
 *     sequence number and optional time_t timestamp)
 *   acknowledge packet_id array length (1 byte)
 *   acknowledge packet-id array (if length > 0)
 *   acknowledge remote session_id (if length > 0)
 *   control packet-id (4 bytes)
 *   TLS ciphertext (n bytes) (only for P_CONTROL)
 *
 * TLS plaintext packet (key_method == 1):
 *   cipher key length in bytes (1 byte)
 *   cipher key (n bytes)
 *   hmac key length in bytes (1 byte)
 *   hmac key (n bytes)
 *   options string (n bytes, null terminated, client/server options string must match)
 *
 * TLS plaintext packet (key_method >= 2):
 *   0 (4 bytes)
 *   key_method (1 byte)
 *   key_source structure (pre_master only defined for client -> server)
 *   options_string_length, including null (2 bytes)
 *   options string (n bytes, null terminated, client/server options string must match)
 *   [The username/password data below is optional, record can end at this point]
 *   username_string_length, including null (2 bytes)
 *   username string (n bytes, null terminated)
 *   password_string_length, including null (2 bytes)
 *   password string (n bytes, null terminated)
 *
 * P_DATA Payload:
 *   hmac of ciphertext IV + ciphertext (if enabled by --auth)
 *   ciphertext IV (size is cipher-dependent, if not disabled by --no-iv)
 *   P_DATA ciphertext
 *
 * P_DATA plaintext
 *   packet_id (4 or 8 bytes, if not disabled by --no-replay)
 *   user plaintext (n bytes)
 *
 * Notes:
 *   (1) Acknowledgements can be encoded in either the dedicated P_ACK record
 *       or they can be prepended to a P_CONTROL* record.
 *   (2) P_DATA and P_CONTROL/P_ACK use independent packet-id sequences because
 *       P_DATA is an unreliable channel while P_CONTROL/P_ACK is a reliable channel.
 */

/* Used in the TLS PRF function */
#define KEY_EXPANSION_ID "OpenVPN"

/* passwords */
#define UP_TYPE_AUTH        "Auth"
#define UP_TYPE_PRIVATE_KEY "Private Key"

/* packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte */
#define P_KEY_ID_MASK                  0x07
#define P_OPCODE_SHIFT                 3

/* packet opcodes -- the V1 is intended to allow protocol changes in the future */
#define P_CONTROL_HARD_RESET_CLIENT_V1 1     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V1 2     /* initial key from server, forget previous state */
#define P_CONTROL_SOFT_RESET_V1        3     /* new key, graceful transition from old to new key */
#define P_CONTROL_V1                   4     /* control channel packet (usually TLS ciphertext) */
#define P_ACK_V1                       5     /* acknowledgement for packets received */
#define P_DATA_V1                      6     /* data channel packet */

/* indicates key_method >= 2 */
#define P_CONTROL_HARD_RESET_CLIENT_V2 7     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V2 8     /* initial key from server, forget previous state */

/* define the range of legal opcodes */
#define P_FIRST_OPCODE                 1
#define P_LAST_OPCODE                  8

/* key negotiation states */
#define S_ERROR          -1
#define S_UNDEF           0
#define S_INITIAL         1	/* tls_init() was called */
#define S_PRE_START       2	/* waiting for initial reset & acknowledgement */
#define S_START           3	/* ready to exchange keys */
#define S_SENT_KEY        4	/* client does S_SENT_KEY -> S_GOT_KEY */
#define S_GOT_KEY         5	/* server does S_GOT_KEY -> S_SENT_KEY */
#define S_ACTIVE          6	/* ready to exchange data channel packets */
#define S_NORMAL          7	/* normal operations */

/*
 * Are we ready to receive data channel packets?
 *
 * Also, if true, we can safely assume session has been
 * authenticated by TLS.
 *
 * NOTE: Assumes S_SENT_KEY + 1 == S_GOT_KEY.
 */
#define DECRYPT_KEY_ENABLED(multi, ks) ((ks)->state >= (S_GOT_KEY - (multi)->opt.server))

/* Should we aggregate TLS acknowledgements, and tack them onto control packets? */
#define TLS_AGGREGATE_ACK

/*
 * If TLS_AGGREGATE_ACK, set the
 * max number of acknowledgments that
 * can "hitch a ride" on an outgoing
 * non-P_ACK_V1 control packet.
 */
#define CONTROL_SEND_ACK_MAX 4

/*
 * Define number of buffers for send and receive in the reliability layer.
 */
#define TLS_RELIABLE_N_SEND_BUFFERS  4 /* also window size for reliablity layer */
#define TLS_RELIABLE_N_REC_BUFFERS   8

/*
 * Various timeouts
 */
 
#define TLS_MULTI_REFRESH 15    /* call tls_multi_process once every n seconds */
#define TLS_MULTI_HORIZON 2     /* call tls_multi_process frequently for n seconds after
				   every packet sent/received action */

/* The SSL/TLS worker thread will wait at most this many seconds for the interprocess
   communication pipe to the main thread to be ready to accept writes. */
#define TLS_MULTI_THREAD_SEND_TIMEOUT 5

/*
 * Buffer sizes (also see mtu.h).
 */

#define PLAINTEXT_BUFFER_SIZE 1024

/* Maximum length of common name */
#define TLS_CN_LEN 64

/* Legal characters in an X509 or common name */
#define X509_NAME_CHAR_CLASS   (CC_ALNUM|CC_UNDERBAR|CC_DASH|CC_DOT|CC_AT|CC_COLON|CC_SLASH|CC_EQUAL)
#define COMMON_NAME_CHAR_CLASS (CC_ALNUM|CC_UNDERBAR|CC_DASH|CC_DOT|CC_AT)

/* Maximum length of OCC options string passed as part of auth handshake */
#define TLS_OPTIONS_LEN 512

/*
 * Range of key exchange methods
 */
#define KEY_METHOD_MIN 1
#define KEY_METHOD_MAX 2

/* key method taken from lower 4 bits */
#define KEY_METHOD_MASK 0x0F

/*
 * Measure success rate of TLS handshakes, for debugging only
 */
/* #define MEASURE_TLS_HANDSHAKE_STATS */

/*
 * Key material, used as source for PRF-based
 * key expansion.
 */

struct key_source {
  uint8_t pre_master[48]; /* client generated */
  uint8_t random1[32];    /* generated by both client and server */
  uint8_t random2[32];    /* generated by both client and server */
};

struct key_source2 {
  struct key_source client;
  struct key_source server;
};

/*
 * Represents a single instantiation of a TLS negotiation and
 * data channel key exchange.  4 keys are kept: encrypt hmac,
 * decrypt hmac, encrypt cipher, and decrypt cipher.  The TLS
 * control channel is used to exchange these keys.
 * Each hard or soft reset will build
 * a fresh key_state.  Normally an openvpn session will contain two
 * key_state objects, one for the current TLS connection, and other
 * for the retiring or "lame duck" key.  The lame duck key_state is
 * used to maintain transmission continuity on the data-channel while
 * a key renegotiation is taking place.
 */
struct key_state
{
  int state;
  int key_id;			/* inherited from struct tls_session below */

  SSL *ssl;			/* SSL object -- new obj created for each new key */
  BIO *ssl_bio;			/* read/write plaintext from here */
  BIO *ct_in;			/* write ciphertext to here */
  BIO *ct_out;			/* read ciphertext from here */

  time_t established;		/* when our state went S_ACTIVE */
  time_t must_negotiate;	/* key negotiation times out if not finished before this time */
  time_t must_die;		/* this object is destroyed at this time */

  int initial_opcode;		/* our initial P_ opcode */
  struct session_id session_id_remote; /* peer's random session ID */
  struct sockaddr_in remote_addr;      /* peer's IP addr */
  struct packet_id packet_id;	       /* for data channel, to prevent replay attacks */

  struct key_ctx_bi key;	       /* data channel keys for encrypt/decrypt/hmac */

  struct key_source2 *key_src;         /* source entropy for key expansion */

  struct buffer plaintext_read_buf;
  struct buffer plaintext_write_buf;
  struct buffer ack_write_buf;

  struct reliable *send_reliable; /* holds a copy of outgoing packets until ACK received */
  struct reliable *rec_reliable;  /* order incoming ciphertext packets before we pass to TLS */
  struct reliable_ack *rec_ack;	  /* buffers all packet IDs we want to ACK back to sender */

  int n_bytes;			 /* how many bytes sent/recvd since last key exchange */
  int n_packets;		 /* how many packets sent/recvd since last key exchange */

  /*
   * If bad username/password, TLS connection will come up but 'authenticated' will be false.
   */
  bool authenticated;
};

/*
 * Our const options, obtained directly or derived from
 * command line options.
 */
struct tls_options
{
  /* our master SSL_CTX from which all SSL objects derived */
  SSL_CTX *ssl_ctx;

  /* data channel cipher, hmac, and key lengths */
  struct key_type key_type;

  /* true if we are a TLS server, client otherwise */
  bool server;

#ifdef ENABLE_OCC
  /* local and remote options strings
     that must match between client and server */
  const char *local_options;
  const char *remote_options;
#endif

  /* from command line */
  int key_method;
  bool replay;
  bool single_session;
#ifdef ENABLE_OCC
  bool disable_occ;
#endif
  int transition_window;
  int handshake_window;
  interval_t packet_timeout;
  int renegotiate_bytes;
  int renegotiate_packets;
  interval_t renegotiate_seconds;

  /* cert verification parms */
  const char *verify_command;
  const char *verify_x509name;
  const char *crl_file;
  int ns_cert_type;

  /* allow openvpn config info to be
     passed over control channel */
  bool pass_config_info;

  /* struct crypto_option flags */
  unsigned int crypto_flags_and;
  unsigned int crypto_flags_or;

  int replay_window;                   /* --replay-window parm */
  int replay_time;                     /* --replay-window parm */

  /* packet authentication for TLS handshake */
  struct crypto_options tls_auth;
  struct key_ctx_bi tls_auth_key;

  /* frame parameters for TLS control channel */
  struct frame frame;

  /* used for username/password authentication */
  const char *auth_user_pass_verify_script;
  bool auth_user_pass_verify_script_via_file;
  const char *tmp_dir;
  bool username_as_common_name;

  /* use the client-config-dir as a positive authenticator */
  const char *client_config_dir_exclusive;

  /* instance-wide environment variable set */
  struct env_set *es;
  const struct plugin_list *plugins;

  /* --gremlin bits */
  int gremlin;
};

/* index into tls_session.key */
#define KS_PRIMARY    0		/* the primary key */
#define KS_LAME_DUCK  1		/* the key that's going to retire soon */
#define KS_SIZE       2

/*
 * A tls_session lives through multiple key_state life-cycles.  Soft resets
 * will reuse a tls_session object, but hard resets or errors will require
 * that a fresh object be built.  Normally three tls_session objects are maintained
 * by an active openvpn session.  The first is the current, TLS authenticated
 * session, the second is used to process connection requests from a new
 * client that would usurp the current session if successfully authenticated,
 * and the third is used as a repository for a "lame-duck" key in the event
 * that the primary session resets due to error while the lame-duck key still
 * has time left before its expiration.  Lame duck keys are used to maintain
 * the continuity of the data channel connection while a new key is being
 * negotiated.
 */
struct tls_session
{
  /* const options and config info */
  const struct tls_options *opt;

  /* during hard reset used to control burst retransmit */
  bool burst;

  /* authenticate control packets */
  struct crypto_options tls_auth;
  struct packet_id tls_auth_pid;

  int initial_opcode;		/* our initial P_ opcode */
  struct session_id session_id;	/* our random session ID */
  int key_id;			/* increments with each soft reset (for key renegotiation) */

  int limit_next;               /* used for traffic shaping on the control channel */

  int verify_maxlevel;

  char *common_name;
  bool verified;                /* true if peer certificate was verified against CA */

  /* not-yet-authenticated incoming client */
  struct sockaddr_in untrusted_sockaddr;

  struct key_state key[KS_SIZE];
};

/* index into tls_multi.session */
#define TM_ACTIVE    0
#define TM_UNTRUSTED 1
#define TM_LAME_DUCK 2
#define TM_SIZE      3

/*
 * The number of keys we will scan on encrypt or decrypt.  The first
 * is the "active" key.  The second is the lame_duck or retiring key
 * associated with the active key's session ID.  The third is a detached
 * lame duck session that only occurs in situations where a key renegotiate
 * failed on the active key, but a lame duck key was still valid.  By
 * preserving the lame duck session, we can be assured of having a data
 * channel key available even when network conditions are so bad that
 * we can't negotiate a new key within the time allotted.
 */
#define KEY_SCAN_SIZE 3

/*
 * An openvpn session running with TLS enabled has one tls_multi object.
 */
struct tls_multi
{
  /* used to coordinate access between main thread and TLS thread */
  //MUTEX_PTR_DEFINE (mutex);

  /* const options and config info */
  struct tls_options opt;

  /*
   * A list of key_state objects in the order they should be
   * scanned by data channel encrypt and decrypt routines.
   */
  struct key_state* key_scan[KEY_SCAN_SIZE];

  /*
   * used by tls_pre_encrypt to communicate the encrypt key
   * to tls_post_encrypt()
   */
  struct key_state *save_ks;	/* temporary pointer used between pre/post routines */

  /*
   * Number of sessions negotiated thus far.
   */
  int n_sessions;

  /*
   * Number of errors.
   */
  int n_hard_errors;   /* errors due to TLS negotiation failure */
  int n_soft_errors;   /* errors due to unrecognized or failed-to-authenticate incoming packets */

  /*
   * Our locked common name (cannot change during the life of this tls_multi object)
   */
  char *locked_cn;

  /*
   * Our session objects.
   */
  struct tls_session session[TM_SIZE];
};

/*
 * Used in --mode server mode to check tls-auth signature on initial
 * packets received from new clients.
 */
struct tls_auth_standalone
{
  struct key_ctx_bi tls_auth_key;
  struct crypto_options tls_auth_options;
  struct frame frame;
};

void init_ssl_lib (void);
void free_ssl_lib (void);

/* Build master SSL_CTX object that serves for the whole of openvpn instantiation */
SSL_CTX *init_ssl (const struct options *options);

struct tls_multi *tls_multi_init (struct tls_options *tls_options);

struct tls_auth_standalone *tls_auth_standalone_init (struct tls_options *tls_options,
						      struct gc_arena *gc);

void tls_auth_standalone_finalize (struct tls_auth_standalone *tas,
				   const struct frame *frame);

void tls_multi_init_finalize(struct tls_multi *multi,
			     const struct frame *frame);

void tls_multi_init_set_options(struct tls_multi* multi,
				const char *local,
				const char *remote);

bool tls_multi_process (struct tls_multi *multi,
			struct buffer *to_link,
			struct sockaddr_in *to_link_addr,
			struct link_socket_info *to_link_socket_info,
			interval_t *wakeup);

void tls_multi_free (struct tls_multi *multi, bool clear);

bool tls_pre_decrypt (struct tls_multi *multi,
		      struct sockaddr_in *from,
		      struct buffer *buf,
		      struct crypto_options *opt);

bool tls_pre_decrypt_lite (const struct tls_auth_standalone *tas,
			   const struct sockaddr_in *from,
			   const struct buffer *buf);

void tls_pre_encrypt (struct tls_multi *multi,
		      struct buffer *buf, struct crypto_options *opt);

void tls_post_encrypt (struct tls_multi *multi, struct buffer *buf);

void show_available_tls_ciphers (void);
void get_highest_preference_tls_cipher (char *buf, int size);

void pem_password_setup (const char *auth_file);
int pem_password_callback (char *buf, int size, int rwflag, void *u);
void auth_user_pass_setup (const char *auth_file);
void ssl_set_auth_nocache (void);

void tls_set_verify_command (const char *cmd);
void tls_set_crl_verify (const char *crl);
void tls_set_verify_x509name (const char *x509name);

void tls_adjust_frame_parameters(struct frame *frame);

bool tls_send_payload (struct tls_multi *multi,
		       const uint8_t *data,
		       int size);

bool tls_rec_payload (struct tls_multi *multi,
		      struct buffer *buf);

const char *tls_common_name (struct tls_multi* multi, bool null);
void tls_set_common_name (struct tls_multi *multi, const char *common_name);
void tls_lock_common_name (struct tls_multi *multi);

bool tls_authenticated (struct tls_multi *multi);
void tls_deauthenticate (struct tls_multi *multi);

/*
 * inline functions
 */

static inline int
tls_test_payload_len (const struct tls_multi *multi)
{
  if (multi)
    {
      const struct key_state *ks = &multi->session[TM_ACTIVE].key[KS_PRIMARY];
      if (ks->state >= S_ACTIVE)
	return BLEN (&ks->plaintext_read_buf);
    }
  return 0;
}

/*
 * protocol_dump() flags
 */
#define PD_TLS_AUTH_HMAC_SIZE_MASK 0xFF
#define PD_SHOW_DATA               (1<<8)
#define PD_TLS                     (1<<9)
#define PD_VERBOSE                 (1<<10)

const char *protocol_dump (struct buffer *buffer,
			   unsigned int flags,
			   struct gc_arena *gc);

/*
 * debugging code
 */

#ifdef MEASURE_TLS_HANDSHAKE_STATS
void show_tls_performance_stats(void);
#endif

//#define EXTRACT_X509_FIELD_TEST
void extract_x509_field_test (void);

#endif /* USE_CRYPTO && USE_SSL */

#endif
