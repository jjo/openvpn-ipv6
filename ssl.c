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

/*
 * The routines in this file deal with dynamically negotiating
 * the data channel HMAC and cipher keys through a TLS session.
 *
 * Both the TLS session and the data channel are multiplexed
 * over the same UDP port.
 */

#include "config.h"

#if defined(USE_CRYPTO) && defined(USE_SSL)

#include "syshead.h"

#include "ssl.h"
#include "error.h"
#include "common.h"
#include "socket.h"
#include "thread.h"
#include "misc.h"
#include "fdmisc.h"

#include "memdbg.h"

/*
 * Max number of bytes we will add
 * for data structures common to both
 * data and control channel packets.
 * (opcode only). 
 */
void
tls_adjust_frame_parameters(struct frame *frame)
{
  frame->extra_frame += 1; /* space for opcode */
}

/*
 * Max number of bytes we will add
 * to control channel packet. 
 */
static void
tls_init_control_channel_frame_parameters(const struct frame *data_channel_frame,
					  struct frame *frame)
{
  /*
   * frame->extra_frame is already initialized with tls_auth buffer requirements,
   * if --tls-auth is enabled.
   */

  /* set extra_frame */
  tls_adjust_frame_parameters(frame);
  reliable_ack_adjust_frame_parameters(frame, CONTROL_SEND_ACK_MAX);
  frame->extra_frame += SID_SIZE;
  frame->extra_frame += sizeof (packet_id_type);

  /* finalize parameters based on data_channel_frame */
  frame->mtu = MTU_EXTRA_SIZE (data_channel_frame) - frame->extra_frame;
  frame->extra_buffer += frame->extra_frame;
}

void
init_ssl_lib ()
{
  SSL_library_init ();
  SSL_load_error_strings ();
  OpenSSL_add_all_algorithms ();

  init_crypto_lib();

  /*
   * If you build the OpenSSL library and OpenVPN with
   * CRYPTO_MDEBUG, you will get a listing of OpenSSL
   * memory leaks on program termination.
   */
#ifdef CRYPTO_MDEBUG
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
}

void
free_ssl_lib ()
{
#ifdef CRYPTO_MDEBUG
  FILE* fp = fopen ("sdlog", "w");
  ASSERT (fp);
  CRYPTO_mem_leaks_fp (fp);
  fclose (fp);
#endif

  EVP_cleanup ();
  ERR_free_strings ();
}

/*
 * OpenSSL library calls back here if the private key
 * is protected by a password.
 */
int
pem_password_callback (char *buf, int size, int rwflag, void *u)
{
#ifdef HAVE_GETPASS
  static char passbuf[256];

  if (!strlen (passbuf))
    {
      char *gp = getpass ("Enter PEM pass phrase:");
      strncpynt (passbuf, gp, sizeof (passbuf));
      memset (gp, 0, strlen (gp));
    }

  if (buf)
    {
      if (!strlen (passbuf))
	msg (M_FATAL, "TLS Error: need PEM password for private key");
      strncpynt (buf, passbuf, size);
      CLEAR (passbuf);
      return strlen (buf);
    }
#else
  msg (M_FATAL, "Sorry but I can't read a password from the console because this operating system or C library doesn't support the getpass() function");
#endif
  return 0;
}

/*
 * OpenSSL callback to get a temporary RSA key, mostly
 * used for export ciphers.
 */
static RSA *
tmp_rsa_cb (SSL * s, int is_export, int keylength)
{
  static RSA *rsa_tmp = NULL;
  if (rsa_tmp == NULL)
    {
      msg (D_HANDSHAKE, "Generating temp (%d bit) RSA key", keylength);
      rsa_tmp = RSA_generate_key (keylength, RSA_F4, NULL, NULL);
    }
  return (rsa_tmp);
}

/* make cp safe to be passed to system() */
static void
system_safe_string (char *cp)
{
  int c;
  while (c = *cp)
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
 * Our verify callback function -- check
 * that an incoming peer certificate is good.
 */

static const char *verify_command;

void
tls_set_verify_command (const char *cmd)
{
  verify_command = cmd;
}

static int
verify_callback (int preverify_ok, X509_STORE_CTX * ctx)
{
  char txt[512];

  X509_NAME_oneline (X509_get_subject_name (ctx->current_cert), txt,
		     sizeof (txt));
  txt[sizeof (txt) - 1] = '\0';
  system_safe_string (txt);

  if (!preverify_ok)
    {
      /* Remote site specified a certificate, but it's not correct */
      msg (M_WARN, "VERIFY ERROR: depth=%d, error=%s: %s",
	   ctx->error_depth, X509_verify_cert_error_string (ctx->error), txt);
      return 0;			/* Reject connection */
    }

  if (verify_command)
    {
      char command[512];
      struct buffer out;
      int ret;
      buf_set_write (&out, command, sizeof (command));
      buf_printf (&out, "%s %d %s", verify_command, ctx->error_depth, txt);
      msg (D_TLS_DEBUG, "executing verify command: %s", command);
      ret = openvpn_system (command);
      if (ret != -1 && WEXITSTATUS (ret) == 0)
	{
	  msg (D_HANDSHAKE, "VERIFY SCRIPT OK: depth=%d, %s",
	       ctx->error_depth, txt);
	  return 1;		/* Accept connection */
	}
      else
	{
	  if (ret == -1 || WEXITSTATUS (ret) == 127)
	    msg (M_ERR, "Verify command failed to execute: %s", command);
	  msg (D_HANDSHAKE, "VERIFY SCRIPT ERROR: depth=%d, %s",
	       ctx->error_depth, txt);
	  return 0;		/* Reject connection */
	}
    }
  else
    {
      msg (D_HANDSHAKE, "VERIFY OK: depth=%d, %s", ctx->error_depth, txt);
      return 1;			/* Accept connection */
    }
}

/*
 * Print debugging information on SSL/TLS session negotiation.
 */
static void
info_callback (INFO_CALLBACK_SSL_CONST SSL * s, int where, int ret)
{
  if (where & SSL_CB_LOOP)
    {
      msg (D_HANDSHAKE_VERBOSE, "SSL state (%s): %s",
	   where & SSL_ST_CONNECT ? "connect" :
	   where & SSL_ST_ACCEPT ? "accept" :
	   "undefined", SSL_state_string_long (s));
    }
  else if (where & SSL_CB_ALERT)
    {
      msg (D_HANDSHAKE_VERBOSE, "SSL alert (%s): %s: %s",
	   where & SSL_CB_READ ? "read" : "write",
	   SSL_alert_type_string_long (ret),
	   SSL_alert_desc_string_long (ret));
    }
}

/*
 * Initialize SSL context.
 * All files are in PEM format.
 */
SSL_CTX *
init_ssl (bool server,
	  const char *ca_file,
	  const char *dh_file,
	  const char *cert_file,
	  const char *priv_key_file, const char *cipher_list)
{
  SSL_CTX *ctx;
  DH *dh;
  BIO *bio;

  if (server)
    {
      ctx = SSL_CTX_new (TLSv1_server_method ());
      if (ctx == NULL)
	msg (M_SSLERR, "SSL_CTX_new TLSv1_server_method");

      SSL_CTX_set_tmp_rsa_callback (ctx, tmp_rsa_cb);

      /* Get Diffie Hellman Parameters */
      if (!(bio = BIO_new_file (dh_file, "r")))
	msg (M_SSLERR, "Cannot open %s for DH parameters", dh_file);
      dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
      BIO_free (bio);
      if (!dh)
	msg (M_SSLERR, "Cannot load DH parameters from %s", dh_file);
      if (!SSL_CTX_set_tmp_dh (ctx, dh))
	msg (M_SSLERR, "SSL_CTX_set_tmp_dh");
      msg (D_TLS_DEBUG_LOW, "Diffie-Hellman initialized with %d bit key",
	   8 * DH_size (dh));
      DH_free (dh);

    }
  else				/* if client */
    {
      ctx = SSL_CTX_new (TLSv1_client_method ());
      if (ctx == NULL)
	msg (M_SSLERR, "SSL_CTX_new TLSv1_client_method");
    }

  /* Set SSL options */
  SSL_CTX_set_session_cache_mode (ctx, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options (ctx, SSL_OP_SINGLE_DH_USE);

  /* Set callback for getting password from user to decrypt private key */
  SSL_CTX_set_default_passwd_cb (ctx, pem_password_callback);

  /* Load Certificate */
  if (!SSL_CTX_use_certificate_chain_file (ctx, cert_file))
    msg (M_SSLERR, "Cannot load certificate chain file %s", cert_file);

  /* Load Private Key */
  if (!SSL_CTX_use_PrivateKey_file (ctx, priv_key_file, SSL_FILETYPE_PEM))
    msg (M_SSLERR, "Cannot load private key file %s", priv_key_file);

  /* Check Private Key */
  if (!SSL_CTX_check_private_key (ctx))
    msg (M_SSLERR, "Private key does not match the certificate");

  /* Load Certificate Authority File */
  if (!SSL_CTX_load_verify_locations (ctx, ca_file, NULL))
    msg (M_SSLERR, "Cannot load CA certificate file %s", ca_file);

  /* Require peer certificate verification */
  SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		      verify_callback);

  /* Connection information callback */
  SSL_CTX_set_info_callback (ctx, info_callback);

  /* Allowable ciphers */
  if (cipher_list)
    {
      if (!SSL_CTX_set_cipher_list (ctx, cipher_list))
	msg (M_SSLERR, "Problem with cipher list: %s", cipher_list);
    }

  return ctx;
}

/*
 * Print a one line summary of SSL/TLS session handshake.
 */
static void
print_details (SSL * c_ssl, const char *prefix)
{
  SSL_CIPHER *ciph;
  X509 *cert;
  char s1[256];
  char s2[256];

  s1[0] = s2[0] = 0;
  ciph = SSL_get_current_cipher (c_ssl);
  snprintf (s1, sizeof (s1), "%s %s, cipher %s %s",
	    prefix,
	    SSL_get_version (c_ssl),
	    SSL_CIPHER_get_version (ciph), SSL_CIPHER_get_name (ciph));
  cert = SSL_get_peer_certificate (c_ssl);
  if (cert != NULL)
    {
      EVP_PKEY *pkey = X509_get_pubkey (cert);
      if (pkey != NULL)
	{
	  if (pkey->type == EVP_PKEY_RSA && pkey->pkey.rsa != NULL
	      && pkey->pkey.rsa->n != NULL)
	    {
	      snprintf (s2, sizeof (s2), ", %d bit RSA",
			BN_num_bits (pkey->pkey.rsa->n));
	    }
	  else if (pkey->type == EVP_PKEY_DSA && pkey->pkey.dsa != NULL
		   && pkey->pkey.dsa->p != NULL)
	    {
	      snprintf (s2, sizeof (s2), ", %d bit DSA",
			BN_num_bits (pkey->pkey.dsa->p));
	    }
	  EVP_PKEY_free (pkey);
	}
      X509_free (cert);
    }
  /* The SSL API does not allow us to look at temporary RSA/DH keys,
   * otherwise we should print their lengths too */
  msg (M_INFO, "%s%s", s1, s2);
}

/*
 * Show the TLS ciphers that are available for us to use
 * in the OpenSSL library.
 */
void
show_available_tls_ciphers ()
{
  SSL_CTX *ctx;
  SSL *ssl;
  const char *cipher_name;
  int priority = 0;

  ctx = SSL_CTX_new (TLSv1_method ());
  if (!ctx)
    msg (M_SSLERR, "Cannot create SSL_CTX object");
  ssl = SSL_new (ctx);
  if (!ssl)
    msg (M_SSLERR, "Cannot create SSL object");

  printf ("Available TLS Ciphers,\n");
  printf ("listed in order of preference:\n\n");
  while (cipher_name = SSL_get_cipher_list (ssl, priority++))
    printf ("%s\n", cipher_name);
  printf ("\n");

  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

/*
 * The OpenSSL library has a notion of preference in TLS
 * ciphers.  Higher preference == more secure.
 * Return the highest preference cipher.
 */
void
get_highest_preference_tls_cipher (char *buf, int size)
{
  SSL_CTX *ctx;
  SSL *ssl;
  const char *cipher_name;

  ctx = SSL_CTX_new (TLSv1_method ());
  if (!ctx)
    msg (M_SSLERR, "Cannot create SSL_CTX object");
  ssl = SSL_new (ctx);
  if (!ssl)
    msg (M_SSLERR, "Cannot create SSL object");

  cipher_name = SSL_get_cipher_list (ssl, 0);
  strncpynt (buf, cipher_name, size);

  SSL_free (ssl);
  SSL_CTX_free (ctx);
}

/*
 * Map internal constants to ascii names.
 */
static const char *
state_name (int state)
{
  switch (state)
    {
    case S_UNDEF:
      return "S_UNDEF";
    case S_INITIAL:
      return "S_INITIAL";
    case S_PRE_START:
      return "S_PRE_START";
    case S_START:
      return "S_START";
    case S_SENT_KEY:
      return "S_SENT_KEY";
    case S_GOT_KEY:
      return "S_GOT_KEY";
    case S_ACTIVE:
      return "S_ACTIVE";
    case S_ERROR:
      return "S_ERROR";
    default:
      return "S_???";
    }
}

static const char *
packet_opcode_name (int op)
{
  switch (op)
    {
    case P_CONTROL_HARD_RESET_CLIENT_V1:
      return "P_CONTROL_HARD_RESET_CLIENT_V1";
    case P_CONTROL_HARD_RESET_SERVER_V1:
      return "P_CONTROL_HARD_RESET_SERVER_V1";
    case P_CONTROL_SOFT_RESET_V1:
      return "P_CONTROL_SOFT_RESET_V1";
    case P_CONTROL_V1:
      return "P_CONTROL_V1";
    case P_ACK_V1:
      return "P_ACK_V1";
    case P_DATA_V1:
      return "P_DATA_V1";
    default:
      return "P_???";
    }
}

static const char *
session_index_name (int index)
{
  switch (index)
    {
    case TM_ACTIVE:
      return "TM_ACTIVE";
    case TM_UNTRUSTED:
      return "TM_UNTRUSTED";
    case TM_LAME_DUCK:
      return "TM_LAME_DUCK";
    default:
      return "TM_???";
    }
}

/*
 * For debugging.
 */
static const char *
print_key_id (struct tls_multi *multi)
{
  int i;
  struct buffer out = alloc_buf_gc (256);

  for (i = 0; i < KEY_SCAN_SIZE; ++i)
    {
      struct key_state *ks = multi->key_scan[i];
      buf_printf (&out, " [key#%d state=%s id=%d sid=%s]", i,
		  state_name (ks->state), ks->key_id,
		  session_id_print (&ks->session_id_remote));
    }

  return out.data;
}

/*
 * OpenVPN's interface to SSL/TLS authentication,
 * encryption, and decryption is exclusively
 * through "memory BIOs".
 */
static BIO *
getbio (BIO_METHOD * type, const char *desc)
{
  BIO *ret;
  ret = BIO_new (type);
  if (!ret)
    msg (M_SSLERR, "Error creating %s BIO", desc);
  return ret;
}

/*
 * Write to an OpenSSL BIO in non-blocking mode.
 */
static int
bio_write (BIO * bio, struct buffer *buf, const char *desc)
{
  int i;
  int ret = 0;
  ASSERT (buf->len >= 0);
  if (buf->len)
    {
      /*
       * Free the L_TLS lock prior to calling BIO routines
       * so that foreground thread can still call
       * tls_pre_decrypt or tls_pre_encrypt,
       * allowing tunnel packet forwarding to continue.
       */
      mutex_unlock (L_TLS);
      i = BIO_write (bio, BPTR (buf), BLEN (buf));
      mutex_lock (L_TLS);
      if (i < 0)
	{
	  if (BIO_should_retry (bio))
	    {
	      ;
	    }
	  else
	    {
	      msg (D_TLS_ERRORS | M_SSL, "TLS ERROR: BIO write %s error",
		   desc);
	      ret = -1;
	    }
	}
      else if (i != buf->len)
	{
	  msg (D_TLS_ERRORS | M_SSL,
	       "TLS ERROR: BIO write %s incomplete %d/%d", desc, i, buf->len);
	  ret = -1;
	}
      else
	{			/* successful write */
	  msg (D_HANDSHAKE_VERBOSE, "BIO write %s %d bytes", desc, i);
	  memset (BPTR (buf), 0, BLEN (buf)); /* erase data just written */
	  buf->len = 0;
	  ret = 1;
	}
    }
  return ret;
}

/*
 * Read from an OpenSSL BIO in non-blocking mode.
 */
static int
bio_read (BIO * bio, struct buffer *buf, int maxlen, const char *desc)
{
  int i;
  int ret = 0;
  ASSERT (buf->len >= 0);
  if (buf->len)
    {
      ;
    }
  else
    {
      int len = buf_forward_capacity (buf);
      if (maxlen < len)
	len = maxlen;
      /*
       * Free the L_TLS lock prior to calling BIO routines
       * so that foreground thread can still call
       * tls_pre_decrypt or tls_pre_encrypt,
       * allowing tunnel packet forwarding to continue.
       *
       * BIO_read brackets most of the serious RSA
       * key negotiation number crunching.
       */
      mutex_unlock (L_TLS);
      i = BIO_read (bio, BPTR (buf), len);
      mutex_lock (L_TLS);
      if (i < 0)
	{
	  if (BIO_should_retry (bio))
	    {
	      ;
	    }
	  else
	    {
	      msg (D_TLS_ERRORS | M_SSL, "TLS_ERROR: BIO read %s error",
		   desc);
	      buf->len = 0;
	      ret = -1;
	    }
	}
      else if (!i)
	{
	  buf->len = 0;
	}
      else
	{			/* successful read */
	  msg (D_HANDSHAKE_VERBOSE, "BIO read %s %d bytes", desc, i);
	  buf->len = i;
	  ret = 1;
	}
    }
  return ret;
}

/*
 * Inline functions for reading from and writing
 * to BIOs.
 */

static inline int
key_state_write_plaintext (struct key_state *ks, struct buffer *buf)
{
  return bio_write (ks->ssl_bio, buf, "tls_write_plaintext");
}

static inline int
key_state_write_ciphertext (struct key_state *ks, struct buffer *buf)
{
  return bio_write (ks->ct_in, buf, "tls_write_ciphertext");
}

static inline int
key_state_read_plaintext (struct key_state *ks, struct buffer *buf,
			  int maxlen)
{
  return bio_read (ks->ssl_bio, buf, maxlen, "tls_read_plaintext");
}

static inline int
key_state_read_ciphertext (struct key_state *ks, struct buffer *buf,
			   int maxlen)
{
  return bio_read (ks->ct_out, buf, maxlen, "tls_read_ciphertext");
}

/*
 * Initialize a key_state.  Each key_state corresponds to
 * a specific SSL/TLS session.
 */
static void
key_state_init (struct tls_session *session, struct key_state *ks,
		time_t current)
{
  /*
   * Build TLS object that reads/writes ciphertext
   * to/from memory BIOs.
   */
  CLEAR (*ks);

  ks->ssl = SSL_new (session->opt->ssl_ctx);
  if (!ks->ssl)
    msg (M_SSLERR, "SSL_new failed");

  ks->ssl_bio = getbio (BIO_f_ssl (), "ssl_bio");
  ks->ct_in = getbio (BIO_s_mem (), "ct_in");
  ks->ct_out = getbio (BIO_s_mem (), "ct_out");

  if (session->opt->server)
    SSL_set_accept_state (ks->ssl);
  else
    SSL_set_connect_state (ks->ssl);

  SSL_set_bio (ks->ssl, ks->ct_in, ks->ct_out);
  BIO_set_ssl (ks->ssl_bio, ks->ssl, BIO_NOCLOSE);

  /* Set control-channel initiation mode */
  ks->initial_opcode = session->initial_opcode;
  session->initial_opcode = P_CONTROL_SOFT_RESET_V1;
  ks->state = S_INITIAL;
  ks->key_id = session->key_id;

  /*
   * key_id increments to KEY_ID_MASK then recycles back to 1.
   * This way you know that if key_id is 0, it is the first key.
   */
  ++session->key_id;
  session->key_id &= P_KEY_ID_MASK;
  if (!session->key_id)
    session->key_id = 1;

  /* allocate buffers */
  ks->plaintext_read_buf = alloc_buf (BUF_SIZE (&session->opt->frame));
  ks->plaintext_write_buf = alloc_buf (BUF_SIZE (&session->opt->frame));
  ks->ack_write_buf = alloc_buf (BUF_SIZE (&session->opt->frame));
  reliable_init (&ks->send_reliable, BUF_SIZE (&session->opt->frame),
		 EXTRA_FRAME (&session->opt->frame));
  reliable_init (&ks->rec_reliable, BUF_SIZE (&session->opt->frame),
		 EXTRA_FRAME (&session->opt->frame));
  reliable_set_timeout (&ks->send_reliable, session->opt->packet_timeout);
}

static void
key_state_free (struct key_state *ks, bool clear)
{
  ks->state = S_UNDEF;

  if (ks->ssl) {
    BIO_free_all(ks->ssl_bio);
    SSL_free (ks->ssl);
  }

  free_key_ctx_bi (&ks->key);
  free_buf (&ks->plaintext_read_buf);
  free_buf (&ks->plaintext_write_buf);
  free_buf (&ks->ack_write_buf);
  reliable_free (&ks->send_reliable);
  reliable_free (&ks->rec_reliable);

  if (clear)
    CLEAR (*ks);
}

/*
 * Must be called if we move a tls_session in memory.
 */
static inline void tls_session_set_self_referential_pointers (struct tls_session* session) {
  session->tls_auth.packet_id = &session->tls_auth_pid;
}

/*
 * Initialize a TLS session.  A TLS session normally has 2 key_state objects,
 * one for the current key, and one for the retiring key.
 */
static void
tls_session_init (struct tls_multi *multi, struct tls_session *session)
{
  msg (D_TLS_DEBUG, "tls_session_init: entry");

  CLEAR (*session);

  session->opt = &multi->opt;
  
  while (!session_id_defined(&session->session_id))
    session_id_random (&session->session_id);

  session->initial_opcode = session->opt->server ?
    P_CONTROL_HARD_RESET_SERVER_V1 : P_CONTROL_HARD_RESET_CLIENT_V1;

  /* Initialize control channel authentication parameters */
  session->tls_auth = session->opt->tls_auth;

  tls_session_set_self_referential_pointers(session);

  key_state_init (session, &session->key[KS_PRIMARY], time (NULL));

  msg (D_TLS_DEBUG, "tls_session_init: new session object, sid=%s",
       session_id_print (&session->session_id));
}

static void
tls_session_free (struct tls_session *session, bool clear)
{
  int i;

  for (i = 0; i < KS_SIZE; ++i)
    key_state_free (&session->key[i], false);

  if (clear)
    CLEAR (*session);
}

static void
move_session(struct tls_multi* multi, int dest, int src, bool reinit_src)
{
  msg (D_TLS_DEBUG_LOW, "move_session: dest=%s src=%s reinit_src=%d",
       session_index_name(dest),
       session_index_name(src),
       reinit_src);
  ASSERT (src != dest);
  ASSERT (src >= 0 && src < TM_SIZE);
  ASSERT (dest >= 0 && dest < TM_SIZE);
  tls_session_free (&multi->session[dest], false);
  multi->session[dest] = multi->session[src];
  tls_session_set_self_referential_pointers (&multi->session[dest]);

  if (reinit_src)
    tls_session_init (multi, &multi->session[src]);
  else
    CLEAR (multi->session[src]);

  msg (D_TLS_DEBUG, "move_session: exit");
}

/*
 * Used to determine in how many seconds we should be
 * called again.
 */
static inline void
compute_earliest_wakeup (time_t* earliest, int seconds_from_now) {
  if (seconds_from_now > 0 && (seconds_from_now < *earliest || !*earliest))
    *earliest = seconds_from_now;
}

/*
 * Return true if "lame duck" or retiring key has expired and can
 * no longer be used.
 */
static inline bool
lame_duck_must_die (const struct tls_session* session, time_t* wakeup, time_t current)
{
  const struct key_state* lame = &session->key[KS_LAME_DUCK];
  if (lame->state >= S_INITIAL)
    {
      ASSERT (lame->must_die); /* a lame duck key must always have an expiration */
      if (current < lame->must_die)
	{
	  compute_earliest_wakeup (wakeup, lame->must_die - current);
	  return false;
	}
      else
	return true;
    }
  else if (lame->state == S_ERROR)
    return true;
  else
    return false;
}

/*
 * A tls_multi object fully encapsulates OpenVPN's TLS state.
 * See ssl.h for more comments.
 */
struct tls_multi *
tls_multi_init (struct tls_options *tls_options,
		struct udp_socket *udp_socket)
{
  struct tls_multi *ret;

  ret = (struct tls_multi *) malloc (sizeof (struct tls_multi));
  ASSERT (ret);
  CLEAR (*ret);

  /* get command line derived options */
  ret->opt = *tls_options;

  /* set up pointer to HMAC object for TLS packet authentication */
  ret->opt.tls_auth.key_ctx_bi = &ret->opt.tls_auth_key;

  /* set up list of keys to be scanned by data channel encrypt and decrypt routines */
  ASSERT (SIZE (ret->key_scan) == 3);
  ret->key_scan[0] = &ret->session[TM_ACTIVE].key[KS_PRIMARY];
  ret->key_scan[1] = &ret->session[TM_ACTIVE].key[KS_LAME_DUCK];
  ret->key_scan[2] = &ret->session[TM_LAME_DUCK].key[KS_LAME_DUCK];

  return ret;
}

/*
 * Finalize our computation of frame sizes.
 */
void
tls_multi_init_finalize(struct tls_multi* multi, const struct frame* frame)
{
  tls_init_control_channel_frame_parameters(frame, &multi->opt.frame);
  
  /* initialize the active and untrusted sessions */
  tls_session_init (multi, &multi->session[TM_ACTIVE]);
  tls_session_init (multi, &multi->session[TM_UNTRUSTED]);
}

void
tls_multi_free (struct tls_multi *multi, bool clear)
{
  int i;

  ASSERT (multi);

  for (i = 0; i < TM_SIZE; ++i)
    tls_session_free (&multi->session[i], false);

  free_key_ctx_bi (&multi->opt.tls_auth_key);

  if (clear)
    CLEAR (*multi);

  free(multi);
}

/*
 * Move a packet authentication HMAC + related fields to or from the front
 * of the buffer so it can be processed by encrypt/decrypt.
 */

/*
 * Dependent on hmac size, opcode size, and session_id size.
 * Will assert if too small.
 */
#define SWAP_BUF_SIZE 256

static bool
swap_hmac (struct buffer *buf, const struct crypto_options *co, bool incoming)
{
  struct key_ctx *ctx;

  ASSERT (co);

  ctx = (incoming ? &co->key_ctx_bi->decrypt : &co->key_ctx_bi->encrypt);
  ASSERT (ctx->hmac);

  {
    /* hmac + packet_id (8 bytes) */
    const int hmac_size = HMAC_size (ctx->hmac) + packet_id_size (true);

    /* opcode + session_id */
    const int osid_size = 1 + SID_SIZE;

    int e1, e2;
    uint8_t *b = BPTR (buf);
    uint8_t buf1[SWAP_BUF_SIZE];
    uint8_t buf2[SWAP_BUF_SIZE];

    if (incoming)
      {
	e1 = osid_size;
	e2 = hmac_size;
      }
    else
      {
	e1 = hmac_size;
	e2 = osid_size;
      }

    ASSERT (e1 <= SWAP_BUF_SIZE && e2 <= SWAP_BUF_SIZE);

    if (buf->len >= e1 + e2)
      {
	memcpy (buf1, b, e1);
	memcpy (buf2, b + e1, e2);
	memcpy (b, buf2, e2);
	memcpy (b + e2, buf1, e1);
	return true;
      }
    else
      return false;
  }
}

#undef SWAP_BUF_SIZE

/*
 * A simple traffic shaper for the control channel, to prevent
 * it from hogging the bandwidth during key exchanges.
 *
 * Return true if okay to send.
 * If not, return false and set *wakeup.
 *
 * Never limit the rate unless we have an active lame duck key
 * which will not be expiring any time soon.
 */
static bool transmit_rate_limiter(struct tls_session* session, time_t* wakeup, time_t current)
{
  const struct key_state *lame = &session->key[KS_LAME_DUCK];
  const struct key_state *pri = &session->key[KS_PRIMARY];

  /* transmit one packet every freq seconds */
  const int freq = 2;

  /* rough estimate of how many bytes still to transmit */
  const int estimated_bytes = 20000;

  /* worst-case estimated finish at this rate */
  time_t finish = current + ((freq * estimated_bytes) / MTU_SIZE (&session->opt->frame));

  if (check_debug_level (D_TLS_DEBUG))
    {
      if (lame->must_die)
	msg (D_TLS_DEBUG, "TLS XMIT FINISH ESTIMATE = lame->must_die      %d seconds",
	     lame->must_die - finish);
      if (pri->must_negotiate)
	msg (D_TLS_DEBUG, "TLS XMIT FINISH ESTIMATE = pri->must_negotiate %d seconds",
	     pri->must_negotiate - finish);
    }

  if (freq && lame->state == S_ACTIVE && finish < lame->must_die && finish < pri->must_negotiate)
    {
      if (current >= session->limit_next)
	{
	  session->limit_next = current + freq;
	  return true;
	}
      else
	{
	  compute_earliest_wakeup (wakeup, session->limit_next - current);
	  return false;
	}
    }
  return true;
}

/*
 * Write a control channel authentication record.
 */
static void
write_control_auth (struct tls_session *session,
		    struct key_state *ks,
		    struct buffer *buf,
		    struct sockaddr_in *to_udp_addr,
		    int opcode,
		    int max_ack,
		    bool prepend_ack,
		    time_t current)
{
  uint8_t *header;
  struct buffer null = clear_buf ();

  ASSERT (ADDR (ks->remote_addr));
  ASSERT (reliable_ack_write
	  (&ks->rec_ack, buf, &ks->session_id_remote, max_ack, prepend_ack));
  ASSERT (session_id_write_prepend (&session->session_id, buf));
  ASSERT (header = buf_prepend (buf, 1));
  *header = ks->key_id | (opcode << P_OPCODE_SHIFT);
  if (session->tls_auth.key_ctx_bi->encrypt.hmac)
    {
      /* no encryption, only write hmac */
      openvpn_encrypt (buf, null, &session->tls_auth, NULL, current);
      ASSERT (swap_hmac (buf, &session->tls_auth, false));
    }
  *to_udp_addr = ks->remote_addr;
}

/*
 * Read a control channel authentication record.
 */
static bool
read_control_auth (struct buffer *buf,
		   struct crypto_options *co,
		   struct sockaddr_in *from,
		   time_t current)
{
  if (co->key_ctx_bi->decrypt.hmac)
    {
      struct buffer null = clear_buf ();

      /* move the hmac record to the front of the packet */
      if (!swap_hmac (buf, co, true))
	{
	  msg (D_TLS_ERRORS,
	       "TLS Error: cannot locate HMAC in incoming packet from %s",
	       print_sockaddr (from));
	  return false;
	}

      /* authenticate only (no decrypt) and remove the hmac record
         from the head of the buffer */
      openvpn_decrypt (buf, null, co, NULL, current);
      if (!buf->len)
	{
	  msg (D_TLS_ERRORS,
	       "TLS Error: incoming packet authentication failed from %s",
	       print_sockaddr (from));
	  return false;
	}

    }

  /* advance buffer pointer past opcode & session_id since our caller
     already read it */
  buf_advance (buf, SID_SIZE + 1);

  return true;
}

/*
 * Macros for key_state_soft_reset & tls_process
 */
#define ks      (&session->key[KS_PRIMARY])	/* primary key */
#define ks_lame (&session->key[KS_LAME_DUCK])	/* retiring key */

/* true if no in/out acknowledgements pending */
#define FULL_SYNC \
  (reliable_empty(&ks->send_reliable) && reliable_ack_empty(&ks->rec_ack))

/*
 * Move the active key to the lame duck key and reinitialize the
 * active key.
 */
static void
key_state_soft_reset (struct tls_session *session, time_t current)
{
  ks->must_die = current + session->opt->transition_window; /* remaining lifetime of old key */
  key_state_free (ks_lame, false);
  *ks_lame = *ks;

  key_state_init (session, ks, current);
  ks->session_id_remote = ks_lame->session_id_remote;
  ks->remote_addr = ks_lame->remote_addr;
}

/*
 * This is the primary routine for processing TLS stuff inside the
 * the main event loop (see openvpn.c).  When this routine exits
 * with non-error status, it will set *wakeup to the number of seconds
 * when it wants to be called again, or 0 if it doesn't care.
 *
 * Return value is true if we have placed a packet in *to_udp which we
 * want to send to our peer.
 */
static bool
tls_process (struct tls_multi *multi,
	     struct tls_session *session,
	     struct buffer *to_udp,
	     struct sockaddr_in *to_udp_addr,
	     struct udp_socket *to_udp_socket,
	     time_t * wakeup, time_t current)
{
  struct buffer *buf;
  bool state_change = false;
  bool generated_output = false;

  /* Make sure we were initialized and that we're not in an error state */
  ASSERT (ks->state != S_UNDEF);
  ASSERT (ks->state != S_ERROR);
  ASSERT (session_id_defined (&session->session_id));

  /* Should we trigger a soft reset? -- new key, keeps old key for a while */
  if (ks->state == S_ACTIVE &&
      ((session->opt->renegotiate_seconds
	&& current >= ks->established + session->opt->renegotiate_seconds)
       || (session->opt->renegotiate_bytes
	   && ks->n_bytes >= session->opt->renegotiate_bytes)
       || (session->opt->renegotiate_packets
	   && ks->n_packets >= session->opt->renegotiate_packets)
       || (packet_id_close_to_wrapping (&ks->packet_id.send))))
    {
      msg (D_TLS_DEBUG_LOW, "tls_process: soft reset sec=%d bytes=%d/%d pkts=%d/%d",
	   (int) ks->established + session->opt->renegotiate_seconds - current,
	   ks->n_bytes, session->opt->renegotiate_bytes,
	   ks->n_packets, session->opt->renegotiate_packets);
      key_state_soft_reset (session, current);
    }

  /* Kill lame duck key transition_window seconds after primary key negotiation */
  if (lame_duck_must_die (session, wakeup, current)) {
	key_state_free (ks_lame, true);
	msg (D_TLS_DEBUG_LOW, "tls_process: killed lame duck key");
  }

  mutex_cycle (L_TLS);

  do
    {
      current = time (NULL);

      msg (D_TLS_DEBUG, "tls_process: chg=%d ks=%s lame=%s",
	   state_change, state_name (ks->state), state_name (ks_lame->state));

      state_change = false;

      /*
       * TLS activity is finished once we get to S_ACTIVE,
       * though we will still process acknowledgements.
       */
      if (ks->state < S_ACTIVE)
	{
	  /* Initial handshake */
	  if (ks->state == S_INITIAL)
	    {
	      buf = reliable_get_buf (&ks->send_reliable);
	      if (buf)
		{
		  ks->must_negotiate = current + session->opt->handshake_window;
	      
		  /* null buffer */
		  reliable_mark_active_outgoing (&ks->send_reliable, buf, ks->initial_opcode);
	      
		  ks->state = S_PRE_START;
		  state_change = true;
		  msg (D_TLS_DEBUG, "Initial Handshake, sid=%s",
		       session_id_print (&session->session_id));
		}
	    }

	  /* Are we timed out on receive? */
	  if (current >= ks->must_negotiate)
	    {
	      msg (D_TLS_ERRORS,
		   "TLS Error: TLS key negotiation failed to occur within %d seconds",
		   session->opt->handshake_window);
	      goto error;
	    }

	  /* Wait for Initial Handshake ACK */
	  if (ks->state == S_PRE_START && FULL_SYNC)
	    {
	      ks->state = S_START;
	      state_change = true;
	      msg (D_TLS_DEBUG, "Transitioned to S_START");
	    }

	  /* Wait for ACK */
	  if (((ks->state == S_GOT_KEY && !session->opt->server) ||
	       (ks->state == S_SENT_KEY && session->opt->server)))
	    {
	      if (FULL_SYNC)
		{
		  ks->established = current;
		  msg (D_TLS_DEBUG, "Transition to S_ACTIVE");
		  if (check_debug_level (D_HANDSHAKE))
		    print_details (ks->ssl, "Control Channel:");
		  state_change = true;
		  ks->state = S_ACTIVE;

		  /* Set outgoing address for data channel packets */
		  udp_socket_set_outgoing_addr (NULL, to_udp_socket, &ks->remote_addr);
		}
	    }

	  /* Reliable buffer to outgoing UDP (send up to CONTROL_SEND_ACK_MAX ACKs
	     for previously received packets) */
	  if (!to_udp->len && reliable_can_send (&ks->send_reliable, current))
	    {
	      if (transmit_rate_limiter(session, wakeup, current))
		{
		  int opcode;
		  struct buffer b;

		  buf = reliable_send (&ks->send_reliable, &opcode, current);
		  ASSERT (buf);
		  b = *buf;

		  write_control_auth (session, ks, &b, to_udp_addr, opcode,
				      CONTROL_SEND_ACK_MAX, true, current);
		  *to_udp = b;
		  generated_output = true;
		  state_change = true;
		  msg (D_TLS_DEBUG, "Reliable -> UDP");
		  break;
		}
	    }

	  /* Send 1 or more ACKs (each received control packet gets one ACK) */
	  if (!to_udp->len && !reliable_ack_empty (&ks->rec_ack))
	    {
	      buf = &ks->ack_write_buf;
	      ASSERT (buf_init (buf, EXTRA_FRAME (&multi->opt.frame)));
	      write_control_auth (session, ks, buf, to_udp_addr, P_ACK_V1,
				  RELIABLE_ACK_SIZE, false, current);
	      *to_udp = *buf;
	      generated_output = true;
	      state_change = true;
	      msg (D_TLS_DEBUG, "Dedicated ACK -> UDP");
	      break;
	    }

	  /* Write incoming ciphertext to TLS object */
	  buf = reliable_get_buf_sequenced (&ks->rec_reliable);
	  if (buf)
	    {
	      int status = 0;
	      if (buf->len)
		{
		  status = key_state_write_ciphertext (ks, buf);
		  if (status == -1)
		    {
		      msg (D_TLS_ERRORS,
			   "TLS Error: Incoming Ciphertext -> TLS object write error");
		      goto error;
		    }
		}
	      else
		{
		  status = 1;
		}
	      if (status == 1)
		{
		  reliable_mark_deleted (&ks->rec_reliable, buf, true);
		  state_change = true;
		  msg (D_TLS_DEBUG, "Incoming Ciphertext -> TLS");
		}
	    }

	  /* Read incoming plaintext from TLS object */
	  buf = &ks->plaintext_read_buf;
	  if (!buf->len)
	    {
	      int status;

	      ASSERT (buf_init (buf, EXTRA_FRAME (&multi->opt.frame)));
	      status = key_state_read_plaintext (ks, buf, MTU_SIZE (&multi->opt.frame));
	      current = time (NULL);
	      if (status == -1)
		{
		  msg (D_TLS_ERRORS, "TLS Error: TLS object -> incoming plaintext read error");
		  goto error;
		}
	      if (status == 1)
		{
		  state_change = true;
		  msg (D_TLS_DEBUG, "TLS -> Incoming Plaintext");
		}
	    }

	  /* Send Key */
	  buf = &ks->plaintext_write_buf;
	  if (!buf->len && ((ks->state == S_START && !session->opt->server) ||
			    (ks->state == S_GOT_KEY && session->opt->server)))
	    {
	      struct key key;
	      ASSERT (buf_init (buf, EXTRA_FRAME (&multi->opt.frame)));
	      generate_key_random (&key, &session->opt->key_type);
	      if (!check_key (&key, &session->opt->key_type))
		{
		  msg (D_TLS_ERRORS, "TLS Error: Bad encrypting key generated");
		  goto error;
		}
	      write_key (&key, &session->opt->key_type, buf);
	      init_key_ctx (&ks->key.encrypt, &key, &session->opt->key_type,
			    DO_ENCRYPT, "Data Channel Encrypt");
	      CLEAR (key);
	      ASSERT (buf_write
		      (buf, session->opt->options,
		       strlen (session->opt->options) + 1));
	      state_change = true;
	      msg (D_TLS_DEBUG, "Send Key");
	      ks->state = S_SENT_KEY;
	    }

	  /* Recieve Key */
	  buf = &ks->plaintext_read_buf;
	  if (buf->len
	      && ((ks->state == S_SENT_KEY && !session->opt->server)
		  || (ks->state == S_START && session->opt->server)))
	    {
	      int status;
	      struct key key;

	      status = read_key (&key, &session->opt->key_type, buf);
	      if (status == -1)
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: Error reading data channel key from plaintext buffer");
		  goto error;
		}

	      if (!check_key (&key, &session->opt->key_type))
		{
		  msg (D_TLS_ERRORS, "TLS Error: Bad decrypting key received from peer");
		  goto error;
		}

	      ASSERT (buf->len > 0);
	      if (strncmp (BPTR (buf), session->opt->options, buf->len))
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: Local ('%s') and Remote ('%s') options are incompatible",
		       session->opt->options, BPTR (buf));
		  status = 0;
		}
	      buf_clear (buf);

	      if (status == 1)
		{
		  init_key_ctx (&ks->key.decrypt, &key, &session->opt->key_type,
				DO_DECRYPT, "Data Channel Decrypt");
		}
	      CLEAR (key);
	      if (status == 0)
		goto error;
	      state_change = true;
	      msg (D_TLS_DEBUG, "Rec Key");
	      ks->state = S_GOT_KEY;
	    }

	  /* Write outgoing plaintext to TLS object */
	  buf = &ks->plaintext_write_buf;
	  if (buf->len)
	    {
	      int status = key_state_write_plaintext (ks, buf);
	      if (status == -1)
		{
		  msg (D_TLS_ERRORS,
		       "TLS ERROR: Outgoing Plaintext -> TLS object write error");
		  goto error;
		}
	      if (status == 1)
		{
		  state_change = true;
		  msg (D_TLS_DEBUG, "Outgoing Plaintext -> TLS");
		}
	    }

	  /* Outgoing Ciphertext to reliable buffer */
	  if (ks->state >= S_START)
	    {
	      buf = reliable_get_buf (&ks->send_reliable);
	      if (buf)
		{
		  int status = key_state_read_ciphertext (ks, buf, MTU_SIZE (&multi->opt.frame));
		  if (status == -1)
		    {
		      msg (D_TLS_ERRORS,
			   "TLS Error: Ciphertext -> reliable UDP transport read error");
		      goto error;
		    }
		  if (status == 1)
		    {
		      reliable_mark_active_outgoing (&ks->send_reliable, buf, P_CONTROL_V1);
		      state_change = true;
		      msg (D_TLS_DEBUG, "Outgoing Ciphertext -> Reliable");
		    }
		}
	    }
	}
      else /* state is ACTIVE */
	{
	  /* Send 1 or more ACKs (each received control packet gets one ACK) */
	  if (!to_udp->len && !reliable_ack_empty (&ks->rec_ack))
	    {
	      buf = &ks->ack_write_buf;
	      ASSERT (buf_init (buf, EXTRA_FRAME (&multi->opt.frame)));
	      write_control_auth (session, ks, buf, to_udp_addr, P_ACK_V1,
				  RELIABLE_ACK_SIZE, false, current);
	      *to_udp = *buf;
	      generated_output = true;
	      state_change = true;
	      msg (D_TLS_DEBUG, "Post-Active Dedicated ACK -> UDP");
	      break;
	    }
	}
      mutex_cycle (L_TLS); 
    }
  while (state_change);

  current = time (NULL);

  /* When should we wake up again? */
  {
    if (ks->state >= S_INITIAL && ks->state < S_ACTIVE)
      {
	compute_earliest_wakeup (wakeup, reliable_send_timeout (&ks->send_reliable, current));
	
	if (ks->must_negotiate)
	  compute_earliest_wakeup (wakeup, ks->must_negotiate - current);
      }

    if (ks->established && session->opt->renegotiate_seconds)
      compute_earliest_wakeup (wakeup, ks->established + session->opt->renegotiate_seconds - current);

    if (*wakeup)
      msg (D_TLS_DEBUG, "tls_process: timeout set to %d", *wakeup);

    return generated_output;
  }

error:
  ks->state = S_ERROR;
  msg (D_TLS_ERRORS, "TLS Error: TLS handshake failed");
  return false;
}

#undef ks
#undef ks_lame

/*
 * Called at the top of the event loop in openvpn.c.
 *
 * Basically decides if we should call tls_process for
 * the active or untrusted sessions.
 */

bool
tls_multi_process (struct tls_multi *multi,
		   struct buffer *to_udp,
		   struct sockaddr_in *to_udp_addr,
		   struct udp_socket *to_udp_socket,
		   time_t * wakeup,
		   time_t current)
{
  int i;
  bool generated_output = false;

  mutex_lock (L_TLS);

  /*
   * Process each session object having state of S_INITIAL or greater,
   * and which has a defined remote IP addr.
   */

  for (i = 0; i < TM_SIZE; ++i)
    {
      struct tls_session *session = &multi->session[i];
      struct key_state *ks = &session->key[KS_PRIMARY];
      struct key_state *ks_lame = &session->key[KS_LAME_DUCK];

      /* set initial remote address */
      if (i == TM_ACTIVE && ks->state == S_INITIAL && ADDR_P (to_udp_socket->actual))
	ks->remote_addr = *to_udp_socket->actual;

      msg (D_TLS_DEBUG,
	   "tls_multi_process: i=%d state=%s, mysid=%s, stored-sid=%s, stored-ip=%s",
	   i,
	   state_name (ks->state),
	   session_id_print (&session->session_id),
	   session_id_print (&ks->session_id_remote),
	   print_sockaddr (&ks->remote_addr));

      if (ks->state >= S_INITIAL && ADDR (ks->remote_addr))
	{
	  current = time (NULL);

	  if (tls_process (multi, session, to_udp, to_udp_addr, to_udp_socket, wakeup, current))
	    generated_output = true;

	  /*
	   * If tls_process hits an error:
	   * (1) If the session has an unexpired lame duck key, preserve it.
	   * (2) Reinitialize the session.
	   */
	  if (ks->state == S_ERROR)
	    {
	      if (i == TM_ACTIVE && ks_lame->state == S_ACTIVE)
		move_session(multi, TM_LAME_DUCK, TM_ACTIVE, true);
	      else
		{
		  tls_session_free (session, false);
		  tls_session_init (multi, session);
		}
	    }
	}
      mutex_cycle (L_TLS);
    }

  current = time (NULL);

  /*
   * If lame duck session expires, kill it.
   */
  if (lame_duck_must_die (&multi->session[TM_LAME_DUCK], wakeup, current)) {
    tls_session_free(&multi->session[TM_LAME_DUCK], true);
    msg (D_TLS_DEBUG_LOW, "tls_multi_process: killed lame duck session");
  }

  /*
   * If untrusted session achieves TLS authentication,
   * move it to active session, usurping any prior session.
   */
  if (DECRYPT_KEY_ENABLED (multi, &multi->session[TM_UNTRUSTED].key[KS_PRIMARY])) {
    move_session(multi, TM_ACTIVE, TM_UNTRUSTED, true);
    msg (D_TLS_DEBUG_LOW, "tls_multi_process: untrusted session promoted to trusted");
  }

  mutex_unlock (L_TLS);

  return generated_output;
}

/*
 * When OpenVPN is built in pthread-mode, thread_func
 * will periodically call tls_multi_process.
 */

#ifdef USE_PTHREAD

/*
 * Main thread <-> TLS thread communication
 * errors are fatal if they are of these types.
 */
static inline bool
local_sock_fatal ()
{
  return errno == ENOTCONN || errno == ECONNREFUSED;
}

/*
 * This routine is the TLS work thread.
 */
static void *
thread_func (void *arg)
{
  const int gc_level = gc_new_level ();
  const struct thread_parms parm = *(struct thread_parms*) arg;
  fd_set reads;
  time_t current;
  bool fatal;

  if (parm.mlock) /* should we disable paging? */
    do_mlockall (true);  

  /* change thread priority if requested */
  set_nice (parm.nice);

  /* event loop */
  current = time (NULL);
  while (true)
    {
      int stat;
      time_t wakeup;
      struct tt_ret ret;
      struct buffer buf;

      /*
       * Call tls_multi_process repeatedly as long
       * as it has data to forward to the UDP port.
       */
      do {
	CLEAR (ret);
	CLEAR (buf);
	wakeup = TLS_MULTI_REFRESH;   /* maximum timeout */
	
	/* do one TLS process pass */
	if (tls_multi_process (parm.multi, &buf, &ret.to_udp_addr,
			       parm.udp_socket, &wakeup, current))
	  {
	    /* make a fresh copy of buf in ret */
	    ret.to_udp = clone_buf(&buf);

	    /* send buffer to foreground where it will be forwarded to remote */
	    stat = write (parm.sd, &ret, sizeof (ret));
	    fatal = local_sock_fatal();
	    check_status (stat, "write to foreground");
	    if (fatal)
	      goto exit;
	  }
      } while (ret.to_udp.len);

      /* do a quick garbage collect */
      gc_collect (gc_level);

      /* wait on select */
      {
	struct timeval tv;
	tv.tv_sec = wakeup;
	tv.tv_usec = 0;
	FD_ZERO (&reads);
	FD_SET (parm.sd, &reads);
	stat = select (parm.sd + 1, &reads, NULL, NULL, &tv);
      }

      /* update current time */
      current = time (NULL);

      /* received a message from foreground */
      check_status (stat, "select");

      /* timeout? */
      if (!stat)
	continue;

      /* process message from foreground */
      if (stat > 0 && FD_ISSET (parm.sd, &reads))
	{
	  struct tt_cmd tc;
	  stat = read (parm.sd, &tc, sizeof (tc));
	  fatal = local_sock_fatal();
	  check_status (stat, "read from foreground");
	  if (stat == sizeof (tc))
	    {
	      if (tc.cmd == TTCMD_PROCESS)
		;
	      else if (tc.cmd == TTCMD_EXIT)
		break;
	      else
		msg (D_TLS_DEBUG, "TLS_THREAD: Unknown TTCMD code: %d", tc.cmd);
	    }
	  else if (fatal)
	    break;
	}
    }
 exit:
  close (parm.sd);
  gc_free_level (gc_level);
  return NULL;
}

/*
 * Send a command to TLS thread.
 */
static int
tls_thread_send_command (int sd, int cmd)
{
  struct tt_cmd tc;
  int stat;
  bool fatal;

  tc.cmd = cmd;
  stat = write (sd, &tc, sizeof (tc));
  fatal = local_sock_fatal();
  check_status (stat, "write command to tls thread");
  if (stat == sizeof (tc))
    return 1;
  else if (fatal)
    return -1;
  else
    return 0;
}

/*
 * Create the TLS thread.
 */
int
tls_thread_create (struct tls_multi *multi,
		   struct udp_socket *udp_socket,
		   int nice, bool mlock)
{
  struct thread_parms *tp = (struct thread_parms *) malloc (sizeof (struct thread_parms));
  int sd[2];

  ASSERT (tp);
  tp->multi = multi;
  tp->udp_socket = udp_socket;
  tp->nice = nice;
  tp->mlock = mlock;

  /*
   * Make a socket for foreground and background threads
   * to communicate.  The background thread will set its
   * end to blocking, while the foreground will set its
   * end to non-blocking.
   */
  if (socketpair (PF_UNIX, SOCK_DGRAM, 0, sd) == -1)
    msg (M_ERR, "socketpair call failed");
  set_nonblock (sd[0]);
  tp->sd = sd[1];
  work_thread_create (thread_func, (void*)tp);
  return sd[0];
}

/*
 * Send a command to TLS thread telling it to cycle
 * through tls_multi_process() as long as there
 * is data to process.
 */
int
tls_thread_process (int sd)
{
  return tls_thread_send_command (sd, TTCMD_PROCESS);
}

/*
 * Close the TLS thread
 */
void
tls_thread_close (int sd)
{
  if (sd)
    {
      struct tt_ret ttr;

      tls_thread_send_command (sd, TTCMD_EXIT);
      work_thread_join ();

      /* free any unprocessed buffers sent from background to foreground */
      while (tls_thread_rec_buf (sd, &ttr, false) == 1)
	{
	  free_buf (&ttr.to_udp);
	}

      close (sd);
    }
}

/*
 * Receive an object from the TLS thread which
 * normally contains a buffer to be sent to
 * the remote peer over the UDP port.
 *
 * Return:
 *  1 if ok
 *  0 if non-fatal error
 *  -1 if fatal error
 */
int
tls_thread_rec_buf (int sd, struct tt_ret* ttr, bool do_check_status)
{
  int stat;
  bool fatal;

  stat = read (sd, ttr, sizeof (*ttr));
  fatal = local_sock_fatal();
  if (do_check_status)
    check_status (stat, "read buffer from tls thread");
  if (stat == sizeof (*ttr))
    return 1;
  else if (fatal)
    return -1;
  else
    return 0;
}

#endif

/*
 * Pre and post-process the encryption & decryption buffers in order
 * to implement a multiplexed TLS channel over the UDP port.
 */

/*
 *
 * When we are in TLS mode, this is the first routine which sees
 * an incoming packet.
 *
 * If it's a data packet, we set opt so that our caller can
 * decrypt it.  We also give our caller the appropriate decryption key.
 *
 * If it's a control packet, we authenticate it and process it,
 * possibly creating a new tls_session if it represents the
 * first packet of a new session.  For control packets, we will
 * also zero the size of *buf so that our caller ignores the
 * packet on our return.
 *
 * Note that openvpn only allows one active session at a time,
 * so a new session (once authenticated) will always usurp
 * an old session.
 *
 * Return true if input was an authenticated control channel
 * packet.
 *
 * If we are running in TLS thread mode, all public routines
 * below this point must be called with the L_TLS lock held.
 */

bool
tls_pre_decrypt (struct tls_multi *multi,
		 struct sockaddr_in *from,
		 struct buffer *buf,
		 struct crypto_options *opt,
		 time_t current)
{
  bool ret = false;

  if (buf->len > 0)
    {
      int i;
      int op;
      int key_id;

      /* get opcode and key ID */
      {
	uint8_t c = *BPTR (buf);
	op = c >> P_OPCODE_SHIFT;
	key_id = c & P_KEY_ID_MASK;
      }

      if (op == P_DATA_V1)
	{			/* data channel packet */
	  for (i = 0; i < KEY_SCAN_SIZE; ++i)
	    {
	      struct key_state *ks = multi->key_scan[i];
	      if (DECRYPT_KEY_ENABLED (multi, ks)
		  && key_id == ks->key_id
		  && ADDR_P(from) == ADDR(ks->remote_addr))
		{
		  opt->key_ctx_bi = &ks->key;
		  opt->packet_id = multi->opt.packet_id ? &ks->packet_id : NULL;
		  opt->packet_id_long_form = multi->opt.packet_id_long_form;
		  ASSERT (buf_advance (buf, 1));
		  ++ks->n_packets;
		  ks->n_bytes += buf->len;
		  msg (D_TLS_DEBUG,
		       "tls_pre_decrypt: data channel, key_id=%d, IP=%s",
		       key_id, print_sockaddr (from));
		  return ret;
		}
	    }
	  msg (D_TLS_ERRORS,
	       "TLS Error: Unknown data channel key ID or IP address received from %s: %d",
	       print_sockaddr (from), key_id);
	}
      else			  /* control channel packet */
	{
	  bool do_burst = false;
	  bool new_link = false;
	  struct session_id sid;  /* remote session ID */

	  /* verify legal opcode */
	  if (op < P_FIRST_OPCODE || op > P_LAST_OPCODE)
	    {
	      msg (D_TLS_ERRORS,
		   "TLS Error: unknown opcode received from %s op=%d",
		   print_sockaddr (from), op);
	      goto done;
	    }

	  /* hard reset ? */
	  if (HARD_RESET(op))
	    {
	      /* verify client -> server or server -> client connection */
	      if ((op == P_CONTROL_HARD_RESET_CLIENT_V1 && !multi->opt.server) ||
		  (op == P_CONTROL_HARD_RESET_SERVER_V1 && multi->opt.server))
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: client->client or server->server connection attempted from %s",
		       print_sockaddr (from));
		  goto done;
		}
	    }

	  /*
	   * Authenticate Packet
	   */
	  msg (D_TLS_DEBUG, "tls_pre_decrypt: control channel, op=%s, IP=%s",
	       packet_opcode_name (op), print_sockaddr (from));

	  /* get remote session-id */
	  {
	    struct buffer tmp = *buf;
	    buf_advance (&tmp, 1);
	    if (!session_id_read (&sid, &tmp) || !session_id_defined (&sid))
	      {
		msg (D_TLS_ERRORS,
		     "TLS Error: session-id not found in packet from %s",
		     print_sockaddr (from));
		goto done;
	      }
	  }

	  /* use session ID to match up packet with appropriate tls_session object */
	  for (i = 0; i < TM_SIZE; ++i)
	    {
	      struct tls_session *session = &multi->session[i];
	      struct key_state *ks = &session->key[KS_PRIMARY];

	      msg (D_TLS_DEBUG,
		   "tls_pre_decrypt: initial packet test, i=%d state=%s, mysid=%s, rec-sid=%s, rec-ip=%s, stored-sid=%s, stored-ip=%s",
		   i,
		   state_name (ks->state),
		   session_id_print (&session->session_id),
		   session_id_print (&sid),
		   print_sockaddr (from),
		   session_id_print (&ks->session_id_remote),
		   print_sockaddr (&ks->remote_addr));

	      if (session_id_equal (&ks->session_id_remote, &sid))
		/* found a match */
		{
		  if (i == TM_LAME_DUCK) {
		    msg (D_TLS_ERRORS,
			 "TLS ERROR: received control packet with stale session-id=%s",
			 session_id_print (&sid));
		    goto done;
		  }
		  msg (D_TLS_DEBUG,
		       "tls_pre_decrypt: found match, session[%d], sid=%s",
		       i, session_id_print (&sid));
		  break;
		}
	    }

	  /*
	   * check if this is the first response from a host to which
	   * we sent an initial packet
	   */

	  if (i == TM_SIZE && HARD_RESET(op))
	    {
	      struct tls_session *session = &multi->session[TM_ACTIVE];
	      struct key_state *ks = &session->key[KS_PRIMARY];

	      if (!session_id_defined (&ks->session_id_remote))
		{
		  msg (D_TLS_DEBUG_LOW,
		       "tls_pre_decrypt: first response to initial packet sid=%s",
		       session_id_print (&sid));
		  do_burst = true;
		  new_link = true;
		  i = TM_ACTIVE;
		}
	    }

	  if (i == TM_SIZE && HARD_RESET(op))
	    {
	      /*
	       * No match with existing sessions,
	       * probably a new session.
	       */
	      struct tls_session *session = &multi->session[TM_UNTRUSTED];

	      if (!read_control_auth (buf, &session->tls_auth, from, current))
		goto done;

	      /*
	       * New session-initiating control packet is authenticated at this point
	       * assuming that the --tls-auth command line option was used.
	       *
	       * Without --tls-auth, we leave authentication entirely up to TLS.
	       */
	      msg (D_TLS_DEBUG_LOW,
		   "tls_pre_decrypt: new session incoming connection from %s",
		   print_sockaddr (from));

	      new_link = true;
	      i = TM_UNTRUSTED;
	    }
	  else
	    {
	      struct tls_session *session = &multi->session[i];
	      struct key_state *ks = &session->key[KS_PRIMARY];

	      /*
	       * Packet must belong to an existing session.
	       */
	      if (i != TM_ACTIVE && i != TM_UNTRUSTED)
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: Unroutable control packet received from %s (si=%d op=%s)",
		       print_sockaddr (from),
		       i,
		       packet_opcode_name (op));
		  goto done;
		}

	      /*
	       * Verify remote IP address
	       */
	      if (!new_link && ADDR(ks->remote_addr) != ADDR_P(from))
		{
		  msg(D_TLS_ERRORS, "TLS Error: Received control packet from unexpected IP addr: %s",
		      print_sockaddr (from));
		  goto done;
		}

	      /*
	       * Remote is requesting a key renegotiation
	       */
	      if (op == P_CONTROL_SOFT_RESET_V1
		  && DECRYPT_KEY_ENABLED (multi, ks))
		{
		  if (!read_control_auth (buf, &session->tls_auth, from, current))
		    goto done;

		  key_state_soft_reset (session, current);

		  msg (D_TLS_DEBUG,
		       "tls_pre_decrypt: received P_CONTROL_SOFT_RESET_V1 s=%d sid=%s",
		       i, session_id_print (&sid));
		}
	      else
		{
		  /*
		   * Remote responding to our key renegotiation request?
		   */
		  if (op == P_CONTROL_SOFT_RESET_V1)
		    do_burst = true;

		  if (!read_control_auth (buf, &session->tls_auth, from, current))
		    goto done;
		  msg (D_TLS_DEBUG,
		       "tls_pre_decrypt: received control channel packet s#=%d sid=%s",
		       i, session_id_print (&sid));
		}
	    }
	  
	  /*
	   * We have an authenticated packet (if --tls-auth was set).
           * Now pass to our reliability level which deals with
	   * packet acknowledgements, retransmits, sequencing, etc.
	   */
	  {
	    struct tls_session *session = &multi->session[i];
	    struct key_state *ks = &session->key[KS_PRIMARY];

	    /* Make sure we were initialized and that we're not in an error state */
	    ASSERT (ks->state != S_UNDEF);
	    ASSERT (ks->state != S_ERROR);
	    ASSERT (session_id_defined (&session->session_id));

	    /* Let our caller know we processed a control channel packet */
	    ret = true;

	    /*
	     * Set our remote address and remote session_id
	     */
	    if (new_link)
	      {
		ks->session_id_remote = sid;
		ks->remote_addr = *from;
	      }
	    else if (ADDR(ks->remote_addr) != ADDR_P(from))
	      {
		msg (D_TLS_ERRORS,
		     "TLS Error: Existing session control channel packet from unknown IP address: %s",
		     print_sockaddr (from));
		goto done;
	      }

	    /*
	     * Should we do a retransmit of all unacknowledged packets in
	     * the send buffer?  This improves the start-up efficiency of the
	     * initial key negotiation after the 2nd peer comes online.
	     */
	    if (do_burst && !session->burst)
	      {
		reliable_schedule_now (&ks->send_reliable, current);
		session->burst = true;
	      }

	    /* Check key_id */
	    if (ks->key_id != key_id)
	      {
		msg (D_TLS_ERRORS,
		     "TLS ERROR: local/remote key IDs out of sync (%d/%d) ID: %s",
		     ks->key_id, key_id, print_key_id (multi));
		goto done;
	      }
	      
	    /*
	     * Process incoming ACKs for packets we can now
	     * delete from reliable send buffer
	     */
	    {
	      /* buffers all packet IDs to delete from send_reliable */
	      struct reliable_ack send_ack;

	      send_ack.len = 0;
	      if (!reliable_ack_read
		  (&send_ack, buf, &session->session_id))
		{
		  msg (D_TLS_ERRORS,
		       "TLS Error: reading acknowledgement record from packet");
		  goto done;
		}
	      reliable_send_purge (&ks->send_reliable, &send_ack);
	    }

	    /* Process outgoing acknowledgment for packet just received */
	    if (op != P_ACK_V1 && reliable_can_get (&ks->rec_reliable))
	      {
		packet_id_type id;

		/* Save incoming ciphertext packet to reliable buffer */
		if (reliable_ack_read_packet_id (&ks->rec_ack, buf, &id))
		  {
		    struct buffer *in = reliable_get_buf (&ks->rec_reliable);
		    ASSERT (in);
		    ASSERT (buf_copy (in, buf));
		    reliable_mark_active_incoming (&ks->rec_reliable, in, id, op);
		  }
	      }
	  }
	}
    }
 done:
  buf->len = 0;
  opt->key_ctx_bi = NULL;
  opt->packet_id = NULL;
  opt->packet_id_long_form = false;
  return ret;
}

/* Choose the key with which to encrypt a data packet */
void
tls_pre_encrypt (struct tls_multi *multi,
		 struct buffer *buf, struct crypto_options *opt)
{
  multi->save_ks = NULL;
  if (buf->len > 0)
    {
      int i;
      for (i = 0; i < KEY_SCAN_SIZE; ++i)
	{
	  struct key_state *ks = multi->key_scan[i];
	  if (ks->state == S_ACTIVE)
	    {
	      opt->key_ctx_bi = &ks->key;
	      opt->packet_id = multi->opt.packet_id ? &ks->packet_id : NULL;
	      opt->packet_id_long_form = multi->opt.packet_id_long_form;
	      multi->save_ks = ks;
	      msg (D_TLS_DEBUG, "tls_pre_encrypt: key_id=%d", ks->key_id);
	      return;
	    }
	}
      msg (D_TLS_NO_SEND_KEY, "TLS Error: no data channel send key available: %s",
	   print_key_id (multi));
    }

  buf->len = 0;
  opt->key_ctx_bi = NULL;
  opt->packet_id = NULL;
  opt->packet_id_long_form = false;
}

/* Prepend the appropriate opcode to encrypted buffer prior to UDP send */
void
tls_post_encrypt (struct tls_multi *multi, struct buffer *buf)
{
  struct key_state *ks;
  uint8_t *op;

  ks = multi->save_ks;
  multi->save_ks = NULL;
  if (buf->len > 0)
    {
      ASSERT (ks);
      ASSERT (op = buf_prepend (buf, 1));
      *op = (P_DATA_V1 << P_OPCODE_SHIFT) | ks->key_id;
      ++ks->n_packets;
      ks->n_bytes += buf->len;
    }
}

/*
 * Dump a human-readable rendition of an openvpn packet
 * into a garbage collectable string which is returned.
 */
const char *
protocol_dump (struct buffer *buffer, unsigned int flags)
{
  struct buffer out = alloc_buf_gc (256);
  struct buffer buf = *buffer;

  uint8_t c;
  int op;
  int key_id;

  int tls_auth_hmac_size = (flags & PD_TLS_AUTH_HMAC_SIZE_MASK);

  if (buf.len <= 0)
    {
      buf_printf (&out, "DATA UNDEF len=%d", buf.len);
      goto done;
    }

  if (!(flags & PD_TLS))
    goto print_data;

  /*
   * Initial byte (opcode)
   */
  if (!buf_read (&buf, &c, sizeof (c)))
    goto done;
  op = (c >> P_OPCODE_SHIFT);
  key_id = c & P_KEY_ID_MASK;
  buf_printf (&out, "%s kid=%d", packet_opcode_name (op), key_id);

  if (op == P_DATA_V1)
    goto print_data;

  /*
   * Session ID
   */
  {
    struct session_id sid;

    if (!session_id_read (&sid, &buf))
      goto done;
    buf_printf (&out, " sid=%s", session_id_print (&sid));
  }

  /*
   * tls-auth hmac + packet_id
   */
  if (tls_auth_hmac_size)
    {
      struct packet_id_net pin;
      uint8_t tls_auth_hmac[MAX_HMAC_KEY_LENGTH];

      ASSERT (tls_auth_hmac_size <= MAX_HMAC_KEY_LENGTH);

      if (!buf_read (&buf, tls_auth_hmac, tls_auth_hmac_size))
	goto done;
      buf_printf (&out, " tls_hmac=%s", format_hex (tls_auth_hmac, tls_auth_hmac_size, 0));

      if (!packet_id_read (&pin, &buf, true))
	goto done;
      buf_printf(&out, " pid=%s", packet_id_net_print (&pin));
    }

  /*
   * ACK list
   */
  buf_printf (&out, " %s", reliable_ack_print(&buf));

  if (op == P_ACK_V1)
    goto done;

  /*
   * Packet ID
   */
  {
    packet_id_type l;
    if (!buf_read (&buf, &l, sizeof (l)))
      goto done;
    l = ntohpid (l);
    buf_printf (&out, " pid=" packet_id_format, l);
  }

print_data:
  if (flags & PD_SHOW_DATA)
    buf_printf (&out, " DATA %s", format_hex (BPTR (&buf), BLEN (&buf), 80));
  else
    buf_printf (&out, " DATA len=%d", buf.len);

done:
  return out.data;
}

#endif /* USE_CRYPTO && USE_SSL*/
