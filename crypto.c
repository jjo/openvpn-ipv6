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

#ifdef USE_CRYPTO

#include "syshead.h"

#include "crypto.h"
#include "error.h"

#include "memdbg.h"

#if MAX_CIPHER_KEY_LENGTH < EVP_MAX_KEY_LENGTH
#warning Some OpenSSL EVP ciphers now support key lengths greater than MAX_CIPHER_KEY_LENGTH -- consider increasing MAX_CIPHER_KEY_LENGTH
#endif

#if MAX_HMAC_KEY_LENGTH < EVP_MAX_MD_SIZE
#warning Some OpenSSL HMAC message digests now support key lengths greater than MAX_HMAC_KEY_LENGTH -- consider increasing MAX_HMAC_KEY_LENGTH
#endif

/*
 * Encryption and Compression Routines.
 *
 * On entry, buf contains the input data and length.
 * On exit, it should be set to the output data and length.
 *
 * If buf->len is <= 0 we should return
 * If buf->len is set to 0 on exit it tells the caller to ignore the packet.
 *
 * work is a workspace buffer we are given of size BUF_SIZE.
 * work may be used to return output data, or the input buffer
 * may be modified and returned as output.  If output data is
 * returned in work, the data should start after EXTRA_FRAME bytes
 * of padding to leave room for downstream routines to prepend.
 *
 * Up to a total of EXTRA_FRAME bytes may be prepended to the input buf
 * by all routines (encryption, decryption, compression, and decompression).
 *
 * Note that the buf_prepend return will assert if we try to
 * make a header bigger than EXTRA_FRAME.  This should not
 * happen unless the frame parameters are wrong.
 *
 * If opt->iv is not NULL it will be used and the residual
 * IV will be returned.
 *
 */

#define CRYPT_ERROR(format) \
  do { msg (D_CRYPT_ERRORS, "%s: " format, error_prefix); goto error_exit; } while (false)

#define CRYPT_ERROR_ARGS(format, args...) \
  do { msg (D_CRYPT_ERRORS, "%s: " format, error_prefix, args); goto error_exit; } while (false)

void
openvpn_encrypt (struct buffer *buf, struct buffer work,
		 const struct crypto_options *opt,
		 const struct frame* frame,
		 const time_t current)
{
  if (buf->len > 0 && opt->key_ctx_bi)
    {
      struct key_ctx *ctx = &opt->key_ctx_bi->encrypt;

      /* Do Encrypt from buf -> work */
      if (ctx->cipher)
	{
	  unsigned char *iv = opt->iv;
	  const int iv_size = EVP_CIPHER_CTX_iv_length (ctx->cipher);
	  const unsigned int mode = EVP_CIPHER_CTX_mode (ctx->cipher);  
	  int outlen;

	  /* Put packet ID in plaintext buffer or IV, depending on cipher mode */
	  if (mode == EVP_CIPH_CBC_MODE)
	    {
	      if (opt->packet_id)
		{
		  struct packet_id_net pin;
		  packet_id_alloc_outgoing (&opt->packet_id->send, &pin, opt->packet_id_long_form);
		  ASSERT (packet_id_write (&pin, buf, opt->packet_id_long_form, true));
		}
	    }
	  else if (mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE)
	    {
	      struct packet_id_net pin;
	      struct buffer b;

	      ASSERT (iv);             /* IV and packet-ID required */
	      ASSERT (opt->packet_id); /*  for this mode. */

	      packet_id_alloc_outgoing (&opt->packet_id->send, &pin, true);
	      memset (iv, 0, iv_size);
	      buf_set_write (&b, iv, iv_size);
	      ASSERT (packet_id_write (&pin, &b, true, false));
	    }
	  else /* We only support CBC, CFB, or OFB modes right now */
	    {
	      ASSERT (0);
	    }

	  /* initialize work buffer with EXTRA_FRAME bytes of prepend capacity */
	  ASSERT (buf_init (&work, EXTRA_FRAME (frame)));

	  /* show the IV's initial state */
	  if (iv)
	    msg (D_PACKET_CONTENT, "ENCRYPT IV: %s", format_hex (iv, iv_size, 0));

	  msg (D_PACKET_CONTENT, "ENCRYPT FROM: %s",
	       format_hex (BPTR (buf), BLEN (buf), 80));

	  /* cipher_ctx was already initialized with key & keylen */
	  ASSERT (EVP_CipherInit (ctx->cipher, NULL, NULL, iv, DO_ENCRYPT));

	  /* Buffer overflow check (should never happen) */
	  ASSERT (buf_safe (&work, buf->len + EVP_CIPHER_CTX_block_size (ctx->cipher)));

	  /* Encrypt packet ID, payload */
	  ASSERT (EVP_CipherUpdate (ctx->cipher, BPTR (&work), &outlen, BPTR (buf), BLEN (buf)));
	  work.len += outlen;

	  /* Flush the encryption buffer */
	  ASSERT (EVP_CipherFinal (ctx->cipher, BPTR (&work) + outlen, &outlen));
	  work.len += outlen;

	  /* prepend the IV to the ciphertext */
	  if (iv)
	    {
	      unsigned char *output = buf_prepend (&work, iv_size);
	      ASSERT (output);
	      memcpy (output, iv, iv_size);

	      /* save the residual IV */
	      memcpy (iv, ctx->cipher->iv, iv_size);
	    }

	  msg (D_PACKET_CONTENT, "ENCRYPT TO: %s",
	       format_hex (BPTR (&work), BLEN (&work), 80));

	}
      else				/* No Encryption */
	{
	  if (opt->packet_id)
	    {
	      struct packet_id_net pin;
	      packet_id_alloc_outgoing (&opt->packet_id->send, &pin, opt->packet_id_long_form);
	      ASSERT (packet_id_write (&pin, buf, opt->packet_id_long_form, true));
	    }
	  work = *buf;
	}

      /* HMAC the ciphertext (or plaintext if !cipher) */
      if (ctx->hmac)
	{
	  int hmac_len;
	  unsigned char *output;

	  HMAC_Init (ctx->hmac, NULL, 0, NULL);
	  HMAC_Update (ctx->hmac, BPTR (&work), BLEN (&work));
	  output = buf_prepend (&work, HMAC_size (ctx->hmac));
	  ASSERT (output);
	  HMAC_Final (ctx->hmac, output, &hmac_len);
	  ASSERT (hmac_len == HMAC_size (ctx->hmac));
	}

      *buf = work;
    }
  return;
}

/*
 * If opt->iv is not NULL, we will read an IV from the packet.
 * opt->iv is not modified.
 */
void
openvpn_decrypt (struct buffer *buf, struct buffer work,
		 const struct crypto_options *opt,
		 const struct frame* frame,
		 const time_t current)
{
  static const char error_prefix[] = "Authenticate/Decrypt packet error";

  if (buf->len > 0 && opt->key_ctx_bi)
    {
      struct key_ctx *ctx = &opt->key_ctx_bi->decrypt;
      struct packet_id_net pin;
      bool have_pin = false;

      /* Verify the HMAC */
      if (ctx->hmac)
	{
	  int hmac_len;
	  unsigned char local_hmac[MAX_HMAC_KEY_LENGTH]; /* HMAC of ciphertext computed locally */
	  int in_hmac_len;

	  HMAC_Init (ctx->hmac, NULL, 0, NULL);

	  /* Assume the length of the input HMAC */
	  hmac_len = HMAC_size (ctx->hmac);

	  /* Authentication fails if insufficient data in packet for HMAC */
	  if (buf->len < hmac_len)
	    CRYPT_ERROR ("missing authentication info");

	  HMAC_Update (ctx->hmac, BPTR (buf) + hmac_len,
		       BLEN (buf) - hmac_len);
	  HMAC_Final (ctx->hmac, local_hmac, &in_hmac_len);
	  ASSERT (hmac_len == in_hmac_len);

	  /* Compare locally computed HMAC with packet HMAC */
	  if (memcmp (local_hmac, BPTR (buf), hmac_len))
	    CRYPT_ERROR ("packet HMAC authentication failed");

	  ASSERT (buf_advance (buf, hmac_len));
	}

      /* Decrypt packet ID + payload */

      if (ctx->cipher)
	{
	  const unsigned int mode = EVP_CIPHER_CTX_mode (ctx->cipher);
	  const int iv_size = EVP_CIPHER_CTX_iv_length (ctx->cipher);
	  unsigned char iv[EVP_MAX_IV_LENGTH];
	  int outlen;

	  /* initialize work buffer with EXTRA_FRAME bytes of prepend capacity */
	  ASSERT (buf_init (&work, EXTRA_FRAME (frame)));

	  /* use IV if user requested it */
	  CLEAR (iv);
	  if (opt->iv)
	    {
	      if (buf->len < iv_size)
		CRYPT_ERROR ("missing IV info");
	      memcpy (iv, BPTR (buf), iv_size);
	      ASSERT (buf_advance (buf, iv_size));
	    }

	  /* show the IV's initial state */
	  if (iv)
	    msg (D_PACKET_CONTENT, "DECRYPT IV: %s", format_hex (iv, iv_size, 0));

	  if (buf->len < 1)
	    CRYPT_ERROR ("missing payload");

	  /* ctx->cipher was already initialized with key & keylen */
	  if (!EVP_CipherInit (ctx->cipher, NULL, NULL, iv, DO_DECRYPT))
	    CRYPT_ERROR ("cipher init failed");

	  /* Buffer overflow check (should never happen) */
	  if (!buf_safe (&work, buf->len))
	    CRYPT_ERROR ("buffer overflow");

	  /* Decrypt packet ID, payload */
	  if (!EVP_CipherUpdate (ctx->cipher, BPTR (&work), &outlen, BPTR (buf), BLEN (buf)))
	    CRYPT_ERROR ("cipher update failed");
	  work.len += outlen;

	  /* Flush the decryption buffer */
	  if (!EVP_CipherFinal (ctx->cipher, BPTR (&work) + outlen, &outlen))
	    CRYPT_ERROR ("cipher final failed");
	  work.len += outlen;

	  msg (D_PACKET_CONTENT, "DECRYPT TO: %s",
	       format_hex (BPTR (&work), BLEN (&work), 80));

	  /* Get packet ID from plaintext buffer or IV, depending on cipher mode */
	  {
	    if (mode == EVP_CIPH_CBC_MODE)
	      {
		if (opt->packet_id)
		  {
		    if (!packet_id_read (&pin, &work, opt->packet_id_long_form))
		      CRYPT_ERROR ("error reading CBC packet-id");
		    have_pin = true;
		  }
	      }
	    else if (mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE)
	      {
		struct buffer b;

		ASSERT (iv);             /* IV and packet-ID required */
		ASSERT (opt->packet_id); /*  for this mode. */

		buf_set_read (&b, iv, iv_size);
		if (!packet_id_read (&pin, &b, true))
		  CRYPT_ERROR ("error reading CFB/OFB packet-id");
		have_pin = true;
	      }
	    else /* We only support CBC, CFB, or OFB modes right now */
	      {
		ASSERT (0);
	      }
	  }
	}
      else
	{
	  work = *buf;
	  if (opt->packet_id)
	    {
	      if (!packet_id_read (&pin, &work, opt->packet_id_long_form))
		CRYPT_ERROR ("error reading packet-id");
	      have_pin = true;
	    }
	}
      
      if (have_pin)
	{
	  if (packet_id_test (&opt->packet_id->rec, &pin))
	    packet_id_add (&opt->packet_id->rec, &pin);
	  else
	    CRYPT_ERROR_ARGS ("bad packet ID (may be a replay): %s", packet_id_net_print (&pin));
	}
      *buf = work;
    }
  return;

 error_exit:
  buf->len = 0;
  return;
}

/*
 * How many bytes will we add to frame buffer for a given
 * set of crypto options?
 */
void
crypto_adjust_frame_parameters(struct frame *frame,
			       const struct key_type* kt,
			       bool cipher_defined,
			       bool iv,
			       bool packet_id,
			       bool packet_id_long_form)
{
  frame->extra_frame +=
    (packet_id ? packet_id_size (packet_id_long_form) : 0) +
    ((cipher_defined && iv) ? EVP_CIPHER_iv_length (kt->cipher) : 0) +
    (cipher_defined ? EVP_CIPHER_block_size(kt->cipher) : 0) + /* worst case padding expansion */
    kt->hmac_length;
}

static const EVP_CIPHER *
get_cipher (const char *ciphername)
{
  const EVP_CIPHER *cipher = NULL;
  ASSERT (ciphername);
  cipher = EVP_get_cipherbyname (ciphername);
  if (!cipher)
    msg (M_SSLERR, "Cipher algorithm '%s' not found", ciphername);
  return cipher;
}

static const EVP_MD *
get_md (const char *digest)
{
  const EVP_MD *md = NULL;
  ASSERT (digest);
  md = EVP_get_digestbyname (digest);
  if (!md)
    msg (M_SSLERR, "Message digest algorithm '%s' not found", digest);
  return md;
}

static void
init_cipher (EVP_CIPHER_CTX * ctx, const EVP_CIPHER * cipher,
	     struct key *key, const struct key_type *kt, int enc,
	     const char *prefix)
{
  EVP_CIPHER_CTX_init (ctx);
  if (!EVP_CipherInit (ctx, cipher, NULL, NULL, enc))
    msg (M_SSLERR, "EVP cipher init #1");
  if (!EVP_CIPHER_CTX_set_key_length (ctx, kt->cipher_length))
    msg (M_SSLERR, "EVP set key size");
  if (!EVP_CipherInit (ctx, NULL, key->cipher, NULL, enc))
    msg (M_SSLERR, "EVP cipher init #2");

  msg (D_HANDSHAKE, "%s: Cipher '%s' initialized with %d bit key",
       prefix,
       OBJ_nid2sn (EVP_CIPHER_CTX_nid (ctx)),
       EVP_CIPHER_CTX_key_length (ctx) * 8);

  /* make sure we used a big enough key */
  ASSERT (EVP_CIPHER_CTX_key_length (ctx) <= kt->cipher_length);

  msg (D_SHOW_KEYS, "%s: CIPHER KEY: %s", prefix,
       format_hex (key->cipher, kt->cipher_length, 0));
  msg (D_CRYPTO_DEBUG, "%s: CIPHER block_size=%d iv_size=%d",
       prefix,
       EVP_CIPHER_CTX_block_size (ctx),
       EVP_CIPHER_CTX_iv_length (ctx));
}

static void
init_hmac (HMAC_CTX * ctx, const EVP_MD * digest,
	   struct key *key, const struct key_type *kt, const char *prefix)
{
  HMAC_Init (ctx, key->hmac, kt->hmac_length, digest);
  msg (D_HANDSHAKE,
       "%s: Using %d bit message digest '%s' for HMAC authentication",
       prefix, HMAC_size (ctx) * 8, OBJ_nid2sn (EVP_MD_type (digest)));

  /* make sure we used a big enough key */
  ASSERT (HMAC_size (ctx) <= kt->hmac_length);

  msg (D_SHOW_KEYS, "%s: HMAC KEY: %s", prefix,
       format_hex (key->hmac, kt->hmac_length, 0));
  msg (D_CRYPTO_DEBUG, "%s: HMAC size=%d block_size=%d",
       prefix,
       EVP_MD_size (digest),
       EVP_MD_block_size (digest));
}

/* build a key_type */
void
init_key_type (struct key_type *kt, const char *ciphername,
	       bool ciphername_defined, const char *authname,
	       bool authname_defined, int keysize)
{
  CLEAR (*kt);
  if (ciphername && ciphername_defined)
    {
      kt->cipher = get_cipher (ciphername);
      kt->cipher_length = EVP_CIPHER_key_length (kt->cipher);
      if (keysize > 0 && keysize <= MAX_CIPHER_KEY_LENGTH)
	kt->cipher_length = keysize;

      /* check legal cipher mode */
      {
	const unsigned int mode = EVP_CIPHER_mode (kt->cipher);
	if (!(mode == EVP_CIPH_CBC_MODE || mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE))
	  msg (M_FATAL, "Cipher %s uses a mode not supported by OpenVPN.  Only CBC, CFB, or OFB modes are supported.", ciphername);
      }
    }
  else
    {
      msg (M_WARN,
	   "******* WARNING *******: null cipher specified, no encryption will be used");
    }
  if (authname && authname_defined)
    {
      kt->digest = get_md (authname);
      kt->hmac_length = EVP_MD_size (kt->digest);
    }
  else
    {
      msg (M_WARN,
	   "******* WARNING *******: null MAC specified, no authentication will be used");
    }
}

/* given a key and key_type, build a key_ctx */
void
init_key_ctx (struct key_ctx *ctx, struct key *key,
	      const struct key_type *kt, int enc,
	      const char *prefix)
{
  CLEAR (*ctx);
  if (kt->cipher && kt->cipher_length > 0)
    {
      ASSERT (ctx->cipher = (EVP_CIPHER_CTX *) malloc (sizeof (EVP_CIPHER_CTX)));
      init_cipher (ctx->cipher, kt->cipher, key, kt, enc, prefix);
    }
  if (kt->digest && kt->hmac_length > 0)
    {
      ASSERT (ctx->hmac = (HMAC_CTX *) malloc (sizeof (HMAC_CTX)));
      init_hmac (ctx->hmac, kt->digest, key, kt, prefix);
    }
}

void free_key_ctx (struct key_ctx *ctx)
{
  if (ctx->cipher)
    {
      EVP_CIPHER_CTX_cleanup (ctx->cipher);
      free (ctx->cipher);
      ctx->cipher = NULL;
    }
  if (ctx->hmac)
    {
      HMAC_CTX_cleanup (ctx->hmac);
      free (ctx->hmac);
      ctx->hmac = NULL;
    }
}

void free_key_ctx_bi (struct key_ctx_bi *ctx)
{
  free_key_ctx(&ctx->encrypt);
  free_key_ctx(&ctx->decrypt);
}

/*
 * Return number of DES cblocks for the current
 * key type or 0 if not a DES cipher.
 */
static int
n_DES_cblocks (const struct key_type *kt)
{
  int ret = 0;
  const char *name = OBJ_nid2sn (EVP_CIPHER_nid (kt->cipher));
  if (name)
    {
      if (!strncmp (name, "DES-", 4))
	{
	  ret = EVP_CIPHER_key_length (kt->cipher) / sizeof (DES_cblock);
	}
      else if (!strncmp (name, "DESX-", 5))
	{
	  ret = 1;
	}
    }
  msg (D_CRYPTO_DEBUG, "CRYPTO INFO: n_DES_cblocks=%d", ret);
  return ret;
}

static bool
check_key_DES (struct key *key, const struct key_type *kt, int ndc)
{
  int i;
  struct buffer b;

  buf_set_read (&b, key->cipher, kt->cipher_length);
  for (i = 0; i < ndc; ++i)
    {
      DES_cblock *dc = (DES_cblock*) buf_read_alloc (&b, sizeof (DES_cblock));
      if (!dc)
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: insufficient key material");
	  return false;
	}
      if (DES_is_weak_key(dc))
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: weak key detected");
	  return false;
	}
      if (!DES_check_key_parity (dc))
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: check_key_DES: bad parity detected");
	  return false;
	}
    }
  return true;
}

static void
fixup_key_DES (struct key *key, const struct key_type *kt, int ndc)
{
  int i;
  struct buffer b;

  buf_set_read (&b, key->cipher, kt->cipher_length);
  for (i = 0; i < ndc; ++i)
    {
      DES_cblock *dc = (DES_cblock*) buf_read_alloc(&b, sizeof(DES_cblock));
      if (!dc)
	{
	  msg (D_CRYPT_ERRORS, "CRYPTO INFO: fixup_key_DES: insufficient key material");
	  return;
	}
      DES_set_odd_parity (dc);
    }
}

static bool
key_is_zero(struct key *key, const struct key_type *kt)
{
  int i;
  for (i = 0; i < kt->cipher_length; ++i)
    if (key->cipher[i])
      return false;
  msg (D_CRYPT_ERRORS, "CRYPTO INFO: WARNING: zero key detected");
  return true;
}

/*
 * Make sure that cipher key is a valid key for current key_type.
 */
bool
check_key (struct key *key, const struct key_type *kt)
{
  if (kt->cipher)
    {
      /*
       * Check for zero key
       */
      if (key_is_zero(key, kt))
	return false;

      /*
       * Check for weak or semi-weak DES keys.
       */
      {
	const int ndc = n_DES_cblocks (kt);
	if (ndc)
	  return check_key_DES (key, kt, ndc);
	else
	  return true;
      }
    }
  return true;
}

/*
 * Make safe mutations to key to ensure it is valid,
 * such as ensuring correct parity on DES keys.
 *
 * This routine cannot guarantee it will generate a good
 * key.  You must always call check_key after this routine
 * to make sure.
 */ 
void
fixup_key (struct key *key, const struct key_type *kt)
{
  if (kt->cipher)
    {
      const struct key orig = *key;
      const int ndc = n_DES_cblocks (kt);

      if (ndc)
	fixup_key_DES (key, kt, ndc);

      if (check_debug_level (D_CRYPTO_DEBUG))
	{
	  if (memcmp (orig.cipher, key->cipher, kt->cipher_length))
	    msg (D_CRYPTO_DEBUG, "CRYPTO INFO: fixup_key: before=%s after=%s",
		 format_hex (orig.cipher, kt->cipher_length, 0),
		 format_hex (key->cipher, kt->cipher_length, 0));
	}
    }
}

void
check_replay_iv_consistency(const struct key_type *kt, bool packet_id, bool iv)
{
  if (cfb_ofb_mode (kt) && !(packet_id && iv))
    msg (M_FATAL, "--no-replay or --no-iv cannot be used with a CFB or OFB mode cipher");
}

bool
cfb_ofb_mode(const struct key_type* kt)
{
  if (kt->cipher) {
    const unsigned int mode = EVP_CIPHER_mode (kt->cipher);
    return mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE;
  } else
    return false;
}

/*
 * Generate a random key.  If key_type is provided, make
 * sure generated key is valid for key_type.
 */
void
generate_key_random (struct key *key, const struct key_type *kt)
{
  int cipher_len = MAX_CIPHER_KEY_LENGTH;
  int hmac_len = MAX_HMAC_KEY_LENGTH;

  do {
    CLEAR (*key);
    if (kt)
      {
	if (kt->cipher && kt->cipher_length > 0 && kt->cipher_length <= cipher_len)
	  cipher_len = kt->cipher_length;

	if (kt->digest && kt->hmac_length > 0 && kt->hmac_length <= hmac_len)
	  hmac_len = kt->hmac_length;
      }
    ASSERT (RAND_bytes (key->cipher, cipher_len));
    ASSERT (RAND_bytes (key->hmac, hmac_len));
    if (kt)
      fixup_key (key, kt);
  } while (kt && !check_key (key, kt));
}

void
randomize_iv (unsigned char *iv)
{
  if (RAND_bytes (iv, EVP_MAX_IV_LENGTH) < 0)
    msg (M_SSLERR, "RAND_bytes failed");
}

void
test_crypto (const struct crypto_options *co, struct frame* frame)
{
  int i, j;
  struct buffer src = alloc_buf_gc (MTU_SIZE (frame));
  struct buffer work = alloc_buf_gc (BUF_SIZE (frame));
  struct buffer encrypt_workspace = alloc_buf_gc (BUF_SIZE (frame));
  struct buffer decrypt_workspace = alloc_buf_gc (BUF_SIZE (frame));
  struct buffer buf = clear_buf();

  /* init work */
  ASSERT (buf_init (&work, EXTRA_FRAME (frame)));

  msg (M_INFO, "Entering OpenVPN crypto self-test mode.");
  for (i = 1; i <= MTU_SIZE (frame); ++i)
    {
      const time_t current = time (NULL);

      msg (M_INFO, "TESTING ENCRYPT/DECRYPT of packet length=%d", i);

      /*
       * Load src with random data.
       */
      ASSERT (buf_init (&src, 0));
      ASSERT (i <= src.capacity);
      src.len = i;
      ASSERT (RAND_pseudo_bytes (BPTR (&src), BLEN (&src)));

      /* copy source to input buf */
      buf = work;
      memcpy (buf_write_alloc (&buf, BLEN (&src)), BPTR (&src), BLEN (&src));

      /* encrypt */
      openvpn_encrypt (&buf, encrypt_workspace, co, frame, current);

      /* decrypt */
      openvpn_decrypt (&buf, decrypt_workspace, co, frame, current);

      /* compare */
      if (buf.len != src.len)
	msg (M_FATAL, "SELF TEST FAILED, src.len=%d buf.len=%d", src.len, buf.len);
      for (j = 0; j < i; ++j)
	{
	  const unsigned char in = *(BPTR (&src) + j);
	  const unsigned char out = *(BPTR (&buf) + j);
	  if (in != out)
	    msg (M_FATAL, "SELF TEST FAILED, pos=%d in=%d out=%d", j, in, out);
	}
    }
  msg (M_INFO, "OpenVPN crypto self-test mode SUCCEEDED.");
}

#ifdef USE_SSL
void
get_tls_handshake_key (const struct key_type *key_type,
		       struct key_ctx_bi *ctx, const char *passphrase_file)
{
  if (passphrase_file && key_type->hmac_length)
    {
      struct key key;
      struct key_type kt = *key_type;

      /* for control channel we are only authenticating, not encrypting */
      kt.cipher_length = 0;
      kt.cipher = NULL;

      /* get key material for hmac */
      {
	int digest_len;
	unsigned char digest[MAX_HMAC_KEY_LENGTH];
	EVP_MD_CTX md;

	CLEAR (key);
	EVP_DigestInit (&md, kt.digest);

	/* read passphrase file */
	{
	  const int min_passphrase_size = 8;
	  unsigned char buf[512];
	  int total_size = 0;
	  int fd = open (passphrase_file, O_RDONLY);

	  if (fd == -1)
	    msg (M_ERR, "Cannot open passphrase file: %s", passphrase_file);

	  for (;;)
	    {
	      int size = read (fd, buf, sizeof (buf));
	      if (size == 0)
		break;
	      if (size == -1)
		msg (M_ERR, "Read error on passphrase file: %s",
		     passphrase_file);
	      EVP_DigestUpdate (&md, buf, size);
	      total_size += size;
	    }
	  close (fd);
	  if (total_size < min_passphrase_size)
	    msg (M_FATAL,
		 "Passphrase file %s is too small (must have at least %d characters)",
		 passphrase_file, min_passphrase_size);
	}

	EVP_DigestFinal (&md, digest, &digest_len);
	ASSERT (digest_len == kt.hmac_length);
	memcpy (key.hmac, digest, digest_len);
	CLEAR (digest);
	EVP_MD_CTX_cleanup (&md);
      }

      /* use same hmac key in both directions */

      init_key_ctx (&ctx->encrypt, &key, &kt, DO_ENCRYPT,
		    "Outgoing Control Channel Authentication");
      init_key_ctx (&ctx->decrypt, &key, &kt, DO_DECRYPT,
		    "Incoming Control Channel Authentication");

      CLEAR (key);
    }
  else
    {
      CLEAR (*ctx);
    }
}
#endif

/* header and footer for static key file */
static const char static_key_head[] = "-----BEGIN OpenVPN Static key V1-----";
static const char static_key_foot[] = "-----END OpenVPN Static key V1-----";

static const char printable_char_fmt[] =
  "Non-Hex character ('%c') found at line %d in key file %s (%d/%d bytes found/required)";

static const char unprintable_char_fmt[] =
  "Non-Hex, unprintable character (0x%02x) found at line %d in key file %s (%d/%d bytes found/required)";

/* read key from file */
void
read_key_file (struct key *key, const char *filename)
{
  const int gc_level = gc_new_level ();
  struct buffer in = alloc_buf_gc (512);
  int state = 0;
  unsigned char* out = (unsigned char*) key;
  int count = 0;
  unsigned char hex_byte[3] = {0, 0, 0};
  int hb_index = 0;
  int line_num = 1;
  int line_index = 0;
  int matchlen = 0;
  const int headlen = strlen(static_key_head);
  const int keylen = sizeof (*key);
  int fd, size;

  fd = open (filename, O_RDONLY);
  if (fd == -1)
    msg (M_ERR, "Cannot open shared secret file %s", filename);

  while (size = read (fd, in.data, in.capacity))
    {
      const char *cp = in.data;
      while (size)
	{
	  const char c = *cp;

	  /* msg (M_INFO, "char='%c' state=%d line_num=%d line_index=%d matchlen=%d",
	     c, state, line_num, line_index, matchlen); */

	  if (c == '\n')
	    {
	      line_index = 0;
	      ++line_num;
	    }
	  else
	    {
	      /* found header line? */
	      if (state == 0 && !line_index)
		{
		  if (matchlen == headlen)
		    state = 1;
		  matchlen = 0;
		}

	      /* compare read chars with header line */
	      if (state == 0) {
		if (line_index < headlen && c == static_key_head[line_index])
		  ++matchlen;
	      }

	      /* reading key */
	      if (state == 1) {
		if (isxdigit(c))
		  {
		    ASSERT(hb_index < 2);
		    hex_byte[hb_index++] = c;
		    if (hb_index == 2)
		      {
			unsigned int u;
			ASSERT(sscanf(hex_byte, "%x", &u) == 1);
			*out++ = u;
			hb_index = 0;
			if (++count == keylen)
			  state = 2;
		      }
		  }
		else if (isspace(c))
		  ;
		else
		  {
		    msg (M_FATAL,
			 (isprint (c) ? printable_char_fmt : unprintable_char_fmt),
			 c, line_num, filename, count, keylen);
		  }
	      }
	      ++line_index;
	    }
	  ++cp;
	  --size;
	}
    }

  close (fd);
  if (state != 2)
    msg (M_ERR, "Key not found in file %s (%d/%d bytes found/required)",
	 filename, count, keylen);

  /* zero file read buffer */
  memset(in.data, 0, in.capacity);

  /* pop our garbage collection level */
  gc_free_level (gc_level);
}

/* write key to file */
void
write_key_file (const struct key *key, const char *filename)
{
  int fd, size, len;
  char* fmt;
  const int gc_level = gc_new_level ();
  struct buffer out = alloc_buf_gc (512);

  /* open key file */
  fd = open (filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRWXU);
  if (fd == -1)
    msg (M_ERR, "Cannot open shared secret file %s for write", filename);

  /* format key as ascii */
  fmt = format_hex_ex ((unsigned const char*)key, sizeof (*key), 0, 8, "\n");
  buf_printf (&out, "%s\n", static_key_head);
  buf_printf (&out, "%s\n", fmt);
  buf_printf (&out, "%s\n", static_key_foot);

  /* write data to file */
  len = strlen (BPTR(&out));
  size = write (fd, BPTR(&out), len);
  if (size != len)
    msg (M_ERR, "Write error on shared secret file %s", filename);
  close (fd);

  /* zero memory that held keys (memory will be freed by garbage collector) */
  memset (BPTR(&out), 0, len);
  memset (fmt, 0, strlen(fmt));

  /* pop our garbage collection level */
  gc_free_level (gc_level);
}

/* given a key and key_type, write key to buffer */
void
write_key (const struct key *key, const struct key_type *kt,
	   struct buffer *buf)
{
  ASSERT (kt->cipher_length <= MAX_CIPHER_KEY_LENGTH
	  && kt->hmac_length <= MAX_HMAC_KEY_LENGTH);
  ASSERT (buf_write (buf, &kt->cipher_length, 1));
  ASSERT (buf_write (buf, &kt->hmac_length, 1));
  ASSERT (buf_write (buf, key->cipher, kt->cipher_length));
  ASSERT (buf_write (buf, key->hmac, kt->hmac_length));
}

/*
 * Given a key_type and buffer, read key from buffer.
 * Return: 1 on success
 *        -1 read failure
 *         0 on key length mismatch 
 */
int
read_key (struct key *key, const struct key_type *kt, struct buffer *buf)
{
  unsigned char cipher_length;
  unsigned char hmac_length;

  CLEAR (*key);
  if (!buf_read (buf, &cipher_length, 1))
    goto read_err;
  if (!buf_read (buf, &hmac_length, 1))
    goto read_err;

  if (!buf_read (buf, key->cipher, cipher_length))
    goto read_err;
  if (!buf_read (buf, key->hmac, hmac_length))
    goto read_err;

  if (cipher_length != kt->cipher_length || hmac_length != kt->hmac_length)
    goto key_len_err;

  return 1;

read_err:
  msg (D_TLS_ERRORS, "TLS Error: error reading key from remote");
  return -1;

key_len_err:
  msg (D_TLS_ERRORS,
       "TLS Error: key length mismatch, local cipher/hmac %d/%d, remote cipher/hmac %d/%d",
       kt->cipher_length, kt->hmac_length, cipher_length, hmac_length);
  return 0;
}

void
show_available_ciphers ()
{
  int nid;

  printf ("The following ciphers and cipher modes are available\n"
	  "for use with OpenVPN.\n"
	  "Each cipher name is shown in brackets and may be used as a\n"
	  "parameter to the --cipher option.  The default key size is\n"
	  "shown as well as whether or not it can be changed with\n"
	  "the --keysize directive.  If you don't know what\n"
	  "to choose, I would recommend BF-CBC (Blowfish in CBC mode)\n"
	  "as a cipher that combines good security with speed.\n\n");

  for (nid = 0; nid < 10000; ++nid)	/* is there a better way to get the size of the nid list? */
    {
      const EVP_CIPHER *cipher = EVP_get_cipherbynid (nid);
      if (cipher)
	{
	  const unsigned int mode = EVP_CIPHER_mode (cipher);
	  if (mode == EVP_CIPH_CBC_MODE || mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE)
	    printf ("%s %d bit default key (%s)\n",
		    OBJ_nid2sn (nid),
		    EVP_CIPHER_key_length (cipher) * 8,
		    ((EVP_CIPHER_flags (cipher) & EVP_CIPH_VARIABLE_LENGTH) ?
		     "variable" : "fixed"));
	}
    }
  printf ("\n");
}

void
show_available_digests ()
{
  int nid;

  printf ("The following message digests are available for use with\n"
	  "OpenVPN.  A message digest is used in conjunction with\n"
	  "the HMAC function, to authenticate received packets.\n"
	  "You can specify a message digest as parameter to\n"
	  "the --auth option.\n"
	  "Each message digest is shown below in brackets.\n"
	  "If you don't know what to choose, I would pick SHA1.\n\n");

  for (nid = 0; nid < 10000; ++nid)
    {
      const EVP_MD *digest = EVP_get_digestbynid (nid);
      if (digest)
	{
	  printf ("%s %d bit digest size\n",
		  OBJ_nid2sn (nid), EVP_MD_size (digest) * 8);
	}
    }
  printf ("\n");
}

/*
 * This routine should have additional OpenSSL crypto library initialisations
 * used by both crypto and ssl components of OpenVPN.
 */
void init_crypto_lib ()
{
}

#ifndef USE_SSL

void
init_ssl_lib ()
{
  ERR_load_crypto_strings ();
  OpenSSL_add_all_algorithms ();
  init_crypto_lib();
}

void
free_ssl_lib ()
{
  EVP_cleanup ();
  ERR_free_strings ();
}

#endif /* USE_SSL */
#endif /* USE_CRYPTO */
