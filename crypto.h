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

#ifndef CRYPTO_H
#define CRYPTO_H
#ifdef USE_CRYPTO

#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/des.h>

#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "common.h"

/*
 * Workarounds for incompatibilites between OpenSSL libraries.
 * Right now we accept OpenSSL libraries from 0.9.5 to 0.9.7.
 */

#if SSLEAY_VERSION_NUMBER < 0x00907000L

/* Workaround: EVP_CIPHER_mode is defined wrong in OpenSSL 0.9.6 but is fixed in 0.9.7 */
#undef EVP_CIPHER_mode
#define EVP_CIPHER_mode(e)  (((e)->flags) & EVP_CIPH_MODE)

#define DES_cblock              des_cblock
#define DES_is_weak_key         des_is_weak_key
#define DES_check_key_parity    des_check_key_parity
#define DES_set_odd_parity      des_set_odd_parity

#define HMAC_CTX_cleanup        HMAC_cleanup
#define EVP_MD_CTX_cleanup(md)  CLEAR (*md)

#define INFO_CALLBACK_SSL_CONST

#endif

#ifndef INFO_CALLBACK_SSL_CONST
#define INFO_CALLBACK_SSL_CONST const
#endif

#if SSLEAY_VERSION_NUMBER < 0x00906000

#undef EVP_CIPHER_mode
#define EVP_CIPHER_mode(x) 1
#define EVP_CIPHER_CTX_mode(x) 1
#define EVP_CIPHER_flags(x) 0

#define EVP_CIPH_CBC_MODE 1
#define EVP_CIPH_CFB_MODE 0
#define EVP_CIPH_OFB_MODE 0
#define EVP_CIPH_VARIABLE_LENGTH 0

#define OPENSSL_malloc(x) malloc(x)
#define OPENSSL_free(x) free(x)

static inline int
EVP_CipherInit_ov (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, uint8_t *key, uint8_t *iv, int enc)
{
  EVP_CipherInit (ctx, type, key, iv, enc);
  return 1;
}

static inline int
EVP_CipherUpdate_ov (EVP_CIPHER_CTX *ctx, uint8_t *out, int *outl, uint8_t *in, int inl)
{
  EVP_CipherUpdate (ctx, out, outl, in, inl);
  return 1;
}

static inline bool
cipher_ok (const char* name)
{
  const int i = strlen (name) - 4;
  if (i >= 0)
    return !strcmp (name + i, "-CBC");
  else
    return false;
}

#else

static inline int
EVP_CipherInit_ov (EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, uint8_t *key, uint8_t *iv, int enc)
{
  return EVP_CipherInit (ctx, type, key, iv, enc);
}

static inline int
EVP_CipherUpdate_ov (EVP_CIPHER_CTX *ctx, uint8_t *out, int *outl, uint8_t *in, int inl)
{
  return EVP_CipherUpdate (ctx, out, outl, in, inl);
}

static inline bool
cipher_ok (const char* name)
{
  return true;
}

#endif

#if SSLEAY_VERSION_NUMBER < 0x0090581f
#undef DES_check_key_parity
#define DES_check_key_parity(x) 1
#endif

/*
 * Defines a key type and key length for both cipher and HMAC.
 */
struct key_type
{
  uint8_t cipher_length;
  uint8_t hmac_length;
  const EVP_CIPHER *cipher;
  const EVP_MD *digest;
};

/*
 * A random key.
 */
struct key
{
  uint8_t cipher[MAX_CIPHER_KEY_LENGTH];
  uint8_t hmac[MAX_HMAC_KEY_LENGTH];
};

/*
 * A key context for cipher and/or HMAC.
 */
struct key_ctx
{
  EVP_CIPHER_CTX *cipher;
  HMAC_CTX *hmac;
};

/*
 * Cipher/HMAC key context for both sending and receiving
 * directions.
 */
struct key_ctx_bi
{
  struct key_ctx encrypt;
  struct key_ctx decrypt;
};

/*
 * Options for encrypt/decrypt.
 */
struct crypto_options
{
  struct key_ctx_bi *key_ctx_bi;
  struct packet_id *packet_id;
  bool packet_id_long_form;
  uint8_t *iv;
};

void init_key_type (struct key_type *kt, const char *ciphername,
		    bool ciphername_defined, const char *authname,
		    bool authname_defined, int keysize,
		    bool cfb_ofb_allowed);

void read_key_file (struct key *key, const char *filename);

void write_key_file (const struct key *key, const char *filename);

void generate_key_random (struct key *key, const struct key_type *kt);

void randomize_iv (uint8_t *iv);

void check_replay_iv_consistency(const struct key_type *kt, bool packet_id, bool iv);

bool check_key (struct key *key, const struct key_type *kt);

void fixup_key (struct key *key, const struct key_type *kt);

void write_key (const struct key *key, const struct key_type *kt,
		struct buffer *buf);

int read_key (struct key *key, const struct key_type *kt, struct buffer *buf);

bool cfb_ofb_mode (const struct key_type* kt);

/* enc parameter in init_key_ctx */
#define DO_ENCRYPT 1
#define DO_DECRYPT 0

void init_key_ctx (struct key_ctx *ctx, struct key *key,
		   const struct key_type *kt, int enc,
		   const char *prefix);

void free_key_ctx (struct key_ctx *ctx);
void free_key_ctx_bi (struct key_ctx_bi *ctx);

void openvpn_encrypt (struct buffer *buf, struct buffer work,
		      const struct crypto_options *opt,
		      const struct frame* frame,
		      const time_t current);

void openvpn_decrypt (struct buffer *buf, struct buffer work,
		      const struct crypto_options *opt,
		      const struct frame* frame,
		      const time_t current);


void crypto_adjust_frame_parameters (struct frame *frame,
				     const struct key_type* kt,
				     bool cipher_defined,
				     bool iv,
				     bool packet_id,
				     bool packet_id_long_form);

void test_crypto (const struct crypto_options *co, struct frame* f);

void show_available_ciphers ();

void show_available_digests ();

void init_crypto_lib ();

#ifdef USE_SSL

void get_tls_handshake_key (const struct key_type *key_type,
			    struct key_ctx_bi *ctx,
			    const char *passphrase_file);
#else

void init_ssl_lib ();
void free_ssl_lib ();

#endif /* USE_SSL */

/*
 * Inline functions
 */

static inline bool
key_ctx_bi_defined(const struct key_ctx_bi* key)
{
  return key->encrypt.cipher || key->encrypt.hmac || key->decrypt.cipher || key->decrypt.hmac;
}

#endif /* USE_CRYPTO */
#endif /* CRYPTO_H */
