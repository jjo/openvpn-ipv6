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

#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "basic.h"
#include "buffer.h"
#include "packet_id.h"
#include "common.h"

/* convert a time_t to and from network order */
#define htontime(x) htonl(x)
#define ntohtime(x) ntohl(x)

struct key_type
{
  unsigned char cipher_length;
  unsigned char hmac_length;
  const EVP_CIPHER *cipher;
  const EVP_MD *digest;
};

struct key
{
  unsigned char cipher[MAX_CIPHER_KEY_LENGTH];
  unsigned char hmac[MAX_HMAC_KEY_LENGTH];
};

struct key_ctx
{
  bool cipher_defined;
  bool hmac_defined;
  EVP_CIPHER_CTX cipher;
  HMAC_CTX hmac;
};

struct key_ctx_bi
{
  struct key_ctx encrypt;
  struct key_ctx decrypt;
};


struct crypto_options
{
  struct key_ctx_bi *key_ctx_bi;
  int max_timestamp_delta;
  int peer_time_adjust;
  struct packet_id *packet_id;
  bool random_ivec;
  int *n_auth_errors;
};

void init_key_type (struct key_type *kt, const char *ciphername,
		    bool ciphername_defined, const char *authname,
		    bool authname_defined, int keysize);

void read_key_file (struct key *key, const char *filename);

void write_key_file (const struct key *key, const char *filename);

void generate_key_random (struct key *key, const struct key_type *kt);

void write_key (const struct key *key, const struct key_type *kt,
		struct buffer *buf);

int read_key (struct key *key, const struct key_type *kt, struct buffer *buf);

void init_key_ctx (struct key_ctx *key_ctx, struct key *key,
		   const struct key_type *kt, const char *prefix);

void encrypt (struct buffer *buf, struct buffer work,
	      const struct crypto_options *opt,
	      const struct frame* frame,
	      const time_t current);

void decrypt (struct buffer *buf, struct buffer work,
	      const struct crypto_options *opt,
	      const struct frame* frame,
	      const time_t current);


void crypto_adjust_frame_parameters(struct frame *frame,
				    const struct key_type* kt,
				    bool cipher_defined,
				    bool packet_id,
				    bool random_ivec,
				    bool timestamp);

void show_available_ciphers ();

void show_available_digests ();

#ifdef USE_SSL

void get_tls_handshake_key (const struct key_type *key_type,
			    struct key_ctx_bi *ctx,
			    const char *passphrase_file);
#else

void init_ssl_lib ();
void free_ssl_lib ();

#endif /* USE_SSL */
#endif /* USE_CRYPTO */
#endif /* CRYPTO_H */
