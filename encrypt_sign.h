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

{
#ifndef NO_COMP_FRAG
#ifdef USE_LZO
  /* Compress the packet. */
  if (options->comp_lzo)
    lzo_compress (&buf, lzo_compress_buf, &lzo_compwork, &frame, current);
#endif
#ifdef FRAGMENT_ENABLE
  if (fragment)
    fragment_outgoing (fragment, &buf, &frame_fragment, current);
#endif
#endif

#ifdef USE_CRYPTO
#ifdef USE_SSL
  /*
   * If TLS mode, get the key we will use to encrypt
   * the packet.
   */
  mutex_lock (L_TLS);
  if (tls_multi)
    tls_pre_encrypt (tls_multi, &buf, &crypto_options);
#endif
  /*
   * Encrypt the packet and write an optional
   * HMAC signature.
   */
  openvpn_encrypt (&buf, encrypt_buf, &crypto_options, &frame, current);
#endif
  /*
   * Get the address we will be sending the packet to.
   */
  link_socket_get_outgoing_addr (&buf, &link_socket,
				 &to_link_addr);
#ifdef USE_CRYPTO
#ifdef USE_SSL
  /*
   * In TLS mode, prepend the appropriate one-byte opcode
   * to the packet which identifies it as a data channel
   * packet and gives the low-permutation version of
   * the key-id to the recipient so it knows which
   * decrypt key to use.
   */
  if (tls_multi)
    tls_post_encrypt (tls_multi, &buf);
  mutex_unlock (L_TLS);
#endif
#endif
  to_link = buf;
  free_to_link = false;
}
#undef NO_COMP_FRAG
