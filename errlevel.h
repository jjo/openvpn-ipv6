/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2003 James Yonan <jim@yonan.net>
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

#ifndef ERRLEVEL_H
#define ERRLEVEL_H

#include "error.h"

/*
 * Debugging levels for various kinds
 * of output.
 */

#define M_INFO               LOGLEV(1, 0, 0)         /* default informational messages */

#define D_LINK_ERRORS        LOGLEV(1, 10, M_NONFATAL)   /* show link errors from main event loop */
#define D_CRYPT_ERRORS       LOGLEV(1, 11, M_NONFATAL)   /* show errors from encrypt/decrypt */
#define D_TLS_ERRORS         LOGLEV(1, 12, M_NONFATAL)   /* show TLS control channel errors */
#define D_RESOLVE_ERRORS     LOGLEV(1, 13, M_NONFATAL)   /* show hostname resolve errors */
#define D_COMP_ERRORS        LOGLEV(1, 14, M_NONFATAL)   /* show compression errors */
#define D_PID_PERSIST        LOGLEV(1, 15, M_NONFATAL)   /* show packet_id persist errors */
#define D_FRAG_ERRORS        LOGLEV(1, 16, M_NONFATAL)   /* show fragmentation errors */

#define D_HANDSHAKE          LOGLEV(2, 20, 0)        /* show data & control channel handshakes */
#define D_MTU_INFO           LOGLEV(2, 21, 0)        /* show debugging MTU info */

#define D_TLS_DEBUG_LOW      LOGLEV(3, 20, 0)        /* low frequency info from tls_session routines */
#define D_GREMLIN            LOGLEV(3, 30, 0)        /* show simulated outage info from gremlin module */
#define D_COMP_LOW           LOGLEV(3, 31, 0)        /* show adaptive compression state changes */

#define D_SHOW_PARMS         LOGLEV(4, 40, 0)        /* show all parameters on program initiation */

#define D_UDP_RW             LOGLEV(6, 60, M_DEBUG)  /* show UDP reads/writes (terse) */

#define D_SHOW_KEYS          LOGLEV(7, 70, M_DEBUG)  /* show data channel encryption keys */
#define D_REL_DEBUG          LOGLEV(7, 70, M_DEBUG)  /* show detailed info from reliable routines */
#define D_MTU_DEBUG          LOGLEV(7, 70, M_DEBUG)  /* show dynamic MTU info */
#define D_FRAG_DEBUG         LOGLEV(7, 70, M_DEBUG)  /* show fragment debugging info */

#define D_HANDSHAKE_VERBOSE  LOGLEV(8, 70, M_DEBUG)  /* show detailed description of each handshake */
#define D_TLS_DEBUG_MED      LOGLEV(8, 70, M_DEBUG)  /* medium frequency info from tls_session routines */
#define D_INTERVAL           LOGLEV(8, 70, M_DEBUG)  /* show interval.h debugging info */
#define D_GREMLIN_VERBOSE    LOGLEV(8, 70, M_DEBUG)  /* show verbose info from gremlin module */

#define D_TLS_DEBUG          LOGLEV(9, 70, M_DEBUG)  /* show detailed info from TLS routines */
#define D_CRYPTO_DEBUG       LOGLEV(9, 70, M_DEBUG)  /* show detailed info from crypto.c routines */
#define D_COMP               LOGLEV(9, 70, M_DEBUG)  /* show compression info */
#define D_READ_WRITE         LOGLEV(9, 70, M_DEBUG)  /* verbose account of all tun/UDP reads/writes/opens */
#define D_PACKET_CONTENT     LOGLEV(9, 70, M_DEBUG)  /* show before/after encryption packet content */
#define D_TLS_NO_SEND_KEY    LOGLEV(9, 70, M_DEBUG)  /* show when no data channel send-key exists */
#define D_THREAD_DEBUG       LOGLEV(9, 70, M_DEBUG)  /* show pthread debug information */
#define D_REL_LOW            LOGLEV(9, 70, M_DEBUG)  /* show low frequency info from reliable layer */
#define D_PID_DEBUG          LOGLEV(9, 70, M_DEBUG)  /* show packet-id debugging info */
#define D_PID_PERSIST_DEBUG  LOGLEV(9, 70, M_DEBUG)  /* show packet-id persist debugging info */
#define D_UDP_RW_VERBOSE     LOGLEV(9, 70, M_DEBUG)  /* show UDP reads/writes with greater verbosity */
#define D_TLS_THREAD_DEBUG   LOGLEV(5, 70, M_DEBUG)  /* CHANGEME show detailed info from TLS thread routines */

#define D_SHAPER_DEBUG       LOGLEV(10, 70, M_DEBUG)  /* show traffic shaper info */

#define D_OPENSSL_LOCK       LOGLEV(11, 70, M_DEBUG) /* show OpenSSL locks */

#endif
