#ifndef ERRLEVEL_H
#define ERRLEVEL_H

#include "error.h"

/*
 * Debugging levels for various kinds
 * of output.
 */

#define M_INFO               LOGLEV(1, 0, 0)  /* default informational messages */

#define D_LINK_ERRORS        LOGLEV(1, 1, M_NONFATAL)   /* show link errors from main event loop */
#define D_CRYPT_ERRORS       LOGLEV(1, 2, M_NONFATAL)   /* show errors from encrypt/decrypt */
#define D_TLS_ERRORS         LOGLEV(1, 3, M_NONFATAL)   /* show TLS control channel errors */
#define D_RESOLVE_ERRORS     LOGLEV(1, 4, M_NONFATAL)   /* show hostname resolve errors */
#define D_COMP_ERRORS        LOGLEV(1, 5, M_NONFATAL)   /* show compression errors */

#define D_SHOW_PARMS         LOGLEV(2, 10, 0)   /* show all parameters on program initiation */

#define D_HANDSHAKE          LOGLEV(3, 11, 0)   /* show data & control channel handshakes */
#define D_GREMLIN            LOGLEV(3, 12, 0)   /* show simulated outage info from gremlin module */

#define D_TLS_DEBUG_LOW      LOGLEV(4, 11, 0)   /* low frequency info from tls_session routines */

#define D_COMP_LOW           LOGLEV(5, 13, 0)   /* show adaptive compression state changes */

#define D_SHOW_KEYS          LOGLEV(6, 14, 0)   /* show data channel encryption keys */

#define D_HANDSHAKE_VERBOSE  LOGLEV(7, 15, 0)   /* show detailed description of each handshake */

#define D_TLS_DEBUG          LOGLEV(8, 20, M_DEBUG)  /* show detailed info from TLS routines */
#define D_CRYPTO_DEBUG       LOGLEV(8, 21, M_DEBUG)  /* show detailed info from crypto.c routines */
#define D_COMP               LOGLEV(8, 22, M_DEBUG)  /* show compression info */
#define D_READ_WRITE         LOGLEV(8, 23, M_DEBUG)  /* verbose account of all tun/UDP reads/writes */
#define D_REL_DEBUG          LOGLEV(8, 24, M_DEBUG)  /* show detailed info from reliable routines */
#define D_PACKET_CONTENT     LOGLEV(8, 25, M_DEBUG)  /* show before/after encryption packet content */
#define D_GREMLIN_VERBOSE    LOGLEV(8, 26, M_DEBUG)  /* show verbose info from gremlin module */
#define D_TLS_NO_SEND_KEY    LOGLEV(8, 27, M_DEBUG)  /* show when no data channel send-key exists */
#define D_THREAD_DEBUG       LOGLEV(8, 28, M_DEBUG)  /* show pthread debug information */
#define D_REL_LOW            LOGLEV(8, 29, M_DEBUG)  /* show low frequency info from reliable layer */
#define D_PID_DEBUG          LOGLEV(8, 30, M_DEBUG)  /* show packet-id debugging info */

#define D_SHAPER             LOGLEV(9, 31, M_DEBUG)  /* show traffic shaper info */

#define D_OPENSSL_LOCK       LOGLEV(10, 32, M_DEBUG) /* show OpenSSL locks */

#endif
