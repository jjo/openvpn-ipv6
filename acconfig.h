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

/* use crypto library */
#undef USE_CRYPTO

/* use ssl library */
#undef USE_SSL

/* use LZO library */
#undef USE_LZO

/* use pthread thread library to optimize latency */
#undef USE_PTHREAD
#undef _REENTRANT

/* enable dmalloc memory leak debugging */
#undef DMALLOC

/* enable ssl memory leak debugging */
#undef CRYPTO_MDEBUG

/* early versions of glibc don't define in_addr_t */
#undef in_addr_t

/* what system are we running on? */
#undef TARGET_ALIAS

/* are we running on linux? */
#undef TARGET_LINUX

/* are we running on solaris? */
#undef TARGET_SOLARIS

/* are we running on OpenBSD? */
#undef TARGET_OPENBSD

/* are we running on FreeBSD? */
#undef TARGET_FREEBSD
