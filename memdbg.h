/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#ifdef DMALLOC /* see ./configure options to enable */

/*
 * See ./configure options to enable dmalloc
 * support for memory leak checking.
 *
 * The dmalloc package can be downloaded from:
 *
 *     http://dmalloc.com/
 *
 * When dmalloc is installed and enabled,
 * use this command prior to running openvpn:
 *
 *    dmalloc -l dlog -i 100 low -p log-unknown
 *
 * Also, put this in your .bashrc file:
 *
 *    function dmalloc { eval `command dmalloc -b $*`; }
 */

#include "dmalloc.h"

/*
 * This #define will put the line number of the log
 * file position where leaked memory was allocated instead
 * of the source code file and line number.  Make sure
 * to increase the size of dmalloc's info tables,
 * (MEMORY_TABLE_SIZE in settings.h)
 * otherwise it might get overwhelmed by the large
 * number of unique file/line combinations.
 */
#if 0
#define malloc(size) \
  _malloc_leap("logfile", msg_line_num, size)
#endif

#endif
