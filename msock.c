/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2011 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *                     2011 JuanJo Ciarlante <juanjosec@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
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

#include "syshead.h"

#if P2MP_SERVER

#include "msock.h"

#include "multi.h"
#include "forward-inline.h"

#include "memdbg.h"
/*
 * MSOCK States
 */
#define TA_UNDEF                 0
#define TA_SOCKET_READ           1
#define TA_SOCKET_READ_RESIDUAL  2
#define TA_SOCKET_WRITE          3
#define TA_SOCKET_WRITE_READY    4
#define TA_SOCKET_WRITE_DEFERRED 5
#define TA_TUN_READ              6
#define TA_TUN_WRITE             7
#define TA_INITIAL               8
#define TA_TIMEOUT               9
#define TA_TUN_WRITE_TIMEOUT     10


/*
 * Special tags passed to event.[ch] functions
 */
#define MSOCK_SOCKET      ((void*)1)
#define MSOCK_TUN         ((void*)2)
#define MSOCK_SIG         ((void*)3) /* Only on Windows */
#ifdef ENABLE_MANAGEMENT
# define MSOCK_MANAGEMENT ((void*)4)
#endif

#define MSOCK_N           ((void*)16) /* upper bound on MSOCK_x */

static inline int
multi_sock_wait (const struct context *c,
		  struct multi_sock *msock)
{
  int status;
  socket_set_listen_persistent (c->c2.link_socket, msock->es, MSOCK_SOCKET); // TODO(jjo): msock
  tun_set (c->c1.tuntap, msock->es, EVENT_READ, MSOCK_TUN, &msock->tun_rwflags);
#ifdef ENABLE_MANAGEMENT
  if (management)
    management_socket_set (management, msock->es, MSOCK_MANAGEMENT, &msock->management_persist_flags);
#endif
  status = event_wait (msock->es, &c->c2.timeval, msock->esr, msock->maxevents);
  update_time ();
  msock->n_esr = 0;
  if (status > 0)
    msock->n_esr = status;
  return status;
}

/*
 * Top level event loop for single-threaded operation.
 * MSOCK mode.
 */
void
tunnel_server_msock (struct context *top)
{
  struct multi_context multi;
  int status;

  top->mode = CM_TOP;
  context_clear_2 (top);

  /* initialize top-tunnel instance */
  init_instance_handle_signals (top, top->es, CC_HARD_USR1_TO_HUP);
  if (IS_SIG (top))
    return;
  
  /* initialize global multi_context object */
  multi_init (&multi, top, true, MC_SINGLE_THREADED);

  /* initialize our cloned top object */
  multi_top_init (&multi, top, true);

  /* initialize management interface */
  init_management_callback_multi (&multi);

  /* finished with initialization */
  initialization_sequence_completed (top, ISC_SERVER); /* --mode server --proto tcp-server */

  /* per-packet event loop */
  while (true)
    {
      perf_push (PERF_EVENT_LOOP);

      /* wait on tun/socket list */
      multi_get_timeout (&multi, &multi.top.c2.timeval);
      status = multi_sock_wait (&multi.top, multi.msock);
      MULTI_CHECK_SIG (&multi);

      /* check on status of coarse timers */
      multi_process_per_second_timers (&multi);

      /* timeout? */
      if (status > 0)
	{
	  /* process the I/O which triggered select */
	  multi_tcp_process_io (&multi);
	  MULTI_CHECK_SIG (&multi);
	}
      else if (status == 0)
	{
	  multi_tcp_action (&multi, NULL, TA_TIMEOUT, false);
	}

      perf_pop ();
    }

  /* shut down management interface */
  uninit_management_callback_multi (&multi);

  /* save ifconfig-pool */
  multi_ifconfig_pool_persist (&multi, true);

  /* tear down tunnel instance (unless --persist-tun) */
  multi_uninit (&multi);
  multi_top_free (&multi);
  close_instance (top);
}

#endif
