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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#include "syshead.h"

#if P2MP_SERVER

#include "multi.h"
#include "forward-inline.h"

#include "memdbg.h"

/*
 * Get a client instance based on real address.  If
 * the instance doesn't exist, create it while
 * maintaining real address hash table atomicity.
 */

struct multi_instance *
multi_get_create_instance_udp (struct multi_context *m)
{
  struct gc_arena gc = gc_new ();
  struct mroute_addr real;
  struct multi_instance *mi = NULL;
  struct hash *hash = m->hash;

  if (mroute_extract_sockaddr_in (&real, &m->top.c2.from, true))
    {
      struct hash_element *he;
      const uint32_t hv = hash_value (hash, &real);
      struct hash_bucket *bucket = hash_bucket (hash, hv);
  
      hash_bucket_lock (bucket);
      he = hash_lookup_fast (hash, bucket, &real, hv);

      if (he)
	{
	  mi = (struct multi_instance *) he->value;
	}
      else
	{
	  if (!m->top.c2.tls_auth_standalone
	      || tls_pre_decrypt_lite (m->top.c2.tls_auth_standalone, &m->top.c2.from, &m->top.c2.buf))
	    {
	      if (frequency_limit_event_allowed (m->new_connection_limiter))
		{
		  mi = multi_create_instance (m, &real);
		  if (mi)
		    {
		      hash_add_fast (hash, bucket, &mi->real, hv, mi);
		      mi->did_real_hash = true;
		    }
		}
	      else
		{
		  msg (D_MULTI_ERRORS,
		       "MULTI: Connection from %s would exceed new connection frequency limit as controlled by --connect-freq",
		       mroute_addr_print (&real, &gc));
		}
	    }
	}

      hash_bucket_unlock (bucket);

#ifdef ENABLE_DEBUG
      if (check_debug_level (D_MULTI_DEBUG))
	{
	  const char *status;

	  if (he && mi)
	    status = "[succeeded]";
	  else if (!he && mi)
	    status = "[created]";
	  else
	    status = "[failed]";
	
	  dmsg (D_MULTI_DEBUG, "GET INST BY REAL: %s %s",
	       mroute_addr_print (&real, &gc),
	       status);
	}
#endif
    }

  gc_free (&gc);
  ASSERT (!(mi && mi->halt));
  return mi;
}

/*
 * Send a packet to TCP/UDP socket.
 */
static inline void
multi_process_outgoing_link (struct multi_context *m, const unsigned int mpp_flags)
{
  struct multi_instance *mi = multi_process_outgoing_link_pre (m);
  if (mi)
    multi_process_outgoing_link_dowork (m, mi, mpp_flags);
}

/*
 * Process an I/O event.
 */
static void
multi_process_io_udp (struct multi_context *m)
{
  const unsigned int status = m->top.c2.event_set_status;
  const unsigned int mpp_flags = m->top.c2.fast_io
    ? (MPP_CONDITIONAL_PRE_SELECT | MPP_CLOSE_ON_SIGNAL)
    : (MPP_PRE_SELECT | MPP_CLOSE_ON_SIGNAL);

#ifdef MULTI_DEBUG_EVENT_LOOP
  char buf[16];
  buf[0] = 0;
  if (status & SOCKET_READ)
    strcat (buf, "SR/");
  else if (status & SOCKET_WRITE)
    strcat (buf, "SW/");
  else if (status & TUN_READ)
    strcat (buf, "TR/");
  else if (status & TUN_WRITE)
    strcat (buf, "TW/");
  printf ("IO %s\n", buf);
#endif

#ifdef ENABLE_MANAGEMENT
  if (status & (MANAGEMENT_READ|MANAGEMENT_WRITE))
    {
      ASSERT (management);
      management_io (management);
    }
#endif

  /* UDP port ready to accept write */
  if (status & SOCKET_WRITE)
    {
      multi_process_outgoing_link (m, mpp_flags);
    }
  /* TUN device ready to accept write */
  else if (status & TUN_WRITE)
    {
      multi_process_outgoing_tun (m, mpp_flags);
    }
  /* Incoming data on UDP port */
  else if (status & SOCKET_READ)
    {
      read_incoming_link (&m->top);
      multi_release_io_lock (m);
      if (!IS_SIG (&m->top))
	multi_process_incoming_link (m, NULL, mpp_flags);
    }
  /* Incoming data on TUN device */
  else if (status & TUN_READ)
    {
      read_incoming_tun (&m->top);
      multi_release_io_lock (m);
      if (!IS_SIG (&m->top))
	multi_process_incoming_tun (m, mpp_flags);
    }
}

/*
 * Return the io_wait() flags appropriate for
 * a point-to-multipoint tunnel.
 */
static inline unsigned int
p2mp_iow_flags (const struct multi_context *m)
{
  unsigned int flags = IOW_WAIT_SIGNAL;
  if (m->pending)
    {
      if (TUN_OUT (&m->pending->context))
	flags |= IOW_TO_TUN;
      if (LINK_OUT (&m->pending->context))
	flags |= IOW_TO_LINK;
    }
  else if (mbuf_defined (m->mbuf))
    flags |= IOW_MBUF;
  else
    flags |= IOW_READ;

  return flags;
}

/*
 * Top level event loop for single-threaded operation.
 * UDP mode.
 */
static void
tunnel_server_udp_single_threaded (struct context *top)
{
  struct multi_context multi;

  top->mode = CM_TOP;
  context_clear_2 (top);

  /* initialize top-tunnel instance */
  init_instance (top, top->es, CC_HARD_USR1_TO_HUP);
  if (IS_SIG (top))
    return;
  
  /* initialize global multi_context object */
  multi_init (&multi, top, false, MC_SINGLE_THREADED);

  /* initialize our cloned top object */
  multi_top_init (&multi, top, true);

  /* initialize management interface */
  init_management_callback_multi (&multi);

  /* finished with initialization */
  initialization_sequence_completed (top, false); /* --mode server --proto udp */

  /* per-packet event loop */
  while (true)
    {
      perf_push (PERF_EVENT_LOOP);

      /* set up and do the io_wait() */
      multi_get_timeout (&multi, &multi.top.c2.timeval);
      io_wait (&multi.top, p2mp_iow_flags (&multi));
      MULTI_CHECK_SIG (&multi);

      /* check on status of coarse timers */
      multi_process_per_second_timers (&multi);

      /* timeout? */
      if (multi.top.c2.event_set_status == ES_TIMEOUT)
	{
	  multi_process_timeout (&multi, MPP_PRE_SELECT|MPP_CLOSE_ON_SIGNAL);
	}
      else
	{
	  /* process I/O */
	  multi_process_io_udp (&multi);
	  MULTI_CHECK_SIG (&multi);
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

#ifdef USE_PTHREAD

struct thread_info
{
  volatile bool halt;
  unsigned int thread_mode;
  const struct multi_context *multi;
};

static void
multi_thread_udp_event_loop_scheduler (const struct thread_info *mt, struct multi_context *m)
{
}

static void
multi_thread_udp_event_loop_worker (const struct thread_info *mt, struct multi_context *m)
{
  /* per-packet event loop */
  while (true)
    {
      unsigned int iow_flags;

      if (!m->pending)
	multi_release_io_lock (m);

      if (mt->halt)
	break;

      m->top.c2.timeval.tv_sec = 5;
      m->top.c2.timeval.tv_usec = 0;

      iow_flags = p2mp_iow_flags (m);

      multi_acquire_io_lock (m, iow_flags);
      if (mt->halt)
	break;

      io_wait (&m->top, iow_flags);
      if (mt->halt)
	  break;

      /* process I/O */
      if (!IS_SIG (&m->top) && m->top.c2.event_set_status != ES_TIMEOUT)
	{
	  multi_process_io_udp (m);
	}
    }
  multi_release_io_lock (m);
}

static void *
multi_thread_udp_func (void *arg)
{
  const struct thread_info *mt = (struct thread_info *) arg;
  struct multi_context multi;

  /*
   * Clone the top-level multi_context object
   */
  inherit_multi_context (&multi, mt->multi, mt->thread_mode);

  if (mt->thread_mode & MC_MULTI_THREADED_WORKER)
    {
      multi_thread_udp_event_loop_worker (mt, &multi);
    }
  else if (mt->thread_mode & MC_MULTI_THREADED_SCHEDULER)
    {
      multi_thread_udp_event_loop_scheduler (mt, &multi);
    }
  else
    {
      ASSERT (0);
    }

  multi_uninit (&multi);

  dmsg (D_THREAD_DEBUG, "Thread exiting");

  return NULL;
}

/*
 * Top level event loop for multi-threaded operation.
 * UDP mode.
 */
static void
tunnel_server_udp_multi_threaded (struct context *top)
{
  struct multi_context multi;
  struct thread_info thread;
  openvpn_thread_t thread_ids[MAX_THREADS];
  struct multi_context_thread_shared thread_shared;
  int i;

  ASSERT (top->options.n_threads >= 2 && top->options.n_threads < MAX_THREADS);

  CLEAR (thread);

  top->mode = CM_TOP;
  context_clear_2 (top);

  /* initialize top-tunnel instance */
  init_instance (top, top->es, CC_HARD_USR1_TO_HUP);
  if (IS_SIG (top))
    return;
  
  /* initialize global multi_context object */
  multi_init (&multi, top, false, MC_MULTI_THREADED_MASTER);

  /* this object is shared across all threads */
  thread_shared_init (&thread_shared);
  multi.thread_shared = &thread_shared;

  /* initialize our cloned top object */
  multi_top_init (&multi, top, false);

  /* initialize management interface */
  init_management_callback_multi (&multi);

  /* finished with initialization */
  initialization_sequence_completed (top, false);

  /* initialize pthread subsystem */
  openvpn_thread_init ();

  /* init info object to pass to each thread */
  thread.multi = &multi;
  thread.halt = false;

  /* initialize threads */
  for (i = 0; i < top->options.n_threads; ++i)
    {
      thread.thread_mode = (i ? MC_MULTI_THREADED_WORKER : MC_MULTI_THREADED_SCHEDULER);
      thread_ids[i] = openvpn_thread_create (multi_thread_udp_func, (void*)&thread);
    }

  /* let threads do all the work -- we will sleep until signal */
  sleep_until_signal ();

  msg (M_INFO, "THREADS: Shutting down");

  /* signal received, tell threads to shut down */
  thread.halt = true;

  /* wait for threads to shut down */
  for (i = 0; i < top->options.n_threads; ++i)
    openvpn_thread_join (thread_ids[i]);

  thread_shared_uninit (&thread_shared);
  openvpn_thread_cleanup ();

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

void
tunnel_server_udp (struct context *top)
{
#ifdef USE_PTHREAD
  if (top->options.n_threads == 1)
    tunnel_server_udp_single_threaded (top);
  else
    tunnel_server_udp_multi_threaded (top);
#else
  tunnel_server_udp_single_threaded (top);
#endif
}

#endif
