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

#include "config.h"

#include "syshead.h"

#include "common.h"
#include "buffer.h"
#include "mtu.h"
#include "error.h"

#include "memdbg.h"

void
frame_finalize (struct frame *frame,
		bool udp_mtu_defined,
		int udp_mtu,
		bool tun_mtu_defined,
		int tun_mtu,
		bool udp_mtu_min_defined,
		int udp_mtu_min,
		bool udp_mtu_max_defined,
		int udp_mtu_max)
{
  /* Set udp_mtu based on command line options */
  if (tun_mtu_defined)
    {
      frame->udp_mtu = tun_mtu + TUN_UDP_DELTA (frame);
    }
  else
    {
      ASSERT (udp_mtu_defined);
      frame->udp_mtu = udp_mtu;
    }

  if (TUN_MTU_SIZE (frame) < TUN_MTU_MIN)
    {
      msg (M_WARN, "TUN MTU value (%d) must be at least %d", TUN_MTU_SIZE (frame), TUN_MTU_MIN);
      frame_print (frame, M_FATAL, "MTU is too small");
    }

  /*
   * Sets a range for the dynamic mtu value.
   * Requires call to frame_dynamic_finalize to finalize.
   */
  if (udp_mtu_min_defined)
    frame->dynamic.mtu_min_initial = udp_mtu_min;
  else
    frame->dynamic.mtu_min_initial = MTU_INITIAL_UNDEF;

  if (udp_mtu_max_defined)
    frame->dynamic.mtu_max_initial = udp_mtu_max;
  else
    frame->dynamic.mtu_max_initial = MTU_INITIAL_UNDEF;

  if (udp_mtu_min_defined && udp_mtu_max_defined && udp_mtu_min > udp_mtu_max)
    frame_print (frame, M_FATAL, "Dynamic MTU min is larger than dynamic MTU max");

  frame_set_mtu_dynamic (frame, MTU_SET_TO_MAX);
  frame_dynamic_finalize (frame);
}

/*
 * struct frame_dynamic has two types of parameters: source parameters and derived parameters.
 * This function sets the derived parameters based on the source parameters.
 */
void
frame_dynamic_finalize (struct frame *frame)
{
  const int lower_bound = TUN_MTU_MIN + TUN_UDP_DELTA (frame);
  const int upper_bound = max_int (lower_bound, frame->udp_mtu);

  if (frame->dynamic.mtu_min_initial == MTU_INITIAL_UNDEF)
    frame->dynamic.mtu_min = lower_bound;
  else
    frame->dynamic.mtu_min = constrain_int (frame->dynamic.mtu_min_initial, lower_bound, upper_bound);
  
  if (frame->dynamic.mtu_max_initial == MTU_INITIAL_UNDEF)
    frame->dynamic.mtu_max = upper_bound;
  else
    frame->dynamic.mtu_max = max_int (frame->dynamic.mtu_min,
				      constrain_int (frame->dynamic.mtu_max_initial, lower_bound, upper_bound));

  if (frame->dynamic.mtu_initial == MTU_SET_TO_MIN)
    frame->dynamic.mtu = frame->dynamic.mtu_min;
  else if (frame->dynamic.mtu_initial == MTU_SET_TO_MAX)
    frame->dynamic.mtu = frame->dynamic.mtu_max;
  else
    frame->dynamic.mtu = constrain_int (frame->dynamic.mtu_initial, frame->dynamic.mtu_min, frame->dynamic.mtu_max);

  msg (D_MTU_DEBUG, "MTU dynamic=%d", frame->dynamic.mtu);
}

/*
 * Client initializes a struct frame by zeroing, then calling,
 *   frame_set_mtu_dynamic
 *   frame_add_to_extra_frame
 *   frame_add_to_extra_tun
 *   frame_add_to_extra_buffer
 *
 * frame_finalize_derivative will then finalize the frame based
 * on a previously finalized frame (src).
 */
void
frame_finalize_derivative (struct frame *frame, const struct frame *src)
{
  frame->udp_mtu = src->udp_mtu;
  frame->dynamic.mtu_min_initial = src->dynamic.mtu_min_initial;
  frame->dynamic.mtu_max_initial = src->dynamic.mtu_max_initial;
  frame_dynamic_finalize (frame);  
}

/*
 * Sets the dynamic mtu value (requires call to frame_dynamic_finalize to finalize).
 * mtu_dynamic can be a value or MTU_SET_TO_MIN or MTU_SET_TO_MAX.
 */
void
frame_set_mtu_dynamic (struct frame *frame, int mtu_dynamic)
{
  frame->dynamic.mtu_initial = mtu_dynamic;
}

/*
 * Increase/Decrease udp_mtu by a percentage.
 *
 * Return true if mtu changed.
 */
bool
frame_mtu_change_pct (struct frame *frame, int pct)
{
  const int orig_mtu = frame->udp_mtu;
  const int new_mtu = orig_mtu + (orig_mtu * pct / 100);
  frame_set_mtu_dynamic (frame, new_mtu);
  frame_dynamic_finalize (frame);
  return frame->udp_mtu != orig_mtu;
}

/*
 * Move extra_frame octets into extra_tun.  Used by fragmenting code
 * to adjust frame relative to its position in the buffer processing
 * queue.
 */
void
frame_subtract_extra (struct frame *frame, const struct frame *src)
{
  frame->extra_frame -= src->extra_frame;
  frame->extra_tun   += src->extra_frame;
}

void
frame_print (const struct frame *frame, int level, const char *prefix)
{
  struct buffer out = alloc_buf_gc (256);
  if (prefix)
    buf_printf (&out, "%s ", prefix);
  buf_printf (&out, "[");
  buf_printf (&out, " udp_mtu=%d", frame->udp_mtu);
  buf_printf (&out, " extra_frame=%d", frame->extra_frame);
  buf_printf (&out, " extra_buffer=%d", frame->extra_buffer);
  buf_printf (&out, " extra_tun=%d", frame->extra_tun);
  buf_printf (&out, " dynamic = [");
  buf_printf (&out, " mtu_min_initial=");
  if (frame->dynamic.mtu_min_initial == MTU_INITIAL_UNDEF)
    buf_printf (&out, "MTU_INITIAL_UNDEF");
  else
    buf_printf (&out, "%d", frame->dynamic.mtu_min_initial);
  buf_printf (&out, " mtu_max_initial=");
  if (frame->dynamic.mtu_max_initial == MTU_INITIAL_UNDEF)
    buf_printf (&out, "MTU_INITIAL_UNDEF");
  else
    buf_printf (&out, "%d", frame->dynamic.mtu_max_initial);
  buf_printf (&out, " mtu_initial=");
  if (frame->dynamic.mtu_initial == MTU_SET_TO_MIN)
    buf_printf (&out, "MTU_SET_TO_MIN");
  else if (frame->dynamic.mtu_initial == MTU_SET_TO_MAX)
    buf_printf (&out, "MTU_SET_TO_MAX");
  else
    buf_printf (&out, "%d", frame->dynamic.mtu_initial);
  buf_printf (&out, " mtu_min=%d", frame->dynamic.mtu_min);
  buf_printf (&out, " mtu_max=%d", frame->dynamic.mtu_max);
  buf_printf (&out, " mtu=%d", frame->dynamic.mtu);
  buf_printf (&out, " ]]");

  msg (level, "%s", out.data);
}

#define MTUDISC_NOT_SUPPORTED_MSG "--mtu-disc is not supported on this OS"

void
set_mtu_discover_type (int sd, int mtu_type)
{
  if (mtu_type >= 0)
    {
#if defined(HAVE_SETSOCKOPT) && defined(SOL_IP) && defined(IP_MTU_DISCOVER)
      if (setsockopt
	  (sd, SOL_IP, IP_MTU_DISCOVER, &mtu_type, sizeof (mtu_type)))
	msg (M_ERR, "Error setting IP_MTU_DISCOVER type=%d on UDP socket",
	     mtu_type);
#else
      msg (M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
#endif
    }
}

int
translate_mtu_discover_type_name (const char *name)
{
#if defined(IP_PMTUDISC_DONT) && defined(IP_PMTUDISC_WANT) && defined(IP_PMTUDISC_DO)
  if (!strcmp (name, "yes"))
    return IP_PMTUDISC_DO;
  if (!strcmp (name, "maybe"))
    return IP_PMTUDISC_WANT;
  if (!strcmp (name, "no"))
    return IP_PMTUDISC_DONT;
  msg (M_FATAL,
       "invalid --mtu-disc type: '%s' -- valid types are 'yes', 'maybe', or 'no'",
       name);
#else
  msg (M_FATAL, MTUDISC_NOT_SUPPORTED_MSG);
#endif
  return -1;			/* NOTREACHED */
}

#if EXTENDED_SOCKET_ERROR_CAPABILITY

/*
 *
 * The following code is adapted from tracepath
 * Copyright (C) Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>.
 */

struct probehdr
{
  uint32_t ttl;
  struct timeval tv;
};

const char *
format_extended_socket_error (int fd, int* mtu)
{
  int res;
  struct probehdr rcvbuf;
  struct iovec iov;
  struct msghdr msg;
  struct cmsghdr *cmsg;
  struct sock_extended_err *e;
  struct sockaddr_in addr;
  struct buffer out = alloc_buf_gc (512);
  char cbuf[512];

  *mtu = 0;

  while (true)
    {
      memset (&rcvbuf, -1, sizeof (rcvbuf));
      iov.iov_base = &rcvbuf;
      iov.iov_len = sizeof (rcvbuf);
      msg.msg_name = (uint8_t *) &addr;
      msg.msg_namelen = sizeof (addr);
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
      msg.msg_flags = 0;
      msg.msg_control = cbuf;
      msg.msg_controllen = sizeof (cbuf);

      res = recvmsg (fd, &msg, MSG_ERRQUEUE);
      if (res < 0)
	goto exit;

      e = NULL;

      for (cmsg = CMSG_FIRSTHDR (&msg); cmsg; cmsg = CMSG_NXTHDR (&msg, cmsg))
	{
	  if (cmsg->cmsg_level == SOL_IP)
	    {
	      if (cmsg->cmsg_type == IP_RECVERR)
		{
		  e = (struct sock_extended_err *) CMSG_DATA (cmsg);
		}
	      else
		{
		  buf_printf (&out ,"CMSG=%d|", cmsg->cmsg_type);
		}
	    }
	}
      if (e == NULL)
	{
	  buf_printf (&out, "NO-INFO|");
	  goto exit;
	}

      switch (e->ee_errno)
	{
	case ETIMEDOUT:
	  buf_printf (&out, "ETIMEDOUT|");
	  break;
	case EMSGSIZE:
	  buf_printf (&out, "EMSGSIZE Path-MTU=%d|", e->ee_info);
	  *mtu = e->ee_info;
	  break;
	case ECONNREFUSED:
	  buf_printf (&out, "ECONNREFUSED|");
	  break;
	case EPROTO:
	  buf_printf (&out, "EPROTO|");
	  break;
	case EHOSTUNREACH:
	  buf_printf (&out, "EHOSTUNREACH|");
	  break;
	case ENETUNREACH:
	  buf_printf (&out, "ENETUNREACH|");
	  break;
	case EACCES:
	  buf_printf (&out, "EACCES|");
	  break;
	default:
	  buf_printf (&out, "UNKNOWN|");
	  break;
	}
    }

 exit:
  buf_chomp (&out, '|');
  return BSTR (&out);
}

void
set_sock_extended_error_passing (int sd)
{
  int on = 1;
  if (setsockopt (sd, SOL_IP, IP_RECVERR, &on, sizeof (on)))
    msg (M_WARN | M_ERRNO,
	 "Note: enable extended error passing on UDP socket failed (IP_RECVERR)");
}

#endif
