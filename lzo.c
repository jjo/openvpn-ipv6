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

#ifdef WIN32
#include "config-win32.h"
#else
#include "config.h"
#endif

#ifdef USE_LZO

#include "syshead.h"

#include "lzo.h"
#include "error.h"

#include "memdbg.h"

static bool
lzo_adaptive_compress_test (struct lzo_adaptive_compress *ac, const time_t time)
{
  const bool save = ac->compress_state;

  if (!ac->enabled)
    return true;

  if (!ac->compress_state)
    {
      if (time >= ac->next)
	{
	  if (ac->n_total > AC_MIN_BYTES
	      && (ac->n_total - ac->n_comp) < (ac->n_total / (100 / AC_SAVE_PCT)))
	    {
	      ac->compress_state = true;
	      ac->next = time + AC_OFF_SEC;
	    }
	  else
	    {
	      ac->next = time + AC_SAMP_SEC;
	    }
	  msg (D_COMP, "lzo_adaptive_compress_test: comp=%d total=%d", ac->n_comp, ac->n_total);
	  ac->n_total = ac->n_comp = 0;
	}
    }
  else 
    {
      if (time >= ac->next)
	{
	  ac->next = time + AC_SAMP_SEC;
	  ac->n_total = ac->n_comp = 0;
	  ac->compress_state = false;
	}
    }

  if (ac->compress_state != save)
    msg (D_COMP_LOW, "Adaptive compression state %s", (ac->compress_state ? "OFF" : "ON"));

  return !ac->compress_state;
}

inline static void
lzo_adaptive_compress_data (struct lzo_adaptive_compress *ac, int n_total, int n_comp)
{
  if (ac->enabled)
    {
      ac->n_total += n_total;
      ac->n_comp += n_comp;
    }
}

void lzo_adjust_frame_parameters (struct frame *frame)
{
  /* Leave room for our one-byte compressed/didn't-compress flag. */
  frame_add_to_extra_frame (frame, 1);

  /* Leave room for compression buffer to expand in worst case scenario
     where data is totally uncompressible */
  frame_add_to_extra_buffer (frame, LZO_EXTRA_BUFFER (EXPANDED_SIZE(frame)));
}

void
lzo_compress_init (struct lzo_compress_workspace *lzowork, bool adaptive)
{
  CLEAR (*lzowork);

  lzowork->wmem_size = LZO_WORKSPACE;
  lzowork->ac.enabled = adaptive;

  if (lzo_init () != LZO_E_OK)
    msg (M_FATAL, "Cannot initialize LZO compression library");
  if ((lzowork->wmem = (lzo_voidp) lzo_malloc (lzowork->wmem_size)) == NULL)
    msg (M_FATAL, "Cannot allocate memory for LZO compression library");
  msg (M_INFO, "LZO compression initialized");
}

void
lzo_compress_uninit (struct lzo_compress_workspace *lzowork)
{
  lzo_free (lzowork->wmem);
  lzowork->wmem = NULL;
}

/* Magic numbers to tell our peer if we compressed or not */
#define YES_COMPRESS 0x66
#define NO_COMPRESS  0xFA

void
lzo_compress (struct buffer *buf, struct buffer work,
	      struct lzo_compress_workspace *lzowork,
	      const struct frame* frame,
	      const time_t current)
{
  int zlen = 0;
  int err;
  bool compressed = false;

  if (buf->len <= 0)
    return;

  /*
   * In order to attempt compression, length must be at least COMPRESS_THRESHOLD,
   * and our adaptive level must give the OK.
   */
  if (buf->len >= COMPRESS_THRESHOLD && lzo_adaptive_compress_test(&lzowork->ac, current))
    {
      ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));
      ASSERT (buf_safe (&work, LZO_EXTRA_BUFFER (PAYLOAD_SIZE (frame))));
      ASSERT (buf->len <= PAYLOAD_SIZE (frame));

      err = LZO_COMPRESS (BPTR (buf), BLEN (buf), BPTR (&work), &zlen, lzowork->wmem);
      if (err != LZO_E_OK)
	{
	  msg (D_COMP_ERRORS, "LZO compression error: %d", err);
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, zlen));
      work.len = zlen;
      compressed = true;

      msg (D_COMP, "compress %d -> %d", buf->len, work.len);
      lzowork->pre_compress += buf->len;
      lzowork->post_compress += work.len;

      /* tell adaptive level about our success or lack thereof in getting any size reduction */
      lzo_adaptive_compress_data(&lzowork->ac, buf->len, work.len);
    }

  /* did compression save us anything ? */
  if (compressed && work.len < buf->len)
    {
      uint8_t *header = buf_prepend (&work, 1);
      *header = YES_COMPRESS;
      *buf = work;
    }
  else
    {
      uint8_t *header = buf_prepend (buf, 1);
      *header = NO_COMPRESS;
    }
}

void
lzo_decompress (struct buffer *buf, struct buffer work,
		struct lzo_compress_workspace *lzowork,
		const struct frame* frame)
{
  int zlen = EXPANDED_SIZE (frame);
  uint8_t c;		/* flag indicating whether or not our peer compressed */
  int err;

  if (buf->len <= 0)
    return;

  ASSERT (buf_init (&work, FRAME_HEADROOM (frame)));

  c = *BPTR (buf);
  ASSERT (buf_advance (buf, 1));

  if (c == YES_COMPRESS)	/* packet was compressed */
    {
      ASSERT (buf_safe (&work, zlen));
      err = LZO_DECOMPRESS (BPTR (buf), BLEN (buf), BPTR (&work), &zlen,
			    lzowork->wmem);
      if (err != LZO_E_OK)
	{
	  msg (D_COMP_ERRORS, "LZO decompression error: %d", err);
	  buf->len = 0;
	  return;
	}

      ASSERT (buf_safe (&work, zlen));
      work.len = zlen;

      msg (D_COMP, "decompress %d -> %d", buf->len, work.len);
      lzowork->pre_decompress += buf->len;
      lzowork->post_decompress += work.len;

      *buf = work;
    }
  else if (c == NO_COMPRESS)	/* packet was not compressed */
    {
      ;
    }
  else
    {
      msg (D_COMP_ERRORS, "Bad LZO decompression header byte: %d", c);
      buf->len = 0;
    }
}

/*
 * Print statistics
 */
void lzo_print_stats (struct lzo_compress_workspace *lzo_compwork)
{
  msg (M_INFO, " pre-compress bytes:   " counter_format, lzo_compwork->pre_compress);
  msg (M_INFO, " post-compress bytes:  " counter_format, lzo_compwork->post_compress);
  msg (M_INFO, " pre-decompress bytes: " counter_format, lzo_compwork->pre_decompress);
  msg (M_INFO, " post-decompress bytes:" counter_format, lzo_compwork->post_decompress);
}

#else
static void dummy(void) {}
#endif /* USE_LZO */
