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

#ifndef THREAD_H
#define THREAD_H

#include "basic.h"
#include "common.h"

#ifdef USE_PTHREAD

extern pthread_t _main_thread_id;
extern pthread_t _work_thread_id;
extern pthread_mutex_t _lock_cs[N_MUTEXES];
extern bool _lock_cs_init;

#define MAIN_THREAD 0
#define WORK_THREAD 1
#define N_THREADS   2

#define MUTEX_DEFINE_STATIC(lock)  static pthread_mutex_t lock
#define MUTEX_DEFINE(lock)         pthread_mutex_t lock
#define MUTEX_INIT(lock)           pthread_mutex_init(&lock, NULL)
#define MUTEX_DESTROY(lock)        pthread_mutex_destroy(&lock)
#define MUTEX_LOCK(lock)           pthread_mutex_lock (&lock)
#define MUTEX_UNLOCK(lock)         pthread_mutex_unlock (&lock)

static inline int
thread_number()
{
  return (!_main_thread_id || pthread_self () == _main_thread_id) ? MAIN_THREAD : WORK_THREAD;
}

static inline void
mutex_lock (int type)
{
  if (_lock_cs_init)
    {
      pthread_mutex_lock (&(_lock_cs[type]));
    }
}

static inline void
mutex_unlock (int type)
{
  if (_lock_cs_init)
    {
      pthread_mutex_unlock (&(_lock_cs[type]));

#if 0
      /* DEBUGGING -- if lock bugs exist, make them more likely to occur */
      {
	if (thread_number() == WORK_THREAD)
	  sleep (0);
      }
#endif
    }
}

static inline void
mutex_cycle (int type)
{
  if (_lock_cs_init)
    {
      pthread_mutex_unlock (&(_lock_cs[type]));
      sleep (0);
      pthread_mutex_lock (&(_lock_cs[type]));
    }
}

void thread_init();
void thread_cleanup();

void work_thread_create (void *(*start_routine) (void *), void* arg);
void work_thread_join ();

#else /* USE_PTHREAD */

#define N_THREADS 1

#define MUTEX_DEFINE_STATIC(lock)
#define MUTEX_DEFINE(lock)
#define MUTEX_INIT(lock)
#define MUTEX_DESTROY(lock)
#define MUTEX_LOCK(lock)
#define MUTEX_UNLOCK(lock)

static inline void
thread_init()
{
}

static inline void
thread_cleanup()
{
}

static inline int
thread_number()
{
  return 0;
}

static inline void
work_thread_create (void *(*start_routine) (void *), void* arg)
{
}

static inline void
work_thread_join ()
{
}

static inline void
mutex_lock (int type)
{
}

static inline void
mutex_unlock (int type)
{
}

static inline void
mutex_cycle (int type)
{
}

#endif /* USE_PTHREAD */

#endif /* THREAD_H */
