/** @internal @file src/threads.h
 * @brief POSIX threads wrappers, or stubs.
 */
/* Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   libkdumpfile is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _THREADS_H
#define _THREADS_H	1

/* Multi-threading */
#if USE_PTHREAD

#include <pthread.h>

typedef pthread_mutex_t mutex_t;
typedef pthread_mutexattr_t mutexattr_t;

static inline int
mutex_init(mutex_t *mutex, const mutexattr_t *attr)
{
	return pthread_mutex_init(mutex, attr);
}

static inline int
mutex_destroy(mutex_t *mutex)
{
	return pthread_mutex_destroy(mutex);
}

static inline int
mutex_lock(mutex_t *mutex)
{
	return pthread_mutex_lock(mutex);
}

static inline int
mutex_trylock(mutex_t *mutex)
{
	return pthread_mutex_trylock(mutex);
}

static inline int
mutex_unlock(mutex_t *mutex)
{
	return pthread_mutex_unlock(mutex);
}

#else  /* USE_PTHREAD */

typedef struct { } mutex_t;
typedef struct { } mutexattr_t;

static inline int
mutex_init(mutex_t *mutex, const mutexattr_t *attr)
{
	return 0;
}

static inline int
mutex_destroy(mutex_t *mutex)
{
	return 0;
}

static inline int
mutex_lock(mutex_t *mutex)
{
	return 0;
}

static inline int
mutex_trylock(mutex_t *mutex)
{
	return 0;
}

static inline int
mutex_unlock(mutex_t *mutex)
{
	return 0;
}

#endif

#endif	/* threads.h */
