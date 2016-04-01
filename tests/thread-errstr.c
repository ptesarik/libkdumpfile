/* Check per-thread error strings.
   Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <kdumpfile.h>

#include "testutil.h"

static pthread_mutex_t attr_mutex = PTHREAD_MUTEX_INITIALIZER;

static enum {
	state_get_nokey,
	state_get_nodata,
	state_check_nokey,
	state_check_nodata
} state = state_get_nokey;

static pthread_cond_t state_cond = PTHREAD_COND_INITIALIZER;

static void *
get_nokey(void *arg)
{
	kdump_ctx *ctx = arg;
	kdump_attr_t attr;
	kdump_status res;
	char *err, *ret;

	pthread_mutex_lock(&attr_mutex);

	res = kdump_get_attr(ctx, "non.existent", &attr);
	if (res == kdump_ok)
		return (void*) "non.existent is a valid key?!";
	else if (res != kdump_nokey)
		return (void*) kdump_err_str(ctx);

	err = strdup(kdump_err_str(ctx));
	if (!err)
		return (void*) "Cannot copy error string";

	state = state_get_nodata;
	pthread_cond_signal(&state_cond);
	while (state != state_check_nokey)
		pthread_cond_wait(&state_cond, &attr_mutex);

	ret = NULL;
	if (strcmp(err, kdump_err_str(ctx))) {
		fprintf(stderr, "nokey: '%s' != '%s'\n",
			err, kdump_err_str(ctx));
		ret = "kdump_nokey error string has changed";
	}

	state = state_check_nodata;
	pthread_cond_signal(&state_cond);

	pthread_mutex_unlock(&attr_mutex);

	free(err);
	return ret;
}

static void *
get_novalue(void *arg)
{
	kdump_ctx *ctx = arg;
	kdump_attr_t attr;
	kdump_status res;
	char *err, *ret;

	pthread_mutex_lock(&attr_mutex);

	while (state != state_get_nodata)
		pthread_cond_wait(&state_cond, &attr_mutex);

	res = kdump_get_attr(ctx, "xen.type", &attr);
	if (res == kdump_ok)
		return (void*) "xen.type has a value?!";
	else if (res != kdump_nodata)
		return (void*) kdump_err_str(ctx);

	err = strdup(kdump_err_str(ctx));
	if (!err)
		return (void*) "Cannot copy error string";

	state = state_check_nokey;
	pthread_cond_signal(&state_cond);
	while (state != state_check_nodata)
		pthread_cond_wait(&state_cond, &attr_mutex);

	ret = NULL;
	if (strcmp(err, kdump_err_str(ctx))) {
		fprintf(stderr, "nodata: '%s' != '%s'\n",
			err, kdump_err_str(ctx));
		ret = "kdump_nodata error string has changed";
	}

	pthread_mutex_unlock(&attr_mutex);

	free(err);
	return ret;
}

static int
run_threads(kdump_ctx *ctx)
{
	struct {
		pthread_t id;
		kdump_ctx *ctx;
	} tinfo[2];
	pthread_attr_t attr;
	unsigned i;
	int res, rc;
	kdump_status status;

	res = pthread_attr_init(&attr);
	if (res) {
		fprintf(stderr, "pthread_attr_init: %s\n", strerror(res));
		return TEST_ERR;
	}

	if (! (tinfo[0].ctx = kdump_alloc()) ) {
		fprintf(stderr, "Cannot allocate clone: %s\n", strerror(res));
		return TEST_ERR;
	}
	status = kdump_clone(tinfo[0].ctx, ctx);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot initialize clone: %s\n",
			kdump_err_str(tinfo[0].ctx));
		return TEST_ERR;
	}
	res = pthread_create(&tinfo[0].id, &attr, get_nokey, tinfo[0].ctx);
	if (res) {
		fprintf(stderr, "pthread_create: %s\n", strerror(res));
		return TEST_ERR;
	}

	if (! (tinfo[1].ctx = kdump_alloc()) ) {
		fprintf(stderr, "Cannot allocate clone: %s\n", strerror(res));
		return TEST_ERR;
	}
	status = kdump_clone(tinfo[1].ctx, ctx);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot initialize clone: %s\n",
			kdump_err_str(tinfo[1].ctx));
		return TEST_ERR;
	}
	res = pthread_create(&tinfo[1].id, &attr, get_novalue, tinfo[1].ctx);
	if (res) {
		fprintf(stderr, "pthread_create: %s\n", strerror(res));
		return TEST_ERR;
	}

	rc = TEST_OK;
	for (i = 0; i < ARRAY_SIZE(tinfo); ++i) {
		void *retval;
		res = pthread_join(tinfo[i].id, &retval);
		kdump_free(tinfo[i].ctx);
		if (res) {
			fprintf(stderr, "pthread_join: %s\n", strerror(res));
			return TEST_ERR;
		}
		if (retval) {
			fprintf(stderr, "Thread %u failed: %s\n",
				i, (const char*) retval);
			rc = TEST_FAIL;
		}
	}

	return rc;
}

int
main(int argc, char **argv)
{
	kdump_ctx *ctx;
	int rc;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	rc = run_threads(ctx);

	kdump_free(ctx);
	return rc;
}
