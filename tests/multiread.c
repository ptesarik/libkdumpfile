/* Multi-threaded data read.
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
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <kdumpfile.h>

#include "testutil.h"

#define DEFITER		1000
#define DEFTHREADS	1

static unsigned long base_pfn, npages;
static unsigned long niter = DEFITER;

static void *
run_reads(void *arg)
{
	kdump_ctx *ctx = arg;
	kdump_attr_t attr;
	unsigned page_shift;
	unsigned long pfn;
	char buf[1];
	size_t sz;
	unsigned i;
	kdump_status res;

	res = kdump_get_attr(ctx, "arch.page_shift", &attr);
	if (res != kdump_ok)
		return (void*) kdump_err_str(ctx);
	page_shift = attr.val.number;

	sz = sizeof buf;
	for (i = 0; i < niter; ++i) {
		pfn = base_pfn + lrand48() % npages;
		res = kdump_read(ctx, KDUMP_MACHPHYSADDR, pfn << page_shift,
				 &buf, &sz);
		if (res != kdump_ok) {
			fprintf(stderr, "Read failed at 0x%llx\n",
				(unsigned long long) pfn << page_shift);
			return (void*) kdump_err_str(ctx);
		}
	}

	return NULL;
}

static int
run_threads(kdump_ctx *ctx, unsigned long nthreads, unsigned long cache_size)
{
	struct {
		pthread_t id;
		kdump_ctx *ctx;
	} tinfo[nthreads];
	pthread_attr_t attr;
	kdump_attr_t val;
	kdump_status res;
	unsigned i;
	int rc;

	if (cache_size) {
		val.type = kdump_number;
		val.val.number = cache_size;
		res = kdump_set_attr(ctx, "cache.size", &val);
		if (res != kdump_ok) {
			fprintf(stderr, "Cannot set cache size: %s\n",
				kdump_err_str(ctx));
			return TEST_ERR;
		}
	}

	res = pthread_attr_init(&attr);
	if (res) {
		fprintf(stderr, "pthread_attr_init: %s\n", strerror(res));
		return TEST_ERR;
	}

	for (i = 0; i < nthreads; ++i) {
		tinfo[i].ctx = kdump_clone(ctx);
		if (!tinfo[i].ctx) {
			fprintf(stderr, "Cannot allocate clone: %s\n",
				strerror(res));
			return TEST_ERR;
		}

		res = pthread_create(&tinfo[i].id, &attr, run_reads,
				     tinfo[i].ctx);
		if (res) {
			fprintf(stderr, "pthread_create: %s\n", strerror(res));
			return TEST_ERR;
		}
	}

	rc = TEST_OK;
	for (i = 0; i < nthreads; ++i) {
		void *retval;
		res = pthread_join(tinfo[i].id, &retval);
		if (res) {
			fprintf(stderr, "pthread_join: %s\n", strerror(res));
			return TEST_ERR;
		}
		if (retval) {
			fprintf(stderr, "Thread %u failed: %s\n",
				i, (const char*) retval);
			rc = TEST_FAIL;
		}
		kdump_free(tinfo[i].ctx);
	}

	return rc;
}

static int
run_threads_fd(int fd, unsigned long nthreads, unsigned long cache_size)
{
	kdump_ctx *ctx;
	kdump_status res;
	int rc;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	res = kdump_set_fd(ctx, fd);
	if (res != kdump_ok) {
		fprintf(stderr, "Cannot open dump: %s\n", kdump_err_str(ctx));
		rc = TEST_ERR;
	} else
		rc = run_threads(ctx, nthreads, cache_size);

	kdump_free(ctx);
	return rc;
}

static void
usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [<options>] <dump> <base-pfn> <num-pages>\n"
		"\n"
		"Options:\n"
		"  -i iterations   Number of reads per thread (default: %u)\n"
		"  -n num-threads  Number of threads (default: %u)\n"
		"  -s cache-size   Cache size\n"
		"  -t timeout      Maximum execution time in seconds\n",
		name, DEFITER, DEFTHREADS);
}

int
main(int argc, char **argv)
{
	struct timespec ts;
	unsigned long nthreads, cache_size, timeout;
	char *p;
	int opt;
	int fd;
	int rc;

	nthreads = DEFTHREADS;
	cache_size = 0;
	timeout = 0;
	while ((opt = getopt(argc, argv, "hi:n:s:t:")) != -1) {
		switch (opt) {
		case 'i':
			niter = strtoul(optarg, &p, 0);
			if (*p) {
				fprintf(stderr, "Invalid number: %s\n", optarg);
				return TEST_ERR;
			}
			break;

		case 'n':
			nthreads = strtoul(optarg, &p, 0);
			if (*p) {
				fprintf(stderr, "Invalid number: %s\n", optarg);
				return TEST_ERR;
			}
			break;

		case 's':
			cache_size = strtoul(optarg, &p, 0);
			if (*p) {
				fprintf(stderr, "Invalid number: %s\n", optarg);
				return TEST_ERR;
			}
			break;

		case 't':
			timeout = strtoul(optarg, &p, 0);
			if (*p) {
				fprintf(stderr, "Invalid number: %s\n", optarg);
				return TEST_ERR;
			}
			break;


		case 'h':
		default:
			usage(argv[0]);
			return (opt == 'h') ? TEST_OK : TEST_ERR;
		}
	}

	if (argc - optind != 3) {
		usage(argv[0]);
		return TEST_ERR;
	}

	base_pfn = strtoul(argv[optind+1], &p, 0);
	if (*p) {
		fprintf(stderr, "Invalid number: %s\n", argv[optind+1]);
		return TEST_ERR;
	}
	npages = strtoul(argv[optind+2], &p, 0);
	if (*p) {
		fprintf(stderr, "Invalid number: %s\n", argv[optind+2]);
		return TEST_ERR;
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open dump");
		return TEST_ERR;
	}

	clock_gettime(CLOCK_REALTIME, &ts);
	srand48(ts.tv_nsec);

	if (timeout)
		alarm(timeout);

	rc = run_threads_fd(fd, nthreads, cache_size);

	if (close(fd) < 0) {
		perror("close dump");
		rc = TEST_ERR;
	}

	return rc;
}
