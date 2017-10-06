/** @internal @file src/test-fcache.c
 * @brief Test file cache.
 */
/* Copyright (C) 2017 Petr Tesarik <ptesarik@suse.com>

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

#define _GNU_SOURCE

#include "kdumpfile-priv.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dlfcn.h>

#define TEST_OK     0
#define TEST_FAIL   1
#define TEST_ERR   99

#define TEST_FNAME	"tmp.fcache"

/** Number of elements in the test cache. */
#define CACHE_SIZE	4

/** Cache element size as page order. */
#define CACHE_ORDER	2

static int exitcode;

static unsigned long pagesize;

static int dumpfd;

static char *mmapbuf;

static int failmmap;

static void* (*orig_mmap)(void *addr, size_t length, int prot, int flags,
			  int fd, off_t offset);

void *
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	if (fd == dumpfd) {
		if (failmmap)
			return MAP_FAILED;

		if (length != pagesize * (1UL << CACHE_ORDER)) {
			fprintf(stderr, "Incorrect mmap size: %zu\n",
				length);
			exitcode = TEST_FAIL;
			return MAP_FAILED;
		}
	}

	return orig_mmap(addr, length, prot, flags, fd, offset);
}

static void
prepare_buf(unsigned startpg, unsigned numpg)
{
	int pg, i;
	char *p = mmapbuf;

	for (pg = startpg; pg < startpg + numpg; ++pg)
		for (i = 0; i < pagesize; ++i)
			*p++ = i ^ pg;
}

static int
test_basic(struct fcache *fc)
{
	off_t pos;
	struct fcache_entry ent, ent2;
	kdump_status status;

	exitcode = TEST_OK;

	/* Test mmap at file position 0. */
	pos = 0;
	failmmap = 0;
	status = fcache_get(fc, &ent, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get entry at %ld: %s\n",
			(long)pos, kdump_strerror(status));
		return TEST_ERR;
	}

	if (ent.len != pagesize << CACHE_ORDER) {
		printf("length at %ld: %zu != %lu\n",
		       (long)pos, ent.len, pagesize << CACHE_ORDER);
		exitcode = TEST_FAIL;
	}
	prepare_buf(0, 1UL << CACHE_ORDER);
	if (memcmp(ent.data, mmapbuf, ent.len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}

	/* Test non-aligned position. */
	pos = 1;
	failmmap = 0;
	status = fcache_get(fc, &ent2, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get entry at %ld: %s\n",
			(long)pos, kdump_strerror(status));
		return TEST_ERR;
	}

	if (ent2.len != (pagesize << CACHE_ORDER) - 1) {
		printf("length at %ld: %zu != %lu\n",
		       (long)pos, ent.len, (pagesize << CACHE_ORDER) - 1);
		exitcode = TEST_FAIL;
	}
	if (ent2.data != ent.data + 1) {
		printf("data pointer mismatch at %ld: %p != %p\n",
		       (long)pos, ent2.data, ent.data + 1);
		exitcode = TEST_FAIL;
	}

	fcache_put(&ent);
	fcache_put(&ent2);

	/* Test read at file position 0. */
	pos = pagesize << CACHE_ORDER;
	failmmap = 1;
	status = fcache_get(fc, &ent, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get entry at %ld: %s\n",
			(long)pos, kdump_strerror(status));
		return TEST_ERR;
	}

	if (ent.len != pagesize) {
		printf("length at %ld: %zu != %lu\n",
		       (long)pos, ent.len, pagesize);
		exitcode = TEST_FAIL;
	}
	prepare_buf(1UL << CACHE_ORDER, 1);
	if (memcmp(ent.data, mmapbuf, ent.len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}

	/* Check that fallback cache works properly. */
	++pos;
	failmmap = 0;
	status = fcache_get(fc, &ent2, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get entry at %ld: %s\n",
			(long)pos, kdump_strerror(status));
		return TEST_ERR;
	}

	if (ent2.len != pagesize - 1) {
		printf("length at %ld: %zu != %lu\n",
		       (long)pos, ent2.len, pagesize);
		exitcode = TEST_FAIL;
	}
	if (ent2.data != ent.data + 1) {
		printf("data pointer mismatch at %ld: %p != %p\n",
		       (long)pos, ent2.data, ent.data + 1);
		exitcode = TEST_FAIL;
	}

	fcache_put(&ent);
	fcache_put(&ent2);

	/* Check that mmap failures are persistent. */
	failmmap = 0;
	pos = (pagesize << CACHE_ORDER) + pagesize;
	status = fcache_get(fc, &ent, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get entry at %ld: %s\n",
			(long)pos, kdump_strerror(status));
		return TEST_ERR;
	}

	if (ent.len != pagesize) {
		printf("length at %ld: %zu != %lu\n",
		       (long)pos, ent.len, pagesize);
		exitcode = TEST_FAIL;
	}
	prepare_buf((1UL << CACHE_ORDER) + 1, 1);
	if (memcmp(ent.data, mmapbuf, ent.len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}

	fcache_put(&ent);

	/* Check partial read at EOF. */
	failmmap = 0;
	pos = (pagesize << CACHE_ORDER) + 2 * pagesize;
	status = fcache_get(fc, &ent, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get entry at %ld: %s\n",
			(long)pos, kdump_strerror(status));
		return TEST_ERR;
	}

	if (ent.len != pagesize) {
		printf("length at %ld: %zu != %lu\n",
		       (long)pos, ent.len, pagesize);
		exitcode = TEST_FAIL;
	}
	prepare_buf((1UL << CACHE_ORDER) + 2, 1);
	memset(mmapbuf + (pagesize >> 1), 0, pagesize >> 1);
	if (memcmp(ent.data, mmapbuf, ent.len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}

	fcache_put(&ent);

	return exitcode;
}

static int
test_chunks(struct fcache *fc)
{
	off_t pos;
	size_t len;
	struct fcache_chunk fch;
	kdump_status status;

	/* Check a single-block chunk. */
	pos = 0;
	len = 16;
	status = fcache_get_chunk(fc, &fch, len, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get %zd-byte chunk at %ld: %s\n",
			len, (long)pos, kdump_strerror(status));
		return TEST_ERR;
	}
	prepare_buf(0, 1);
	if (memcmp(fch.data, mmapbuf + pos, len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}
	fcache_put_chunk(&fch);

	/* Check a single-block chunk at non-zero block offset. */
	pos = 8;
	len = 16;
	status = fcache_get_chunk(fc, &fch, len, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get %zd-byte chunk at %ld: %s\n",
			len, (long)pos, kdump_strerror(status));
		return TEST_ERR;
	}
	prepare_buf(0, 1);
	if (memcmp(fch.data, mmapbuf + pos, len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}
	fcache_put_chunk(&fch);

	/* Check a small chunk that crosses a block boundary. */
	pos = (pagesize << CACHE_ORDER) - 8;
	len = 16;
	status = fcache_get_chunk(fc, &fch, len, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get %zd-byte chunk at %ld: %s\n",
			len, (long)pos, kdump_strerror(status));
		return TEST_ERR;
	}
	prepare_buf((1UL << CACHE_ORDER) - 1, 2);
	if (memcmp(fch.data, mmapbuf + pagesize - 8, len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}
	fcache_put_chunk(&fch);

	/* Check a small combined chunk. */
	pos = (pagesize << CACHE_ORDER) + pagesize - 8;
	len = 16;
	status = fcache_get_chunk(fc, &fch, len, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get %zd-byte chunk at %ld: %s\n",
			len, (long)pos, kdump_strerror(status));
		return TEST_ERR;
	}
	prepare_buf((1UL << CACHE_ORDER), 2);
	if (memcmp(fch.data, mmapbuf + pagesize - 8, len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}
	fcache_put_chunk(&fch);

	/* Check a large combined chunk. */
	pos = (pagesize << CACHE_ORDER) + pagesize - 8;
	len = pagesize + 16;
	status = fcache_get_chunk(fc, &fch, len, pos);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get %zd-byte chunk at %ld: %s\n",
			len, (long)pos, kdump_strerror(status));
		return TEST_ERR;
	}
	prepare_buf((1UL << CACHE_ORDER), 3);
	if (memcmp(fch.data, mmapbuf + pagesize - 8, len)) {
		printf("data mismatch at %ld\n", (long)pos);
		exitcode = TEST_FAIL;
	}
	fcache_put_chunk(&fch);

	return exitcode;
}

static int
test_fcache(struct fcache *fc)
{
	int ret, ret2;

	ret = test_basic(fc);
	ret2 = test_chunks(fc);
	if (ret < ret2)
		ret = ret2;
	return ret;
}

static int
write_dump(int fd)
{
	ssize_t wr;

	prepare_buf(0, 1UL << CACHE_ORDER);
	wr = write(fd, mmapbuf, pagesize << CACHE_ORDER);
	if (wr != pagesize << CACHE_ORDER) {
		perror("Cannot write dump");
		return TEST_ERR;
	}

	prepare_buf(1UL << CACHE_ORDER, 1);
	wr = write(fd, mmapbuf, pagesize);
	if (wr != pagesize) {
		perror("Cannot write dump");
		return TEST_ERR;
	}

	prepare_buf((1UL << CACHE_ORDER) + 1, 1);
	wr = write(fd, mmapbuf, pagesize);
	if (wr != pagesize) {
		perror("Cannot write dump");
		return TEST_ERR;
	}

	prepare_buf((1UL << CACHE_ORDER) + 2, 1);
	wr = write(fd, mmapbuf, pagesize >> 1);
	if (wr != pagesize >> 1) {
		perror("Cannot write dump");
		return TEST_ERR;
	}

	return TEST_OK;
}

int
main(int argc, char **argv)
{
	struct fcache *fc;
	int ret;

	pagesize = sysconf(_SC_PAGESIZE);

	mmapbuf = malloc(pagesize << CACHE_ORDER);
	if (!mmapbuf) {
		perror("Cannot allocate mmap buffer");
		return TEST_ERR;
	}

	orig_mmap = dlsym(RTLD_NEXT, "mmap");
	if (!orig_mmap) {
		fprintf(stderr, "Cannot get original mmap() address: %s\n",
			dlerror());
		return TEST_ERR;
	}

	dumpfd = open(TEST_FNAME, O_RDWR | O_TRUNC | O_CREAT, 0666);
	if (dumpfd < 0) {
		perror("Cannot open test file");
		return TEST_ERR;
	}
	ret = write_dump(dumpfd);
	if (ret != TEST_OK) {
		close(dumpfd);
		return ret;
	}

	fc = fcache_new(dumpfd, CACHE_SIZE, CACHE_ORDER);
	if (!fc) {
		perror("Allocation failure");
		close(dumpfd);
		return TEST_ERR;
	}

	ret = test_fcache(fc);
	fcache_free(fc);
	close(dumpfd);
	return ret;
}
