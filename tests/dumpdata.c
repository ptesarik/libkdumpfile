/* Data dumper.
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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <kdumpfile.h>

#include "testutil.h"

#define CHUNKSZ 256
#define BYTES_PER_LINE 16

static inline int
endofline(unsigned long long addr)
{
	return (addr % BYTES_PER_LINE == BYTES_PER_LINE - 1);
}

static inline char
separator(unsigned long long addr)
{
	return endofline(addr) ? '\n' : ' ';
}

static void
dump_buffer(unsigned long long addr, unsigned char *buf, size_t len)
{
	while (len--)
		printf("%02X%c", *buf++, separator(addr++));
}

static int
dump_data(kdump_ctx_t *ctx, unsigned long long addr, unsigned long long len)
{
	unsigned char buf[CHUNKSZ];
	size_t sz, remain;
	kdump_status res;
	int iserr;
	int rc = TEST_OK;

	iserr = 0;
	while (len > 0) {
		sz = (len >= CHUNKSZ) ? CHUNKSZ : len;
		len -= sz;

		remain = sz;
		while (remain) {
			sz = remain;
			res = kdump_read(ctx, KDUMP_MACHPHYSADDR, addr,
					 buf, &sz);
			dump_buffer(addr, buf, sz);
			addr += sz;
			remain -= sz;
			if (res != kdump_ok) {
				if (!iserr) {
					fprintf(stderr,
						"Read failed at 0x%llx: %s\n",
						addr, kdump_err_str(ctx));
					iserr = 1;
					rc = TEST_FAIL;
				}
				if (remain) {
					printf("??%c", separator(addr));
					++addr;
					--remain;
				}
			} else
				iserr = 0;
		}
	}

	if (!endofline(addr - 1))
		putchar('\n');

	return rc;
}

static int
dump_data_fd(int fd, unsigned long long addr, unsigned long long len)
{
	kdump_ctx_t *ctx;
	kdump_status res;
	int rc;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	res = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_FD, fd);
	if (res != kdump_ok) {
		fprintf(stderr, "Cannot open dump: %s\n", kdump_err_str(ctx));
		rc = TEST_ERR;
	} else
		rc = dump_data(ctx, addr, len);

	kdump_free(ctx);
	return rc;
}

int
main(int argc, char **argv)
{
	unsigned long long addr, len;
	char *endp;
	int fd;
	int rc;

	if (argc != 4 || !*argv[2] || !*argv[3]) {
		fprintf(stderr, "Usage: %s <dump> <addr> <len>\n", argv[0]);
		return TEST_ERR;
	}

	addr = strtoull(argv[2], &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid address: %s", argv[2]);
		return TEST_ERR;
	}

	len = strtoull(argv[3], &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid length: %s", argv[3]);
		return TEST_ERR;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open dump");
		return TEST_ERR;
	}

	rc = dump_data_fd(fd, addr, len);

	if (close(fd) < 0) {
		perror("close dump");
		rc = TEST_ERR;
	}

	return rc;
}
