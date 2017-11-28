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
#include <string.h>
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
dump_data(kdump_ctx_t *ctx, kdump_addrspace_t as, unsigned long long addr,
	  unsigned long long len)
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
			res = kdump_read(ctx, as, addr, buf, &sz);
			dump_buffer(addr, buf, sz);
			addr += sz;
			remain -= sz;
			if (res != KDUMP_OK) {
				if (!iserr) {
					fprintf(stderr,
						"Read failed at 0x%llx: %s\n",
						addr, kdump_get_err(ctx));
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

static addrxlat_addrspace_t
get_addrspace(const char *p, const char *endp)
{
	if (!strncasecmp(p, "KPHYSADDR:", endp - p))
		return KDUMP_KPHYSADDR;
	else if (!strncasecmp(p, "MACHPHYSADDR:", endp - p))
		return KDUMP_MACHPHYSADDR;
	else if (!strncasecmp(p, "KVADDR:", endp - p))
		return KDUMP_KVADDR;
	else
		return (addrxlat_addrspace_t)-1;
}

static int
dump_data_fd(int fd, char **argv)
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
	if (res != KDUMP_OK) {
		fprintf(stderr, "Cannot open dump: %s\n", kdump_get_err(ctx));
		rc = TEST_ERR;
	} else {
		kdump_addrspace_t as;
		unsigned long long addr, len;
		char *endp;

		while (*argv) {
			endp = strchr(argv[0], ':');
			if (endp) {
				as = get_addrspace(argv[0], endp);
				if (as == -1) {
					fprintf(stderr, "Invalid address space spec: %s\n",
						argv[0]);
					return TEST_ERR;
				}
				++endp;
			} else {
				as = KDUMP_MACHPHYSADDR;
				endp = argv[0];
			}

			addr = strtoull(endp, &endp, 0);
			if (*endp) {
				fprintf(stderr, "Invalid address: %s\n",
					argv[0]);
				return TEST_ERR;
			}

			len = strtoull(argv[1], &endp, 0);
			if (*endp) {
				fprintf(stderr, "Invalid length: %s\n",
					argv[1]);
				return TEST_ERR;
			}

			rc = dump_data(ctx, as, addr, len);
			if (rc != KDUMP_OK)
				break;
			argv += 2;
		}
	}

	kdump_free(ctx);
	return rc;
}

int
main(int argc, char **argv)
{
	int fd;
	int rc;

	if (argc < 4 || argc % 2 != 0) {
		fprintf(stderr, "Usage: %s <dump> <addr> <len> [...]\n",
			argv[0]);
		return TEST_ERR;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open dump");
		return TEST_ERR;
	}

	rc = dump_data_fd(fd, argv + 2);

	if (close(fd) < 0) {
		perror("close dump");
		rc = TEST_ERR;
	}

	return rc;
}
