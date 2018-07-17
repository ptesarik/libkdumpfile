/* Data read using multiple translations.
   Copyright (C) 2018 Petr Tesarik <ptesarik@suse.com>

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
#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

#define CHUNKSZ 256
#define BYTES_PER_LINE 16

static unsigned long long rootpgt1, rootpgt2;
static unsigned long long addr = 0;
static unsigned long len = sizeof(long);

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
	const char *opts;
	unsigned char buf[CHUNKSZ];
	size_t sz, remain;
	kdump_status res;
	int iserr;
	int rc = TEST_OK;

	res = kdump_get_string_attr(ctx, "addrxlat.opts.post", &opts);
	if (res == KDUMP_OK)
		printf("%s\n", opts);
	else
		fprintf(stderr, "WARNING: Cannot get %s: %s\n",
			"addrxlat.opts.post", kdump_get_err(ctx));

	iserr = 0;
	while (len > 0) {
		sz = (len >= CHUNKSZ) ? CHUNKSZ : len;
		len -= sz;

		remain = sz;
		while (remain) {
			sz = remain;
			res = kdump_read(ctx, KDUMP_KVADDR, addr, buf, &sz);
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

static int
dump_ctx(kdump_ctx_t *ctx, unsigned long long rootpgt)
{
	char opts[256];
	kdump_status res;

	sprintf(opts, "rootpgt=MACHPHYSADDR:0x%llx", rootpgt);
	res = kdump_set_string_attr(ctx, "addrxlat.opts.post", opts);
	if (res != KDUMP_OK) {
		fprintf(stderr, "Cannot set option: %s\n", kdump_get_err(ctx));
		return TEST_ERR;
	}

	return dump_data(ctx, addr, len);
}

static int
read_ctx(kdump_ctx_t *ctx)
{
	kdump_ctx_t *clonectx;
	int res;

	puts("Using first root page table:");
	res = dump_ctx(ctx, rootpgt1);
	if (res != TEST_OK)
		return res;

	clonectx = kdump_clone(ctx, KDUMP_CLONE_ALL & ~KDUMP_CLONE_XLAT);
	if (!clonectx) {
		fputs("Cannot clone context\n", stderr);
		return TEST_OK;
	}

	puts("Using second root page table on a cloned context:");
	res = dump_ctx(clonectx, rootpgt2);
	if (res != TEST_OK)
		goto out_free;

	puts("Using original context again:");
	res = dump_data(ctx, addr, len);
	if (res != TEST_OK)
		goto out_free;

	puts("Reinitialized original context:");
	res = dump_ctx(ctx, rootpgt1);
	if (res != TEST_OK)
		goto out_free;

	puts("Using cloned context again:");
	res = dump_data(clonectx, addr, len);

 out_free:
	kdump_free(clonectx);
	return res;
}

static int
read_fd(int fd)
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
	} else
		rc = read_ctx(ctx);

	kdump_free(ctx);
	return rc;
}

static void
usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [<options>] <dump>\n"
		"\n"
		"Options:\n"
		"  -1 paddr   First root page table\n"
		"  -2 paddr   Second root page table\n"
		"  -a addr    Read start address (default: 0)\n"
		"  -l len     Number of bytes to read (default: %lu)\n",
		name, len);
}

int
main(int argc, char **argv)
{
	int opt;
	int fd;
	int rc;

	while ((opt = getopt(argc, argv, "h1:2:a:l:")) != -1) {
		char *p;
		switch (opt) {
		case '1':
			rootpgt1 = strtoull(optarg, &p, 0);
			if (*p) {
				fprintf(stderr, "Invalid number: %s\n", optarg);
				return TEST_ERR;
			}
			break;

		case '2':
			rootpgt2 = strtoull(optarg, &p, 0);
			if (*p) {
				fprintf(stderr, "Invalid number: %s\n", optarg);
				return TEST_ERR;
			}
			break;

		case 'a':
			addr = strtoull(optarg, &p, 0);
			if (*p) {
				fprintf(stderr, "Invalid number: %s\n", optarg);
				return TEST_ERR;
			}
			break;

		case 'l':
			len = strtoul(optarg, &p, 0);
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

	if (argc - optind != 1) {
		usage(argv[0]);
		return TEST_ERR;
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open dump");
		return TEST_ERR;
	}

	rc = read_fd(fd);

	if (close(fd) < 0) {
		perror("close dump");
		rc = TEST_ERR;
	}

	return rc;
}
