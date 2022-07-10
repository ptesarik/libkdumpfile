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
#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

#define CHUNKSZ 256
#define BYTES_PER_LINE 16

static const char *ostype = NULL;
static unsigned long valsz = 1;
static int zero_excluded;

static inline int
endofline(unsigned long long addr)
{
	return (addr % BYTES_PER_LINE == 0);
}

static inline char
separator(unsigned long long addr)
{
	return endofline(addr) ? '\n' : ' ';
}

static void
dump_buffer(kdump_ctx_t *ctx, unsigned long long addr,
	    unsigned char *buf, size_t len)
{
	switch (valsz) {
	case 8:
		while (len >= 8) {
			printf("%016"PRIXFAST64"%c",
			       kdump_d64toh(ctx, *(uint64_t*)buf),
			       separator((addr += 8) & -8ULL));
			buf += 8;
			len -= 8;
		}
		break;

	case 4:
		while (len >= 4) {
			printf("%08"PRIXFAST32"%c",
			       kdump_d32toh(ctx, *(uint32_t*)buf),
			       separator((addr += 4) & -4ULL));
			buf += 4;
			len -= 4;
		}
		break;

	case 2:
		while (len >= 2) {
			printf("%04"PRIXFAST16"%c",
			       kdump_d16toh(ctx, *(uint16_t*)buf),
			       separator((addr += 2) & -2ULL));
			buf += 2;
			len -= 2;
		}
		break;
	}

	while (len--)
		printf("%02X%c", *buf++, separator(++addr));
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
			dump_buffer(ctx, addr, buf, sz);
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
					--remain;
					printf("??%c", separator(++addr));
				}
			} else
				iserr = 0;
		}
	}

	if (!endofline(addr))
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

	if (ostype) {
		res = kdump_set_string_attr(ctx, KDUMP_ATTR_OSTYPE, ostype);
		if (res != KDUMP_OK) {
			fprintf(stderr, "Cannot set OS type: %s\n",
				kdump_get_err(ctx));
			goto err;
		}
	}

	if (zero_excluded) {
		res = kdump_set_number_attr(ctx, KDUMP_ATTR_ZERO_EXCLUDED, 1);
		if (res != KDUMP_OK) {
			fprintf(stderr, "Cannot set zero_excluded: %s\n",
				kdump_get_err(ctx));
			goto err;
		}
	}

	res = kdump_open_fd(ctx, fd);
	if (res != KDUMP_OK) {
		fprintf(stderr, "Cannot open dump: %s\n", kdump_get_err(ctx));
		goto err;
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

			rc = dump_data(ctx, as, addr, len * valsz);
			if (rc != KDUMP_OK)
				break;
			argv += 2;
		}
	}

	kdump_free(ctx);
	return rc;

 err:
	kdump_free(ctx);
	return TEST_ERR;
}

static void
usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [<options>] <dump> <addr> <len> [...]\n"
		"\n"
		"Options:\n"
		"  -o ostype  Set OS type\n"
		"  -s size    Set value size in bytes\n"
		"  -z         Fill excluded pages with zeroes\n",
		name);
}

int
main(int argc, char **argv)
{
	char *endp;
	int opt;
	int fd;
	int rc;

	while ((opt = getopt(argc, argv, "ho:s:z")) != -1) {
		switch (opt) {
		case 'o':
			ostype = optarg;
			break;

		case 's':
			valsz = strtoul(optarg, &endp, 0);
			if (endp == optarg || *endp ||
			    (valsz != 1 && valsz != 2 &&
			     valsz != 4 && valsz != 8)) {
				fprintf(stderr, "Invalid size: %s\n", optarg);
				return TEST_ERR;
			}
			break;

		case 'z':
			zero_excluded = 1;
			break;

		case 'h':
		default:
			usage(argv[0]);
			return (opt == 'h') ? TEST_OK : TEST_ERR;
		}
	}

	if ((argc - optind) < 3 || (argc - optind) % 2 != 1) {
		usage(argv[0]);
		return TEST_ERR;
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open dump");
		return TEST_ERR;
	}

	rc = dump_data_fd(fd, argv + optind + 1);

	if (close(fd) < 0) {
		perror("close dump");
		rc = TEST_ERR;
	}

	return rc;
}
