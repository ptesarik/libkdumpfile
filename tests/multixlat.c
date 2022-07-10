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

struct xlat_option {
	const char *name;
	const char *value;
};

#define MAX_OPTIONS	ADDRXLAT_OPT_NUM

static struct xlat_option options[MAX_OPTIONS];
static unsigned num_options;

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
	unsigned char buf[CHUNKSZ];
	size_t sz, remain;
	kdump_status res;
	int iserr;
	kdump_num_t rootas;
	kdump_addr_t rootaddr;
	int rc = TEST_OK;

	res = kdump_get_number_attr(
		ctx, KDUMP_ATTR_XLAT_FORCE ".rootpgt.as", &rootas);
	if (res == KDUMP_OK)
		res = kdump_get_address_attr(
			ctx, KDUMP_ATTR_XLAT_FORCE ".rootpgt.addr", &rootaddr);
	if (res == KDUMP_OK)
		printf("rootpgt=%s:0x%" KDUMP_PRIxADDR "\n",
		       addrxlat_addrspace_name(rootas), rootaddr);
	else
		fprintf(stderr, "WARNING: Cannot get %s: %s\n",
			KDUMP_ATTR_XLAT_FORCE ".rootpgt", kdump_get_err(ctx));

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
dump_ctx_dir(kdump_ctx_t *ctx, unsigned long long rootpgt,
	     const kdump_attr_ref_t *dir)
{
	kdump_status status;
	kdump_attr_t attr;
	const char *key;
	unsigned i;

	key = "rootpgt.as";
	attr.type = KDUMP_NUMBER;
	attr.val.number = ADDRXLAT_MACHPHYSADDR;
	status = kdump_set_sub_attr(ctx, dir, key, &attr);
	if (status != KDUMP_OK)
		goto err_set;

	key = "rootpgt.addr";
	attr.type = KDUMP_ADDRESS;
	attr.val.address = rootpgt;
	status = kdump_set_sub_attr(ctx, dir, key, &attr);
	if (status != KDUMP_OK)
		goto err_set;

	for (i = 0; i < num_options; ++i) {
		struct xlat_option *opt = &options[i];
		kdump_attr_ref_t ref;

		key = opt->name;
		status = kdump_sub_attr_ref(ctx, dir, key, &ref);
		if (status != KDUMP_OK)
			goto err_set;

		attr.type = kdump_attr_ref_type(&ref);
		switch (attr.type) {
		case KDUMP_STRING:
			attr.val.string = opt->value;
			break;

		case KDUMP_NUMBER:
			attr.val.number = strtoull(opt->value, NULL, 0);
			break;

		default:
			fprintf(stderr, "%s: unimplemented option type: %ld\n",
				opt->name, (long)attr.type);
			kdump_attr_unref(ctx, &ref);
			return TEST_ERR;
		}

		status = kdump_attr_ref_set(ctx, &ref, &attr);
		if (status != KDUMP_OK)
			goto err_set;

		kdump_attr_unref(ctx, &ref);
	}

	return dump_data(ctx, addr, len);

 err_set:
	fprintf(stderr, "Cannot set %s: %s\n", key, kdump_get_err(ctx));
	return TEST_ERR;
}

static int
dump_ctx(kdump_ctx_t *ctx, unsigned long long rootpgt)
{
	kdump_attr_ref_t dir;
	kdump_status status;
	int res;

	status = kdump_attr_ref(ctx, KDUMP_ATTR_XLAT_FORCE, &dir);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference %s: %s\n",
			KDUMP_ATTR_XLAT_FORCE, kdump_get_err(ctx));
		return TEST_ERR;
	}

	res = dump_ctx_dir(ctx, rootpgt, &dir);
	kdump_attr_unref(ctx, &dir);
	return res;
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

	clonectx = kdump_clone(ctx, KDUMP_CLONE_XLAT);
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

	res = kdump_open_fd(ctx, fd);
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
		"  -l len     Number of bytes to read (default: %lu)\n"
		"  -o opt=val Additional addrxlat options\n",
		name, len);
}

int
main(int argc, char **argv)
{
	int opt;
	int fd;
	int rc;

	while ((opt = getopt(argc, argv, "h1:2:a:l:o:")) != -1) {
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

		case 'o':
			if (num_options >= MAX_OPTIONS) {
				fprintf(stderr, "Too many xlat options\n");
				return TEST_ERR;
			}

			p = strchr(optarg, '=');
			if (!p) {
				fprintf(stderr, "Missing option value: %s\n",
					optarg);
				return TEST_ERR;
			}
			*p = '\0';
			options[num_options].name = optarg;
			options[num_options].value = p + 1;
			++num_options;
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
