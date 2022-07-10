/* Check dump attributes.
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

#define _GNU_SOURCE

#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

static int
check_noattr(kdump_ctx_t *ctx, char *key)
{
	kdump_attr_t attr;
	kdump_status res;

	printf("Checking no %s... ", key);
	res = kdump_get_attr(ctx, key, &attr);
	if (res == KDUMP_OK) {
		puts("FAILED");
		return TEST_FAIL;
	} else if (res != KDUMP_ERR_NODATA) {
		fprintf(stderr, "Cannot get attribute %s: %s\n",
			key, kdump_get_err(ctx));
		return TEST_ERR;
	}

	puts("OK");
	return TEST_OK;
}

static int
check_attr(kdump_ctx_t *ctx, char *key, const kdump_attr_t *expect, int chkval)
{
	kdump_attr_t attr;

	printf("Checking %s... ", key);
	if (kdump_get_attr(ctx, key, &attr) != KDUMP_OK) {
		puts("FAILED");
		fprintf(stderr, "Cannot get attribute %s: %s\n",
			key, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	if (attr.type != expect->type) {
		puts("FAILED");
		fprintf(stderr, "Type mismatch for %s: expect %u, got %u\n",
			key, (unsigned) expect->type, (unsigned) attr.type);
		return TEST_FAIL;
	}

	if (!chkval)
		goto out;

	switch (attr.type) {
	case KDUMP_DIRECTORY:
		/* Nothing to check (beyond type) */
		break;

	case KDUMP_NUMBER:
		if (attr.val.number == expect->val.number)
			break;

		puts("FAILED");
		fprintf(stderr, "%s value mismatch: ", key);
		fprintf(stderr, "expect %llu, got %llu\n",
			(unsigned long long) expect->val.number,
			(unsigned long long) attr.val.number);
		return TEST_FAIL;

	case KDUMP_ADDRESS:
		if (attr.val.address == expect->val.address)
			break;

		puts("FAILED");
		fprintf(stderr, "%s value mismatch: ", key);
		fprintf(stderr, "expect 0x%016llx, got 0x%016llx\n",
			(unsigned long long) expect->val.address,
			(unsigned long long) attr.val.address);
		return TEST_FAIL;

	case KDUMP_STRING:
		if (!strcmp(attr.val.string, expect->val.string))
			break;

		puts("FAILED");
		fprintf(stderr, "%s value mismatch: ", key);
		fprintf(stderr, "expect %s, got %s\n",
			expect->val.string, attr.val.string);
		return TEST_FAIL;

	default:
		puts("FATAL");
		fprintf(stderr, "INTERNAL ERROR: Invalid attr type: %u\n",
			(unsigned) attr.type);
		return TEST_FAIL;
	}

 out:
	puts("OK");
	return TEST_OK;
}

static int
check_attr_bmp(kdump_ctx_t *ctx, char *key, const struct number_array *expect)
{
	kdump_attr_t attr;
	unsigned char bits[expect->n];
	kdump_status status;
	unsigned i;

	printf("Checking %s... ", key);
	if (kdump_get_attr(ctx, key, &attr) != KDUMP_OK) {
		puts("FAILED");
		fprintf(stderr, "Cannot get attribute %s: %s\n",
			key, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	if (attr.type != KDUMP_BITMAP) {
		puts("FAILED");
		fprintf(stderr, "Type mismatch for %s: expect %u, got %u\n",
			key, (unsigned) KDUMP_BITMAP, (unsigned) attr.type);
		return TEST_FAIL;
	}

	status = kdump_bmp_get_bits(attr.val.bitmap,
				    0, (expect->n << 3) - 1, bits);
	if (status != KDUMP_OK) {
		puts("FAILED");
		fprintf(stderr, "Cannot get bitmap bits: %s\n",
			kdump_bmp_get_err(attr.val.bitmap));
		return TEST_FAIL;
	}

	for (i = 0; i < expect->n; ++i) {
		if (bits[i] != expect->val[i]) {
			puts("FAILED");
			fprintf(stderr, "%s value mismatch at index %u: ",
				key, i);
			fprintf(stderr, "expect 0x%02x, got 0x%02x\n",
				(unsigned) expect->val[i], bits[i]);
			return TEST_FAIL;
		}
	}

	puts("OK");
	return TEST_OK;
}

static int
check_attr_blob(kdump_ctx_t *ctx, char *key, const struct blob *expect)
{
	kdump_attr_t attr;
	unsigned char *data;
	size_t size;
	size_t i;

	printf("Checking %s... ", key);
	if (kdump_get_attr(ctx, key, &attr) != KDUMP_OK) {
		puts("FAILED");
		fprintf(stderr, "Cannot get attribute %s: %s\n",
			key, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	if (attr.type != KDUMP_BLOB) {
		puts("FAILED");
		fprintf(stderr, "Type mismatch for %s: expect %u, got %u\n",
			key, (unsigned) KDUMP_BLOB, (unsigned) attr.type);
		return TEST_FAIL;
	}

	data = kdump_blob_pin(attr.val.blob);
	size = kdump_blob_size(attr.val.blob);
	if (size != expect->length) {
		kdump_blob_unpin(attr.val.blob);
		puts("FAILED");
		fprintf(stderr, "Size mismatch for %s: expect %zd, got %zd\n",
			key, expect->length, size);
		return TEST_FAIL;
	}

	for (i = 0; i < size; ++i) {
		if (data[i] != expect->data[i]) {
			kdump_blob_unpin(attr.val.blob);
			puts("FAILED");
			fprintf(stderr, "%s value mismatch at index %zu: ",
				key, i);
			fprintf(stderr, "expect 0x%02x, got 0x%02x\n",
				expect->data[i], data[i]);
			return TEST_FAIL;
		}
	}
	kdump_blob_unpin(attr.val.blob);

	puts("OK");
	return TEST_OK;
}

static int
check_attr_val(kdump_ctx_t *ctx, char *key, char *val)
{
	char *sep, *p, savedsep;
	unsigned long long number;
	char *string;
	struct number_array number_array;
	struct blob *blob;
	struct param param;
	kdump_attr_t attr;
	int rc;

	sep = strchrnul(val, ':');
	savedsep = *sep;

	p = sep;
	do {
		*p-- = '\0';
	} while (p >= val && isspace(*p));

	if (!strcmp(val, "directory")) {
		attr.type = KDUMP_DIRECTORY;
		return check_attr(ctx, key, &attr, 0);
	} else if (!strcmp(val, "number")) {
		attr.type = KDUMP_NUMBER;
		param.type = param_number;
		param.number = &number;
	} else if (!strcmp(val, "address")) {
		attr.type = KDUMP_ADDRESS;
		param.type = param_number;
		param.number = &number;
	} else if (!strcmp(val, "string")) {
		attr.type = KDUMP_STRING;
		param.type = param_string;
		param.string = &string;
		string = NULL;
	} else if (!strcmp(val, "bitmap")) {
		attr.type = KDUMP_BITMAP;
		param.type = param_number_array;
		param.number_array = &number_array;
		number_array.val = NULL;
	} else if (!strcmp(val, "blob")) {
		attr.type = KDUMP_BLOB;
		param.type = param_blob;
		param.blob = &blob;
		blob = NULL;
	} else if (!strcmp(val, "nil")) {
		return check_noattr(ctx, key);
	} else {
		fprintf(stderr, "Invalid type: %s\n", val);
		return TEST_FAIL;
	}

	if (!savedsep)
		return check_attr(ctx, key, &attr, 0);

	param.key = key;

	p = sep + 1;
	while (*p && isspace(*p))
		++p;

	rc = set_param(&param, p);
	if (rc != TEST_OK)
		return rc;

	switch (attr.type) {
	case KDUMP_NUMBER:  attr.val.number = number;  break;
	case KDUMP_ADDRESS: attr.val.address = number; break;
	case KDUMP_STRING:  attr.val.string = string;  break;
	case KDUMP_BITMAP:
		return check_attr_bmp(ctx, key, &number_array);
	case KDUMP_BLOB:
		return check_attr_blob(ctx, key, blob);
	default:
		fprintf(stderr, "INTERNAL ERROR: Invalid attr type: %u\n",
			(unsigned) attr.type);
		return TEST_FAIL;
	}

	return check_attr(ctx, key, &attr, 1);
}

static int
check_attrs(FILE *parm, kdump_ctx_t *ctx)
{
	char *line, *key, *val;
	size_t linesz;
	unsigned linenum;
	int tmprc, rc = TEST_OK;

	line = NULL;
	linesz = 0;
	linenum = 0;

	puts("Dump looks fine. Now checking attributes.");
	while (getline(&line, &linesz, parm) > 0) {
		++linenum;

		if (parse_key_val(line, &key, &val)) {
			fprintf(stderr, "Malformed check: %s\n", line);
			rc = TEST_FAIL;
			break;
		}

		if (!key)
			continue;

		tmprc = check_attr_val(ctx, key, val);
		if (tmprc != TEST_OK) {
			rc = tmprc;
			fprintf(stderr, "Error on line #%d\n", linenum);
			if (rc == TEST_ERR)
				break;
		}
	}

	if (line)
		free(line);
	return rc;
}

static int
check_attrs_fd(FILE *parm, int dumpfd)
{
	kdump_ctx_t *ctx;
	kdump_status res;
	int rc;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	res = kdump_open_fd(ctx, dumpfd);
	if (res != KDUMP_OK) {
		fprintf(stderr, "Cannot open dump: %s\n", kdump_get_err(ctx));
		rc = TEST_ERR;
	} else
		rc = check_attrs(parm, ctx);

	kdump_free(ctx);
	return rc;
}

int
main(int argc, char **argv)
{
	int fd;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <dump>\n", argv[0]);
		return TEST_ERR;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("Cannot open dump file");
		return TEST_ERR;
	}

	rc = check_attrs_fd(stdin, fd);

	if (close(fd) != 0) {
		perror("Cannot close dump file");
		rc = TEST_ERR;
	}

	return rc;
}
