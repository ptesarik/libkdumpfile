/* Check VMCOREINFO cleanup.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

static const char vmcore1[] =
	"DIR.SUB.VAL=test1\n";

static const char vmcore2[] =
	"DIR.SUB=test2\n";

static int
set_vmcoreinfo_value(kdump_ctx_t *ctx, int cnt, const char *val)
{
	kdump_blob_t *blob;
	kdump_attr_t attr;
	kdump_status status;

	blob = kdump_blob_new_dup(val, strlen(val));
	if (!blob) {
		fprintf(stderr, "#%d: Cannot allocate VMCOREINFO blob.\n",
			cnt);
		return TEST_ERR;
	}
	attr.type = KDUMP_BLOB;
	attr.val.blob = blob;
	status = kdump_set_attr(ctx, "linux.vmcoreinfo.raw", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "#%d: Cannot set vmcoreinfo: %s\n",
			cnt, kdump_get_err(ctx));
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
check_vmcoreinfo_raw(kdump_ctx_t *ctx, int cnt, const char *expect)
{
	char *rawval;
	kdump_status status;

	status = kdump_vmcoreinfo_raw(ctx, &rawval);
	if (status != KDUMP_OK) {
		fprintf(stderr, "#%d: kdump_vmcoreinfo_raw() failed: %s\n",
			cnt, kdump_get_err(ctx));
		return TEST_ERR;
	}
	if (strcmp(rawval, expect)) {
		fprintf(stderr, "#%d: Invalid raw value:\n%s\n",
			cnt, rawval);
		return TEST_FAIL;
	}
	printf("#%d: kdump_vmcoreinfo_raw() value match\n", cnt);
	free(rawval);

	return TEST_OK;
}

static int
check_vmcoreinfo_line(kdump_ctx_t *ctx, int cnt, const char *key,
		      const char *expect)
{
	char *lineval;
	kdump_status status;

	status = kdump_vmcoreinfo_line(ctx, key, &lineval);
	if (status != KDUMP_OK) {
		fprintf(stderr, "#%d: kdump_vmcoreinfo_line() failed: %s\n",
			cnt, kdump_get_err(ctx));
		return TEST_ERR;
	}
	if (strcmp(lineval, expect)) {
		fprintf(stderr, "#%d: Invalid line value: %s\n",
			cnt, lineval);
		return TEST_FAIL;
	}
	printf("#%d: kdump_vmcoreinfo_line() value match\n", cnt);
	free(lineval);

	return TEST_OK;
}

static int
check(kdump_ctx_t *ctx)
{
	unsigned cnt;
	kdump_attr_t attr;
	kdump_status status;
	int rc;

	status = kdump_set_string_attr(ctx, "addrxlat.ostype", "linux");
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set ostype: %s\n",
			kdump_get_err(ctx));
		return TEST_ERR;
	}

	/* First value. */
	cnt = 1;
	rc = set_vmcoreinfo_value(ctx, cnt, vmcore1);
	if (rc != TEST_OK)
		return rc;

	rc = check_vmcoreinfo_raw(ctx, cnt, vmcore1);
	if (rc != TEST_OK)
		return rc;

	status = kdump_get_attr(ctx, "linux.vmcoreinfo.lines.DIR.SUB.VAL",
				&attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "#%d: Cannot get vmcoreinfo: %s\n",
			cnt, kdump_get_err(ctx));
		return TEST_ERR;
	}

	if (attr.type != KDUMP_STRING || strcmp(attr.val.string, "test1")) {
		fprintf(stderr, "#%d: Invalid attribute value\n", cnt);
		return TEST_FAIL;
	}
	printf("#%d: DIR.SUB.VAL=%s\n", cnt, attr.val.string);

	rc = check_vmcoreinfo_line(ctx, cnt, "DIR.SUB.VAL", attr.val.string);
	if (rc != TEST_OK)
		return rc;

	/* (Conflicting) second value */
	cnt = 2;
	rc = set_vmcoreinfo_value(ctx, cnt, vmcore2);
	if (rc != TEST_OK)
		return rc;

	rc = check_vmcoreinfo_raw(ctx, cnt, vmcore2);
	if (rc != TEST_OK)
		return rc;

	status = kdump_get_attr(ctx, "linux.vmcoreinfo.lines.DIR.SUB", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "#%d: Cannot get vmcoreinfo: %s\n",
			cnt, kdump_get_err(ctx));
		return TEST_ERR;
	}

	if (attr.type != KDUMP_STRING || strcmp(attr.val.string, "test2")) {
		fprintf(stderr, "#%d: Invalid attribute value\n", cnt);
		return TEST_FAIL;
	}
	printf("#%d: DIR.SUB=%s\n", cnt, attr.val.string);

	rc = check_vmcoreinfo_line(ctx, cnt, "DIR.SUB", attr.val.string);
	if (rc != TEST_OK)
		return rc;

	attr.type = KDUMP_NIL;
	status = kdump_set_attr(ctx, "linux.vmcoreinfo.raw", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot clear vmcoreinfo: %s\n",
			kdump_get_err(ctx));
		return TEST_ERR;
	}

	status = kdump_get_attr(ctx, "linux.vmcoreinfo.lines.DIR.SUB", &attr);
	if (status == KDUMP_OK) {
		fprintf(stderr, "vmcoreinfo not cleared!\n");
		return TEST_ERR;
	} else if (status != KDUMP_ERR_NOKEY) {
		fprintf(stderr, "Unexpected failure after unset: %s\n",
			kdump_get_err(ctx));
		return TEST_ERR;
	}
	printf("DIR.SUB is now clear\n");

	return TEST_OK;
}

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	int rc;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	rc = check(ctx);

	kdump_free(ctx);
	return rc;
}
