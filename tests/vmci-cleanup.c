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
#include <string.h>
#include <kdumpfile.h>

#include "testutil.h"

static const char vmcore1[] =
	"DIR.SUB.VAL=test1\n";

static const char vmcore2[] =
	"DIR.SUB=test2\n";

static int
check(kdump_ctx *ctx)
{
	unsigned cnt;
	kdump_attr_t attr;
	kdump_status status;

	/* First value. */
	cnt = 1;

	attr.type = kdump_string;
	attr.val.string = vmcore1;
	status = kdump_set_attr(ctx, "linux.vmcoreinfo.raw", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "#%d: Cannot set vmcoreinfo: %s\n",
			cnt, kdump_err_str(ctx));
		return TEST_ERR;
	}

	status = kdump_get_attr(ctx, "linux.vmcoreinfo.lines.DIR.SUB.VAL",
				&attr);
	if (status != kdump_ok) {
		fprintf(stderr, "#%d: Cannot get vmcoreinfo: %s\n",
			cnt, kdump_err_str(ctx));
		return TEST_ERR;
	}

	if (attr.type != kdump_string || strcmp(attr.val.string, "test1")) {
		fprintf(stderr, "#%d: Invalid attribute value\n", cnt);
		return TEST_FAIL;
	}
	printf("#%d: DIR.SUB.VAL=%s\n", cnt, attr.val.string);

	/* (Conflicting) second value */
	cnt = 2;

	attr.type = kdump_string;
	attr.val.string = vmcore2;
	status = kdump_set_attr(ctx, "linux.vmcoreinfo.raw", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "#%d: Cannot set vmcoreinfo: %s\n",
			cnt, kdump_err_str(ctx));
		return TEST_ERR;
	}

	status = kdump_get_attr(ctx, "linux.vmcoreinfo.lines.DIR.SUB", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "#%d: Cannot get vmcoreinfo: %s\n",
			cnt, kdump_err_str(ctx));
		return TEST_ERR;
	}

	if (attr.type != kdump_string || strcmp(attr.val.string, "test2")) {
		fprintf(stderr, "#%d: Invalid attribute value\n", cnt);
		return TEST_FAIL;
	}
	printf("#%d: DIR.SUB=%s\n", cnt, attr.val.string);

	attr.type = kdump_nil;
	status = kdump_set_attr(ctx, "linux.vmcoreinfo.raw", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot clear vmcoreinfo: %s\n",
			kdump_err_str(ctx));
		return TEST_ERR;
	}

	status = kdump_get_attr(ctx, "linux.vmcoreinfo.lines.DIR.SUB", &attr);
	if (status == kdump_ok) {
		fprintf(stderr, "vmcoreinfo not cleared!\n");
		return TEST_ERR;
	} else if (status != kdump_nokey) {
		fprintf(stderr, "Unexpected failure after unset: %s\n",
			kdump_err_str(ctx));
		return TEST_ERR;
	}
	printf("DIR.SUB is now clear\n");

	return TEST_OK;
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

	rc = check(ctx);

	kdump_free(ctx);
	return rc;
}
