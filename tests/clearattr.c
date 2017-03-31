/* Test clearing attributes.
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

#define ATTRPATH	"linux.uts.sysname"
#define ATTRVALUE	"Linux"

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	kdump_attr_t attr;
	kdump_status status;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	attr.type = kdump_string;
	attr.val.string = ATTRVALUE;
	status = kdump_set_attr(ctx, ATTRPATH, &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot set %s: %s\n",
			ATTRPATH, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	memset(&attr, 0, sizeof attr);
	status = kdump_get_attr(ctx, ATTRPATH, &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot get %s: %s\n",
			ATTRPATH, kdump_get_err(ctx));
		return TEST_FAIL;
	}
	printf("%s = %s\n", ATTRPATH, attr.val.string);

	attr.type = kdump_nil;
	status = kdump_set_attr(ctx, ATTRPATH, &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot clear %s: %s\n",
			ATTRPATH, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	memset(&attr, 0, sizeof attr);
	status = kdump_get_attr(ctx, ATTRPATH, &attr);
	if (status == kdump_ok) {
		fprintf(stderr, "Attribute %s is still set!\n", ATTRPATH);
		return TEST_FAIL;
	} else if (status != kdump_nodata) {
		fprintf(stderr, "Unexpected error on getting %s: %s\n",
			ATTRPATH, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	kdump_free(ctx);

	return TEST_OK;
}
