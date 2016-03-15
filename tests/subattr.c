/* Test subordinate attributes.
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
	kdump_ctx *ctx;
	kdump_attr_t attr;
	kdump_attr_ref_t ref, subref;
	kdump_status status;
	int rc;

	ctx = kdump_init();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	attr.type = kdump_string;
	attr.val.string = ATTRVALUE;
	status = kdump_set_attr(ctx, ATTRPATH, &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot set %s: %s\n",
			ATTRPATH, kdump_err_str(ctx));
		return TEST_FAIL;
	}

	status = kdump_attr_ref(ctx, NULL, &ref);
	if (status != kdump_ok) {
		fprintf(stderr, "kdump_attr_ref failed: %s\n",
			kdump_err_str(ctx));
		return TEST_FAIL;
	}

	rc = TEST_OK;

	status = kdump_sub_attr_ref(ctx, &ref, "linux", &subref);
	if (status == kdump_ok) {
		status = kdump_attr_ref_get(ctx, &subref, &attr);
		if (attr.type != kdump_directory) {
			fprintf(stderr, "Wrong type for %s: %d\n",
				"linux", (int) attr.type);
			rc = TEST_FAIL;
		} else
			printf("%s is a directory\n", "linux");
		kdump_attr_unref(ctx, &subref);
	} else {
		fprintf(stderr, "kdump_sub_attr_ref failed for %s: %s\n",
			"linux", kdump_err_str(ctx));
		rc = TEST_FAIL;
	}

	status = kdump_sub_attr_ref(ctx, &ref, ATTRPATH, &subref);
	if (status == kdump_ok) {
		status = kdump_attr_ref_get(ctx, &subref, &attr);
		if (attr.type != kdump_string) {
			fprintf(stderr, "Wrong type for %s: %d\n",
				ATTRPATH, (int) attr.type);
			rc = TEST_FAIL;
		} else if (strcmp(attr.val.string, ATTRVALUE)) {
			fprintf(stderr, "Wrong type for %s: %d\n",
				ATTRPATH, (int) attr.type);
			rc = TEST_FAIL;
		} else
			printf("%s = %s\n", ATTRPATH, attr.val.string);
		kdump_attr_unref(ctx, &subref);
	} else {
		fprintf(stderr, "kdump_sub_attr_ref failed for %s: %s\n",
			ATTRPATH, kdump_err_str(ctx));
		rc = TEST_FAIL;
	}

	kdump_attr_unref(ctx, &ref);
	kdump_free(ctx);

	return rc;
}
