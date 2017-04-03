/* Test attribute iterators.
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

#include <string.h>
#include <stdio.h>
#include <kdumpfile.h>

#include "testutil.h"

struct attrdef {
	const char *name;
	const char *value;
};

#define ATTRPATH	"linux.uts"
#define NOPATH		"nonexistent.path"

static const struct attrdef attrs[] = {
	{ "sysname", "Linux" },
	{ "nodename", "testnode" },
	{ "release", "3.0.0-test" },
	{ "version", "#1 SMP Mon Mar 14 14:08:28 UTC 2016" },
	{ "machine", "x86_64" },
	{ "domainname", "(none)" },
};

#define MAXATTRLEN 32

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	kdump_attr_iter_t it;
	kdump_attr_t attr;
	unsigned seen[ARRAY_SIZE(attrs)];
	unsigned i;
	kdump_status res;
	int rc;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	/* Non-existent path must fail. */
	res = kdump_attr_iter_start(ctx, NOPATH, &it);
	if (res == KDUMP_OK) {
		fprintf(stderr, "Found non-existent path %s??\n", NOPATH);
		return TEST_FAIL;
	} else if (res != KDUMP_NOKEY) {
		fprintf(stderr, "Unexpected error for %s: %s\n",
			NOPATH, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	/* Set the values and verify that all keys are found. */

	for (i = 0; i < ARRAY_SIZE(attrs); ++i) {
		const struct attrdef *ad = &attrs[i];
		char key[MAXATTRLEN];

		sprintf(key, "%s.%s", ATTRPATH, ad->name);
		attr.type = kdump_string;
		attr.val.string = ad->value;
		res = kdump_set_attr(ctx, key, &attr);
		if (res != KDUMP_OK) {
			fprintf(stderr, "Cannot set %s: %s\n",
				key, kdump_get_err(ctx));
			return TEST_FAIL;
		}
	}

	res = kdump_attr_iter_start(ctx, ATTRPATH, &it);
	if (res != KDUMP_OK) {
		fprintf(stderr, "Cannot start iteration: %s\n",
			kdump_get_err(ctx));
		return TEST_FAIL;
	}

	memset(seen, 0, sizeof seen);
	rc = TEST_OK;
	while (it.key) {
		for (i = 0; i < ARRAY_SIZE(attrs); ++i)
			if (!strcmp(it.key, attrs[i].name))
				break;

		if (i >= ARRAY_SIZE(attrs)) {
			fprintf(stderr, "Unknown key: %s\n", it.key);
			rc = TEST_FAIL;
		} else {
			if (seen[i]) {
				fprintf(stderr, "Duplicate key: %s\n",
					it.key);
				rc = TEST_FAIL;
			} else
				seen[i] = 1;

			res = kdump_attr_ref_get(ctx, &it.pos, &attr);
			if (res != KDUMP_OK) {
				fprintf(stderr, "Cannot get value of %s: %s\n",
					it.key, kdump_get_err(ctx));
				rc = TEST_FAIL;
			}

			if (attr.type != kdump_string) {
				fprintf(stderr, "Wrong type: %d\n", attr.type);
				rc = TEST_FAIL;
			} else if (strcmp(attrs[i].value, attr.val.string)) {
				fprintf(stderr, "Value mismatch for %s:"
					" expect %s, found %s\n",
					it.key, attrs[i].value,
					attr.val.string);
				rc = TEST_FAIL;
			} else
				printf("%s = %s\n", it.key, attr.val.string);
		}

		res = kdump_attr_iter_next(ctx, &it);
		if (res != KDUMP_OK) {
			fprintf(stderr, "Cannot advance iterator: %s\n",
				kdump_get_err(ctx));
			rc = TEST_FAIL;
			break;
		}
	}

	res = kdump_attr_iter_next(ctx, &it);
	if (res == KDUMP_OK) {
		fprintf(stderr, "Advancing past end succeeds??\n");
		rc = TEST_FAIL;
	} else if (res != KDUMP_INVALID) {
		fprintf(stderr, "Unexpected error advancing past end: %s\n",
			kdump_get_err(ctx));
		rc = TEST_FAIL;
	}

	kdump_attr_iter_end(ctx, &it);

	for (i = 0; i < ARRAY_SIZE(attrs); ++i)
		if (!seen[i]) {
			fprintf(stderr, "Key not found: %s.%s\n",
				ATTRPATH, attrs[i].name);
			rc = TEST_FAIL;
		}

	return rc;
}
