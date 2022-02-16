/** @internal @file src/kdumpfile/test-blob.c
 * @brief Test blob attributes.
 */
/* Copyright (C) 2020 Petr Tesarik <ptesarik@suse.com>

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

#include "kdumpfile-priv.h"

#include <stdio.h>
#include <malloc.h>

#define TEST_OK     0
#define TEST_FAIL   1
#define TEST_ERR   99

static const struct attr_template tmpla = {
	.key = "a",
	.type = KDUMP_NUMBER,
};

static const struct attr_template tmplb = {
	.key = "b",
	.type = KDUMP_NUMBER,
};

static const struct attr_template tmplc = {
	.key = "c",
	.type = KDUMP_NUMBER,
};

static const struct attr_template tmpld = {
	.key = "d",
	.type = KDUMP_NUMBER,
};

static const struct attr_template tmplsub = {
	.key = "sub",
	.type = KDUMP_DIRECTORY,
};

static const struct attr_template tmplx = {
	.key = "x",
	.type = KDUMP_NUMBER,
};

static int
test_value(kdump_ctx_t *ctx, const char *key, unsigned val)
{
	kdump_num_t num;
	kdump_status status;

	status = kdump_get_number_attr(ctx, key, &num);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get attribute '%s': %s\n",
			key, kdump_get_err(ctx));
		return TEST_ERR;
	}
	if (num != val) {
		printf("%s: expect %u, found %" KDUMP_PRIuNUM "\n",
		       key, val, num);
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
test_change_value(kdump_ctx_t *ctx, const char *key, unsigned newval)
{
	kdump_status status;

	status = kdump_set_number_attr(ctx, key, newval);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot change attribute '%s': %s\n",
			key, kdump_get_err(ctx));
		return TEST_ERR;
	}

	return test_value(ctx, key, newval);
}

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx1, *ctx2;
	const struct attr_template **t;
	struct attr_data *a, *c, *sub;
	kdump_attr_ref_t ref;
	kdump_num_t num;
	kdump_status status;
	int ret;

	ret = TEST_OK;

	/* Make sure freed regions are overwritten */
	mallopt(M_PERTURB, 1);

	/* Set up a dictionary with these attributes:
	 *  a = 1
	 *  b = 2
	 *  c is unset
	 *  d is unset
	 *  sub is a directory
	 *  sub.x = 100
	 */
	ctx1 = kdump_new();
	if (!ctx1) {
		perror("Cannot allocate kdump context");
		return TEST_FAIL;
	}

	a = new_attr(ctx1->dict, gattr(ctx1, GKI_dir_root), &tmpla);
	if (!a) {
		perror("Cannot allocate attribute");
		return TEST_FAIL;
	}

	if (!new_attr(ctx1->dict, gattr(ctx1, GKI_dir_root), &tmplb)) {
		perror("Cannot allocate attribute");
		return TEST_FAIL;
	}

	c = new_attr(ctx1->dict, gattr(ctx1, GKI_dir_root), &tmplc);
	if (!c) {
		perror("Cannot allocate attribute");
		return TEST_FAIL;
	}

	if (!new_attr(ctx1->dict, gattr(ctx1, GKI_dir_root), &tmpld)) {
		perror("Cannot allocate attribute");
		return TEST_FAIL;
	}

	sub = new_attr(ctx1->dict, gattr(ctx1, GKI_dir_root), &tmplsub);
	if (!sub) {
		perror("Cannot allocate attribute");
		return TEST_FAIL;
	}

	if (!new_attr(ctx1->dict, sub, &tmplx)) {
		perror("Cannot allocate attribute");
		return TEST_FAIL;
	}

	if (test_change_value(ctx1, "a", 1))
		ret = TEST_ERR;
	if (test_change_value(ctx1, "b", 2))
		ret = TEST_ERR;
	if (test_change_value(ctx1, "sub.x", 100))
		ret = TEST_ERR;

	/* Clone the dictionary and attributes 'a', 'c' and 'sub'. */
	ctx2 = kdump_clone(ctx1, KDUMP_CLONE_XLAT);
	if (!ctx2) {
		perror("Cannot clone kdump context");
		return TEST_FAIL;
	}
	if (!clone_attr_path(ctx2->dict, a)) {
		perror("Cannot clone attribute");
		return TEST_FAIL;
	}
	if (!clone_attr_path(ctx2->dict, c)) {
		perror("Cannot clone attribute");
		return TEST_FAIL;
	}
	if (!clone_attr_path(ctx2->dict, sub)) {
		perror("Cannot clone attribute");
		return TEST_FAIL;
	}

	/* Check that 'a' can be changed independently. */
	if (test_change_value(ctx1, "a", 3))
		ret = TEST_ERR;
	if (test_value(ctx2, "a", 1))
		ret = TEST_ERR;
	if (test_change_value(ctx2, "a", 4))
		ret = TEST_ERR;
	if (test_value(ctx1, "a", 3))
		ret = TEST_ERR;

	/* Check that 'b' is shared. */
	if (test_change_value(ctx1, "b", 5))
		ret = TEST_ERR;
	if (test_value(ctx2, "b", 5))
		ret = TEST_ERR;

	/* Check that 'c' remains unset in ctx2. */
	if (test_change_value(ctx1, "c", 6))
		ret = TEST_ERR;
	status = kdump_attr_ref(ctx2, "c", &ref);
	if (status == KDUMP_OK) {
		if (kdump_attr_ref_isset(&ref)) {
			printf("Attribute '%s' is set incorrectly.\n", "c");
			ret = TEST_ERR;
		}
		kdump_attr_unref(ctx2, &ref);
	} else {
		fprintf(stderr, "Cannot reference '%s': %s\n",
			"c", kdump_get_err(ctx2));
		ret = TEST_ERR;
	}

	/* Check that 'd' becomes set in ctx2. */
	if (test_change_value(ctx1, "d", 7))
		ret = TEST_ERR;
	if (test_value(ctx2, "d", 7))
		ret = TEST_ERR;

	/* Check that 'sub.x' was also cloned. */
	if (test_change_value(ctx2, "sub.x", 101))
		ret = TEST_ERR;
	if (test_value(ctx1, "sub.x", 100))
		ret = TEST_ERR;
	if (test_change_value(ctx1, "sub.x", 102))
		ret = TEST_ERR;
	if (test_value(ctx2, "sub.x", 101))
		ret = TEST_ERR;

	kdump_free(ctx2);
	kdump_free(ctx1);

	return ret;
}
