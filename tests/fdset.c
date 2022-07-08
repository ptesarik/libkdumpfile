/* Test file.fdset attribute creation/deletion.
   Copyright (C) 2022 Petr Tesarik <ptesarik@suse.com>

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
#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

/** Check that fdset.key does not exist.
 */
static int
check_not_exist(kdump_ctx_t *ctx, kdump_attr_ref_t *fdset, const char *key)
{
	kdump_attr_ref_t tmpref;
	kdump_status status;
	int ret;

	ret = TEST_OK;

	status = kdump_sub_attr_ref(ctx, fdset, key, &tmpref);
	if (status == KDUMP_OK) {
		fprintf(stderr, "fdset.%s exists, but it should not!\n", key);
		kdump_attr_unref(ctx, &tmpref);
		ret = TEST_FAIL;
	} else if (status != KDUMP_ERR_NOKEY) {
		fprintf(stderr, "fdset.%s cannot be referenced: %s\n",
			key, kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	return ret;
}

/** Check that fdset.key exists but has no value.
 */
static int
check_unset_file(kdump_ctx_t *ctx, kdump_attr_ref_t *fdset, const char *key)
{
	kdump_attr_ref_t tmpref;
	kdump_status status;
	kdump_attr_t attr;
	int ret;

	ret = TEST_OK;

	status = kdump_sub_attr_ref(ctx, fdset, key, &tmpref);
	if (status != KDUMP_OK) {
		fprintf(stderr, "fdset.%s cannot be referenced: %s\n",
			key, kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else {
		kdump_attr_type_t type = kdump_attr_ref_type(&tmpref);
		if (type != KDUMP_NUMBER) {
			fprintf(stderr, "Wrong fdset.%s type: %d\n",
				key, type);
			ret = TEST_FAIL;
		}

		status = kdump_attr_ref_get(ctx, &tmpref, &attr);
		if (status == KDUMP_OK) {
			fprintf(stderr, "fdset.%s has an initial value!\n",
				key);
			ret = TEST_FAIL;
		} else if (status != KDUMP_ERR_NODATA) {
			fprintf(stderr, "Cannot get fdset.%s: %s\n",
				key, kdump_get_err(ctx));
			ret = TEST_FAIL;
		}
		kdump_attr_unref(ctx, &tmpref);
	}

	return ret;
}

int
main(int argc, char **argv)
{
	kdump_attr_ref_t fdset;
	kdump_attr_ref_t number;
	kdump_attr_ref_t tmpref;
	kdump_attr_t attr;
	kdump_ctx_t *ctx;
	kdump_status status;
	int fd;
	int ret;
	int rc;

	ret = TEST_OK;

	/*************************************************************
	 * Initialize context and base attribute references.
	 */
	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	status = kdump_attr_ref(ctx, KDUMP_ATTR_FDSET, &fdset);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference attribute %s: %s\n",
			KDUMP_ATTR_FDSET, kdump_get_err(ctx));
		return TEST_ERR;
	}
	kdump_attr_unref(ctx, &fdset);

	status = kdump_sub_attr_ref(ctx, &fdset, "number", &number);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference attribute %s: %s\n",
			KDUMP_ATTR_FDSET ".number", kdump_get_err(ctx));
		return TEST_ERR;
	}

	/*************************************************************
	 * Check initial state.
	 */
	status = kdump_attr_ref_get(ctx, &number, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get number of dump files: %s\n",
			kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else if (attr.type != KDUMP_NUMBER) {
		fprintf(stderr, "Wrong dump file attribute type: %d\n",
			(int)attr.type);
		ret = TEST_FAIL;
	} else if (attr.val.number != 0) {
		fprintf(stderr, "Wrong initial number of dump files: %" KDUMP_PRIuNUM "\n",
			attr.val.number);
		ret = TEST_FAIL;
	}

	/* Check that fdset.0 does not exist. */
	rc = check_not_exist(ctx, &fdset, "0");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * File set with one file.
	 */
	attr.type = KDUMP_NUMBER;
	attr.val.number = 1;
	status = kdump_attr_ref_set(ctx, &number, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set number of dump files: %s\n",
			kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	/* Check that fdset.0 exists now but has no value. */
	rc = check_unset_file(ctx, &fdset, "0");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that fdset.1 does not exist. */
	rc = check_not_exist(ctx, &fdset, "1");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * Expand set to three files.
	 */
	attr.type = KDUMP_NUMBER;
	attr.val.number = 3;
	status = kdump_attr_ref_set(ctx, &number, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set number of dump files: %s\n",
			kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	/* Check that fdset.1 exists now but has no value. */
	rc = check_unset_file(ctx, &fdset, "1");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that fdset.2 also exists and has no value. */
	rc = check_unset_file(ctx, &fdset, "2");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that fdset.3 does not exist. */
	rc = check_not_exist(ctx, &fdset, "3");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * Reduce set to two files.
	 */
	attr.type = KDUMP_NUMBER;
	attr.val.number = 2;
	status = kdump_attr_ref_set(ctx, &number, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set number of dump files: %s\n",
			kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	/* Check that fdset.2 no longer exists. */
	rc = check_not_exist(ctx, &fdset, "2");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* But fdset.1 still exists. */
	rc = check_unset_file(ctx, &fdset, "1");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * Empty set.
	 */
	attr.type = KDUMP_NUMBER;
	attr.val.number = 0;
	status = kdump_attr_ref_set(ctx, &number, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set number of dump files: %s\n",
			kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	/* Check that fdset.1 no longer exists. */
	rc = check_not_exist(ctx, &fdset, "1");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Neither does fdset.0. */
	rc = check_not_exist(ctx, &fdset, "0");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * Interaction with kdump_open_fdset()
	 */
	char fname[] = "fdset.XXXXXX";
	fd = mkstemp(fname);
	if (fd < 0) {
		perror("Cannot create temporary file");
		return TEST_ERR;
	}
	remove(fname);
	status = kdump_open_fd(ctx, fd);
	if (status != KDUMP_OK && status != KDUMP_ERR_NOTIMPL) {
		fprintf(stderr, "Cannot set dump file descriptor: %s\n",
			kdump_get_err(ctx));
		return TEST_ERR;
	}

	/* Check that the file descriptor is found as fdset.0. */
	status = kdump_sub_attr_ref(ctx, &fdset, "0", &tmpref);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference attribute %s: %s\n",
			KDUMP_ATTR_FDSET ".0", kdump_get_err(ctx));
		return TEST_ERR;
	}
	status = kdump_attr_ref_get(ctx, &tmpref, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get fdset.0: %s\n",
			kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else if (attr.type != KDUMP_NUMBER) {
		fprintf(stderr, "Wrong fdset.0 attribute type: %d\n",
			(int)attr.type);
		ret = TEST_FAIL;
	} else if (attr.val.number != fd) {
		fprintf(stderr, "Wrong %s value: %" KDUMP_PRIuNUM " != %d\n",
			"fdset.0", attr.val.number, fd);
		ret = TEST_FAIL;
	}
	kdump_attr_unref(ctx, &tmpref);

	/* Check that file.fd is also set. */
	status = kdump_get_number_attr(ctx, KDUMP_ATTR_FILE_FD,
				       &attr.val.number);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get %s: %s\n",
			KDUMP_ATTR_FILE_FD, kdump_get_err(ctx));
		ret = TEST_FAIL;
	}
	if (attr.val.number != fd) {
		fprintf(stderr, "Wrong %s value: %" KDUMP_PRIuNUM " != %d\n",
			KDUMP_ATTR_FILE_FD, attr.val.number, fd);
		ret = TEST_FAIL;
	}

	/*************************************************************
	 * Clean up.
	 */
	close(fd);
	kdump_attr_unref(ctx, &number);
	kdump_attr_unref(ctx, &fdset);
	kdump_free(ctx);
	return ret;
}

