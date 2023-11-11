/* Test file.set attribute creation/deletion.
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
#include <string.h>
#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

#define FILENAME_0	"fileA"
#define FILENAME_1	"fileB"

/** Check that file.set.key does not exist.
 */
static int
check_not_exist(kdump_ctx_t *ctx, kdump_attr_ref_t *fileset, const char *key)
{
	kdump_attr_ref_t tmpref;
	kdump_status status;
	int ret;

	ret = TEST_OK;

	status = kdump_sub_attr_ref(ctx, fileset, key, &tmpref);
	if (status == KDUMP_OK) {
		fprintf(stderr, "file.set.%s exists, but it should not!\n", key);
		kdump_attr_unref(ctx, &tmpref);
		ret = TEST_FAIL;
	} else if (status != KDUMP_ERR_NOKEY) {
		fprintf(stderr, "file.set.%s cannot be referenced: %s\n",
			key, kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	return ret;
}

/** Check that file.set.key exists and has the expected type but no value.
 */
static int
check_unset_file(kdump_ctx_t *ctx, kdump_attr_ref_t *fileset, const char *key,
		 kdump_attr_type_t exp_type)
{
	kdump_attr_ref_t tmpref;
	kdump_status status;
	kdump_attr_t attr;
	int ret;

	ret = TEST_OK;

	status = kdump_sub_attr_ref(ctx, fileset, key, &tmpref);
	if (status != KDUMP_OK) {
		fprintf(stderr, "file.set.%s cannot be referenced: %s\n",
			key, kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else {
		kdump_attr_type_t type = kdump_attr_ref_type(&tmpref);
		if (type != exp_type) {
			fprintf(stderr, "Wrong file.set.%s type: %d\n",
				key, type);
			ret = TEST_FAIL;
		}

		status = kdump_attr_ref_get(ctx, &tmpref, &attr);
		if (status == KDUMP_OK) {
			fprintf(stderr, "file.set.%s has an initial value!\n",
				key);
			ret = TEST_FAIL;
		} else if (status != KDUMP_ERR_NODATA) {
			fprintf(stderr, "Cannot get file.set.%s: %s\n",
				key, kdump_get_err(ctx));
			ret = TEST_FAIL;
		}
		kdump_attr_unref(ctx, &tmpref);
	}

	return ret;
}

static int
check_fileset_size(kdump_ctx_t *ctx, int num)
{
	kdump_attr_t attr;
	kdump_status status;
	int ret;

	ret = TEST_OK;

	status = kdump_get_attr(ctx, KDUMP_ATTR_FILE_SET ".number", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "%s cannot be retrieved: %s\n",
			"file.set.number", kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else if (attr.val.number != num) {
		fprintf(stderr, "Wrong %s value: %" KDUMP_PRIuNUM " != %d\n",
			"file.set.number", attr.val.number, num);
		ret = TEST_FAIL;
	}

	return ret;
}

static int
check_fileset_zero(kdump_ctx_t *ctx, kdump_attr_ref_t *fileset, int fd)
{
	kdump_attr_ref_t tmpref;
	kdump_attr_t attr;
	kdump_status status;
	int ret;

	ret = TEST_OK;

	status = kdump_sub_attr_ref(ctx, fileset, "0.fd", &tmpref);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference attribute %s: %s\n",
			KDUMP_ATTR_FILE_SET ".0.fd", kdump_get_err(ctx));
		return TEST_ERR;
	}
	status = kdump_attr_ref_get(ctx, &tmpref, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get file.set.0.fd: %s\n",
			kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else if (attr.type != KDUMP_NUMBER) {
		fprintf(stderr, "Wrong file.set.0.fd attribute type: %d\n",
			(int)attr.type);
		ret = TEST_FAIL;
	} else if (attr.val.number != fd) {
		fprintf(stderr, "Wrong %s value: %" KDUMP_PRIuNUM " != %d\n",
			"file.set.0.fd", attr.val.number, fd);
		ret = TEST_FAIL;
	}
	kdump_attr_unref(ctx, &tmpref);

	return ret;
}

static int
check_filename(kdump_ctx_t *ctx, kdump_attr_ref_t *fileset,
	       const char *subkey, const char *name)
{
	kdump_attr_ref_t tmpref;
	kdump_attr_t attr;
	kdump_status status;
	int ret;

	ret = TEST_OK;

	status = kdump_sub_attr_ref(ctx, fileset, subkey, &tmpref);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference attribute %s.%s: %s\n",
			KDUMP_ATTR_FILE_SET, subkey, kdump_get_err(ctx));
		return TEST_ERR;
	}
	status = kdump_attr_ref_get(ctx, &tmpref, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get %s.%s: %s\n",
			KDUMP_ATTR_FILE_SET, subkey, kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else if (attr.type != KDUMP_STRING) {
		fprintf(stderr, "Wrong %s.%s attribute type: %d\n",
			KDUMP_ATTR_FILE_SET, subkey, (int)attr.type);
		ret = TEST_FAIL;
	} else if (strcmp(attr.val.string, name)) {
		fprintf(stderr, "Wrong %s.%s value: %s != %s\n",
			KDUMP_ATTR_FILE_SET, subkey, attr.val.string, name);
		ret = TEST_FAIL;
	}
	kdump_attr_unref(ctx, &tmpref);

	return ret;
}

int
main(int argc, char **argv)
{
	kdump_attr_ref_t fileset;
	kdump_attr_ref_t number;
	kdump_attr_t attr;
	kdump_ctx_t *ctx;
	kdump_status status;
	const char *names[2];
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

	status = kdump_attr_ref(ctx, KDUMP_ATTR_FILE_SET, &fileset);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference attribute %s: %s\n",
			KDUMP_ATTR_FILE_SET, kdump_get_err(ctx));
		return TEST_ERR;
	}
	kdump_attr_unref(ctx, &fileset);

	status = kdump_sub_attr_ref(ctx, &fileset, "number", &number);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reference attribute %s: %s\n",
			KDUMP_ATTR_FILE_SET ".number", kdump_get_err(ctx));
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

	/* Check that file.set.0.fd does not exist. */
	rc = check_not_exist(ctx, &fileset, "0.fd");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that file.set.0.name does not exist. */
	rc = check_not_exist(ctx, &fileset, "0.name");
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

	/* Check that file.set.0.fd exists now but has no value. */
	rc = check_unset_file(ctx, &fileset, "0.fd", KDUMP_NUMBER);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that file.set.0.name also exists. */
	rc = check_unset_file(ctx, &fileset, "0.name", KDUMP_STRING);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that file.set.1.fd does not exist. */
	rc = check_not_exist(ctx, &fileset, "1.fd");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Neither does file.set.1.name. */
	rc = check_not_exist(ctx, &fileset, "1.name");
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

	/* Check that file.set.1.fd and file.set.1.name exist now but
	 * have no value. */
	rc = check_unset_file(ctx, &fileset, "1.fd", KDUMP_NUMBER);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_unset_file(ctx, &fileset, "1.name", KDUMP_STRING);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that file.set.2.fd and file.set.2.name also exist and
	 * have no value. */
	rc = check_unset_file(ctx, &fileset, "2.fd", KDUMP_NUMBER);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_unset_file(ctx, &fileset, "2.name", KDUMP_STRING);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that file.set.3.fd and file.set.3.name do not exist. */
	rc = check_not_exist(ctx, &fileset, "3.fd");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_not_exist(ctx, &fileset, "3.name");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * Store a file name in the attribute.
	 */

	/* Set file.set.0.name. */
	attr.type = KDUMP_STRING;
	attr.val.string = FILENAME_0;
	status = kdump_set_sub_attr(ctx, &fileset, "0.name", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set %s.0.name: %s\n",
			KDUMP_ATTR_FILE_SET, kdump_get_err(ctx));
		ret = TEST_FAIL;
	}


	/* Set file.set.1.name. */
	attr.type = KDUMP_STRING;
	attr.val.string = FILENAME_1;
	status = kdump_set_sub_attr(ctx, &fileset, "1.name", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set %s.1.name: %s\n",
			KDUMP_ATTR_FILE_SET, kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	/* Verify file.set.0.name. */
	rc = check_filename(ctx, &fileset, "0.name", FILENAME_0);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Verify file.set.1.name. */
	rc = check_filename(ctx, &fileset, "1.name", FILENAME_1);
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

	/* Check that file.set.2.fd and file.set.2.name no longer exist. */
	rc = check_not_exist(ctx, &fileset, "2.fd");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_not_exist(ctx, &fileset, "2.name");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* But file.set.1.fd and file.set.1.name still exist. */
	rc = check_unset_file(ctx, &fileset, "1.fd", KDUMP_NUMBER);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_filename(ctx, &fileset, "1.name", FILENAME_1);
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

	/* Check that file.set.1.fd and file.set.1.name no longer exist. */
	rc = check_not_exist(ctx, &fileset, "1.fd");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_not_exist(ctx, &fileset, "1.name");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Neither does file.set.0.fd or file.set.0.name. */
	rc = check_not_exist(ctx, &fileset, "0.fd");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_not_exist(ctx, &fileset, "0.name");
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

	/* Check that fdset size is one. */
	rc = check_fileset_size(ctx, 1);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that the file descriptor is found as file.set.0.fd. */
	rc = check_fileset_zero(ctx, &fileset, fd);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that legacy file.fd is not set. */
	status = kdump_get_attr(ctx, KDUMP_ATTR_FILE_FD, &attr);
	if (status == KDUMP_OK) {
		fprintf(stderr, "%s has a value, but it should not!\n",
			KDUMP_ATTR_FILE_FD);
		ret = TEST_FAIL;
	} else if (status != KDUMP_ERR_NODATA) {
		fprintf(stderr, "%s cannot be retrieved: %s\n",
			KDUMP_ATTR_FILE_FD, kdump_get_err(ctx));
		ret = TEST_FAIL;
	}

	/* Close dump. */
	status = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_SET ".number", 0);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set dump number to zero: %s\n",
			kdump_get_err(ctx));
		return TEST_ERR;
	}

	/*************************************************************
	 * Interaction with legacy file.fd attribute.
	 */
	status = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_FD, fd);
	if (status != KDUMP_OK && status != KDUMP_ERR_NOTIMPL) {
		fprintf(stderr, "Cannot set dump file descriptor: %s\n",
			kdump_get_err(ctx));
		return TEST_ERR;
	}

	/* Check that legacy file.fd is set. */
	status = kdump_get_attr(ctx, KDUMP_ATTR_FILE_FD, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "%s cannot be retrieved: %s\n",
			KDUMP_ATTR_FILE_FD, kdump_get_err(ctx));
		ret = TEST_FAIL;
	} else if (attr.val.number != fd) {
		fprintf(stderr, "Wrong %s value: %" KDUMP_PRIuNUM " != %d\n",
			KDUMP_ATTR_FILE_FD, attr.val.number, fd);
		ret = TEST_FAIL;
	}

	/* Check that file set size is one. */
	rc = check_fileset_size(ctx, 1);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that the file descriptor is also found as file.set.0.fd. */
	rc = check_fileset_zero(ctx, &fileset, fd);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * RESET.
	 */
	attr.type = KDUMP_NUMBER;
	attr.val.number = 0;
	status = kdump_attr_ref_set(ctx, &number, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot clean up the file set: %s\n",
			kdump_get_err(ctx));
		rc = TEST_FAIL;
	}

	/*************************************************************
	 * Unset file names.
	 */
	names[0] = NULL;
	names[1] = NULL;
	status = kdump_set_filenames(ctx, 2, names);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set file names: %s\n",
			kdump_get_err(ctx));
		rc = TEST_FAIL;
	}

	/* Check that fdset size is two. */
	rc = check_fileset_size(ctx, 2);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Check that file.set.0.name and file.set.1.name are unset */
	rc = check_unset_file(ctx, &fileset, "0.name", KDUMP_STRING);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_unset_file(ctx, &fileset, "1.name", KDUMP_STRING);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * Real file names.
	 */
	names[0] = FILENAME_0;
	names[1] = FILENAME_1;
	status = kdump_set_filenames(ctx, 2, names);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set file names: %s\n",
			kdump_get_err(ctx));
		rc = TEST_FAIL;
	}

	/* Check that fdset size is two. */
	rc = check_fileset_size(ctx, 2);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Verify file.set.0.name and file.set.1.name. */
	rc = check_filename(ctx, &fileset, "0.name", FILENAME_0);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;
	rc = check_filename(ctx, &fileset, "1.name", FILENAME_1);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* Set the file descriptor and reduce the set to one file. */
	status = kdump_open_fd(ctx, fd);
	if (status != KDUMP_OK && status != KDUMP_ERR_NOTIMPL) {
		fprintf(stderr, "Cannot set dump file descriptor: %s\n",
			kdump_get_err(ctx));
		return TEST_ERR;
	}

	/* Verify file.set.0.name is still set. */
	rc = check_filename(ctx, &fileset, "0.name", FILENAME_0);
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/* But file.set.1.name no longer exists. */
	rc = check_not_exist(ctx, &fileset, "1.name");
	if (rc == TEST_ERR)
		return rc;
	else if (rc != TEST_OK)
		ret = rc;

	/*************************************************************
	 * Clean up.
	 */
	close(fd);
	kdump_attr_unref(ctx, &number);
	kdump_attr_unref(ctx, &fileset);
	kdump_free(ctx);
	return ret;
}

