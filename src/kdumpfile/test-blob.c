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

#define TEST_OK     0
#define TEST_FAIL   1
#define TEST_ERR   99

static const struct attr_template blob_tmpl = {
	.key = "blob",
	.type = KDUMP_BLOB,
};

static const char bufdata[] = "This is a dummy buffer.";

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	kdump_attr_t attr;
	struct attr_data *d;
	kdump_attr_value_t val;
	kdump_blob_t *blob;
	kdump_status status;
	void *data;
	void *buffer;
	size_t size;
	unsigned long cnt;
	int ret;

	ret = TEST_OK;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot allocate kdump context");
		return TEST_FAIL;
	}

	d = new_attr(ctx->dict, gattr(ctx, GKI_dir_root), &blob_tmpl);
	if (!d) {
		perror("Cannot allocate blob attribute");
		return TEST_FAIL;
	}

	blob = kdump_blob_new(NULL, 0);
	if (!blob) {
		perror("Cannot allocate blob");
		return TEST_FAIL;
	}

	buffer = malloc(sizeof bufdata);
	if (!buffer) {
		perror("Cannot allocate buffer data");
		return TEST_FAIL;
	}
	memcpy(buffer, bufdata, sizeof bufdata);

	val.blob = blob;
	status = set_attr(ctx, d, ATTR_DEFAULT, &val);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set blob attribute: %s\n",
			kdump_get_err(ctx));
		ret = TEST_ERR;
	}

	/* Basic sanity checks */
	status = kdump_get_attr(ctx, "blob", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get blob attribute: %s\n",
			kdump_get_err(ctx));
		ret = TEST_ERR;
	}

	if (attr.type != KDUMP_BLOB ||
	    attr.val.blob != blob) {
		fprintf(stderr, "Attribute value mismatch!\n");
		ret = TEST_ERR;
	}

	/* Check init data buffer */
	data = kdump_blob_pin(blob);
	size = kdump_blob_size(blob);
	printf("Blob internal buffer set to %p+%zd, found %p+%zd\n",
	       NULL, (size_t)0, data, size);
	if (data != NULL || size != 0) {
		fputs("Internal buffer mismatch!\n", stderr);
		ret = TEST_ERR;
	}

	/* Check changes to a pinned blob */
	status = kdump_blob_set(blob, buffer, sizeof buffer);
	if (status != KDUMP_ERR_BUSY) {
		fputs("Changes to a pinned blob not blocked!\n", stderr);
		ret = TEST_ERR;
	}

	/* Unpin blob */
	cnt = kdump_blob_unpin(blob);
	printf("Expected pin count %lu, found %lu\n", 0, cnt);
	if (cnt != 0) {
		fputs("Pin count mismatch!\n", stderr);
		ret = TEST_ERR;
	}

	/* Set own data buffer */
	status = kdump_blob_set(blob, buffer, sizeof buffer);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot change internal buffer: %s\n",
			kdump_strerror(status));
		ret = TEST_ERR;
	}

	/* Check own data buffer */
	data = kdump_blob_pin(blob);
	size = kdump_blob_size(blob);
	printf("Blob internal buffer set to %p+%zd, found %p+%zd\n",
	       buffer, sizeof buffer, data, size);
	if (data != buffer || size != sizeof buffer) {
		fputs("Internal buffer mismatch!\n", stderr);
		ret = TEST_ERR;
	}

	/* Unpin own data buffer */
	cnt = kdump_blob_unpin(blob);
	printf("Expected pin count %lu, found %lu\n", 0, cnt);
	if (cnt != 0) {
		fputs("Pin count mismatch!\n", stderr);
		ret = TEST_ERR;
	}

	/* Set NULL buffer */
	status = kdump_blob_set(blob, NULL, 1234);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot change internal buffer: %s\n",
			kdump_strerror(status));
		ret = TEST_ERR;
	}

	/* Check that size is forced to zero */
	size = kdump_blob_size(blob);
	printf("Expected size %zd, found %zd\n", (size_t)0, size);
	if (size != 0) {
		fputs("Internal buffer size mismatch!\n", stderr);
		ret = TEST_ERR;
	}

	cnt = kdump_blob_decref(blob);
	if (cnt != 0) {
		fputs("Blob reference count mismatch\n", stderr);
		ret = TEST_ERR;
	}

	kdump_free(ctx);

	return TEST_OK;
}
