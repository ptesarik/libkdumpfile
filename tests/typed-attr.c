/* Test typed attribute access.
   Copyright (C) 2018 Petr Tesarik <ptesarik@suse.com>

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

#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

#define ATTR_CACHE_SIZE	"cache.size"
#define ATTR_SYSNAME	"linux.uts.sysname"
#define ATTR_PHYS_BASE	"linux.phys_base"

int main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	kdump_attr_t attr;
	kdump_num_t num;
	kdump_addr_t addr;
	const char *str;
	kdump_status status;
	int rc = TEST_OK;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	puts("# Test kdump_get_typed_attr:");

	attr.type = KDUMP_NUMBER;
	status = kdump_get_typed_attr(ctx, ATTR_CACHE_SIZE, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_CACHE_SIZE, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s: %lld\n",
		       ATTR_CACHE_SIZE, (long long)attr.val.number);

	attr.type = KDUMP_STRING;
	status = kdump_get_typed_attr(ctx, ATTR_CACHE_SIZE, &attr);
	if (status == KDUMP_OK) {
		fprintf(stderr, "%s can be read as a string??\n",
			ATTR_CACHE_SIZE);
		rc = TEST_FAIL;
	} else if (status != KDUMP_ERR_INVALID) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_CACHE_SIZE, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s as a string: %s\n",
		       ATTR_CACHE_SIZE, kdump_get_err(ctx));

	attr.type = KDUMP_STRING;
	attr.val.string = "Linux";
	status = kdump_set_attr(ctx, ATTR_SYSNAME, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set %s: %s\n",
			ATTR_SYSNAME, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	attr.type = KDUMP_STRING;
	status = kdump_get_typed_attr(ctx, ATTR_SYSNAME, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_SYSNAME, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s: %s\n", ATTR_SYSNAME, attr.val.string);

	attr.type = KDUMP_NUMBER;
	status = kdump_get_typed_attr(ctx, ATTR_SYSNAME, &attr);
	if (status == KDUMP_OK) {
		fprintf(stderr, "%s can be read as a number??\n",
			ATTR_SYSNAME);
		rc = TEST_FAIL;
	} else if (status != KDUMP_ERR_INVALID) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_SYSNAME, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s as a number: %s\n",
		       ATTR_SYSNAME, kdump_get_err(ctx));

	puts("\n# Test convenience functions:");

	status = kdump_get_number_attr(ctx, ATTR_CACHE_SIZE, &num);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_CACHE_SIZE, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s: %lld\n",
		       ATTR_CACHE_SIZE, (long long)num);


	status = kdump_get_string_attr(ctx, ATTR_CACHE_SIZE, &str);
	if (status == KDUMP_OK) {
		fprintf(stderr, "%s can be read as a string??\n",
			ATTR_CACHE_SIZE);
		rc = TEST_FAIL;
	} else if (status != KDUMP_ERR_INVALID) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_CACHE_SIZE, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s as a string: %s\n",
		       ATTR_CACHE_SIZE, kdump_get_err(ctx));

	attr.type = KDUMP_ADDRESS;
	attr.val.address = 0x1234;
	status = kdump_set_attr(ctx, ATTR_PHYS_BASE, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set %s: %s\n",
			ATTR_PHYS_BASE, kdump_get_err(ctx));
		return TEST_FAIL;
	}

	status = kdump_get_address_attr(ctx, ATTR_PHYS_BASE, &addr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_PHYS_BASE, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s: %"ADDRXLAT_PRIXADDR"\n",
		       ATTR_PHYS_BASE, addr);

	status = kdump_get_string_attr(ctx, ATTR_PHYS_BASE, &str);
	if (status == KDUMP_OK) {
		fprintf(stderr, "%s can be read as a string??\n",
			ATTR_PHYS_BASE);
		rc = TEST_FAIL;
	} else if (status != KDUMP_ERR_INVALID) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_PHYS_BASE, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s as a string: %s\n",
		       ATTR_PHYS_BASE, kdump_get_err(ctx));

	status = kdump_get_string_attr(ctx, ATTR_SYSNAME, &str);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_SYSNAME, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s: %s\n", ATTR_SYSNAME, str);

	status = kdump_get_number_attr(ctx, ATTR_SYSNAME, &num);
	if (status == KDUMP_OK) {
		fprintf(stderr, "%s can be read as a number??\n",
			ATTR_SYSNAME);
		rc = TEST_FAIL;
	} else if (status != KDUMP_ERR_INVALID) {
		fprintf(stderr, "Cannot read %s: %s\n",
			ATTR_SYSNAME, kdump_get_err(ctx));
		rc = TEST_FAIL;
	} else
		printf("%s as a number: %s\n",
		       ATTR_SYSNAME, kdump_get_err(ctx));

	kdump_free(ctx);
	return rc;
}
