/* Check VMCOREINFO per-line post-set hooks.
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

#define xstr(s)	#s
#define str(s)	xstr(s)

#define OSRELEASE	"3.4.5-test"
#define ALT_OSRELEASE	"4.0.0-test"
#define ATTR_OSRELEASE	"linux.uts.release"

#define PAGESIZE	2048	/* unlikely to match host page size. */
#define ALT_PAGESIZE	8192
#define ATTR_PAGESIZE	"arch.page_size"

#define SYM_NAME	"test_symbol"
#define SYM_VALUE	0x123456
#define ALT_SYM_VALUE	0x789abc

#define LEN_NAME	"test_length"
#define LEN_VALUE	16
#define ALT_LEN_VALUE	20
#define ATTR_LEN	"linux.vmcoreinfo.LENGTH." LEN_NAME

#define NUM_NAME	"test_number"
#define NUM_VALUE	64
#define ALT_NUM_VALUE	128
#define ATTR_NUM	"linux.vmcoreinfo.NUMBER." NUM_NAME

#define OFF_NAME	"test_struct.test_off"
#define OFF_VALUE	80
#define ALT_OFF_VALUE	96
#define ATTR_OFF	"linux.vmcoreinfo.OFFSET." OFF_NAME

#define SIZE_NAME	"test_size"
#define SIZE_VALUE	240
#define ALT_SIZE_VALUE	320
#define ATTR_SIZE	"linux.vmcoreinfo.SIZE." SIZE_NAME

#define ATTR_LINES	"linux.vmcoreinfo.lines"

static const char vmcore[] =
	"OSRELEASE=" OSRELEASE			"\n"
	"PAGESIZE=" str(PAGESIZE)		"\n"
	"SYMBOL(" SYM_NAME ")=" str(SYM_VALUE)	"\n"
	"LENGTH(" LEN_NAME ")=" str(LEN_VALUE)	"\n"
	"NUMBER(" NUM_NAME ")=" str(NUM_VALUE)	"\n"
	"OFFSET(" OFF_NAME ")=" str(OFF_VALUE)	"\n"
	"SIZE(" SIZE_NAME ")=" str(SIZE_VALUE)	"\n"
	"";

static int
check_string(kdump_ctx *ctx, const char *attrpath, const char *expect)
{
	kdump_attr_t attr;
	kdump_status status;

	status = kdump_get_attr(ctx, attrpath, &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "%s: Cannot get value: %s\n",
			attrpath, kdump_err_str(ctx));
		return TEST_ERR;
	}
	if (attr.type != kdump_string) {
		fprintf(stderr, "%s: Wrong attribute type: %d\n",
			attrpath, (int) attr.type);
		return TEST_FAIL;
	}
	if (strcmp(attr.val.string, expect)) {
		fprintf(stderr, "%s: Invalid attribute value: '%s' != '%s'\n",
			attrpath, attr.val.string, expect);
		return TEST_FAIL;
	}

	printf("%s: %s\n", attrpath, attr.val.string);
	return TEST_OK;
}

static int
check_number(kdump_ctx *ctx, const char *attrpath, long long expect)
{
	kdump_attr_t attr;
	kdump_status status;

	status = kdump_get_attr(ctx, attrpath, &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "%s: Cannot get value: %s\n",
			attrpath, kdump_err_str(ctx));
		return TEST_ERR;
	}
	if (attr.type != kdump_number) {
		fprintf(stderr, "%s: Wrong attribute type: %d\n",
			attrpath, (int) attr.type);
		return TEST_FAIL;
	}
	if (attr.val.number != expect) {
		fprintf(stderr, "%s: Invalid attribute value: %lld != %lld\n",
			attrpath, (long long) attr.val.number, expect);
		return TEST_FAIL;
	}

	printf("%s: %lld\n", attrpath, (long long) attr.val.number);

	return TEST_OK;
}

static int
check(kdump_ctx *ctx)
{
	kdump_attr_t attr;
	kdump_addr_t symval;
	kdump_status status;
	int rc, tmprc;

	attr.type = kdump_string;
	attr.val.string = "linux";
	status = kdump_set_attr(ctx, "addrxlat.ostype", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot set ostype: %s\n",
			kdump_err_str(ctx));
		return TEST_ERR;
	}

	attr.type = kdump_string;
	attr.val.string = vmcore;
	status = kdump_set_attr(ctx, "linux.vmcoreinfo.raw", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot set vmcoreinfo: %s\n",
			kdump_err_str(ctx));
		return TEST_ERR;
	}

	rc = TEST_OK;
	attr.type = kdump_string;

	/* Check modifications */
	attr.val.string = ALT_OSRELEASE;
	status = kdump_set_attr(ctx, ATTR_LINES ".OSRELEASE", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot modify %s: %s\n",
			ATTR_LINES ".OSRELEASE", kdump_err_str(ctx));
		return TEST_ERR;
	}
	tmprc = check_string(ctx, ATTR_OSRELEASE, ALT_OSRELEASE);
	if (tmprc == TEST_ERR)
		return tmprc;
	if (tmprc != TEST_OK)
		rc = tmprc;

	attr.val.string= str(ALT_PAGESIZE);
	status = kdump_set_attr(ctx, ATTR_LINES ".PAGESIZE", &attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot modify %s: %s\n",
			ATTR_LINES ".PAGESIZE", kdump_err_str(ctx));
		return TEST_ERR;
	}
	tmprc = check_number(ctx, ATTR_PAGESIZE, ALT_PAGESIZE);
	if (tmprc == TEST_ERR)
		return tmprc;
	if (tmprc != TEST_OK)
		rc = tmprc;

	attr.val.string= str(ALT_SYM_VALUE);
	status = kdump_set_attr(ctx, ATTR_LINES ".SYMBOL(" SYM_NAME ")",
				&attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot modify %s: %s\n",
			ATTR_LINES ".SYMBOL(" SYM_NAME ")",
			kdump_err_str(ctx));
		return TEST_ERR;
	}
	status = kdump_vmcoreinfo_symbol(ctx, SYM_NAME, &symval);
	if (status != kdump_ok) {
		fprintf(stderr, "%s: Cannot get value: %s\n",
			SYM_NAME, kdump_err_str(ctx));
		return TEST_ERR;
	}
	if (symval != ALT_SYM_VALUE) {
		fprintf(stderr, "%s: Invalid attribute value: %llx != %llx\n",
			SYM_NAME, (long long) symval,
			(long long) ALT_SYM_VALUE);
		rc = TEST_FAIL;
	} else
		printf("%s = %llx\n", SYM_NAME, (long long) symval);


	attr.val.string= str(ALT_LEN_VALUE);
	status = kdump_set_attr(ctx, ATTR_LINES ".LENGTH(" LEN_NAME ")",
				&attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot modify %s: %s\n",
			ATTR_LINES ".LENGTH(" LEN_NAME ")",
			kdump_err_str(ctx));
		return TEST_ERR;
	}
	tmprc = check_number(ctx, ATTR_LEN, ALT_LEN_VALUE);
	if (tmprc == TEST_ERR)
		return tmprc;
	if (tmprc != TEST_OK)
		rc = tmprc;

	attr.val.string= str(ALT_NUM_VALUE);
	status = kdump_set_attr(ctx, ATTR_LINES ".NUMBER(" NUM_NAME ")",
				&attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot modify %s: %s\n",
			ATTR_LINES ".NUMBER(" NUM_NAME ")",
			kdump_err_str(ctx));
		return TEST_ERR;
	}
	tmprc = check_number(ctx, ATTR_NUM, ALT_NUM_VALUE);
	if (tmprc == TEST_ERR)
		return tmprc;
	if (tmprc != TEST_OK)
		rc = tmprc;

	attr.val.string= str(ALT_OFF_VALUE);
	status = kdump_set_attr(ctx, ATTR_LINES ".OFFSET(" OFF_NAME ")",
				&attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot modify %s: %s\n",
			ATTR_LINES ".OFFSET(" OFF_NAME ")",
			kdump_err_str(ctx));
		return TEST_ERR;
	}
	tmprc = check_number(ctx, ATTR_OFF, ALT_OFF_VALUE);
	if (tmprc == TEST_ERR)
		return tmprc;
	if (tmprc != TEST_OK)
		rc = tmprc;

	attr.val.string= str(ALT_SIZE_VALUE);
	status = kdump_set_attr(ctx, ATTR_LINES ".SIZE(" SIZE_NAME ")",
				&attr);
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot modify %s: %s\n",
			ATTR_LINES ".SIZE(" SIZE_NAME ")",
			kdump_err_str(ctx));
		return TEST_ERR;
	}
	tmprc = check_number(ctx, ATTR_SIZE, ALT_SIZE_VALUE);
	if (tmprc == TEST_ERR)
		return tmprc;
	if (tmprc != TEST_OK)
		rc = tmprc;

	/* Check cleanup */

	return rc;
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
