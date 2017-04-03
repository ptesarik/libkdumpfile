/* Addrxlat error reporting.
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
#include <stdlib.h>
#include <malloc.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <addrxlat.h>

#include "testutil.h"

/* To test all corner cases, this string should be bigger than
 * the internal fallback buffer (ERRBUF in addrxlat-priv.h)
 */
static const char loremipsum[] =
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit."
	" Nunc euismod dui in tristique tempus."
	" In sit amet erat interdum, porta velit in, pharetra nisi."
	" Nam nulla nibh, vestibulum at est a massa nunc.";

static const char othermsg[] =
	"Hopefully fits into fallback buffer";

#define MAXHOGS	1024
static int nhogs;
static void *hogs[MAXHOGS];

static int
force_nomem(void)
{
	struct rlimit rl;
	size_t sz;
	void *hog;

	malloc_trim(0);

	if (getrlimit(RLIMIT_AS, &rl)) {
		perror("Cannot get current AS limit");
		return -1;
	}
	rl.rlim_cur = 0;
	if (setrlimit(RLIMIT_AS, &rl)) {
		perror("Cannot set current AS limit");
		return -1;
	}
	for (sz = 1024; sz; sz >>= 1)
		while ( (hog = malloc(sz)) )
			if (nhogs < MAXHOGS)
				hogs[nhogs++] = hog;
	return 0;
}

static int
release_mem(void)
{
	struct rlimit rl;

	while (nhogs)
		free(hogs[--nhogs]);

	if (getrlimit(RLIMIT_AS, &rl)) {
		perror("Cannot get current AS limit");
		return -1;
	}
	rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_AS, &rl)) {
		perror("Cannot set current AS limit");
		return -1;
	}
	return 0;
}

int
main(int argc, char **argv)
{
	addrxlat_ctx_t *ctx;
	const char *err;
	void *(old_realloc_hook)(void *, size_t, const void *);
	int errors;
	size_t len, explen, maxlen;
	int i;

	ctx = addrxlat_ctx_new();
	if (!ctx) {
		perror("Cannot allocate context");
		return TEST_ERR;
	}

	errors = 0;

	puts("Testing single error message...");
	for (i = 0; i < sizeof(loremipsum); ++i) {
		addrxlat_ctx_clear_err(ctx);
		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE,
				 "%.*s", i, loremipsum);
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		if (len != i) {
			printf("Wrong error message length: %zd != %d\n",
			       len, i);
			++errors;
		}
		if (memcmp(err, loremipsum, i)) {
			printf("Wrong error message: %s\n", err);
			++errors;
		}
	}

	puts("Testing appended message...");
	for (i = 0; i < sizeof(loremipsum); ++i) {
		addrxlat_ctx_clear_err(ctx);
		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE, othermsg);
		err = addrxlat_ctx_get_err(ctx);
		if (strcmp(err, othermsg)) {
			printf("Wrong last level message: %s\n", err);
			++errors;
		}

		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE,
				 "%.*s", i, loremipsum);
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		explen = i + strlen(": ") + strlen(othermsg);
		if (len != explen) {
			printf("Wrong error message length: %zd != %zd\n",
			       len, explen);
			++errors;
		} else if (memcmp(err, loremipsum, i) ||
			   memcmp(err + i, ": ", 2) ||
			   strcmp(err + i + 2, othermsg)) {
			printf("Wrong error message: %s\n", err);
			++errors;
		}
	}

	puts("Testing prepended message...");
	for (i = 0; i < sizeof(loremipsum); ++i) {
		addrxlat_ctx_clear_err(ctx);
		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE,
				 "%.*s", i, loremipsum);
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		if (len != i || memcmp(err, loremipsum, i)) {
			printf("Wrong original message (len=%d)\n", i);
			++errors;
			continue;
		}

		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE, othermsg);
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		explen = strlen(othermsg) + i;
		if (i > 0)
			explen += strlen(": ");
		if (len != explen) {
			printf("Wrong error message length: %zd != %zd\n",
			       len, explen);
			++errors;
		} else if (i == 0) {
			if (strcmp(err, othermsg)) {
				printf("Wrong error message: %s\n", err);
				++errors;
			}
		} else if (memcmp(err, othermsg, strlen(othermsg)) ||
			   memcmp(err + strlen(othermsg), ": ", 2) ||
			   memcmp(err + strlen(othermsg) + 2, loremipsum, i)) {
			printf("Wrong error message: %s\n", err);
			++errors;
		}
	}

	puts("Invalid format string...");
	addrxlat_ctx_clear_err(ctx);
	addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE,
			 "%9999999999999d", 0);
	err = addrxlat_ctx_get_err(ctx);
	if (strcmp(err, "(bad format string)")) {
		printf("Unexpected message: %s\n", err);
		++errors;
	}

	/* Allocation failures. */
	puts("\nALLOCATION FAILURE TESTS"
	     "\n------------------------\n");

	/* First, allocate a new context to make sure that already allocated
	 * space cannot be re-used. */
	addrxlat_ctx_decref(ctx);
	ctx = addrxlat_ctx_new();
	if (!ctx) {
		perror("Cannot allocate fresh context");
		return TEST_ERR;
	}

	/* Get size of the fallback buffer. */
	if (force_nomem())
		return TEST_ERR;
	addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE, loremipsum);
	if (release_mem())
		return TEST_ERR;

	err = addrxlat_ctx_get_err(ctx);
	if (err[0] != '<') {
		printf("Error message not truncated: %s\n", err);
		++errors;
		goto out;
	}

	maxlen = strlen(err);
	printf("Fallback buffer length: %zd\n", maxlen);

	puts("Testing single error message...");
	if (force_nomem())
		return TEST_ERR;
	for (i = maxlen; i < sizeof(loremipsum); ++i) {
		addrxlat_ctx_clear_err(ctx);
		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE,
				 "%.*s", i, loremipsum);
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		if (len != maxlen) {
			printf("Wrong error message length: %zd != %zd\n",
			       len, maxlen);
			++errors;
		}
		if ((i <= maxlen && memcmp(err, loremipsum, maxlen)) ||
		    (i > maxlen &&
		     (err[0] != '<' ||
		      memcmp(err + 1, loremipsum + 1, maxlen - 2) ||
		      err[maxlen-1] != '>'))) {
			printf("Wrong error message: %s\n", err);
			++errors;
		}
	}
	if (release_mem())
		return TEST_ERR;

	puts("Testing appended message...");
	if (force_nomem())
		return TEST_ERR;
	for (i = maxlen - strlen(othermsg) - 2; i < sizeof(loremipsum); ++i) {
		addrxlat_ctx_clear_err(ctx);
		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE, othermsg);
		err = addrxlat_ctx_get_err(ctx);
		if (strcmp(err, othermsg)) {
			printf("Wrong last level message: %s\n", err);
			++errors;
		}

		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE,
				 "%.*s", i, loremipsum);
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		if (len != maxlen) {
			printf("Wrong error message length: %zd != %zd\n",
			       len, maxlen);
			++errors;
			continue;
		}

		len -= strlen(othermsg) + 2;
		if (memcmp(err + len, ": ", 2) ||
		    strcmp(err + len + 2, othermsg)) {
			printf("Wrong other message: %s\n", err);
			++errors;
		} else if (i <= maxlen - strlen(othermsg) - 2) {
			if (memcmp(err, loremipsum, i)) {
				printf("Wrong error message: %s\n", err);
				++errors;
			}
		} else if (err[0] != '<') {
			printf("Wrong truncate at begin: %s\n", err);
			++errors;
		} else if (i <= maxlen) {
			if (memcmp(err + 1, loremipsum + 1 + i - len, len - 1)) {
				printf("Wrong truncate at end: %s\n", err);
				++errors;
			}
		} else if (memcmp(err + 1, loremipsum + 1 + maxlen - len, len - 2) ||
			   err[len-1] != '>') {
			printf("Wrong truncate in middle: %s\n", err);
			++errors;
		}
	}
	if (release_mem())
		return TEST_ERR;

	puts("Testing prepended message...");
	for (i = maxlen - strlen(othermsg) - 2; i < sizeof(loremipsum); ++i) {
		addrxlat_ctx_clear_err(ctx);
		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE,
				 "%.*s", i, loremipsum);
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		if (len != i || memcmp(err, loremipsum, i)) {
			printf("Wrong original message (len=%d)\n", i);
			++errors;
			continue;
		}

		if (force_nomem())
			return TEST_ERR;
		addrxlat_ctx_err(ctx, ADDRXLAT_CUSTOM_STATUS_BASE, othermsg);
		if (release_mem())
			return TEST_ERR;
		err = addrxlat_ctx_get_err(ctx);
		len = strlen(err);
		if (i <= maxlen)
			explen = maxlen;
		else
			explen = i + 1;
		if (len != explen) {
			printf("Wrong error message length: %zd != %zd\n",
			       len, explen);
			++errors;
			continue;
		}

		if (i == maxlen - strlen(othermsg) - 2) {
			if (memcmp(err, othermsg, strlen(othermsg)) ||
			    memcmp(err + len - i - 2, ": ", 2) ||
			    memcmp(err + len - i, loremipsum, i)) {
				printf("Wrong message: %s\n", err);
				++errors;
			}
		} else if (err[0] != '<') {
			printf("Message not truncated: %s\n", err);
			++errors;
		} else if (i < maxlen - 2) {
			if (memcmp(err + 1, othermsg + strlen(othermsg) - (len - i - 3), len - i - 3) ||
			    memcmp(err + len - i - 2, ": ", 2) ||
			    memcmp(err + len - i, loremipsum, i)) {
				printf("Wrong combined message: %s\n", err);
			}
		} else if (i == maxlen - 2) {
			if (memcmp(err + 1, othermsg + strlen(othermsg) - (len - i - 2), len - i - 2) ||
			    err[len - i - 1] != ' ' ||
			    memcmp(err + len - i, loremipsum, i)) {
				printf("Wrong combined message: %s\n", err);
			}
		} else if (i == maxlen) {
			if (memcmp(err + 1, loremipsum + 1, maxlen - 1)) {
				printf("Wrong truncate at begin: %s\n", err);
				++errors;
			}
		} else if (memcmp(err + 1, loremipsum, i)) {
			printf("Wrong message: %s\n", err);
			++errors;
		}
	}

out:
	printf("\nAll done: %d errors\n", errors);

	return errors == 0 ? TEST_OK : TEST_FAIL;
}
