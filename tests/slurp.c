/* Slurp whole file content.
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "testutil.h"

#define WATERMARK_LOW	256
#define WATERMARK_HIGH	1024

struct blob*
slurp_file(FILE *f)
{
	struct blob *ret, *newret;
	size_t alloc, newalloc;
	size_t remain, rd;

	ret = NULL;
	alloc = remain = 0;
	while (!feof(f)) {
		if (remain < WATERMARK_LOW) {
			newalloc = alloc + WATERMARK_HIGH - remain;
			newret = realloc(ret, newalloc + sizeof(struct blob));
			if (!newret)
				goto fail;

			alloc = newalloc;
			ret = newret;
			remain = WATERMARK_HIGH;
		}

		rd = fread(ret->data + alloc - remain, 1, remain, f);
		remain -= rd;
		if (ferror(f))
			goto fail;
	}

	if (remain) {
		alloc -= remain;
		newret = realloc(ret, newalloc + sizeof(struct blob));
		if (newret)
			ret = newret;
	}

	ret->length = alloc;
	return ret;

 fail:
	perror("Cannot slurp file");
	if (ret)
		free(ret);
	return NULL;
}

struct blob*
slurp(const char *fname)
{
	FILE *f;
	struct blob *ret;

	f = fopen(fname, "r");
	if (!f) {
		fprintf(stderr, "Cannot open %s: %s\n",
			fname, strerror(errno));
		return NULL;
	}

	ret = slurp_file(f);
	if (fclose(f) != TEST_OK) {
		fprintf(stderr, "Cannot close %s: %s\n",
			fname, strerror(errno));
		if (ret)
			free(ret);
		ret = NULL;
	}

	return ret;
}
