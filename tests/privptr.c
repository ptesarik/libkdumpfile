/* Chek private data pointer.
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

static char test_string[] = "Hello, world!";

int main(int argc, char **argv)
{
	kdump_ctx *ctx;
	char *priv;

	ctx = kdump_init();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	puts("Set string private data");
	kdump_set_priv(ctx, test_string);
	priv = kdump_get_priv(ctx);
	if (priv != test_string) {
		fprintf(stderr, "Expected %p (\"%s\"), got %p%s%s%s\n",
			test_string, test_string, priv,
			priv ? " (\"" : "", priv ?: "", priv ? "\")" : "");
		return TEST_FAIL;
	}

	puts("Set NULL private data");
	kdump_set_priv(ctx, NULL);
	priv = kdump_get_priv(ctx);
	if (priv != NULL) {
		fprintf(stderr, "Expected NULL, got %p\n", priv);
		return TEST_FAIL;
	}

	kdump_free(ctx);
	puts("OK");
	return TEST_OK;
}
