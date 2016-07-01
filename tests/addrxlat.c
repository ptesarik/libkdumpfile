/* Address translation.
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
#include <addrxlat.h>

#include "testutil.h"

static int
do_xlat(addrxlat_ctx *ctx, addrxlat_addr_t vaddr)
{
	addrxlat_addr_t paddr;
	addrxlat_status status;

	status = addrxlat_vtop_pgt(ctx, vaddr, &paddr);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Address translation failed: %s\n",
			addrxlat_err_str(ctx));
		return TEST_FAIL;
	}

	printf("0x%llx\n", (unsigned long long)paddr);

	return TEST_OK;
}

int
main(int argc, char **argv)
{
	unsigned long long vaddr;
	char *endp;
	addrxlat_ctx *ctx;
	int rc;

	if (argc != 2 || !*argv[1]) {
		fprintf(stderr, "Usage: %s <addr>\n", argv[0]);
		return TEST_ERR;
	}

	vaddr = strtoull(argv[1], &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid address: %s", argv[1]);
		return TEST_ERR;
	}

	ctx = addrxlat_new();
	if (!ctx) {
		perror("Cannot initialize address translation context");
		return TEST_ERR;
	}

	rc = do_xlat(ctx, vaddr);

	addrxlat_free(ctx);
	return rc;
}
