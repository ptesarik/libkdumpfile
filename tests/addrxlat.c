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
#include <string.h>
#include <getopt.h>
#include <addrxlat.h>

#include "testutil.h"

static addrxlat_paging_form_t paging_form;

static addrxlat_fulladdr_t pgt_root;

static int
set_paging_form(const char *spec)
{
	char *endp;

	paging_form.pteval_size = strtoul(spec, &endp, 0);
	if (*endp != ':') {
		fprintf(stderr, "Invalid paging form: %s\n", spec);
		return TEST_ERR;
	}

	do {
		if (paging_form.levels >= ADDRXLAT_MAXLEVELS) {
			fprintf(stderr, "Too many paging levels!\n");
			return TEST_ERR;
		}
		paging_form.bits[paging_form.levels++] =
			strtoul(endp + 1, &endp, 0);
	} while (*endp == ',');

	if (*endp) {
		fprintf(stderr, "Invalid paging form: %s\n", spec);
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
set_root(const char *spec)
{
	char *endp;

	endp = strchr(spec, ':');
	if (!endp) {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}

	if (!strncasecmp(spec, "KPHYSADDR:", endp - spec))
		pgt_root.as = ADDRXLAT_KPHYSADDR;
	else if (!strncasecmp(spec, "MACHPHYSADDR:", endp - spec))
		pgt_root.as = ADDRXLAT_MACHPHYSADDR;
	else if (!strncasecmp(spec, "KVADDR:", endp - spec))
		pgt_root.as = ADDRXLAT_KVADDR;
	else if (!strncasecmp(spec, "XENVADDR:", endp - spec))
		pgt_root.as = ADDRXLAT_XENVADDR;
	else {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}

	pgt_root.addr = strtoull(endp + 1, &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}
	return TEST_OK;
}

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

static const struct option opts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "paging", required_argument, NULL, 'p' },
	{ "root", required_argument, NULL, 'r' },
	{ NULL, 0, NULL, 0 }
};

static void
usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [<options>] <addr>\n"
		"\n"
		"Options:\n"
		"  -p|--paging sz:bits  Set paging form\n"
		"  -r|--root as:addr    Set the root page table address\n",
		name);
}

int
main(int argc, char **argv)
{
	unsigned long long vaddr;
	char *endp;
	addrxlat_ctx *ctx;
	int opt;
	int rc;

	while ((opt = getopt_long(argc, argv, "hp:r:", opts, NULL)) != -1) {
		switch (opt) {
		case 'p':
			rc = set_paging_form(optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'r':
			rc = set_root(optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'h':
		default:
			usage(argv[0]);
			return (opt == 'h') ? TEST_OK : TEST_ERR;
		}
	}

	if (argc - optind != 1 || !*argv[optind]) {
		fprintf(stderr, "Usage: %s <addr>\n", argv[0]);
		return TEST_ERR;
	}

	vaddr = strtoull(argv[optind], &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid address: %s\n", argv[optind]);
		return TEST_ERR;
	}

	ctx = addrxlat_new();
	if (!ctx) {
		perror("Cannot initialize address translation context");
		return TEST_ERR;
	}

	addrxlat_set_paging_form(ctx, &paging_form);
	addrxlat_set_pgt_root(ctx, pgt_root);
	rc = do_xlat(ctx, vaddr);

	addrxlat_free(ctx);
	return rc;
}
