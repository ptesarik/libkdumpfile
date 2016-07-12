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

enum read_status {
	read_ok = addrxlat_ok,
	read_notfound,
};

static addrxlat_paging_form_t paging_form;

static addrxlat_pgt_root_t pgt_root;

#define MAXERR	64
static char read_err_str[MAXERR];

struct entry {
	struct entry *next;
	addrxlat_addr_t addr;
	unsigned long long val;
};

struct entry *entry_list;

struct entry*
find_entry(addrxlat_addr_t addr)
{
	struct entry *ent;
	for (ent = entry_list; ent; ent = ent->next)
		if (ent->addr == addr)
			return ent;
	return NULL;
}

static addrxlat_status
read32(addrxlat_ctx *ctx, addrxlat_fulladdr_t addr, uint32_t *val, void *data)
{
	struct entry *ent = find_entry(addr.addr);
	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%llx",
			 (unsigned long long) addr.addr);
		return -read_notfound;
	}
	*val = ent->val;
	return addrxlat_ok;
}

static addrxlat_status
read64(addrxlat_ctx *ctx, addrxlat_fulladdr_t addr, uint64_t *val, void *data)
{
	struct entry *ent = find_entry(addr.addr);
	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%llx",
			 (unsigned long long) addr.addr);
		return -read_notfound;
	}
	*val = ent->val;
	return addrxlat_ok;
}

static int
add_entry(const char *spec)
{
	unsigned long long addr, val;
	struct entry *ent;
	char *endp;

	addr = strtoull(spec, &endp, 0);
	if (*endp != ':') {
		fprintf(stderr, "Invalid entry spec: %s\n", spec);
		return TEST_ERR;
	}

	val = strtoull(endp + 1, &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid entry spec: %s\n", spec);
		return TEST_ERR;
	}

	ent = malloc(sizeof(*ent));
	if (!ent) {
		perror("Cannot allocate entry");
		return TEST_ERR;
	}

	ent->next = entry_list;
	ent->addr = addr;
	ent->val = val;
	entry_list = ent;

	return TEST_OK;
}

static int
set_paging_form(const char *spec)
{
	char *endp;

	endp = strchr(spec, ':');
	if (!endp) {
		fprintf(stderr, "Invalid paging form: %s\n", spec);
		return TEST_ERR;
	}

	if (!strncasecmp(spec, "none:", endp - spec))
		paging_form.pte_format = addrxlat_pte_none;
	else if (!strncasecmp(spec, "ia32:", endp - spec))
		paging_form.pte_format = addrxlat_pte_ia32;
	else if (!strncasecmp(spec, "ia32_pae:", endp - spec))
		paging_form.pte_format = addrxlat_pte_ia32_pae;
	else if (!strncasecmp(spec, "x86_64:", endp - spec))
		paging_form.pte_format = addrxlat_pte_x86_64;
	else if (!strncasecmp(spec, "s390x:", endp - spec))
		paging_form.pte_format = addrxlat_pte_s390x;
	else if (!strncasecmp(spec, "ppc64:", endp - spec))
		paging_form.pte_format = addrxlat_pte_ppc64;
	else {
		fprintf(stderr, "Unknown PTE format: %s\n", spec);
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

	if (*endp == ':')
		paging_form.rpn_shift = strtoul(endp + 1, &endp, 0);

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
	addrxlat_fulladdr_t *addrspec;

	endp = strchr(spec, ':');
	if (!endp) {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}

	addrspec = &pgt_root.kernel;
	if (!strncasecmp(spec, "KPHYSADDR:", endp - spec))
		addrspec->as = ADDRXLAT_KPHYSADDR;
	else if (!strncasecmp(spec, "MACHPHYSADDR:", endp - spec))
		addrspec->as = ADDRXLAT_MACHPHYSADDR;
	else if (!strncasecmp(spec, "KVADDR:", endp - spec))
		addrspec->as = ADDRXLAT_KVADDR;
	else if (!strncasecmp(spec, "XENVADDR:", endp - spec))
		addrspec->as = ADDRXLAT_XENVADDR;
	else {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}

	addrspec->addr = strtoull(endp + 1, &endp, 0);
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

	status = addrxlat_vtop_pgt(ctx, ADDRXLAT_SCOPE_KERNEL, vaddr, &paddr);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Address translation failed: %s\n",
			((int) status > 0
			 ? addrxlat_err_str(ctx)
			 : read_err_str));
		return TEST_FAIL;
	}

	printf("0x%llx\n", (unsigned long long)paddr);

	return TEST_OK;
}

static const struct option opts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "entry", required_argument, NULL, 'e' },
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
		"  -p|--paging fmt:bits  Set paging form\n"
		"  -r|--root as:addr     Set the root page table address\n"
		"  -e|--entry addr:val   Set page table entry value\n",
		name);
}

int
main(int argc, char **argv)
{
	unsigned long long vaddr;
	char *endp;
	addrxlat_ctx *ctx;
	int opt;
	addrxlat_status status;
	unsigned long refcnt;
	int rc;

	while ((opt = getopt_long(argc, argv, "he:p:r:", opts, NULL)) != -1) {
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

		case 'e':
			rc = add_entry(optarg);
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

	status = addrxlat_set_paging_form(ctx, &paging_form);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Cannot set paging form: %s\n",
			addrxlat_err_str(ctx));
		rc = TEST_ERR;
		goto err;
	}

	addrxlat_set_pgt_root(ctx, &pgt_root);
	addrxlat_cb_read32(ctx, read32);
	addrxlat_cb_read64(ctx, read64);

	rc = do_xlat(ctx, vaddr);

 err:
	refcnt = addrxlat_decref(ctx);
	if (refcnt)
		fprintf(stderr, "WARNING: Leaked %lu addrxlat references\n",
			refcnt);

	return rc;
}
