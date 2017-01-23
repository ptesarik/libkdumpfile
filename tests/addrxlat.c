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

static addrxlat_meth_t *xlat;

#define MAXERR	64
static char read_err_str[MAXERR];

#define ALLOC_INC 32

static size_t nentries;
static addrxlat_lookup_elem_t *entries;

addrxlat_lookup_elem_t*
find_entry(addrxlat_addr_t addr)
{
	size_t i;
	for (i = 0; i < nentries; ++i)
		if (entries[i].virt == addr)
			return &entries[i];
	return NULL;
}

static addrxlat_status
read32(void *data, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	addrxlat_lookup_elem_t *ent = find_entry(addr->addr);
	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%"ADDRXLAT_PRIxADDR,
			 addr->addr);
		return -read_notfound;
	}
	*val = ent->phys;
	return addrxlat_ok;
}

static addrxlat_status
read64(void *data, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	addrxlat_lookup_elem_t *ent = find_entry(addr->addr);
	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%"ADDRXLAT_PRIxADDR,
			 addr->addr);
		return -read_notfound;
	}
	*val = ent->phys;
	return addrxlat_ok;
}

static int
add_entry(const char *spec)
{
	unsigned long long addr, val;
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

	if ((nentries % ALLOC_INC) == 0) {
		addrxlat_lookup_elem_t *newentries;
		newentries = realloc(entries, ((nentries + ALLOC_INC) *
					       sizeof(*entries)));
		if (!newentries) {
			perror("Cannot allocate entry");
			return TEST_ERR;
		}
		entries = newentries;
	}

	entries[nentries].virt = addr;
	entries[nentries].phys = val;
	++nentries;

	return TEST_OK;
}

static int
set_paging_form(addrxlat_paging_form_t *pf, const char *spec)
{
	char *endp;

	endp = strchr(spec, ':');
	if (!endp) {
		fprintf(stderr, "Invalid paging form: %s\n", spec);
		return TEST_ERR;
	}

	if (!strncasecmp(spec, "none:", endp - spec + 1))
		pf->pte_format = addrxlat_pte_none;
	else if (!strncasecmp(spec, "ia32:", endp - spec + 1))
		pf->pte_format = addrxlat_pte_ia32;
	else if (!strncasecmp(spec, "ia32_pae:", endp - spec + 1))
		pf->pte_format = addrxlat_pte_ia32_pae;
	else if (!strncasecmp(spec, "x86_64:", endp - spec + 1))
		pf->pte_format = addrxlat_pte_x86_64;
	else if (!strncasecmp(spec, "s390x:", endp - spec + 1))
		pf->pte_format = addrxlat_pte_s390x;
	else if (!strncasecmp(spec, "ppc64_linux_rpn30:", endp - spec + 1))
		pf->pte_format = addrxlat_pte_ppc64_linux_rpn30;
	else {
		fprintf(stderr, "Unknown PTE format: %s\n", spec);
		return TEST_ERR;
	}

	pf->levels = 0;
	do {
		if (pf->levels >= ADDRXLAT_MAXLEVELS) {
			fprintf(stderr, "Too many paging levels!\n");
			return TEST_ERR;
		}
		pf->bits[pf->levels++] =
			strtoul(endp + 1, &endp, 0);
	} while (*endp == ',');

	if (*endp) {
		fprintf(stderr, "Invalid paging form: %s\n", spec);
		return TEST_ERR;
	}

	return TEST_OK;
}

static addrxlat_addrspace_t
get_addrspace(const char *p, const char *endp)
{
	if (!strncasecmp(p, "KPHYSADDR:", endp - p))
		return ADDRXLAT_KPHYSADDR;
	else if (!strncasecmp(p, "MACHPHYSADDR:", endp - p))
		return ADDRXLAT_MACHPHYSADDR;
	else if (!strncasecmp(p, "KVADDR:", endp - p))
		return ADDRXLAT_KVADDR;
	else if (!strncasecmp(p, "XENVADDR:", endp - p))
		return ADDRXLAT_XENVADDR;
	else
		return ADDRXLAT_NOADDR;
}

static int
set_root(addrxlat_fulladdr_t *root, const char *spec)
{
	char *endp;

	endp = strchr(spec, ':');
	if (!endp) {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}

	root->as = get_addrspace(spec, endp);
	if (root->as == ADDRXLAT_NOADDR) {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}

	root->addr = strtoull(endp + 1, &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid address spec: %s\n", spec);
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
set_linear(addrxlat_off_t *off, const char *spec)
{
	char *endp;

	*off = strtoll(spec, &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid offset: %s\n", spec);
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
set_lookup(addrxlat_addr_t *endoff, const char *spec)
{
	char *endp;

	*endoff = strtoll(spec, &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid page size: %s\n", spec);
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
set_memarr(addrxlat_def_memarr_t *ma, const char *spec)
{
	char *endp;

	endp = strchr(spec, ':');
	if (!endp) {
		fprintf(stderr, "Invalid memory array: %s\n", spec);
		return TEST_ERR;
	}

	ma->base.as = get_addrspace(spec, endp);
	if (ma->base.as == ADDRXLAT_NOADDR) {
		fprintf(stderr, "Invalid base address space: %s\n", spec);
		return TEST_ERR;
	}

	ma->base.addr = strtoull(endp + 1, &endp, 0);
	if (*endp != ':') {
		fprintf(stderr, "Invalid base address: %s\n", spec);
		return TEST_ERR;
	}

	ma->shift = strtoul(endp + 1, &endp, 0);
	if (*endp != ':') {
		fprintf(stderr, "Invalid shift: %s\n", spec);
		return TEST_ERR;
	}

	ma->elemsz = strtoul(endp + 1, &endp, 0);
	if (*endp != ':') {
		fprintf(stderr, "Invalid element size: %s\n", spec);
		return TEST_ERR;
	}

	ma->valsz = strtoul(endp + 1, &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid value size: %s\n", spec);
		return TEST_ERR;
	}

	return TEST_OK;
}


static int
do_xlat(addrxlat_ctx_t *ctx, addrxlat_addr_t addr)
{
	addrxlat_status status;

	status = addrxlat_walk(ctx, xlat, &addr);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Address translation failed: %s\n",
			((int) status > 0
			 ? addrxlat_ctx_err(ctx)
			 : read_err_str));
		return TEST_FAIL;
	}

	printf("0x%"ADDRXLAT_PRIxADDR "\n", addr);

	return TEST_OK;
}

static const struct option opts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "entry", required_argument, NULL, 'e' },
	{ "form", required_argument, NULL, 'f' },
	{ "root", required_argument, NULL, 'r' },
	{ "linear", required_argument, NULL, 'l' },
	{ "memarr", required_argument, NULL, 'm' },
	{ "pgt", no_argument, NULL, 'p' },
	{ "table", required_argument, NULL, 't' },
	{ NULL, 0, NULL, 0 }
};

static void
usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [<options>] <addr>\n"
		"\n"
		"Options:\n"
		"  -l|--linear off       Use linear transation\n"
		"  -p|--pgt              Use page table translation\n"
		"  -t|--table pgendoff   Use table lookup translation\n"
		"  -m|--memarr params    Use memory array translation\n"
		"  -f|--form fmt:bits    Set paging form\n"
		"  -r|--root as:addr     Set the root page table address\n"
		"  -e|--entry addr:val   Set table entry value\n",
		name);
}

int
main(int argc, char **argv)
{
	unsigned long long vaddr;
	char *endp;
	addrxlat_ctx_t *ctx;
	addrxlat_def_t pgt, linear, lookup, memarr, *def;
	int opt;
	addrxlat_status status;
	unsigned long refcnt;
	int rc;

	ctx = NULL;
	def = NULL;

	pgt.kind = ADDRXLAT_PGT;
	pgt.param.pgt.root.as = ADDRXLAT_NONE;
	pgt.param.pgt.root.addr = 0;

	linear.kind = ADDRXLAT_LINEAR;
	linear.param.linear.off = 0;

	lookup.kind = ADDRXLAT_LOOKUP;
	lookup.param.lookup.endoff = 0;

	memarr.kind = ADDRXLAT_MEMARR;
	memarr.param.memarr.base.as = ADDRXLAT_NOADDR;

	while ((opt = getopt_long(argc, argv, "he:f:l:m:pr:t:",
				  opts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			def = &pgt;
			rc = set_paging_form(&def->param.pgt.pf, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'r':
			def = &pgt;
			rc = set_root(&def->param.pgt.root, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'e':
			rc = add_entry(optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'l':
			def = &linear;
			rc = set_linear(&def->param.linear.off, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'm':
			def = &memarr;
			rc = set_memarr(&def->param.memarr, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'p':
			def = &pgt;
			break;

		case 't':
			def = &lookup;
			rc = set_lookup(&def->param.lookup.endoff, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'h':
		default:
			usage(argv[0]);
			rc = (opt == 'h') ? TEST_OK : TEST_ERR;
			goto out;
		}
	}

	if (def == NULL) {
		fputs("No translation method specified\n", stderr);
		return TEST_ERR;
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

	xlat = addrxlat_meth_new();
	if (!xlat) {
		perror("Cannot allocate translation method");
		rc = TEST_ERR;
		goto out;
	}

	lookup.param.lookup.nelem = nentries;
	lookup.param.lookup.tbl = entries;

	status = addrxlat_meth_set_def(xlat, def);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Cannot set up address translation\n");
		rc = TEST_ERR;
		goto out;
	}

	ctx = addrxlat_ctx_new();
	if (!ctx) {
		perror("Cannot initialize address translation context");
		rc = TEST_ERR;
		goto out;
	}

	addrxlat_ctx_cb_read32(ctx, read32);
	addrxlat_ctx_cb_read64(ctx, read64);

	rc = do_xlat(ctx, vaddr);

 out:
	if (xlat && (refcnt = addrxlat_meth_decref(xlat)) != 0)
		fprintf(stderr, "WARNING: Leaked %lu method references\n",
			refcnt);

	if (ctx && (refcnt = addrxlat_ctx_decref(ctx)) != 0)
		fprintf(stderr, "WARNING: Leaked %lu addrxlat references\n",
			refcnt);

	return rc;
}
