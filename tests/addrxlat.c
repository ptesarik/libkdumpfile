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

static addrxlat_meth_t *xlat;

#define ALLOC_INC 32

static size_t nentries;
static addrxlat_lookup_elem_t *entries;

addrxlat_lookup_elem_t*
find_entry(addrxlat_addr_t addr)
{
	size_t i;
	for (i = 0; i < nentries; ++i)
		if (entries[i].orig == addr)
			return &entries[i];
	return NULL;
}

static addrxlat_status
read32(void *data, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	addrxlat_ctx_t *ctx = data;
	addrxlat_lookup_elem_t *ent = find_entry(addr->addr);
	if (!ent)
		return addrxlat_ctx_err(ctx, ADDRXLAT_ERR_NODATA, "No data");
	*val = ent->dest;
	return ADDRXLAT_OK;
}

static addrxlat_status
read64(void *data, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	addrxlat_ctx_t *ctx = data;
	addrxlat_lookup_elem_t *ent = find_entry(addr->addr);
	if (!ent)
		return addrxlat_ctx_err(ctx, ADDRXLAT_ERR_NODATA, "No data");
	*val = ent->dest;
	return ADDRXLAT_OK;
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

	entries[nentries].orig = addr;
	entries[nentries].dest = val;
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
		pf->pte_format = ADDRXLAT_PTE_NONE;
	else if (!strncasecmp(spec, "pfn32:", endp - spec + 1))
		pf->pte_format = ADDRXLAT_PTE_PFN32;
	else if (!strncasecmp(spec, "pfn64:", endp - spec + 1))
		pf->pte_format = ADDRXLAT_PTE_PFN64;
	else if (!strncasecmp(spec, "ia32:", endp - spec + 1))
		pf->pte_format = ADDRXLAT_PTE_IA32;
	else if (!strncasecmp(spec, "ia32_pae:", endp - spec + 1))
		pf->pte_format = ADDRXLAT_PTE_IA32_PAE;
	else if (!strncasecmp(spec, "x86_64:", endp - spec + 1))
		pf->pte_format = ADDRXLAT_PTE_X86_64;
	else if (!strncasecmp(spec, "s390x:", endp - spec + 1))
		pf->pte_format = ADDRXLAT_PTE_S390X;
	else if (!strncasecmp(spec, "ppc64_linux_rpn30:", endp - spec + 1))
		pf->pte_format = ADDRXLAT_PTE_PPC64_LINUX_RPN30;
	else {
		fprintf(stderr, "Unknown PTE format: %s\n", spec);
		return TEST_ERR;
	}

	pf->nfields = 0;
	do {
		if (pf->nfields >= ADDRXLAT_FIELDS_MAX) {
			fprintf(stderr, "Too many paging levels!\n");
			return TEST_ERR;
		}
		pf->fieldsz[pf->nfields++] =
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
set_memarr(addrxlat_param_memarr_t *ma, const char *spec)
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
	addrxlat_step_t step;
	addrxlat_status status;

	step.ctx = ctx;
	step.sys = NULL;
	step.meth = xlat;
	status = addrxlat_launch(&step, addr);
	if (status != ADDRXLAT_OK) {
		fprintf(stderr, "Cannot launch address translation: %s\n",
			addrxlat_ctx_get_err(ctx));
		return TEST_FAIL;
	}

	status = addrxlat_walk(&step);
	if (status != ADDRXLAT_OK) {
		fprintf(stderr, "Address translation failed: %s\n",
			addrxlat_ctx_get_err(ctx));
		return TEST_FAIL;
	}

	printf("0x%"ADDRXLAT_PRIxADDR "\n", step.base.addr);

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
		"  -f|--form fmt:fields  Set paging form\n"
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
	addrxlat_cb_t cb = {
		.read32 = read32,
		.read64 = read64,
		.read_caps = (ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR) |
			      ADDRXLAT_CAPS(ADDRXLAT_KVADDR))
	};
	addrxlat_desc_t pgt, linear, lookup, memarr, *desc;
	int opt;
	addrxlat_status status;
	unsigned long refcnt;
	int rc;

	ctx = NULL;
	desc = NULL;

	pgt.kind = ADDRXLAT_PGT;
	pgt.target_as = ADDRXLAT_MACHPHYSADDR;
	pgt.param.pgt.root.as = ADDRXLAT_NOADDR;
	pgt.param.pgt.root.addr = 0;

	linear.kind = ADDRXLAT_LINEAR;
	linear.target_as = ADDRXLAT_MACHPHYSADDR;
	linear.param.linear.off = 0;

	lookup.kind = ADDRXLAT_LOOKUP;
	lookup.target_as = ADDRXLAT_MACHPHYSADDR;
	lookup.param.lookup.endoff = 0;

	memarr.kind = ADDRXLAT_MEMARR;
	memarr.target_as = ADDRXLAT_MACHPHYSADDR;
	memarr.param.memarr.base.as = ADDRXLAT_NOADDR;

	while ((opt = getopt_long(argc, argv, "he:f:l:m:pr:t:",
				  opts, NULL)) != -1) {
		switch (opt) {
		case 'f':
			desc = &pgt;
			rc = set_paging_form(&desc->param.pgt.pf, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'r':
			desc = &pgt;
			rc = set_root(&desc->param.pgt.root, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'e':
			rc = add_entry(optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'l':
			desc = &linear;
			rc = set_linear(&desc->param.linear.off, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'm':
			desc = &memarr;
			rc = set_memarr(&desc->param.memarr, optarg);
			if (rc != TEST_OK)
				return rc;
			break;

		case 'p':
			desc = &pgt;
			break;

		case 't':
			desc = &lookup;
			rc = set_lookup(&desc->param.lookup.endoff, optarg);
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

	if (desc == NULL) {
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

	status = addrxlat_meth_set_desc(xlat, desc);
	if (status != ADDRXLAT_OK) {
		fprintf(stderr, "Cannot set up address translation: %s\n",
			addrxlat_strerror(status));
		rc = TEST_ERR;
		goto out;
	}

	ctx = addrxlat_ctx_new();
	if (!ctx) {
		perror("Cannot initialize address translation context");
		rc = TEST_ERR;
		goto out;
	}
	cb.data = ctx;
	addrxlat_ctx_set_cb(ctx, &cb);

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
