/* Test automatic translation using a translation system.
   Copyright (C) 2017 Petr Tesarik <ptesarik@suse.com>

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

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <addrxlat.h>

#include "testutil.h"

static char *data_file;
static char *cfg_file;

static const struct param param_array[] = {
	PARAM_STRING("DATA", data_file),
	PARAM_STRING("CONFIG", cfg_file)
};

static const struct params params = {
	ARRAY_SIZE(param_array),
	param_array
};

typedef struct {
	const char *str;
	long val;
} kw_pair_t;

#define NOTFOUND	LONG_MIN

static long
match_keyword(const char *kw, size_t kwlen, const kw_pair_t *tbl)
{
	size_t i;
	for (i = 0; tbl[i].str; ++i)
		if (!strncasecmp(kw, tbl[i].str, kwlen) &&
		    tbl[i].str[kwlen] == '\0')
			return tbl[i].val;
	return NOTFOUND;
}

/** Verbose version of @ref match_keyword.
 * This function prints an error to @c stderr if the match fails.
 */
static long
match_keyword_verb(const char *desc, const char *kw, size_t kwlen,
		   const kw_pair_t *tbl)
{
	long res = match_keyword(kw, kwlen, tbl);
	if (res == NOTFOUND)
		fprintf(stderr, "Unknown %s: %.*s\n", desc, (int)kwlen, kw);
	return res;
}

static const kw_pair_t as_names[] = {
	{ "NOADDR", ADDRXLAT_NOADDR },
	{ "KPHYSADDR", ADDRXLAT_KPHYSADDR },
	{ "MACHPHYSADDR", ADDRXLAT_MACHPHYSADDR },
	{ "KVADDR", ADDRXLAT_KVADDR },
	{NULL}
};

static const kw_pair_t meth_names[] = {
	{ "rootpgt", ADDRXLAT_SYS_METH_PGT },
	{ "userpgt", ADDRXLAT_SYS_METH_UPGT },
	{ "direct", ADDRXLAT_SYS_METH_DIRECT },
	{ "ktext", ADDRXLAT_SYS_METH_KTEXT },
	{ "vmemmap", ADDRXLAT_SYS_METH_VMEMMAP },
	{ "rdirect", ADDRXLAT_SYS_METH_RDIRECT },
	{ "machphys_kphys", ADDRXLAT_SYS_METH_MACHPHYS_KPHYS },
	{ "kphys_machphys", ADDRXLAT_SYS_METH_KPHYS_MACHPHYS },
	{NULL}
};

static const kw_pair_t kind_names[] = {
	{ "NONE", ADDRXLAT_NONE },
	{ "LINEAR", ADDRXLAT_LINEAR },
	{ "PGT", ADDRXLAT_PGT },
	{ "LOOKUP", ADDRXLAT_LOOKUP },
	{ "MEMARR", ADDRXLAT_MEMARR },
	{NULL}
};

static const kw_pair_t map_names[] = {
	{ "KV -> HW", ADDRXLAT_SYS_MAP_HW },
	{ "KV -> PHYS", ADDRXLAT_SYS_MAP_KV_PHYS },
	{ "KPHYS -> DIRECT", ADDRXLAT_SYS_MAP_KPHYS_DIRECT },
	{ "MACHPHYS -> KPHYS", ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS },
	{ "KPHYS -> MACHPHYS", ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS },
	{NULL}
};

static const kw_pair_t pte_formats[] = {
	{ "none", ADDRXLAT_PTE_NONE },
	{ "pfn32", ADDRXLAT_PTE_PFN32 },
	{ "pfn64", ADDRXLAT_PTE_PFN64 },
	{ "ia32", ADDRXLAT_PTE_IA32 },
	{ "ia32_pae", ADDRXLAT_PTE_IA32_PAE },
	{ "x86_64", ADDRXLAT_PTE_X86_64 },
	{ "s390x", ADDRXLAT_PTE_S390X },
	{ "ppc64_linux_rpn30", ADDRXLAT_PTE_PPC64_LINUX_RPN30 },
	{NULL}
};

enum param_index {
	/* Generic */
	param_kind,
	param_target_as,

	/* Linear */
	linear_off,

	/* Page tables */
	pgt_root,
	pgt_pte_format,
	pgt_bits,

	/* Table lookup */
	lookup_endoff,
	lookup_nelem,

	/* Memory array */
	memarr_base,
	memarr_shift,
	memarr_elemsz,
	memarr_valsz,
};

static const kw_pair_t gen_param[] = {
	{"kind", param_kind },
	{"target_as", param_target_as },
	{NULL}
};

static const kw_pair_t linear_param[] = {
	{"off", linear_off },
	{NULL}
};

static const kw_pair_t pgt_param[] = {
	{"root", pgt_root },
	{"pte_format", pgt_pte_format },
	{"bits", pgt_bits },
	{NULL}
};

static const kw_pair_t lookup_param[] = {
	{"endoff", lookup_endoff },
	{"nelem", lookup_nelem },
	{NULL}
};

static const kw_pair_t memarr_param[] = {
	{"base", memarr_base },
	{"shift", memarr_shift },
	{"elemsz", memarr_elemsz },
	{"valsz", memarr_valsz },
	{NULL}
};

static int
parse_addrspace(const char *spec, addrxlat_addrspace_t *as)
{
	long i = match_keyword_verb("address space", spec, strlen(spec),
				    as_names);
	if (i == NOTFOUND)
		return TEST_ERR;
	*as = i;
	return TEST_OK;
}

static int
parse_fulladdr(const char *spec, addrxlat_fulladdr_t *addr)
{
	const char *p, *endp;
	long i;

	p = spec;
	while (*p && *p != ':' && !isspace(*p))
		++p;

	i = match_keyword_verb("address space", spec, p - spec, as_names);
	if (i == NOTFOUND)
		return TEST_ERR;
	addr->as = i;

	while (isspace(*p))
		++p;
	if (addr->as == ADDRXLAT_NOADDR && !*p)
		return TEST_OK;
	if (*p != ':') {
		fprintf(stderr, "Invalid full address: %s\n", spec);
		return TEST_ERR;
	}
	++p;

	while (isspace(*p))
		++p;
	addr->addr = strtoull(p, (char**)&endp, 0);
	if (endp == p || *endp) {
		fprintf(stderr, "Invalid number: %s\n", p);
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
parse_kind(const char *spec, addrxlat_kind_t *kind)
{
	long i = match_keyword_verb("address space", spec, strlen(spec),
				    as_names);
	if (i == NOTFOUND)
		return TEST_ERR;
	*kind = i;
	return TEST_OK;
}

static int
parse_pte_format(const char *spec, addrxlat_pte_format_t *fmt)
{
	long i = match_keyword_verb("PTE format", spec, strlen(spec),
				    pte_formats);
	if (i == NOTFOUND)
		return TEST_ERR;
	*fmt = i;
	return TEST_OK;
}

static int
parse_pgt_bits(const char *spec, addrxlat_paging_form_t *pf)
{
	const char *p;
	int i;

	p = spec;
	for (i = 0; i < ADDRXLAT_MAXLEVELS; ++i) {
		char *endp;
		pf->bits[i] = strtoul(p, &endp, 0);
		if (endp == p) {
			fprintf(stderr, "Invalid page form bits: %s\n", spec);
			return TEST_ERR;
		}
		p = endp;
		while (isspace(*p))
			++p;
		if (!*p)
			break;
		if (*p != ',') {
			fprintf(stderr, "Invalid page form bits: %s\n", spec);
			return TEST_ERR;
		}
		++p;
		while (isspace(*p))
			++p;
	}

	if (i >= ADDRXLAT_MAXLEVELS) {
		fprintf(stderr, "Too many paging levels: %s\n", spec);
		return TEST_ERR;
	}

	pf->levels = i + 1;
	return TEST_OK;
}

static int
add_lookup_entry(const char *spec, addrxlat_def_t *def)
{
	const char *p, *endp;
	addrxlat_lookup_elem_t elem;
	addrxlat_lookup_elem_t *newtbl;
	size_t n = def->param.lookup.nelem;

	p = spec;
	elem.orig = strtoull(p, (char**)&endp, 16);
	if (endp == p) {
		fprintf(stderr, "Invalid address: %s\n", p);
		return TEST_ERR;
	}
	p = endp;

	while (isspace(*p))
		++p;
	if (p[0] != '-' || p[1] != '>') {
		fprintf(stderr, "Invalid lookup format: %s\n", spec);
		return TEST_ERR;
	}
	p += 2;

	while (isspace(*p))
		++p;
	elem.dest = strtoull(p, (char**)&endp, 16);
	if (endp == p || *endp) {
		fprintf(stderr, "Invalid address: %s\n", p);
		return TEST_ERR;
	}

	newtbl = realloc((addrxlat_lookup_elem_t*)def->param.lookup.tbl,
			 (n + 1) * sizeof newtbl[0]);
	if (!newtbl) {
		perror("Cannot add lookup entry");
		return TEST_ERR;
	}

	newtbl[n] = elem;
	def->param.lookup.tbl = newtbl;
	++def->param.lookup.nelem;

	return TEST_OK;
}

static int
parse_meth_header(const char *spec, addrxlat_sys_meth_t *idx,
		  addrxlat_def_t *def)
{
	const char *p, *endp;
	long i;

	memset(def, 0, sizeof *def);

	p = spec;
	while (*p && *p != ':' && !isspace(*p))
		++p;

	i = match_keyword_verb("method name", spec, p - spec, meth_names);
	if (i == NOTFOUND)
		return TEST_ERR;
	*idx = i;

	while(isspace(*p))
		++p;
	if (*p != ':') {
		fprintf(stderr, "Method header syntax error: %s\n", spec);
		return TEST_ERR;
	}

	++p;
	while (isspace(*p))
		++p;

	endp = p;
	while (isalnum(*endp))
		++endp;
	i = match_keyword_verb("method kind", p, endp - p, kind_names);
	if (i == NOTFOUND)
		return TEST_ERR;
	def->kind = i;

	if (*endp) {
		fprintf(stderr, "Garbage after method specification: %s\n",
			endp);
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
parse_meth_param(const char *spec, addrxlat_def_t *def)
{
	const char *p, *endp;
	long i;
	int res;

	p = strchr(spec, '=');
	if (p == NULL && def->kind == ADDRXLAT_LOOKUP) {
		p = strstr(spec, "->");
		if (p == NULL) {
			fprintf(stderr, "Method parameter syntax error: %s\n",
				spec);
			return TEST_ERR;
		}
		return add_lookup_entry(spec, def);
	}

	endp = p;
	while (endp > spec && isspace(endp[-1]))
	       --endp;

	i = NOTFOUND;
	switch (def->kind) {
	case ADDRXLAT_NONE:
		break;

	case ADDRXLAT_LINEAR:
		i = match_keyword(spec, endp - spec, linear_param);
		break;

	case ADDRXLAT_PGT:
		i = match_keyword(spec, endp - spec, pgt_param);
		break;

	case ADDRXLAT_LOOKUP:
		i = match_keyword(spec, endp - spec, lookup_param);
		break;

	case ADDRXLAT_MEMARR:
		i = match_keyword(spec, endp - spec, memarr_param);
		break;
	}

	if (i == NOTFOUND) {
		i = match_keyword_verb("method param", spec, endp - spec,
				       gen_param);
		if (i == NOTFOUND)
			return TEST_ERR;
	}

	++p;
	while (isspace(*p))
		++p;

	res = TEST_ERR;
	switch (i) {
	case param_kind:
		res = parse_kind(p, &def->kind);
		break;

	case param_target_as:
		res = parse_addrspace(p, &def->target_as);
		break;

	case linear_off:
		def->param.linear.off = strtoull(p, (char**)&endp, 0);
		if (endp != p && !*endp)
			res = TEST_OK;
		else
			fprintf(stderr, "Invalid number: %s", p);
		break;

	case pgt_root:
		res = parse_fulladdr(p, &def->param.pgt.root);
		break;

	case pgt_pte_format:
		res = parse_pte_format(p, &def->param.pgt.pf.pte_format);
		break;

	case pgt_bits:
		res = parse_pgt_bits(p, &def->param.pgt.pf);
		break;

	case lookup_endoff:
		def->param.lookup.endoff = strtoull(p, (char**)&endp, 0);
		if (endp != p && !*endp)
			res = TEST_OK;
		else
			fprintf(stderr, "Invalid number: %s", p);
		break;

	case lookup_nelem:
		def->param.lookup.nelem = strtoull(p, (char**)&endp, 0);
		if (endp != p && !*endp)
			res = TEST_OK;
		else
			fprintf(stderr, "Invalid number: %s", p);
		break;

	case memarr_base:
		res = parse_fulladdr(p, &def->param.memarr.base);
		break;

	case memarr_shift:
		def->param.memarr.shift = strtoull(p, (char**)&endp, 0);
		if (endp != p && !*endp)
			res = TEST_OK;
		else
			fprintf(stderr, "Invalid number: %s", p);
		break;

	case memarr_elemsz:
		def->param.memarr.elemsz = strtoull(p, (char**)&endp, 0);
		if (endp != p && !*endp)
			res = TEST_OK;
		else
			fprintf(stderr, "Invalid number: %s", p);
		break;

	case memarr_valsz:
		def->param.memarr.valsz = strtoull(p, (char**)&endp, 0);
		if (endp != p && !*endp)
			res = TEST_OK;
		else
			fprintf(stderr, "Invalid number: %s", p);
		break;
	}

	return res;
}

static int
parse_map_header(const char *spec, addrxlat_sys_map_t *idx)
{
	const char *p;
	long i;

	p = spec;
	while (*p && *p != ':')
		++p;

	i = match_keyword_verb("map name", spec, p - spec, map_names);
	if (i == NOTFOUND)
		return TEST_ERR;
	*idx = i;

	if (*p != ':') {
		fprintf(stderr, "Method header syntax error: %s\n", spec);
		return TEST_ERR;
	}

	++p;
	if (*p) {
		fprintf(stderr, "Garbage after map specification: %s\n", p);
		return TEST_ERR;
	}

	return TEST_OK;
}

static addrxlat_meth_t *
get_sys_meth(addrxlat_sys_t *sys, addrxlat_sys_meth_t methidx)
{
	addrxlat_meth_t *meth = addrxlat_sys_get_meth(sys, methidx);

	if (!meth) {
		meth = addrxlat_meth_new();
		if (meth)
			addrxlat_sys_set_meth(sys, methidx, meth);
		else
			perror("Cannot add method");
	}
	return meth;
}

static int
add_map_entry(const char *spec, addrxlat_sys_t *sys, addrxlat_map_t **map)
{
	const char *p, *endp;
	unsigned long long beg, end;
	addrxlat_range_t range;
	addrxlat_status status;

	p = spec;
	beg = strtoull(p, (char**)&endp, 16);
	if (endp == p) {
		fprintf(stderr, "Invalid range begin: %s\n", p);
		return TEST_ERR;
	}
	p = endp;

	while (isspace(*p))
		++p;
	if (*p != '-') {
		fprintf(stderr, "Invalid map range: %s\n", spec);
		return TEST_ERR;
	}
	++p;

	end = strtoull(p, (char**)&endp, 16);
	if (endp == p) {
		fprintf(stderr, "Invalid range end: %s\n", p);
		return TEST_ERR;
	}
	p = endp;

	while (isspace(*p))
		++p;
	if (*p != ':') {
		fprintf(stderr, "Invalid range delimiter: %s\n", spec);
		return TEST_ERR;
	}
	++p;

	while (isspace(*p))
		++p;
	if (*p == '@') {
		long i;

		++p;
		i = match_keyword_verb("method name", p, strlen(p),
				       meth_names);
		if (i == NOTFOUND)
			return TEST_ERR;
		range.meth = get_sys_meth(sys, i);
		if (!range.meth)
			return TEST_ERR;
	} else if (!strcasecmp(p, "NONE")) {
		range.meth = NULL;
	} else {
		fprintf(stderr, "Invalid method specifier: %s\n", p);
		return TEST_ERR;
	}

	range.endoff = end - beg;
	if (!*map) {
		addrxlat_map_t *newmap = addrxlat_map_new();
		if (!newmap) {
			perror("Cannot allocate translation map");
			return TEST_ERR;
		}
		*map = newmap;
	}
	status = addrxlat_map_set(*map, beg, &range);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Cannot add map entry: %s\n",
			addrxlat_strerror(status));
		return TEST_ERR;
	}

	return TEST_OK;
}

enum cfg_state {
	cfg_init,
	cfg_meth,
	cfg_map
};

static int
cfg_block(enum cfg_state state, addrxlat_sys_t *sys,
	  addrxlat_sys_meth_t methidx, addrxlat_def_t *def,
	  addrxlat_sys_map_t mapidx, addrxlat_map_t *map)
{
	addrxlat_status status;

	if (state == cfg_meth) {
		addrxlat_meth_t *meth = get_sys_meth(sys, methidx);
		if (!meth)
			return TEST_ERR;

		status = addrxlat_meth_set_def(meth, def);
		if (status != addrxlat_ok) {
			fprintf(stderr, "Cannot define translation: %s\n",
				addrxlat_strerror(status));
			addrxlat_meth_decref(meth);
			return TEST_ERR;
		}

		addrxlat_meth_decref(meth);

	} else if (state == cfg_map) {
		addrxlat_sys_set_map(sys, mapidx, map);
	}

	return TEST_OK;
}

static addrxlat_sys_t*
read_config(FILE *f)
{
	char *line = NULL;
	size_t linealloc = 0;
	ssize_t linelen;
	enum cfg_state state = cfg_init;
	addrxlat_sys_meth_t methidx = ADDRXLAT_SYS_METH_NUM;
	addrxlat_sys_map_t mapidx = ADDRXLAT_SYS_MAP_NUM;
	addrxlat_def_t def = { .kind = ADDRXLAT_NONE };
	addrxlat_map_t *map = NULL;
	addrxlat_sys_t *sys;
	int res;

	sys = addrxlat_sys_new();
	if (!sys) {
		perror("Cannot allocate translation system");
		return NULL;
	}

	while ( (linelen = getline(&line, &linealloc, f)) >= 0) {
		char *p, *delim;

		/* chop whitespace from both sides */
		p = line + linelen - 1;
		while (p > line && isspace(*p))
			*p-- = '\0';
		p = line;
		while (isspace(*p))
			++p;

		/* ignore comments */
		if (*p == '#')
			continue;

		/* blank line ends current block */
		if (!*p) {
			res = cfg_block(state, sys, methidx, &def,
					mapidx, map);
			if (res != TEST_OK)
				return NULL;

			state = cfg_init;
			continue;
		}

		switch (state) {
		case cfg_init:
			if (*p == '@') {
				res = parse_meth_header(p + 1, &methidx, &def);
				if (res != TEST_OK)
					return NULL;
				state = cfg_meth;
			} else if ( (delim = strstr(p, "->")) ) {
				res = parse_map_header(p, &mapidx);
				if (res != TEST_OK)
					return NULL;
				map = NULL;
				state = cfg_map;
			} else {
				fprintf(stderr, "Syntax error: %s\n", line);
				return NULL;
			}
			break;

		case cfg_meth:
			res = parse_meth_param(p, &def);
			if (res != TEST_OK)
				return NULL;
			break;

		case cfg_map:
			res = add_map_entry(p, sys, &map);
			if (res != TEST_OK)
				return NULL;
			break;
		}
	}

	if (line)
		free(line);

	if (ferror(f)) {
		perror("Config I/O Error");
		return NULL;
	}

	res = cfg_block(state, sys, methidx, &def, mapidx, map);
	if (res != TEST_OK)
		return NULL;

	return sys;
}

struct store_page_data {
	addrxlat_addr_t addr;
};

struct entry {
	struct entry *next;
	addrxlat_addr_t addr;
	size_t buflen;
	char buf[];
};

enum read_status {
	read_ok = addrxlat_ok,
	read_notfound,
	read_vtop_failed,
	read_unknown_as,
};

struct cbdata {
	addrxlat_ctx_t *ctx;
	addrxlat_sys_t *sys;
};

static struct entry *entry_list;

struct entry*
find_entry(addrxlat_addr_t addr, size_t sz)
{
	struct entry *ent;
	for (ent = entry_list; ent; ent = ent->next)
		if (ent->addr <= addr && ent->addr + ent->buflen >= addr + sz)
			return ent;
	return NULL;
}

static addrxlat_status
read32(void *data, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	struct cbdata *cbd = data;
	struct entry *ent;
	uint32_t *p;

	if (addr->as != ADDRXLAT_MACHPHYSADDR)
		return addrxlat_ctx_err(cbd->ctx, addrxlat_invalid,
					"Unexpected address space: %ld",
					(long)addr->as);

	ent = find_entry(addr->addr, sizeof(uint32_t));
	if (!ent)
		return addrxlat_ctx_err(cbd->ctx, -read_notfound, "No data");
	p = (uint32_t*)(ent->buf + addr->addr - ent->addr);
	*val = *p;
	return addrxlat_ok;
}

static addrxlat_status
read64(void *data, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	struct cbdata *cbd = data;
	struct entry *ent;
	uint64_t *p;

	if (addr->as != ADDRXLAT_MACHPHYSADDR)
		return addrxlat_ctx_err(cbd->ctx, addrxlat_invalid,
					"Unexpected address space: %ld",
					(long)addr->as);

	ent = find_entry(addr->addr, sizeof(uint64_t));
	if (!ent)
		return addrxlat_ctx_err(cbd->ctx, -read_notfound, "No data");
	p = (uint64_t*)(ent->buf + addr->addr - ent->addr);
	*val = *p;
	return addrxlat_ok;
}

static int
add_entry(addrxlat_addr_t addr, void *buf, size_t sz)
{
	struct entry *ent;

	ent = malloc(sizeof(*ent) + sz);
	if (!ent) {
		perror("Cannot allocate entry");
		return TEST_ERR;
	}

	ent->next = entry_list;
	ent->addr = addr;
	ent->buflen = sz;
	memcpy(ent->buf, buf, sz);
	entry_list = ent;

	return TEST_OK;
}

static int
parseheader(struct page_data *pg, char *p)
{
	struct store_page_data *spd = pg->priv;
	char *endp;

	spd->addr = strtoull(p, &endp, 0);
	if (*endp) {
		*endp = '\0';
		fprintf(stderr, "Invalid address: %s\n", p);
		return TEST_FAIL;
	}

	return TEST_OK;
}

static int
storedata(struct page_data *pg)
{
	struct store_page_data *spd = pg->priv;
	return add_entry(spd->addr, pg->buf, pg->len);
}

static int
read_data(void)
{
	struct store_page_data spd;
	struct page_data pg;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	pg.endian = data_le;
#else
	pg.endian = data_be;
#endif

	pg.parse_hdr = parseheader;
	pg.write_page = storedata;
	pg.priv = &spd;

	return process_data(&pg, data_file);
}

static int
translate(struct cbdata *cbd, char *spec)
{
	char *delim = strrchr(spec, ':');
	addrxlat_fulladdr_t addr;
	addrxlat_addrspace_t goal;
	addrxlat_status status;
	int res;

	if (!delim) {
		fprintf(stderr, "Invalid translation: %s\n", spec);
		return TEST_ERR;
	}
	*delim = '\0';

	res = parse_fulladdr(spec, &addr);
	if (res != TEST_OK)
		return res;

	res = parse_addrspace(delim + 1, &goal);
	if (res != TEST_OK)
		return res;

	status = addrxlat_by_sys(cbd->ctx, cbd->sys, &addr, goal);
	if (status == addrxlat_nometh) {
		printf("%s -> NOMETH\n", spec);
	} else if (status != addrxlat_ok) {
		fprintf(stderr, "Address translation failed: %s\n",
			addrxlat_ctx_get_err(cbd->ctx));
		return TEST_FAIL;
	} else
		printf("%s -> %s:0x%"ADDRXLAT_PRIxADDR"\n",
		       spec, delim + 1, addr.addr);

	return TEST_OK;
}

int main(int argc, char *argv[])
{
	char *paramfn = NULL;
	FILE *param, *cfg;
	struct cbdata data;
	addrxlat_cb_t cb = {
		.data = &data,
		.read32 = read32,
		.read64 = read64,
		.read_caps = ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	};
	int c;
	int i;
	int rc;

	while ( (c = getopt(argc, argv, "f:")) != -1)
		switch (c) {
		case 'f':
			paramfn = optarg;
			break;

		default:
			fprintf(stderr, "Usage: %s [-f <params>] [xlat]...\n",
				argv[0]);
			return TEST_ERR;
		}

	if (paramfn) {
		param = fopen(paramfn, "r");
		if (!param) {
			perror("Cannot open params");
			return TEST_ERR;
		}
	} else
		param = stdin;

	rc = parse_params_file(&params, param);
	if (param != stdin)
		fclose(param);
	if (rc != TEST_OK)
		return rc;

	if (data_file) {
		rc = read_data();
		if (rc != TEST_OK)
			return rc;
	}

	data.ctx = addrxlat_ctx_new();
	if (!data.ctx) {
		perror("Cannot allocate addrxlat");
		return TEST_ERR;
	}
	addrxlat_ctx_set_cb(data.ctx, &cb);

	cfg = fopen(cfg_file, "r");
	if (!cfg) {
		perror("Cannot open config file");
		return TEST_ERR;
	}
	data.sys = read_config(cfg);
	fclose(cfg);

	for (i = optind; i < argc; ++i) {
		rc = translate(&data, argv[i]);
		if (rc != TEST_OK)
			return rc;
	}

	addrxlat_sys_decref(data.sys);
	addrxlat_ctx_decref(data.ctx);

	return TEST_OK;
}
