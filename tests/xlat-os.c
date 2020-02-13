/* Translation map initialization from OS details.
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
#include <endian.h>
#include <ctype.h>
#include <libkdumpfile/addrxlat.h>

#include "testutil.h"

struct cbdata {
	addrxlat_ctx_t *ctx;
	addrxlat_sys_t *sys;
};

struct store_page_data {
	addrxlat_addr_t addr;
};

struct entry {
	struct entry *next;
	addrxlat_addr_t addr;
	size_t buflen;
	char buf[];
};

static unsigned long long entry_as = ADDRXLAT_MACHPHYSADDR;
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
get_page(void *data, addrxlat_buffer_t *buf)
{
	struct cbdata *cbd = data;
	struct entry *ent;
	uint32_t *p;

	if (buf->addr.as != entry_as)
		return addrxlat_ctx_err(cbd->ctx, ADDRXLAT_ERR_INVALID,
					"Unexpected address space: %ld",
					(long)buf->addr.as);

	ent = find_entry(buf->addr.addr, sizeof(uint32_t));
	if (!ent)
		return addrxlat_ctx_err(cbd->ctx, ADDRXLAT_ERR_NODATA,
					"No data");
	buf->addr.addr = ent->addr;
	buf->ptr = ent->buf;
	buf->size = ent->buflen;
	buf->byte_order = ADDRXLAT_HOST_ENDIAN;
	return ADDRXLAT_OK;
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

struct symdata {
	struct symdata *next;
	addrxlat_sym_t ss;
	addrxlat_addr_t val;
};

static struct symdata *symdata;

static int
add_symdata(const addrxlat_sym_t *ss, addrxlat_addr_t val)
{
	struct symdata *sd = malloc(sizeof(*sd));
	if (!sd) {
		perror("Cannot allocat symbol data");
		return TEST_ERR;
	}

	sd->ss = *ss;
	sd->val = val;
	sd->next = symdata;
	symdata = sd;
	return TEST_OK;
}

static addrxlat_status
get_symdata(void *data, addrxlat_sym_t *sym)
{
	struct symdata *sd;
	for (sd = symdata; sd; sd = sd->next) {
		if (sd->ss.type != sym->type)
			continue;

		switch (sd->ss.type) {
		case ADDRXLAT_SYM_REG:
		case ADDRXLAT_SYM_VALUE:
		case ADDRXLAT_SYM_SIZEOF:
			if (sd->ss.args[0] &&
			    !strcmp(sd->ss.args[0], sym->args[0])) {
				sym->val = sd->val;
				return ADDRXLAT_OK;
			}
			break;

		case ADDRXLAT_SYM_OFFSETOF:
			if (sd->ss.args[0] && sd->ss.args[1] &&
			    !strcmp(sd->ss.args[0], sym->args[0]) &&
			    !strcmp(sd->ss.args[1], sym->args[1])) {
				sym->val = sd->val;
				return ADDRXLAT_OK;
			}
		}
	}

	return ADDRXLAT_ERR_NODATA;
}

static unsigned long long ostype;
static unsigned long long osver;
static char *arch;
static char *opts;

static char *sym_file;
static char *data_file;

static const struct param param_array[] = {
	PARAM_NUMBER("ostype", ostype),
	PARAM_NUMBER("osver", osver),
	PARAM_STRING("arch", arch),
	PARAM_STRING("opts", opts),
	PARAM_NUMBER("data_as", entry_as),

	PARAM_STRING("SYM", sym_file),
	PARAM_STRING("DATA", data_file)
};

static const struct params params = {
	ARRAY_SIZE(param_array),
	param_array
};

static void
print_addrspace(addrxlat_addrspace_t as)
{
	switch (as) {
	case ADDRXLAT_KPHYSADDR:
		fputs("KPHYSADDR", stdout);
		break;

	case ADDRXLAT_MACHPHYSADDR:
		fputs("MACHPHYSADDR", stdout);
		break;

	case ADDRXLAT_KVADDR:
		fputs("KVADDR", stdout);
		break;

	case ADDRXLAT_NOADDR:
		fputs("NOADDR", stdout);
		break;

	default:
		printf("<addrspace %ld>", (long) as);
	}
}

static void
print_target_as(const addrxlat_meth_t *meth)
{
	fputs("  target_as=", stdout);
	print_addrspace(meth->target_as);
	putchar('\n');
}

static void
print_fulladdr(const addrxlat_fulladdr_t *addr)
{
	print_addrspace(addr->as);
	if (addr->as != ADDRXLAT_NOADDR)
		printf(":0x%"ADDRXLAT_PRIxADDR, addr->addr);
}

static void
print_linear(const addrxlat_meth_t *meth)
{
	puts("LINEAR");
	print_target_as(meth);
	printf("  off=0x%"PRIxFAST64"\n",
	       (uint_fast64_t) meth->param.linear.off);
}

static void
print_pgt(const addrxlat_meth_t *meth)
{
	static const char *pte_formats[] = {
		[ADDRXLAT_PTE_NONE] = "none",
		[ADDRXLAT_PTE_PFN32] = "pfn32",
		[ADDRXLAT_PTE_PFN64] = "pfn64",
		[ADDRXLAT_PTE_IA32] = "ia32",
		[ADDRXLAT_PTE_IA32_PAE] = "ia32_pae",
		[ADDRXLAT_PTE_X86_64] = "x86_64",
		[ADDRXLAT_PTE_S390X] = "s390x",
		[ADDRXLAT_PTE_PPC64_LINUX_RPN30] = "ppc64_linux_rpn30",
	};

	const addrxlat_paging_form_t *pf = &meth->param.pgt.pf;
	unsigned i;

	puts("PGT");
	print_target_as(meth);
	fputs("  root=", stdout);
	print_fulladdr(&meth->param.pgt.root);
	putchar('\n');
	fputs("  pte_format=", stdout);
	if (pf->pte_format < ARRAY_SIZE(pte_formats) &&
	    pte_formats[pf->pte_format])
		printf("%s", pte_formats[pf->pte_format]);
	else
		printf("%u", pf->pte_format);
	printf("\n  fields=");
	for (i = 0; i < pf->nfields; ++i)
		printf("%s%u", i ? "," : "", pf->fieldsz[i]);
	putchar('\n');
}

static void
print_lookup(const addrxlat_meth_t *meth)
{
	const addrxlat_lookup_elem_t *p = meth->param.lookup.tbl;
	size_t n = meth->param.lookup.nelem;

	puts("LOOKUP");
	print_target_as(meth);
	printf("  endoff=0x%"ADDRXLAT_PRIxADDR"\n", meth->param.lookup.endoff);
	while (n--) {
		printf("  %"ADDRXLAT_PRIxADDR" -> %"ADDRXLAT_PRIxADDR"\n",
		       p->orig, p->dest);
		++p;
	}
}

static void
print_memarr(const addrxlat_meth_t *meth)
{
	puts("MEMARR");
	print_target_as(meth);
	fputs("  base=", stdout);
	print_fulladdr(&meth->param.memarr.base);
	putchar('\n');
	printf("  shift=%u\n", meth->param.memarr.shift);
	printf("  elemsz=%u\n", meth->param.memarr.elemsz);
	printf("  valsz=%u\n", meth->param.memarr.valsz);
}

static const char *const meth_names[] = {
	[ADDRXLAT_SYS_METH_PGT] = "rootpgt",
	[ADDRXLAT_SYS_METH_UPGT] = "userpgt",
	[ADDRXLAT_SYS_METH_DIRECT] = "direct",
	[ADDRXLAT_SYS_METH_KTEXT] = "ktext",
	[ADDRXLAT_SYS_METH_VMEMMAP] = "vmemmap",
	[ADDRXLAT_SYS_METH_RDIRECT] = "rdirect",
	[ADDRXLAT_SYS_METH_MACHPHYS_KPHYS] = "machphys_kphys",
	[ADDRXLAT_SYS_METH_KPHYS_MACHPHYS] = "kphys_machphys",
};

static void
print_meth(const addrxlat_sys_t *sys, addrxlat_sys_meth_t methidx)
{
	const addrxlat_meth_t *meth = addrxlat_sys_get_meth(sys, methidx);

	if (meth->kind == ADDRXLAT_NOMETH)
		return;

	printf("@%s: ", meth_names[methidx]);

	switch (meth->kind) {
	case ADDRXLAT_NOMETH:
		break;

	case ADDRXLAT_CUSTOM:
		puts("CUSTOM");
		break;

	case ADDRXLAT_LINEAR:
		print_linear(meth);
		break;

	case ADDRXLAT_PGT:
		print_pgt(meth);
		break;

	case ADDRXLAT_LOOKUP:
		print_lookup(meth);
		break;

	case ADDRXLAT_MEMARR:
		print_memarr(meth);
		break;
	}

	putchar('\n');
}

static void
print_xlat(addrxlat_sys_meth_t methidx)
{
	if (methidx == ADDRXLAT_SYS_METH_NONE)
		puts("NONE");
	else if (methidx >= 0 && methidx < ARRAY_SIZE(meth_names) &&
		 meth_names[methidx])
		printf("@%s\n", meth_names[methidx]);
	else
		printf("<%ld>\n", (long)methidx);
}

static void
print_map(const addrxlat_sys_t *sys, addrxlat_sys_map_t mapidx)
{
	addrxlat_map_t *map;
	addrxlat_addr_t addr;
	const addrxlat_range_t *range;
	size_t i, n;

	map = addrxlat_sys_get_map(sys, mapidx);
	if (!map)
		return;

	n = addrxlat_map_len(map);
	addr = 0;
	range = addrxlat_map_ranges(map);
	for (i = 0; i < n; ++i) {
		printf("%"ADDRXLAT_PRIxADDR"-%"ADDRXLAT_PRIxADDR": ",
			addr, addr + range->endoff);
		print_xlat(range->meth);

		addr += range->endoff + 1;
		++range;
	}
}

static int
os_map(void)
{
	struct cbdata data;
	addrxlat_cb_t cb = {
		.data = &data,
		.get_page = get_page,
		.read_caps = ADDRXLAT_CAPS(entry_as),
		.sym = get_symdata
	};
	addrxlat_osdesc_t meth;
	addrxlat_status status;

	meth.type = ostype;
	meth.ver = osver;
	meth.arch = arch;
	meth.opts = opts;

	data.ctx = addrxlat_ctx_new();
	if (!data.ctx) {
		perror("Cannot allocate addrxlat");
		return TEST_ERR;
	}
	addrxlat_ctx_set_cb(data.ctx, &cb);

	data.sys = addrxlat_sys_new();
	if (!data.sys) {
		perror("Cannot allocate translation system");
		addrxlat_ctx_decref(data.ctx);
		return TEST_ERR;
	}

	status = addrxlat_sys_os_init(data.sys, data.ctx, &meth);
	if (status != ADDRXLAT_OK) {
		fprintf(stderr, "OS map failed: %s\n",
			addrxlat_ctx_get_err(data.ctx));
		addrxlat_sys_decref(data.sys);
		addrxlat_ctx_decref(data.ctx);
		return TEST_ERR;
	}

	print_meth(data.sys, ADDRXLAT_SYS_METH_PGT);
	print_meth(data.sys, ADDRXLAT_SYS_METH_UPGT);
	print_meth(data.sys, ADDRXLAT_SYS_METH_DIRECT);
	print_meth(data.sys, ADDRXLAT_SYS_METH_KTEXT);
	print_meth(data.sys, ADDRXLAT_SYS_METH_VMEMMAP);
	print_meth(data.sys, ADDRXLAT_SYS_METH_RDIRECT);
	print_meth(data.sys, ADDRXLAT_SYS_METH_MACHPHYS_KPHYS);
	print_meth(data.sys, ADDRXLAT_SYS_METH_KPHYS_MACHPHYS);

	puts("KV -> HW:");
	print_map(data.sys, ADDRXLAT_SYS_MAP_HW);

	putchar('\n');

	puts("KV -> PHYS:");
	print_map(data.sys, ADDRXLAT_SYS_MAP_KV_PHYS);

	putchar('\n');

	puts("KPHYS -> DIRECT:");
	print_map(data.sys, ADDRXLAT_SYS_MAP_KPHYS_DIRECT);

	putchar('\n');

	puts("MACHPHYS -> KPHYS:");
	print_map(data.sys, ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS);

	putchar('\n');

	puts("KPHYS -> MACHPHYS:");
	print_map(data.sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS);

	addrxlat_sys_decref(data.sys);
	addrxlat_ctx_decref(data.ctx);
	return TEST_OK;
}

static int
symheader(struct page_data *pg, char *p)
{
	addrxlat_sym_t *ss = pg->priv;
	char *delim;
	int argc;

	delim = strchr(p, '(');
	if (!delim) {
		fprintf(stderr, "Invalid symbolic header: %s\n", p);
		return TEST_FAIL;
	}

	if (!strncmp(p, "REG", 3)) {
		ss->type = ADDRXLAT_SYM_REG;
		p += 3;
	} else if (!strncmp(p, "VALUE", 5)) {
		ss->type = ADDRXLAT_SYM_VALUE;
		p += 5;
	} else if (!strncmp(p, "SIZEOF", 6)) {
		ss->type = ADDRXLAT_SYM_SIZEOF;
		p += 6;
	} else if (!strncmp(p, "OFFSETOF", 8)) {
		ss->type = ADDRXLAT_SYM_OFFSETOF;
		p += 8;
	} else {
		fprintf(stderr, "Invalid symbolic header: %s\n", p);
		return TEST_FAIL;
	}

	while (isspace(*p))
		++p;
	if (*p != '(') {
		fprintf(stderr, "Invalid symbolic header: %s\n", p);
		return TEST_FAIL;
	}
	++p;

	for (argc = 0; argc < ADDRXLAT_SYM_ARGC_MAX; ++argc) {
		char *endp, *arg;

		while (isspace(*p))
			++p;
		delim = strpbrk(p, ",)");
		if (!delim) {
			fprintf(stderr, "Invalid symbolic header: %s\n", p);
			return TEST_FAIL;
		}

		endp = delim;
		while (isspace(endp[-1]))
			--endp;

		arg = malloc(endp - p + 1);
		if (!arg) {
			fprintf(stderr, "Cannot allocate arg #%d\n", argc + 1);
			return TEST_ERR;
		}
		memcpy(arg, p, endp - p);
		arg[endp - p] = '\0';
		ss->args[argc] = arg;

		if (*delim == ')') {
			while (++argc < ADDRXLAT_SYM_ARGC_MAX)
				ss->args[argc] = NULL;
			return TEST_OK;
		}

		p = delim + 1;
	}

	fprintf(stderr, "Too many symbolic arguments: %s\n", p);
	return TEST_FAIL;
}

static int
storesym(struct page_data *pg)
{
	addrxlat_sym_t *ss = pg->priv;
	addrxlat_addr_t val;
	size_t sz = pg->len;

	if (sz > sizeof(val))
		sz = sizeof(val);
	val = 0;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	memcpy(&val, pg->buf, pg->len);
#else
	memcpy((char*)(&val + 1) - sz,
	       pg->buf + sizeof(val) - pg->len,
	       pg->len);
#endif
	return add_symdata(ss, val);
}

static int
read_sym(void)
{
	addrxlat_sym_t ss;
	struct page_data pg;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	pg.endian = data_le;
#else
	pg.endian = data_be;
#endif

	pg.parse_hdr = symheader;
	pg.write_page = storesym;
	pg.priv = &ss;

	return process_data(&pg, sym_file);
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

int
main(int argc, char **argv)
{
	FILE *param;
	int rc;

	if (argc > 2) {
		fprintf(stderr, "Usage: %s [<params>]\n", argv[0]);
		return TEST_ERR;
	}

	if (argc == 2) {
		param = fopen(argv[1], "r");
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

	if (sym_file) {
		rc = read_sym();
		if (rc != TEST_OK)
			return rc;
	}

	if (data_file) {
		rc = read_data();
		if (rc != TEST_OK)
			return rc;
	}

	rc = os_map();
	if (rc != TEST_OK)
		return rc;

	return TEST_OK;
}
