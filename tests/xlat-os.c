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
#include <addrxlat.h>

#include "testutil.h"

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

#define MAXERR	64
static char read_err_str[MAXERR];

struct sym {
	struct sym *next;
	addrxlat_sym_t sym;
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
get_physaddr(struct cbdata *cbd, const addrxlat_fulladdr_t *addr,
	     addrxlat_addr_t *physaddr)
{
	addrxlat_status status;

	*physaddr = addr->addr;

	switch (addr->as) {
	case ADDRXLAT_MACHPHYSADDR:
		break;

	case ADDRXLAT_KPHYSADDR:
		/* FIXME: Xen address translation not yet implemented.
		 * On bare metal, kernel physical addresses are identical
		 * to machine physical addresses.
		 */
		break;

	case ADDRXLAT_KVADDR:
		status = addrxlat_by_map(cbd->ctx, physaddr,
					 addrxlat_sys_get_map(
						 cbd->sys,
						 ADDRXLAT_SYS_MAP_KV_PHYS));
		if (status != addrxlat_ok) {
			snprintf(read_err_str, sizeof read_err_str,
				 "Cannot translate virt addr 0x%"ADDRXLAT_PRIxADDR,
				 addr->addr);
			return -read_vtop_failed;
		}
		break;

	default:
		snprintf(read_err_str, sizeof read_err_str,
			 "No method to handle address space %u",
			 (unsigned) addr->as);
		return -read_unknown_as;
	}

	return addrxlat_ok;
}

static addrxlat_status
read32(void *data, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	addrxlat_addr_t physaddr;
	addrxlat_status status;
	struct entry *ent;
	uint32_t *p;

	status = get_physaddr(data, addr, &physaddr);
	if (status != addrxlat_ok)
		return status;

	ent = find_entry(physaddr, sizeof(uint32_t));
	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%"ADDRXLAT_PRIxADDR,
			 physaddr);
		return -read_notfound;
	}
	p = (uint32_t*)(ent->buf + physaddr - ent->addr);
	*val = *p;
	return addrxlat_ok;
}

static addrxlat_status
read64(void *data, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	addrxlat_addr_t physaddr;
	addrxlat_status status;
	struct entry *ent;
	uint64_t *p;

	status = get_physaddr(data, addr, &physaddr);
	if (status != addrxlat_ok)
		return status;

	ent = find_entry(physaddr, sizeof(uint64_t));
	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%"ADDRXLAT_PRIxADDR,
			 physaddr);
		return -read_notfound;
	}
	p = (uint64_t*)(ent->buf + physaddr - ent->addr);
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

#define MAX_SYMDATA_ARGS	2
struct store_symdata {
	addrxlat_sym_type_t type;
	const char *args[MAX_SYMDATA_ARGS];
};

struct symdata {
	struct symdata *next;
	struct store_symdata ss;
	addrxlat_addr_t val;
};

static struct symdata *symdata;

static int
add_symdata(const struct store_symdata *ss, addrxlat_addr_t val)
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
				return addrxlat_ok;
			}
			break;

		case ADDRXLAT_SYM_OFFSETOF:
			if (sd->ss.args[0] && sd->ss.args[1] &&
			    !strcmp(sd->ss.args[0], sym->args[0]) &&
			    !strcmp(sd->ss.args[1], sym->args[1])) {
				sym->val = sd->val;
				return addrxlat_ok;
			}
		}
	}

	return addrxlat_notpresent;
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

	PARAM_STRING("SYM", sym_file),
	PARAM_STRING("DATA", data_file)
};

static const struct params params = {
	ARRAY_SIZE(param_array),
	param_array
};

#define MAX_SYMBOLS	16

static struct {
	const void *p;
	const char *name;
} symbols[MAX_SYMBOLS];
static unsigned num_symbols;

static void
add_symbol(const void *ptr, const char *name)
{
	if (ptr) {
		symbols[num_symbols].p = ptr;
		symbols[num_symbols].name = name;
		++num_symbols;
	}
}

static void
print_ind(const char *desc, const void *ptr)
{
	unsigned i;

	for (i = 0; i < num_symbols; ++i) {
		if (symbols[i].p == ptr) {
			printf("%s @%s", desc, symbols[i].name);
			return;
		}
	};

	printf("%s @%p", desc, ptr);
}

static void
print_lookup_tbl(const addrxlat_meth_t *meth)
{
	const addrxlat_def_t *def = addrxlat_meth_get_def(meth);
	const addrxlat_lookup_elem_t *p = def->param.lookup.tbl;
	size_t n = def->param.lookup.nelem;

	while (n--) {
		printf("\n  %"ADDRXLAT_PRIxADDR" -> %"ADDRXLAT_PRIxADDR,
		       p->phys, p->virt);
		++p;
	}
}

static void
print_pgt(const addrxlat_meth_t *pgt)
{
	static const char *pte_formats[] = {
		[addrxlat_pte_none] = "none",
		[addrxlat_pte_ia32] = "ia32",
		[addrxlat_pte_ia32_pae] = "ia32_pae",
		[addrxlat_pte_x86_64] = "x86_64",
		[addrxlat_pte_s390x] = "s390x",
		[addrxlat_pte_ppc64_linux_rpn30] = "ppc64_linux_rpn30",
	};

	const addrxlat_def_t *def = addrxlat_meth_get_def(pgt);
	const addrxlat_paging_form_t *pf = &def->param.pgt.pf;
	unsigned i;

	fputs("\n  pte_format: ", stdout);
	if (pf->pte_format < ARRAY_SIZE(pte_formats) &&
	    pte_formats[pf->pte_format])
		printf("%s", pte_formats[pf->pte_format]);
	else
		printf("%u", pf->pte_format);
	printf("\n  bits:");
	for (i = 0; i < pf->levels; ++i)
		printf(" %u", pf->bits[i]);
}

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

	case ADDRXLAT_XENVADDR:
		fputs("XENVADDR", stdout);
		break;

	case ADDRXLAT_NOADDR:
		fputs("NOADDR", stdout);
		break;

	default:
		printf("<addrspace %ld>", (long) as);
	}
}

static void
print_xlat(const addrxlat_meth_t *meth)
{
	if (meth == NULL)
		fputs("NONE", stdout);
	else {
		const addrxlat_def_t *def = addrxlat_meth_get_def(meth);

		switch (def->kind) {
		case ADDRXLAT_NONE:
			print_ind("NONE", meth);
			break;

		case ADDRXLAT_LINEAR:
			print_ind("LINEAR", meth);
			printf(" off=0x%llx",
			       (unsigned long long) def->param.linear.off);
			break;

		case ADDRXLAT_PGT:
			print_ind("PGT", meth);
			print_pgt(meth);
			break;

		case ADDRXLAT_LOOKUP:
			print_ind("LOOKUP", meth);
			print_lookup_tbl(meth);
			break;


		case ADDRXLAT_MEMARR:
			print_ind("MEMARR", meth);
			fputs(" base=", stdout);
			print_addrspace(def->param.memarr.base.as);
			printf(":%"ADDRXLAT_PRIxADDR
			       " shift=%u elemsz=%u valsz=%u",
			       def->param.memarr.base.addr,
			       def->param.memarr.shift,
			       def->param.memarr.elemsz,
			       def->param.memarr.valsz);
			break;

		}
	}
}

static void
print_map(const addrxlat_map_t *map)
{
	addrxlat_addr_t addr = 0;
	unsigned i;

	for (i = 0; i < map->n; ++i) {
		const addrxlat_range_t *range = &map->ranges[i];
		printf("%"ADDRXLAT_PRIxADDR"-%"ADDRXLAT_PRIxADDR": ",
			addr, addr + range->endoff);
		print_xlat(range->meth);
		putchar('\n');

		addr += range->endoff + 1;
	}
}

static int
os_map(void)
{
	struct cbdata data;
	addrxlat_osdesc_t desc;
	const addrxlat_meth_t *meth;
	addrxlat_status status;

	desc.type = ostype;
	desc.ver = osver;
	desc.arch = arch;
	desc.opts = opts;

	data.ctx = addrxlat_ctx_new();
	if (!data.ctx) {
		perror("Cannot allocate addrxlat");
		return TEST_ERR;
	}
	addrxlat_ctx_set_cbdata(data.ctx, &data);
	addrxlat_ctx_cb_read32(data.ctx, read32);
	addrxlat_ctx_cb_read64(data.ctx, read64);
	addrxlat_ctx_cb_sym(data.ctx, get_symdata);

	data.sys = addrxlat_sys_new();
	if (!data.sys) {
		perror("Cannot allocate translation system");
		addrxlat_ctx_decref(data.ctx);
		return TEST_ERR;
	}

	status = addrxlat_sys_init(data.sys, data.ctx, &desc);
	if (status != addrxlat_ok) {
		fprintf(stderr, "OS map failed: %s\n",
			(status > 0
			 ? addrxlat_ctx_err(data.ctx)
			 : read_err_str));
		addrxlat_sys_decref(data.sys);
		addrxlat_ctx_decref(data.ctx);
		return TEST_ERR;
	}

	meth = addrxlat_sys_get_xlat(data.sys, ADDRXLAT_SYS_METH_PGT);
	add_symbol(meth, "rootpgt");

	meth = addrxlat_sys_get_xlat(data.sys, ADDRXLAT_SYS_METH_UPGT);
	add_symbol(meth, "userpgt");

	meth = addrxlat_sys_get_xlat(data.sys, ADDRXLAT_SYS_METH_DIRECT);
	add_symbol(meth, "direct");

	meth = addrxlat_sys_get_xlat(data.sys, ADDRXLAT_SYS_METH_KTEXT);
	add_symbol(meth, "ktext");

	meth = addrxlat_sys_get_xlat(data.sys, ADDRXLAT_SYS_METH_VMEMMAP);
	add_symbol(meth, "vmemmap");

	meth = addrxlat_sys_get_xlat(data.sys,
				     ADDRXLAT_SYS_METH_MACHPHYS_KPHYS);
	add_symbol(meth, "machphys_kphys");

	meth = addrxlat_sys_get_xlat(data.sys,
				     ADDRXLAT_SYS_METH_KPHYS_MACHPHYS);
	add_symbol(meth, "kphys_machphys");

	puts("KV -> PHYS:");
	print_map(addrxlat_sys_get_map(data.sys, ADDRXLAT_SYS_MAP_KV_PHYS));

	putchar('\n');

	puts("MACHPHYS -> KPHYS:");
	print_map(addrxlat_sys_get_map(data.sys,
				       ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS));

	putchar('\n');

	puts("KPHYS -> MACHPHYS:");
	print_map(addrxlat_sys_get_map(data.sys,
				       ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS));

	addrxlat_sys_decref(data.sys);
	addrxlat_ctx_decref(data.ctx);
	return TEST_OK;
}

static int
symheader(struct page_data *pg, char *p)
{
	struct store_symdata *ss = pg->priv;
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

	for (argc = 0; argc < MAX_SYMDATA_ARGS; ++argc) {
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
			while (++argc < MAX_SYMDATA_ARGS)
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
	struct store_symdata *ss = pg->priv;
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
	struct store_symdata ss;
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
