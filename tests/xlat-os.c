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
#include <addrxlat.h>

#include "testutil.h"

enum read_status {
	read_ok = addrxlat_ok,
	read_notfound,
};

#define MAXERR	64
static char read_err_str[MAXERR];

struct store_page_data {
	addrxlat_addr_t addr;
};

struct entry {
	struct entry *next;
	addrxlat_addr_t addr;
	size_t buflen;
	char buf[];
};

struct entry *entry_list;

struct entry*
find_entry(addrxlat_addr_t addr, size_t sz)
{
	struct entry *ent;
	for (ent = entry_list; ent; ent = ent->next)
		if (ent->addr <= addr && ent->addr + ent->buflen <= addr + sz)
			return ent;
	return NULL;
}

static addrxlat_status
read32(void *data, const addrxlat_fulladdr_t *addr, uint32_t *val)
{
	struct entry *ent = find_entry(addr->addr, sizeof(uint32_t));
	uint32_t *p;

	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%"ADDRXLAT_PRIxADDR,
			 addr->addr);
		return -read_notfound;
	}
	p = (uint32_t*)(ent->buf + addr->addr - ent->addr);
	*val = *p;
	return addrxlat_ok;
}

static addrxlat_status
read64(void *data, const addrxlat_fulladdr_t *addr, uint64_t *val)
{
	struct entry *ent = find_entry(addr->addr, sizeof(uint64_t));
	uint64_t *p;

	if (!ent) {
		snprintf(read_err_str, sizeof read_err_str,
			 "No entry for address 0x%"ADDRXLAT_PRIxADDR,
			 addr->addr);
		return -read_notfound;
	}
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

static unsigned long long ostype;
static unsigned long long osver;
static char *arch;
static unsigned long long rootpgt = ADDRXLAT_ADDR_MAX;

static char *data_file;

static const struct param param_array[] = {
	PARAM_NUMBER("ostype", ostype),
	PARAM_NUMBER("osver", osver),
	PARAM_STRING("arch", arch),
	PARAM_NUMBER("rootpgt", rootpgt),

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
	symbols[num_symbols].p = ptr;
	symbols[num_symbols].name = name;
	++num_symbols;
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
print_xlat(const addrxlat_def_t *def)
{
	if (def == NULL)
		fputs("NONE", stdout);
	else switch (addrxlat_def_get_kind(def)) {
	case ADDRXLAT_NONE:
		fputs("NONE", stdout);
		break;

	case ADDRXLAT_LINEAR:
		print_ind("LINEAR", def);
		printf(" off=0x%llx",
		       (unsigned long long) addrxlat_def_get_offset(def));
		break;

	case ADDRXLAT_PGT:
		print_ind("PGT", def);
		break;

	}
}

static void
print_pgt(const addrxlat_def_t *pgt)
{
	static const char *pte_formats[] = {
		[addrxlat_pte_none] = "none",
		[addrxlat_pte_ia32] = "ia32",
		[addrxlat_pte_ia32_pae] = "ia32_pae",
		[addrxlat_pte_x86_64] = "x86_64",
		[addrxlat_pte_s390x] = "s390x",
		[addrxlat_pte_ppc64] = "ppc64",
	};

	const addrxlat_paging_form_t *pf = addrxlat_def_get_form(pgt);
	unsigned i;

	fputs("pte_format: ", stdout);
	if (pf->pte_format < ARRAY_SIZE(pte_formats) &&
	    pte_formats[pf->pte_format])
		printf("%s\n", pte_formats[pf->pte_format]);
	else
		printf("%u\n", pf->pte_format);
	printf("rpn_shift: %u\n", pf->rpn_shift);
	printf("bits:");
	for (i = 0; i < pf->levels; ++i)
		printf(" %u", pf->bits[i]);
	putchar('\n');
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
		print_xlat(range->def);
		putchar('\n');

		addr += range->endoff + 1;
	}
}

static int
os_map(void)
{
	addrxlat_ctx *ctx;
	addrxlat_osdesc_t desc;
	addrxlat_osmap_t *osmap;
	const addrxlat_def_t *def;
	addrxlat_status status;

	desc.type = ostype;
	desc.ver = osver;
	desc.arch = arch;

	ctx = addrxlat_new();
	if (!ctx) {
		perror("Cannot allocate addrxlat");
		return TEST_ERR;
	}
	addrxlat_cb_read32(ctx, read32);
	addrxlat_cb_read64(ctx, read64);

	osmap = addrxlat_osmap_new();
	if (!osmap) {
		perror("Cannot allocate osmap");
		addrxlat_decref(ctx);
		return TEST_ERR;
	}

	status = addrxlat_osmap_init(osmap, ctx, &desc);
	if (status != addrxlat_ok) {
		fprintf(stderr, "OS map failed: %s\n",
			(status > 0
			 ? addrxlat_err_str(ctx)
			 : read_err_str));
		addrxlat_osmap_decref(osmap);
		addrxlat_decref(ctx);
		return TEST_ERR;
	}

	def = addrxlat_osmap_get_xlat(osmap, ADDRXLAT_OSMAP_PGT);
	add_symbol(def, "rootpgt");
	print_pgt(def);

	def = addrxlat_osmap_get_xlat(osmap, ADDRXLAT_OSMAP_DIRECT);
	add_symbol(def, "direct");

	def = addrxlat_osmap_get_xlat(osmap, ADDRXLAT_OSMAP_KTEXT);
	add_symbol(def, "ktext");

	print_map(addrxlat_osmap_get_map(osmap));

	addrxlat_osmap_decref(osmap);
	addrxlat_decref(ctx);
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
