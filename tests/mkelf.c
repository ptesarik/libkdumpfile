/* ELF format test suite.
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

#include <string.h>
#include <endian.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <elf.h>

#include "config.h"
#include "testutil.h"
#include "diskdump.h"

typedef int write_fn(FILE *);

struct page_data_elf {
	FILE *f;

	unsigned shnum;
	unsigned phnum;

	union {
		struct {
			unsigned long long sh_name;
			unsigned long long sh_type;
			unsigned long long sh_flags;
			unsigned long long sh_addr;
			unsigned long long sh_link;
			unsigned long long sh_info;
			unsigned long long sh_addralign;
			unsigned long long sh_entsize;
		} shdr;
		struct {
			unsigned long long p_type;
			unsigned long long p_flags;
			unsigned long long p_vaddr;
			unsigned long long p_paddr;
			unsigned long long p_memsz;
			unsigned long long p_align;
		} phdr;
	};

	off_t filepos;
	off_t filesz;

	int (*parsehdr)(struct page_data *pg, char *p);
	int (*finshdr)(struct page_data *pg);
	int (*finphdr)(struct page_data *pg);
	int (*finhdr)(struct page_data *pg);
};

static endian_t be;

static bool flattened;
static unsigned long long flattened_type = MDF_TYPE_FLAT_HEADER;
static unsigned long long flattened_version = MDF_VERSION_FLAT_HEADER;

static char *ei_mag;
static unsigned long long ei_class = ELFCLASS64;
static unsigned long long ei_data = ELFDATA2LSB;
static unsigned long long ei_version = EV_CURRENT;
static unsigned long long ei_osabi = ELFOSABI_NONE;
static unsigned long long ei_abiversion = 0;

static unsigned long long e_type = ET_CORE;
static unsigned long long e_machine = EM_X86_64;
static unsigned long long e_version = EV_CURRENT;
static unsigned long long e_entry;
static unsigned long long e_phoff;
static unsigned long long e_shoff;
static unsigned long long e_flags;
static unsigned long long e_ehsize = sizeof(Elf64_Ehdr);
static unsigned long long e_phentsize = sizeof(Elf64_Phdr);
static unsigned long long e_phnum;
static unsigned long long e_shentsize = sizeof(Elf64_Shdr);
static unsigned long long e_shnum;
static unsigned long long e_shstrndx;

static char *data_file;

static const struct param param_array[] = {
	/* meta-data */
	PARAM_YESNO("flattened", flattened),
	PARAM_NUMBER("flattened.type", flattened_type),
	PARAM_NUMBER("flattened.version", flattened_version),

	/* ELF file header */
	PARAM_STRING("ei_mag", ei_mag),
	PARAM_NUMBER("ei_class", ei_class),
	PARAM_NUMBER("ei_data", ei_data),
	PARAM_NUMBER("ei_version", ei_version),
	PARAM_NUMBER("ei_osabi", ei_osabi),
	PARAM_NUMBER("ei_abiversion", ei_abiversion),

	PARAM_NUMBER("e_type", e_type),
	PARAM_NUMBER("e_machine", e_machine),
	PARAM_NUMBER("e_version", e_version),
	PARAM_NUMBER("e_entry", e_entry),
	PARAM_NUMBER("e_phoff", e_phoff),
	PARAM_NUMBER("e_shoff", e_shoff),
	PARAM_NUMBER("e_flags", e_flags),
	PARAM_NUMBER("e_ehsize", e_ehsize),
	PARAM_NUMBER("e_phentsize", e_phentsize),
	PARAM_NUMBER("e_phnum", e_phnum),
	PARAM_NUMBER("e_shentsize", e_shentsize),
	PARAM_NUMBER("e_shnum", e_shnum),
	PARAM_NUMBER("e_shstrndx", e_shstrndx),

	PARAM_STRING("DATA", data_file)
};

static const struct params params = {
	ARRAY_SIZE(param_array),
	param_array
};

static int
write_chunk(FILE *f, off_t off, const void *ptr, size_t sz, const char *what)
{
	if (flattened) {
		struct makedumpfile_data_header hdr = {
			.offset = htobe64(off),
			.buf_size = htobe64(sz),
		};
		if (fwrite(&hdr, sizeof hdr, 1, f) != 1) {
			perror("flattened segment header");
			return -1;
		}
	} else if (fseek(f, off, SEEK_SET) != 0) {
		fprintf(stderr, "seek %s: %s\n", what, strerror(errno));
		return -1;
	}
	if (fwrite(ptr, 1, sz, f) != sz) {
		fprintf(stderr, "write %s: %s\n", what, strerror(errno));
		return -1;
	}
	return 0;
}

static int
writeheader32(FILE *f)
{
	Elf32_Ehdr ehdr;

	/* initialize dump header to zero */
	memset(&ehdr, 0, sizeof ehdr);

	strncpy((char*)ehdr.e_ident, ei_mag, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ei_class;
	ehdr.e_ident[EI_DATA] = ei_data;
	ehdr.e_ident[EI_VERSION] = ei_version;
	ehdr.e_ident[EI_OSABI] = ei_osabi;
	ehdr.e_ident[EI_ABIVERSION] = ei_abiversion;

	ehdr.e_type = htodump16(be, e_type);
	ehdr.e_machine = htodump16(be, e_machine);
	ehdr.e_version = htodump32(be, e_version);
	ehdr.e_entry = htodump32(be, e_entry);
	ehdr.e_phoff = htodump32(be, e_phoff);
	ehdr.e_shoff = htodump32(be, e_shoff);
	ehdr.e_flags = htodump32(be, e_flags);
	ehdr.e_ehsize = htodump16(be, e_ehsize);
	ehdr.e_phentsize = htodump16(be, e_phentsize);
	ehdr.e_phnum = htodump16(be, e_phnum);
	ehdr.e_shentsize = htodump16(be, e_shentsize);
	ehdr.e_shnum = htodump16(be, e_shnum);
	ehdr.e_shstrndx = htodump16(be, e_shstrndx);

	if (write_chunk(f, 0, &ehdr, sizeof ehdr, "header"))
		return TEST_ERR;

	return TEST_OK;
}

static int
writeheader64(FILE *f)
{
	Elf64_Ehdr ehdr;

	/* initialize dump header to zero */
	memset(&ehdr, 0, sizeof ehdr);

	strncpy((char*)ehdr.e_ident, ei_mag, SELFMAG);
	ehdr.e_ident[EI_CLASS] = ei_class;
	ehdr.e_ident[EI_DATA] = ei_data;
	ehdr.e_ident[EI_VERSION] = ei_version;
	ehdr.e_ident[EI_OSABI] = ei_osabi;
	ehdr.e_ident[EI_ABIVERSION] = ei_abiversion;

	ehdr.e_type = htodump16(be, e_type);
	ehdr.e_machine = htodump16(be, e_machine);
	ehdr.e_version = htodump32(be, e_version);
	ehdr.e_entry = htodump64(be, e_entry);
	ehdr.e_phoff = htodump64(be, e_phoff);
	ehdr.e_shoff = htodump64(be, e_shoff);
	ehdr.e_flags = htodump32(be, e_flags);
	ehdr.e_ehsize = htodump16(be, e_ehsize);
	ehdr.e_phentsize = htodump16(be, e_phentsize);
	ehdr.e_phnum = htodump16(be, e_phnum);
	ehdr.e_shentsize = htodump16(be, e_shentsize);
	ehdr.e_shnum = htodump16(be, e_shnum);
	ehdr.e_shstrndx = htodump16(be, e_shstrndx);

	if (write_chunk(f, 0, &ehdr, sizeof ehdr, "header"))
		return TEST_ERR;

	return TEST_OK;
}

static int
writeheader(FILE *f)
{
	if (ei_class == ELFCLASS32)
		return writeheader32(f);
	else if (ei_class == ELFCLASS64)
		return writeheader64(f);

	fprintf(stderr, "Unsupported class: %llu\n", ei_class);
	return TEST_ERR;
}

static unsigned long long
numarg(const char *s)
{
	unsigned long long val;
	char *end;

	val = strtoull(s, &end, 0);
	if (*end)
		val = ULLONG_MAX;

	return val;
}

static unsigned long long
stype(const char *s)
{
	if (!strcmp(s, "NULL"))
		return SHT_NULL;
	else if (!strcmp(s, "PROGBITS"))
		return SHT_PROGBITS;
	else if (!strcmp(s, "STRTAB"))
		return SHT_STRTAB;
	else if (!strcmp(s, "NOTE"))
		return SHT_NOTE;

	return numarg(s);
}

static int
parseshdr(struct page_data *pg, char *p)
{
	struct page_data_elf *pgelf = pg->priv;
	char *endp, *v;
	unsigned long long num;

	memset(&pgelf->shdr, 0, sizeof pgelf->shdr);
	while (*p) {
		while (*p && isspace(*p))
			++p;
		endp = p;
		while (*endp && !isspace(*endp))
			++endp;
		if (*endp)
			*endp++ = '\0';

		v = strchr(p, '=');
		if (!v) {
			fprintf(stderr, "Missing value: %s\n", p);
			return TEST_ERR;
		}
		*v = '\0';
		++v;

		if (!strcmp(p, "name"))
			num = pgelf->shdr.sh_name = numarg(v);
		else if (!strcmp(p, "type"))
			num = pgelf->shdr.sh_type = stype(v);
		else if (!strcmp(p, "flags"))
			num = pgelf->shdr.sh_flags = numarg(v);
		else if (!strcmp(p, "addr"))
			num = pgelf->shdr.sh_addr = numarg(v);
		else if (!strcmp(p, "offset"))
			num = pgelf->filepos = numarg(v);
		else if (!strcmp(p, "link"))
			num = pgelf->shdr.sh_link = numarg(v);
		else if (!strcmp(p, "info"))
			num = pgelf->shdr.sh_info = numarg(v);
		else if (!strcmp(p, "align"))
			num = pgelf->shdr.sh_addralign = numarg(v);
		else if (!strcmp(p, "entsize"))
			num = pgelf->shdr.sh_entsize = numarg(v);
		else {
			fprintf(stderr, "Invalid argument: %s\n", p);
			return TEST_ERR;
		}

		if (num == ULLONG_MAX) {
			fprintf(stderr, "Invalid %s value: %s\n", p, v);
			return TEST_ERR;
		}

		p = endp;
	}

	return TEST_OK;
}

static unsigned long long
ptype(const char *s)
{
	if (!strcmp(s, "NULL"))
		return PT_NULL;
	else if (!strcmp(s, "LOAD"))
		return PT_LOAD;
	else if (!strcmp(s, "NOTE"))
		return PT_NOTE;

	return numarg(s);
}

static int
parsephdr(struct page_data *pg, char *p)
{
	struct page_data_elf *pgelf = pg->priv;
	char *endp, *v;
	unsigned long long num;

	memset(&pgelf->phdr, 0, sizeof pgelf->phdr);
	while (*p) {
		while (*p && isspace(*p))
			++p;
		endp = p;
		while (*endp && !isspace(*endp))
			++endp;
		if (*endp)
			*endp++ = '\0';

		v = strchr(p, '=');
		if (!v) {
			fprintf(stderr, "Missing value: %s\n", p);
			return TEST_ERR;
		}
		*v = '\0';
		++v;

		if (!strcmp(p, "type"))
			num = pgelf->phdr.p_type = ptype(v);
		else if (!strcmp(p, "flags"))
			num = pgelf->phdr.p_flags = numarg(v);
		else if (!strcmp(p, "offset"))
			num = pgelf->filepos = numarg(v);
		else if (!strcmp(p, "vaddr"))
			num = pgelf->phdr.p_vaddr = numarg(v);
		else if (!strcmp(p, "paddr"))
			num = pgelf->phdr.p_paddr = numarg(v);
		else if (!strcmp(p, "memsz"))
			num = pgelf->phdr.p_memsz = numarg(v);
		else if (!strcmp(p, "align"))
			num = pgelf->phdr.p_align = numarg(v);
		else {
			fprintf(stderr, "Invalid argument: %s\n", p);
			return TEST_ERR;
		}

		if (num == ULLONG_MAX) {
			fprintf(stderr, "Invalid %s value: %s\n", p, v);
			return TEST_ERR;
		}

		p = endp;
	}

	return TEST_OK;
}

static int
parseheader(struct page_data *pg, char *p)
{
	struct page_data_elf *pgelf = pg->priv;
	char *endp, endc;
	int rc;

	if (pgelf->finhdr) {
		rc = pgelf->finhdr(pg);
		if (rc != TEST_OK)
			return rc;
	}

	pgelf->filepos += pgelf->filesz;
	pgelf->filesz = 0;

	while (*p && isspace(*p))
		++p;
	endp = p;
	while (*endp && !isspace(*endp))
		++endp;
	endc = *endp;
	if (*endp)
		*endp++ = '\0';

	if (!strcmp(p, "shdr")) {
		pgelf->parsehdr = parseshdr;
		pgelf->finhdr = pgelf->finshdr;
	} else if (!strcmp(p, "phdr")) {
		pgelf->parsehdr = parsephdr;
		pgelf->finhdr = pgelf->finphdr;
	} else {
		/* recover for type-specific parsing */
		*endp = endc;
		endp = p;
	}
	return pgelf->parsehdr(pg, endp);
}

static int
finshdr32(struct page_data *pg)
{
	struct page_data_elf *pgelf = pg->priv;
	Elf32_Shdr shdr;
	off_t off;

	shdr.sh_name = htodump32(be, pgelf->shdr.sh_name);
	shdr.sh_type = htodump32(be, pgelf->shdr.sh_type);
	shdr.sh_flags = htodump32(be, pgelf->shdr.sh_flags);
	shdr.sh_addr = htodump32(be, pgelf->shdr.sh_addr);
	shdr.sh_offset = htodump32(be, pgelf->filepos);
	shdr.sh_size = htodump32(be, pgelf->filesz);
	shdr.sh_link = htodump32(be, pgelf->shdr.sh_link);
	shdr.sh_info = htodump32(be, pgelf->shdr.sh_info);
	shdr.sh_addralign = htodump32(be, pgelf->shdr.sh_addralign);
	shdr.sh_entsize = htodump32(be, pgelf->shdr.sh_entsize);

	off = e_shoff + pgelf->shnum * sizeof shdr;
	if (write_chunk(pgelf->f, off, &shdr, sizeof shdr, "section header"))
		return TEST_ERR;

	++pgelf->shnum;
	return TEST_OK;
}

static int
finshdr64(struct page_data *pg)
{
	struct page_data_elf *pgelf = pg->priv;
	Elf64_Shdr shdr;
	off_t off;

	shdr.sh_name = htodump32(be, pgelf->shdr.sh_name);
	shdr.sh_type = htodump32(be, pgelf->shdr.sh_type);
	shdr.sh_flags = htodump64(be, pgelf->shdr.sh_flags);
	shdr.sh_addr = htodump64(be, pgelf->shdr.sh_addr);
	shdr.sh_offset = htodump64(be, pgelf->filepos);
	shdr.sh_size = htodump64(be, pgelf->filesz);
	shdr.sh_link = htodump32(be, pgelf->shdr.sh_link);
	shdr.sh_info = htodump32(be, pgelf->shdr.sh_info);
	shdr.sh_addralign = htodump64(be, pgelf->shdr.sh_addralign);
	shdr.sh_entsize = htodump64(be, pgelf->shdr.sh_entsize);

	off = e_shoff + pgelf->shnum * sizeof shdr;
	if (write_chunk(pgelf->f, off, &shdr, sizeof shdr, "section header"))
		return TEST_ERR;

	++pgelf->shnum;
	return TEST_OK;
}

static int
finphdr32(struct page_data *pg)
{
	struct page_data_elf *pgelf = pg->priv;
	Elf32_Phdr phdr;
	off_t off;

	if (!pgelf->phdr.p_memsz)
		pgelf->phdr.p_memsz = pgelf->filesz;

	phdr.p_type = htodump32(be, pgelf->phdr.p_type);
	phdr.p_offset = htodump32(be, pgelf->filepos);
	phdr.p_vaddr = htodump32(be, pgelf->phdr.p_vaddr);
	phdr.p_paddr = htodump32(be, pgelf->phdr.p_paddr);
	phdr.p_filesz = htodump32(be, pgelf->filesz);
	phdr.p_memsz = htodump32(be, pgelf->phdr.p_memsz);
	phdr.p_flags = htodump32(be, pgelf->phdr.p_flags);
	phdr.p_align = htodump32(be, pgelf->phdr.p_align);

	off = e_phoff + pgelf->phnum * sizeof phdr;
	if (write_chunk(pgelf->f, off, &phdr, sizeof phdr, "program header"))
		return TEST_ERR;

	++pgelf->phnum;
	return TEST_OK;
}

static int
finphdr64(struct page_data *pg)
{
	struct page_data_elf *pgelf = pg->priv;
	Elf64_Phdr phdr;
	off_t off;

	if (!pgelf->phdr.p_memsz)
		pgelf->phdr.p_memsz = pgelf->filesz;

	phdr.p_type = htodump32(be, pgelf->phdr.p_type);
	phdr.p_flags = htodump64(be, pgelf->phdr.p_flags);
	phdr.p_offset = htodump64(be, pgelf->filepos);
	phdr.p_vaddr = htodump64(be, pgelf->phdr.p_vaddr);
	phdr.p_paddr = htodump64(be, pgelf->phdr.p_paddr);
	phdr.p_filesz = htodump64(be, pgelf->filesz);
	phdr.p_memsz = htodump64(be, pgelf->phdr.p_memsz);
	phdr.p_align = htodump64(be, pgelf->phdr.p_align);

	off = e_phoff + pgelf->phnum * sizeof phdr;
	if (write_chunk(pgelf->f, off, &phdr, sizeof phdr, "program header"))
		return TEST_ERR;

	++pgelf->phnum;
	return TEST_OK;
}

static int
writepage(struct page_data *pg)
{
	struct page_data_elf *pgelf = pg->priv;

	pgelf->filesz += pg->len;
	if (write_chunk(pgelf->f, pgelf->filepos, pg->buf, pg->len, "data"))
		return TEST_ERR;

	return TEST_OK;
}

static int
writedata(FILE *f)
{
	struct page_data_elf pgelf;
	struct page_data pg;
	int rc;

	if (!data_file)
		return TEST_OK;

	printf("Creating segments and/or sections\n");

	memset(&pgelf, 0, sizeof pgelf);

	pgelf.f = f;
	pgelf.shnum = 0;
	pgelf.phnum = 0;

	if (ei_class == ELFCLASS32) {
		pgelf.finshdr = finshdr32;
		pgelf.finphdr = finphdr32;
	} else if (ei_class == ELFCLASS64) {
		pgelf.finshdr = finshdr64;
		pgelf.finphdr = finphdr64;
	} else {
		fprintf(stderr, "Unsupported class: %llu\n", ei_class);
		return TEST_ERR;
	}

	pg.endian = be;
	pg.priv = &pgelf;
	pg.parse_hdr = parseheader;
	pg.write_page = writepage;

	rc = process_data(&pg, data_file);

	if (rc == TEST_OK && pgelf.finhdr)
		rc = pgelf.finhdr(&pg);

	if (!e_shnum)
		e_shnum = pgelf.shnum;
	if (!e_phnum)
		e_phnum = pgelf.phnum;

	return rc;
}

static int
writedump(FILE *f)
{
	int rc;

	if (flattened) {
		struct makedumpfile_header hdr = {
			.signature = MDF_SIGNATURE,
			.type = htobe64(flattened_type),
			.version = htobe64(flattened_version),
		};
		size_t remain;

		if (fwrite(&hdr, sizeof hdr, 1, f) != 1) {
			perror("flattened header");
			return TEST_ERR;
		}
		remain = MDF_HEADER_SIZE - sizeof hdr;
		while (remain--) {
			if (putc(0, f) != 0) {
				perror("flattened header padding");
				return TEST_ERR;
			}
		}
	}

	if (ei_data == ELFDATA2LSB)
		be = data_le;
	else if (ei_data == ELFDATA2MSB)
		be = data_be;
	else {
		fprintf(stderr, "Unsupported data format: %llu\n", ei_data);
		return TEST_ERR;
	}

	rc = writedata(f);
	if (rc != TEST_OK)
		return rc;

	rc = writeheader(f);
	if (rc != TEST_OK)
		return rc;

	if (flattened) {
		struct makedumpfile_data_header hdr = {
			.offset = htobe64(MDF_OFFSET_END_FLAG),
			.buf_size = htobe64(MDF_OFFSET_END_FLAG),
		};
		if (fwrite(&hdr, sizeof hdr, 1, f) != 1) {
			perror("end segment header");
			return TEST_ERR;
		}
	}

	return TEST_OK;
}

static int
create_file(const char *name)
{
	FILE *f;
	int rc;

	f = fopen(name, "w");
	if (!f) {
		perror("Cannot create output");
		return TEST_ERR;
	}

	rc = writedump(f);
	if (fclose(f) != 0) {
		perror("Error closing output");
		rc = TEST_ERR;
	}

	return rc;
}

int
main(int argc, char **argv)
{
	int rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <dump>\n", argv[0]);
		return TEST_ERR;
	}

	ei_mag = strdup(ELFMAG);
	if (!ei_mag) {
		perror("Cannot set default ELF identification bytes");
		return TEST_ERR;
	}

	rc = parse_params_file(&params, stdin);
	if (rc != TEST_OK)
		return rc;

	rc = create_file(argv[1]);
	if (rc != TEST_OK)
		return rc;

	return TEST_OK;
}
