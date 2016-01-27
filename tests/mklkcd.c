/* LKCD format test suite.
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
#include <stdlib.h>
#include <ctype.h>

#include "config.h"
#include "testutil.h"
#include "lkcd.h"

#if USE_ZLIB
# include <zlib.h>
#endif

#define DUMP_VERSION_NUMBER  9

typedef int write_fn(FILE *);

struct page_data_lkcd {
	FILE *f;

	unsigned long long addr;
	unsigned long flags;
	enum {
		compress_auto = -1,
		compress_no,
		compress_yes,
	} compress;

	void *cbuf;
	size_t cbufsz;

	unsigned long skip;
};

static endian_t be;
static write_fn *writeheader_asm;

static char *arch_name;
static unsigned long long page_shift;
static unsigned long long page_offset;
static unsigned long long dump_level = DUMP_LEVEL_KERN;
static char *panic_string;
static unsigned long long compression = DUMP_COMPRESS_NONE;
static unsigned long long buffer_size = (256*1024);

static char *uts_sysname;
static char *uts_nodename;
static char *uts_release;
static char *uts_version;
static char *uts_machine;
static char *uts_domainname;

static unsigned long long NR_CPUS;
static unsigned long long num_cpus;
static struct number_array current_task;
static struct number_array stack;
static struct number_array stack_ptr;

static unsigned long num_dump_pages;

static char *data_file;

static const struct param param_array[] = {
	PARAM_STRING("arch_name", arch_name),
	PARAM_NUMBER("page_shift", page_shift),
	PARAM_NUMBER("page_offset", page_offset),
	PARAM_NUMBER("dump_level", dump_level),
	PARAM_STRING("panic_string", panic_string),
	PARAM_NUMBER("compression", compression),
	PARAM_NUMBER("buffer_size", buffer_size),

	PARAM_STRING("uts.sysname", uts_sysname),
	PARAM_STRING("uts.nodename", uts_nodename),
	PARAM_STRING("uts.release", uts_release),
	PARAM_STRING("uts.version", uts_version),
	PARAM_STRING("uts.machine", uts_machine),
	PARAM_STRING("uts.domainname", uts_domainname),

	PARAM_NUMBER("NR_CPUS", NR_CPUS),
	PARAM_NUMBER("num_cpus", num_cpus),
	PARAM_NUMBER_ARRAY("current_task", current_task),
	PARAM_NUMBER_ARRAY("stack", stack),
	PARAM_NUMBER_ARRAY("stak_ptr", stack_ptr),

	PARAM_STRING("DATA", data_file)
};

static const struct params params = {
	ARRAY_SIZE(param_array),
	param_array
};

static int
set_default_params(void)
{
	arch_name = strdup("x86_64");
	if (!arch_name)
		return TEST_ERR;

	panic_string = strdup("");
	if (!panic_string)
		return TEST_ERR;

	uts_sysname = strdup("Linux");
	if (!uts_sysname)
		return TEST_ERR;

	uts_nodename = strdup("");
	if (!uts_nodename)
		return TEST_ERR;

	uts_release = strdup("0.0.0");
	if (!uts_release)
		return TEST_ERR;

	uts_version = strdup("#1");
	if (!uts_version)
		return TEST_ERR;

	uts_machine = strdup("x86_64");
	if (!uts_machine)
		return TEST_ERR;

	uts_domainname = strdup("(none)");
	if (!uts_domainname)
		return TEST_ERR;

	return TEST_OK;
}

static int
writeheader(FILE *f)
{
	struct timeval tv;
	struct dump_header hdr;

	if (gettimeofday(&tv, NULL) != 0) {
		perror("gettimeofday");
		return -1;
	}

	/* initialize dump header to zero */
	memset(&hdr, 0, sizeof hdr);

	/* configure dump header values */
	hdr.dh_magic_number = htodump64(be, DUMP_MAGIC_NUMBER);
	hdr.dh_version = htodump32(be, DUMP_VERSION_NUMBER);
	hdr.dh_header_size = htodump32(be, sizeof hdr);
	hdr.dh_dump_level = htodump32(be, dump_level);
	hdr.dh_page_size = htodump32(be, 1UL << page_shift);
	hdr.dh_memory_size = htodump64(be, 0);
	hdr.dh_memory_start = htodump64(be, page_offset);
	hdr.dh_memory_end = htodump64(be, DUMP_MAGIC_NUMBER); /* sic! */
	hdr.dh_num_dump_pages = htodump32(be, num_dump_pages);
	strncpy(hdr.dh_panic_string, panic_string,
		sizeof hdr.dh_panic_string);
	hdr.dh_time.tv_sec = htodump64(be, tv.tv_sec);
	hdr.dh_time.tv_usec = htodump64(be, tv.tv_usec);
	strncpy(hdr.dh_utsname_sysname, uts_sysname,
		sizeof hdr.dh_utsname_sysname);
	strncpy(hdr.dh_utsname_nodename, uts_nodename,
		sizeof hdr.dh_utsname_nodename);
	strncpy(hdr.dh_utsname_release, uts_release,
		sizeof hdr.dh_utsname_release);
	strncpy(hdr.dh_utsname_version, uts_version,
		sizeof hdr.dh_utsname_version);
	strncpy(hdr.dh_utsname_machine, uts_machine,
		sizeof hdr.dh_utsname_machine);
	strncpy(hdr.dh_utsname_domainname, uts_domainname,
		sizeof hdr.dh_utsname_domainname);
	if (current_task.n > 0)
		hdr.dh_current_task = htodump64(be, current_task.val[0]);
	hdr.dh_dump_compress = htodump32(be, compression);
	hdr.dh_dump_buffer_size = htodump64(be, buffer_size);

	if (fseek(f, 0, SEEK_SET) != 0) {
		perror("seek header");
		return -1;
	}

	if (fwrite(&hdr, sizeof hdr, 1, f) != 1) {
		perror("write header");
		return -1;
	}

	return writeheader_asm(f);
}

static int
writeheader_asm_x86_64(FILE *f)
{
	struct dump_header_asm_x86_64 asmhdr;
	size_t sz;
	off_t off;
	unsigned i;

	memset(&asmhdr, 0, sizeof asmhdr);
	asmhdr.dha_magic_number = htodump64(be, DUMP_ASM_MAGIC_NUMBER_X86_64);
	asmhdr.dha_version = htodump32(be, DUMP_ASM_VERSION_NUMBER_X86_64);
	sz = sizeof asmhdr +
		NR_CPUS * sizeof(struct pt_regs_x86_64) + /* dha_smp_regs */
		NR_CPUS * sizeof(uint64_t) + /* dha_smp_current_task */
		NR_CPUS * sizeof(uint64_t) + /* dha_stack */
		NR_CPUS * sizeof(uint64_t);  /* dha_stack_ptr */
	asmhdr.dha_header_size = htodump32(be, sz);

	asmhdr.dha_smp_num_cpus = htodump32(be, num_cpus);
	asmhdr.dha_dumping_cpu = htodump32(be, 0);

	if (fwrite(&asmhdr, sizeof asmhdr, 1, f) != 1) {
		perror("write asm header");
		return -1;
	}

	off = NR_CPUS * sizeof(struct pt_regs_x86_64);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_smp_current_task");
		return -1;
	}
	for (i = 0; i < current_task.n; ++i) {
		uint64_t tmp = htodump64(be, current_task.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_smp_current_task");
			return -1;
		}
	}
	off = (NR_CPUS - current_task.n) * sizeof(uint64_t);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_stack");
		return -1;
	}
	for (i = 0; i < stack.n; ++i) {
		uint64_t tmp = htodump64(be, stack.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_task");
			return -1;
		}
	}
	off = (NR_CPUS - stack.n) * sizeof(uint64_t);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_stack_ptr");
		return -1;
	}
	for (i = 0; i < stack_ptr.n; ++i) {
		uint64_t tmp = htodump64(be, stack_ptr.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_task");
			return -1;
		}
	}

	return 0;
}

static int
writeheader_asm_i386(FILE *f)
{
	struct dump_header_asm_i386 asmhdr;
	size_t sz;
	off_t off;
	unsigned i;

	memset(&asmhdr, 0, sizeof asmhdr);
	asmhdr.dha_magic_number = htodump64(be, DUMP_ASM_MAGIC_NUMBER_I386);
	asmhdr.dha_version = htodump32(be, DUMP_ASM_VERSION_NUMBER_I386);
	sz = sizeof asmhdr +
		NR_CPUS * sizeof(struct pt_regs_i386) + /* dha_smp_regs */
		NR_CPUS * sizeof(uint32_t) + /* dha_smp_current_task */
		NR_CPUS * sizeof(uint32_t) + /* dha_stack */
		NR_CPUS * sizeof(uint32_t);  /* dha_stack_ptr */
	asmhdr.dha_header_size = htodump32(be, sz);

	asmhdr.dha_smp_num_cpus = htodump32(be, num_cpus);
	asmhdr.dha_dumping_cpu = htodump32(be, 0);

	if (fwrite(&asmhdr, sizeof asmhdr, 1, f) != 1) {
		perror("write asm header");
		return -1;
	}

	off = NR_CPUS * sizeof(struct pt_regs_i386);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_smp_current_task");
		return -1;
	}
	for (i = 0; i < current_task.n; ++i) {
		uint32_t tmp = htodump32(be, current_task.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_smp_current_task");
			return -1;
		}
	}
	off = (NR_CPUS - current_task.n) * sizeof(uint32_t);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_stack");
		return -1;
	}
	for (i = 0; i < stack.n; ++i) {
		uint32_t tmp = htodump32(be, stack.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_task");
			return -1;
		}
	}
	off = (NR_CPUS - stack.n) * sizeof(uint32_t);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_stack_ptr");
		return -1;
	}
	for (i = 0; i < stack_ptr.n; ++i) {
		uint32_t tmp = htodump32(be, stack_ptr.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_task");
			return -1;
		}
	}

	return 0;
}

static int
writeheader_asm_ppc64(FILE *f)
{
	struct dump_header_asm_ppc64 asmhdr;
	size_t sz;
	off_t off;
	unsigned i;

	memset(&asmhdr, 0, sizeof asmhdr);
	asmhdr.dha_magic_number = htodump64(be, DUMP_ASM_MAGIC_NUMBER_PPC64);
	asmhdr.dha_version = htodump32(be, DUMP_ASM_VERSION_NUMBER_PPC64);
	sz = sizeof asmhdr +
		NR_CPUS * sizeof(struct pt_regs_ppc64) + /* dha_smp_regs */
		NR_CPUS * sizeof(uint64_t) + /* dha_smp_current_task */
		NR_CPUS * sizeof(uint64_t) + /* dha_stack */
		NR_CPUS * sizeof(uint64_t);  /* dha_stack_ptr */
	asmhdr.dha_header_size = htodump32(be, sz);

	asmhdr.dha_smp_num_cpus = htodump32(be, num_cpus);
	asmhdr.dha_dumping_cpu = htodump32(be, 0);

	if (fwrite(&asmhdr, sizeof asmhdr, 1, f) != 1) {
		perror("write asm header");
		return -1;
	}

	off = NR_CPUS * sizeof(struct pt_regs_ppc64);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_smp_current_task");
		return -1;
	}
	for (i = 0; i < current_task.n; ++i) {
		uint64_t tmp = htodump64(be, current_task.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_smp_current_task");
			return -1;
		}
	}
	off = (NR_CPUS - current_task.n) * sizeof(uint64_t);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_stack");
		return -1;
	}
	for (i = 0; i < stack.n; ++i) {
		uint64_t tmp = htodump64(be, stack.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_task");
			return -1;
		}
	}
	off = (NR_CPUS - stack.n) * sizeof(uint64_t);

	if (fseek(f, off, SEEK_CUR) != 0) {
		perror("seek dha_stack_ptr");
		return -1;
	}
	for (i = 0; i < stack_ptr.n; ++i) {
		uint64_t tmp = htodump64(be, stack_ptr.val[i]);
		if (fwrite(&tmp, sizeof tmp, 1, f) != 1) {
			perror("write dha_task");
			return -1;
		}
	}

	return 0;
}

static int
parseheader(struct page_data *pg, char *p)
{
	struct page_data_lkcd *pglkcd = pg->priv;
	char *endp;

	if (!*p) {
		pglkcd->addr += 1ULL << page_shift;
		return TEST_OK;
	}

	pglkcd->addr = strtoull(p, &endp, 0);
	if (*endp && !isspace(*endp)) {
		*endp = '\0';
		fprintf(stderr, "Invalid address: %s\n", p);
		return TEST_FAIL;
	}

	pglkcd->flags = 0;
	pglkcd->compress = compress_auto;
	pglkcd->skip = 0;

	p = endp;
	while (*p && isspace(*p))
		++p;

	if (!strncmp(p, "skip=", 5)) {
		p += 5;
		pglkcd->skip = strtoul(p, &endp, 0);
		if (*endp && !isspace(*endp)) {
			fprintf(stderr, "Invalid skip: %s\n", p);
			return TEST_FAIL;
		}
		p = endp;
		while (*p && isspace(*p))
			++p;
	}

	if (!*p)
		return TEST_OK;

	if (!strcmp(p, "raw")) {
		pglkcd->flags |= DUMP_DH_RAW;
		pglkcd->compress = compress_no;
	} else if (!strcmp(p, "compress")) {
		pglkcd->flags |= DUMP_DH_COMPRESSED;
		pglkcd->compress = compress_yes;
	} else if (!strcmp(p, "end")) {
		pglkcd->flags |= DUMP_DH_END;
	} else {
		pglkcd->flags = strtoul(p, &endp, 0);
		if (*endp) {
			fprintf(stderr, "Invalid flags: %s\n", p);
			return TEST_FAIL;
		}
	}

	return TEST_OK;
}

static size_t
do_rle(struct page_data *pg)
{
	struct page_data_lkcd *pglkcd = pg->priv;
	size_t clen;

	clen = pglkcd->cbufsz;
	while (compress_rle(pglkcd->cbuf, &clen, pg->buf, pg->len)) {
		unsigned char *newbuf;

		clen = pglkcd->cbufsz + (1UL << (page_shift-2));
		newbuf = realloc(pglkcd->cbuf, clen);
		if (!newbuf) {
			perror("Cannot allocate compression buffer");
			return 0;
		}
		pglkcd->cbuf = newbuf;
		pglkcd->cbufsz = clen;
	}
	return clen;
}

#if USE_ZLIB
static size_t
do_gzip(struct page_data *pg)
{
	struct page_data_lkcd *pglkcd = pg->priv;
	uLongf clen;

	clen = pglkcd->cbufsz;
	while (compress(pglkcd->cbuf, &clen, pg->buf, pg->len) != Z_OK) {
		unsigned char *newbuf;

		clen = pglkcd->cbufsz + (1UL << (page_shift-2));
		newbuf = realloc(pglkcd->cbuf, clen);
		if (!newbuf) {
			perror("Cannot allocate compression buffer");
			return 0;
		}
		pglkcd->cbuf = newbuf;
		pglkcd->cbufsz = clen;
	}
	return clen;
}
#endif

static size_t
compresspage(struct page_data *pg)
{
	switch (compression) {
	case DUMP_COMPRESS_RLE:
		return do_rle(pg);

#if USE_ZLIB
	case DUMP_COMPRESS_GZIP:
		return do_gzip(pg);
#endif

	default:
		fprintf(stderr, "Unsupported compression method: %llu\n",
			compression);
	}

	return 0;
}

static int
writepage(struct page_data *pg)
{
	struct page_data_lkcd *pglkcd = pg->priv;
	struct dump_page dp;
	unsigned char *buf;
	size_t buflen;
	uint32_t flags;

	flags = pglkcd->flags;

	if (pg->len && compression != DUMP_COMPRESS_NONE &&
	    pglkcd->compress != compress_no) {
		buflen = compresspage(pg);
		if (!buflen)
			return TEST_ERR;
		buf = pglkcd->cbuf;

		if (pglkcd->compress == compress_auto) {
			if (buflen >= pg->len) {
				buflen = pg->len;
				buf = pg->buf;
				flags &= ~DUMP_DH_COMPRESSED;
				flags |= DUMP_DH_RAW;
			} else {
				flags &= ~DUMP_DH_RAW;
				flags |= DUMP_DH_COMPRESSED;
			}
		}
	} else {
		buflen = pg->len;
		buf = pg->buf;
	}
	dp.dp_address = htodump64(be, pglkcd->addr);
	dp.dp_size = htodump32(be, buflen + pglkcd->skip);
	dp.dp_flags = htodump32(be, flags);

	if (fwrite(&dp, sizeof dp, 1, pglkcd->f) != 1) {
		perror("write page desc");
		return TEST_ERR;
	}

	if (fwrite(buf, 1, buflen, pglkcd->f) != buflen) {
		perror("write page data");
		return TEST_ERR;
	}

	if (pglkcd->skip &&
	    fseek(pglkcd->f, pglkcd->skip, SEEK_CUR) != 0) {
		perror("skip page data");
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
writedata(FILE *f)
{
	struct page_data_lkcd pglkcd;
	struct page_data pg;
	int rc;

	if (!data_file)
		return TEST_OK;

	if (fseek(f, buffer_size, SEEK_SET) != 0) {
		perror("seek data");
		return TEST_ERR;
	}

	printf("Creating page data\n");

	pglkcd.f = f;
	pglkcd.addr = 0;
	pglkcd.flags = 0;
	pglkcd.cbuf = NULL;
	pglkcd.cbufsz = 0;

	pg.endian = be;
	pg.priv = &pglkcd;
	pg.parse_hdr = parseheader;
	pg.write_page = writepage;

	rc = process_data(&pg, data_file);

	if (pglkcd.cbuf)
		free(pglkcd.cbuf);

	return rc;
}

static int
writedump(FILE *f)
{
	int rc;

	rc = writedata(f);
	if (rc != 0)
		return rc;

	rc = writeheader(f);
	if (rc != 0)
		return rc;

	return 0;
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

static int
setup_arch(void)
{
	if (!strcmp(arch_name, "x86_64")) {
		be = 0;
		writeheader_asm = writeheader_asm_x86_64;
	} else if (!strcmp(arch_name, "i386")) {
		be = 0;
		writeheader_asm = writeheader_asm_i386;
	} else if (!strcmp(arch_name, "ppc64")) {
		be = 1;
		writeheader_asm = writeheader_asm_ppc64;
	} else {
		fprintf(stderr, "Unknown architecture: %s\n", arch_name);
		return -1;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <dump>\n", argv[0]);
		return TEST_ERR;
	}

	rc = set_default_params();
	if (rc != TEST_OK) {
		perror("Cannot set default params");
		return rc;
	}

	rc = parse_params_file(&params, stdin);
	if (rc != TEST_OK)
		return rc;

	rc = setup_arch();
	if (rc != TEST_OK)
		return rc;

	rc = create_file(argv[1]);
	if (rc != TEST_OK)
		return rc;

	return TEST_OK;
}
