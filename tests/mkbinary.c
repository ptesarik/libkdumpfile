/* Make binary from data file.
   Copyright (C) 2023 Petr Tesarik <petr@tesarici.cz>

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

#include <endian.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "testutil.h"

static int
parseheader(struct page_data *pg, char *p)
{
	FILE *fout = *(FILE**)pg->priv;
	unsigned long long offset;
	char *endp;

	while (isspace(*p))
		++p;
	if (!*p) {
		fputs("Missing chunk offset\n", stderr);
		return TEST_ERR;
	}

	offset = strtoull(p, &endp, 0);
	if (*endp) {
		fprintf(stderr, "Invalid chunk offset: %s\n", p);
		return TEST_ERR;
	}

	if (fseek(fout, offset, SEEK_SET) != 0) {
		perror("Cannot seek chunk");
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
writechunk(struct page_data *pg)
{
	FILE *fout = *(FILE**)pg->priv;

	if (fwrite(pg->buf, 1, pg->len, fout) != pg->len) {
		perror("Cannot write data");
		return TEST_ERR;
	}

	return TEST_OK;
}

static bool
setendian(struct page_data *pg, const char *spec)
{
	if (!strcasecmp(spec, "be")) {
		pg->endian = data_be;
	} else if (!strcasecmp(spec, "le")) {
		pg->endian = data_le;
	} else {
		fprintf(stderr, "Invalid endianity: %s\n", spec);
		return false;
	}
	return true;
}

static void
usage(FILE *out, const char *progname)
{
	fprintf(out, "Usage: %s [options] <outfile>\n", progname);
	fputs("Options:\n"
	      "  -h, --help\n\tShow this help\n"
	      "  -d, --data file\n\tRead data frin file instead of stdin\n"
	      "  -e, --endian be|le\n\tSet endianity\n",
	      out);
}

static const struct option opts[] = {
	{ "data", required_argument, NULL, 'd' },
	{ "endian", required_argument, NULL, 'e' },
	{ "help", no_argument, NULL, 'h' },
	{ }
};

int
main(int argc, char **argv)
{
	struct page_data pg;
	const char *data = NULL;
	FILE *fout;
	int opt;
	int rc;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	pg.endian = data_le;
#elif __BYTE_ORDER == __BIG_ENDIAN
	pg.endian = data_be;
#else
# error "Neither __LITTLE_ENDIAN nor __BIG_ENDIAN?"
#endif
	pg.parse_hdr = parseheader;
	pg.write_page = writechunk;
	pg.priv = &fout;

	while ((opt = getopt_long(argc, argv, "he:o:", opts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			data = optarg;
			break;

		case 'e':
			if (!setendian(&pg, optarg))
				return TEST_ERR;
			break;

		case 'h':
			usage(stdout, argv[0]);
			return TEST_OK;

		case '?':
			usage(stderr, argv[0]);
			return TEST_ERR;
		}
	}

	if (optind != argc - 1) {
		usage(stderr, argv[0]);
		return TEST_ERR;
	}

	fout = fopen(argv[optind], "wb");
	if (!fout) {
		perror("Cannot open output file");
		return TEST_ERR;
	}

	rc = data
		? process_data(&pg, data)
		: process_data_file(&pg, stdin);
	if (rc != TEST_OK)
		return rc;

	if (fclose(fout)) {
		perror("Cannot close output file");
		return TEST_ERR;
	}

	return TEST_OK;
}
