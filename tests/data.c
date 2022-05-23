/* Data file parsing.
   Copyright (C) 2016 Petr Tesarik <ptesarik@suse.cz>

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
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "testutil.h"

#define ALLOC_INC	4096

static int
make_room(struct page_data *pg, size_t sz)
{
	unsigned char *newbuf;

	if (pg->alloc - pg->len >= sz)
		return TEST_OK;

	sz += ALLOC_INC - (sz % ALLOC_INC);
	newbuf = realloc(pg->buf, pg->alloc + sz);
	if (!newbuf) {
		perror("realloc page buffer");
		return TEST_ERR;
	}

	pg->buf = newbuf;
	pg->alloc += sz;

	return TEST_OK;
}

static int
add_string(struct page_data *pg, char **pp)
{
	signed char tmp1, tmp2, tmp3;
	char *endp;

	for (endp = *pp; *endp && *endp != '\"'; ++endp) {
		int rc = make_room(pg, 1);
		if (rc != TEST_OK)
			return rc;

		if (*endp == '\\') {
			tmp1 = unoct(*++endp);
			if (tmp1 != -1) {
				tmp2 = unoct(*++endp);
				if (tmp2 != -1) {
					tmp3 = unoct(*++endp);
					if (tmp3 != -1)
						pg->buf[pg->len] = (tmp1 << 6) | (tmp2 << 3) | tmp3;
					else {
						pg->buf[pg->len] = (tmp1 << 3) | tmp2;
						--endp;
					}
				} else {
					pg->buf[pg->len] = tmp1;
					--endp;
				}
			} else switch (*endp) {
			case 'a':
				pg->buf[pg->len] = '\a';
				break;
			case 'b':
				pg->buf[pg->len] = '\b';
				break;
			case 'e':
				pg->buf[pg->len] = '\033';
				break;
			case 'f':
				pg->buf[pg->len] = '\f';
				break;
			case 'n':
				pg->buf[pg->len] = '\n';
				break;
			case 'r':
				pg->buf[pg->len] = '\r';
				break;
			case 't':
				pg->buf[pg->len] = '\t';
				break;
			case 'v':
				pg->buf[pg->len] = '\v';
				break;
			case 'x':
				tmp1 = unhex(endp[1]);
				tmp2 = (tmp1 == -1 ? tmp1 : unhex(endp[2]));
				if (tmp2 == -1) {
					fputs("Invalid hex escape\n", stderr);
					return TEST_FAIL;
				}
				pg->buf[pg->len] = (tmp1 << 4) | tmp2;
				endp += 2;
				break;
			case '\\':
			case '\'':
			case '\"':
			case '?':
			default:
				pg->buf[pg->len] = *endp;
			}
		} else
			pg->buf[pg->len] = *endp;
		++pg->len;
	}

	if (!*endp) {
		fprintf(stderr, "Unterminated string: %s\n", *pp);
		return TEST_FAIL;
	}

	*pp = endp + 1;
	return TEST_OK;
}

static int
add_page_data(struct page_data *pg, char *p)
{
	char *endp;
	unsigned char *bufp, c;
	unsigned long len, sz, rep, i, j;
	int rc;

	while (*p) {
		while (*p && isspace(*p))
			++p;

		if (*p == '#')
			return TEST_OK;

		if (*p == '"') {
			++p;
			rc = add_string(pg, &p);
			if (rc != TEST_OK)
				return rc;
			continue;
		}

		endp = p;
		while (*endp && isxdigit(*endp))
			++endp;
		len = endp - p;
		sz = (len + (len & 1)) / 2;

		rc = make_room(pg, sz);
		if (rc != TEST_OK)
			return rc;

		c = 0;
		bufp = pg->buf + pg->len;
		if (pg->endian == data_le)
			bufp += sz;
		for (i = len; i > 0; --i) {
			c |= unhex(*p++);
			if (i & 1) {
				if (pg->endian == data_le)
					--bufp;
				*bufp = c;
				if (pg->endian == data_be)
					++bufp;
				c = 0;
			} else
				c <<= 4;
		}
		pg->len += sz;

		p = endp;
		while (*p && isspace(*p))
			++p;
		if (*p != '*')
			continue;

		++p;
		while (*p && isspace(*p))
			++p;
		rep = strtoul(p, &endp, 0);
		if (!*p || (*endp && !isspace(*endp) &&
			    *endp != '+' && *endp != '-')) {
			fprintf(stderr, "Invalid repeat: %s\n", p);
			return TEST_FAIL;
		}
		p = endp;

		rc = make_room(pg, sz * rep);
		if (rc != TEST_OK)
			return rc;
		--rep;
		pg->len += sz * rep;
		memset(pg->buf + pg->len, 0, sz);

		while (*p && isspace(*p))
			++p;
		if (*p == '+' || *p == '-') {
			unsigned char sign = *p;

			++p;
			while (*p && isspace(*p))
				++p;

			endp = p;
			while (*endp && isxdigit(*endp))
				++endp;
			len = endp - p;
			if (len > 2 * sz) {
				p += len - 2 * sz;
				len = 2 * sz;
			}

			c = 0;
			bufp = pg->buf + pg->len;
			if (pg->endian == data_le)
				bufp += (len + 1) / 2;
			else
				bufp += sz - (len + 1) / 2;
			for (i = len; i > 0; --i) {
				c |= unhex(*p++);
				if (i & 1) {
					if (pg->endian == data_le)
						--bufp;
					*bufp = c;
					if (pg->endian == data_be)
						++bufp;
					c = 0;
				} else
					c <<= 4;
			}
			p = endp;

			if (sign == '-') {
				bufp = pg->buf + pg->len;
				for (i = 0; i < sz; ++i)
					bufp[i] = ~bufp[i];
				if (pg->endian == data_le)
					for (i = 0; i < sz; ++i)
						if (++bufp[i])
							break;
				if (pg->endian == data_be)
					while (i--)
						if (++bufp[i])
							break;
			}
		}

		bufp = pg->buf + pg->len - sz * rep;
		for (i = 0; i < rep; ++i) {
			memcpy(bufp, bufp - sz, sz);
			if (pg->endian == data_le) {
				unsigned sum = 0;
				for (j = 0; j < sz; ++j) {
					sum += bufp[j] + pg->buf[pg->len + j];
					bufp[j] = sum;
					sum >>= 8;
				}
			}
			if (pg->endian == data_be) {
				unsigned sum = 0;
				j = sz;
				while (j--) {
					sum += bufp[j] + pg->buf[pg->len + j];
					bufp[j] = sum;
					sum >>= 8;
				}
			}

			bufp += sz;
		}
	}

	return TEST_OK;
}

int
process_data_file(struct page_data *pg, FILE *f)
{
	char *line, *p;
	size_t linesz;
	unsigned linenum;
	int hdrseen = 0;
	int rc = TEST_OK;

	line = NULL;
	linesz = 0;
	linenum = 0;

	pg->alloc = pg->len = 0;
	pg->buf = NULL;

	while (rc == TEST_OK && getline(&line, &linesz, f) > 0) {
		++linenum;

		p = line + strlen(line) - 1;
		while (p > line && isspace(*p))
			*p-- = '\0';

		p = line;
		while (*p && isspace(*p))
			++p;

		if (*p == '#' || *p == '\0')
			continue;

		if (*p == '@') {
			if (hdrseen) {
				rc = pg->write_page(pg);
				if (rc != TEST_OK)
					break;
				pg->len = 0;
			}

			rc = pg->parse_hdr(pg, p + 1);
			if (rc == TEST_OK)
				hdrseen = 1;
		} else if (!hdrseen) {
			fputs("Missing page header\n", stderr);
			rc = TEST_FAIL;
		} else
			rc = add_page_data(pg, p);
	}

	if (rc != TEST_OK)
		fprintf(stderr, "Error on line #%d\n", linenum);
	else if (hdrseen)
		rc = pg->write_page(pg);

	if (pg->buf)
		free(pg->buf);
	pg->buf = NULL;

	if (line)
		free(line);

	return rc;
}

int
process_data(struct page_data *pg, const char *fname)
{
	FILE *f;
	int rc;

	f = fopen(fname, "r");
	if (!f) {
		perror("Cannot open data source");
		return TEST_ERR;
	}

	rc = process_data_file(pg, f);
	if (fclose(f) != TEST_OK) {
		perror("Cannot close data source");
		rc = TEST_ERR;
	}

	return rc;
}
