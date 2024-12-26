/*
 * search.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "kdumpid.h"

static void
compute_badchar(ssize_t *badchar, const unsigned char *s, ssize_t len)
{
	size_t i = 1;
	while (i < len)
		badchar[*s++] = i++;
}

static void
compute_sfx(ssize_t *sfx, const unsigned char *s, ssize_t len)
{
	ssize_t f, g, i;

	sfx[len - 1] = len;
	f = 0;			/* bogus assignment to silence a warning */
	g = len - 1;
	for (i = len - 2; i >= 0; --i) {
		if (i > g && sfx[i + len - 1 - f] < i - g)
			sfx[i] = sfx[i + len - 1 - f];
		else {
			if (i < g)
				g = i;
			f = i;
			while (g >= 0 && s[g] == s[g + len - 1 - f])
				--g;
			sfx[i] = f - g;
		}
	}
}

static void
compute_goodsfx(ssize_t *goodsfx, const unsigned char *s, ssize_t len)
{
	ssize_t i, j, *sfx = goodsfx + len;

	compute_sfx(sfx, s, len);

	for (i = 0; i < len; ++i)
		goodsfx[i] = len;
	j = 0;
	for (i = len - 1; i >= 0; --i)
		if (sfx[i] == i + 1)
			for (; j < len - 1 - i; ++j)
				if (goodsfx[j] == len)
					goodsfx[j] = len - 1 - i;
	for (i = 0; i <= len - 2; ++i)
		goodsfx[len - 1 - sfx[i]] = len - 1 - i;
}

/* A helper function for doing cpin forwards or backwards inside the
 * find_bytestr() inner loop
 */
static inline void*
search_cpin(struct dump_desc *dd, void *buf, uint64_t addr, size_t len)
{
	if (!dump_cpin(dd, buf, addr, len))
		return buf;
	else if (dd->flags & DIF_FORCE) {
		memset(buf, 0, len);
		return buf;
	} else
		return NULL;
}

/* Search for a constant byte string using the Boyer-Moore algorithm.
 */
static inline unsigned char*
search_buf(unsigned char *buf, size_t buflen,
	   const unsigned char *needle, size_t maxidx,
	   ssize_t *badchar, ssize_t *goodsfx)
{
	if (!maxidx)
		return memchr(buf, *needle, buflen);

	while (buflen > maxidx) {
		unsigned char *p;
		ssize_t shift, i;

		for (p = buf + maxidx, i = maxidx; i >= 0; --p, --i)
			if (needle[i] != *p)
				break;

		if (i < 0)
			return buf;

		shift = i + 1 - badchar[*p];
		if (shift < goodsfx[i])
			shift = goodsfx[i];

		buf += shift;
		buflen -= shift;
	}
	return NULL;
}

/* Search for a constant byte string using the Boyer-Moore algorithm. */
uint64_t
dump_search_range(struct dump_desc *dd,
		  uint64_t start, uint64_t end,
		  const unsigned char *needle, size_t len)
{
	void *dynalloc;
	ssize_t *badchar, *goodsfx;
	unsigned char *readbuf;

	if (len > 1) {
		dynalloc = calloc(sizeof(ssize_t) * (256 + 2*len)
				  + 2*(len-1), 1);
		if (!dynalloc)
			return INVALID_ADDR;
		badchar = dynalloc;
		goodsfx = badchar + 256;
		readbuf = dynalloc + sizeof(ssize_t) * (256 + 2*len);

		compute_badchar(badchar, needle, len);
		compute_goodsfx(goodsfx, needle, len);
	} else {
		dynalloc = NULL;
		badchar = goodsfx = NULL;
		readbuf = NULL;
	}

	--len;			/* simplify offset computing */

	while (start < end) {
		off_t remain;
		unsigned char *p, *q;

		remain = dd->page_size - (start & (dd->page_size - 1));
		if (remain > end - start)
			remain = end - start;

		if (remain > len) {
			if (read_page(dd, start / dd->page_size)) {
				if (! (dd->flags & DIF_FORCE))
					break;
				memset(dd->page, 0, dd->page_size);
			}
			p = dd->page + (start & (dd->page_size - 1));
		} else {
			remain += len;
			p = search_cpin(dd, readbuf, start, remain);
			if (!p)
				break;
		}
		start += remain;

		q = search_buf(p, remain, needle, len,
			       badchar, goodsfx);
		if (q) {
			if (dynalloc)
				free(dynalloc);
			return start + q - p - remain;
		}

		start -= len;
	}

	if (dynalloc)
		free(dynalloc);
	return INVALID_ADDR;
}
