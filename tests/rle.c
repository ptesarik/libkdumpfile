/* RLE encoding.
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

#include "testutil.h"

static inline int
rleop(unsigned char **pdst, size_t *pdstlen,
      unsigned char c, unsigned char rep)
{
	unsigned len = rep;
	if (c == 0)
		++len;
	if (len > 3)
		len = 3;
	if (*pdstlen < len)
		return -1;
	*pdstlen -= len;

	if (len > 2) {
		*(*pdst)++ = 0;
		*(*pdst)++ = rep;
	} else if (len > 1)
		*(*pdst)++ = c;
	*(*pdst)++ = c;

	return 0;
}

int
compress_rle(unsigned char *dst, size_t *pdstlen,
	     const unsigned char *src, size_t srclen)
{
	const unsigned char *srcend;
	unsigned char cur, prev, rep;
	size_t remain;

	if (!srclen) {
		*pdstlen = 0;
		return 0;
	}

	srcend = src + srclen;
	remain = *pdstlen;
	prev = *src++;
	rep = 1;
	while (src < srcend) {
		cur = *src++;

		if (cur != prev || rep == 0xff) {
			if (rleop(&dst, &remain, prev, rep))
				return -1;
			prev = cur;
			rep = 1;
		} else
			++rep;
	}

	if (rleop(&dst, &remain, prev, rep))
		return -1;

	*pdstlen -= remain;
	return 0;
}
