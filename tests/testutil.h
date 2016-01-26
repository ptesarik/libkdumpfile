/* Utility functions for unit tests.
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

#ifndef _TESTUTIL_H
#define _TESTUTIL_H 1

#include <stdio.h>
#include <stdint.h>

#define TEST_OK     0
#define TEST_FAIL   1
#define TEST_SKIP  77
#define TEST_ERR   99

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Endianity conversions */

typedef enum endian {
	data_le,		/**< Least significant byte first */
	data_be			/**< Most significant byte first */
} endian_t;

static inline uint16_t
htodump16(endian_t endian, uint16_t x)
{
	return endian != data_le
		? htobe16(x)
		: htole16(x);
}

static inline uint32_t
htodump32(endian_t endian, uint32_t x)
{
	return endian != data_le
		? htobe32(x)
		: htole32(x);
}

static inline uint64_t
htodump64(endian_t endian, uint64_t x)
{
	return endian != data_le
		? htobe64(x)
		: htole64(x);
}

/* Hex/oct */
static inline char
unhex(char digit)
{
	if (digit >= '0' && digit <= '9')
		return digit - '0';

	if (digit >= 'A' && digit <= 'F')
		return digit - 'A' + 10;

	if (digit >= 'a' && digit <= 'f')
		return digit - 'a' + 10;

	return -1;
}

static inline char
unoct(char digit)
{
	if (digit >= '0' && digit <= '7')
		return digit - '0';

	return -1;
}

/* Parameter files */

struct number_array {
	unsigned n;
	unsigned long long *val;
};

struct param {
	const char *key;
	enum {
		param_string,
		param_number,
		param_number_array,
	} type;
	union {
		char **string;
		unsigned long long *number;
		struct number_array *number_array;
	};
};

struct params {
	unsigned n;
	const struct param *params;
};

#define PARAM_STRING(key, val) \
	{ (key), param_string, { .string = &(val) } }
#define PARAM_NUMBER(key, val) \
	{ (key), param_number, { .number = &(val) } }
#define PARAM_NUMBER_ARRAY(key, val) \
	{ (key), param_number_array, { .number_array = &(val) } }

int parse_key_val(char *line, char **key, char **val);

int set_param(const struct param *p, const char *val);
int parse_params_file(const struct params *params, FILE *f);
int parse_params(const struct params *params, const char *fname);

/* Data files */

struct page_data;

typedef int data_parse_hdr_fn(struct page_data *pg, char *p);
typedef int data_write_page_fn(struct page_data *pg);

struct page_data {
	size_t alloc;		/**< Allocated bytes */
	size_t len;		/**< Current buffer length */
	unsigned char *buf;	/**< Page buffer */
	endian_t endian;	/**< Data endianity */

	void *priv;		/**< To be used by callbacks */

	data_parse_hdr_fn *parse_hdr;	/**< Parse header */
	data_write_page_fn *write_page; /**< Write full page */
};

int process_data(struct page_data *pg, const char *fname);
int process_data_file(struct page_data *pg, FILE *f);

#endif	/* testutil.h */
