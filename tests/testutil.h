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

static inline uint16_t
htodump16(int bigendian, uint16_t x)
{
	return bigendian
		? htobe16(x)
		: htole16(x);
}

static inline uint32_t
htodump32(int bigendian, uint32_t x)
{
	return bigendian
		? htobe32(x)
		: htole32(x);
}

static inline uint64_t
htodump64(int bigendian, uint64_t x)
{
	return bigendian
		? htobe64(x)
		: htole64(x);
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

#endif	/* testutil.h */
