/* XDG-style config file parsing.
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

#define ARRAY_SEPARATORS  " \t"

static char
unescape_hex(const char **pp)
{
	char n, ret;

	ret = unhex(**pp);
	if (ret < 0) {
		*pp = NULL;
		return '\0';
	}
	++(*pp);

	n = unhex(**pp);
	if (n >= 0) {
		ret <<= 4;
		ret |= n;
		++(*pp);
	}

	return ret;
}

static char
unescape_oct(const char **pp)
{
	char n, ret;

	ret = unoct(**pp);
	++(*pp);
	n = unoct(**pp);
	if (n >= 0) {
		ret <<= 3;
		ret |= n;
		++(*pp);

		n = unoct(**pp);
		if (n >= 0) {
			ret <<= 3;
			ret |= n;
			++(*pp);
		}
	}

	return ret;
}

static char
unescape(const char **pp)
{
	char ret;

	++(*pp);
	ret = **pp;

	switch (ret) {
	case 'a': ret = '\a'; break;
	case 'b': ret = '\b'; break;
	case 'f': ret = '\f'; break;
	case 'n': ret = '\n'; break;
	case 'r': ret = '\r'; break;
	case 's': ret = ' '; break; /* XDG-style */
	case 't': ret = '\t'; break;
	case 'v': ret = '\v'; break;
	case 'x':
		++(*pp);
		return unescape_hex(pp);

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		return unescape_oct(pp);

	case '\0':
		return ret;
	}

	++(*pp);
	return ret;
}

static int
set_param_string(const struct param *param, const char *val)
{
	const char *p;
	char *str, *q;

	str = malloc(strlen(val) + 1);
	if (!str) {
		perror("Allocate string param");
		return TEST_ERR;
	}

	p = val;
	q = str;
	while (*p)
		if (*p == '\\')
			*q++ = unescape(&p);
		else
			*q++ = *p++;
	*q = '\0';

	if (!str) {
		fprintf(stderr, "Invalid string: %s\n", val);
		return TEST_FAIL;
	}

	if (*param->string)
		free(*param->string);
	*param->string = str;
	return TEST_OK;
}

static int
set_param_yesno(const struct param *param, const char *val)
{
	if (!strcasecmp(val, "yes") ||
	    !strcasecmp(val, "true")) {
		*param->yesno = true;
	} else if (!strcasecmp(val, "no") ||
		   !strcasecmp(val, "false")) {
		*param->yesno = false;
	} else {
		unsigned long long num;
		char *endp;

		num = strtoull(val, &endp, 0);
		if (!*val || *endp) {
			fprintf(stderr, "Invalid yes/no value: %s\n", val);
			return TEST_FAIL;
		}
		*param->yesno = !!num;
	}

	return TEST_OK;
}

static int
set_param_number(const struct param *param, const char *val)
{
	unsigned long long num;
	char *endp;

	num = strtoull(val, &endp, 0);
	if (!*val || *endp) {
		fprintf(stderr, "Invalid number: %s\n", val);
		return TEST_FAIL;
	}

	*param->number = num;
	return TEST_OK;
}

static int
set_param_number_array(const struct param *param, const char *val)
{
	unsigned long long *arr, *valp;
	unsigned i, n;
	const char *p;
	char *endp;

	n = 1;
	p = val;
	while ( (p = strpbrk(p, ARRAY_SEPARATORS)) != NULL) {
		while (strchr(ARRAY_SEPARATORS, *p))
			++p;
		++n;
	}

	arr = malloc(n * sizeof(unsigned long long));
	if (!arr) {
		perror("Array allocation failed");
		return TEST_ERR;
	}

	p = val;
	valp = arr;
	for (i = 0; i < n; ++i) {
		*valp++ = strtoull(p, &endp, 0);
		p = strpbrk(p, ARRAY_SEPARATORS) ?: p + strlen(p);
		if (endp != p) {
			fprintf(stderr, "Invalid number array: %s\n", val);
			free(arr);
			return TEST_FAIL;
		}

		while (strchr(ARRAY_SEPARATORS, *p))
			++p;
	}

	if (param->number_array->val)
		free(param->number_array->val);
	param->number_array->n = n;
	param->number_array->val = arr;
	return TEST_OK;
}

static int
set_param_blob(const struct param *param, const char *val)
{
	struct blob *blob;
	unsigned i, n;
	const char *p;
	unsigned char *valp;

	p = strpbrk(val, ARRAY_SEPARATORS);
	n = p ? p - val : strlen(val);
	if (n % 2 != 0) {
		fputs("Blob hex string has odd length!\n", stderr);
		return TEST_FAIL;
	}
	n /= 2;

	blob = malloc(sizeof(struct blob) + n);
	if (!blob) {
		perror("Blob allocation failed");
		return TEST_ERR;
	}
	blob->length = n;

	p = val;
	valp = blob->data;
	for (i = 0; i < n; ++i) {
		int isok = 0;

		if (isxdigit(*p)) {
			*valp = unhex(*p++) << 4;
			if (isxdigit(*p)) {
				*valp |= unhex(*p++);
				isok = 1;
			}
		}
		if (!isok) {
			fprintf(stderr, "Invalid hex digit at %zu: '%c'\n",
				p - val, *p);
			free(blob);
			return TEST_FAIL;
		}
		++valp;
	}

	if (*param->blob)
		free(*param->blob);
	*param->blob = blob;
	return TEST_OK;
}

static int
set_param_fulladdr(const struct param *param, const char *val)
{
	const char *p = val;
	const char *q;
	char *endp;

	if (isdigit(*p)) {
		param->fulladdr->as = strtoul(p, &endp, 0);
		if (!*p || *endp)
			goto err;
		p = endp;
	} else {
		q = p;
		while (isalnum(*q))
			++q;

		switch (q - p) {
		case 6:
			if (!strncasecmp(p, "KVADDR", 6))
				param->fulladdr->as = ADDRXLAT_KVADDR;
			else
				goto err;
			break;

		case 9:
			if (!strncasecmp(p, "KPHYSADDR", 9))
				param->fulladdr->as = ADDRXLAT_KPHYSADDR;
			else
				goto err;
			break;

		case 12:
			if (!strncasecmp(p, "MACHPHYSADDR", 12))
				param->fulladdr->as = ADDRXLAT_MACHPHYSADDR;
			else
				goto err;
			break;

		default:
			goto err;
		}
		p = q;
	}

	if (*p != ':')
		goto err;
	++p;

	param->fulladdr->addr = strtoull(p, &endp, 0);
	if (!*p || *endp)
		goto err;

	return TEST_OK;

 err:
	fprintf(stderr, "Invalid full address: %s\n", val);
	return TEST_FAIL;
}

int
set_param(const struct param *p, const char *val)
{
	switch (p->type) {
	case param_string:
		return set_param_string(p, val);

	case param_yesno:
		return set_param_yesno(p, val);

	case param_number:
		return set_param_number(p, val);

	case param_number_array:
		return set_param_number_array(p, val);

	case param_blob:
		return set_param_blob(p, val);

	case param_fulladdr:
		return set_param_fulladdr(p, val);
	}

	fprintf(stderr, "INTERNAL ERROR: Invalid param type: %d\n",
		(int) p->type);
	return TEST_FAIL;
}

static int
set_param_key(const struct params *params,
	      const char *key, const char *val)
{
	unsigned i;

	for (i = 0; i < params->n; ++i) {
		const struct param *p = params->params + i;
		if (!strcmp(key, p->key))
			return set_param(p, val);
	}

	fprintf(stderr, "Unknown key: %s\n", key);
	return TEST_FAIL;
}

int
parse_key_val(char *line, char **key, char **val)
{
	char *p, *eq;

	p = line;
	while (*p && isspace(*p))
		++p;
	*key = p;

	p += strlen(p) - 1;
	while (p > *key && isspace(*p))
		*p-- = '\0';

	if (p < *key) {
		*key = *val = NULL;
		return 0;
	}

	eq = strchr(*key, '=');
	if (!eq)
		return -1;
	*eq = '\0';

	p = eq - 1;
	while (p > line && isspace(*p))
		*p-- = '\0';

	p = eq + 1;
	while (*p && isspace(*p))
		++p;
	*val = p;

	return 0;
}

int
parse_params_file(const struct params *params, FILE *f)
{
	char *line, *logline, *key, *val;
	size_t linesz, loglinesz;
	unsigned linenum;
	int rc = TEST_OK;

	line = logline = NULL;
	linesz = loglinesz = 0;
	linenum = 0;

	while (getline(&line, &linesz, f) > 0) {
		++linenum;

		/* Handle continuation lines */
		if (logline) {
			char *p;
			size_t len = strlen(line);

			logline = realloc(logline, loglinesz + len);
			memcpy(logline + loglinesz, line, len);
			loglinesz += len;
			p = logline + loglinesz;
			if (*p == '\n')
				--p, --loglinesz;
			if (*p == '\r')
				--p, --loglinesz;
			if (*p == '\\') {
				--p, --loglinesz;
				continue;
			}
			free(line);
			line = logline;
			linesz = loglinesz;
			logline = NULL;
		}

		if (parse_key_val(line, &key, &val)) {
			fprintf(stderr, "Malformed param: %s\n", line);
			rc = TEST_FAIL;
			break;
		}

		if (!key)
			continue;

		rc = set_param_key(params, key, val);
		if (rc != TEST_OK) {
			fprintf(stderr, "Error on line #%d\n", linenum);
			break;
		}
	}

	if (line)
		free(line);

	return rc;
}

int
parse_params(const struct params *params, const char *fname)
{
	FILE *f;
	int rc;

	f = fopen(fname, "r");
	if (!f) {
		perror("open params");
		return TEST_ERR;
	}

	rc = parse_params_file(params, f);

	if (fclose(f) != 0) {
		perror("close params");
		rc = TEST_ERR;
	}

	return rc;
}
