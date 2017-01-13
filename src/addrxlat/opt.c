/** @internal @file src/addrxlat/opt.c
 * @brief Option parsing.
 */
/* Copyright (C) 2016 Petr Tesarik <ptesarik@suse.com>

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

#include <stdlib.h>
#include <string.h>

#include "addrxlat-priv.h"

/** Check if a character is a POSIX white space.
 * @param c  Character to check.
 *
 * We are not using @c isspace here, because the library function may
 * be called in a strange locale, and the parsing should not really
 * depend on locale and this function is less overhead then messing around
 * with the C library locale...
 */
static int
is_posix_space(int c)
{
	return (c == ' ' || c == '\f' || c == '\n' ||
		c == '\r' || c == '\t' || c == '\v');
}

/** Type of option. */
enum opttype {
	opt_string,		/**< Unparsed string option */
	opt_number,		/**< Signed number */
	opt_bool,		/**< Boolean value */
};

/** Option description. */
struct optdesc {
	enum optidx idx;	/**< Option index */
	enum opttype type;	/**< Type of option (string, number, ...) */
	const char name[];	/**< Option name */
};

/** Define an option without repeating its name. */
#define DEF(name, type)				\
	{ OPT_ ## name, opt_ ## type, #name }

/** Option table terminator. */
#define END					\
	{ OPT_NUM }

/** Three-character options. */
static const struct optdesc opt3[] = {
	DEF(pae, bool),
	END
};

/** Eight-character options. */
static const struct optdesc opt8[] = {
	DEF(pagesize, number),
	DEF(physbase, number),
	END
};

static const struct optdesc *const options[] = {
	[3] = opt3,
	[8] = opt8,
};

/** Parse a single option value.
 * @param popt   Parsed options.
 * @param ctx    Translation context (for error handling).
 * @param opt    Option descriptor.
 * @param val    Value.
 * @returns      Error status.
 */
static addrxlat_status
parse_val(struct parsed_opts *popt, addrxlat_ctx_t *ctx,
	  const struct optdesc *opt, const char *val)
{
	struct optval *optval = &popt->val[opt->idx];
	char *endp;

	switch (opt->type) {
	case opt_string:
		optval->str = val;
		goto ok;

	case opt_bool:
		if (!val ||
		    !strcasecmp(val, "yes") ||
		    !strcasecmp(val, "true")) {
			optval->num = 1;
			goto ok;
		} else if (!strcasecmp(val, "no") ||
			   !strcasecmp(val, "false")) {
			optval->num = 0;
			goto ok;
		}
		/* else fall-through */

	case opt_number:
		if (!val)
			return set_error(ctx, addrxlat_invalid,
					 "Missing value for option '%s'",
					 opt->name);

		optval->num = strtol(val, &endp, 0);
		if (*val && !*endp)
			goto ok;

		return set_error(ctx, addrxlat_invalid,
				 "Invalid value for option '%s': %s",
				 opt->name, val);
	}

	return set_error(ctx, addrxlat_notimpl,
			 "Unknown option type: %u", (unsigned) opt->type);

 ok:
	optval->set = 1;
	return addrxlat_ok;
}

/** Parse a single option.
 * @param popt   Parsed options.
 * @param ctx    Translation context (for error handling).
 * @param key    Option name.
 * @param klen   Name length.
 * @param val    Value.
 * @returns      Error status.
 */
static addrxlat_status
parse_opt(struct parsed_opts *popt, addrxlat_ctx_t *ctx,
	  const char *key, size_t klen, const char *val)
{
	const struct optdesc *opt;

	if (klen >= ARRAY_SIZE(options))
		goto err;

	opt = options[klen];
	if (!opt)
		goto err;

	while (opt->idx != OPT_NUM) {
		if (!strcasecmp(key, opt->name))
			return parse_val(popt, ctx, opt, val);
		opt = (void*)(opt + 1) + klen + 1;
	}

 err:
	return set_error(ctx, addrxlat_notimpl, "Unknown option: %s", key);
}

/** OS map option parser.
 * @param popt  Parsed options.
 * @param ctx   Translation context (for error handling).
 * @param opts  Option string.
 * @returns     Error status.
 */
addrxlat_status
parse_opts(struct parsed_opts *popt, addrxlat_ctx_t *ctx, const char *opts)
{
	enum optidx idx;
	const char *p;
	char *dst;
	addrxlat_status status;

	for (idx = 0; idx < OPT_NUM; ++idx)
		popt->val[idx].set = 0;

	if (!opts)
		return addrxlat_ok;

	popt->buf = realloc(NULL, strlen(opts) + 1);
	if (!popt->buf)
		return set_error(ctx, addrxlat_nomem,
				 "Cannot allocate options");

	p = opts;
	while (is_posix_space(*p))
		++p;

	dst = popt->buf;
	while (*p) {
		char quot, *key, *val;
		size_t keylen;

		key = dst;
		val = NULL;
		while (*p) {
			if (quot) {
				if (*p == quot)
					quot = 0;
				else
					*dst++ = *p;
			} else if (*p == '\'' || *p == '"')
				quot = *p;
			else if (is_posix_space(*p))
				break;
			else if (*p == '=') {
				*dst++ = '\0';
				val = dst;
			} else
				*dst++ = *p;
			++p;
		}
		if (quot) {
			status = set_error(ctx, addrxlat_invalid,
					   "Unterminated %s quotes",
					   quot == '"' ? "double" : "single");
			goto err;
		}

		*dst++ = '\0';

		keylen = (val ? val - key : dst - key) - 1;
		status = parse_opt(popt, ctx, key, keylen, val);
		if (status != addrxlat_ok)
			goto err;

		while (is_posix_space(*p))
			++p;
	}

	return addrxlat_ok;

 err:
	free(popt->buf);
	return status;
}
