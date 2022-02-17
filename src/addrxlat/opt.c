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

/** Parse a single option.
 * @param popt   Parsed options.
 * @param opt    Option.
 * @returns      @c true if option was parsed, @c false if option is unknown.
 */
static bool
parse_opt(struct parsed_opts *popt, const addrxlat_opt_t *opt)
{
	switch (opt->idx) {
	case ADDRXLAT_OPT_levels:
		popt->levels = opt->val.num;
		break;

	case ADDRXLAT_OPT_pagesize:
		popt->pagesize = opt->val.num;
		break;

	case ADDRXLAT_OPT_phys_base:
		popt->phys_base = opt->val.addr;
		break;

	case ADDRXLAT_OPT_rootpgt:
		popt->rootpgt = opt->val.fulladdr;
		break;

	case ADDRXLAT_OPT_xen_p2m_mfn:
		popt->xen_p2m_mfn = opt->val.num;
		break;

	case ADDRXLAT_OPT_xen_xlat:
		popt->xen_xlat = opt->val.num;
		break;

	default:
		return false;
	}

	return true;
}

/** OS map option parser.
 * @param popt  Parsed options.
 * @param ctx   Translation context (for error handling).
 * @param optc  Number of options in @p opts.
 * @param opts  Options.
 * @returns     Error status.
 */
addrxlat_status
parse_opts(struct parsed_opts *popt, addrxlat_ctx_t *ctx,
	   unsigned optc, const addrxlat_opt_t *opts)
{
	addrxlat_optidx_t idx;

	for (idx = 0; idx < ADDRXLAT_OPT_NUM; ++idx)
		popt->isset[idx] = false;

	while (optc) {
		if (!parse_opt(popt, opts))
			return set_error(ctx, ADDRXLAT_ERR_NOTIMPL,
					 "Unknown option: %u",
					 (unsigned) opts->idx);
		popt->isset[opts->idx] = true;

		++opts;
		--optc;
	}

	return ADDRXLAT_OK;
}
