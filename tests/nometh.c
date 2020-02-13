/* Translations that should produce ADDRXLAT_ERR_NOMETH errors
   Copyright (C) 2017 Petr Tesarik <ptesarik@suse.com>

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

#define _GNU_SOURCE

#include <stdio.h>

#include <libkdumpfile/addrxlat.h>

#include "testutil.h"

static int
setup_pgt(addrxlat_ctx_t *ctx, addrxlat_sys_t *sys)
{
	addrxlat_range_t range;
	addrxlat_map_t *map;
	addrxlat_meth_t meth;
	addrxlat_status status;

	meth.kind = ADDRXLAT_PGT;
	meth.target_as = ADDRXLAT_MACHPHYSADDR;
	meth.param.pgt.root.addr = 0xf000;
	meth.param.pgt.root.as = ADDRXLAT_KVADDR;
	meth.param.pgt.pf.pte_format = ADDRXLAT_PTE_PFN64;
	meth.param.pgt.pf.nfields = 2;
	meth.param.pgt.pf.fieldsz[0] = 12;
	meth.param.pgt.pf.fieldsz[1] = 9;
	addrxlat_sys_set_meth(sys, ADDRXLAT_SYS_METH_PGT, &meth);

	range.endoff = 0xffffffff;
	range.meth = ADDRXLAT_SYS_METH_PGT;
	map = addrxlat_map_new();
	if (!map) {
		perror("Cannot allocate translation map");
		return TEST_ERR;
	}
	status = addrxlat_map_set(map, 0, &range);
	if (status != ADDRXLAT_OK) {
		fprintf(stderr, "Cannot add translation map range: %s\n",
			addrxlat_strerror(status));
		return TEST_ERR;
	}
	addrxlat_sys_set_map(sys, ADDRXLAT_SYS_MAP_KV_PHYS, map);

	return TEST_OK;
}

static addrxlat_status
mygetpage(void *data, addrxlat_buffer_t *buf)
{
	fputs("read callback called?!\n", stderr);
	return ADDRXLAT_OK;
}

static addrxlat_status
nullop(void *data, const addrxlat_fulladdr_t *paddr)
{
	return ADDRXLAT_OK;
}

int
main(int argc, char **argv)
{
	static addrxlat_cb_t cb = {
		.get_page = mygetpage,
		.read_caps = ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	};

	addrxlat_ctx_t *ctx;
	addrxlat_sys_t *sys;
	addrxlat_fulladdr_t faddr;
	addrxlat_op_ctl_t opctl;
	addrxlat_status status;
	int ret;

	ctx = addrxlat_ctx_new();
	if (!ctx) {
		fputs("Cannot allocate translation context", stderr);
		return TEST_ERR;
	}

	addrxlat_ctx_set_cb(ctx, &cb);

	sys = addrxlat_sys_new();
	if (!sys) {
		fputs("Cannot allocate translation system", stderr);
		return TEST_ERR;
	}

	ret = setup_pgt(ctx, sys);
	if (ret != TEST_OK)
		return ret;

	faddr.addr = 0x123456;
	faddr.as = ADDRXLAT_KVADDR;

	opctl.ctx = ctx;
	opctl.sys = sys;
	opctl.op = nullop;
	opctl.data = &faddr;
	opctl.caps = ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR);

	fputs("Infinite recursion: ", stdout);
	status = addrxlat_op(&opctl, &faddr);
	if (status == ADDRXLAT_OK) {
		puts("FAIL");
		fputs("Unexpected success??\n", stderr);
		ret = TEST_FAIL;
	} else if (status != ADDRXLAT_ERR_NOMETH) {
		puts("ERR");
		fprintf(stderr, "Cannot translate: %s\n",
			addrxlat_ctx_get_err(ctx));
		ret = TEST_ERR;
	} else
		printf("OK (%s)\n", addrxlat_ctx_get_err(ctx));

	fputs("Callback with no capabilities: ", stdout);
	cb.read_caps = 0;
	addrxlat_ctx_set_cb(ctx, &cb);
	status = addrxlat_op(&opctl, &faddr);
	if (status == ADDRXLAT_OK) {
		puts("FAIL");
		fputs("Unexpected success??\n", stderr);
		ret = TEST_FAIL;
	} else if (status != ADDRXLAT_ERR_NOMETH) {
		puts("ERR");
		fprintf(stderr, "Cannot translate: %s\n",
			addrxlat_ctx_get_err(ctx));
		ret = TEST_ERR;
	} else
		printf("OK (%s)\n", addrxlat_ctx_get_err(ctx));

	fputs("Missing callback: ", stdout);
	cb.get_page = NULL;
	addrxlat_ctx_set_cb(ctx, &cb);
	status = addrxlat_op(&opctl, &faddr);
	if (status == ADDRXLAT_OK) {
		puts("FAIL");
		fputs("Unexpected success??\n", stderr);
		ret = TEST_FAIL;
	} else if (status != ADDRXLAT_ERR_NOMETH) {
		puts("ERR");
		fprintf(stderr, "Cannot translate: %s\n",
			addrxlat_ctx_get_err(ctx));
		ret = TEST_ERR;
	} else
		printf("OK (%s)\n", addrxlat_ctx_get_err(ctx));

	addrxlat_sys_decref(sys);
	addrxlat_ctx_decref(ctx);

	return ret;
}
