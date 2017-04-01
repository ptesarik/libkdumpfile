/* Generic operations on translated addresses.
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

#include <addrxlat.h>

#include "testutil.h"

struct test {
	addrxlat_fulladdr_t addr;
	addrxlat_fulladdr_t expect;
	unsigned long caps;
};

#define FULLADDR(_as, _addr)	{ .addr = (_addr), .as = ADDRXLAT_ ## _as }

#define NOMETH(_as) {				\
	FULLADDR(_as, 0x12345678),		\
	FULLADDR(NOADDR, 0)			\
}

#define IDENTITY(_as) {				\
	FULLADDR(_as, 0x12345678),		\
	FULLADDR(_as, 0x12345678),		\
	ADDRXLAT_CAPS(ADDRXLAT_ ## _as)		\
}

static struct test tests[] = {
	NOMETH(KVADDR),
	NOMETH(KPHYSADDR),
	NOMETH(MACHPHYSADDR),

	IDENTITY(KVADDR),
	IDENTITY(KPHYSADDR),
	IDENTITY(MACHPHYSADDR),

	/* Unambiguous simple translation */

	{ FULLADDR(KVADDR, 0x1000abcd),
	  FULLADDR(KPHYSADDR, 0xabcd),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR)
	},

	{ FULLADDR(KVADDR, 0x4000fedc),
	  FULLADDR(MACHPHYSADDR, 0x2000fedc),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	/* Test using second alternative (hw tables) */
	{ FULLADDR(KVADDR, 0x1800ba98),
	  FULLADDR(MACHPHYSADDR, 0x2800ba98),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(KPHYSADDR, 0x1234),
	  FULLADDR(KVADDR, 0x10001234),
	  ADDRXLAT_CAPS(ADDRXLAT_KVADDR)
	},

	{ FULLADDR(KPHYSADDR, 0x4321),
	  FULLADDR(MACHPHYSADDR, 0x20004321),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(MACHPHYSADDR, 0x2000fedc),
	  FULLADDR(KPHYSADDR, 0xfedc),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR)
	},

	/* Two-stage translation */

	{ FULLADDR(KVADDR, 0x10005678),
	  FULLADDR(MACHPHYSADDR, 0x20005678),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	/* Test using second alternative (hw tables) */
	{ FULLADDR(KVADDR, 0x18007654),
	  FULLADDR(KPHYSADDR, 0x8007654),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR)
	},

	{ FULLADDR(MACHPHYSADDR, 0x2000fedc),
	  FULLADDR(KVADDR, 0x1000fedc),
	  ADDRXLAT_CAPS(ADDRXLAT_KVADDR)
	},

	/* Out-of-range translations */

	{ FULLADDR(KVADDR, 0x1001000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR)
	},

	{ FULLADDR(KVADDR, 0x1001000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(KVADDR, 0x4001fedc),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(KVADDR, 0x1801000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(KVADDR, 0x1801000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR)
	},

	{ FULLADDR(KPHYSADDR, 0x10000000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_KVADDR)
	},

	{ FULLADDR(KPHYSADDR, 0x10000000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(MACHPHYSADDR, 0x10000000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR)
	},

	{ FULLADDR(MACHPHYSADDR, 0x10000000),
	  FULLADDR(NOADDR, 0),
	  ADDRXLAT_CAPS(ADDRXLAT_KVADDR)
	},

	/* Alternatives */

	{ FULLADDR(KVADDR, 0x10005678),
	  FULLADDR(KPHYSADDR, 0x5678),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR) |
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(KVADDR, 0x40002345),
	  FULLADDR(MACHPHYSADDR, 0x20002345),
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR) |
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(KPHYSADDR, 0x6543),
	  FULLADDR(MACHPHYSADDR, 0x20006543),
	  ADDRXLAT_CAPS(ADDRXLAT_KVADDR) |
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},

	{ FULLADDR(MACHPHYSADDR, 0x2000dcba),
	  FULLADDR(KPHYSADDR, 0xdcba),
	  ADDRXLAT_CAPS(ADDRXLAT_KVADDR) |
	  ADDRXLAT_CAPS(ADDRXLAT_KPHYSADDR)
	},
};

/* In the absence of a kphys->machphys mapping, the algorithm should
 * fall back to virtual addresses.
 */
static struct test test_nomach[] = {
	{ FULLADDR(KPHYSADDR, 0x8765),
	  FULLADDR(KVADDR, 0x10008765),
	  ADDRXLAT_CAPS(ADDRXLAT_KVADDR) |
	  ADDRXLAT_CAPS(ADDRXLAT_MACHPHYSADDR)
	},
};

static void
print_addrspace(addrxlat_addrspace_t as)
{
	switch (as) {
	case ADDRXLAT_KPHYSADDR:
		fputs("KPHYSADDR", stdout);
		break;

	case ADDRXLAT_MACHPHYSADDR:
		fputs("MACHPHYSADDR", stdout);
		break;

	case ADDRXLAT_KVADDR:
		fputs("KVADDR", stdout);
		break;

	case ADDRXLAT_NOADDR:
		fputs("NOADDR", stdout);
		break;

	default:
		printf("<addrspace %ld>", (long) as);
	}
}

static void
print_fulladdr(const addrxlat_fulladdr_t *addr)
{
	print_addrspace(addr->as);
	if (addr->as != ADDRXLAT_NOADDR)
		printf(":0x%"ADDRXLAT_PRIxADDR, addr->addr);
}

static addrxlat_status
testop(void *data, const addrxlat_fulladdr_t *addr)
{
	const addrxlat_fulladdr_t *expect = data;

	fputs(" actual ", stdout);
	print_fulladdr(addr);

	return addr->as == expect->as && addr->addr == expect->addr
		? addrxlat_ok
		: addrxlat_custom_status_base;
}

static int
test_one(addrxlat_op_ctl_t *ctl, const struct test *test)
{
	addrxlat_fulladdr_t addr;
	addrxlat_status status;

	print_fulladdr(&test->addr);
	fputs(" expect ", stdout);
	if (test->expect.as == ADDRXLAT_NOADDR)
		fputs("addrxlat_nometh", stdout);
	else
		print_fulladdr(&test->expect);

	ctl->data = (void*)&test->expect;
	ctl->caps = test->caps;
	addr = test->addr;
	status = addrxlat_op(ctl, &addr);
	if (test->expect.as == ADDRXLAT_NOADDR) {
		if (status == addrxlat_nometh) {
			printf(": OK (%s)\n", addrxlat_ctx_get_err(ctl->ctx));
			return TEST_OK;
		}
		if (status == addrxlat_ok ||
		    status == addrxlat_custom_status_base) {
			puts(": FAIL");
			return TEST_FAIL;
		}
	} else {
		if (status == addrxlat_ok) {
			puts(": OK");
			return TEST_OK;
		}
		if (status == addrxlat_custom_status_base) {
			puts(": FAIL");
			return TEST_FAIL;
		}
	}
	puts(": ERR");

	fprintf(stderr, "addrxlat_op failed: %s\n",
		addrxlat_ctx_get_err(ctl->ctx));
	return TEST_ERR;
}

static int
unmap(addrxlat_ctx_t *ctx, addrxlat_sys_t *sys,
      addrxlat_sys_map_t mapidx, addrxlat_addr_t addr,
      addrxlat_addr_t endoff)
{
	addrxlat_range_t range;
	addrxlat_map_t *map;
	addrxlat_status status;

	map = addrxlat_sys_get_map(sys, mapidx);
	range.endoff = endoff;
	range.meth = NULL;
	status = addrxlat_map_set(map, addr, &range);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Cannot allocate virt-to-phys map: %s\n",
			addrxlat_strerror(status));
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
make_linear_map(addrxlat_ctx_t *ctx, addrxlat_sys_t *sys,
		addrxlat_sys_map_t mapidx, addrxlat_addr_t addr,
		addrxlat_addr_t endoff, addrxlat_addrspace_t target_as,
		addrxlat_off_t off)
{
	addrxlat_range_t range;
	addrxlat_map_t *map;
	addrxlat_def_t def;
	addrxlat_status status;

	range.meth = addrxlat_meth_new();
	if (!range.meth) {
		fputs("Cannot allocate translation map", stderr);
		return TEST_ERR;
	}
	def.kind = ADDRXLAT_LINEAR;
	def.target_as = target_as;
	def.param.linear.off = off;
	status = addrxlat_meth_set_def(range.meth, &def);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Cannot set up translation map: %s",
			addrxlat_strerror(status));
	}

	map = addrxlat_sys_get_map(sys, mapidx);
	if (!map) {
		map = addrxlat_map_new();
		if (!map) {
			perror("Cannot allocate virt-to-phys map");
			return TEST_ERR;
		}
		addrxlat_sys_set_map(sys, mapidx, map);
	}
	range.endoff = endoff;
	status = addrxlat_map_set(map, addr, &range);
	if (status != addrxlat_ok) {
		fprintf(stderr, "Cannot update virt-to-phys map: %s\n",
			addrxlat_strerror(status));
		return TEST_ERR;
	}

	return TEST_OK;
}

static int
setup_linear_maps(addrxlat_ctx_t *ctx, addrxlat_sys_t *sys)
{
	int res;

	/* Set direct map at 0x10000000-0x1000ffff. */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_KV_PHYS,
			      0x10000000, 0xffff,
			      ADDRXLAT_KPHYSADDR, -0x10000000);
	if (res != TEST_OK)
		return res;

	/* Set reverse direct map at 0-0xffff. */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_KPHYS_DIRECT,
			      0, 0xffff,
			      ADDRXLAT_KVADDR, 0x10000000);
	if (res != TEST_OK)
		return res;

	/* Direct virt-to-mach at 0x40000000-0x4000ffff */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_KV_PHYS,
			      0x40000000, 0xffff,
			      ADDRXLAT_MACHPHYSADDR, -0x40000000 + 0x20000000);
	if (res != TEST_OK)
		return res;

	/* Set kphys->machphys 0-0xfffffff. */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS,
			      0, 0xfffffff,
			      ADDRXLAT_MACHPHYSADDR, 0x20000000);
	if (res != TEST_OK)
		return res;

	/* Bogus kphys->machphys 0x20000000-0x2fffffff (trap!). */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS,
			      0x20000000, 0xfffffff,
			      ADDRXLAT_MACHPHYSADDR, 0xbadbadbad);
	if (res != TEST_OK)
		return res;

	/* Set kphys->machphys 0x20000000-0x2fffffff. */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS,
			      0x20000000, 0xfffffff,
			      ADDRXLAT_KPHYSADDR, -0x20000000);
	if (res != TEST_OK)
		return res;

	/* Bogus kphys->machphys 0-0x2fffffff (trap!). */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS,
			      0, 0xfffffff,
			      ADDRXLAT_KPHYSADDR, 0xbadbadbad);
	if (res != TEST_OK)
		return res;

	/* Distinct hw map at 0x18000000-0x1800ffff. */
	res = make_linear_map(ctx, sys, ADDRXLAT_SYS_MAP_HW,
			      0x18000000, 0xffff,
			      ADDRXLAT_MACHPHYSADDR, -0x10000000 + 0x20000000);
	if (res != TEST_OK)
		return res;

	return TEST_OK;
}

int
main(int argc, char **argv)
{
	addrxlat_ctx_t *ctx;
	addrxlat_sys_t *sys;
	addrxlat_op_ctl_t ctl;
	int i;
	int tmp, ret;

	ctx = addrxlat_ctx_new();
	if (!ctx) {
		fputs("Cannot allocate translation context", stderr);
		return TEST_ERR;
	}

	sys = addrxlat_sys_new();
	if (!sys) {
		fputs("Cannot allocate translation system", stderr);
		return TEST_ERR;
	}

	ret = setup_linear_maps(ctx, sys);
	if (ret != TEST_OK)
		return ret;

	ctl.ctx = ctx;
	ctl.sys = sys;
	ctl.op = testop;

	ret = TEST_OK;
	for (i = 0; i < ARRAY_SIZE(tests); ++i) {
		tmp = test_one(&ctl, &tests[i]);
		if (tmp > ret)
			ret = tmp;
	}

	/* Remove kphys->machphys 0-0xffff. */
	tmp = unmap(ctx, sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS,
		    0, 0xffff);
	if (tmp > ret)
		ret = tmp;

	for (i = 0; i < ARRAY_SIZE(test_nomach); ++i) {
		tmp = test_one(&ctl, &test_nomach[i]);
		if (tmp > ret)
			ret = tmp;
	}

	addrxlat_sys_decref(sys);
	addrxlat_ctx_decref(ctx);

	return ret;
}
