/*
 * util.c
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <zlib.h>
#include <libkdumpfile/addrxlat.h>

#include "kdumpid.h"

#define MAX_KERNEL_SIZE	16*1024*1024

#define ALLOC_INC	1024

static void
chomp(char *banner)
{
	char *p = banner;
	while (*p && *p != '\n')
		++p;
	*p = 0;
}

static const char*
get_machine_arch(const char *machine)
{
	if (!strcmp(machine, "i386") ||
	    !strcmp(machine, "i586") ||
	    !strcmp(machine, "i686"))
		return "ia32";
	else if (!strcmp(machine, "arm64"))
		 return "aarch64";
	else if (!strncmp(machine, "arm", 3))
		return "arm";

	return machine;
}

static const char*
cfg2arch(const char *cfg)
{
	if (strstr(cfg, "CONFIG_X86_64=y"))
		return "x86_64";
	if (strstr(cfg, "CONFIG_X86_32=y"))
		return "ia32";
	if (strstr(cfg, "CONFIG_PPC64=y"))
		return "ppc64";
	if (strstr(cfg, "CONFIG_PPC32=y"))
		return "ppc";
	if (strstr(cfg, "CONFIG_IA64=y"))
		return "ia64";
	if (strstr(cfg, "CONFIG_S390=y"))
		return strstr(cfg, "CONFIG_64BIT=y")
			? "s390x"
			: "s390";
	if (strstr(cfg, "CONFIG_ALPHA=y"))
		return "alpha";
	if (strstr(cfg, "CONFIG_ARM=y"))
		return "arm";
	return NULL;
}

static int
arch_in_array(const char *arch, const char *const *arr)
{
	const char *const *p = arr;
	if (arch == NULL)
		return 1;
	while (*p) {
		if (!strcmp(arch, *p))
			return 1;
		++p;
	}
	return 0;
}

int
get_version_from_banner(struct dump_desc *dd)
{
	const char *p;
	char *q;

	if (!*dd->banner)
		return -1;

	p = dd->banner + sizeof("Linux version ") - 1;
	q = dd->ver;
	while (*p && *p != ' ')
		*q++ = *p++;
	*q = 0;
	return 0;
}

int
need_explore(struct dump_desc *dd)
{
	if (!dd->arch && dd->machine[0])
		dd->arch = get_machine_arch(dd->machine);

	if (!(dd->flags & DIF_VERBOSE) && dd->arch != NULL && dd->ver[0])
		return 0;
	return 1;
}

/* utsname strings are 65 characters long.
 * Final NUL may be missing (i.e. corrupted dump data)
 */
static void
copy_uts_string(char *dest, const char *src)
{
	if (!*dest) {
		memcpy(dest, src, 65);
		dest[65] = 0;
	}
}

static int
uts_looks_sane(struct new_utsname *uts)
{
	return uts->sysname[0] && uts->nodename[0] && uts->release[0] &&
		uts->version[0] && uts->machine[0];
}

int read_page(struct dump_desc *dd, unsigned long pfn)
{
	size_t rd = dd->page_size;
	return kdump_read(dd->ctx, KDUMP_KPHYSADDR, pfn * dd->page_size,
			  dd->page, &rd);
}

size_t
dump_cpin(struct dump_desc *dd, void *buf, uint64_t paddr, size_t len)
{
	size_t rd = len;
	kdump_read(dd->ctx, KDUMP_KPHYSADDR, paddr, buf, &rd);
	return len - rd;
}

int
uncompress_config(struct dump_desc *dd, void *zcfg, size_t zsize)
{
	z_stream stream;
	void *cfg;
	int ret;

	stream.next_in = zcfg;
	stream.avail_in = zsize;
	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;

	if (inflateInit2(&stream, 16+MAX_WBITS) != Z_OK)
		return -1;

	cfg = NULL;
	stream.avail_out = -1;
	stream.total_out = 0;
	do {
		void *newbuf = realloc(cfg, stream.total_out + 1024);
		if (!newbuf) {
			ret = Z_MEM_ERROR;
			break;
		}

		cfg = newbuf;
		stream.next_out = cfg + stream.total_out;
		stream.avail_out += ALLOC_INC;
	} while( (ret = inflate(&stream, Z_NO_FLUSH)) == Z_OK);

	inflateEnd(&stream);

	if (ret != Z_STREAM_END) {
		free(cfg);
		return -1;
	}

	*stream.next_out = 0;	/* terminating NUL */
	dd->cfg = cfg;
	dd->cfglen = stream.total_out;

	return 0;
}

typedef int (*explore_fn)(struct dump_desc *, uint64_t, uint64_t,
			  const char *const *);

static int
explore_ktext(struct dump_desc *dd, explore_fn fn,
	      const char *const *expected_archs)
{
	const addrxlat_range_t *range;
	const addrxlat_meth_t *meth;
	addrxlat_sys_t *xlatsys;
	addrxlat_addr_t addr;
	addrxlat_map_t *map;
	size_t n;
	int ret;

	if (kdump_get_addrxlat(dd->ctx, NULL, &xlatsys) != KDUMP_OK)
		return -1;

	ret = -1;
	meth = addrxlat_sys_get_meth(xlatsys, ADDRXLAT_SYS_METH_KTEXT);
	if (meth->kind != ADDRXLAT_LINEAR)
		goto out;
	addr = meth->param.linear.off;

	map = addrxlat_sys_get_map(xlatsys, ADDRXLAT_SYS_MAP_KV_PHYS);
	range = addrxlat_map_ranges(map);
	n = addrxlat_map_len(map);
	while (n) {
		if (range->meth == ADDRXLAT_SYS_METH_KTEXT &&
		    !fn(dd, addr, addr + range->endoff + 1, expected_archs)) {
			ret = 0;
			goto out;
		}
		addr += range->endoff + 1;
		++range;
		--n;
	}

 out:
	addrxlat_sys_decref(xlatsys);
	return ret;
}

static int
explore_kernel(struct dump_desc *dd, explore_fn fn)
{
	static const char *const all_archs[] = {
		"alpha", "arm", "ia64",
		"ppc", "ppc64",
		"s390", "s390x",
		"ia32", "x86_64",
		NULL
	};
	static const char *const x86_biarch[] = {
		"ia32", "x86_64", NULL
	};
	static const char *const zarch[] = {
		"s390", "s390x", NULL
	};
	static const char *const ppc[] = { "ppc", NULL };
	static const char *const ppc64[] = { "ppc64", NULL };

	uint64_t addr;

	if (dd->flags & DIF_FORCE)
		return fn(dd, 0, dd->max_pfn * dd->page_size, all_archs);

	if (dd->flags & DIF_START_FOUND)
		return fn(dd, dd->start_addr,
			  dd->start_addr + MAX_KERNEL_SIZE, all_archs);

	if (!explore_ktext(dd, fn, all_archs))
		return 0;

	if (arch_in_array(dd->arch, x86_biarch)) {
		/* Xen pv kernels are loaded low */
		addr = 0x2000;
		if (dd->xen_type != KDUMP_XEN_NONE &&
		    looks_like_kcode_x86(dd, addr) > 0 &&
		    !fn(dd, addr, addr + MAX_KERNEL_SIZE, x86_biarch)) {
			dd->start_addr = addr;
			dd->flags |= DIF_START_FOUND;
			return 0;
		}

		/* x86 kernels were traditionally loaded at 1M */
		addr = 1024*1024;
		if (looks_like_kcode_x86(dd, addr) > 0 &&
		    !fn(dd, addr, addr + MAX_KERNEL_SIZE, x86_biarch)) {
			dd->start_addr = addr;
			dd->flags |= DIF_START_FOUND;
			return 0;
		}

		/* other x86 kernels are loaded at 16M */
		addr = 16*1024*1024;
		if (looks_like_kcode_x86(dd, addr) > 0 &&
		    !fn(dd, addr, addr + MAX_KERNEL_SIZE, x86_biarch)) {
			dd->start_addr = addr;
			dd->flags |= DIF_START_FOUND;
			return 0;
		}

		/* some x86 kernels are loaded at 2M (due to align) */
		addr = 2*1024*1024;
		if (looks_like_kcode_x86(dd, addr) > 0 &&
		    !fn(dd, addr, addr + MAX_KERNEL_SIZE, x86_biarch)) {
			dd->start_addr = addr;
			dd->flags |= DIF_START_FOUND;
			return 0;
		}
	}

	if (arch_in_array(dd->arch, ppc64)) {
		/* PPC64 loads at 0 */
		addr = 0;
		if (looks_like_kcode_ppc64(dd, addr) > 0 &&
		    !fn(dd, addr, addr + MAX_KERNEL_SIZE, zarch)) {
			dd->start_addr = addr;
			dd->flags |= DIF_START_FOUND;
			return 0;
		}
	}

	if (arch_in_array(dd->arch, ppc)) {
		/* POWER also loads at 0 */
		addr = 0;
		if (looks_like_kcode_ppc(dd, addr) > 0 &&
		    !fn(dd, addr, addr + MAX_KERNEL_SIZE, zarch)) {
			dd->start_addr = addr;
			dd->flags |= DIF_START_FOUND;
			return 0;
		}
	}

	if (arch_in_array(dd->arch, zarch)) {
		/* Linux/390 loads at 0 */
		addr = 0;
		if (looks_like_kcode_s390(dd, addr) > 0 &&
		    !fn(dd, addr, addr + MAX_KERNEL_SIZE, zarch)) {
			dd->start_addr = addr;
			dd->flags |= DIF_START_FOUND;
			return 0;
		}
	}

	return -1;
}

static int
explore_banner(struct dump_desc *dd, uint64_t addr, uint64_t endaddr,
	       const char *const *expected_archs)
{
	static const unsigned char banhdr[] = "Linux version ";

	while ((addr = dump_search_range(dd, addr, endaddr,
					 banhdr, sizeof(banhdr) - 1)) != INVALID_ADDR) {
		char banner[256];
		size_t len;

		len = dump_cpin(dd, banner, addr, sizeof banner);
		addr += sizeof(banhdr) - 1;
		if (len == sizeof banner)
			continue;
		dd->banner[sizeof(dd->banner)-1] = 0;
		strncpy(dd->banner, banner, sizeof(dd->banner) - 1);
		chomp(dd->banner);
		return 0;
	}

	return -1;
}

static int
explore_utsname(struct dump_desc *dd, uint64_t addr, uint64_t endaddr,
		const char *const *expected_archs)
{
	static const unsigned char sysname[65] = "Linux";

	while ((addr = dump_search_range(dd, addr, endaddr,
					 sysname, sizeof sysname)) != INVALID_ADDR) {
		struct new_utsname uts;
		size_t len;
		const char *arch;

		len = dump_cpin(dd, &uts, addr, sizeof uts);
		addr += sizeof sysname;
		if (len)
			continue;

		if (!uts_looks_sane(&uts))
			continue;

		arch = get_machine_arch(uts.machine);
		if (arch && arch_in_array(arch, expected_archs)) {
			copy_uts_string(dd->machine, uts.machine);
			copy_uts_string(dd->ver, uts.release);
			dd->arch = (arch == uts.machine
				    ? dd->machine
				    : arch);
			return 0;
		}
	}

	return -1;
}

static uint64_t
search_ikcfg(struct dump_desc *dd, uint64_t startaddr, uint64_t endaddr)
{
	const unsigned char magic_start[8] = "IKCFG_ST";
	const unsigned char magic_end[8] = "IKCFG_ED";
	size_t cfgsize;
	char *cfg;

	startaddr = dump_search_range(dd, startaddr, endaddr,
				      magic_start, sizeof magic_start);
	if (startaddr == INVALID_ADDR)
		goto fail;
	startaddr += sizeof(magic_start);

	endaddr = dump_search_range(dd, startaddr, endaddr,
				    magic_end, sizeof magic_end);
	if (endaddr == INVALID_ADDR)
		goto fail;

	cfgsize = endaddr - startaddr;
	if (! (cfg = malloc(cfgsize)) ) {
		perror("Cannot allocate kernel config");
		goto fail;
	}
	if (dump_cpin(dd, cfg, startaddr, cfgsize))
		goto fail_free;

	if (uncompress_config(dd, cfg, cfgsize))
		goto fail_free;

	free(cfg);
	return endaddr;

 fail_free:
	free(cfg);
 fail:
	return INVALID_ADDR;
}

static int
explore_ikcfg(struct dump_desc *dd, uint64_t addr, uint64_t endaddr,
	      const char *const *expected_archs)
{
	while ((addr = search_ikcfg(dd, addr, endaddr)) != INVALID_ADDR) {
		const char *arch = cfg2arch(dd->cfg);
		if (arch && arch_in_array(arch, expected_archs)) {
			dd->arch = arch;
			return 0;
		}
	}

	return -1;
}

int
explore_raw_data(struct dump_desc *dd)
{
	addrxlat_sys_t *sys;
	addrxlat_map_t *map;
	kdump_status kstatus;
	int ret;

	if ( (dd->page = malloc(dd->page_size)) == NULL) {
		perror("Cannot allocate page data");
		return -1;
	}

	ret = -1;

	kstatus = kdump_get_addrxlat(dd->ctx, NULL, &sys);
	if (kstatus != KDUMP_OK) {
		fprintf(stderr, "Cannot get address translation: %s\n",
			kdump_get_err(dd->ctx));
		goto err_free;
	}

	map = addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS);
	if (!map) {
		addrxlat_range_t range;
		addrxlat_meth_t meth;
		addrxlat_status status;

		meth.kind = ADDRXLAT_LINEAR;
		meth.target_as = ADDRXLAT_MACHPHYSADDR;
		meth.param.linear.off = 0;
		addrxlat_sys_set_meth(sys, ADDRXLAT_SYS_METH_KPHYS_MACHPHYS,
				      &meth);

		map = addrxlat_map_new();
		if (!map) {
			perror("Cannot allocate identity map");
			goto err_xlat;
		}

		range.endoff = ADDRXLAT_ADDR_MAX;
		range.meth = ADDRXLAT_SYS_METH_KPHYS_MACHPHYS;
		status = addrxlat_map_set(map, 0, &range);
		if (status != ADDRXLAT_OK) {
			fprintf(stderr, "Cannot set identity range: %s\n",
				addrxlat_strerror(status));
			goto err_xlat;
		}
		addrxlat_sys_set_map(sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS, map);
	}

	ret &= explore_kernel(dd, explore_utsname);
	explore_kernel(dd, explore_ikcfg);
	ret &= explore_kernel(dd, explore_banner);

 err_xlat:
	addrxlat_sys_decref(sys);
 err_free:
	free(dd->page);

	return ret;
}
