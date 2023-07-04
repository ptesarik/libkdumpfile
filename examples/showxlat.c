#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <getopt.h>

#include <libkdumpfile/kdumpfile.h>
#include <libkdumpfile/addrxlat.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static void
print_target_as(const addrxlat_meth_t *meth)
{
	printf("  target_as=%s\n", addrxlat_addrspace_name(meth->target_as));
}

static void
print_fulladdr(const addrxlat_fulladdr_t *addr)
{
	fputs(addrxlat_addrspace_name(addr->as), stdout);
	if (addr->as != ADDRXLAT_NOADDR)
		printf(":0x%"ADDRXLAT_PRIxADDR, addr->addr);
}

static void
print_linear(const addrxlat_meth_t *meth)
{
	puts("LINEAR");
	print_target_as(meth);
	printf("  off=0x%"PRIxFAST64"\n",
	       (uint_fast64_t) meth->param.linear.off);
}

static void
print_pgt(const addrxlat_meth_t *meth)
{
	const addrxlat_paging_form_t *pf = &meth->param.pgt.pf;
	const char *pte_fmt;
	unsigned i;

	puts("PGT");
	print_target_as(meth);
	fputs("  root=", stdout);
	print_fulladdr(&meth->param.pgt.root);
	putchar('\n');
	fputs("  pte_format=", stdout);
	pte_fmt = addrxlat_pte_format_name(pf->pte_format);
	if (pte_fmt)
		printf("%s", pte_fmt);
	else
		printf("%u", pf->pte_format);
	printf("\n  fields=");
	for (i = 0; i < pf->nfields; ++i)
		printf("%s%u", i ? "," : "", pf->fieldsz[i]);
	putchar('\n');
}

static void
print_lookup(const addrxlat_meth_t *meth)
{
	const addrxlat_lookup_elem_t *p = meth->param.lookup.tbl;
	size_t n = meth->param.lookup.nelem;

	puts("LOOKUP");
	print_target_as(meth);
	printf("  endoff=0x%"ADDRXLAT_PRIxADDR"\n", meth->param.lookup.endoff);
	while (n--) {
		printf("  %"ADDRXLAT_PRIxADDR" -> %"ADDRXLAT_PRIxADDR"\n",
		       p->orig, p->dest);
		++p;
	}
}

static void
print_memarr(const addrxlat_meth_t *meth)
{
	puts("MEMARR");
	print_target_as(meth);
	fputs("  base=", stdout);
	print_fulladdr(&meth->param.memarr.base);
	putchar('\n');
	printf("  shift=%u\n", meth->param.memarr.shift);
	printf("  elemsz=%u\n", meth->param.memarr.elemsz);
	printf("  valsz=%u\n", meth->param.memarr.valsz);
}

#define DEF(id)	[ADDRXLAT_SYS_METH_ ## id] = #id
static const char *const meth_names[] = {
	DEF(PGT),
	DEF(UPGT),
	DEF(DIRECT),
	DEF(KTEXT),
	DEF(VMEMMAP),
	DEF(RDIRECT),
	DEF(MACHPHYS_KPHYS),
	DEF(KPHYS_MACHPHYS),
};
#undef DEF

static void
print_meth(const addrxlat_sys_t *sys, addrxlat_sys_meth_t methidx)
{
	const addrxlat_meth_t *meth = addrxlat_sys_get_meth(sys, methidx);

	if (meth->kind == ADDRXLAT_NOMETH)
		return;

	printf("METH_%s: ", meth_names[methidx]);

	switch (meth->kind) {
	case ADDRXLAT_NOMETH:
		break;

	case ADDRXLAT_CUSTOM:
		puts("CUSTOM");
		break;

	case ADDRXLAT_LINEAR:
		print_linear(meth);
		break;

	case ADDRXLAT_PGT:
		print_pgt(meth);
		break;

	case ADDRXLAT_LOOKUP:
		print_lookup(meth);
		break;

	case ADDRXLAT_MEMARR:
		print_memarr(meth);
		break;
	}

	putchar('\n');
}

static const char *
meth_name(addrxlat_sys_meth_t meth)
{
	return (meth >= 0 && meth < ARRAY_SIZE(meth_names))
		? meth_names[meth]
		: NULL;
}

static void
print_xlat(addrxlat_sys_meth_t meth)
{
	if (meth == ADDRXLAT_SYS_METH_NONE)
		puts("NONE");
	else {
		const char *name = meth_name(meth);
		if (!name)
			printf("<%ld>\n", (long)meth);
		else
			puts(name);
	}
}

static void
print_map(const addrxlat_sys_t *sys, addrxlat_sys_map_t mapidx)
{
	addrxlat_map_t *map;
	addrxlat_addr_t addr;
	const addrxlat_range_t *range;
	size_t i, n;

	map = addrxlat_sys_get_map(sys, mapidx);
	if (!map)
		return;

	n = addrxlat_map_len(map);
	addr = 0;
	range = addrxlat_map_ranges(map);
	for (i = 0; i < n; ++i) {
		printf("%"ADDRXLAT_PRIxADDR"-%"ADDRXLAT_PRIxADDR": ",
			addr, addr + range->endoff);
		print_xlat(range->meth);

		addr += range->endoff + 1;
		++range;
	}
}

static int
dump_addrxlat(kdump_ctx_t *ctx)
{
	addrxlat_sys_t *sys;
	kdump_status status;

	status = kdump_get_addrxlat(ctx, NULL, &sys);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get translation system: %s\n",
			kdump_get_err(ctx));
		return 1;
	}

	print_meth(sys, ADDRXLAT_SYS_METH_PGT);
	print_meth(sys, ADDRXLAT_SYS_METH_UPGT);
	print_meth(sys, ADDRXLAT_SYS_METH_DIRECT);
	print_meth(sys, ADDRXLAT_SYS_METH_KTEXT);
	print_meth(sys, ADDRXLAT_SYS_METH_VMEMMAP);
	print_meth(sys, ADDRXLAT_SYS_METH_RDIRECT);
	print_meth(sys, ADDRXLAT_SYS_METH_MACHPHYS_KPHYS);
	print_meth(sys, ADDRXLAT_SYS_METH_KPHYS_MACHPHYS);

	puts("MAP_HW:");
	print_map(sys, ADDRXLAT_SYS_MAP_HW);

	putchar('\n');

	puts("MAP_KV_PHYS:");
	print_map(sys, ADDRXLAT_SYS_MAP_KV_PHYS);

	putchar('\n');

	puts("MAP_KPHYS_DIRECT:");
	print_map(sys, ADDRXLAT_SYS_MAP_KPHYS_DIRECT);

	putchar('\n');

	puts("MAP_MACHPHYS_KPHYS:");
	print_map(sys, ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS);

	putchar('\n');

	puts("MAP_KPHYS_MACHPHYS:");
	print_map(sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS);

	addrxlat_sys_decref(sys);

	return 0;
}

static int
set_attr(kdump_ctx_t *ctx, const char *base, char *opt)
{
	kdump_attr_ref_t dirattr;
	kdump_attr_ref_t subattr;
	kdump_attr_t attr;
	char *val, *endp;

	val = strchr(opt, '=');
	if (!val) {
		fprintf(stderr, "%s missing value", opt);
		return 1;
	}
	*val++ = 0;

	if (kdump_attr_ref(ctx, base, &dirattr) != KDUMP_OK) {
		fprintf(stderr, "Cannot reference %s: %s\n",
			base, kdump_get_err(ctx));
		return 2;
	}

	if (kdump_sub_attr_ref(ctx, &dirattr, opt, &subattr) != KDUMP_OK) {
		fprintf(stderr, "Cannot reference %s.%s: %s\n",
			base, opt, kdump_get_err(ctx));
		return 2;
	}

	attr.type = kdump_attr_ref_type(&subattr);
	switch (attr.type) {
	case KDUMP_STRING:
		attr.val.string = val;
		break;

	case KDUMP_NUMBER:
		attr.val.number = strtoull(val, &endp, 0);
		if (*endp) {
			fprintf(stderr, "Invalid number: %s\n", val);
			return 1;
		}
		break;

	case KDUMP_ADDRESS:
		attr.val.address = strtoull(val, &endp, 0);
		if (*endp) {
			fprintf(stderr, "Invalid address: %s\n", val);
			return 1;
		}
		break;

	default:
		fprintf(stderr, "Unimplemented attribute type (%u)\n",
			(unsigned) attr.type);
		return 1;
	}

	if (kdump_attr_ref_set(ctx, &subattr, &attr) != KDUMP_OK) {
		fprintf(stderr, "Cannot set %s.%s: %s\n",
			base, opt, kdump_get_err(ctx));
		return 2;
	}

	kdump_attr_unref(ctx, &subattr);
	kdump_attr_unref(ctx, &dirattr);
	return 0;
}

static int
set_arch(kdump_ctx_t *ctx, const char *val)
{
	kdump_attr_t attr;

	attr.type = KDUMP_STRING;
	attr.val.string = val;
	if (kdump_set_attr(ctx, KDUMP_ATTR_ARCH_NAME, &attr) != KDUMP_OK) {
		fprintf(stderr, "Cannot set arch: %s\n",
			kdump_get_err(ctx));
		return 1;
	}

	return 0;
}

static int
set_ostype(kdump_ctx_t *ctx, const char *val)
{
	kdump_attr_t attr;

	attr.type = KDUMP_STRING;
	attr.val.string = val;
	if (kdump_set_attr(ctx, KDUMP_ATTR_OSTYPE, &attr) != KDUMP_OK) {
		fprintf(stderr, "Cannot set ostype: %s\n",
			kdump_get_err(ctx));
		return 1;
	}

	return 0;
}

static void
usage(FILE *out, const char *progname)
{
	fprintf(out, "Usage: %s [<options>] <dumpfile>\n\n", progname);
	fputs("Options:\n"
	      "  -h, --help\n\tShow this help\n"
	      "  -a, --arch val\n\tSet architecture\n"
	      "  -d, --default opt=val\n\tSet default addrxlat option\n"
	      "  -f, --force opt=val\n\tForce addrxlat option\n"
	      "  -o, --ostype val\n\tSet OS type\n",
	      out);
}

static const struct option opts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "arch", required_argument, NULL, 'a' },
	{ "default", required_argument, NULL, 'd' },
	{ "force", required_argument, NULL, 'f' },
	{ "ostype", required_argument, NULL, 'o' },
	{ },
};

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	int opt;
	int fd;
	kdump_status status;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot allocate kdump context");
		return -1;
	}

	while ((opt = getopt_long(argc, argv, "ha:d:f:o:",
				  opts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			if (set_arch(ctx, optarg))
				return 1;
			break;

		case 'd':
			if (set_attr(ctx, KDUMP_ATTR_XLAT_DEFAULT, optarg))
				return 1;
			break;

		case 'f':
			if (set_attr(ctx, KDUMP_ATTR_XLAT_FORCE, optarg))
				return 1;
			break;

		case 'o':
			if (set_ostype(ctx, optarg))
				return 1;
			break;

		case 'h':
			usage(stdout, argv[0]);
			return 0;

		case '?':
			usage(stderr, argv[0]);
			return 1;
		}
	}

	if (optind != argc - 1) {
		usage(stderr, argv[0]);
		return 1;
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror(argv[optind]);
		return 2;
	}

	status = kdump_open_fd(ctx, fd);
	if (status != KDUMP_OK) {
		fprintf(stderr, "File initialization failed: %s\n",
			kdump_get_err(ctx));
		kdump_free(ctx);
		return 2;
	}

	dump_addrxlat(ctx);

	kdump_free(ctx);
	close(fd);

	return 0;
}
