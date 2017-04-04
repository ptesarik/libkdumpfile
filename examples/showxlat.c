#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>

#include <kdumpfile.h>
#include <addrxlat.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

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
print_target_as(const addrxlat_desc_t *desc)
{
	fputs("  target_as=", stdout);
	print_addrspace(desc->target_as);
	putchar('\n');
}

static void
print_fulladdr(const addrxlat_fulladdr_t *addr)
{
	print_addrspace(addr->as);
	if (addr->as != ADDRXLAT_NOADDR)
		printf(":0x%"ADDRXLAT_PRIxADDR, addr->addr);
}

static void
print_linear(const addrxlat_desc_t *desc)
{
	puts("LINEAR");
	print_target_as(desc);
	printf("  off=0x%"PRIxFAST64"\n",
	       (uint_fast64_t) desc->param.linear.off);
}

static void
print_pgt(const addrxlat_desc_t *desc)
{
	static const char *pte_formats[] = {
		[ADDRXLAT_PTE_NONE] = "none",
		[ADDRXLAT_PTE_PFN32] = "pfn32",
		[ADDRXLAT_PTE_PFN64] = "pfn64",
		[ADDRXLAT_PTE_IA32] = "ia32",
		[ADDRXLAT_PTE_IA32_PAE] = "ia32_pae",
		[ADDRXLAT_PTE_X86_64] = "x86_64",
		[ADDRXLAT_PTE_S390X] = "s390x",
		[ADDRXLAT_PTE_PPC64_LINUX_RPN30] = "ppc64_linux_rpn30",
	};

	const addrxlat_paging_form_t *pf = &desc->param.pgt.pf;
	unsigned i;

	puts("PGT");
	print_target_as(desc);
	fputs("  root=", stdout);
	print_fulladdr(&desc->param.pgt.root);
	putchar('\n');
	fputs("  pte_format=", stdout);
	if (pf->pte_format < ARRAY_SIZE(pte_formats) &&
	    pte_formats[pf->pte_format])
		printf("%s", pte_formats[pf->pte_format]);
	else
		printf("%u", pf->pte_format);
	printf("\n  fields=");
	for (i = 0; i < pf->nfields; ++i)
		printf("%s%u", i ? "," : "", pf->fieldsz[i]);
	putchar('\n');
}

static void
print_lookup(const addrxlat_desc_t *desc)
{
	const addrxlat_lookup_elem_t *p = desc->param.lookup.tbl;
	size_t n = desc->param.lookup.nelem;

	puts("LOOKUP");
	print_target_as(desc);
	printf("  endoff=0x%"ADDRXLAT_PRIxADDR"\n", desc->param.lookup.endoff);
	while (n--) {
		printf("  %"ADDRXLAT_PRIxADDR" -> %"ADDRXLAT_PRIxADDR"\n",
		       p->orig, p->dest);
		++p;
	}
}

static void
print_memarr(const addrxlat_desc_t *desc)
{
	puts("MEMARR");
	print_target_as(desc);
	fputs("  base=", stdout);
	print_fulladdr(&desc->param.memarr.base);
	putchar('\n');
	printf("  shift=%u\n", desc->param.memarr.shift);
	printf("  elemsz=%u\n", desc->param.memarr.elemsz);
	printf("  valsz=%u\n", desc->param.memarr.valsz);
}

static void
print_meth(const addrxlat_meth_t *meth)
{
	const addrxlat_desc_t *desc = addrxlat_meth_get_desc(meth);

	switch (desc->kind) {
	case ADDRXLAT_NONE:
		puts("NONE");
		break;

	case ADDRXLAT_LINEAR:
		print_linear(desc);
		break;

	case ADDRXLAT_PGT:
		print_pgt(desc);
		break;

	case ADDRXLAT_LOOKUP:
		print_lookup(desc);
		break;

	case ADDRXLAT_MEMARR:
		print_memarr(desc);
		break;
	}
}

static struct {
	const addrxlat_meth_t *meth;
	const char *name;
} meth_map[ADDRXLAT_SYS_METH_NUM];

static void
set_meth(addrxlat_sys_meth_t idx, const addrxlat_meth_t *meth,
	 const char *name)
{
	if (meth) {
		meth_map[idx].meth = meth;
		meth_map[idx].name = name;
		printf("METH_%s: ", name);
		print_meth(meth);
		putchar('\n');
	}
}

static const char *
meth_name(const addrxlat_meth_t *meth)
{
	unsigned i;

	for (i = 0; i < ADDRXLAT_SYS_METH_NUM; ++i)
		if (meth_map[i].meth == meth)
			return meth_map[i].name;
	return NULL;
}

static void
print_xlat(const addrxlat_meth_t *meth)
{
	if (meth == NULL)
		puts("NONE");
	else {
		const char *name = meth_name(meth);
		if (!name) {
			printf("<%p> ", meth);
			print_meth(meth);
		} else
			puts(name);
	}
}

static void
print_map(const addrxlat_map_t *map)
{
	addrxlat_addr_t addr;
	const addrxlat_range_t *range;
	size_t i, n;

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
	const addrxlat_meth_t *meth;

	sys = kdump_get_addrxlat_sys(ctx);
	if (!sys) {
		fputs("No translation system!\n", stderr);
		return 1;
	}

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_PGT);
	set_meth(ADDRXLAT_SYS_METH_PGT, meth, "PGT");

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_UPGT);
	set_meth(ADDRXLAT_SYS_METH_UPGT, meth, "UPGT");

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_DIRECT);
	set_meth(ADDRXLAT_SYS_METH_DIRECT, meth, "DIRECT");

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_KTEXT);
	set_meth(ADDRXLAT_SYS_METH_KTEXT, meth, "KTEXT");

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_VMEMMAP);
	set_meth(ADDRXLAT_SYS_METH_VMEMMAP, meth, "VMEMMAP");

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_RDIRECT);
	set_meth(ADDRXLAT_SYS_METH_RDIRECT, meth, "RDIRECT");

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_MACHPHYS_KPHYS);
	set_meth(ADDRXLAT_SYS_METH_MACHPHYS_KPHYS, meth, "MACHPHYS_KPHYS");

	meth = addrxlat_sys_get_meth(sys, ADDRXLAT_SYS_METH_KPHYS_MACHPHYS);
	set_meth(ADDRXLAT_SYS_METH_KPHYS_MACHPHYS, meth, "KPHYS_MACHPHYS");

	puts("MAP_HW:");
	print_map(addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_HW));

	putchar('\n');

	puts("MAP_KV_PHYS:");
	print_map(addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_KV_PHYS));

	putchar('\n');

	puts("MAP_KPHYS_DIRECT:");
	print_map(addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_KPHYS_DIRECT));

	putchar('\n');

	puts("MACHPHYS -> KPHYS:");
	print_map(addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_MACHPHYS_KPHYS));

	putchar('\n');

	puts("KPHYS -> MACHPHYS:");
	print_map(addrxlat_sys_get_map(sys, ADDRXLAT_SYS_MAP_KPHYS_MACHPHYS));

	addrxlat_sys_decref(sys);

	return 0;
}

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	int fd;
	kdump_attr_t attr;
	kdump_status status;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <dumpfile> [<ostype>]\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror(argv[1]);
		return 2;
	}

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot allocate kdump context");
		return -1;
	}

	status = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_FD, fd);
	if (status != KDUMP_OK) {
		fprintf(stderr, "File initialization failed: %s\n",
			kdump_get_err(ctx));
		kdump_free(ctx);
		return 2;
	}

	if (argv[2]) {
		attr.type = KDUMP_STRING;
		attr.val.string = argv[2];
	} else
		attr.type = KDUMP_NIL;
	status = kdump_set_attr(ctx, "addrxlat.ostype", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot set ostype: %s\n",
			kdump_get_err(ctx));
		return 1;
	}

	dump_addrxlat(ctx);

	kdump_free(ctx);
	close(fd);

	return 0;
}
