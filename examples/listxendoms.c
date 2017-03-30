#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>

#include <kdumpfile.h>

static kdump_vaddr_t
read_ptr(kdump_ctx_t *ctx, kdump_vaddr_t addr)
{
	uint64_t ptr;
	size_t sz = sizeof ptr;

	if (kdump_read(ctx, KDUMP_KVADDR, addr, &ptr, &sz) != kdump_ok) {
		fprintf(stderr, "read failed at 0x%llx: %s\n",
			(unsigned long long) addr, kdump_err_str(ctx));
		return 0;
	}
	return ptr;
}

static kdump_status
print_xen_domains(kdump_ctx_t *ctx)
{
	kdump_addr_t domain;
	uint64_t id;
	size_t sz, off_id, off_next;
	kdump_attr_t attr;
	kdump_status status;

	status = kdump_get_attr(
		ctx, "xen.vmcoreinfo.OFFSET.domain.domain_id", &attr);
	if (status != kdump_ok)
		return status;
	off_id = attr.val.number;

	status = kdump_get_attr(
		ctx, "xen.vmcoreinfo.OFFSET.domain.next_in_list", &attr);
	if (status != kdump_ok)
		return status;
	off_next = attr.val.number;

	status = kdump_vmcoreinfo_symbol(ctx, "domain_list", &domain);
	if (status != kdump_ok)
		return status;

	domain -= off_next;
	while ( (domain = read_ptr(ctx, domain + off_next)) ) {
		sz = sizeof id;
		status = kdump_read(ctx, KDUMP_KVADDR, domain + off_id,
				    &id, &sz);
		if (status != kdump_ok)
			return status;

		printf("Domain ID 0x%"PRIx64" at 0x%llx\n",
		       id, (unsigned long long)domain);
	}

	return kdump_ok;
}

int
main(int argc, char **argv)
{
	kdump_ctx_t *ctx;
	int fd;
	kdump_attr_t attr;
	kdump_status status;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <dumpfile>\n", argv[0]);
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
	if (status != kdump_ok) {
		fprintf(stderr, "File initialization failed: %s\n",
			kdump_err_str(ctx));
		kdump_free(ctx);
		return 2;
	}

	status = kdump_get_attr(ctx, KDUMP_ATTR_XEN_TYPE, &attr);
	if (status == kdump_nodata ||
	    (status == kdump_ok && attr.val.number != kdump_xen_system)) {
		fputs("Not a Xen system dump\n", stderr);
		return 1;
	} else if (status != kdump_ok) {
		fprintf(stderr, "Cannot get Xen type: %s\n",
			kdump_err_str(ctx));
		kdump_free(ctx);
		return 2;
	}

	status = kdump_set_string_attr(ctx, KDUMP_ATTR_OSTYPE, "xen");
	if (status != kdump_ok) {
		fprintf(stderr, "Cannot set ostype: %s\n",
			kdump_err_str(ctx));
		return 1;
	}

	if (print_xen_domains(ctx) != kdump_ok)
		printf("Cannot read domains: %s\n", kdump_err_str(ctx));

	kdump_free(ctx);
	close(fd);

	return 0;
}
