/*
 * main.c
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

#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include "kdumpid.h"

static void
print_xen_info(kdump_ctx_t *ctx)
{
	kdump_attr_t attr;
	kdump_status status;

	fputs("Xen: ", stdout);
	status = kdump_get_attr(ctx, "xen.version.major", &attr);
	if (status == KDUMP_OK)
		printf("%" KDUMP_PRIuNUM ".", attr.val.number);
	else
		fputs("?.", stdout);

	status = kdump_get_attr(ctx, "xen.version.minor", &attr);
	if (status == KDUMP_OK)
		printf("%" KDUMP_PRIuNUM, attr.val.number);
	else
		fputs("?", stdout);

	status = kdump_get_attr(ctx, "xen.version.extra", &attr);
	if (status == KDUMP_OK)
		puts(attr.val.string);
	else
		putchar('\n');
}

static void
version(FILE *out, const char *progname)
{
	fprintf(out, "%s version %d.%d\n",
		basename(progname), VER_MAJOR, VER_MINOR);
}

static void
help(FILE *out, const char *progname)
{
	fprintf(out, "Usage: %s [-f] [-v] <dumpfile>\n",
		basename(progname));
}

#define SHORTOPTS	"fhv"

static void
print_verbose(struct dump_desc *dd)
{
	if (dd->machine[0])
		printf("Machine: %s\n", dd->machine);
	if (*dd->banner)
		printf("Banner: %s\n", dd->banner);

	if (dd->cfg) {
		char *local = strstr(dd->cfg, "CONFIG_LOCALVERSION=");
		if (local) {
			char c, *end = strchr(local, '\n');
			if (end) {
				c = *end;
				*end = 0;
			}
			printf("Cfg release: %s\n", local + 20);
			if (end)
				*end = c;
		}
	}
}

int
main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "force", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "version", no_argument, NULL, 256 },
		{0, 0, 0, 0}
	};
	struct dump_desc dd;
	const char *str;
	kdump_status status;
	int c, opt;

	/* Initialize dd */
	memset(&dd, 0, sizeof dd);

	while ( (c = getopt_long(argc, argv, SHORTOPTS, opts, &opt)) != -1 )
		switch(c) {
		case 'f':
			dd.flags |= DIF_FORCE;
			break;
		case 'h':
			help(stdout, argv[0]);
			return 0;
		case 'v':
			dd.flags |= DIF_VERBOSE;
			break;
		case 256:
			version(stdout, argv[0]);
			return 0;
		}

	if (argc - optind != 1) {
		help(stderr, argv[0]);
		return 1;
	}
	dd.name = argv[optind];

	if ((dd.fd = open(dd.name, O_RDONLY)) < 0) {
		perror(dd.name);
		return 2;
	}

	dd.ctx = kdump_new();
	if (!dd.ctx) {
		perror("Cannot allocate dump file context");
		close(dd.fd);
		return 2;
	}

	status = kdump_set_number_attr(dd.ctx, KDUMP_ATTR_ZERO_EXCLUDED, 1);
	if (status != KDUMP_OK)
		fprintf(stderr, "WARNING: Excluded pages are not zeroed: %s\n",
			kdump_get_err(dd.ctx));

	status = kdump_set_number_attr(dd.ctx, KDUMP_ATTR_FILE_FD, dd.fd);
	if (status != KDUMP_OK) {
		fprintf(stderr, "File initialization failed: %s\n",
			kdump_get_err(dd.ctx));
		close(dd.fd);
		return 2;
	}

	if (dd.flags & DIF_FORCE) {
		status = kdump_get_number_attr(dd.ctx, "max_pfn",
					       &dd.max_pfn);
		if (status != KDUMP_OK) {
			fprintf(stderr, "Cannot get max PFN: %s\n",
				kdump_get_err(dd.ctx));
			kdump_free(dd.ctx);
			return 2;
		}
	}

	kdump_set_string_attr(dd.ctx, KDUMP_ATTR_OSTYPE, "linux");

	status = kdump_get_number_attr(dd.ctx, KDUMP_ATTR_PAGE_SIZE,
				       &dd.page_size);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get page size: %s\n",
			kdump_get_err(dd.ctx));
		kdump_free(dd.ctx);
		return 2;
	}

	status = kdump_get_string_attr(dd.ctx, "linux.uts.release", &str);
	if (status == KDUMP_OK)
		strcpy(dd.ver, str);
	else if (status == KDUMP_ERR_NODATA)
		dd.ver[0] = '\0';
	else {
		fprintf(stderr, "Cannot get UTS release: %s\n",
			kdump_get_err(dd.ctx));
		kdump_free(dd.ctx);
		return 2;
	}

	status = kdump_get_string_attr(dd.ctx, "linux.uts.machine", &str);
	if (status == KDUMP_OK)
		strcpy(dd.machine, str);
	else if (status == KDUMP_ERR_NODATA)
		dd.machine[0] = '\0';
	else {
		fprintf(stderr, "Cannot get UTS machine: %s\n",
			kdump_get_err(dd.ctx));
		kdump_free(dd.ctx);
		return 2;
	}

	status = kdump_get_string_attr(dd.ctx, KDUMP_ATTR_ARCH_NAME, &dd.arch);
	if (status == KDUMP_ERR_NODATA)
		dd.arch = NULL;
	else if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get architecture name: %s\n",
			kdump_get_err(dd.ctx));
		kdump_free(dd.ctx);
		return 2;
	}

	status = kdump_get_number_attr(dd.ctx, "arch.byte_order", &dd.endian);
	if (status == KDUMP_ERR_NODATA)
		dd.endian = (kdump_num_t)-1;
	else if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get architecture byte order: %s\n",
			kdump_get_err(dd.ctx));
		kdump_free(dd.ctx);
		return 2;
	}

	status = kdump_get_string_attr(dd.ctx, KDUMP_ATTR_FILE_FORMAT,
				       &dd.format);
	if (status == KDUMP_ERR_NODATA)
		dd.format = NULL;
	else if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get architecture name: %s\n",
			kdump_get_err(dd.ctx));
		kdump_free(dd.ctx);
		return 2;
	}

	status = kdump_get_number_attr(dd.ctx, KDUMP_ATTR_XEN_TYPE,
				       &dd.xen_type);
	if (status == KDUMP_ERR_NODATA)
		dd.xen_type = KDUMP_XEN_NONE;
	else if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot determine Xen type: %s\n",
			kdump_get_err(dd.ctx));
		kdump_free(dd.ctx);
		return 2;
	}

	if (need_explore(&dd))
		explore_raw_data(&dd);

	if (!*dd.ver)
		get_version_from_banner(&dd);

	printf("Format: %s%s\n", dd.format ?: "<unknown>",
	       dd.xen_type != KDUMP_XEN_NONE ? ", Xen" : "");
	printf("Arch: %s\n", dd.arch);
	printf("Version: %s\n", dd.ver);
	if (dd.xen_type != KDUMP_XEN_NONE)
		print_xen_info(dd.ctx);

	if (dd.flags & DIF_VERBOSE)
		print_verbose(&dd);

	/* Intentionally ignore errors on close */
	kdump_free(dd.ctx);
	close(dd.fd);

	return 0;
}
