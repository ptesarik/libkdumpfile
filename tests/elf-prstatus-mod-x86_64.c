/* Check that PRSTATUS attribute is linked to register attributes.
   Copyright (C) 2020 Petr Tesarik <ptesarik@suse.com>

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

#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <endian.h>
#include <libkdumpfile/kdumpfile.h>

#include "testutil.h"

struct timeval_64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

struct x86_64_elf_siginfo
{
	int32_t si_signo;	/* signal number */
	int32_t si_code;	/* extra code */
	int32_t si_errno;	/* errno */
} __attribute__((packed));

#define X86_64_NGREG	27

struct x86_64_elf_prstatus
{
	struct x86_64_elf_siginfo pr_info;	/* UNUSED in kernel cores */
	int16_t	pr_cursig;		/* UNUSED in kernel cores */
	char	_pad1[2];		/* alignment */
	uint64_t pr_sigpend;		/* UNUSED in kernel cores */
	uint64_t pr_sighold;		/* UNUSED in kernel cores */
	int32_t	pr_pid;			/* PID of crashing task */
	int32_t	pr_ppid;		/* UNUSED in kernel cores */
	int32_t	pr_pgrp;		/* UNUSED in kernel cores */
	int32_t	pr_sid;			/* UNUSED in kernel cores */
	struct timeval_64 pr_utime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_stime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_cutime;	/* UNUSED in kernel cores */
	struct timeval_64 pr_cstime;	/* UNUSED in kernel cores */
	uint64_t pr_reg[X86_64_NGREG];	/* GP registers */
	/* optional UNUSED fields may follow */
} __attribute__((packed));

#define ATTR_KEY_RAX "cpu.0.reg.rax"

static int
check(kdump_ctx_t *ctx)
{
	struct x86_64_elf_prstatus *prstatus;
	kdump_status status;
	kdump_blob_t *blob;
	kdump_attr_t attr;
	kdump_num_t rax;
	uint64_t pr_rax;
	size_t size;

	attr.type = KDUMP_BLOB;
	status = kdump_get_typed_attr(ctx, "cpu.0.PRSTATUS", &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get PRSTATUS attribute: %s\n",
			kdump_get_err(ctx));
		return TEST_FAIL;
	}
	blob = attr.val.blob;

	status = kdump_get_number_attr(ctx, ATTR_KEY_RAX, &rax);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot get RAX value: %s\n",
			kdump_get_err(ctx));
		return TEST_FAIL;
	}

	prstatus = kdump_blob_pin(blob);
	size = kdump_blob_size(blob);
	if (size < sizeof(*prstatus)) {
		kdump_blob_unpin(blob);
		fprintf(stderr, "Wrong PRSTATUS size: expected %zd, got %zd.\n",
			sizeof(*prstatus), size);
		return TEST_FAIL;
	}
	pr_rax = le64toh(prstatus->pr_reg[10]);

	if (rax != pr_rax) {
		kdump_blob_unpin(blob);
		fprintf(stderr, "RAX value mismatch:"
			" attrs: %016llX, PRSTATUS: %016llX\n",
			rax, pr_rax);
		return TEST_FAIL;
	}
	printf("Original RAX value: %016llX\n", (unsigned long long) rax);

	/* Flip odd bits in attribute and re-check. */
	rax ^= 0x5555555555555555ULL;
	status = kdump_set_number_attr(ctx, ATTR_KEY_RAX, rax);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot modify RAX value: %s\n",
			kdump_get_err(ctx));
		return TEST_FAIL;
	}

	pr_rax = le64toh(prstatus->pr_reg[10]);
	if (rax != pr_rax) {
		kdump_blob_unpin(blob);
		fprintf(stderr, "PRSTATUS does not follow RAX attribute:"
			" attrs: %016llX, PRSTATUS: %016llX\n",
			rax, pr_rax);
		return TEST_FAIL;
	}
	printf("RAX value #1: %016llX\n", (unsigned long long) rax);

	/* Flip all bits in PRSTATUS and re-check. */
	pr_rax ^= (int64_t)-1;
	prstatus->pr_reg[10] = htole64(pr_rax);

	status = kdump_get_number_attr(ctx, ATTR_KEY_RAX, &rax);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot re-get RAX value: %s\n",
			kdump_get_err(ctx));
		return TEST_FAIL;
	}

	if (rax != pr_rax) {
		kdump_blob_unpin(blob);
		fprintf(stderr, "RAX attribute does not follow PRSTATUS:"
			" attrs: %016llX, PRSTATUS: %016llX\n",
			rax, pr_rax);
		return TEST_FAIL;
	}
	printf("RAX value #2: %016llX\n", (unsigned long long) rax);

	/* Check that register cannot be accessed after resetting PRSTATUS. */
	kdump_blob_unpin(blob);
	status = kdump_blob_set(blob, NULL, 0);
	if (status != KDUMP_OK) {
		fprintf(stderr, "Cannot reset PRSTATUS: %s\n",
			kdump_strerror(status));
		return TEST_ERR;
	}
	status = kdump_get_number_attr(ctx, ATTR_KEY_RAX, &rax);
	if (status == KDUMP_OK) {
		fprintf(stderr, "Got RAX value with zero-sized PRSTATUS!\n");
		return TEST_FAIL;
	} else if (status != KDUMP_ERR_CORRUPT) {
		fprintf(stderr, "Cannot re-get RAX value: %s\n",
			kdump_get_err(ctx));
		return TEST_FAIL;
	}

	return TEST_OK;
}

static int
check_fd(int fd)
{
	kdump_ctx_t *ctx;
	kdump_status res;
	int rc;

	ctx = kdump_new();
	if (!ctx) {
		perror("Cannot initialize dump context");
		return TEST_ERR;
	}

	res = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_FD, fd);
	if (res != KDUMP_OK) {
		fprintf(stderr, "Cannot open dump: %s\n", kdump_get_err(ctx));
		rc = TEST_ERR;
	} else
		rc = check(ctx);

	kdump_free(ctx);
	return rc;
}

static void
usage(FILE *f, const char *prog)
{
	fprintf(f,
		"Usage: %s <dump>\n\n"
		"Options:\n"
		"  --help     Print this help and exit\n",
		prog);
}

static const struct option opts[] = {
	{ "help", no_argument, NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};

int
main(int argc, char **argv)
{
	FILE *fhelp;
	int fd;
	int rc;
	int c;

	fhelp = stdout;
	while ( (c = getopt_long(argc, argv, "h", opts, NULL)) != -1)
		switch (c) {
		case '?':
			fhelp = stderr;
		case 'h':
			usage(fhelp, argv[0]);
			if (fhelp == stderr)
				return TEST_ERR;
			return TEST_OK;
		}

	if (argc - optind != 1) {
		usage(stderr, argv[0]);
		return TEST_ERR;
	}

	fd = open(argv[optind], O_RDONLY);
	if (fd < 0) {
		perror("open dump");
		return TEST_ERR;
	}

	rc = check_fd(fd);

	if (close(fd) < 0) {
		perror("close dump");
		rc = TEST_ERR;
	}

	return rc;
}
