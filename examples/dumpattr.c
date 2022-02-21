#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libkdumpfile/kdumpfile.h>

static int list_attr_recursive(kdump_ctx_t *, kdump_attr_ref_t *, int);
static int show_attr(kdump_ctx_t *, kdump_attr_ref_t *, int, const char *);

static int
list_attr_recursive(kdump_ctx_t *ctx, kdump_attr_ref_t *dir, int indent)
{
	kdump_attr_iter_t it;
	kdump_status status;
	int ret;

	status = kdump_attr_ref_iter_start(ctx, dir, &it);
	if (status != KDUMP_OK) {
		fprintf(stderr, "kdump_attr_ref_iter_start failed: %s\n",
			kdump_get_err(ctx));
		return -1;
	}

	ret = 0;
	while (it.key) {
		ret = show_attr(ctx, &it.pos, indent, it.key);
		if (ret)
			break;

		status = kdump_attr_iter_next(ctx, &it);
		if (status != KDUMP_OK) {
			fprintf(stderr, "kdump_attr_iter_next failed: %s\n",
				kdump_get_err(ctx));
			ret = -1;
			break;
		}
	}

	kdump_attr_iter_end(ctx, &it);
	return ret;
}

static int
print_bitmap(kdump_ctx_t *ctx, kdump_bmp_t *bmp)
{
	kdump_addr_t idx;
	const char *delim = "";
	kdump_status status;

	idx = 0;
	fputs("[ ", stdout);
	while ( (status = kdump_bmp_find_set(bmp, &idx)) == KDUMP_OK) {
		kdump_addr_t start = idx;
		status = kdump_bmp_find_clear(bmp, &idx);
		if (status != KDUMP_OK) {
			fprintf(stderr, "kdump_bmp_find_clear faild: %s\n",
				kdump_bmp_get_err(bmp));
			return -1;
		}
		printf("%s%llx-%llx",
		       delim,
		       (unsigned long long) start,
		       (unsigned long long) idx - 1);
		delim = ", ";
	}
	fputs("]\n", stdout);

	return 0;
}

static int
print_blob(kdump_ctx_t *ctx, kdump_blob_t *blob)
{
	unsigned char *data;
	size_t size;

	data = kdump_blob_pin(blob);
	size = kdump_blob_size(blob);

	fputs("[ ", stdout);
	while (size--)
		printf("%02X", *data++);
	fputs(" ]\n", stdout);

	kdump_blob_unpin(blob);
	return 0;
}

static int
show_attr(kdump_ctx_t *ctx, kdump_attr_ref_t *ref, int indent, const char *key)
{
	kdump_attr_t attr;
	kdump_status status;

	if (key && *key) {
		printf("%*s%s: ", indent * 2, "", key);
		++indent;
	}

	status = kdump_attr_ref_get(ctx, ref, &attr);
	if (status != KDUMP_OK) {
		fprintf(stderr, "kdump_attr_ref_get failed: %s\n",
			kdump_get_err(ctx));
		return -1;
	}

	switch (attr.type) {
	case KDUMP_STRING:
		printf("%s\n", attr.val.string);
		break;
	case KDUMP_NUMBER:
		printf("%llu\n", (unsigned long long) attr.val.number);
		break;
	case KDUMP_ADDRESS:
		printf("%llx\n", (unsigned long long) attr.val.address);
		break;
	case KDUMP_BITMAP:
		print_bitmap(ctx, attr.val.bitmap);
		break;
	case KDUMP_BLOB:
		print_blob(ctx, attr.val.blob);
		break;
	case KDUMP_DIRECTORY:
		if (key && *key)
			putchar('\n');
		list_attr_recursive(ctx, ref, indent);
		break;
	default:
		printf("<unknown>\n");
	}

	return 0;
}

int
main(int argc, char **argv)
{
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <dumpfile> [<attr>]\n", argv[0]);
		return 1;
	}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror(argv[1]);
		return 2;
	}

	kdump_status res;
	kdump_ctx_t *ctx = kdump_new();

	if (!ctx) {
		perror("Cannot allocate kdump context");
		return -1;
	}

	res = kdump_set_number_attr(ctx, KDUMP_ATTR_FILE_FD, fd);
	if (res != KDUMP_OK) {
		fprintf(stderr, "File initialization failed: %s\n",
			kdump_get_err(ctx));
		kdump_free(ctx);
		return 2;
	}

	kdump_attr_ref_t root;
	res = kdump_attr_ref(ctx, argv[2], &root);
	if (res != KDUMP_OK) {
		fprintf(stderr, "kdump_attr_ref failed: %s\n",
			kdump_get_err(ctx));
		kdump_free(ctx);
		return 2;
	}

	if (show_attr(ctx, &root, 0, argv[2])) {
		kdump_free(ctx);
		return 2;
	}

	kdump_attr_unref(ctx, &root);

	kdump_free(ctx);
	close(fd);

	return 0;
}
