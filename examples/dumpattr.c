#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <kdumpfile.h>

struct attr_data {
	kdump_ctx *ctx;
	const char *path;
	int indent;
};

static int
list_attr_recursive(void *data, const char *key,
		    const struct kdump_attr *valp)
{
	struct attr_data *ad = data;
	const char *oldpath;
	char *newpath;

	printf("%*s%s: ", ad->indent * 2, "", key);
	switch (valp->type) {
	case kdump_string:
		printf("%s\n", valp->val.string);
		break;
	case kdump_number:
		printf("%llu\n", (unsigned long long) valp->val.number);
		break;
	case kdump_address:
		printf("%llx\n", (unsigned long long) valp->val.address);
		break;
	case kdump_directory:
		putchar('\n');
		++ad->indent;
		oldpath = ad->path;
		if (*oldpath) {
			newpath = alloca(strlen(oldpath) + strlen(key) + 2);
			sprintf(newpath, "%s.%s", oldpath, key);
			ad->path = newpath;
		} else
			ad->path = key;
		kdump_enum_attr(ad->ctx, ad->path, list_attr_recursive, ad);
		ad->path = oldpath;
		--ad->indent;
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
	kdump_ctx *ctx = kdump_init();

	if (!ctx) {
		perror("Cannot allocate kdump context");
		return -1;
	}

	res = kdump_set_fd(ctx, fd);
	if (res != kdump_ok) {
		fprintf(stderr, "kdump_set_fd failed: %s\n",
			kdump_err_str(ctx));
		kdump_free(ctx);
		return 2;
	}

	struct attr_data data;
	data.ctx = ctx;
	data.path = argv[2] ?: "";
	data.indent = 0;
	res = kdump_enum_attr(ctx, data.path, list_attr_recursive, &data);
	if (res != kdump_ok) {
		fprintf(stderr, "kdump_enum_attr failed: %s\n",
			kdump_err_str(ctx));
		kdump_free(ctx);
		return 2;
	}

	kdump_free(ctx);
	close(fd);

	return 0;
}
