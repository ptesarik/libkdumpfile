/** @internal @file src/kdumpfile/util.c
 * @brief Utility functions.
 */
/* Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#include "kdumpfile-priv.h"

#include <linux/version.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#if USE_ZLIB
# include <zlib.h>
#endif

/** Set an error message, returning @c kdump_status.
 * @arg err     Error message object.
 * @arg status  Status code.
 * @arg msgfmt  Format string.
 * @returns     Status code (equal to @c status).
 */
kdump_status
status_err(kdump_errmsg_t *err, kdump_status status, const char *msgfmt, ...)
{
	va_list ap;

	va_start(ap, msgfmt);
	err_vadd(err, msgfmt, ap);
	va_end(ap);
	return status;
}

void
kdump_clear_err(kdump_ctx_t *ctx)
{
	clear_error(ctx);
}

DEFINE_ALIAS(err);

kdump_status
kdump_err(kdump_ctx_t *ctx, kdump_status status, const char *msgfmt, ...)
{
	if (status != KDUMP_OK) {
		va_list ap;

		va_start(ap, msgfmt);
		err_vadd(&ctx->err, msgfmt, ap);
		va_end(ap);
	}

	return status;
}

/** Translate an addrxlat error status to a @c kdump_status.
 * @param ctx     Dump file object.
 * @param status  Address translation status.
 * @returns       Error status (libkdumpfile).
 */
kdump_status
addrxlat2kdump(kdump_ctx_t *ctx, addrxlat_status status)
{
	kdump_status ret;

	if (status == ADDRXLAT_OK)
		return KDUMP_OK;

	if (status < 0)
		ret = -status;
	else if (status == ADDRXLAT_ERR_NODATA)
		ret = KDUMP_ERR_NODATA;
	else
		ret = KDUMP_ERR_ADDRXLAT;

	set_error(ctx, ret, "%s", addrxlat_ctx_get_err(ctx->xlatctx));
	addrxlat_ctx_clear_err(ctx->xlatctx);
	return ret;
}

/** Translate a @c kdump_status to addrxlat error status.
 * @param ctx     Dump file object.
 * @param status  libkdumpfile status.
 * @returns       Error status (addrxlat).
 */
addrxlat_status
kdump2addrxlat(kdump_ctx_t *ctx, kdump_status status)
{
	addrxlat_status ret;

	if (status == KDUMP_OK)
		return ADDRXLAT_OK;

	if (status == KDUMP_ERR_NODATA)
		ret = ADDRXLAT_ERR_NODATA;
	else
		ret = -status;

	addrxlat_ctx_err(ctx->xlatctx, ret, "%s", err_str(&ctx->err));
	clear_error(ctx);
	return ret;
}


void *
ctx_malloc(size_t size, kdump_ctx_t *ctx, const char *desc)
{
	void *ret = malloc(size);
	if (!ret)
		set_error(ctx, KDUMP_ERR_SYSTEM,
			  "Cannot allocate %s (%zu bytes)", desc, size);
	return ret;
}

static inline void
add_to_hash(unsigned long *hash, unsigned long x)
{
	*hash += x;
	*hash *= 9;
}

unsigned long
mem_hash(const char *s, size_t len)
{
	unsigned long hash = 0;

	while (len >= sizeof(unsigned long)) {
		add_to_hash(&hash, *(unsigned long*)s);
		s += sizeof(unsigned long);
		len -= sizeof(unsigned long);
	}
	while (len--)
		hash += (unsigned long)*s++ << (8 * len);
	return hash;
}

unsigned long
string_hash(const char *s)
{
	return mem_hash(s, strlen(s));
}

/**  Update a partial hash with a memory area.
 * @param[in,out] ph     Partial hash state.
 * @param[in]     s      Start of memory area with new data to be hashed.
 * @param[in]     len    Number of bytes at @p s to be hashed.
 */
void
phash_update(struct phash *ph, const char *s, size_t len)
{
	if (ph->idx) {
		while (len && ph->idx < sizeof(unsigned long)) {
			ph->part.bytes[ph->idx] = *s++;
			--len;
			++ph->idx;
		}
		if (ph->idx >= sizeof(unsigned long)) {
			add_to_hash(&ph->val, ph->part.num);
			ph->idx = 0;
		}
	}

	while (len >= sizeof(unsigned long)) {
		add_to_hash(&ph->val, *(unsigned long*)s);
		s += sizeof(unsigned long);
		len -= sizeof(unsigned long);
	}
	while (len--)
		ph->part.bytes[ph->idx++] = *s++;
}

static size_t
arch_ptr_size(enum kdump_arch arch)
{
	switch (arch) {
	case ARCH_AARCH64:
	case ARCH_ALPHA:
	case ARCH_IA64:
	case ARCH_PPC64:
	case ARCH_S390X:
	case ARCH_X86_64:
		return 8;	/* 64 bits */

	case ARCH_ARM:
	case ARCH_IA32:
	case ARCH_MIPS:
	case ARCH_PPC:
	case ARCH_S390:
	default:
		return 4;	/* 32 bits */
	}

}

/**  Translate a utsname machine to a canonical architecture name.
 * @param machine  Machine name (as found in utsname).
 * @returns        Canonical architecture name, or @c NULL if not found.
 */
static const char *
machine_arch_name(const char *machine)
{
	if (!strcmp(machine, "alpha"))
		return KDUMP_ARCH_ALPHA;
	else if (!strcmp(machine, "ia64"))
		return KDUMP_ARCH_IA64;
	else if (!strcmp(machine, "mips"))
		return KDUMP_ARCH_MIPS;
	else if (!strcmp(machine, "ppc"))
		return KDUMP_ARCH_PPC;
	else if (!strcmp(machine, "ppc64") ||
		 !strcmp(machine, "ppc64le"))
		return KDUMP_ARCH_PPC64;
	else if (!strcmp(machine, "s390"))
		return KDUMP_ARCH_S390;
	else if (!strcmp(machine, "s390x"))
		return KDUMP_ARCH_S390X;
	else if (!strcmp(machine, "i386") ||
		 !strcmp(machine, "i586") ||
		 !strcmp(machine, "i686"))
		return KDUMP_ARCH_IA32;
	else if (!strcmp(machine, "x86_64"))
		return KDUMP_ARCH_X86_64;
	else if (!strcmp(machine, "arm64") ||
		 !strcmp(machine, "aarch64"))
		return KDUMP_ARCH_AARCH64;
	else if (!strncmp(machine, "arm", 3))
		return KDUMP_ARCH_ARM;
	else
		return NULL;
}

static size_t
default_page_shift(enum kdump_arch arch)
{
	static const int page_shifts[] = {
		[ARCH_AARCH64] = 0,
		[ARCH_ALPHA]= 13,
		[ARCH_ARM] = 12,
		[ARCH_IA64] = 0,
		[ARCH_MIPS] = 12,
		[ARCH_PPC] = 0,
		[ARCH_PPC64] = 0,
		[ARCH_S390] = 12,
		[ARCH_S390X] = 12,
		[ARCH_IA32] = 12,
		[ARCH_X86_64] = 12,
	};

	if (arch < ARRAY_SIZE(page_shifts))
		return page_shifts[arch];
	return 0;
}

static const struct arch_ops*
arch_ops(enum kdump_arch arch)
{
	switch (arch) {
	case ARCH_ALPHA:
	case ARCH_ARM:
	case ARCH_IA64:
	case ARCH_MIPS:
	case ARCH_PPC:
	case ARCH_S390:
		/* TODO */
		break;

	case ARCH_AARCH64:	return &aarch64_ops;
	case ARCH_IA32:		return &ia32_ops;
	case ARCH_PPC64:	return &ppc64_ops;
	case ARCH_S390X:	return &s390x_ops;
	case ARCH_X86_64:	return &x86_64_ops;

	default:
		break;
	}

	return NULL;
}

/** Maximum length of a canonical arch name, including terminating NUL. */
#define MAX_ARCH_NAME_LEN 8
/** List of canonical architecture names. */
static const char canon_arch_names[][MAX_ARCH_NAME_LEN] =
{
#define DEF_ARCH(name)	[ARCH_ ## name] = KDUMP_ARCH_ ## name "\0"
	DEF_ARCH(AARCH64),
	DEF_ARCH(ALPHA),
	DEF_ARCH(ARM),
	DEF_ARCH(IA32),
	DEF_ARCH(IA64),
	DEF_ARCH(MIPS),
	DEF_ARCH(PPC),
	DEF_ARCH(PPC64),
	DEF_ARCH(S390),
	DEF_ARCH(S390X),
	DEF_ARCH(X86_64),
};

/**  Look up an architecture by its canonical name.
 * @param name  Canonical architecture name.
 * @returns     Architecture index, or @c ARCH_UNKNOWN if not found.
 */
static enum kdump_arch
arch_index(const char *name)
{
	enum kdump_arch arch;
	if (*name)
		for (arch = 0; arch < ARRAY_SIZE(canon_arch_names); ++arch)
			if (!strcmp(name, canon_arch_names[arch]))
				return arch;
	return ARCH_UNKNOWN;
}

/**  Perform arch-specific initialization.
 * @param ctx  Dump file object.
 * @returns    Error status.
 *
 * This function should be called when all arch-specific attributes
 * are ready:
 *   - arch.name (sets arch_ops)
 *   - arch.byte_order
 *   - arch.ptr_size
 *   - arch.page_size and arch.page_shift
 *   - cache has been allocated
 */
static kdump_status
do_arch_init(kdump_ctx_t *ctx)
{
	ctx->shared->arch_init_done = 1;
	if (ctx->shared->arch_ops && ctx->shared->arch_ops->init)
		return ctx->shared->arch_ops->init(ctx);

	return KDUMP_OK;
}

static kdump_status
arch_name_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	ctx->shared->arch = arch_index(attr_value(attr)->string);

	if (ctx->shared->arch_ops) {
		if (ctx->shared->arch_ops->attr_cleanup)
			ctx->shared->arch_ops->attr_cleanup(ctx->dict);
		if (ctx->shared->arch_ops->cleanup)
			ctx->shared->arch_ops->cleanup(ctx->shared);
	}
	ctx->shared->arch_ops = arch_ops(ctx->shared->arch);
	ctx->shared->arch_init_done = 0;

	if (ctx->shared->arch == ARCH_UNKNOWN)
		return KDUMP_OK;

	set_ptr_size(ctx, arch_ptr_size(ctx->shared->arch));
	set_attr_number(ctx, gattr(ctx, GKI_pteval_size), ATTR_DEFAULT,
			get_ptr_size(ctx));

	if (!isset_page_size(ctx)) {
		int page_shift = default_page_shift(ctx->shared->arch);
		if (!page_shift)
			return KDUMP_OK;

		/* Call do_arch_init() via hooks. */
		return set_page_shift(ctx, page_shift);
	}

	return do_arch_init(ctx);
}

const struct attr_ops arch_name_ops = {
	.post_set = arch_name_post_hook,
};


static kdump_status
uts_machine_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	const char *arch;

	if (isset_arch_name(ctx))
		return KDUMP_OK;

	arch = machine_arch_name(attr_value(attr)->string);
	return arch
		? set_arch_name(ctx, arch)
		: KDUMP_OK;
}

const struct attr_ops uts_machine_ops = {
	.post_set = uts_machine_post_hook,
};

/** Revalidate linux.version_code.
 * @param ctx      Dump file object.
 * @param attr     "linux.version_code" attribute.
 * @returns        Error status.
 *
 * Re-initialize Linux version code from kernel release string to make
 * sure that it is up to date.
 */
static kdump_status
linux_ver_revalidate(kdump_ctx_t *ctx, struct attr_data *attr)
{
	struct attr_data *rel;
	const char *p;
	char *endp;
	long a, b, c;
	kdump_attr_value_t val;
	kdump_status status;

	rel = gattr(ctx, GKI_linux_uts_release);
	if (!attr_isset(rel))
		return KDUMP_OK;
	status = attr_revalidate(ctx, rel);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot get Linux release");

	p = attr_value(rel)->string;
	a = strtoul(p, &endp, 10);
	if (endp == p || *endp != '.')
		goto err;

	b = c = 0L;
	if (*endp) {
		p = endp + 1;
		b = strtoul(p, &endp, 10);
		if (endp == p || *endp != '.')
			goto err;

		if (*endp) {
			p = endp + 1;
			c = strtoul(p, &endp, 10);
			if (endp == p)
				goto err;
		}
	}

	val.number = KERNEL_VERSION(a, b, c);
	return set_attr(ctx, attr, ATTR_DEFAULT, &val);
 err:
	return set_error(ctx, KDUMP_ERR_CORRUPT, "Invalid kernel version: %s",
			 attr_value(rel)->string);
}

const struct attr_ops linux_version_code_ops = {
	.revalidate = linux_ver_revalidate,
};

static kdump_status
linux_ver_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return set_attr_number(ctx, gattr(ctx, GKI_linux_version_code),
			       ATTR_INVALID, 0);
}

const struct attr_ops linux_ver_ops = {
	.post_set = linux_ver_post_hook,
};

/** Revalidate xen.version_code.
 * @param ctx      Dump file object.
 * @param attr     "xen.version_code" attribute.
 * @returns        Error status.
 *
 * Re-initialize Xen version code from Xen major/minor version to make
 * sure that it is up to date.
 */
static kdump_status
xen_ver_revalidate(kdump_ctx_t *ctx, struct attr_data *attr)
{
	struct attr_data *attr_major, *attr_minor;
	unsigned long major, minor;
	kdump_attr_value_t val;
	kdump_status status;

	attr_major = gattr(ctx, GKI_xen_ver_major);
	if (!attr_isset(attr_major))
		return KDUMP_OK;
	attr_minor = gattr(ctx, GKI_xen_ver_minor);
	if (!attr_isset(attr_minor))
		return KDUMP_OK;

	status = attr_revalidate(ctx, attr_major);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot get Xen major");
	major = attr_value(attr_major)->number;

	status = attr_revalidate(ctx, attr_minor);
	if (status != KDUMP_OK)
		return set_error(ctx, status, "Cannot get Xen minor");
	minor = attr_value(attr_minor)->number;

	val.number = ADDRXLAT_VER_XEN(major, minor);
	return set_attr(ctx, attr, ATTR_DEFAULT, &val);
}

const struct attr_ops xen_version_code_ops = {
	.revalidate = xen_ver_revalidate,
};

static kdump_status
xen_ver_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return set_attr_number(ctx, gattr(ctx, GKI_xen_version_code),
			       ATTR_INVALID, 0);
}

const struct attr_ops xen_ver_ops = {
	.post_set = xen_ver_post_hook,
};

/**  Re-allocate a cache with default parameters.
 * @param ctx  Dump file object.
 * @returns    Error status.
 *
 * This function can be used as the @c realloc_caches method if
 * the cache is organized as @c cache.size elements of @c arch.page_size
 * bytes each.
 */
kdump_status
def_realloc_caches(kdump_ctx_t *ctx)
{
	unsigned cache_size = get_cache_size(ctx);
	struct cache *cache;
	kdump_status status;

	cache = cache_alloc(cache_size, get_page_size(ctx));
	if (!cache)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Cannot allocate cache (%u * %zu bytes)",
				 cache_size, get_page_size(ctx));

	status = cache_set_attrs(cache, ctx,
				 gattr(ctx, GKI_cache_hits),
				 gattr(ctx, GKI_cache_misses));
	if (status != KDUMP_OK) {
		cache_free(cache);
		return status;
	}

	if (ctx->shared->cache)
		cache_free(ctx->shared->cache);
	ctx->shared->cache = cache;

	return KDUMP_OK;
}

static kdump_status
cache_size_pre_hook(kdump_ctx_t *ctx, struct attr_data *attr,
		    kdump_attr_value_t *val)
{
	if (val->number > UINT_MAX)
		return set_error(ctx, KDUMP_ERR_INVALID,
				 "Cache size too big (max %u)", UINT_MAX);
	return KDUMP_OK;
}

static kdump_status
cache_size_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return ctx->shared->ops && ctx->shared->ops->realloc_caches
		? ctx->shared->ops->realloc_caches(ctx)
		: KDUMP_OK;
}

const struct attr_ops cache_size_ops = {
	.pre_set = cache_size_pre_hook,
	.post_set = cache_size_post_hook,
};

static kdump_status
page_size_pre_hook(kdump_ctx_t *ctx, struct attr_data *attr,
		   kdump_attr_value_t *newval)
{
	size_t page_size = newval->number;

	/* It must be a power of 2 */
	if (page_size != (page_size & ~(page_size - 1)))
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Invalid page size: %zu", page_size);

	return set_page_shift(ctx, ffsl((unsigned long)page_size) - 1);
}

static kdump_status
page_size_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	kdump_status res;

	if (ctx->shared->ops && ctx->shared->ops->realloc_caches) {
		res = ctx->shared->ops->realloc_caches(ctx);
		if (res != KDUMP_OK)
			return res;
	}

	if (isset_arch_name(ctx) && !ctx->shared->arch_init_done) {
		res = do_arch_init(ctx);
		if (res != KDUMP_OK)
			return res;
	}

	return KDUMP_OK;
}

const struct attr_ops page_size_ops = {
	.pre_set = page_size_pre_hook,
	.post_set = page_size_post_hook,
};

static kdump_status
page_shift_post_hook(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return set_page_size(ctx, (size_t)1 << attr_value(attr)->number);
}

const struct attr_ops page_shift_ops = {
	.post_set = page_shift_post_hook,
};

/* Final NUL may be missing in the source (i.e. corrupted dump data),
 * but let's make sure that it is present in the destination.
 */
static kdump_status
set_uts_string(kdump_ctx_t *ctx, struct attr_data *attr, const char *src)
{
	char str[NEW_UTS_LEN + 1];

	memcpy(str, src, NEW_UTS_LEN);
	str[NEW_UTS_LEN] = 0;
	return set_error(ctx, set_attr_string(ctx, attr, ATTR_DEFAULT, str),
			 "Cannot set attribute %s", attr->template->key);
}

kdump_status
set_uts(kdump_ctx_t *ctx, const struct new_utsname *src)
{
	static const struct {
		unsigned idx, off;
	} defs[] = {
#define DEF(name) \
		{ GKI_linux_uts_ ## name, offsetof(struct new_utsname, name) }
		DEF(sysname),
		DEF(nodename),
		DEF(release),
		DEF(version),
		DEF(machine),
		DEF(domainname)
#undef DEF
	};

	unsigned i;
	kdump_status res;

	for (i = 0; i < ARRAY_SIZE(defs); ++i) {
		struct attr_data *d = gattr(ctx, defs[i].idx);
		const char *s = (const char*)src + defs[i].off;
		if (*s || !attr_isset(d)) {
			res = set_uts_string(ctx, d, s);
			if (res != KDUMP_OK)
				return res;
		}
	}

	return KDUMP_OK;
}

int
uts_looks_sane(struct new_utsname *uts)
{
	/* Since all strings are NUL-terminated, the last byte in
	 * the array must be always zero; domainname may be missing.
	 */
	if (uts->sysname[NEW_UTS_LEN] || uts->nodename[NEW_UTS_LEN] ||
	    uts->release[NEW_UTS_LEN] || uts->version[NEW_UTS_LEN] ||
	    uts->machine[NEW_UTS_LEN])
		return 0;

	/* release, version and machine cannot be empty */
	if (!uts->release[0] || !uts->version[0] || !uts->machine[0])
		return 0;

	/* sysname is kind of a magic signature */
	return !strcmp(uts->sysname, UTS_SYSNAME);
}

int
uncompress_rle(unsigned char *dst, size_t *pdstlen,
	       const unsigned char *src, size_t srclen)
{
	const unsigned char *srcend = src + srclen;
	size_t remain = *pdstlen;

	while (src < srcend) {
		unsigned char byte, cnt;

		if (! (byte = *src++)) {
			if (src >= srcend)
				return -1;
			if ( (cnt = *src++) ) {
				if (remain < cnt)
					return -1;
				if (src >= srcend)
					return -1;
				memset(dst, *src++, cnt);
				dst += cnt;
				remain -= cnt;
				continue;
			}
		}

		if (!remain)
			return -1;
		*dst++ = byte;
		--remain;
	}

	*pdstlen -= remain;
	return 0;
}

#if USE_ZLIB
static kdump_status
set_zlib_error(kdump_ctx_t *ctx, const char *what,
	       const z_stream *zstream, int err)
{
	if (err == Z_ERRNO)
		return set_error(ctx, KDUMP_ERR_SYSTEM, "%s", what);

	if (!zstream->msg)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "%s: error %d", what, err);

	return set_error(ctx, KDUMP_ERR_CORRUPT,
			 "%s: %s", what, zstream->msg);
}
#endif

/**  Uncompress a gzipp'ed page.
 * @param ctx     Dump file object.
 * @param dst     Destination buffer.
 * @param src     Source (compressed) data.
 * @param srclen  Length of source data.
 */
kdump_status
uncompress_page_gzip(kdump_ctx_t *ctx, unsigned char *dst,
		     unsigned char *src, size_t srclen)
{
#if USE_ZLIB
	z_stream zstream;
	int res;

	memset(&zstream, 0, sizeof zstream);
	zstream.next_in = (z_const Bytef *)src;
	zstream.avail_in = srclen;
	zstream.next_out = dst;
	zstream.avail_out = get_page_size(ctx);

	res = inflateInit(&zstream);
	if (res != Z_OK)
		return set_zlib_error(ctx, "Cannot init zlib", &zstream, res);

	res = inflate(&zstream, Z_FINISH);
	if (res != Z_STREAM_END) {
		inflateEnd(&zstream);
		if (res == Z_NEED_DICT ||
		    (res == Z_BUF_ERROR && zstream.avail_in == 0))
			res = Z_DATA_ERROR;
		return set_zlib_error(ctx, "Decompresion failed",
				      &zstream, res);
	}

	res = inflateEnd(&zstream);
	if (res != Z_OK)
		return set_zlib_error(ctx, "Decompression failed",
				      &zstream, res);

	if (zstream.avail_out)
		return set_error(ctx, KDUMP_ERR_CORRUPT,
				 "Wrong uncompressed size: %lu",
				 (unsigned long) zstream.total_out);

	return KDUMP_OK;

#else
	return set_error(ctx, KDUMP_ERR_NOTIMPL,
			 "Unsupported compression method: %s", "zlib");
#endif
}

uint32_t
cksum32(void *buffer, size_t size, uint32_t csum)
{
	uint32_t *p, prevsum;

	for (p = buffer; size >= 4; ++p, size -= 4) {
		prevsum = csum;
		csum += be32toh(*p);
		if (csum < prevsum)
			++csum;
	}

	if (size) {
		unsigned char *pbyte = (unsigned char*)p;
		uint32_t val = 0;
		while (size--)
			val = (val >> 8) | (*pbyte++ << 24);

		prevsum = csum;
		csum += val;
		if (csum < prevsum)
			++csum;
	}

	return csum;
}

/**  Get a symbol value.
 * @param      ctx   Dump object.
 * @param      name  Linux symbol name.
 * @param[out] val   Symbol value, returned on sucess.
 * @returns          Error status.
 *
 * The symbol is resolved using a user-supplied callback. Since the
 * callback may again use a libkdumpfile call, this function must
 * be called without holding any locks.
 */
kdump_status
get_symbol_val(kdump_ctx_t *ctx, const char *name, kdump_addr_t *val)
{
	addrxlat_sym_t sym;
	addrxlat_cb_t *cb;
	addrxlat_status status;

	cb = addrxlat_ctx_get_ecb(ctx->xlatctx);
	if (!cb->sym)
		return set_error(ctx, KDUMP_ERR_NODATA, "NULL callback");

	sym.type = ADDRXLAT_SYM_VALUE;
	sym.args[0] = name;
	status = cb->sym(cb->data, &sym);
	if (status != ADDRXLAT_OK)
		return set_error(ctx, addrxlat2kdump(ctx, status),
				 "Cannot resolve \"%s\"", sym.args[0]);

	*val = sym.val;
	return KDUMP_OK;
}

/**  Get the CPU directory attribute.
 * @param ctx   Dump object.
 * @param cpu   CPU number.
 * @param pdir  Directory attribute, set on success.
 * @returns     Error status.
 *
 * If the directory attribute does not exist yet, it is created.
 */
static kdump_status
cpu_dir(kdump_ctx_t *ctx, unsigned cpu, struct attr_data **pdir)
{
	char cpukey[21];
	size_t keylen;

	keylen = sprintf(cpukey, "%u", cpu);
	*pdir = create_attr_path(ctx->dict, gattr(ctx, GKI_dir_cpu),
				 cpukey, keylen, &dir_template);
	return *pdir
		? KDUMP_OK
		: set_error(ctx, KDUMP_ERR_SYSTEM,
			    "Cannot allocate CPU %u attributes", cpu);
}

/**  Get the CPU register directory attribute.
 * @param ctx   Dump object.
 * @param cpu   CPU number.
 * @param pdir  Directory attribute, set on success.
 * @returns     Error status.
 *
 * If the directory attribute does not exist yet, it is created.
 */
static kdump_status
cpu_regs_dir(kdump_ctx_t *ctx, unsigned cpu, struct attr_data **pdir)
{
	char cpukey[20 + sizeof(".reg")];
	size_t keylen;

	keylen = sprintf(cpukey, "%u.reg", cpu);
	*pdir = create_attr_path(ctx->dict, gattr(ctx, GKI_dir_cpu),
				 cpukey, keylen, &dir_template);
	return *pdir
		? KDUMP_OK
		: set_error(ctx, KDUMP_ERR_SYSTEM,
			    "Cannot allocate CPU %u registers", cpu);
}

/**  Initialize a per-cpu blob attribute.
 * @param ctx   Dump object.
 * @param cpu   CPU number.
 * @param data  Raw binary data.
 * @param size  Size of the binary data in bytes.
 * @param tmpl  Blob attribute template.
 * @returns     Error status.
 */
static kdump_status
init_cpu_blob_attr(kdump_ctx_t *ctx, unsigned cpu,
		   const void *data, size_t size,
		   const struct attr_template *tmpl)
{
	void *buffer;
	struct attr_data *dir, *attr;
	kdump_attr_value_t val;
	kdump_status status;

	status = cpu_dir(ctx, cpu, &dir);
	if (status != KDUMP_OK)
		return status;

	buffer = malloc(size);
	if (!buffer)
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Buffer allocation failed");
	memcpy(buffer, data, size);

	val.blob = internal_blob_new(buffer, size);
	if (!val.blob) {
		free(buffer);
		return set_error(ctx, KDUMP_ERR_SYSTEM,
				 "Blob allocation failed");
	}

	attr = new_attr(ctx->dict, dir, tmpl);
	if (!attr) {
		internal_blob_decref(val.blob);
		return set_error(ctx, status,
				 "Attribute allocation failed");
	}

	status = set_attr(ctx, attr, ATTR_DEFAULT, &val);
	if (status != KDUMP_OK) {
		internal_blob_decref(val.blob);
		return set_error(ctx, status,
				 "Cannot set attribute");
	}

	return status;
}

/**  PRSTATUS blob attribute template. */
static const struct attr_template prstatus_tmpl = {
	.key = "PRSTATUS",
	.type = KDUMP_BLOB,
};

/**  Initialize the PRSTATUS attribute for a CPU
 * @param ctx   Dump object.
 * @param cpu   CPU number.
 * @param data  PRSTATUS raw binary data.
 * @param size  Size of the PRSTATUS data in bytes.
 * @returns     Error status.
 */
kdump_status
init_cpu_prstatus(kdump_ctx_t *ctx, unsigned cpu,
		  const void *data, size_t size)
{
	return init_cpu_blob_attr(ctx, cpu, data, size, &prstatus_tmpl);
}

/**  XEN_PRSTATUS blob attribute template. */
static const struct attr_template xen_prstatus_tmpl = {
	.key = "XEN_PRSTATUS",
	.type = KDUMP_BLOB,
};

/**  Initialize the XEN_PRSTATUS attribute for a CPU
 * @param ctx   Dump object.
 * @param cpu   CPU number.
 * @param data  XEN_PRSTATUS raw binary data.
 * @param size  Size of the XEN_PRSTATUS data in bytes.
 * @returns     Error status.
 */
kdump_status
init_xen_cpu_prstatus(kdump_ctx_t *ctx, unsigned cpu,
		      const void *data, size_t size)
{
	return init_cpu_blob_attr(ctx, cpu, data, size, &xen_prstatus_tmpl);
}

/**  Get the blob corresponding to a derived number attribute.
 * @param ctx   Dump object.
 * @param attr  Derived attribute.
 * @param tmpl  Template of the blob attribute.
 * @param blob  Pointer to the blob variable.
 * @returns     Error status.
 */
static kdump_status
get_attr_blob(kdump_ctx_t *ctx, struct attr_data *attr,
	      const struct attr_template *tmpl, kdump_blob_t **blob)
{
	struct attr_data *raw;
	unsigned i;

	for (i = attr->template->depth; i; --i)
		attr = attr->parent;

	raw = lookup_attr_child(attr->parent, tmpl);
	if (!raw)
		return set_error(ctx, KDUMP_ERR_NODATA,
				 "%s raw attribute not found", tmpl->key);

	*blob = raw->val.blob;
	return KDUMP_OK;
}

/**  Get attribute value from the corresponding blob attribute.
 * @param ctx   Dump object.
 * @param attr  Derived attribute.
 * @param tmpl  Template of the blob attribute.
 * @returns     Error status.
 *
 * Call this from a revalidation hook to update the current value.
 * The attribute's invalid flag is not removed, so the hook will be
 * called for every attribute read.
 */
static kdump_status
derived_attr_revalidate(kdump_ctx_t *ctx, struct attr_data *attr,
			const struct attr_template *tmpl)
{
	const struct derived_attr_def *def = attr_to_derived_def(attr);
	kdump_blob_t *blob;
	kdump_status status;
	void *ptr;

	status = get_attr_blob(ctx, attr, tmpl, &blob);
	if (status != KDUMP_OK)
		return status;

	ptr = internal_blob_pin(blob) + def->offset;
	if (def->offset + def->length > blob->size) {
		status = set_error(ctx, KDUMP_ERR_CORRUPT,
				   "%s attribute too short", tmpl->key);
		goto unpin;
	}

	switch(def->length) {
	case 1:
		attr->val.number = *(uint8_t*)ptr;
		break;
	case 2:
		attr->val.number = dump16toh(ctx, *(uint16_t*)ptr);
		break;
	case 4:
		attr->val.number = dump32toh(ctx, *(uint32_t*)ptr);
		break;
	case 8:
		attr->val.number = dump64toh(ctx, *(uint64_t*)ptr);
		break;
	default:
		status = set_error(ctx, KDUMP_ERR_NOTIMPL,
				   "Reading %hu-byte values not implemented",
				   def->length);
	}

 unpin:
	internal_blob_unpin(blob);
	return status;
}

/**  Update blob after setting a derived attribute's value.
 * @param ctx   Dump object.
 * @param attr  Derived attribute.
 * @param tmpl  Template of the blob attribute.
 * @returns     Error status.
 *
 * Call this from a post-set hook to update the blob attribute.
 * Since a derived attribute's value is always retrieved from the
 * corresponding blob, the blob must be updated to assign a new value.
 */
static kdump_status
derived_attr_update(kdump_ctx_t *ctx, struct attr_data *attr,
		    const struct attr_template *tmpl)
{
	const struct derived_attr_def *def = attr_to_derived_def(attr);
	kdump_blob_t *blob;
	kdump_status status;
	void *ptr;

	if (attr->flags.invalid)
		return KDUMP_OK;

	status = get_attr_blob(ctx, attr, tmpl, &blob);
	if (status != KDUMP_OK)
		return status;

	ptr = internal_blob_pin(blob) + def->offset;
	if (def->offset + def->length > blob->size) {
		status = set_error(ctx, KDUMP_ERR_CORRUPT,
				   "%s attribute too short", tmpl->key);
		goto unpin;
	}

	switch(def->length) {
	case 1:
		*(uint8_t*)ptr = attr->val.number;
		break;
	case 2:
		*(uint16_t*)ptr = htodump16(ctx, attr->val.number);
		break;
	case 4:
		*(uint32_t*)ptr = htodump32(ctx, attr->val.number);
		break;
	case 8:
		*(uint64_t*)ptr = htodump64(ctx, attr->val.number);
		break;
	default:
		status = set_error(ctx, KDUMP_ERR_NOTIMPL,
				   "Writing %hu-byte values not implemented",
				   def->length);
	}
	attr->flags.invalid = 1;

 unpin:
	internal_blob_unpin(blob);
	return status;
}

/**  Create a derived attribute.
 * @param ctx  Dump object.
 * @param dir  Directory containing the blob attribute.
 * @param def  Derived attribute definition.
 * @returns    Error status.
 */
static kdump_status
create_derived_attr(kdump_ctx_t *ctx, struct attr_data *dir,
		    struct derived_attr_def *def)
{
	struct attr_data *attr;
	const char *action;
	kdump_status status;
	unsigned i;

	for (i = 1 - def->tmpl.depth; i; --i)
		dir = dir->parent;

	action = "allocate";
	attr = new_attr(ctx->dict, dir, &def->tmpl);
	if (!attr)
		goto err;

	action = "set";
	status = set_attr_number(ctx, attr, ATTR_INVALID, 0);
	if (status != KDUMP_OK)
		goto err;

	return KDUMP_OK;

err:
	return set_error(ctx, status,
			 "Cannot %s CPU %s register %s",
			 action, dir->template->key, def->tmpl.key);
}

/**  Get register value from the corresponding PRSTATUS attribute.
 * @param ctx   Dump object.
 * @param attr  Register value attribute.
 * @returns     Error status.
 */
static kdump_status
prstatus_reg_revalidate(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return derived_attr_revalidate(ctx, attr, &prstatus_tmpl);
}

/**  Update the PRSTATUS attribute after setting the register value.
 * @param ctx   Dump object.
 * @param attr  Register value attribute.
 * @returns     Error status.
 */
static kdump_status
prstatus_reg_update(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return derived_attr_update(ctx, attr, &prstatus_tmpl);
}

/**  Create a set of CPU register attributes.
 * @param ctx   Dump object.
 * @param cpu   CPU number.
 * @param def   Register definitions (array).
 * @param ndef  Number of entries in the @c def array.
 * @returns     Error status.
 *
 * Use this function to create register attributes under
 * cpu.<num>.reg.  The values are taken from the corresponding
 * cpu.<num>.PRSTATUS blob attribute, using offsets and sizes
 * from the definition array.
 */
kdump_status
create_cpu_regs(kdump_ctx_t *ctx, unsigned cpu,
		struct derived_attr_def *def, unsigned ndef)
{
	static const struct attr_ops prstatus_reg_ops = {
		.revalidate = prstatus_reg_revalidate,
		.post_set = prstatus_reg_update,
	};

	struct attr_data *dir;
	kdump_status status;

	status = cpu_regs_dir(ctx, cpu, &dir);
	while (status == KDUMP_OK && ndef--) {
		def->tmpl.ops = &prstatus_reg_ops;
		status = create_derived_attr(ctx, dir, def++);
	}

	return status;
}

/**  Get register value from the corresponding XEN_PRSTATUS attribute.
 * @param ctx   Dump object.
 * @param attr  Register value attribute.
 * @returns     Error status.
 */
static kdump_status
xen_prstatus_reg_revalidate(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return derived_attr_revalidate(ctx, attr, &xen_prstatus_tmpl);
}

/**  Update the XEN_PRSTATUS attribute after setting the register value.
 * @param ctx   Dump object.
 * @param attr  Register value attribute.
 * @returns     Error status.
 */
static kdump_status
xen_prstatus_reg_update(kdump_ctx_t *ctx, struct attr_data *attr)
{
	return derived_attr_update(ctx, attr, &xen_prstatus_tmpl);
}

/**  Create a set of CPU register attributes.
 * @param ctx   Dump object.
 * @param cpu   CPU number.
 * @param def   Register definitions (array).
 * @param ndef  Number of entries in the @c def array.
 * @returns     Error status.
 *
 * Use this function to create register attributes under
 * cpu.<num>.reg.  The values are taken from the corresponding
 * cpu.<num>.XEN_PRSTATUS blob attribute, using offsets and sizes
 * from the definition array.
 */
kdump_status
create_xen_cpu_regs(kdump_ctx_t *ctx, unsigned cpu,
		    struct derived_attr_def *def, unsigned ndef)
{
	static const struct attr_ops xen_prstatus_reg_ops = {
		.revalidate = xen_prstatus_reg_revalidate,
		.post_set = xen_prstatus_reg_update,
	};

	struct attr_data *dir;
	kdump_status status;

	status = cpu_regs_dir(ctx, cpu, &dir);
	while (status == KDUMP_OK && ndef--) {
		def->tmpl.ops = &xen_prstatus_reg_ops;
		status = create_derived_attr(ctx, dir, def++);
	}

	return status;
}

/**  Set file.description to a static string.
 * @param ctx   Dump file object.
 * @param name  Descriptive format name.
 * @returns     Error status.
 */
kdump_status
set_file_description(kdump_ctx_t *ctx, const char *name)
{
	return set_attr_static_string(ctx, gattr(ctx, GKI_file_description),
				      ATTR_DEFAULT, name);
}
