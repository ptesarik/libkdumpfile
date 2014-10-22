/* Private interfaces for libkdumpfile (kernel coredump file access).
   Copyright (C) 2014 Petr Tesarik <ptesarik@suse.cz>

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

#ifndef _KDUMPFILE_PRIV_H
#define _KDUMPFILE_PRIV_H	1

#include "config.h"
#include "kdumpfile.h"

#include <endian.h>

/* This should cover all possibilities:
 * - no supported architecture has less than 4K pages.
 * - PowerPC can have up to 256K large pages.
 */
#define MIN_PAGE_SIZE	(1UL << 12)
#define MAX_PAGE_SIZE	(1UL << 18)

enum kdump_arch {
	ARCH_UNKNOWN = 0,
	ARCH_ALPHA,
	ARCH_ARM,
	ARCH_IA64,
	ARCH_PPC,
	ARCH_PPC64,
	ARCH_PPC64LE,
	ARCH_S390,
	ARCH_S390X,
	ARCH_X86,
	ARCH_X86_64,
};

typedef kdump_status (*readpage_fn)(kdump_ctx *, kdump_paddr_t);

/* provide our own definition of new_utsname */
#define NEW_UTS_LEN 64
struct new_utsname {
	char sysname[NEW_UTS_LEN + 1];
	char nodename[NEW_UTS_LEN + 1];
	char release[NEW_UTS_LEN + 1];
	char version[NEW_UTS_LEN + 1];
	char machine[NEW_UTS_LEN + 1];
	char domainname[NEW_UTS_LEN + 1];
};

struct _tag_kdump_ctx {
	int fd;			/* dump file descriptor */
	const char *format;	/* file format (descriptive name) */
	unsigned long flags;	/* see DIF_XXX below */

	enum kdump_arch arch;	/* architecture (if known) */
	int endian;		/* __LITTLE_ENDIAN or __BIG_ENDIAN */

	void *buffer;		/* temporary buffer */
	void *page;		/* page data buffer */
	size_t page_size;	/* target page size */
	readpage_fn read_page;	/* method to read dump pages */
	kdump_paddr_t last_pfn;	/* last read PFN */
	kdump_paddr_t max_pfn;	/* max PFN for read_page */

	struct new_utsname utsname;

	void *fmtdata;		/* format-specific private data */
};

/* kdump_ctx flags */
#define DIF_XEN		(1UL<<1)

/* LKCD */
kdump_status kdump_open_lkcd_le(kdump_ctx *ctx);
kdump_status kdump_open_lkcd_be(kdump_ctx *ctx);

/* diskdump/compressed kdump */
kdump_status kdump_open_diskdump(kdump_ctx *ctx);
kdump_status kdump_open_kdump(kdump_ctx *ctx);

/* ELF dumps */
kdump_status kdump_open_elfdump(kdump_ctx *ctx);

/* struct timeval has a different layout on 32-bit and 64-bit */
struct timeval_32 {
	int32_t tv_sec;
	int32_t tv_usec;
};
struct timeval_64 {
	int64_t tv_sec;
	int64_t tv_usec;
};

/* utils */

const size_t kdump_arch_ptr_size(enum kdump_arch arch);

void kdump_copy_uts_string(char *dest, const char *src);
void kdump_copy_uts(struct new_utsname *dest, const struct new_utsname *src);
int kdump_uts_looks_sane(struct new_utsname *uts);

int kdump_uncompress_rle(unsigned char *dst, size_t *pdstlen,
			 const unsigned char *src, size_t srclen);

/* Older glibc didn't have the byteorder macros */
#ifndef be16toh

#include <byteswap.h>

# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htobe16(x) bswap_16(x)
#  define htole16(x) (x)
#  define be16toh(x) bswap_16(x)
#  define le16toh(x) (x)

#  define htobe32(x) bswap_32(x)
#  define htole32(x) (x)
#  define be32toh(x) bswap_32(x)
#  define le32toh(x) (x)

#  define htobe64(x) bswap_64(x)
#  define htole64(x) (x)
#  define be64toh(x) bswap_64(x)
#  define le64toh(x) (x)
# else
#  define htobe16(x) (x)
#  define htole16(x) bswap_16(x)
#  define be16toh(x) (x)
#  define le16toh(x) bswap_16(x)

#  define htobe32(x) (x)
#  define htole32(x) bswap_32(x)
#  define be32toh(x) (x)
#  define le32toh(x) bswap_32(x)

#  define htobe64(x) (x)
#  define htole64(x) bswap_64(x)
#  define be64toh(x) (x)
#  define le64toh(x) bswap_64(x)
# endif
#endif

/* Inline utility functions */

static inline unsigned
bitcount(unsigned x)
{
	return (uint32_t)((((x * 0x08040201) >> 3) & 0x11111111) * 0x11111111)
		>> 28;
}

static inline uint16_t
dump16toh(kdump_ctx *ctx, uint16_t x)
{
	return ctx->endian == __BIG_ENDIAN
		? be16toh(x)
		: le16toh(x);
}

static inline uint32_t
dump32toh(kdump_ctx *ctx, uint32_t x)
{
	return ctx->endian == __BIG_ENDIAN
		? be32toh(x)
		: le32toh(x);
}

static inline uint64_t
dump64toh(kdump_ctx *ctx, uint64_t x)
{
	return ctx->endian == __BIG_ENDIAN
		? be64toh(x)
		: le64toh(x);
}

#endif	/* kdumpfile-priv.h */
