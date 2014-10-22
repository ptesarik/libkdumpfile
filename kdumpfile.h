/* Interfaces for libkdumpfile (kernel coredump file access).
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

#ifndef _KDUMPFILE_H
#define _KDUMPFILE_H	1

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef uint_fast64_t kdump_paddr_t;
typedef struct _tag_kdump_ctx kdump_ctx;
typedef enum _tag_kdump_status {
	kdump_ok = 0,
	kdump_syserr,		/* OS error, see errno */
	kdump_unsupported,	/* unsupported file format */
	kdump_nodata,		/* data is not stored in the dump file */
	kdump_dataerr,		/* corrupted file data */
} kdump_status;

kdump_status kdump_fdopen(kdump_ctx **pctx, int fd);
void kdump_free(kdump_ctx *ctx);

ssize_t kdump_read(kdump_ctx *ctx, kdump_paddr_t paddr,
		   unsigned char *buffer, size_t length);

const char *kdump_format(kdump_ctx *ctx);
size_t kdump_pagesize(kdump_ctx *ctx);

const char *kdump_sysname(kdump_ctx *ctx);
const char *kdump_nodename(kdump_ctx *ctx);
const char *kdump_release(kdump_ctx *ctx);
const char *kdump_version(kdump_ctx *ctx);
const char *kdump_machine(kdump_ctx *ctx);
const char *kdump_domainname(kdump_ctx *ctx);

const char *kdump_vmcoreinfo(kdump_ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif	/* kdumpfile.h */
