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

/* Must be large enough to hold any possible address type */
typedef uint_fast64_t kdump_addr_t;

#define KDUMP_ADDR_MAX	(~(kdump_addr_t)0)

/* Provide two types to convey phys/virt semantics where possible */
typedef kdump_addr_t kdump_paddr_t;
typedef kdump_addr_t kdump_vaddr_t;

typedef uint_fast64_t kdump_reg_t;

typedef struct _tag_kdump_ctx kdump_ctx;
typedef enum _tag_kdump_status {
	kdump_ok = 0,
	kdump_syserr,		/* OS error, see errno */
	kdump_unsupported,	/* unsupported file format */
	kdump_nodata,		/* data is not stored in the dump file */
	kdump_dataerr,		/* corrupted file data */
} kdump_status;

typedef enum _tag_kdump_byte_order {
	kdump_big_endian,
	kdump_little_endian,
} kdump_byte_order_t;

typedef struct _tag_kdump_xen_version {
	unsigned long major;
	unsigned long minor;
	const char *extra;
} kdump_xen_version_t;

kdump_status kdump_fdopen(kdump_ctx **pctx, int fd);
void kdump_free(kdump_ctx *ctx);

const char *kdump_err_str(kdump_ctx *ctx);

kdump_status kdump_vtop_init(kdump_ctx *ctx);
kdump_status kdump_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			kdump_paddr_t *paddr);

#define KDUMP_PHYSADDR		(1UL<<0)
#define KDUMP_XENMACHADDR	(1UL<<1)
#define KDUMP_KVADDR		(1UL<<2)

ssize_t kdump_read(kdump_ctx *ctx, kdump_addr_t addr,
		   void *buffer, size_t length, long flags);
kdump_status kdump_readp(kdump_ctx *ctx, kdump_addr_t addr,
			 void *buffer, size_t *plength, long flags);
kdump_status kdump_read_string(kdump_ctx *ctx, kdump_addr_t addr,
			       char **pstr, long flags);

const char *kdump_format(kdump_ctx *ctx);
kdump_byte_order_t kdump_byte_order(kdump_ctx *ctx);

/* Return the name of the architecture.
 * Unlike kdump_machine, which may contain the name of a particular
 * platform (e.g. "i586" v. "i686") or may not even be initialised,
 * this function always returns the detected architecture from a fixed
 * list below:
 *   aarch64, alpha, arm, ia64, ppc, ppc64, ppc64le,
 *   s390, s390x, i386, x86_64
 * Note: this function may return NULL if the target architecture
 *       was not detected for some reason.
 */
const char *kdump_arch_name(kdump_ctx *ctx);

int kdump_is_xen(kdump_ctx *ctx);
size_t kdump_pagesize(kdump_ctx *ctx);
unsigned kdump_pageshift(kdump_ctx *ctx);
kdump_paddr_t kdump_phys_base(kdump_ctx *ctx);

const char *kdump_sysname(kdump_ctx *ctx);
const char *kdump_nodename(kdump_ctx *ctx);
const char *kdump_release(kdump_ctx *ctx);
const char *kdump_version(kdump_ctx *ctx);
const char *kdump_machine(kdump_ctx *ctx);
const char *kdump_domainname(kdump_ctx *ctx);
unsigned kdump_version_code (kdump_ctx *ctx);

unsigned kdump_num_cpus(kdump_ctx *ctx);
kdump_status kdump_read_reg(kdump_ctx *ctx, unsigned cpu, unsigned index,
			    kdump_reg_t *value);

const char *kdump_vmcoreinfo(kdump_ctx *ctx);
const char *kdump_vmcoreinfo_xen(kdump_ctx *ctx);

const char *kdump_vmcoreinfo_row(kdump_ctx *ctx, const char *key);
const char *kdump_vmcoreinfo_row_xen(kdump_ctx *ctx, const char *key);

kdump_status kdump_vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname,
				     kdump_addr_t *symvalue);
kdump_status kdump_vmcoreinfo_symbol_xen(kdump_ctx *ctx, const char *symname,
					 kdump_addr_t *symvalue);

void kdump_xen_version(kdump_ctx *ctx, kdump_xen_version_t *version);

#ifdef  __cplusplus
}
#endif

#endif	/* kdumpfile.h */
