/* Functions for the Intel 32-bit (x86) architecture.
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

#define _GNU_SOURCE

#include "kdumpfile-priv.h"

#include <stdint.h>
#include <stdlib.h>
#include <linux/version.h>

/* Maximum virtual address bits (architecture limit) */
#define VIRTADDR_BITS_MAX	32
#define VIRTADDR_MAX		UINT32_MAX

#define __START_KERNEL_map	0xc0000000UL

static kdump_status
ia32_init(kdump_ctx *ctx)
{
	kdump_status ret;

	ret = kdump_set_region(ctx, __START_KERNEL_map, VIRTADDR_MAX,
			       KDUMP_XLAT_DIRECT, __START_KERNEL_map);
	if (ret != kdump_ok)
		return ret;

	return kdump_ok;
}

const struct arch_ops kdump_ia32_ops = {
	.init = ia32_init,
};
