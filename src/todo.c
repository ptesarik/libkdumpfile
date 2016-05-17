/** @internal @file src/todo.c
 * @brief TODO items - formats which are not yet supported.
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

#include <string.h>

static kdump_status
qemu_probe(kdump_ctx *ctx, void *hdr)
{
	static const char magic[] =
		{ 'Q', 'E', 'V', 'M' };

	if (memcmp(hdr, magic, sizeof magic))
		return kdump_noprobe;

	set_file_description(ctx, "QEMU snapshot");
	return set_error(ctx, kdump_unsupported,
			 "%s files not yet implemented", "QEMU snapshot");
}

const struct format_ops qemu_ops = {
	.name = "qemu",
	.probe = qemu_probe,
};

static kdump_status
libvirt_probe(kdump_ctx *ctx, void *hdr)
{
	static const char magic[] =
		{ 'L', 'i', 'b', 'v' };

	if (memcmp(hdr, magic, sizeof magic))
		return kdump_noprobe;

	set_file_description(ctx, "Libvirt core dump");
	return set_error(ctx, kdump_unsupported,
			 "%s files not yet implemented", "Libvirt core dump");
}

const struct format_ops libvirt_ops = {
	.name = "libvirt",
	.probe = libvirt_probe,
};

static kdump_status
xc_save_probe(kdump_ctx *ctx, void *hdr)
{
	static const char magic[] =
		{ 'L', 'i', 'n', 'u', 'x', 'G', 'u', 'e',
		  's', 't', 'R', 'e', 'c', 'o', 'r', 'd' };

	if (memcmp(hdr, magic, sizeof magic))
		return kdump_noprobe;

	set_file_description(ctx, "Xen xc_save");
	return set_error(ctx, kdump_unsupported,
			 "%s files not yet implemented", "Xen xc_save");
}

const struct format_ops xc_save_ops = {
	.name = "xc_save",
	.probe = xc_save_probe,
};

static kdump_status
xc_core_probe(kdump_ctx *ctx, void *hdr)
{
	static const char magic[] =
		{ 0xeb, 0x0f, 0xf0 };
	unsigned char firstbyte;

	if (memcmp(hdr + 1, magic, sizeof magic))
		return kdump_noprobe;

	firstbyte = *(unsigned char*)hdr;
	if (firstbyte == 0xed)
		set_file_description(ctx, "Xen xc_core");
	else if (firstbyte == 0xee)
		set_file_description(ctx, "Xen xc_core (HVM)");
	else
		return kdump_noprobe;

	return set_error(ctx, kdump_unsupported,
			 "%s files not yet implemented", "Xen xc_core");
}

const struct format_ops xc_core_ops = {
	.name = "xc_core",
	.probe = xc_core_probe,
};

static kdump_status
mclxcd_probe(kdump_ctx *ctx, void *hdr)
{
	static const char magic[] =
		{ 0xdd, 0xcc, 0x8b, 0x9a };

	if (memcmp(hdr, magic, sizeof magic))
		return kdump_noprobe;

	set_file_description(ctx, "Mision Critical Linux Crash Dump");
	return set_error(ctx, kdump_unsupported,
			 "%s files not yet implemented",
			 "Mision Critical Linux Crash Dump");
}

const struct format_ops mclxcd_ops = {
	.name = "mclxcd",
	.probe = mclxcd_probe,
};
