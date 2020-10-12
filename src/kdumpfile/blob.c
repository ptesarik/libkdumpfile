/** @internal @file src/kdumpfile/blob.c
 * @brief Binary large objects.
 */
/* Copyright (C) 2020 Petr Tesarik <ptesarik@suse.com>

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
#include <stdlib.h>

kdump_blob_t *
kdump_blob_new(void *data, size_t size)
{
	kdump_blob_t *blob;
	blob = malloc(sizeof(kdump_blob_t));
	if (blob) {
		blob->refcnt = 1;
		blob->pincnt = 0;
		blob->data = data;
		blob->size = size;
	}
	return blob;
}

kdump_blob_t *
kdump_blob_new_dup(const void *data, size_t size)
{
	kdump_blob_t *ret;
	void *newdata;

	if (data) {
		newdata = malloc(size);
		if (!newdata)
			return NULL;
		memcpy(newdata, data, size);
		data = newdata;
	} else
		newdata = NULL;
	ret = internal_blob_new(newdata, size);
	if (!ret && newdata)
		free(newdata);
	return ret;
}

unsigned long
kdump_blob_incref(kdump_blob_t *blob)
{
	return ++blob->refcnt;
}

unsigned long
kdump_blob_decref(kdump_blob_t *blob)
{
	unsigned long refcnt = --blob->refcnt;
	if (!refcnt) {
		if (blob->data)
			free(blob->data);
		free(blob);
	}
	return refcnt;
}

DEFINE_ALIAS(blob_pin);

void *
kdump_blob_pin(kdump_blob_t *blob)
{
	++blob->pincnt;
	return blob->data;
}

DEFINE_ALIAS(blob_unpin);

unsigned long
kdump_blob_unpin(kdump_blob_t *blob)
{
	return --blob->pincnt;
}

size_t
kdump_blob_size(const kdump_blob_t *blob)
{
	return blob->size;
}

kdump_status
kdump_blob_set(kdump_blob_t *blob, void *data, size_t size)
{
	if (blob->pincnt)
		return KDUMP_ERR_BUSY;

	if (blob->data && blob->data != data)
		free(blob->data);

	if (!data)
		size = 0;
	blob->data = data;
	blob->size = size;
	return KDUMP_OK;
}
