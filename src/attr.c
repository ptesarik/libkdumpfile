/* Attribute handling.
   Copyright (C) 2015 Petr Tesarik <ptesarik@suse.cz>

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

#include <stdlib.h>
#include <string.h>

static const struct attr_template global_keys[] = {
#define ATTR(dir, key, field, type, ctype)				\
	[GKI_ ## field] = {						\
		key,							\
		&global_keys[GKI_dir_ ## dir],				\
		kdump_ ## type						\
	},
#include "static-attr.def"
#include "global-attr.def"
#undef ATTR
};

static const size_t static_offsets[] = {
#define ATTR(dir, key, field, type, ctype)		\
	[GKI_ ## field] = offsetof(kdump_ctx, field),
#include "static-attr.def"
#undef ATTR
};

#define NR_GLOBAL	ARRAY_SIZE(global_keys)
#define NR_STATIC	ARRAY_SIZE(static_offsets)

/**  Get a modifiable pointer to the static data with a given index.
 * @param ctx  Dump file object.
 * @param idx  Static index.
 * @returns    Pointer to the actual static attribute data.
 * @sa static_attr_data_const
 */
static inline struct attr_data *
static_attr_data(kdump_ctx *ctx, enum global_keyidx idx)
{
	return (struct attr_data*)((char*)ctx + static_offsets[idx]);
}

/**  Get a const pointer to the static data with a given index.
 * @sa static_attr_data
 */
static inline const struct attr_data *
static_attr_data_const(const kdump_ctx *ctx, enum global_keyidx idx)
{
	return (const struct attr_data*)
		((const char*)ctx + static_offsets[idx]);
}

/**  Check if a template denotes statically allocated attribute
 * @param tmpl  Template.
 * @returns     Non-zero if the template's attribute is static.
 */
static inline int
template_static(const struct attr_template *tmpl)
{
	return tmpl >= &global_keys[0] &&
		tmpl < &global_keys[NR_STATIC];
}

/**  Check if a template matches search criteria.
 * @param tmpl    Template to be checked.
 * @param dir     Template directory.
 * @param key     Key name.
 * @param keylen  Key length.
 */
static inline int
template_match(const struct attr_template *tmpl,
	       const struct attr_template *dir,
	       const char *key, size_t keylen)
{
	return (tmpl->parent == dir &&
		!strncmp(tmpl->key, key, keylen) &&
		tmpl->key[keylen] == '\0');
}

/**  Look up a template by its name in one directory.
 * @param ctx     Dump file object.
 * @param dir     Attribute directory.
 * @param key     Key name.
 * @param keylen  Key length.
 * @returns       Template with the given key, or @c NULL if not found.
 *
 * By specifying the key length, it is possible to search for a
 * component of an attribute path without copying the path string.
 */
static const struct attr_template*
lookup_template_dir(const kdump_ctx *ctx, const struct attr_template *dir,
		    const char *key, size_t keylen)
{
	const struct dyn_attr_template *dt;
	const struct attr_template *t;

	for (dt = ctx->tmpl; dt; dt = dt->next)
		if (template_match(&dt->template, dir, key, keylen))
			return &dt->template;

	for (t = global_keys; t < &global_keys[NR_GLOBAL]; ++t)
		if (template_match(t, dir, key, keylen))
			return t;
	return NULL;
}

/**  Look up the parent of a template by name.
 * @param ctx   Dump file object.
 * @param pkey  Pointer to key name. If the path is found, this pointer
 *              is updated to the last path component on return.
 * @returns     Attribute template of @c key's parent attribute,
 *              or @c NULL if not found.
 */
static const struct attr_template*
lookup_template_parent(const kdump_ctx *ctx, const char **pkey)
{
	const struct attr_template *dir;
	const char *p, *key = *pkey;

	dir = &global_keys[GKI_dir_root];
	while ( (p = strchr(key, '.')) ) {
		dir = lookup_template_dir(ctx, dir, key, p - key);
		if (!dir || dir->type != kdump_directory)
			return NULL; /* directory not found */

		key = p + 1;
	}

	*pkey = key;
	return dir;
}

/**  Lookup attribute value by template.
 * @param ctx   Dump file object.
 * @param tmpl  Attribute template.
 * @returns     Stored attribute or @c NULL if not found.
 */
static const struct attr_data*
lookup_attr_tmpl(const kdump_ctx *ctx, const struct attr_template *tmpl)
{
	const struct attr_data *parent;
	const struct attr_data *d;

	if (template_static(tmpl))
		return static_attr_data_const(ctx, tmpl - global_keys);

	parent = lookup_attr_tmpl(ctx, tmpl->parent);
	if (!parent)
		return NULL;

	for (d = parent->dir; d; d = d->next)
		if (d->template == tmpl)
			return d;
	return NULL;
}

/**  Calculate the hash index of a key path.
 * @param key  Key path.
 * @returns    Desired index in the hash table.
 */
static unsigned
key_hash_index(const char *key)
{
	return fold_hash(string_hash(key), ATTR_HASH_BITS);
}

/**  Calculate the hash index of a partial key path.
 * @param key     Key path.
 * @param keylen  Initial portion of @c key to be considered.
 * @returns       Desired index in the hash table.
 */
static unsigned
part_hash_index(const char *key, size_t keylen)
{
	return fold_hash(mem_hash(key, keylen), ATTR_HASH_BITS);
}

/**  Get the length of an attribute path
 * @param attr  Attribute data.
 * @returns     Length of the full path string.
 *
 * The returned length does not include the terminating NUL character.
 */
static size_t
attr_pathlen(const struct attr_data *attr)
{
	const struct attr_data *d;
	size_t len = 0;

	for (d = attr; d->parent != d; d = d->parent) {
		len += strlen(d->template->key);
		if (d != attr)
			++len;	/* for the separating dot ('.') */
	}
	return len;
}

/**  Construct an attribute's key path.
 * @param attr  Attribute data.
 * @param endp  Pointer to the __end__ of the path buffer.
 * @returns     Beginning of the path buffer.
 *
 * The output buffer must be big enough to hold the full path. You can
 * use @c attr_pathlen to calculate the required length.
 * Note that the resulting path is a NUL-terminated string, and the buffer
 * must also contain space for this terminating NUL character.
 */
static char *
make_attr_path(const struct attr_data *attr, char *endp)
{
	const struct attr_data *d;

	*endp = '\0';
	for (d = attr; d->parent != d; d = d->parent) {
		size_t len = strlen(d->template->key);
		if (d != attr)
			*(--endp) = '.';
		endp -= len;
		memcpy(endp, d->template->key, len);
	}
	return endp;
}

/**  Calculate the hash index of an attribute.
 * @param attr  Attribute data.
 * @returns     Desired index in the hash table.
 */
static unsigned
attr_hash_index(const struct attr_data *attr)
{
	size_t pathlen = attr_pathlen(attr);
	char path[pathlen + 1];

	make_attr_path(attr, path + pathlen);
	return key_hash_index(path);
}

/**  Compare if attribute data correponds to a given key.
 * @param attr  Attribute data.
 * @param key   Key path.
 * @param len   Initial portion of @c key to be considered.
 * @returns     Zero if the data is stored under the given key,
 *              non-zero otherwise.
 */
static int
keycmp(const struct attr_data *attr, const char *key, size_t len)
{
	const char *p;

	while ( (p = memrchr(key, '.', len)) ) {
		size_t partlen = key + len - p - 1;
		int res = strncmp(attr->template->key, p + 1, partlen);
		if (res)
			return res;
		if (attr->template->key[partlen] != '\0')
			return 1;
		attr = attr->parent;
		len = p - key;
	}

	return memcmp(attr->template->key, key, len);
}

/**  Look up attribute value by name.
 * @param ctx     Dump file object.
 * @param key     Key name.
 * @param keylen  Initial portion of @c key to be considered.
 * @returns       Stored attribute or @c NULL if not found.
 */
static struct attr_data*
lookup_attr_part(const kdump_ctx *ctx, const char *key, size_t keylen)
{
	unsigned ehash, i;
	const struct attr_hash *tbl;

	i = part_hash_index(key, keylen);
	ehash = (i + ATTR_HASH_FUZZ) % ATTR_HASH_SIZE;
	do {
		tbl = &ctx->attr;
		do {
			if (!tbl->table[i])
				break;
			if (!keycmp(tbl->table[i], key, keylen))
				return tbl->table[i];
			tbl = tbl->next;
		} while (tbl);
		i = (i + 1) % ATTR_HASH_SIZE;
	} while (i != ehash);

	return NULL;
}

/**  Look up raw attribute data by name.
 * @param ctx   Dump file object.
 * @param key   Key name.
 * @returns     Stored attribute or @c NULL if not found.
 *
 * This function does not check whether an attribute is set, or not.
 */
static struct attr_data *
lookup_attr_raw(const kdump_ctx *ctx, const char *key)
{
	if (!key || key > GATTR(NR_GLOBAL))
		return (struct attr_data*)
			lookup_attr_tmpl(ctx, &global_keys[-(intptr_t)key]);

	return lookup_attr_part(ctx, key, strlen(key));
}

/**  Look up attribute data by name.
 * @param ctx   Dump file object.
 * @param key   Key name.
 * @returns     Stored attribute or @c NULL if not found.
 */
const struct attr_data *
lookup_attr(const kdump_ctx *ctx, const char *key)
{
	const struct attr_data *d = lookup_attr_raw(ctx, key);
	return d && attr_isset(d) ? d : NULL;
}

/**  Allocate a new attribute.
 * @param tmpl   Attribute template.
 */
static struct attr_data*
alloc_attr(const struct attr_template *tmpl)
{
	struct attr_data *ret;

	ret = malloc(sizeof(struct attr_data));
	if (!ret)
		return NULL;

	ret->parent = NULL;
	ret->template = tmpl;
	ret->isset = 0;
	ret->dynstr = 0;
	return ret;
}

/**  Link a new attribute to its parent.
 * @param dir   Parent attribute.
 * @param attr  Complete initialized attribute.
 *
 * This function merely adds the attribute to the dump file object.
 * It does not check for duplicates.
 */
static void
link_attr(struct attr_data *dir, struct attr_data *attr)
{
	/* Link the new node */
	attr->next = dir->dir;
	if (attr != dir)
		dir->dir = attr;
	attr->parent = dir;
}

/**  Add an attribute to the hash table.
 * @param ctx   Dump file object.
 * @param attr  Attribute data.
 * @returns     Error status.
 */
static kdump_status
hash_attr(kdump_ctx *ctx, struct attr_data *attr)
{
	unsigned hash, ehash, i;
	struct attr_hash *tbl, *newtbl;

	i = hash = attr_hash_index(attr);
	ehash = (i + ATTR_HASH_FUZZ) % ATTR_HASH_SIZE;
	do {
		newtbl = &ctx->attr;
		do {
			tbl = newtbl;
			if (!tbl->table[i]) {
				tbl->table[i] = attr;
				return kdump_ok;
			}
			newtbl = tbl->next;
		} while (newtbl);
		i = (i + 1) % ATTR_HASH_SIZE;
	} while (i != ehash);

	newtbl = calloc(1, sizeof(struct attr_hash));
	if (!newtbl)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate hash table");
	newtbl->table[hash] = attr;
	tbl->next = newtbl;

	return kdump_ok;
}

/**  Remove an attribute from the hash table.
 * @param ctx   Dump file object.
 * @param attr  Attribute data.
 */
static void
unhash_attr(kdump_ctx *ctx, const struct attr_data *attr)
{
	unsigned ehash, i;
	struct attr_hash *tbl, *newtbl;

	i = attr_hash_index(attr);
	ehash = (i + ATTR_HASH_FUZZ) % ATTR_HASH_SIZE;
	do {
		for (tbl = &ctx->attr; tbl; tbl = tbl->next)
			if (tbl->table[i] == attr) {
				newtbl = tbl;
				while (newtbl->next)
					newtbl = newtbl->next;
				tbl->table[i] = newtbl->table[i];
				newtbl->table[i] = NULL;
				return;
			}
		i = (i + 1) % ATTR_HASH_SIZE;
	} while (i != ehash);

	/* Not hashed? This should never happen. */
}

/**  Free all memory associated with an attribute.
 * @param ctx   Dump file object.
 * @param attr  The attribute to be freed (detached).
 */
static void
free_attr(kdump_ctx *ctx, struct attr_data *attr)
{
	if (attr->template->type == kdump_directory) {
		struct attr_data *node = attr->dir;
		while (node) {
			struct attr_data *next = node->next;
			free_attr(ctx, node);
			node = next;
		}
	}

	attr->isset = 0;
	if (attr->parent)
		unhash_attr(ctx, attr);
	if (attr->dynstr) {
		attr->dynstr = 0;
		free((void*)attr->val.string);
	}
	if (!template_static(attr->template))
		free(attr);
}

/**  Delete an attribute.
 * @param ctx   Dump file object.
 * @param attr  Attribute to be deleted.
 *
 * Remove an attribute from its dump file object and free it.
 */
static void
delete_attr(kdump_ctx *ctx, struct attr_data *attr)
{
	struct attr_data **d;
	d = &attr->parent->dir;
	while (*d && *d != attr)
		d = &(*d)->next;
	if (*d)
		*d = attr->next;
	free_attr(ctx, attr);
}

/**  Add an attribute template.
 * @param ctx   Dump file object.
 */
kdump_status
add_attr_template(kdump_ctx *ctx, const char *path,
		  enum kdump_attr_type type)
{
	const struct attr_template *parent, *t;
	struct dyn_attr_template *dt;
	struct attr_data *attrparent, *attr;
	char *keyname;
	kdump_status res;

	parent = lookup_template_parent(ctx, &path);
	if (!parent)
		return set_error(ctx, kdump_nokey, "No such path");

	if (parent->type != kdump_directory)
		return set_error(ctx, kdump_invalid,
				 "Path is a leaf attribute");

	t = lookup_template_dir(ctx, parent, path, strlen(path));
	if (t)
		return set_error(ctx,
				 (t->type == type ? kdump_ok : kdump_invalid),
				 "Type conflict with existing template");

	dt = malloc(sizeof *dt + strlen(path) + 1);
	if (!dt)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate attribute template");

	keyname = (char*) (dt + 1);
	strcpy(keyname, path);
	dt->template.key = keyname;
	dt->template.parent = parent;
	dt->template.type = type;

	attrparent = (struct attr_data*) lookup_attr_tmpl(ctx, parent);
	if (!attrparent) {
		free(dt);
		return set_error(ctx, kdump_nokey, "No such path");
	}

	attr = alloc_attr(&dt->template);
	if (!attr) {
		free(dt);
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate attribute stub");
	}
	if (type == kdump_directory)
		attr->dir = NULL;

	link_attr(attrparent, attr);
	res = hash_attr(ctx, attr);
	if (res != kdump_ok) {
		free_attr(ctx, attr);
		free(dt);
		return set_error(ctx, res,
				 "Cannot hash attribute stub");
	}

	dt->next = ctx->tmpl;
	ctx->tmpl = dt;

	return kdump_ok;
}

/**  Instantiate a directory path.
 * @param attr  Leaf attribute.
 * @returns     The newly instantiated attribute,
 *              or @c NULL on allocation failure.
 *
 * Inititalize all paths up the hierarchy for the (leaf) directory
 * denoted by @c tmpl.
 */
static void
instantiate_path(struct attr_data *attr)
{
	while (!attr_isset(attr)) {
		attr->isset = 1;
		if (attr == attr->parent)
			break;
		attr = attr->parent;
	}
}

/**  Clear (unset) all attributes.
 * @param ctx   Dump file object.
 */
void
clear_attrs(kdump_ctx *ctx)
{
	if (attr_isset(&ctx->dir_root))
		free_attr(ctx, &ctx->dir_root);
}

/**  Free all memory used by attributes.
 * @param ctx  Dump file object.
 */
void
cleanup_attr(kdump_ctx *ctx)
{
	struct attr_hash *tbl, *tblnext;
	struct dyn_attr_template *dt, *dtnext;

	clear_attrs(ctx);

	tblnext = ctx->attr.next;
	while(tblnext) {
		tbl = tblnext;
		tblnext = tbl->next;
		free(tbl);
	}
	ctx->attr.next = NULL;

	dtnext = ctx->tmpl;
	while(dtnext) {
		dt = dtnext;
		dtnext = dt->next;
		free(dt);
	}
	ctx->tmpl = NULL;
}

/**  Initialize statically allocated attributes
 */
kdump_status
init_attrs(kdump_ctx *ctx)
{
	struct attr_data *attrs[NR_GLOBAL];
	enum global_keyidx i;
	kdump_status res;

	for (i = 0; i < NR_GLOBAL; ++i) {
		const struct attr_template *tmpl = &global_keys[i];
		struct attr_data *attr;

		if (i < NR_STATIC) {
			attr = static_attr_data(ctx, i);
			attr->template = tmpl;
		} else {
			attr = alloc_attr(tmpl);
			if (!attr)
				return kdump_syserr;
		}

		if (tmpl->type == kdump_directory)
			attr->dir = NULL;

		attrs[i] = attr;
		link_attr(attrs[tmpl->parent - global_keys], attr);
		res = hash_attr(ctx, attr);
		if (res != kdump_ok)
			return res;
	}

	return kdump_ok;
}

/**  Replace an attribute.
 * @param ctx     Dump file object.
 * @param parent  Parent attribute.
 * @param attr    New attribute data.
 *
 * Replace an attribute node under @c parent with @c attr. If the
 * given attribute does not exist yet, @c attr is simply added under
 * @c parent. Otherwise, the old attribute is deleted first.
 */
static void
replace_attr(kdump_ctx *ctx, struct attr_data *parent, struct attr_data *attr)
{
	struct attr_data *old;

	for (old = parent->dir; old; old = old->next)
		if (old->template == attr->template) {
			delete_attr(ctx, old);
			break;
		}

	link_attr(parent, attr);
}

/**  Set an attribute of a dump file object.
 * @param ctx   Dump file object.
 * @param attr  Attribute (detached).
 * @returns     Error status (see below).
 *
 * This function works both for statically allocated and dynamically
 * allocated attributes.
 */
void
set_attr(struct attr_data *attr)
{
	instantiate_path(attr->parent);
	attr->isset = 1;
}

/**  Set a numeric attribute of a dump file object.
 * @param ctx  Dump file object.
 * @param key  Key name.
 * @param num  Key value (numeric).
 * @returns    Error status.
 */
kdump_status
set_attr_number(kdump_ctx *ctx, const char *key, kdump_num_t num)
{
	struct attr_data *attr;

	attr = lookup_attr_raw(ctx, key);
	if (!attr)
		return set_error(ctx, kdump_nokey, "No such key");

	attr->val.number = num;
	set_attr(attr);
	return kdump_ok;
}

/**  Set an address attribute of a dump file object.
 * @param ctx   Dump file object.
 * @param key   Key name.
 * @param addr  Key value (address).
 * @returns     Error status.
 */
kdump_status
set_attr_address(kdump_ctx *ctx, const char *key, kdump_addr_t addr)
{
	struct attr_data *attr;

	attr = lookup_attr_raw(ctx, key);
	if (!attr)
		return set_error(ctx, kdump_nokey, "No such key");

	attr->val.address = addr;
	set_attr(attr);
	return kdump_ok;
}

/**  Set a string attribute of a dump file object.
 * @param ctx  Dump file object.
 * @param key  Key name.
 * @param str  Key value (string).
 * @returns    Error status.
 */
kdump_status
set_attr_string(kdump_ctx *ctx, const char *key, const char *str)
{
	struct attr_data *attr;
	char *dynstr;

	dynstr = strdup(str);
	if (!dynstr)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate string");

	attr = lookup_attr_raw(ctx, key);
	if (!attr) {
		free(dynstr);
		return set_error(ctx, kdump_nokey, "No such key");
	}

	if (attr->dynstr)
		free((void*)attr->val.string);

	attr->dynstr = 1;
	attr->val.string = dynstr;
	set_attr(attr);
	return kdump_ok;
}

/**  Set a static string attribute of a dump file object.
 * @param ctx  Dump file object.
 * @param key  Key name.
 * @param str  Key value (static string).
 * @returns    Error status.
 */
kdump_status
set_attr_static_string(kdump_ctx *ctx, const char *key, const char *str)
{
	struct attr_data *attr;

	attr = lookup_attr_raw(ctx, key);
	if (!attr)
		return set_error(ctx, kdump_nokey, "No such key");

	if (attr->dynstr)
		free((void*) attr->val.string);

	attr->dynstr = 0;
	attr->val.string = str;
	set_attr(attr);
	return kdump_ok;
}

/**  Add an attribute to any directory.
 * @param ctx   Dump file object.
 * @param path  Key name.
 * @param attr  Attribute data.
 * @returns     Newly allocated attr_data, or @c NULL on failure.
 */
kdump_status
add_attr(kdump_ctx *ctx, const char *path, struct attr_data *attr)
{
	struct attr_data *parent;

	parent = (struct attr_data*) lookup_attr_raw(ctx, path);
	if (!parent)
		return set_error(ctx, kdump_nokey,
				 "No such path");
	if (parent->template->type != kdump_directory)
		return set_error(ctx, kdump_invalid,
				 "Path is a leaf attribute");

	instantiate_path(parent);
	replace_attr(ctx, parent, attr);
	attr->isset = 1;
	return hash_attr(ctx, attr);
}

/**  Add a numeric attribute to a directory.
 * @param ctx   Dump file object.
 * @param path  Key name.
 * @param tmpl  Attribute template.
 * @param num   Key value (numeric).
 * @returns     Newly allocated attr_data, or @c NULL on failure.
 *
 * This is a wrapper around @c add_attr. It also generates a good enough
 * error message, so callers don't have to provide their own.
 */
kdump_status
add_attr_number(kdump_ctx *ctx, const char *path,
		const struct attr_template *tmpl, kdump_num_t num)
{
	struct attr_data *attr;
	kdump_status res;

	attr = alloc_attr(tmpl);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate attribute");

	attr->val.number = num;
	res = add_attr(ctx, path, attr);
	if (res != kdump_ok)
		free_attr(ctx, attr);

	return set_error(ctx, res,
			 "Cannot set '%s.%s'", path, tmpl->key);
}

/**  Add a string attribute to a directory.
 * @param ctx   Dump file object.
 * @param path  Key name.
 * @param tmpl  Attribute template.
 * @param str   Key value (string).
 * @returns     Newly allocated attr_data, or @c NULL on failure.
 *
 * This is a wrapper around @c add_attr. It also generates a good enough
 * error message, so callers don't have to provide their own.
 */
kdump_status
add_attr_string(kdump_ctx *ctx, const char *path,
		const struct attr_template *tmpl, const char *str)
{
	struct attr_data *attr;
	char *dynstr;
	kdump_status res;

	dynstr = strdup(str);
	if (!dynstr)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate string");

	attr = alloc_attr(tmpl);
	if (!attr) {
		free(dynstr);
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate attribute");
	}

	attr->dynstr = 1;
	attr->val.string = dynstr;
	res = add_attr(ctx, path, attr);
	if (res != kdump_ok)
		free_attr(ctx, attr);

	return set_error(ctx, res,
			 "Cannot set '%s.%s'", path, tmpl->key);
}

/**  Add a static string attribute to a directory.
 * @param ctx   Dump file object.
 * @param path  Key name.
 * @param tmpl  Attribute template.
 * @param str   Key value (static string).
 * @returns     Newly allocated attr_data, or @c NULL on failure.
 *
 * This is a wrapper around @c add_attr. It also generates a good enough
 * error message, so callers don't have to provide their own.
 */
kdump_status add_attr_static_string(kdump_ctx *ctx, const char *path,
				    const struct attr_template *tmpl,
				    const char *str)
{
	struct attr_data *attr;
	kdump_status res;

	attr = alloc_attr(tmpl);
	if (!attr)
		return set_error(ctx, kdump_syserr,
				 "Cannot allocate attribute");

	attr->val.string = str;
	res = add_attr(ctx, path, attr);
	if (res != kdump_ok)
		free_attr(ctx, attr);

	return set_error(ctx, res,
			 "Cannot set '%s.%s'", path, tmpl->key);
}
