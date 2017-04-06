/** @internal @file src/attr.c
 * @brief Attribute handling.
 */
/* Copyright (C) 2015 Petr Tesarik <ptesarik@suse.cz>

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

/** Generic directory attribute template. */
const struct attr_template dir_template = {
	.type = KDUMP_DIRECTORY,
};

#define KDUMP_nil	KDUMP_NIL
#define KDUMP_directory	KDUMP_DIRECTORY
#define KDUMP_number	KDUMP_NUMBER
#define KDUMP_address	KDUMP_ADDRESS
#define KDUMP_string	KDUMP_STRING

static const struct attr_template global_keys[] = {
#define ATTR(dir, key, field, type, ctype, ...)				\
	[GKI_ ## field] = {						\
		key,							\
		&global_keys[GKI_dir_ ## dir],				\
		KDUMP_ ## type,						\
		##__VA_ARGS__						\
	},
#include "static-attr.def"
#include "global-attr.def"
#undef ATTR
};

static const size_t static_offsets[] = {
#define ATTR(dir, key, field, type, ctype, ...)				\
	[GKI_ ## field - GKI_static_first] =				\
		offsetof(struct kdump_shared, field),
#include "static-attr.def"
#undef ATTR
};

/**  Get a pointer to the static value with a given index.
 * @param shared  Dump file shared data.
 * @param idx     Static index.
 * @returns       Pointer to the static attribute value.
 */
static inline kdump_attr_value_t *
static_attr_value(struct kdump_shared *shared, enum global_keyidx idx)
{
	return (kdump_attr_value_t *)
		((char*)shared + static_offsets[idx - GKI_static_first]);
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

/**  Compare if attribute data correponds to a key relative to base.
 * @param attr  Attribute data.
 * @param dir   Base directory attribute.
 * @param key   Key path.
 * @param len   Initial portion of @c key to be considered.
 * @returns     Zero if the data is stored under the given key,
 *              non-zero otherwise.
 */
static int
keycmp(const struct attr_data *attr, const struct attr_data *dir,
       const char *key, size_t len)
{
	const char *p;
	size_t partlen;
	int res;

	do {
		p = memrchr(key, '.', len) ?: key - 1;
		partlen = key + len - p - 1;
		res = strncmp(attr->template->key, p + 1, partlen);
		if (res)
			return res;
		if (attr->template->key[partlen] != '\0')
			return 1;
		attr = attr->parent;
		len = p - key;
	} while (p > key);

	return attr == dir ? 0 : 1;
}

/**  Update a partial hash with an attribute directory path.
 * @param ph   Partial hash state.
 * @param dir  (Leaf) attribute directory attribute.
 *
 * Note that this function's intended use is a lookup under the
 * directory, and the hash includes a terminating dot ("."). This
 * may not be particularly useful for other purposes, but is good
 * enough for the intended one and simplifies the implementation.
 */
static void
path_hash(struct phash *ph, const struct attr_data *dir)
{
	const struct attr_template *tmpl;
	if (dir->parent != dir) {
		path_hash(ph, dir->parent);
		tmpl = dir->template;
		phash_update(ph, tmpl->key, strlen(tmpl->key));
		phash_update(ph, ".", 1);
	}
}

/**  Look up a child attribute of a given directory.
 * @param shared  Dump file shared data.
 * @param dir     Directory attribute.
 * @param key     Key name relative to @p dir.
 * @param keylen  Initial portion of @c key to be considered.
 * @returns       Stored attribute or @c NULL if not found.
 */
struct attr_data *
lookup_dir_attr(const struct kdump_shared *shared,
		const struct attr_data *dir,
		const char *key, size_t keylen)
{
	struct phash ph;
	unsigned ehash, i;
	struct attr_hash *tbl;

	phash_init(&ph);
	path_hash(&ph, dir);
	phash_update(&ph, key, keylen);
	i = fold_hash(phash_value(&ph), ATTR_HASH_BITS);
	ehash = (i + ATTR_HASH_FUZZ) % ATTR_HASH_SIZE;
	do {
		tbl = shared->attr;
		do {
			struct attr_data *d = &tbl->table[i];
			if (!d->parent)
				break;
			if (!keycmp(d, dir, key, keylen))
				return d;
			tbl = tbl->next;
		} while (tbl);
		i = (i + 1) % ATTR_HASH_SIZE;
	} while (i != ehash);

	return NULL;
}

/**  Look up attribute value by name.
 * @param shared  Dump file shared data.
 * @param key     Key name.
 * @param keylen  Initial portion of @c key to be considered.
 * @returns       Stored attribute or @c NULL if not found.
 */
static struct attr_data*
lookup_attr_part(const struct kdump_shared *shared,
		 const char *key, size_t keylen)
{
	return lookup_dir_attr(shared, sgattr(shared, GKI_dir_root),
			       key, keylen);
}

/**  Look up attribute data by name.
 * @param shared  Dump file shared data.
 * @param key     Key name, or @c NULL for the root attribute.
 * @returns       Stored attribute or @c NULL if not found.
 *
 * This function does not check whether an attribute is set, or not.
 */
struct attr_data *
lookup_attr(const struct kdump_shared *shared, const char *key)
{
	return key
		? lookup_attr_part(shared, key, strlen(key))
		: sgattr(shared, GKI_dir_root);
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

/**  Allocate an attribute from the hash table.
 * @param shared  Dump file shared data.
 * @param parent  Parent directory, or @c NULL.
 * @param tmpl    Attribute template.
 * @returns       Attribute data, or @c NULL on allocation failure.
 */
static struct attr_data *
alloc_attr(struct kdump_shared *shared, struct attr_data *parent,
	   const struct attr_template *tmpl)
{
	struct attr_data tmp;
	size_t pathlen;
	char *path;
	unsigned hash, ehash, i;
	struct attr_hash *tbl, **pnext;

	tmp.parent = parent ?: &tmp;
	tmp.template = tmpl;
	pathlen = attr_pathlen(&tmp);
	path = alloca(pathlen + 1);
	make_attr_path(&tmp, path + pathlen);

	i = hash = key_hash_index(path);
	ehash = (i + ATTR_HASH_FUZZ) % ATTR_HASH_SIZE;
	do {
		pnext = &shared->attr;
		while (*pnext) {
			tbl = *pnext;
			if (!tbl->table[i].parent)
				return &tbl->table[i];
			pnext = &tbl->next;
		}
		i = (i + 1) % ATTR_HASH_SIZE;
	} while (i != ehash);

	tbl = calloc(1, sizeof(struct attr_hash));
	if (!tbl)
		return NULL;
	tbl->next = *pnext;
	*pnext = tbl;

	return &tbl->table[hash];
}

/**  Clear (unset) a single attribute.
 * @param ctx   Dump file object.
 * @param attr  Attribute to be cleared.
 *
 * This function should be used only for attributes without any
 * children.
 */
static void
clear_single_attr(kdump_ctx_t *ctx, struct attr_data *attr)
{
	const struct attr_ops *ops = attr->template->ops;
	if (ops && ops->pre_clear)
		ops->pre_clear(ctx, attr);

	attr->flags.isset = 0;
	if (attr->flags.dynstr) {
		attr->flags.dynstr = 0;
		free((void*) attr_value(attr)->string);
	}
}

/**  Clear (unset) any attribute and its children recursively.
 * @param ctx   Dump file object.
 * @param attr  Attribute to be cleared.
 */
void
clear_attr(kdump_ctx_t *ctx, struct attr_data *attr)
{
	struct attr_data *child;

	if (attr->template->type == KDUMP_DIRECTORY)
		for (child = attr->dir; child; child = child->next)
			clear_attr(ctx, child);

	clear_single_attr(ctx, attr);
}

/**  Clear (unset) a volatile attribute and its children recursively.
 * @param ctx   Dump file object.
 * @param attr  Attribute to be cleared.
 * @returns     Non-zero if the entry could not be cleared.
 *
 * It is not possible to clear a persistent attribute, or a directory
 * attribute which contains at least one persistent attribute.
 */
static unsigned
clear_volatile(kdump_ctx_t *ctx, struct attr_data *attr)
{
	struct attr_data *child;
	unsigned persist;

	persist = attr->flags.persist;
	if (attr->template->type == KDUMP_DIRECTORY)
		for (child = attr->dir; child; child = child->next)
			persist |= clear_volatile(ctx, child);

	if (!persist)
		clear_single_attr(ctx, attr);
	return persist;
}

/**  Clear (unset) all volatile attributes.
 * @param ctx   Dump file object.
 */
void
clear_volatile_attrs(kdump_ctx_t *ctx)
{
	clear_volatile(ctx, gattr(ctx, GKI_dir_root));
}

/**  Deallocate attribute (and its children).
 * @param attr  Attribute data to be deallocated.
 */
void
dealloc_attr(struct attr_data *attr)
{
	struct attr_data *child;
	if (attr->template->type == KDUMP_DIRECTORY)
		for (child = attr->dir; child; child = child->next)
			dealloc_attr(child);

	if (attr->flags.dynstr)
		free((void*) attr_value(attr)->string);
	if (attr->tflags.dyntmpl)
		free((void*) attr->template);
	attr->parent = NULL;
}

/**  Allocate a new attribute in any directory.
 * @param shared  Dump file shared data.
 * @param parent  Parent directory. If @c NULL, create a self-owned
 *                attribute (root directory).
 * @param tmpl    Attribute template.
 * @returns       Attribute data, or @c NULL on allocation failure.
 */
struct attr_data *
new_attr(struct kdump_shared *shared, struct attr_data *parent,
	 const struct attr_template *tmpl)
{
	struct attr_data *attr;

	attr = alloc_attr(shared, parent, tmpl);
	if (!attr)
		return attr;

	memset(attr, 0, sizeof *attr);
	attr->template = tmpl;
	if (!parent)
		parent = attr;
	link_attr(parent, attr);
	return attr;
}

/**  Allocate an attribute template.
 * @param tmpl    Attribute type template.
 * @param key     Key name.
 * @param keylen  Key length (maybe partial).
 * @returns       Newly allocated attribute template, or @c NULL.
 *
 * All template fields except the key name are copied from @p tmpl.
 */
struct attr_template *
alloc_attr_template(const struct attr_template *tmpl,
		    const char *key, size_t keylen)
{
	struct attr_template *ret;

	ret = malloc(sizeof *ret + keylen + 1);
	if (ret) {
		char *retkey;

		*ret = *tmpl;
		retkey = (char*) (ret + 1);
		memcpy(retkey, key, keylen);
		retkey[keylen] = '\0';
		ret->key = retkey;
	}
	return ret;
}

/** Create an attribute including full path.
 * @param shared  Dump file shared data.
 * @param dir     Base directory.
 * @param path    Path under @p dir.
 * @param pathlen Length of @p path (maybe partial).
 * @param atmpl   Attribute template.
 * @returns       Attribute data, or @c NULL on allocation failure.
 *
 * Look up the attribute @p path under @p dir. If the attribute does not
 * exist yet, create it with type @p type. If @p path contains dots, then
 * all path elements are also created as necessary.
 */
struct attr_data *
create_attr_path(struct kdump_shared *shared, struct attr_data *dir,
		 const char *path, size_t pathlen,
		 const struct attr_template *atmpl)
{
	const char *p, *endp, *endpath;
	struct attr_data *attr;
	struct attr_template *tmpl;

	p = endp = endpath = path + pathlen;
	while (! (attr = lookup_dir_attr(shared, dir, path, endp - path)) )
		if (! (endp = memrchr(path, '.', endp - path)) ) {
			endp = path - 1;
			attr = dir;
			break;
		}

	while (endp && endp != endpath) {
		p = endp + 1;
		endp = memchr(p, '.', endpath - p);

		tmpl = endp
			? alloc_attr_template(&dir_template, p, endp - p)
			: alloc_attr_template(atmpl, p, endpath - p);
		if (!tmpl)
			return NULL;
		attr = new_attr(shared, attr, tmpl);
		if (!attr) {
			free(tmpl);
			return NULL;
		}
		attr->tflags.dyntmpl = 1;
	}

	return attr;
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
		attr->flags.isset = 1;
		if (attr == attr->parent)
			break;
		attr = attr->parent;
	}
}

/**  Free all memory used by attributes.
 * @param shared  Shared data of a dump file object.
 */
void
cleanup_attr(struct kdump_shared *shared)
{
	struct attr_hash *tbl, *tblnext;

	dealloc_attr(sgattr(shared, GKI_dir_root));

	tblnext = shared->attr;
	while(tblnext) {
		tbl = tblnext;
		tblnext = tbl->next;
		free(tbl);
	}
	shared->attr = NULL;
}

/**  Initialize global attributes
 * @param shared  Shared data of a dump file object.
 * @returns       Global attribute array, or @c NULL on allocation failure.
 */
struct attr_data **
init_attrs(struct kdump_shared *shared)
{
	enum global_keyidx i;

	for (i = 0; i < NR_GLOBAL_ATTRS; ++i) {
		const struct attr_template *tmpl = &global_keys[i];
		struct attr_data *attr, *parent;

		parent = shared->global_attrs[tmpl->parent - global_keys];
		attr = new_attr(shared, parent, tmpl);
		if (!attr)
			return NULL;
		shared->global_attrs[i] = attr;

		if (i >= GKI_static_first && i <= GKI_static_last) {
			attr->flags.indirect = 1;
			attr->pval = static_attr_value(shared, i);
		}
	}

	return shared->global_attrs;
}

/**  Check whether an attribute has a given value.
 * @param attr    Attribute data.
 * @param newval  Checked value.
 * @returns       Non-zero if attribute already has this value,
 *                zero otherwise.
 */
static int
attr_has_value(struct attr_data *attr, kdump_attr_value_t newval)
{
	const kdump_attr_value_t *oldval = attr_value(attr);

	if (!attr_isset(attr))
		return 0;

	switch (attr->template->type) {
	case KDUMP_DIRECTORY:
		return 1;

	case KDUMP_NUMBER:
		return oldval->number == newval.number;

	case KDUMP_ADDRESS:
		return oldval->address == newval.address;

	case KDUMP_STRING:
		return !strcmp(oldval->string, newval.string);

	case KDUMP_NIL:
	default:
		return 0;	/* Should not happen */
	}
}

/**  Set an attribute of a dump file object.
 * @param ctx      Dump file object.
 * @param attr     Attribute data.
 * @param flags    New attribute value flags.
 * @param pval     Pointer to new attribute value (ignored for directories).
 * @returns        Error status.
 *
 * Note that the @c flags.indirect has a slightly different meaning:
 *
 * - If the flag is set, @p pval is set as the value location for @p attr.
 * - If the flag is clear, the value of @p attr is changed, but the value
 *   of @c attr->flags.indirect is left unmodified.
 *
 * The idea is that you set @c flags.indirect, if @p pval should become
 * the new indirect value of @p attr. If you want to modify only the value
 * of @p attr, leave @c flags.indirect clear.
 */
kdump_status
set_attr(kdump_ctx_t *ctx, struct attr_data *attr,
	 struct attr_flags flags, kdump_attr_value_t *pval)
{
	int skiphooks = attr_has_value(attr, *pval);
	kdump_status res;

	if (!skiphooks) {
		const struct attr_ops *ops = attr->template->ops;
		if (ops && ops->pre_set &&
		    (res = ops->pre_set(ctx, attr, pval)) != KDUMP_OK) {
			if (flags.dynstr)
				free((void*) pval->string);
			return res;
		}
	}

	instantiate_path(attr->parent);

	if (attr->template->type != KDUMP_DIRECTORY) {
		if (attr->flags.dynstr)
			free((void*) attr_value(attr)->string);

		if (flags.indirect)
			attr->pval = pval;
		else if (attr->flags.indirect) {
			flags.indirect = 1;
			*attr->pval = *pval;
		} else
			attr->val = *pval;
	}
	flags.isset = 1;
	attr->flags = flags;

	if (!skiphooks) {
		const struct attr_ops *ops = attr->template->ops;
		if (ops && ops->post_set &&
		    (res = ops->post_set(ctx, attr)) != KDUMP_OK)
			return res;
	}

	return KDUMP_OK;
}

/**  Set a numeric attribute of a dump file object.
 * @param ctx      Dump file object.
 * @param attr     Attribute data.
 * @param flags    New attribute value flags.
 * @param num      Key value (numeric).
 * @returns        Error status.
 */
kdump_status
set_attr_number(kdump_ctx_t *ctx, struct attr_data *attr,
		struct attr_flags flags, kdump_num_t num)
{
	kdump_attr_value_t val;

	val.number = num;
	return set_attr(ctx, attr, flags, &val);
}

/**  Set an address attribute of a dump file object.
 * @param ctx      Dump file object.
 * @param attr     Attribute data.
 * @param flags    New attribute value flags.
 * @param addr     Key value (address).
 * @returns        Error status.
 */
kdump_status
set_attr_address(kdump_ctx_t *ctx, struct attr_data *attr,
		 struct attr_flags flags, kdump_addr_t addr)
{
	kdump_attr_value_t val;

	val.address = addr;
	return set_attr(ctx, attr, flags, &val);
}

/**  Set a string attribute's value.
 * @param ctx      Dump file object.
 * @param attr     An attribute string.
 * @param flags    New attribute value flags.
 * @param str      New string value.
 * @returns        Error status.
 */
kdump_status
set_attr_string(kdump_ctx_t *ctx, struct attr_data *attr,
		struct attr_flags flags, const char *str)
{
	char *dynstr = strdup(str);
	kdump_attr_value_t val;

	if (!dynstr)
		return set_error(ctx, KDUMP_SYSERR,
				 "Cannot allocate string");

	val.string = dynstr;
	flags.dynstr = 1;
	return set_attr(ctx, attr, flags, &val);
}

/**  Set a string attribute's value to a string of a known size.
 * @param ctx      Dump file object.
 * @param attr     An attribute string.
 * @param flags    New attribute value flags.
 * @param str      New string value.
 * @param len      Length of the new value.
 * @returns        Error status.
 */
kdump_status
set_attr_sized_string(kdump_ctx_t *ctx, struct attr_data *attr,
		      struct attr_flags flags, const char *str, size_t len)
{
	size_t dynlen;
	char *dynstr;
	kdump_attr_value_t val;

	dynlen = len;
	if (!len || str[len-1] != '\0')
		++dynlen;
	dynstr = ctx_malloc(dynlen, ctx, "sized string");
	if (!dynstr)
		return KDUMP_SYSERR;
	memcpy(dynstr, str, len);
	dynstr[dynlen-1] = '\0';

	val.string = dynstr;
	flags.dynstr = 1;
	return set_attr(ctx, attr, flags, &val);
}

/**  Set a static string attribute of a dump file object.
 * @param ctx      Dump file object.
 * @param attr     Attribute data.
 * @param flags    New attribute value flags.
 * @param str      Key value (static string).
 * @returns        Error status.
 */
kdump_status
set_attr_static_string(kdump_ctx_t *ctx, struct attr_data *attr,
		       struct attr_flags flags, const char *str)
{
	kdump_attr_value_t val;

	val.string = str;
	return set_attr(ctx, attr, flags, &val);
}

/**  Validate attribute data.
 * @param ctx   Dump file object.
 * @param attr  Attribute data.
 * @returns     Error status.
 *
 * This can be safely used with unset attributes. If an attribute
 * has no value, then this function returns @ref KDUMP_NODATA but
 * does not set any error message, so callers can clear the error
 * simply by ignoring the return value.
 */
kdump_status
validate_attr(kdump_ctx_t *ctx, struct attr_data *attr)
{
	if (!attr_isset(attr))
		return KDUMP_NODATA;
	if (!attr->template->ops || !attr->template->ops->validate)
		return KDUMP_OK;
	return attr->template->ops->validate(ctx, attr);
}

/**  Add a template override to an attribute.
 * @param attr      Attribute data.
 * @param override  Override definition.
 */
void
attr_add_override(struct attr_data *attr, struct attr_override *override)
{
	const struct attr_template *tmpl = attr->template;

	if (tmpl->ops)
		override->ops = *tmpl->ops;
	else
		memset(&override->ops, 0, sizeof override->ops);

	override->template.key = tmpl->key;
	override->template.parent = attr->template;
	override->template.type = tmpl->type;
	override->template.ops = &override->ops;

	attr->template = &override->template;
}

/**  Remove a template override from an attribute.
 * @param attr      Attribute data.
 * @param override  Override definition to be removed.
 */
void
attr_remove_override(struct attr_data *attr, struct attr_override *override)
{
	const struct attr_template *tmpl, **pprev;
	pprev = &attr->template;
	do {
		tmpl = *pprev;
		if (tmpl == &override->template) {
			*pprev = tmpl->parent;
			break;
		}
		pprev = &((struct attr_template*)tmpl)->parent;
	} while (tmpl->parent != tmpl);
}

kdump_status
kdump_get_attr(kdump_ctx_t *ctx, const char *key, kdump_attr_t *valp)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	d = lookup_attr(ctx->shared, key);
	if (!d) {
		ret = set_error(ctx, KDUMP_NOKEY, "No such key");
		goto out;
	}
	if (validate_attr(ctx, d) != KDUMP_OK) {
		ret = set_error(ctx, KDUMP_NODATA, "Key has no value");
		goto out;
	}

	valp->type = d->template->type;
	valp->val = *attr_value(d);
	ret = KDUMP_OK;

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Set an attribute value with type check.
 * @param ctx   Dump file object.
 * @param attr  Attribute to be modified.
 * @param valp  New value for the attribute.
 */
static kdump_status
check_set_attr(kdump_ctx_t *ctx, struct attr_data *attr,
	       const kdump_attr_t *valp)
{
	kdump_attr_value_t val;

	if (valp->type == KDUMP_NIL) {
		clear_attr(ctx, attr);
		return KDUMP_OK;
	}

	if (valp->type != attr->template->type)
		return set_error(ctx, KDUMP_INVALID, "Type mismatch");

	if (valp->type == KDUMP_STRING)
		return set_attr_string(ctx, attr, ATTR_PERSIST,
				       valp->val.string);

	val = valp->val;
	return set_attr(ctx, attr, ATTR_PERSIST, &val);
}

kdump_status
kdump_set_attr(kdump_ctx_t *ctx, const char *key,
	       const kdump_attr_t *valp)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_wrlock(&ctx->shared->lock);

	d = lookup_attr(ctx->shared, key);
	if (!d) {
		ret = set_error(ctx, KDUMP_NODATA, "No such key");
		goto out;
	}

	ret = check_set_attr(ctx, d, valp);

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

/**  Convert attribute data to an attribute reference.
 * @param[out] ref   Attribute reference.
 * @param[in]  attr  Attribute data.
 */
static inline void
mkref(kdump_attr_ref_t *ref, struct attr_data *attr)
{
	ref->_ptr = attr;
}

/**  Convert an attribute reference to attribute data.
 * @param ref  Attribute reference.
 * @returns    Attribute data.
 */
static inline struct attr_data *
ref_attr(const kdump_attr_ref_t *ref)
{
	return ref->_ptr;
}

kdump_status
kdump_attr_ref(kdump_ctx_t *ctx, const char *key, kdump_attr_ref_t *ref)
{
	struct attr_data *d;

	clear_error(ctx);

	rwlock_rdlock(&ctx->shared->lock);
	d = lookup_attr(ctx->shared, key);
	rwlock_unlock(&ctx->shared->lock);
	if (!d)
		return set_error(ctx, KDUMP_NOKEY, "No such key");

	mkref(ref, d);
	return KDUMP_OK;
}

kdump_status
kdump_sub_attr_ref(kdump_ctx_t *ctx, const kdump_attr_ref_t *base,
		   const char *subkey, kdump_attr_ref_t *ref)
{
	struct attr_data *dir, *attr;

	clear_error(ctx);

	dir = ref_attr(base);
	rwlock_rdlock(&ctx->shared->lock);
	attr = lookup_dir_attr(ctx->shared, dir, subkey, strlen(subkey));
	rwlock_unlock(&ctx->shared->lock);
	if (!attr)
		return set_error(ctx, KDUMP_NOKEY, "No such key");

	mkref(ref, attr);
	return KDUMP_OK;
}

void
kdump_attr_unref(kdump_ctx_t *ctx, kdump_attr_ref_t *ref)
{
	clear_error(ctx);
}

kdump_attr_type_t
kdump_attr_ref_type(kdump_attr_ref_t *ref)
{
	return ref_attr(ref)->template->type;
}

int
kdump_attr_ref_isset(kdump_attr_ref_t *ref)
{
	return attr_isset(ref_attr(ref));
}

kdump_status
kdump_attr_ref_get(kdump_ctx_t *ctx, const kdump_attr_ref_t *ref,
		   kdump_attr_t *valp)
{
	struct attr_data *d = ref_attr(ref);
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	if (validate_attr(ctx, d) != KDUMP_OK) {
		ret = set_error(ctx, KDUMP_NODATA, "Key has no value");
		goto out;
	}

	valp->type = d->template->type;
	valp->val = *attr_value(d);
	ret = KDUMP_OK;

 out:
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_attr_ref_set(kdump_ctx_t *ctx, kdump_attr_ref_t *ref,
		   const kdump_attr_t *valp)
{
	kdump_status ret;

	clear_error(ctx);
	rwlock_wrlock(&ctx->shared->lock);

	ret = check_set_attr(ctx, ref_attr(ref), valp);

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

static kdump_status
set_iter_pos(kdump_attr_iter_t *iter, struct attr_data *attr)
{
	while (attr && !attr_isset(attr))
		attr = attr->next;

	iter->key = attr ? attr->template->key : NULL;
	mkref(&iter->pos, attr);
	return KDUMP_OK;
}

/**  Get an attribute iterator by attribute data.
 * @param      ctx   Dump file object.
 * @param[in]  attr  Attribute directory data.
 * @param[out] iter  Attribute iterator.
 * @returns          Error status.
 *
 * This is the common implementation of @ref kdump_attr_iter_start
 * and @ref kdump_attr_ref_iter_start, which takes an attribute data
 * pointer as argument.
 */
static kdump_status
attr_iter_start(kdump_ctx_t *ctx, const struct attr_data *attr,
		kdump_attr_iter_t *iter)
{
	if (!attr_isset(attr))
		return set_error(ctx, KDUMP_NODATA, "Key has no value");
	if (attr->template->type != KDUMP_DIRECTORY)
		return set_error(ctx, KDUMP_INVALID,
				 "Path is a leaf attribute");

	return set_iter_pos(iter, attr->dir);
}

kdump_status
kdump_attr_iter_start(kdump_ctx_t *ctx, const char *path,
		      kdump_attr_iter_t *iter)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	d = lookup_attr(ctx->shared, path);
	if (d)
		ret = attr_iter_start(ctx, d, iter);
	else
		ret = set_error(ctx, KDUMP_NOKEY, "No such path");

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_attr_ref_iter_start(kdump_ctx_t *ctx, const kdump_attr_ref_t *ref,
			  kdump_attr_iter_t *iter)
{
	kdump_status ret;
	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);
	ret = attr_iter_start(ctx, ref_attr(ref), iter);
	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

kdump_status
kdump_attr_iter_next(kdump_ctx_t *ctx, kdump_attr_iter_t *iter)
{
	struct attr_data *d;
	kdump_status ret;

	clear_error(ctx);
	rwlock_rdlock(&ctx->shared->lock);

	d = ref_attr(&iter->pos);
	if (d)
		ret = set_iter_pos(iter, d->next);
	else
		ret = set_error(ctx, KDUMP_INVALID, "End of iteration");

	rwlock_unlock(&ctx->shared->lock);
	return ret;
}

void
kdump_attr_iter_end(kdump_ctx_t *ctx, kdump_attr_iter_t *iter)
{
	clear_error(ctx);
}

/**  Use a map to choose an attribute by current OS type.
 * @param shared  Shared data of a dump file object.
 * @param map     OS type -> global attribute index.
 * @returns       Attribute, or @c NULL if OS type not found.
 */
struct attr_data *
ostype_attr(const struct kdump_shared *shared,
	    const struct ostype_attr_map *map)
{
	while (map->ostype != ADDRXLAT_OS_UNKNOWN) {
		if (map->ostype == shared->ostype)
			return sgattr(shared, map->attrkey);
		++map;
	}

	return NULL;
}
