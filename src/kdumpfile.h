/**  @file kdumpfile.h
 * Public interface for `libkdumpfile` (kernel coredump file access).
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

#ifndef _KDUMPFILE_H
#define _KDUMPFILE_H	1

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#define KDUMPFILE_VER_MAJOR	0
#define KDUMPFILE_VER_MINOR	2
#define KDUMPFILE_VER_MICRO	0

#ifdef  __cplusplus
extern "C" {
#endif

/**  Type of a physical or virtual address.
 *
 * This type is large enough to hold any possible address type on any
 * architecture supported by `libkdumpfile`. Note that this type may
 * be larger than the actual address in the target.
 */
typedef uint_fast64_t kdump_addr_t;

/**  Type of a generic number.
 *
 * This type is large enough to hold register value on any architecture
 * supported by `libkdumpfile`. Note that it may be larger than the
 * registers in the target.
 */
typedef uint_fast64_t kdump_num_t;

/**  Maximum value represented by kdump_addr_t.
 */
#define KDUMP_ADDR_MAX	(~(kdump_addr_t)0)

/**  Type of a physical address.
 *
 * Use this type instead of @ref kdump_addr_t if the entity is always
 * known to be a physical address.
 */
typedef kdump_addr_t kdump_paddr_t;

/**  Type of a virtual addresses.
 *
 * Use this type instead of @ref kdump_addr_t if the entity is always
 * known to be a virtual address.
 */
typedef kdump_addr_t kdump_vaddr_t;

/**  Type of a Xen machine address.
 *
 * Use this type instead of @ref kdump_addr_t if the entity is always
 * known to be a Xen machine address.
 */
typedef kdump_addr_t kdump_maddr_t;

/**  Type of a register.
 *
 * Use this type for register values. Note that it might be larger than
 * the target register size.
 */
typedef uint_fast64_t kdump_reg_t;

/**  Representation of a dump file.
 *
 * The context contains all information needed to work with a dump file.
 * It is an opaque type, so it can be modified and/or extended without
 * breaking binary compatibility with existing programs.
 */
typedef struct _tag_kdump_ctx kdump_ctx;

/**  Status code.
 *
 * Return type of all (almost) library functions that may fail. It
 * provides a very rough description of the error. See @ref kdump_err_str
 * if you want a human-readable error description.
 */
typedef enum _tag_kdump_status {
	kdump_ok = 0,		/**< Success. */
	kdump_syserr,		/**< OS error, see @c errno. */
	kdump_unsupported,	/**< Unsupported file format. */
	kdump_nodata,		/**< Data is not stored in the dump file. */
	kdump_dataerr,		/**< Corrupted file data. */
	kdump_invalid,		/**< Invalid value. */
	kdump_nokey,		/**< No such attribute key. */
	kdump_eof,		/**< Unexpected EOF. */
	kdump_busy,		/**< Too many pending requests. */
} kdump_status;

/**  Target dump byte order.
 *
 * Target byte order. Note that this may be different from the host byte
 * order. The library will convert any values it needs internally, but
 * if you read any data from the dump file, you are responsible for
 * converting the data to the host byte order.
 *
 * @sa kdump_byte_order
 */
typedef enum _tag_kdump_byte_order {
	kdump_big_endian,
	kdump_little_endian,
} kdump_byte_order_t;

/**  Type of a Xen dump.
 */
typedef enum _tag_kdump_xen_type {
	kdump_xen_none,		/**< Not running under Xen */
	kdump_xen_system,	/**< Comlete dump of a Xen machine */
	kdump_xen_domain,	/**< Dump of a single domain */
} kdump_xen_type_t;

/**  Xen physmap translation type.
 */
typedef enum _tag_kdump_xen_xlat {
	kdump_xen_auto,		/**< Auto-translated physmap */
	kdump_xen_nonauto	/**< Non-auto-translated physmap */
} kdump_xen_xlat_t;

/**  Allocate a new dump file object.
 * @returns Newly allocated object, or NULL on failure.
 *
 * Use this function to create a new @ref kdump_ctx. When the object
 * is no longer needed, you should free all resources with @ref kdump_free.
 */
kdump_ctx *kdump_alloc_ctx(void);

/**  Initialize an already allocated dump file object.
 * @param ctx     Dump file object.
 * @returns       Error status.
 *
 * Use this function to initialize a @ref kdump_ctx allocated using
 * @ref kdump_alloc_ctx.
 */
kdump_status kdump_init_ctx(kdump_ctx *ctx);

/**  Initialize a new dump file object.
 * @returns Newly allocated object, or NULL on failure.
 *
 * Use this function to create a new @ref kdump_ctx. When the object
 * is no longer needed, you should free all resources with @ref kdump_free.
 */
kdump_ctx *kdump_init(void);

/**  Free a dump file object.
 * @param ctx  Object to be freed.
 *
 * Free all resources associated with the dump file. Do not just call
 * @c free(ctx), because that may leak some resources.
 *
 * The object must not be used after calling this function.
 */
void kdump_free(kdump_ctx *ctx);

/**  Get a detailed error string.
 * @param ctx  Dump file object.
 * @returns    Error string, or @c NULL if there was no error.
 *
 * If an error status is returned, this function can be used to get
 * a human-readable description of the error. The error string is not
 * reset by calling this function, but it is reset by calling any
 * library function that returns @ref kdump_status.
 */
const char *kdump_err_str(kdump_ctx *ctx);

/**  Associate a dump file object with a file descriptor.
 * @param ctx     Dump file object.
 * @param[in] fd  Open file descriptor.
 * @returns       Error status.
 */
kdump_status kdump_set_fd(kdump_ctx *ctx, int fd);

/**  Initialize a dump file object and associate it with a file.
 * @param[out] pctx  Pointer to the (uninitialized) dump file object.
 * @param[in] fd     A file descriptor open for reading.
 * @returns          Error status.
 *
 * This is a shortcut for calling @ref kdump_init and then
 * @ref kdump_set_fd on the newly created object. If this function
 * fails, the variable pointed to by @c pctx is left uninitialized,
 * and there is no way to get a detailed error description.
 */
kdump_status kdump_fdopen(kdump_ctx **pctx, int fd);

/**  Initialize virtual-to-physical translation.
 * @param ctx  Dump file object.
 * @returns    Error status.
 *
 * Perform any extra initialization that is needed for full
 * virtual-to-physical address translation. Using the @ref KDUMP_KVADDR
 * flag does not work until this function is called.
 *
 * The reason this initialization is not done as part of @ref kdump_set_fd
 * is that it usually requires additional resources (and time), and may fail.
 * However, some library users do not need address translation, or they can
 * implement a fallback mechanism if it is unavailable.
 */
kdump_status kdump_vtop_init(kdump_ctx *ctx);

/**  Initialize Xen virtual-to-physical translation.
 * @param ctx  Dump file object.
 * @returns    Error status.
 *
 * Initialize Xen hypervisor virtual-to-physical translation.
 *
 * @sa kdump_vtop_init.
 */
kdump_status kdump_vtop_init_xen(kdump_ctx *ctx);

/**  Translate a virtual address to a physical address.
 * @param ctx         Dump file object.
 * @param[in] vaddr   Virtual address.
 * @param[out] paddr  Physical address.
 * @returns           Error status.
 *
 * Translate a virtual address to a physical address.
 */
kdump_status kdump_vtop(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			kdump_paddr_t *paddr);

/**  Translate a virtual address to a machine address.
 * @param ctx         Dump file object.
 * @param[in] vaddr   Virtual address.
 * @param[out] maddr  Machine address.
 * @returns           Error status.
 *
 * Translate a virtual address to a machine address. If the dump is not
 * a Xen dump or it has an auto-translated physmap, this function is
 * equivallent to @ref kdump_vtop.
 */
kdump_status kdump_vtom(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			kdump_maddr_t *maddr);

/**  Translate a Xen virtual address to a physical address.
 * @param ctx         Dump file object.
 * @param[in] vaddr   Virtual address.
 * @param[out] paddr  Physical address.
 * @returns           Error status.
 *
 * Translate a virtual address to a physical address. Note that in this
 * context, physical address is equal to machine address, because the
 * hypervisor itself does not have a second mapping.
 */
kdump_status kdump_vtop_xen(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			    kdump_paddr_t *paddr);

/**  Translate a kernel physical address to a Xen machine address.
 * @param ctx         Dump file object.
 * @param[in] paddr  Physical address.
 * @param[out] maddr  Machine address.
 * @returns           Error status.
 *
 * Translate a kernel physical address to a machine physical address.
 * If not running under Xen, these two addresses are equal, and this
 * function simply copies @c maddr to @c paddr.
 */
kdump_status kdump_ptom(kdump_ctx *ctx, kdump_paddr_t paddr,
			kdump_maddr_t *maddr);

/**  Translate a Xen machine address to a physical address.
 * @param ctx         Dump file object.
 * @param[in] maddr   Machine address.
 * @param[out] paddr  Physical address.
 * @returns           Error status.
 *
 * Translate a Xen machine address to a physical address.
 */
kdump_status kdump_mtop(kdump_ctx *ctx, kdump_maddr_t maddr,
			kdump_paddr_t *paddr);

/**  Address spaces used by kdump_readp()
 *
 * When passing an address to kdump_readp(), this type is used to
 * specify the kind of address.
 *
 * The difference between @c KDUMP_KPHYSADDR and @c KDUMP_MACHPHYSADDR
 * matters only in environments where the kernel has a different view
 * of physical address space than the CPU, e.g. paravirtualized kernels
 * under Xen.
 */
typedef enum _tag_kdump_addrspace {
	KDUMP_KPHYSADDR,	/**< Kernel physical address. */
	KDUMP_MACHPHYSADDR,	/**< Machine physical address. */
	KDUMP_KVADDR,		/**< Kernel virtual address. */
	KDUMP_XENVADDR,		/**< Xen virtual address.  */
} kdump_addrspace_t;

/**  Read data from the dump file.
 * @param ctx          Dump file object.
 * @param[in] as       Address space of @c addr.
 * @param[in] addr     Any type of address.
 * @param[out] buffer  Buffer to receive data.
 * @param[in] length   Length of @c buffer.
 * @returns            Number of bytes actually read, or -1.
 *
 * Read data from a dump file. The function returns -1 if an error occurs.
 * It may return a short count on EOF or if data is filtered out.
 */
ssize_t kdump_read(kdump_ctx *ctx,
		   kdump_addrspace_t as, kdump_addr_t addr,
		   void *buffer, size_t length);

/**  Read data from the dump file, returning full error status.
 * @param ctx              Dump file object.
 * @param[in] as           Address space of @c addr.
 * @param[in] addr         Any type of address.
 * @param[out] buffer      Buffer to receive data.
 * @param[in,out] plength  Length of the buffer.
 * @returns                Error status.
 *
 * This function works just like @ref kdump_read, but instead of returning
 * the number of bytes, it returns the error status. The lenght of the
 * buffer pointed to by @c plength is updated to reflect the actual number
 * of bytes read from the dump file.
 *
 * If @c kdump_readp returns @ref kdump_ok, then all requested bytes have
 * been read successfully, and the value referenced by @ref plength is not
 * changed. However, if the read fails, some bytes may already have been
 * read, and their number is reported in this variable.
 */
kdump_status kdump_readp(kdump_ctx *ctx,
			 kdump_addrspace_t as, kdump_addr_t addr,
			 void *buffer, size_t *plength);

/**  Read a string from the dump file.
 * @param ctx        Dump file object.
 * @param[in] as     Address space of @c addr.
 * @param[in] addr   Any type of address.
 * @param[out] pstr  String to be read.
 * @returns          Error status.
 *
 * Use this function to read a NUL-terminated string at address @c addr.
 * The resulting string is allocated dynamically, and you should free
 * it with the @c free library function when it is no longer needed.
 * This function is usually more efficient than implementing the same
 * thing with @ref kdump_read or @ref kdump_readp.
 */
kdump_status kdump_read_string(kdump_ctx *ctx,
			       kdump_addrspace_t as, kdump_addr_t addr,
			       char **pstr);

/**  Dump file attribute value type.
 */
typedef enum kdump_attr_type {
	kdump_nil,
	kdump_directory,
	kdump_number,
	kdump_address,
	kdump_string,
} kdump_attr_type_t;

/**  Dump file attribute value.
 */
typedef union kdump_attr_value {
	kdump_num_t number;
	kdump_addr_t address;
	const char *string;
} kdump_attr_value_t;

/**  Dump file attribute: type + value.
 */
typedef struct kdump_attr {
	kdump_attr_type_t type;
	kdump_attr_value_t val;
} kdump_attr_t;

/**  Reference to an attribute.
 * This type is used to make a fixed-size reference to an attribute,
 * rather than its (variable-size) key path.
 *
 * This type points to an internal structure which may change layout
 * without affecting the ABI, so callers must not make any attempts
 * to interpret that data.
 */
typedef struct kdump_attr_ref {
	void *_ptr;		/**< Reference (private field). */
} kdump_attr_ref_t;

/**  Attribute iterator.
 * Iterators are used to iterate over all children of a directory
 * attribute. This is a public structure, so callers can allocate
 * it e.g. on stack.
 *
 * Note that the attribute name is stored in the structure, but
 * the attribute value is not. This allows to keep the same ABI
 * while implementing special attribute handling (e.g. calculate
 * the value on the fly).
 */
typedef struct kdump_attr_iter {
	/** Attribute key.
	 * This is the attribute's name relative to parent (no dots),
	 * or @c NULL if end of iteration has been reached.
	 */
	const char *key;

	/** Iterator position.
	 * This field must not be modified by callers, but it can
	 * be used as an argument to the reference-handling functions.
	 */
	kdump_attr_ref_t pos;
} kdump_attr_iter_t;

/**  Set a dump file attribute.
 * @param ctx  Dump file object.
 * @param key  Attribute key.
 * @param valp New attribute value.
 * @returns    Error status.
 */
kdump_status kdump_set_attr(kdump_ctx *ctx, const char *key,
			    const kdump_attr_t *valp);

/**  Get a dump file attribute.
 * @param ctx  Dump file object.
 * @param key  Attribute key.
 * @param valp Value (filled on successful return).
 * @returns    Error status.
 */
kdump_status kdump_get_attr(kdump_ctx *ctx, const char *key,
			    kdump_attr_t *valp);

/** Get a string attribute.
 *
 * @param ctx  Dump file object.
 * @param key  Attribute key.
 * @returns    The attribute value, @c NULL if not found or if the
 *             attribute is not a string.
 */
const char *kdump_get_string_attr(kdump_ctx *ctx, const char *key);

/** Get a reference to an attribute
 * @param      ctx  Dump file object.
 * @param[in]  key  Attribute key.
 * @param[out] ref  Attribute reference (initialized on successful return).
 * @returns    Error status.
 *
 * A reference is a persistent pointer to the attribute, which stays
 * valid until the reference is dropped using @ref kdump_drop_attr_ref,
 * or the whole dump file object is destroyed.
 */
kdump_status kdump_attr_ref(kdump_ctx *ctx, const char *key,
			    kdump_attr_ref_t *ref);

/** Get a reference to a subordinate attribute
 * @param      ctx     Dump file object.
 * @param[in]  base    Reference to base attribute.
 * @param[in]  subkey  Attribute key, relative to @ref base.
 * @param[out] ref     Attribute reference (initialized on successful return).
 * @returns    Error status.
 */
kdump_status kdump_sub_attr_ref(kdump_ctx *ctx, const kdump_attr_ref_t *base,
				const char *subkey, kdump_attr_ref_t *ref);

/**  Drop a reference to an attribute.
 * @param ctx   Dump file object.
 * @param ref   Attribute reference.
 */
void kdump_attr_unref(kdump_ctx *ctx, kdump_attr_ref_t *ref);

/**  Get the type of an attribute by reference.
 * @param ref  Attribute reference.
 * @returns    Attribute type.
 */
kdump_attr_type_t kdump_attr_ref_type(kdump_attr_ref_t *ref);

/**  Get attribute data by reference.
 * @param      ctx   Dump file object.
 * @param[in]  ref   Attribute reference.
 * @param[out] valp  Attribute value (filled on successful return).
 *
 * This works just like @ref kdump_get_attr, except that the attribute
 * is denoted by a reference rather than by its key path.
 */
kdump_status kdump_attr_ref_get(kdump_ctx *ctx, const kdump_attr_ref_t *ref,
				kdump_attr_t *valp);

/**  Set attribute data by reference.
 * @param      ctx   Dump file object.
 * @param[in]  ref   Attribute reference.
 * @param[in]  valp  New attribute value.
 *
 * This works just like @ref kdump_set_attr, except that the attribute
 * is denoted by a reference rather than by its key path.
 */
kdump_status kdump_attr_ref_set(kdump_ctx *ctx, kdump_attr_ref_t *ref,
				const kdump_attr_t *valp);

/**  Get an attribute iterator.
 * @param      ctx   Dump file object.
 * @param[in]  path  Path to an attribute directory.
 * @param[out] iter  Attribute iterator.
 * @returns          Error status.
 *
 * On return, the iterator is set to the first child attribute. If the
 * attribute directory is empty, this function sets the @c key field
 * of @ref iter to @c NULL and returns @ref kdump_ok.
 */
kdump_status kdump_attr_iter_start(kdump_ctx *ctx, const char *path,
				   kdump_attr_iter_t *iter);

/**  Get an attribute iterator by reference.
 * @param      ctx   Dump file object.
 * @param[in]  ref   Reference to an attribute directory.
 * @param[out] iter  Attribute iterator.
 * @returns          Error status.
 *
 * This works just like @ref kdump_attr_iter_start, but use an
 * attribute reference rather than its key path.
 */
kdump_status kdump_attr_ref_iter_start(kdump_ctx *ctx,
				       const kdump_attr_ref_t *ref,
				       kdump_attr_iter_t *iter);

/**  Advance an attribute iterator.
 * @param ctx   Dump file object.
 * @param iter  Attribute iterator.
 * @returns     Error status.
 *
 * If there are no more items in the iteration, this function sets
 * the @c key field of @ref iter to @c NULL and returns @ref kdump_ok.
 * If you try to advance past end of iteration, this function returns
 * @ref kdump_invalid.
 */
kdump_status kdump_attr_iter_next(kdump_ctx *ctx, kdump_attr_iter_t *iter);

/**  De-initialize an attribute iterator.
 * @param ctx   Dump file object.
 * @param iter  Attribute iterator.
 * @returns     Error status.
 *
 * This function must be called when an iterator is no longer needed.
 */
void kdump_attr_iter_end(kdump_ctx *ctx, kdump_attr_iter_t *iter);

/**  Get target dump format.
 * @param ctx  Dump file object.
 * @returns    Descriptive name of the file format.
 *
 * The return value is intended to be presented to humans rather than
 * machine-parsed. In fact, some format handlers create the string
 * dynamically, e.g. LKCD files will include the version in the string.
 */
const char *kdump_format(kdump_ctx *ctx);

/**  Get target byte order.
 * @param ctx  Dump file object.
 * @returns    Target byte order.
 *
 * The byte order is auto-detected when opening a dump file.
 *
 * @sa kdump_byte_order_t
 */
kdump_byte_order_t kdump_byte_order(kdump_ctx *ctx);

/**  Get target pointer size.
 * @param ctx  Dump file object.
 * @returns    Size of pointer types (in bytes).
 *
 * Note that in Linux, the pointer size is equal to the size of @c long
 * and target register size. The Linux kernel actually makes heavy use of
 * these assumptions, so they are unlikely to change soon.
 */
size_t kdump_ptr_size(kdump_ctx *ctx);

/**  Return the name of the architecture.
 * @param ctx  Dump file object.
 * @returns    Name of the target architecture, or @c NULL (see below).
 *
 * Unlike @ref kdump_machine, which may contain the name of a particular
 * platform (e.g. "i586" v. "i686") or may not even be initialised,
 * this function always returns the detected architecture from a fixed
 * list below:
 *   - aarch64
 *   - alpha
 *   - arm
 *   - i386
 *   - ia64
 *   - mips
 *   - ppc
 *   - ppc64
 *   - s390
 *   - s390x
 *   - x86_64
 *
 * Note: this function may return @c NULL if the target architecture
 *       was not detected for some reason.
 */
const char *kdump_arch_name(kdump_ctx *ctx);

/**  Get the type of a Xen dump file.
 * @param ctx  Dump file object.
 * @returns    Type of the dump (@sa kdump_xen_type_t)
 */
kdump_xen_type_t kdump_xen_type(kdump_ctx *ctx);

/**  Get target page size.
 * @param ctx  Dump file object.
 * @returns     Target page size (in bytes).
 */
size_t kdump_pagesize(kdump_ctx *ctx);

/**  Get target page shift.
 * @param ctx  Dump file object.
 * @returns     Target page shift (in bits).
 */
unsigned kdump_pageshift(kdump_ctx *ctx);

/**  Get target kernel physical base.
 * @param ctx  Dump file object.
 * @returns     Physical address where the kernel is loaded.
 */
kdump_paddr_t kdump_phys_base(kdump_ctx *ctx);

/**  Get target system name.
 * @param ctx  Dump file object.
 * @returns    System name (always @c "Linux"), or @c NULL.
 */
const char *kdump_sysname(kdump_ctx *ctx);

/** Get target node name.
 * @param ctx  Dump file object.
 * @returns    Node name from @c utsname, or @c NULL.
 */
const char *kdump_nodename(kdump_ctx *ctx);

/** Get target kernel release.
 * @param ctx  Dump file object.
 * @returns    Kernel release from @c utsname, or @c NULL.
 */
const char *kdump_release(kdump_ctx *ctx);

/** Get target kernel version.
 * @param ctx  Dump file object.
 * @returns    Kernel version from @c utsname, or @c NULL.
 */
const char *kdump_version(kdump_ctx *ctx);

/**  Get target machine name.
 * @param ctx  Dump file object.
 * @returns    Machine name from @c utsname, or @c NULL.
 * @sa kdump_arch_name
 */
const char *kdump_machine(kdump_ctx *ctx);

/**  Get target domain name.
 * @param ctx  Dump file object.
 * @returns    Domain name from utsname, or @c NULL.
 */
const char *kdump_domainname(kdump_ctx *ctx);

/**  Get kernel version code.
 * @param ctx  Dump file object.
 * @returns    Kernel version code.
 *
 * Kernel version code is a 32-bit integer that combines the first three
 * digits of the kernel version.
 * See the @c KERNEL_VERSION macro in <linux/version.h>.
 */
unsigned kdump_version_code (kdump_ctx *ctx);

/**  Get number of CPUs.
 * @param ctx  Dump file object.
 * @returns    Number of CPUs with registers.
 *
 * The number is not the number of CPUs in the system, but rather the
 * number of CPUs for which register values can be obtained using
 * @ref kdump_read_reg.
 */
unsigned kdump_num_cpus(kdump_ctx *ctx);

/**  Get register value.
 * @param ctx         Dump file object.
 * @param[in] cpu     CPU index.
 * @param[in] index   Register index.
 * @param[out] value  Register value.
 * @returns           Error status.
 *
 * Get the value of register @p index on CPU @p cpu. Register indexing is
 * architecture-specific, but the numbering of general registers follows
 * whatever order is used in `struct elf_prstatus`.
 */
kdump_status kdump_read_reg(kdump_ctx *ctx, unsigned cpu, unsigned index,
			    kdump_reg_t *value);

/**  Get VMCOREINFO raw data.
 * @param ctx  Dump file object.
 * @returns    VMCOREINFO data, or @c NULL.
 *
 * The output string is always NUL-terminated, but if there was a NUL
 * byte inside VMCOREINFO, there is no way to know the full length.
 */
const char *kdump_vmcoreinfo(kdump_ctx *ctx);

/**  Get VMCOREINFO_XEN raw data.
 * @param ctx  Dump file object.
 * @returns    VMCOREINFO_XEN data, or @c NULL.
 *
 * The output string is always NUL-terminated, but if there was a NUL
 * byte inside VMCOREINFO_XEN, there is no way to know the full length.
 */
const char *kdump_vmcoreinfo_xen(kdump_ctx *ctx);

/**  Get a VMCOREINFO row.
 * @param ctx      Dump file object.
 * @param[in] key  Name of the VMCOREINFO variable.
 * @returns        Value of the key, or @c NULL if not found.
 */
const char *kdump_vmcoreinfo_row(kdump_ctx *ctx, const char *key);

/**  Get a VMCOREINFO_XEN row.
 * @param ctx      Dump file object.
 * @param[in] key  Name of the VMCOREINFO_XEN variable.
 * @returns        Value of the key, or @c NULL if not found.
 */
const char *kdump_vmcoreinfo_row_xen(kdump_ctx *ctx, const char *key);

/**  Get VMCOREINFO symbol value.
 * @param ctx            Dump file object.
 * @param[in] symname    Kernel symbol name.
 * @param[out] symvalue  Value of the symbol.
 * @returns              Error status.
 *
 * Get the content of SYMBOL(@c symname) row and parse it as a hexadecimal
 * value.
 */
kdump_status kdump_vmcoreinfo_symbol(kdump_ctx *ctx, const char *symname,
				     kdump_addr_t *symvalue);

/**  Get VMCOREINFO_XEN symbol value.
 * @param ctx            Dump file object.
 * @param[in] symname    Xen hypervisor symbol name.
 * @param[out] symvalue  Value of the symbol.
 * @returns              Error status.
 *
 * Get the content of SYMBOL(@c symname) row and parse it as a hexadecimal
 * value.
 */
kdump_status kdump_vmcoreinfo_symbol_xen(kdump_ctx *ctx, const char *symname,
					 kdump_addr_t *symvalue);

/**  Type for the get_symbol_val callback function.
 * @param ctx      Dump file object of the caller.
 * @param[in] name Name of the symbol.
 * @param[out] val Symbol value.
 * @returns        Error status.
 *
 * This type is used for @ref kdump_cb_get_symbol_val.
 */
typedef kdump_status kdump_get_symbol_val_fn(
	kdump_ctx *ctx, const char *name, kdump_addr_t *val);

/**  Set the get_symbol_val callback
 * @param ctx  Dump file object.
 * @param cb   New callback function.
 * @return the Previous callback function.
 */
kdump_get_symbol_val_fn *
kdump_cb_get_symbol_val(kdump_ctx *ctx, kdump_get_symbol_val_fn *cb);

/**  Set the get_symbol_val_xen callback
 * @param ctx  Dump file object.
 * @param cb   New callback function.
 * @return the Previous callback function.
 *
 * This callback is used for symbols in the Xen hypervisor.
 */
kdump_get_symbol_val_fn *
kdump_cb_get_symbol_val_xen(kdump_ctx *ctx, kdump_get_symbol_val_fn *cb);

/**  Set pointer to user private data.
 * @param ctx  Dump file object.
 * @param data Generic data pointer.
 *
 * A private pointer can be used to associate the dump file object with
 * arbitrary data. The libkdumpfile library does not use the pointer in
 * any way, but it can be retrieved later from a @ref kdump_ctx pointer
 * with @ref kdump_get_priv.
 */
void
kdump_set_priv(kdump_ctx *ctx, void *data);

/**  Get pointer to user private data.
 * @param ctx  Dump file object.
 * @returns    The data pointer stored previously with @ref kdump_set_priv.
 */
void *
kdump_get_priv(kdump_ctx *ctx);

#ifdef  __cplusplus
}
#endif

#endif	/* kdumpfile.h */
