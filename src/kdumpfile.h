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
	kdump_xen_none,		/*< Not running under Xen */
	kdump_xen_system,	/*< Comlete dump of a Xen machine */
	kdump_xen_domain,	/*< Dump of a single domain */
} kdump_xen_type_t;

/**  Xen physmap translation type.
 */
typedef enum _tag_kdump_xen_xlat {
	kdump_xen_auto,		/*< Auto-translated physmap */
	kdump_xen_nonauto	/*< Non-auto-translated physmap */
} kdump_xen_xlat_t;

/**  Xen hypervisor version.
 *
 * Xen dumps may contain the hypervisor version, which consists of three
 * parts. @ref kdump_xen_version uses this structure to return the data.
 */
typedef struct _tag_kdump_xen_version {
	unsigned long major;	/**< Major version. */
	unsigned long minor;	/**< Minor version. */
	const char *extra;	/**< Extra version string (usually starts
				 *   with a dot). */
} kdump_xen_version_t;

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
 * Translate a virtual address to a physical address. This function fails
 * unless there was previously a successful call to @ref kdump_vtop_init.
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
 * hypervisor itself does not have a second mapping. This function fails
 * unless there was previously a successful call to @ref kdump_vtop_init.
 */
kdump_status kdump_vtop_xen(kdump_ctx *ctx, kdump_vaddr_t vaddr,
			    kdump_paddr_t *paddr);

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

#define KDUMP_PHYSADDR		(1UL<<0) /**< Physical address. */
#define KDUMP_XENMACHADDR	(1UL<<1) /**< Xen machine address. */
#define KDUMP_KVADDR		(1UL<<2) /**< Kernel virtual address. */
#define KDUMP_XENVADDR		(1UL<<3) /**< Xen virtual address.  */

/**  Read data from the dump file.
 * @param ctx          Dump file object.
 * @param[in] addr     Any type of address.
 * @param[out] buffer  Buffer to receive data.
 * @param[in] length   Length of @c buffer.
 * @param[in] flags    Flags.
 * @returns            Number of bytes actually read, or -1.
 *
 * Read data from a dump file. The function returns -1 if an error occurs.
 * It may return a short count on EOF or if data is filtered out.
 *
 * Allowed @c flags:
 *   - @ref KDUMP_PHYSADDR: interpret @c addr as physical address.
 *   - @ref KDUMP_XENMACHADDR: interpret @c addr as Xen machine address.
 *   - @ref KDUMP_KVADDR: interpret @c addr as kernel virtual address.
 *   - @ref KDUMP_XENVADDR: interpret @c addr as Xen virtual address.
 */
ssize_t kdump_read(kdump_ctx *ctx, kdump_addr_t addr,
		   void *buffer, size_t length, long flags);

/**  Read data from the dump file, returning full error status.
 * @param ctx              Dump file object.
 * @param[in] addr         Any type of address.
 * @param[out] buffer      Buffer to receive data.
 * @param[in,out] plength  Length of the buffer.
 * @param[in] flags        Flags.
 * @returns                Error status.
 *
 * This function works just like @ref kdump_read, but instead of returning
 * the number of bytes, it returns the error status. The lenght of the
 * buffer pointed to by @c plength is updated to reflect the actual number
 * of bytes read from the dump file. Note that this number may be non-zero
 * even if the call itself fails.
 */
kdump_status kdump_readp(kdump_ctx *ctx, kdump_addr_t addr,
			 void *buffer, size_t *plength, long flags);

/**  Read a string from the dump file.
 * @param ctx        Dump file object.
 * @param[in] addr   Any type of address.
 * @param[out] pstr  String to be read.
 * @param[in] flags  Flags.
 * @returns          Error status.
 *
 * Use this function to read a NUL-terminated string at address @c addr.
 * The resulting string is allocated dynamically, and you should free
 * it with the @c free library function when it is no longer needed.
 * This function is usually more efficient than implementing the same
 * thing with @ref kdump_read or @ref kdump_readp.
 */
kdump_status kdump_read_string(kdump_ctx *ctx, kdump_addr_t addr,
			       char **pstr, long flags);

/**  Dump file attribute value type.
 */
enum kdump_attr_type {
	kdump_nil,
	kdump_directory,
	kdump_number,
	kdump_address,
	kdump_string,
};

/**  Dump file attribute value.
 */
union kdump_attr_value {
	kdump_num_t number;
	kdump_addr_t address;
	const char *string;
};

/**  Dump file attribute: type + value.
 */
struct kdump_attr {
	enum kdump_attr_type type;
	union kdump_attr_value val;
};

/**  Get a dump file attribute.
 * @param ctx  Dump file object.
 * @param key  Attribute key.
 * @param valp Value (filled on successful return).
 * @returns    Error status.
 */
kdump_status kdump_get_attr(kdump_ctx *ctx, const char *key,
			    struct kdump_attr *valp);

/** Get a string attribute.
 *
 * @param ctx  Dump file object.
 * @param key  Attribut key.
 * @returns    The attribute value, @c NULL if not found or if the
 *             attribute is not a string.
 */
const char *kdump_get_string_attr(kdump_ctx *ctx, const char *key);

/**  Type for kdump_enum_attr callback function.
 * @param data  Data pointer which was passed to @ref kdump_enum_attr.
 * @param key   Key name.
 * @param valp  Attribute value.
 * @returns     Non-zero if enumeration should stop.
 */
typedef int kdump_enum_attr_fn(void *data, const char *key,
			       const struct kdump_attr *valp);

/**  Enumerate an attribute directory.
 * @param ctx      Dump file object.
 * @param path     Path to the attribute.
 * @param cb       Callback function.
 * @param cb_data  Data that is passed to the callback function.
 * @returns     Error status.
 */
kdump_status kdump_enum_attr(kdump_ctx *ctx, const char *path,
			     kdump_enum_attr_fn *cb, void *cb_data);

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

/**  Check if the dump file is a Xen dump file.
 * @params ctx  Dump file object.
 * @returns     Non-zero if this is a Xen dump file.
 *
 * This function returns non-zero (true) both for Dom0 dumps and for DomU
 * dumps.
 */
int kdump_is_xen(kdump_ctx *ctx);

/**  Get the type of a Xen dump file.
 * @param ctx  Dump file object.
 * @returns    Type of the dump (@sa kdump_xen_type_t)
 */
kdump_xen_type_t kdump_xen_type(kdump_ctx *ctx);

/**  Get target page size.
 * @params ctx  Dump file object.
 * @returns     Target page size (in bytes).
 */
size_t kdump_pagesize(kdump_ctx *ctx);

/**  Get target page shift.
 * @params ctx  Dump file object.
 * @returns     Target page shift (in bits).
 */
unsigned kdump_pageshift(kdump_ctx *ctx);

/**  Get target kernel physical base.
 * @params ctx  Dump file object.
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
 * Get the value of register @index on CPU @cpu. Register indexing is
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

/**  Get Xen version.
 * @param ctx           Dump file object.
 * @param[out] version  Xen hypervisor version.
 *
 */
void kdump_xen_version(kdump_ctx *ctx, kdump_xen_version_t *version);

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

#ifdef  __cplusplus
}
#endif

#endif	/* kdumpfile.h */
