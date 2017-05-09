Object Lifetime
===============

The C API defines various kinds of data structures with different rules for
their lifetime:

- simple types,
- user-allocated objects,
- reference-counted objects.

Simple types are always passed by value, so their lifetime is not of much
concern. Examples include status codes (`addrxlat_status`), other enumerated
types or integers of a defined minimum size (e.g. `addrxlat_addr_t`).

In contrast, user-allocated objects are passed as pointers to a constant.
Arguments of such types are treated as immutable by the library, that is
the value is never modified, but may be copied into another type. The size
of these objects is part of the public API, because they are allocated by
users of the library user. As a design decision, the full definition of
these data types is made public and part of the API and ABI.

Reference-counted objects have contain a reference count. All such objects
are allocated from the heap by a function that ends with `_new`, e.g.
`addrxlat_ctx_new()`. The reference count of a freshly allocated object is
always one, but it can be incremented and decremented explicitly by calling
the appropriate function (`*_incref` or `*_decref`). If the reference count
drops to zero, the object is deallocated, freeing up all resources that
were associated with it.

When a pointer to an object is passed to a library function, the caller must
ensure that it is valid throughout the call itself. If the library needs
more permanent storage, it makes a copy or takes a new reference to an object.

When a library function returns a pointer, that pointer is a "borrowed
reference", that is it is valid only as long as the container object is
not changed.

Rationale
=========

The above is the only possible consistent interface for all kinds of objects:
Since user-allocated objects cannot be automatically freed (in fact, they may
be even automatic variables on stack), the library cannot hold the last
reference to them. Consequently, these objects must be copied if the value of
an argument is needed after returning to the caller. With reference-counted
objects, copying can be replaced with taking a new reference.

When returning a pointer to an object that is not reference-counted, there is
no way to know how long it should be valid. However, it always refers to some
internal storage in the object itself, so it is valid as long as this internal
storage. Note that such storage may change during the lifetime of the
container object, e.g. when a dynamically allocated array is extended.
