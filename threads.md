Multi-threading							{#threads}
===============

To use `libkdumpfile` in a multi-threaded application, the library
must be compiled with pthread support. This is done by default,
unless you explicitly pass `--without-pthread` as an option to
`./configure`.

All internal state is stored in the context variable ([kdump_ctx_t])
or other data structures referenced through the context. In other
words, it is always safe to access different dump files from
different threads.  In fact, this is safe even if the library was
not compiled with pthread support.

Accessing the same dump file from different threads requires
additional care. Most importantly, a dump file context
([kdump_ctx_t]) must not be accessed by more than one thread
simultaneously. This does not mean the context is bound to a
single thread. For example, you can create a context in one thread
and then pass it to another thread. But you can't use the same
context from two different threads **at the same time**.

So, how do you access the same dump file from different threads?

You can create a *clone* of the original dump file context with
[kdump_clone]. Almost all data is shared by clones, e.g.
attributes and caches. If it is changed through one context, the
change is also visible through all other contexts cloned from the
same base (directly or indirectly). Only the following data bits
are *not* shared:

- error string ([kdump_get_err])
- private data ([kdump_get_priv], [kdump_set_priv])
- callbacks

When a clone is initialized, this data is copied from the original
(except the error string, which is cleared on success, of course),
but later changes made in one context are not propagated to other
contexts.

Caveats
-------

The default cache size is set for a single thread. It may have to
be increased if multiple threads are supposed to read concurrently
from the same dump file.  That's because all I/O uses the cache,
so a cache entry is needed for each read from a dump file. If
there are more threads than cache slots, then you will run out of
cache entries.

The library does not block until a cache entry is available.
Instead, the read attempt fails immediately with a specific error
status: [KDUMP_BUSY]. Retrying the read may be successful, but
this error indicates that the cache size should be increased.

[kdump_ctx_t]: @ref kdump_ctx_t
[kdump_clone]: @ref kdump_clone
[kdump_get_err]: @ref kdump_get_err
[kdump_get_priv]: @ref kdump_get_priv
[kdump_set_priv]: @ref kdump_set_priv
[KDUMP_BUSY]: @ref KDUMP_BUSY
