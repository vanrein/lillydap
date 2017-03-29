# Using LillyDAP

> *LillyDAP is a highly efficient parser/packer stack for LDAP.  It is meant
> for dynamic data handlers and middleware that manipulates queries on their
> way through.  If you need flexibility in your LDAP solution, and it needs
> a bit of custom coding, LillyDAP is probably your best bet.*

There is a standard sequence of parsing/packing stages, and you can intervene
between any of them to take control of the data passing through.  You may
block, generate, redirect, fork and join as you please.  The entire structure
works through event-styled callbacks, and connectivity to remote peers can
be easily integrated with an event loop.

The parser and, mirrorred to it, the packer for LillyDAP turn to their work
in a number of stages.  Parser routines link downwards and have names like
`lillyget_xxx()` whereas packer routines link upwards and have names like
`lillyput_xxx()`.

![Parsing and Packing -- a stack of mirrorred operations](pix/parser-stack.png)

The levels between the operations are good to understand, so as to get the
control that you might desire over the LDAP passing through:

  * The **event** interface is meant for reporting an event worthy of the
    API; this might be an ability to read or to write.
  * The **netbytes** level processes a sequence of bytes and collects
    complete DER messages.  As soon as one is found, it is passed on.
  * The **dercursor** level deals with one complete top-level DER message
    at a time.  So, at this level, the stream of bytes has been broken into
    individual DER blobs.
  * The **ldapmessage** level has taken the top-level DER blob apart, and
    parsed much of the data inside it.  This can be seen from the parameters
    passed at this level.
  * The **operation** level has further processed the LDAP message into an
    operation, and provides structures adapted to the operation at hand.
    These are switched to implementation routines.
  * Finally, the lowest level handles the furthest parsed messages.

This describes parsing the byte stream into individual operations; there is
a mirrorred path up for packing operations back into a byte stream.


## Flexible and Efficient

It is not always necessary to pass through the entire stack, and LillyDAP is
designed to give full control of this.  As a result, various operations on
LDAP can be composed in a highly efficient manner.

![Wild Compositions of LillyDAP layers are possible](pix/stack-flexibility.png)

This ability to take messages apart up to the level that is meaningful for a
piece of middleware, and either recompose or further decompose it, provides
a lot of flexibility and avoids too much zeal in processing LDAP.  It may well
be the most efficient approach to processing LDAP while in transit.

In addition to that, the techniques with which LillyDAP was programmed are
very efficient.  First, its use of
[Quick DER](https://github.com/vanrein/quick-der)
means that it is very conservative in its use of memory allocation and
copying; second, its region-based memory allocator can be used to keep the
memory management highly localised, for instance with a memory region for
each query.  This saves a lot of administration overhead and simplifies
programs.  (These techniques are very much in line with what makes Nginx
great, and that is not a coincidence.)

Much of the pleasantness of using LillyDAP comes from overlay structures,
that overlay simple arrays of the `dercursor` structures that the underlying
Quick DER library uses.  The overlay structures provide field names to route
a C expression to the right `dercursor` to work on.  It is possible to use
[Quick DER API calls](https://github.com/vanrein/quick-der/blob/python-codegen/USING.MD)
and especially the
[pack syntax](https://github.com/vanrein/quick-der/blob/python-codegen/PACK-SYNTAX.MD)
to work on the structures passed around by LDAP.  Quick DER comes with the
definitions for LDAP already built-in, and LillyDAP adds more details, such
as operation descriptive tables.  In fact, LillyDAP works hard to deliver you
with types that fit the operation you are working on, so you will never notice
that it is a really simple data structure with some typing cleverness
overlaying it.  You won't notice that, but your (embedded) code size will!


## Setting up LillyDAP

LillyDAP tries to trim down binary sizes, so it can even be used in
constrained embedded environments.  This specifically means that it provides
a number of components that are not linked up by default &mdash; so a
`NULL` value in a pointer does not mean that a default will be substituted,
because that would force linking default handling code.  A `NULL` really
means that an aspect of LillyDAP is not supported.

As a result, you need to setup a few things explicitly.  This is not always
a real concern; much of it can be done efficiently, in static data structures
that you define in your program.


### Memory Allocation Functions

The first thing one should do to setup LillyDAP, is provide it with
memory handling routines.  LillyDAP uses a pool-based memory handler,
but you must provide one. (Another name is region-based handler).
For convenience, a simple pool-based allocator called *sillymem* is
provided, but you can also wire in your own. Note that you must wire
in the allocator by hand; LillyDAP does not come with *sillymem* pre-configured.

The API that the memory handler follows is defined in [mem.h](include/lillydap/mem.h),
and consists of three functions: newpool (to create a new pool, or region),
endpool (to release a pool, or region) and alloc (to allocate memory from a pool).
Pools are allocated and released. Individual memory requests are allocated from
a pool and not released -- that is done by releasing the entire pool. This
reduces memory-management overhead in the processing pipeline.

To configure LillyDAP to use the memory allocator, assign function pointers
to the three symbols provided. For example, to wire in *sillymem* (which provides
functions called `sillymem_newpool()` and similar) to LillyDAP's memory handling:

```
lillymem_newpool_fun = sillymem_newpool;
lillymem_endpool_fun = sillymem_endpool;
lillymem_alloc_fun   = sillymem_alloc;
```

Within LillyDAP code (including middleware built on top of LillyDAP), use
the LillyDAP memory-handling API instead of calling directly to the underlying
memory handler. This ensures consistent memory usage (and in particular consistent
allocations and releases).

When you want to allocate memory, you should start by allocating a pool
to allocate from:

```
LillyPool *lipo = lillymem_newpool ();
if (lipo == NULL) {
    fprintf (stderr, "%s: Failed to allocate a memory pool\n", progname);
    exit (1);
}
```

Individual allocations are done from a pool by calling `lillymem_alloc()`,
passing in the size of the allocation; or `lillymem_alloc0()` which will
zero-fill the resulting memory.

```
void *p = lillymem_alloc (lipo);
```

You do not have to `free()` the individual allocations from a pool,
but instead release the entire pool at once:

```
lillymem_endpool (lipo);
```

The idea is that you use this to simplify your programs; it is especially
effective for short-lived storage requirements, such as per-query storage,
possibly topped off with some per-connection storage.  Cleaning up a
pool can be done when a query is handled, or when a connection is closed.
The cleanup of a query can in fact be delegated to the writing routines;
the `lillyget_xxx()` routines pass a pool down the stack, and `lillyput_xxx()`
pass it up, the idea being that the former creates the pools and the latter
destroys them.  You may intervene with this, and decide to pass on a fresh
pool if you would like to retain data for longer than the called
routines use it.

### Operation Functions

You also need to link the operations, as they are set to `NULL` or
undefined by default.  The stack shown above already gives
alternative arrows leaving each block, and you may set the defaults or leave
them `NULL` to indicate that they are not implemented.  You may of course
route operations to your own routines, which would then process them like
callbacks.

```
LillyDAP *lil;
lil = lillymem_alloc0 (lipo, sizeof (LillyDAP));

lil->lillyget_dercursor   =
lil->lillyput_dercursor   = lillyput_dercursor;
lil->lillyget_ldapmessage =
lil->lillyput_ldapmessage = lillyput_ldapmessage;
lil->lillyget_operation   =
lil->lillyput_operation   = lillyput_operation;
```
(Future versions of LillyDAP will probably have a static structure with this
setup, so it can be setup in data structures.)

If you want to parse operations into individual operations and data
structures, you will need to setup the according switch with the callback
functions that handle them:
```
static const LillyOpRegistry opregistry = {
    .by_name = {
        .BindRequest = lillyput_BindRequest,
        .BindResponse = lillyput_BindResponse,
        .UnbindRequest = lillyput_UnbindRequest,
        .SearchRequest = lillyput_SearchRequest,
        .SearchResultEntry = lillyput_SearchResultEntry,
        .SearchResultReference = lillyput_SearchResultReference,
        .SearchResultDone = lillyput_SearchResultDone,
    }
};
```
which you will of course hang into the connection's `LillyDAP` structure with
```
lil->opregistry = &opregistry;
```

The management of an LDAP connection is done through an `LillyDAP` structure,
and this holds [TODO:REFERENCES TO] the static function calling scheme that
forms the actual protocol stack used.  The named operations do actually
exist, and can be setup if they are what you want; or you may call them from
a bypass function instead.

Please see the
[test programs](test/lillypass.c)
for up-to-date examples.


## Use with Event Loops

The LDAP protocol consists of asynchronous messages, meaning that request and
response are independent messages; in fact, some requests are answered with
multiple responses, so there is not even a one-to-one relation between requests
and responses.

Each incoming message translates to a callback to a `lillyget_xxx()` routine
setup in the calling scheme.  And each outgoing message is created by calling
a `lillyput_xxx()` routine.

Near the network socket, the model is geared towards an event loop.  So, the
`lillyget_event()` and `lillyput_event()` routines are defined to trigger
treatment of an event for reading and writing, respectively.  The file
descriptors to be used are part of the `LillyDAP` structure that is passed along
with the event callbacks.


## Use with Threads

The LillyDAP routines are thread-safe, as long as each
`LillyDAP` structure's events are processed in one thread.  Meaning,
only one thread should call `lillyget_event()` and one (possibly
other) thread should call `lillyput_event()`.  More precisely,
the functions are not re-entrant and they want to see a continuous
byte sequence on their input or output connection.

Note that it is possible to initiate (worker) threads for the other
calls.  So, a call to `lillyget_dercursor()` or any of the other
functions can be bypassed and a worker thread selected to get the
work assigned.  This is possible because the event handler in
`lillyget_event()` allocates its own memory region pool and is
therefore completely detached from the rest of processing.

The same is true for the `lillyput_xxx()` routines.  However, given
that we can split and join data, sometimes threads do come together.
This is the case in the queue of data standing by to be written out.
The queue mechanism has been setup with lock-free mechanisms, so you should
be able to use any number of threads you like and you should not see them
slow down noticably on locks because there are no locks.

LillyDAP contains a stress test for multi-threading, namely
[stampede](test/stampede.c),
that initiates a large number of threads and makes them line up for
massive writes.  If any program would bring down the concurrency model,
then this is it.

