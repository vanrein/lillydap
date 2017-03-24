# LillyDAP for driving LDAP into Python

> *This is a description of how LillyDAP can be used to make LDAP available
> in Python.  The resulting framework can serve both clients and servers,
> as well as any combintion thereof: filters, splitters, joiners.*

**TODO:** This is currently an unimplemented plan.

The mapping below intends to replicate the flexible minimalism of LillyDAP
in Python.  The purpose is to allow for scripted dynamic data engines.


## Contexts

It seems most sensible to map the `LDAP` structure to a Python class
`lillydap.LDAP` and setup any of the fields in or through that structure.
The underlying C structure is probably best used.

When we split `LDAP` into a dynamic and static part, we may choose to do
this in Python as well, or we may choose to clone the information, as the
memory management model is so different.


## API calls

The API calls can use the same names as in C, and use the mapped form of
the argument data.  This probably involves manual coding rather than
using an engine like Swig.  The functions themselves could be setup as
callbacks that are overridden in a manner as for `BaseHTTPServer` objects.

As with LillyDAP in C, the default behaviour would probably be to report
that a function is not implemented, which in Python would map to the
`NotImplementedError` being raised.  This would be used when the symbol
for an LDAPMessage is simply unavailable.

Subclasses of `LDAP` could facilitate more mappings or, perhaps better,
once we separate out the static parts from the `LDAP` object in C, we
could map these static objects to method mappings in a separate Python
class.  The former is probably simpler to understand, and lines up well
with other Python libraries such as the HTTP framework.


## Memory Allocation

The memory allocation routines of LillyDAP reside in the LillyMem module,
and can be set as desired.  LillyDAP does not cleanup but assumes that an
overall pool or region is deallocated at once.

In Python, we can rely on garbage collection for the cleanup, so that part
is even simpler; we simply allocate things.

A new concern in Python is avoidance of deallocation at a moment too early.
This means that routines must hold on to objects allocated by incrementing
their use count, until they can be released.  Since the C code assumes
deallocation per region, this is not entirely straightforward to map.
An easy solution is to map a region to a Python list that points to the
objects allocated within it, and have the use count of the region set to
one upon creation, and decremented upon cleanup.


## Technicalities

The operations that can be called on LillyDAP are implemented as calls
to the functions in LillyDAP.  This is relatively straightforward.

It would be possible to setup callbacks from LillyDAP to fallback to the
default functions, except when `PyObject_HasAttr()` indicates that an
object has the given method name, which will then be called with
`PyObject_CallMethod()` or `PyObject_CallMethodObjArgs()` and, if it is
not callable such as `None`, perhaps return `NotImplementedError`.
See the
[https://docs.python.org/2/c-api/object.html](object protocol)
of the Python extension API.

This can be used to simulate a superclass that can be overridden in a
concrete object.  Note that no calls to the super-version of the
function can be made; but that is not pleasant in Python anyway, so
we can make a choice of how to handle it here.  Calls to
`LillyDAP.mth(lil,...)` are not bad either, though perhaps not the
best form of integration.  It is also possible to lookup an attribute
(the name of a method) and compare it to the value fixed in the class;
if `D` inherits from `C` then `D.f == C.f` unless `D` overrides the
method `f` from `C`.

The most complex thing to handle is the mapping of data structures.  This
is easy however, when using the module `quick_der.rfc4511` and mapping the
named structures to and from the classes that represent the various types
that are passed along in DER form.  This means that switching between
operations is handled in Python, and not in the C function
`lillyget_operation()` that only unpacks structures partially.  A choice
needs to be made on handling the recursive
[Filter](FILTERS.MD)
structure, possibly by wrapping them in a recursive iterator object
or naively unfolding them into nested data.  An object might also
add computational benefits, including optimisations that make callbacks
to atomic tests, but avoid diving into hopeless corners of expressions.


## Or pure Python?

At the expense of having to maintain two libraries, it would also be
possible to implement the idea of LillyDAP separately, following the same
API idea.  LDAP, after all, is a protocol and can be parsed moderately
efficiently with Python as well, even if DER is not very script-friendly.

One intermediate appraoch with pure Python LDAP might use
[Quick DER](https://github.com/vanrein/quick-der/blob/master/PYTHON.MD)
as a support for DER parsing.  Since Quick DER does nothing in terms of memory
management, its integration with Python should prove more straightforward,
and it does handle the DER parsing -- which is surprisingly knowledge-dense
and so a good unit of sharing between Python and C code.

A more or less pure Python approach might integrate with the LDAP package
that already exists for Python, or it may reuse the name LillyDAP because
it shares its API and general philosophy to make LDAP available as a
general protocol for dynamic data.

The current feeling is that LillyDAP functions that are generic, so up to
the split data types for operations, can very well be used in their C
version, also for reasons of efficiency, and that individual operations
can be handled by the classes in `quick_der.rfc4511` and later LDAP
specifications.

