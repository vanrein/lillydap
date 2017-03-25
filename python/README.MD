# Python mapping for LillyDAP

> *LillyDAP is a powerful engine for LDAP.  Although C is the best place to
> bring out its incredible efficiency, there is also the highly dynamic side
> of it, which may be better served in a language like Python.  For this
> reason, as well as for prototyping purposes, we map LillyDAP to Python.*

**TODO: WORK IN ITS INFANCY, THE CODE IS FULL OF KLUDGES AND BARELY TESTED**

A simple usage example of the LillyDAP port to Python is:
```
from lillydap import LillyDAP, BindResponse

class MyDAPapp (LillyDAP):

    def lillyget_BindRequest (self, msgid, bindreq, ctl):
        if bindreq.authentication.simple == 'sekreet':
            bindresp = BindResponse ()
            bindresp.resultCode = 0
            bindresp.diagnosticMessage = 'Welcome'
            self.lillyput_BindResponse (msgid, bindresp, {})

lil = MyDAPapp ()
lil.get_fd = 0
lil.put_fd = 1
#TODO# Set I/O to non-blocking
while True:
	# signal to cause a reading attempt
	# this is polling, you can do better
	lil.lillyget_event ()
	lil.lillyput_event ()
```

The class `LillyDAP` represents the structure by the same name in C, so
the handler for the LDAP connection.  Classes such as `BindResponse` come
from Quick DER; similarly, the parameter `bindreq` is an instance of
`quick_der.rfc4511.BindRequest` with an alias to `lillydap.BindRequest`.

The `LillyDAP` instance can override any functions that it wants to
handle locally; by default, the `lillyget_xxx()` calls go down until they
hit the end points like `lillyget_BindRequest()` which report a
`NotImplementedError` by default; in the opposite direction, the
`lillyput_xxx()` calls go up and send out the data passed to them.
Effort is being made to avoid entering Python on each step, but instead
a test is made if an overridden function is present, and if so the
necessary data structure mappings will be made.

Effectively, Python programmers can now program stimulus-response logic
that behaves like an LDAP server, client or middleware.  They can send
and receive data over the protocol, and even benefit from the ability
of going up and down the parsing/packing nesting of LillyDAP.

There should be a simple method for wrapping other LillyDAP
components for inclusion in Python, and vise versa.  This would lead
to optimal integration between code bases but, much more importantly,
also allow for stepwise mapping of Python prototypes to C deliverables.

It would be good to have things similar to the HTTP infrastructure in
Python, such as a `lillydap.BaseLDAPServer` class.
