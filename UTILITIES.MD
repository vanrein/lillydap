# LillyDAP additional utilities

> *The utilities of LillyDAP are not required for general processing of LDAP
> messages, but may help out with them.  Usually, they will implement one
> or a few operations.*

The utilities are add-on libraries or library archives that can be helpful
to the application programmer, and avoid repeating work that is not related
to the data manipulation content of the applications.


## Memory Management

The LillyMem API assumes certain things about the context in which LillyDAP
is run; a number of memory management routines must be registered.  There
are a few default implementations that are not efficient, not clever and
not advised at all -- but that may be useful in the early stages of
development, and that only assume a POSIX environment.

This silly implementation of the environment is called SillyMem.  It is
*not* part of the normal utilities set, but may be linked separately.
Do not rely on this if efficiency or scalability are among your concerns.


## TLS Utilities

These utilities implement the StartTLS operation, in the service of
encryption and possibly authentication.  One implementation works
by passing control over the
[TLS Pool](http://tlspool.arpa2.net),
and harvest the remote identity as an authenticated identity.


## Authentication Utilities

These utilities help with the Bind and Unbind operations.  Versions for the
client and server side exist.  There is no support for Simple authantication,
but SASL is supported.

There are various choices of implementation for SASL in general.
There is an implementation that invokes a SASL library, one that relays to
individual SASL mechanism utilities, and then there are utilities that
steer towards a single SASL mechanism such as GSSAPI and Kerberos5.  There
also is support for SASL EXTERNAL, based on prior authentication with TLS.

An implementation of the
[WhoAmI](https://tools.ietf.org/html/rfc4532)
operation is also included in the utilities.


## Authorisation Utilities

There is an option in LDAP to authorise a user identity after authentication,
based on the control for
[Proxied Authorization](https://tools.ietf.org/html/rfc4370)
that may be supplied with each and every operation, including even the
[WhoAmI](https://tools.ietf.org/html/rfc4532)
operation.


## Utility Support for InternetWide / ARPA2

The utilities described above integrate well with the ARPA2 projects,
making this  fit in with the InternetWide Architecture, in the following
ways:

  * The [TLS Pool](http://tlspool.arpa2.net) support means that advanced
    mechanisms such as [TLS-KDH](http://tls-kdh.arpa2.net) can be used;
    this introduces the facilities for
    [realm crossover for Kerberos](http://realm-xover.arpa2.net/kerberos.html).
  * SASL is used as a second (and more broadly implemented) opportunity for
    Kerberos authentication, again with the intention of integrating with
    realm crossover.
  * SASL can alternatively be used with the EXTERNAL mechanism to
    [drop privileges](http://internetwide.org/blog/2016/12/18/id-6-inheritance.html)
    to an identity that may be more suited to use while accessing LDAP-published
    data services; for instance, an alias or a group member's name.
  * LDAP supports [Proxied Authorization](https://tools.ietf.org/html/rfc4370)
    which enables bulk services after a proxy that handles authentication and
    authorisation.  This is one of the design purposes of LillyDAP.

Support for ARPA2 projects is important, because LDAP is vital to the
[Global Directory](http://rickywiki.vanrein.org/doku.php?id=globaldir)
including
[Reservoir](http://reservoir.arpa2.net)
component, as a metadata storage facilitie.
Especially the Input and Output Queues can have a tendency to change
much faster than storage-centric LDAP solutions assume.

The general idea of the Global Directory and the Reservoir can therefore
distribute LDAP queries to different services, while making it look like
one integrated tree under a domain name.


