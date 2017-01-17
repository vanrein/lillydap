# LillyDAP (little LDAP)

> *LDAP is protocol for data communication, with rich semantics for data
> modelling, security and database administration.  But implementations of
> LDAP start off from a notion of data storage, and lack in easy dynamicity.
> LillyDAP changes that.*

Most of today's developers focus solely on HTTP to carry their data
definitions.  This even happens when LDAP would be a better carrier, which
it usually is, due to much richer and finer-grained syntax and semantics.

But this isn't just about standards; it's also about technology.  Where
HTTP has a long tradition of plugins that provide dynamicity to the data
set, this is only marginally true for LDAP.  Furthermore, LDAP servers
are on the heavy side, because they implement a lot of that rich
semantics.


## Reasons for using LillyDAP

What seems to be missing in the LDAP landscape is a simple mechanism to
plugin dynamic scripts and tools that can then be used to deliver data
on the fly, as is customary over HTTP, but with the added benefits of
the more developed protocol.

This is where LillyDAP steps in.  The standard API for LDAP is defined in
C, and is straightforward enough.  So is the translation from and to the
LDAP; this takes a little bit of LDAP knowledge and a few more clues about
BER.  The latter can be handled easily and efficiently with
[Quick DER](https://github.com/vanrein/quick-der).  This library was
written in a terse, embedded style.  LillyDAP follows that approach
and can therefore integrate into event-driven architectures with dedicated
memory management requirements.

What is also missing in the LDAP landscape is a standard API in C for
servers; the existing API only covers clients.  A server however, can
be considered the receiving end of this API.  LillyDAP allows LDAP server
nodes to register a callback structure filled with the routines from the
client API, that should be called as though the client called them
directly.

And now we finally arrive at what LillyDAP will do.  It turns LDAP into
a remote procedure call mechanism that centers around data.  Data that
may be stored, dynamically generated, modified on the fly, and so on.
It does to data what HTTP does to complete resources, and it does it
very, very well.


## Examples

A few examples follow.


### OpenPGP key server

It is simple to
[run a OpenPGP key server](http://rickywiki.vanrein.org/doku.php?id=globaldir-5-openpgp)
under your own domain, where it can add validation to the keys for that domain
in a way that public key servers cannot meet.
Note how this greatly simplifies the biggest problem of OpenPGP, namely to
learn whether a key can be trusted.  Put it in LDAP, protect that with TLS
and store its certificate in a TLSA record signed with DNSSEC, and you have
a secure chain of trust from the DNS root to your OpenPGP public key.

But actually running an LDAP server is not always easy.  OpenLDAP is reliable,
efficient and secure.  What it is not, is easy to setup.  It is nowhere near
the simplicity level of Apache, especially because Apache is usually already
running somewhere.

With LillyDAP however, you can write a simple program that you might run
in your `~/.gnupg` directory, to serve up what it finds there.  There are
two ways this could be done:

 1. Serve up the user's OpenPGP public keys (to anyone),
 2. Serve the user's entire key chain (to authorised users).

The second piece is in fact a personal key server that can be configured
in all GnuPG installations.  Keys are then easily, and sometimes even
automatically downloaded when they are needed.  Indeed, you no longer need
to push and pull keys between machines and accounts!

There is no reason why a single program couldn't do both, actually.  But
it is a bit more complicated, and doing it separately is probably just as
effective.


### Privacy Filtering

One problem with LDAP is that it makes a lot of information available -- and
some of that may be considered personal.  For example, think of email
addresses which some might argue are too personal to distribute to
arbitrary online peers.

On the other hand, being able to search for data based on email addresses
is useful.  So what do we do?

A possible solution is to deliver an email address (or userid, or other
data considered private) only inasfar as it exactly matches a value in
the search filter.  Such a rule is non-standard but useful.  With LillyDAP
you can insert it in your LDAP setup even if your server cannot do it.


## Bidirectional LDAP

Although it is not widely known,
[LDAP can be a P2P protocol](https://tools.ietf.org/html/rfc4531)
and that can be used in situations where HTTP applications depend on
[Server-Sent Events](http://www.w3schools.com/HTML/html5_serversentevents.asp)
with the customary minimalistic semantics.

But not all software will like LDAP Requests to pass in both directions.
LillyDAP can remedy that by treating the two directions separately, even
when the run over the same physical connection.

It is up to each
LillyDAP application whether to do this, and how; even when many
applications will behave like a pipeline with an input on one end
and an output on the other, there is no reason why applications
couldn't connect multiple nodes together.


### Remote Locking

A very simple demonstration of the powerful semantics of LDAP would be
a remote locking mechanism.  This can be based on
[Assertion Control](https://tools.ietf.org/html/rfc4528),
which is usually referred to informally as
[Test-And-Set](https://en.wikipedia.org/wiki/Test-and-set)
semantics.  This basic facility suffices to implement a plethora of
locking primitives.  And since it is approached over a network,
these pritimites are networked locks.  How cool is that?


## Integration into Nginx

One of our wishes for the future is to integrate the LDAP protocol into
Nginx, next to HTTP.  The architecture of LillyDAP lends itself well for
such actions; both event-driven processing and region-pooled memory
allocation have been included into LillyDAP from the onset.

The remarks below on Nginx are a wish list; LillyDAP can be functional
on its own, but is simply better when built into a proxy like Nginx.

Nginx can help to build a virtual LDAP directory built from smaller parts.
This means it would do for LDAP what Apache and Nginx already do for HTTP.
Plus, Nginx can be used to implement redundancy, failover and traffic
redirection; it can offload the backend by collecting requests from many
client connections and once complete it can pass them along.

The LDAP model includes
[Proxied Authorization](https://tools.ietf.org/html/rfc4370)
to support such bundling of connections even when clients may all have
different authorisations.

To make this work really well, Nginx would need to support SASL in the
same way as an LDAP directory does; to this end, a second protocol
named sasl should be added, and handled by proxying to HTTP and/or
LDAP backends.  This mechanism would also be helpful for the current
implementations of SMTP, POP3 and IMAP.  And it will be helpful with any
future attempts of integrating XMPP and AMQP into Nginx.

Since LDAP can be a P2P protocol, it would be possible to listen to
a backend proxy, and see requests in the opposite direction pass through.
This will normally not be used until an LDAP Turn operation has asked
for it, but as should be clear from this, Nginx holds good cards for
formulating this in its configuration files.

