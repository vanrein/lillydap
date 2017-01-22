# LillyDAP (Little LDAP)

> *LDAP is protocol for data communication, with rich semantics for data
> modelling, security and database administration.  But implementations of
> LDAP start off from a notion of data storage, but are not ideal for
> handling dynamic data.  LillyDAP was designed to change that.*

Most of today's developers focus solely on HTTP to carry their data
definitions.  This even happens when LDAP would be a better carrier, which
it usually is, due to much richer and finer-grained syntax and semantics.

But this isn't just about standards; it's also about the technology
implementing it.  The most well-known open source directory is
[OpenLDAP](http://www.openldap.org),
and there are others like
[389ds](http://directory.fedoraproject.org)
and
[ApacheDS](https://directory.apache.org).  All these solutions are
storage-centric, though they add dynamicity options through mechanisms like
[overlays](http://www.openldap.org/doc/admin24/overlays.html)
and
[stored procedures with triggers](https://people.apache.org/~ersiner/ldapcon.2007/LDAPcon.2007_LDAP.Stored.Procedures.and.Triggers.in.ApacheDS_by.Ersin.Er_Paper.pdf)
In all cases, dynamicity is a bit of an afterthought, storage is central and
there is only limited facilitation for dynamicity.

HTTP on the other hand,
has a long tradition of plugins that provide dynamicity to the data
set, and this is a large part of its success story.  The simple mechanisms
for dynamic plugins, pioneered by `cgi-bin` technology, has given rise to
an incredible enthousiasm for dynamic HTTP services.  There is no way to
do this with current-day LDAP solutions, and this is the kind of thing
that LillyDAP wants to improve on.


## Reasons for using LDAP

Given its omnipresence, HTTP is used to do things in spite of better otions.
HTTP was designed for resource transfer as large BLOBs without known content,
so any processing of data contained in those BLOBs depends on semantics
that must be created *in situ*, for instance by interpreting the
contents of a particular JSON format.  Although this gives the programmer
maximal freedom, it also means that many things need to be reinvented.
Many of the facilities that are fully standardised (and that represent a lot
of experience) are entirely lacking in HTTP, also when adding REST.
On top of that, HTTP is stateless in nature, which often conflicts with
application requirements.

This is not a theoretical thought strand.  It is directly reflected in the
high complexity of standards like CalDAV, which have great difficulty to
implement locks and which need to resort to polling to obtain updates.
Polling is inefficient and more expensive than needed when done from a
mobile device.

To name a few semantical uses that LDAP adds, relative to HTTP and REST:

  * Searching *inside* the transferred objects with powerful filter
    expressions; LDAP objects have attributes with well-defined semantics;
    their scheme can be locally extended without risk of conflict with
    other local extensions (!)
  * Transactions spanning across individual updates; this is possible
    because LDAP is connection-oriented and so it can recognise whether
    a client has terminated or crashed -- and its resources should be
    freed
  * Atomic updates, even featuring preconditions that can be imposed on
    such an update: "Add this new attribute value, but only under the
    condition that another attribute (value) is absent"
  * Subscription to data, basically saying "please tell me about changes
    since I connected last, and send me (virtually instant) updates for
    the remainder of this connection"

Having said this, HTTP and REST are much better suited for the transfer of
BLOBs.  Doing that over LDAP is possible in the protocol, but not advised.
(Though one might imagine a front-end that resolves a particular form of
reference to an object store and delivers them inlined in an LDAP object;
this would bother the front-end specialised in data pumping, but it would
releave the directory server of large data blocks.)


## Reasons for using LillyDAP

What seems to be missing in the LDAP landscape is a simple mechanism to
plugin dynamic scripts and tools that can then be used to deliver data
on the fly, as is customary over HTTP, but with the added benefits of
the more developed protocol.  LDAP servers tend to be self-contained,
and not grant plugin scripts in the style that we have come to know
from HTTP with its rich flavours of Server Side Includes, FastCGI,
WSGI, and all sorts of language-specific plugins.

This is where LillyDAP steps in.  The standard API for LDAP is defined in
C, and is straightforward enough.  So is the translation from and to the
LDAP network protocol; this takes a little bit of LDAP knowledge and
BER.  In LillyDAP, the BER layer is easily and efficiently handled with
[Quick DER](https://github.com/vanrein/quick-der).  This library was
written in a terse, embedded style.  LillyDAP follows that approach
to come to an event-driven **LDAP kernel** suited for lock-free concurrency
models.  LillyDAP assumes running in an environment where events trigger
the invocation of event handler functions for reading and writing byte
streams, and when an LDAPMessage is complete it translates to invocation
of callback functions, which most or all of the data already packed into
easy-to-handle formats.

One might view LillyDAP as an engine for LDAP, that turns the protocol into
a remote procedure call mechanism that centers around data.  Data that
may be stored, dynamically generated, modified on the fly, and so on.
The procedure calls can be routed any way desired; an application may
have its own logic to filter or modify the LDAP exchange, and pass it on
to a backend server or handle it locally.  It may also host plugin modules
written in one's favourite language, be it Python, C++ or Java.

In short, LillyDAP does to data what HTTP does to complete resources,
and it does it very, very well.


## Examples

A few examples may help to explain the kind of applications for which
LillyDAP could make a difference.


### OpenPGP key server

It is possible to
[run an OpenPGP key server](http://rickywiki.vanrein.org/doku.php?id=globaldir-5-openpgp)
under your own domain, and support others in automating the retrieval of
your keys and its updates.  GnuPG supports this mode of operation, so most
current implementations are ready to go!

Servicing keys from under the domains that they
claim to be from greatly simplifies the big problem of OpenPGP, namely to
validate a key's trust.  Place the key in LDAP, protect that with TLS
and store its certificate in a TLSA record signed with DNSSEC, and you have
a secure chain of trust from the DNS root, through the domain mentioned in
its email address, all the way to your OpenPGP public key.

The web of trust remains valuable to directly validate the people you met
in person, and the very general facilities it offers can be used in the
many creative ways for which it has been used.  But for hitherto unknown
contacts, the path throught the web of trust required more knowledge of
trust models than casual users have or want to have.  Their reliance on
domain-hosted key servers can help them directly validate remote contacts
that have setup this facility.

Unfortunately, running an LDAP server is not trivial.  OpenLDAP is reliable,
efficient and secure.  What it is not, is easy to setup.  It is nowhere near
the simplicity level of Apache, especially because Apache is usually already
running somewhere.

With LillyDAP however, you can write a simple program that you might run
in your `~/.gnupg` directory, to serve up what it finds there.  There are
two ways this could be done:

 1. Serve up the user's OpenPGP public keys (to anyone),
 2. Serve the user's entire key chain (to authorised users).

The second piece is in fact a personal key server that can be used to
service multiple GnuPG installations.  Keys are then easily, and sometimes
even automatically downloaded when they are needed.  As a user, you no longer
need to push and pull keys between machines and accounts!

LillyDAP is ultimately suited as a basis for a program that exports the
`~/.gnupg` of domain users over LDAP, as a domain-bound service.  It can
respond to search filters and attributes queried by interacting with the
key chain, and it may derive the
[customary attributes](https://wiki.gnupg.org/LDAPKeyserver#Installing_an_Additional_Schema)
and will not have to store them -- instead, it always serves up what is int
the pristine source, the key chain.

It is even possible to do intelligent things with the UserIDs that are
sent back.  It is possible to take OpenPGP keys apart, and pass only those
pieces that are considered useful, so only the UserID that matches the
requested domain could be sent out.


### Privacy Filtering

One problem with LDAP is that it makes a lot of information available -- and
some of that may be considered personal.  For example, think of email
addresses which many would argue are too personal to distribute to
arbitrary online peers.

On the other hand, being able to search for data based on email addresses
is useful.  So what can we do?

One solution could be to only return an email address (or userid, or other
data considered private) only inasfar as it exactly matches a value in
the search filter.  Such a rule is non-standard but useful.  With LillyDAP
you can insert it in your LDAP setup even if your server cannot do it.


## User-controlled ACL

In most LDAP systems, access control is provided through complex rules
that are targeted at system administrators.  It is not usually practical
to let users edit the ACL to the data they're maintaining.  Still, there
could be
[useful applications](http://reservoir.arpa2.net)
where this is precisely what we need.

When existing access control does not work well enough, or when it is not
sufficiently portable between LDAP server solutions, or when it is not
ideal to locate it inside the LDAP server because authorisation is handled
in a proxy, we would like a "wrapper" that can handle authorisation.

Imagine adding attributes such as `readers` and `writers`, with user names or
patterns for such names to grant access.  This might be interpreted by such
a wrapper, and still be sufficiently workable for understand by users.  It
is quite possible to make just that kind of wrapper with LillyDAP, and perhaps
integrate it with the functions of authentication and authorisation, and
let the LDAP server focus on data issues.

The most important issue here is perhaps not even that more flexibility is
created for ACL models; it is that the programming model of an LDAP server
can be easily extended by individual tool developers, of which there are
many in the open source world.  LDAP has not nearly been as good  at
motivating this incredibly potent resource as HTTP has, and LillyDAP is
hoped to provide a solution to that.


## Bidirectional LDAP

Although not everybody knows it,
[LDAP can be a P2P protocol](https://tools.ietf.org/html/rfc4531)
and that means that its very potent data processing semantics can readily
be used in modern, distributed networks that defy network models with a
central controller, such as a server.  In many ways, this is more elegant
than the HTTP application that needs to rely on
[Server-Sent Events](http://www.w3schools.com/HTML/html5_serversentevents.asp)
with the customary minimalistic semantics, and without actually dropping
the client/server distinction.

The fact that it is possible in LDAP does not mean that all LDAP software
is willing to operate bidirectionally.  Even parts of an infrastructure may
object.  With LillyDAP, it would be trivial to split the two directions
into two independent streams, and thereby work around such funny parts
of an infrastructure.


### Remote Locking

A very simple demonstration of the powerful semantics of LDAP would be
a remote locking mechanism.  This can be based on the
[Assertion Control](https://tools.ietf.org/html/rfc4528),
which is usually referred to informally as
[Test-And-Set](https://en.wikipedia.org/wiki/Test-and-set)
semantics.  This basic facility suffices to implement a plethora of
locking and other clever primitives.  And since it is approached over a
network, these pritimites are networked locks.  How cool is that?


## Integration into Nginx

LillyDAP is functional and useful to provision stand-alone programs.  But
a strong wish that we have for the future, which is to support the LDAP
protocol in Nginx, just like it supports HTTP, SMTP, POP3 and IMAP.
The architecture of LillyDAP lends itself well as a basis for this
integration; both event-driven processing and region-pooled memory
allocation have been included into LillyDAP from the onset.  And no,
that is not really a coincidence.

Nginx can help to build a virtual LDAP directory consisting of subtrees
from various places.  This means it would make a directory as pluggable
as web sites in common web servers.
Plus, Nginx can be used to implement load balancing, failover and traffic
redirection; it can offload the backend by collecting requests from many
client connections and once complete it can pass them along.  And it can
even compose responses coming from multiple sources.

The LDAP model includes
[Proxied Authorization](https://tools.ietf.org/html/rfc4370)
to support such bundling of connections even when clients may all have
different authorisations.  In other words, the LDAP server accepting
these can be addressed over a few bulk-traffic connections by a proxy,
even if the proxy has many connections from clients open.  The proxy
would in this scenarion authenticate and authorise the client, and store
the results with the connection to pass to the backend through
Proxied Authorization.

To make this work really well, Nginx would need to support SASL in the
same way as an LDAP directory does; to this end, a second protocol
named sasl should be added, and handled by proxying to HTTP and/or
LDAP backends.  This mechanism would also be helpful for the current
implementations of SMTP, POP3 and IMAP.  And it will be helpful with any
future attempts of integrating XMPP and AMQP into Nginx.
(In case you wonder, we have the
[IdentityHub](http://internetwide.org/tag/idhub.html)
for the
[InternetWide Architecture](http://internetwide.org/tag/architecture.html)
in mind with this example.)

Since LDAP can be a P2P protocol, it would be possible to listen to
a backend proxy, and see requests in the opposite direction pass through.
The reverse flow direction will normally not be used until an
[LDAP Turn operation](https://tools.ietf.org/html/rfc4531)
has asked for it, but as should be clear from this, Nginx holds good cards
for formulating treatment of the Turn operation in its configuration files.

