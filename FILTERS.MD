# Dealing with LDAP Search Filters

> *Filters in LDAP are difficult to handle for LillyDAP, but easy for the
> programmer.  We hereby explain how to handle Filters.*

First, LillyDAP is built on top of
[Quick DER](https://github.com/vanrein/quick-der)
which makes it highly efficient *because of* a limiting assumption that all
data can be parsed into set positions in fixed data structures.  This allows
a generic `der_unpack()` routine to deliver an array of same-structured
`dercursor` values (holding pointer + length) without caring much about what
it means; Quick DER and LillyDAP overlay theses with proper C structures to
allow the programmer to pleasantly navigate these arcane structures.  All
this is automatically generated from ASN.1 specifications by the
`asn2quickder` compiler incorporated with Quick DER.

There are a few places where this assumption is too limiting, and more work
needs to be done:

  * the `SEQUENCE OF` and `SET OF` type declarations in ASN.1 specify any
    number of same-shaped elements, and Quick DER cannot match that with its
    static type structures.  This is usually overcome by invoking `der_unpack()`
    once more, and [TODO: NOT FINISHED YET] LillyDAP does this to conceal such
    idiosyncracies of Quick DER, while retaining the benefits of highly
    efficient DER parsing.
  * recursive type definitions cannot be reduced to a static form.  This is no
    problem when the recursion always involves a `SEQUENCE OF` or `SET OF`, but
    it is a problem when there are cases which do not have that.


## The problem with RFC 4511

Given our choice to parse with Quick DER, RFC 4511 delivers a problem in
its `Filter` specification, which is recursive and not always with a
`SEQUENCE OF` or `SET OF` in the recursive loop:
```
Filter ::= CHOICE {
     and             [0] SET SIZE (1..MAX) OF filter Filter,
     or              [1] SET SIZE (1..MAX) OF filter Filter,
     not             [2] Filter,
     equalityMatch   [3] AttributeValueAssertion,
     substrings      [4] SubstringFilter,
     greaterOrEqual  [5] AttributeValueAssertion,
     lessOrEqual     [6] AttributeValueAssertion,
     present         [7] AttributeDescription,
     approxMatch     [8] AttributeValueAssertion,
     extensibleMatch [9] MatchingRuleAssertion,
     ...  }
```
The `and` and `or` cases are not a problem because these are broken up by
the `SET OF` declaration, but `not` is a problem -- when trying to describe
it as a static structure, the most general form would want to support
`[2] [2] [2] [2] [2] [2] ...` which is infinite.


## The pragmatic resolution

We have redefined the `Filter` to make it suitable for Quick DER, and this
is the version included in Quick DER.  It has some ramifications for
processing it.  The altered specification is:
```
Filter ::= ANY  --FilterOperation (always)

FilterOperation ::= CHOICE {
     and             [0] SET SIZE (1..MAX) OF filter Filter,
     or              [1] SET SIZE (1..MAX) OF filter Filter,
     not             [2] Filter,
     equalityMatch   [3] AttributeValueAssertion,
     substrings      [4] SubstringFilter,
     greaterOrEqual  [5] AttributeValueAssertion,
     lessOrEqual     [6] AttributeValueAssertion,
     present         [7] AttributeDescription,
     approxMatch     [8] AttributeValueAssertion,
     extensibleMatch [9] MatchingRuleAssertion,
     ...  }
```

In terms of ASN.1 matching the data, this is not a change.  But in terms
of parsing it, there is one change, namely the `ANY` that occurs at every
stage of the `Filter`, which cannot be unfolded without some manual work.

The way Quick DER handles `ANY` is by setting a `dercursor` for the type
to the total DER encoding, basically freeing it for recursive handling.

One recursive handling style would be to invoke `der_unpack()` no the
stored `dercursor` for the `ANY` value.  Another handling style is to
manually iterate and recurse through the structure.  Given the simplicity
of the `Filter` and the need to look at the `[N]` tag to switch between
handlers, the overhead of the latter approach is relatively small.


## Example Code

Please review the `print_filter()` routine in the
[lillydump.c program](test/lillydump.c)
for a complete example that recurses to print the `Filter` structure.

Note how the recursive routine starts by iteratively diving into
`not` tags, toggling the `inverted` bit for each one found,

    do {
        err = err || der_header (&filter, &tag, &len, &hlen);
        if ((err == 0) && (tag == DER_TAG_CONTEXT (2))) {    /*NOT*/
            inverted = !inverted;
            filter.derptr += hlen;
            filter.derlen -= hlen;
            continue;
        }
    } while (0);

This is a mathematical optimisation, so it is good to realise that this
is not a literal print routine.  Effectively, we will be pushing the
`not` operation into the `Filter` expression until they all end up before
the leaf expressions.  The intermediate `and` and `or` operations simply
swap when an inversion passes through, accoring to
[De Morgan's laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws).

The collected value in `inverted` is used to toggle between the `and` and
`or` cases,

    case DER_TAG_CONTEXT(0):    /*AND*/
    case DER_TAG_CONTEXT(1):    /*OR*/
        if (inverted) {
            tag ^= DER_TAG_CONTEXT(0) ^ DER_TAG_CONTEXT(1);
        }

What remains is to `der_enter()` the filter, and then to repeatedly
use `der_focus()` on the first component, and then `der_skip()` to the
next.  A recursive call to `print_filter()` is made between these two
steps,

    err = err || der_enter (&filter);
    printf ("(%c", (tag == DER_TAG_CONTEXT(0))? '&': '|');
    while ((err == 0) && (filter.derlen > 0)) {
        dercursor subexp = filter;
        err = err || der_focus (&subexp);
        err = err || print_filter (subexp, inverted);
        err = err || der_skip (&filter);
    }
    printf (")");

This is a printing routine, but the same logic could easily be applied to
calculate the outcome of the `Filter`; this would then incorporate the
elementary comparisons, such as `equalityMatch` and `substrings`.

While developing these routines, it is good to keep in mind that the forms
`(&)` for True and `(|)` for False are commonly used in LDAP; the outcomes
are the neutral elements for the respective operator, so it will work quite
nicely to initialise a collected-boolean value to these values and then to
have a loop that can process zero or more elements that modify that
collected-boolean value.  Note that in the code shown above, the neutral
element can be determined from the operation *after* possible modification
of the operation tag to handle the `inverted` flag.

