# LillyDAP test directory

> *These are programs that were developed alongside LillyDAP, to test its
> functionality interactively.  The same tests can at some point be used
> to accommodate unit testing.*

A number of test files can be found in `ldap/*.bin`; these represent
actual flows of LDAP traffic, split into independent LDAPMessage chunks.
The file names hint at their meaning; you can use
[derdump](https://github.com/vanrein/hexio/blob/master/derdump)
which will constructively report on illegal DER chunks.


## LillyDump

This test takes individual LDAP fragments and pass them into the routine
`lillyget_event()` and passes them all the way down to callback functions
for individual LDAP operations.  The data structures are pre-parsed, and
so they provide symbolic paths that conform to the ASN.1 field names.
They usually end in derptr/derctr values.

LillyDump demonstrates how these data structures can be approached to
retrieve and print the values contained in them.  The output is a
textual dump of the contents of the DER fragmant(s) passed as commandline
arguments.


## Stampede

We have made quite a bold implementation in queue.c -- a lock-free concurrent
model of our own design.  It's always good to be cautious about such things.
(As it turns out, it was warking well from the beginning... clearly the
benefit of thinking *really hard* about this complex code!)

The `stampede` test initiates thousands of threads, each bestowing a
1000 lines of output in groups of 3 lines each, to `stdout`.  On a uniprocessor
machine (or VM) you would get close to sequential output; on a multiprocessor
your should see the output from various threads get mixed, but groups of 3
staying together.  Also, given a thread id (the first number), the line counter
(second number) should monotonouslyincrement under each given thread id.

This program should run for a while, dumping `stdout` into a file, and then
some analysis can be performed or we can simply accept the fact that it
returns with `exit(0)` instead of an error or a crash.

Each thread creates a new memory region for each set of at most 3 lines, so 
there are plenty of memory operations.  If anything goes wrong, then this is
where it would be most likely to happen; memory released by one thread being
reused in another, can only work well if all the lock-free constructs work
really well.


## LillyPass

This test is a pass-through vehicle for LDAPMessage chunks.  They should
appear at the output just as they are on the input, with no more than
encoding changes caused by the variability in the BER format.  In many
cases however, BER is sent as DER, and that would always be the same.

Needless to say that the next step is a filtering utility.

