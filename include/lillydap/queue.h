/* <lillydap/queue.h> -- The queue for async yet atomical send of LDAP ops.
 *
 * The output queue holds a sequence of packets that are ready to be written.  
 * Queues are a necessity to overcome the possibility that we generate LDAP
 * operations at a faster pace than the send buffers are willing to take it.
 *
 * The implementation of the queue is based on atomic operations that
 * compare-and-swap the queue items.  Such items are appended by one of many
 * threads, and taken out by precisely one event-driven callback routine.
 *
 * To facilitate detection that the write operation may commence, a simple
 * test can be called on the LDAP structure holding the queue.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef LILLYPUT_QUEUE_H
#define LILLYPUT_QUEUE_H



/* The atomicity of this queue is founded on libOPA, for a number of reasons:
 *
 *  - targets the C language, usually based on assembly inlines
 *  - portable across quite a few platforms
 *  - no real constraints in terms of licensing
 */


#include "../import/openpa-1.0.4/src/opa_primitives.h"


/* The LillyConnection structure, also known as LDAP *, from <lillydap/api.h>
 */
struct LillyConnection;


/* Each LillySend represent items in the queue.  The entry holds one
 * or more dercursor elements; the last one has derptr == NULL and derlen == 0.
 * There may be a non-NULL LillyPool that is to be cleaned up after sending.
 *
 * The procedure for adding this to an LDAP are:
 *  1. Fill the structure, set next to NULL
 *  2. Use CAS to replace a previously sampled LillyConn->put_tail with this one
 *  3. If the old put_tail was NULL, set this LillySend in LillyConn->put_head
 *  4. Otherwise, set the ->next of the old put_tail to this one
 */
struct LillySend {
	struct LillySend *put_next;
	LillyPool opt_endpool;
	dercursor cursori [1];
};


/* Append a addend:LillySend structure to the lil->head,lil->tail:LillySend**
 */
void lillyput_enqueue (struct LillyConnection *lil, struct LillySend *addend);


/* Test if there is anything in the queue for LillyPut
 */
bool lillyput_cansend (struct LillyConnection *lil);


#endif /* LILLYPUT_QUEUE_H */