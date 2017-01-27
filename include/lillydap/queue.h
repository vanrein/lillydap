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
 * The procedure for adding this to an LDAP are documented in lib/queue.c
 * in the LillyDAP source code.  Lock-free concurrency, I feel so smug!
 */
typedef struct LillySend {
	struct LillySend *put_qnext;
	LillyPool put_qpool;
	dercursor cursori [1];
} LillySend;


/* Append a addend:LillySend structure to the lil->head,lil->tail:LillySend**
 */
void lillyput_enqueue (struct LillyConnection *lil, struct LillySend *addend);


/* Enqueue a message in a single dercursor.  Normally, we supply a series of
 * dermessages, so this is just there to mirror properly; it may actually be
 * useful as a value for a lillyget_dercursor() pointer.
 */
int lillyput_dercursor (LillyDAP *lil, LillyPool qpool, dercursor dermsg);


/* Test if there is anything in the queue for LillyPut
 */
bool lillyput_cansend (struct LillyConnection *lil);


#endif /* LILLYPUT_QUEUE_H */
