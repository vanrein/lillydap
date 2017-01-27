/* queue.c -- Handle output queue items for a LillyDAP connection structure
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <lillydap/api.h>
#include <lillydap/queue.h>

#ifndef CONFIG_SINGLE_THREADED
#   include "opa_primitives.h"
#endif


/* This code gathers input from potentially many threads into one queue.
 * As a result, it must guard the queue's tail, so that the threads append
 * to it in a proper sequence.
 *
 * The lock-free concurrency schema used here models the queue as a qhead
 * pointer, pointing to elements with qnext pointers, forming a linked list
 * that ends in NULL.  There is always exactly one NULL pointer per queue.
 *
 * The qtail pointer-pointer contains the address of the NULL pointer.
 * Well, normally, that is.  Initially, it may be set to NULL due to
 * initialisation, which is then considered an alias for &qhead that is
 * set to NULL by the same initialisation.  And, there may be brief period
 * where *qtail is not NULL, but then we can spinlock for it.
 *
 * To change the end of the queue, a thread grabs hold of the qtail,
 * swapping it with a new &NULL pointer.  Specifically, put_enqueue()
 * constructs a new queue element with qnext set to NULL and will
 * swap whatever is in qtail with a pointer to the new qnext pointer.
 * (If qtail was NULL, it now changes to &qhead.)  It then spinlocks
 * until *qtail is NULL, after which it swaps it with a pointer to the
 * new queue element.  Perhaps other threads already replaced the qnext
 * pointer in the new queue element, perhaps not.  It does not matter
 * to the put_enqueue() routine.
 *
 * The result is a linear queue that will grow on the end through any
 * number of producers.  It is now up to the single consumer in the
 * put_event() procedure to take out the elements one by one.  The one
 * thing this routine should be careful about is not to cleanup the
 * queue item whose qnext is NULL, as that would be pointed to by
 * qtail.  So, if qnext is NULL, it must first swap qtail with a
 * pointer to qhead.  If this delivers another value than a pointer
 * to the current queue element's qnext, then qnext obviously is going
 * to be set to another value than NULL, so the value can be swapped
 * back into qtail, and put_event() can spinlock until qnext has been
 * set to another value than NULL.  Otherwise, if the pointer returned
 * is the pointer to qnext, the only thing left to do is set qhead to
 * NULL.  In both cases, we can now proceed to cleaning up the pool
 * attached to the queue element, if it is non-NULL  This is likely
 * to erase the queue element as well -- but that is not the concern
 * of put_event() anymore.
 *
 * This is the third or fourth algorithm idea.  It seems that finally
 * this is one that will work.  Lock-free concurrency is difficult...
 * and that's why it is so much fun :-D
 *
 * Are there any problems left?  Yes, maybe.  On a cooperatively
 * multitasking system, there may be so many threads willing to act
 * that they occupy the processor in spinlocks, and no cycles go to
 * the threads that actually advance the state of the queue to one
 * where others break out of their spinlocks.  This would call for
 * a yield after a number of spinlock loops (probably the number
 * of loops during which another thread can advance the state, were
 * it to run on the processor at the same time).
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


/* We are not particularly interested in the typing model of OPA; it means
 * including the header files everywhere, which may be better to avoid.
 *
 * Note: These macros are only used below, they are not a generic API.
 *       Because of this, we have not had a lot of zeal in placing bracing.
 */

#ifndef CONFIG_SINGLE_THREADED

/* The atomic operations from OpenPA make us lock-free yet stable */
# define cas_ptr(ptrptr,old,new) OPA_cas_ptr   ((OPA_ptr_t *) ptrptr, old, new)
# define xcg_ptr(ptrptr,new)     OPA_swap_ptr  ((OPA_ptr_t *) ptrptr, new)
# define set_ptr(ptrptr,new)     OPA_store_ptr ((OPA_ptr_t *) ptrptr, new)
# define get_ptr(ptrptr)         ( (LillySend *) \
                                 OPA_load_ptr  ((OPA_ptr_t *) ptrptr) )
# define nil_ptr(ptrptr)         (NULL == get_ptr (ptrptr))

#else /* CONFIG_SINGLE_THREADED */


/* No need for atomic operations when we are sure to have only one thread */
static void *_tmp;
# define cas_ptr(ptrptr,old,new) ((*ptrptr == old) \
                                 ? (*ptrptr=new, old) \
                                 : (*ptrptr))
# define xcg_ptr(ptrptr,new)     (_tmp = (*ptrptr), (*ptrptr)= new, _tmp)
# define set_ptr(ptrptr,new)     (*ptrptr = new)
# define get_ptr(ptrptr)         (*ptrptr)
# define nil_ptr(ptrptr)         (NULL == get_ptr (ptrptr))

#endif /* CONFIG_SIGNLE_THREADED */


/* Initialise the signaling routine that hints that lillyput_event() may work.
 */
typedef void (*lillyput_signal_callback) (int fd);
static lillyput_signal_callback *lillyput_signal_loop;
void lillyput_init (lillyput_signal_callback *sigcb) {
	lillyput_signal_loop = sigcb;
}


/* Append a addend:LillySend structure to the lil->head,lil->tail:LillySend**
 */
void lillyput_enqueue (LillyDAP *lil, LillySend *addend) {
	addend->put_qnext = NULL;
	// Let's swap addend->put_qnext for qtail
	LillySend **qtail = xcg_ptr (&lil->put_qtail, &addend->put_qnext);
	if (qtail == NULL) {
		// Alias as a result of initialisation, set to actual value
		qtail = &lil->put_qhead;
	}
	while (!nil_ptr (qtail)) {
		//TODO// Under cooperative concurrency, yield() at some point
		;
	}
	set_ptr (qtail, addend);
	if (lillyput_signal_loop != NULL) {
		(*lillyput_signal_loop) (lil->put_fd);
	}
}


/* Test if there is anything in the queue for LillyPut
 */
bool lillyput_cansend (LillyDAP *lil) {
	return (!nil_ptr (&lil->put_qhead));
}


/* The callback function for lillyput_event() takes elements off the queue,
 * which is why it is implemented as part of queue.c.  Its API returns -1
 * on error with errno set; where errno is EAGAIN to indicate that it has
 * nothing to send left.
 */
int lillyput_event (LDAP *lil) {
	//
	// First test if the head actually points to an element
	struct LillySend *todo;
restart:
	todo = get_ptr (&lil->put_qhead);
	if (todo == NULL) {
		//
		// We report EAGAIN and rely on event loop hints for wakeup
		errno = EAGAIN;
		return -1;
	}
	//
	// Skip ahead any content that has been written -- and possibly end it
	dercursor *crs = todo->cursori;
	while (crs->derlen == 0) {
		if (crs->derptr == NULL) {
			//
			// Now we clean up the qpool, after untangling it.
			//
			// First, sample our qnext pointer
			LillySend *qnext = get_ptr (&todo->put_qnext);
			if (qnext != NULL) {
				//
				// We can simply overwrite qhead with qnext
				;
			} else {
				//
				// Offer to take over the &NULL pointer
				LillySend **qtail = cas_ptr (
							&lil->put_qtail,
							&todo->put_qnext,
							&lil->put_qhead);
				if (qtail != &todo->put_qnext) {
					//
					// Someone wants to overwrite qnext
					do {
						qnext = get_ptr (
							&todo->put_qnext);
						//TODO// Cooperative multitask
					} while (qnext == NULL);
				} else {
					//
					// Someone will be waiting for qhead
					// to be set to NULL by us
					// Already done: qnext = NULL;
					;
				}
			}
			//
			// Now setup qhead with the next item to read
			set_ptr (&lil->put_qhead, qnext);
			//
			// We are free -- nobody references todo anymore
			//
			// If a memory pool is to be cleared, clear it
			if (todo->put_qpool != NULL) {
				//TODO// Why not make more routines idempotent?
				//TODO// lillymem_endpool(NULL) saves call-test
				lillymem_endpool (todo->put_qpool);
				// Now assume that todo is unreachable
			}
			//
			// Now sample for a new non-NULL value in lil->put_queue
			goto restart;
		}
		crs++;
	}
	//
	// Send out what we have in the current dercursor *crs
	//TODO// Pile up multiple elements?  Difficult to combine ok with error
	// Simple enough for EAGAIN / EWOULDBLOCK, but there are still the other errors...
	// http://stackoverflow.com/questions/19391208/when-a-non-blocking-send-only-transfers-partial-data-can-we-assume-it-would-r
	ssize_t sent = write (lil->put_fd, crs->derptr, crs->derlen);
	if (sent > 0) {
		crs->derlen -= sent;
		crs->derptr += sent;
	}
	//
	// Return the outcome of the send operation
	return sent;
}


/* Enqueue a message in a single dercursor.  Normally, we supply a series of
 * dermessages, so this is just there to mirror properly; it may actually be
 * useful as a value for a lillyget_dercursor() pointer.
 */
int lillyput_dercursor (LillyDAP *lil, LillyPool qpool, dercursor dermsg) {
	LillySend *lise = lillymem_alloc (qpool,
				sizeof(LillySend) + sizeof(dercursor));
	if (lise == NULL) {
		errno = ENOMEM;
		return -1;
	}
	lise->put_qpool = qpool;
	memcpy (&lise->cursori [0], &dermsg, sizeof (dercursor));
	memset (&lise->cursori [1], 0,       sizeof (dercursor));
	lillyput_enqueue (lil, lise);
	return 0;
}

