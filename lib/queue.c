/* queue.c -- Handle output queue items for a LillyDAP connection structure
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <lillydap/api.h>
#include <lillydap/queue.h>

#include "opa_primitives.h"


/* We are not particularly interested in the typing model of OPA; it means
 * including the header files everywhere, which may be better to avoid.
 */
#define get_head(lil) OPA_load_ptr ((OPA_ptr_t *) &lil->put_head)
#define get_tail(lil) OPA_load_ptr ((OPA_ptr_t *) &lil->put_tail)
#define get_next(crs) OPA_load_ptr ((OPA_ptr_t *) &crs->put_next)
#define set_head(lil,new) OPA_store_ptr ((OPA_ptr_t *) &lil->put_head, new)
#define set_tail(lil,new) OPA_store_ptr ((OPA_ptr_t *) &lil->put_tail, new)
#define set_next(crs,new) OPA_store_ptr ((OPA_ptr_t *) &crs->put_next, new)
#define cas_head(lil,old,new) OPA_cas_ptr ((OPA_ptr_t *) &lil->put_head, old, new)
#define cas_tail(lil,old,new) OPA_cas_ptr ((OPA_ptr_t *) &lil->put_tail, old, new)


#define get_ptr(ptrptr)         ( (struct LillySend *) \
                                OPA_load_ptr  ((OPA_ptr_t *) ptrptr) )
#define set_ptr(ptrptr,new)     OPA_store_ptr ((OPA_ptr_t *) ptrptr, new)
#define cas_ptr(ptrptr,old,new) OPA_cas_ptr   ((OPA_ptr_t *) ptrptr, old, new)



/* Initialise the signaling routine that hints that lillyput_event() may work.
 */
typedef void (*lillyput_signal_callback) (int fd);
static lillyput_signal_callback *lillyput_signal_loop;
void lillyput_init (lillyput_signal_callback *sigcb) {
	lillyput_signal_loop = sigcb;
}


/* Append a addend:LillySend structure to the lil->head,lil->tail:LillySend**
 */
void lillyput_enqueue (LillyDAP *lil, struct LillySend *addend) {
	struct LillySend **ptr;
	addend->put_next = NULL;
	ptr = &lil->put_queue;
	while (cas_ptr (ptr, NULL, addend) != addend) {
		//TODO// Race condition against cleanup of this structure
		ptr = &get_ptr (ptr)->put_next;
	}
	if (*lillyput_signal_loop != NULL) {
		(*lillyput_signal_loop) (lil->put_fd);
	}
}


/* Test if there is anything in the queue for LillyPut
 */
bool lillyput_cansend (LillyDAP *lil) {
	return (NULL != get_ptr (&lil->put_queue));
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
	todo = get_ptr (&lil->put_queue);
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
			// Set the head to the current next field
			struct LillySend *next = get_ptr (&todo->put_next);
			//
			// Write it into the queue head pointer
			set_ptr (&lil->put_queue, next);
			//
			//TODO// Race condition if other works on todo->put_next
			//
			// If a memory pool is to be cleared, clear it
			if (todo->opt_endpool) {
				//TODO// Why not make more routines idempotent?
				//TODO// lillymem_endpool(NULL) saves call-test
				lillymem_endpool (todo->opt_endpool);
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
	ssize_t sent = write (lil->put_fd, crs->derptr, crs->derlen);
	if (sent > 0) {
		crs->derlen -= sent;
		crs->derptr += sent;
	}
	//
	// Return the outcome of the send operation
	return sent;
}

