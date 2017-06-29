/* stampede.c -- Let many, many threads send concurrently to one queue
 *
 * This is a true test program for the lock-free concurrency model of the
 * queue.[hc] module.  It makes many threads (default 10,000) sit and wait
 * a pthreads barrier lock after having prepared for their stampede.
 *
 * When all the threads and the main program are ready, the jointly go through
 * the barrier, and start sending all at the same time.  Each thread sends
 * 1000 messages by default.  Only the main program retrieves data from the
 * reader side of the queue, feeding the single file descriptor that would
 * normally be used for LDAP.
 *
 * There should be no crashes, even though memory regions will be ended
 * a lot.  And the output would show a thread id and a sequence number
 * within that; after a (long) sort, it is possible to count the number
 * of entries for each thread.  Grepping on individual thread ids, the
 * 1000 messages sent should be shown in rising order.
 *
 * Reading / writing is not directly suited for testing, due to the
 * non-determinism of so many free-running threads.  Tools could include
 * sort -k so that it does not sort on the sequence number within a thread..
 *
 * It should be noted that the 1000 serial numbers are written out in chunks
 * of 3 at a time; as a result, 0-2 should appear in one sequence, and so
 * should 3-5 and 6-8, and os on.  The last bits may be different.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>
#include <fcntl.h>

#include <lillydap/api.h>
#include <lillydap/mem.h>
#include <lillydap/queue.h>

#include <quick-der/api.h>

#include "opa_primitives.h"


// The LillyDAP structure contains all that is needed to herd cattle
static LDAP lil = {
	//
	// Output facilities (the queue is ok when zeroed)
	.put_fd = 1,
};

// The electric fence is what holds back the stampede, initially
static pthread_barrier_t electric_fence;

// The cowshed door is what keeps the stampede going until all want to go inside
static pthread_barrier_t cowshed_door;

// The earmark counter provides each cattle with their unique serial number
static OPA_int_t earmark_counter = { 0 };


void *cattle (void *nullarg) {
	int thrid = OPA_fetch_and_incr_int (&earmark_counter);
	int i;
	//
	// Allocate the structures we play around with
	LillyPool pools [(1000+2)/3];
	LillySend *lise [(1000+2)/3];
	for (i=0; i<(1000+2)/3; i++) {
		pools [i] = lillymem_newpool ();
		if (pools [i] == NULL) {
			perror ("Error allocating memory pool");
			exit (1);
		}
		lise [i] = lillymem_alloc0 (pools [i], (sizeof (LillySend) + 3 * sizeof (dercursor)));
		if (lise [i] == NULL) {
			perror ("Error allocating LillySend");
			exit (1);
		}
		memset (lise [i]->cursori, 0, 4 * sizeof (dercursor));
	}
	char msg [1000] [20];
	//
	// Fill the msg[] and cursori[]
	// We will skip cursori [3], [6] and [9] and so on
	for (i=0; i<1000; i++) {
		// Construct sizes 3, 3, 3, 1
		snprintf (msg [i], 20, "%06d, %04d\n", thrid, i);
		lise [i / 3]->cursori [i % 3].derptr = (uint8_t *)(msg [i]);
		lise [i / 3]->cursori [i % 3].derlen = strlen (msg [i]);
	}
	//
	// Setup the memory pools for deletion when lillyput_event() is done
	for (i=0; i<(1000+2)/3; i++) {
		lise [i]->put_qpool = pools [i];
	}
	//
	// Scraping your hoofs through the grass, wait for the fence to fall
	pthread_barrier_wait (&electric_fence);
	//
	// The stampede is on!  As soon as possible, deliver your dung
	for (i=0; i<(1000+2)/3; i++) {
		lillyput_enqueue (&lil, lise [i]);
	}
	//
	// Once we're done, we line up in front of the cowshed's door
	pthread_barrier_wait (&cowshed_door);
	//
	// This is the end of our visit with the stampeding cattle
	return NULL;
}


int main (int argc, char *argv []) {
	int nthr = 10000;
	int thr;
	int i;
	//
	// Memory functions are plain silly
	lillymem_newpool_fun = sillymem_newpool;
	lillymem_endpool_fun = sillymem_endpool;
	lillymem_alloc_fun   = sillymem_alloc  ;
	//
	// Parse a few commandline arguments
	if (argc >= 2) {
		nthr = atoi (argv [1]);
	}
	if ((argc >= 3) || (nthr <= 0)) {
		fprintf (stderr, "Usage: %s [num_threads]\n", argv [0]);
		exit (1);
	}

	//
	// Raise the electric_fence for the herd of cattle to be held back
	pthread_barrier_init (&electric_fence, NULL, nthr+1);
	//
	// Close the cowshed door until all cattle are ready
	pthread_barrier_init (&cowshed_door, NULL, nthr+1);
	//
	// Construct the earmark_counter that cattle use to get their number
	//static// earmark_counter = 0;
	//
	// Create the cattle
	for (i=0; i<nthr; i++) {
		pthread_t thr;
		if (pthread_create (&thr, NULL, cattle, NULL) != 0) {
			perror ("Error creating thread");
			exit (1);
		}
	}
	//
	// Start the stampede by pushing through the electric fence together
	pthread_barrier_wait (&electric_fence);
	//
	// Start the event loop to shove out the dung produced by the cattle
	for (i=0; i<1200*nthr; i++) {
		lillyput_event (&lil);
	}
	//
	// End the stampede together, by forcing the cowshed door open as one
	pthread_barrier_wait (&cowshed_door);
	//
	// Cleanup
	pthread_barrier_destroy (&electric_fence);
	pthread_barrier_destroy (&cowshed_door);
}

