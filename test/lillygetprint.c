/* lillygetprint.c -- Send a binary package over LDAP, print it after delivery.
 *
 * This routine passes binary data into the lillyget_* routines, until it is
 * delivered.  At that point, the operation and all its parameters are
 * printed nicely.
 *
 * Reading / writing is highly structured, so it can be used for testing.
 * For this reason, query IDs and times will not be randomly generated.
 * Note that some operations may not be supported -- which is then reported.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <errno.h>
#include <fcntl.h>

#define USE_SILLYMEM

#include <lillydap/api.h>
#include <lillydap/mem.h>

#include <quick-der/api.h>


int lillyget_operation (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const int opcode,
				const dercursor *data,
				const dercursor controls) {
	printf ("Got opcode %d\n", opcode);
}


void process (LDAP *lil, char *progname, char *derfilename) {
	//
	// Open the file
	int fd = open (derfilename, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "%s: Failed to open \"%s\"\n", progname, derfilename);
		exit (1);
	}
	//
	// Print the file handle
	printf ("%s: Processing %s\n", progname, derfilename);
	//
	// Setup the input file descriptor
	lil->get_fd = 0;
	int flags = fcntl (fd, F_GETFL, 0);
	if (flags == -1) {
		fprintf (stderr, "%s: Failed to get flags on stdin\n", progname);
		exit (1);
	}
	flags |= O_NONBLOCK;
	if (fcntl (fd, F_SETFL, flags) == -1) {
		fprintf (stderr, "%s: Failed to set non-blocking flag on stdin\n", progname);
		exit (1);
	}
	//
	// Set the file as the input file handle in lil
	lil->get_fd = fd;
	//
	// Send events until no more can be read
	int rv;
	do {
		rv = lillyget_event (lil);
	} while (rv > 0);
	if (rv == 0) {
		printf ("%s: End of file reached\n", progname);
	} else if (errno == EAGAIN) {
		// Formally, we don't know if the file system is slow or if
		// no more data is available... but during small tests, we can
		// rest assured that the end of file has been reached (right?)
		printf ("%s: End of available data has (probably) been reached\n", progname);
	} else {
		printf ("%s: Read error in lillyget_event(): %s\n", progname, strerror (errno));
	}
	//
	// Close off processing
	printf ("%s: Processing done\n", progname);
	close (fd);
}


void setup (void) {
	lillymem_newpool_fun = sillymem_newpool;
	lillymem_endpool_fun = sillymem_endpool;
	lillymem_alloc_fun   = sillymem_alloc;
}


int main (int argc, char *argv []) {
	//
	// Check arguments
	char *progname = argv [0];
	if (argc < 2) {
		fprintf (stderr, "Usage: %s ldapcmd.der ...\n", progname);
		exit (1);
	}
	//
	// Initialise functions and structures
	setup ();
	//
	// Create the memory pool
	LillyPool *lipo = lillymem_newpool ();
	if (lipo == NULL) {
		fprintf (stderr, "%s: Failed to allocate a memory pool\n", progname);
		exit (1);
	}
	//
	// Allocate the connection structuur
	LillyDAP *lil;
	lil = lillymem_alloc0 (lipo, sizeof (LillyDAP));
	lil->lillyget_dercursor   = lillyget_dercursor;
	lil->lillyget_ldapmessage = lillyget_ldapmessage;
	lil->lillyget_operation   = lillyget_operation;
	lil->support_ops [0] = LILLYGETS_ALL_REQ  | LILLYGETS_ALL_RESP ;
	lil->support_ops [1] = LILLYGETS0_ALL_REQ | LILLYGETS0_ALL_RESP;
	//
	// Allocate a connection pool
	lil->cnxpool = lillymem_newpool ();
	if (lil->cnxpool == NULL) {
		fprintf (stderr, "%s: Failed to allocate connection memory pool\n", progname);
		exit (1);
	}
	//
	// Iterate over the LDAP binary files in argv [1..]
	int argi = 1;
	while (argi < argc) {
		process (lil, progname, argv [argi]);
		argi++;
	}

	//
	// Cleanup and exit
	lillymem_endpool (lil->cnxpool);
	lillymem_endpool (lipo);
	exit (0);
}

