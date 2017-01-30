/* lillypass.c -- Passthrough for LDAPMessage chunks.
 *
 * This routine passes binary data into the lillyget_* routines, until it is
 * delivered.  At that point, it passes it back up, and delivers it to its
 * output stream.
 *
 * Coupling can be done at various levels, and this is why the number of
 * levels to pass through LDAP can be set as a first parameter; levels are:
 *
 *  0. Directly pass LDAPMessage chunks as a dercursor
 *  1. Pass a LDAPMessage after splitting into request, opcode and controls
 *  2. Pass LDAP operations with unpacked data, but use the same code for each
 *  3. Pass LDAP operations through individual operations (chance of ENOSYS)
 *  4. The LDAP operations unpack the controls, and later pack them again
 *
 * TODO: level 4 has not been implemented yet.
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


void process (LDAP *lil, char *progname, char *derfilename) {
	//
	// Open the file
	int fd = open (derfilename, O_RDONLY);
	if (fd < 0) {
		fprintf (stderr, "%s: Failed to open \"%s\"\n", progname, derfilename);
		exit (1);
	}
	//
	// Print the file being handled
	//
	// Setup the input file descriptor
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
	// Set the file handle for input and output file handles in lil
	lil->get_fd = fd;
	lil->put_fd = 1;
	//
	// Send events until no more can be read
	int i;
	for (i=0; i<1000; i++) {
			lillyget_event (lil);
			lillyput_event (lil);
	}
	//
	// Close off processing
	close (fd);
}


void setup (void) {
	lillymem_newpool_fun = sillymem_newpool;
	lillymem_endpool_fun = sillymem_endpool;
	lillymem_alloc_fun   = sillymem_alloc;
}


static const LillyOpRegistry opregistry = {
	.by_name = {
		.BindRequest = lillyput_BindRequest,
		.BindResponse = lillyput_BindResponse,
		.UnbindRequest = lillyput_UnbindRequest,
		.SearchRequest = lillyput_SearchRequest,
		.SearchResultEntry = lillyput_SearchResultEntry,
		.SearchResultReference = lillyput_SearchResultReference,
		.SearchResultDone = lillyput_SearchResultDone,
	}
};


int main (int argc, char *argv []) {
	//
	// Check arguments
	char *progname = argv [0];
	if (argc < 3) {
		fprintf (stderr, "Usage: %s level ldapmsg.der...\nThe level is a value from 0 to 4, with increasing code being used\n", progname);
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
	//
	// We first setup all operations to pass over to output directly...
	lil->lillyget_dercursor   =
	lil->lillyput_dercursor   = lillyput_dercursor;
	lil->lillyget_ldapmessage =
	lil->lillyput_ldapmessage = lillyput_ldapmessage;
	lil->lillyget_operation   =
	lil->lillyput_operation   = lillyput_operation;
	//
	// ...and then we gradually turn it back depending on the level
	char level = 'X';
	if (strlen (argv [1]) == 1) {
		level = argv [1] [0];
	}
	switch (level) {
	default:
		fprintf (stderr, "%s: Invalid level '%s'\n",
					argv [0], argv [1]);
		exit (1);
	case '4':
		fprintf (stderr, "%s: Level 4 is not yet implemented\n",
					argv [0]);
		//TODO// Replace opregistry with control-unpackers-repackers
		// and fallthrough...
	case '3':
		lil->lillyget_operation   = lillyget_operation;
		lil->opregistry = &opregistry;
		// and fallthrough...
	case '2':
		lil->lillyget_ldapmessage = lillyget_ldapmessage;
		// and fallthrough...
	case '1':
		lil->lillyget_dercursor   = lillyget_dercursor;
		// and fallthrough...
	case '0':
		// Keep everything as-is, passing as directly as possible
		break;
	}
	//
	// Allocate a connection pool
	lil->cnxpool = lillymem_newpool ();
	if (lil->cnxpool == NULL) {
		fprintf (stderr, "%s: Failed to allocate connection memory pool\n", progname);
		exit (1);
	}
	//
	// Iterate over the LDAP binary files in argv [1..]
	int argi = 2;
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

