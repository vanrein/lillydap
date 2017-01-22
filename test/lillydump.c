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


int lillyget_BindRequest (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_BindRequest *br,
				const dercursor controls) {
	printf ("Got BindRequest\n");
	printf (" - version in %d bytes %02x,...\n", br->version.derlen, br->version.derptr [0]);
	printf (" - name \"%.*s\"\n", br->name.derlen, br->name.derptr);
	if (br->authentication.simple.derptr != NULL) {
		printf (" - simple authentication with \"%.*s\"\n", br->authentication.simple.derlen, br->authentication.simple.derptr);
	}
	if (br->authentication.sasl.mechanism.derptr != NULL) {
		printf (" - SASL mechanism \"%.*s\"\n", br->authentication.sasl.mechanism.derlen, br->authentication.sasl.mechanism.derptr);
		if (br->authentication.sasl.credentials.derptr != NULL) {
			printf (" - SASL credentias \"%.*s\"\n", br->authentication.sasl.credentials.derlen, br->authentication.sasl.credentials.derptr);
		}
	}
	return 0;
}

int lillyget_BindResponse (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_BindResponse *br,
				const dercursor controls) {
	printf ("Got BindResponse\n");
	printf (" - resultCode in %d bytes %02x,%02x,%02x,%02x,...\n", br->resultCode.derlen, br->resultCode.derptr [0], br->resultCode.derptr [1], br->resultCode.derptr [2], br->resultCode.derptr [3]);
	printf (" - matchedDN \"%.*s\"\n", br->matchedDN.derlen, br->matchedDN.derptr);
	printf (" - diagnosticMessage \"%.*s\"\n", br->diagnosticMessage.derlen, br->diagnosticMessage.derptr);
	return 0;
}

int lillyget_UnbindRequest (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_UnbindRequest *ur,
				const dercursor controls) {
	printf ("Got UnbindRequest\n");
	printf ("  - payload length is %s\n", (ur->derptr == NULL) ? "absent": (ur->derlen == 0) ? "empty" : "filled?!?");
	return 0;
}

int lillyget_SearchRequest (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchRequest *sr,
				const dercursor controls) {
	printf ("Got SearchRequest\n");
	printf (" - baseObject \"%.*s\"\n", sr->baseObject.derlen, sr->baseObject.derptr);
	if (sr->scope.derlen != 1) {
		printf (" ? scope has awkward size %zd instead of 1\n", sr->scope.derlen);
	} else {
		switch (*sr->scope.derptr) {
		case 0:
			printf (" - scope base\n");
			break;
		case 1:
			printf (" - scope one\n");
			break;
		case 2:
			printf (" - scope sub\n");
			break;
		default:
			printf (" ? scope weird value %d instead of 0, 1 or 2\n", *sr->scope.derptr);
		}
	}
	if (sr->derefAliases.derlen != 1) {
		printf (" ? derefAliases has awkward size %zd instead of 1\n", sr->derefAliases.derlen);
	} else {
		switch (*sr->derefAliases.derptr) {
		case 0:
			printf (" - derefAliases neverDerefAlias\n");
			break;
		case 1:
			printf (" - derefAliases derefInSearching\n");
			break;
		case 2:
			printf (" - derefAliases derefFindingBaseObj\n");
			break;
		case 3:
			printf (" - derefAliases derefAlways\n");
			break;
		default:
			printf (" ? derefAliases weird value %d instead of 0, 1, 2 or 3\n", *sr->derefAliases.derptr);
		}
	}
	// attributes SEQUENCE OF LDAPString
	dercursor attrs = sr->attributes;
	printf (" - attributes.derlen = %zd\n", attrs.derlen);
	printf (" - attributes.enter.derlen = %zd\n", attrs.derlen);
	while (attrs.derlen > 0) {
		dercursor attr = attrs;
		if (der_focus (&attr)) {
			fprintf (stderr, "ERROR while focussing on attribute of SearchRequest: %s\n", strerror (errno));
		} else {
			printf (" - attr.derlen = %zd\n", attr.derlen);
			printf (" - attributes \"%.*s\"\n", attr.derlen, attr.derptr);
		}
		der_skip (&attrs);
	}
	return 0;
}

int lillyget_SearchResultEntry (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchResultEntry *sre,
				const dercursor controls) {
	printf ("Got SearchResultEntry\n");
	printf (" - objectName \"%.*s\"\n", sre->objectName.derlen, sre->objectName.derptr);
	// partialAttribute SEQUENCE OF PartialAttribute
	dercursor pa = sre->attributes;
	der_enter (&pa);
	while (pa.derlen > 0) {
		dercursor type = pa;
		// SEQUENCE { type AttributeDescription,
		//		vals SET OF AttributeValue }
		der_enter (&type);
		printf (" - partialAttribute.type \"%.*s\"\n", type.derlen, type.derptr);
		der_skip (&pa);
		dercursor vals = pa;
		der_enter (&vals);
		while (vals.derlen > 0) {
			dercursor val = vals;
			der_enter (&val);
			printf ("    - value \"%.*s\"\n", val.derlen, val.derptr);
			der_skip (&vals);
		}
		der_skip (&pa);
	}
	return 0;
}

int lillyget_SearchResultReference (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchResultReference *srr,
				const dercursor controls) {
	printf ("Got SearchResultReference\n");
	dercursor uris = *srr;
	do {
		dercursor uri = uris;
		der_enter (&uri);
		printf (" - URI \"%.*s\"\n", uri.derlen, uri.derptr);
		der_skip (&uris);
	} while (uris.derlen > 0);
	return 0;
}

int lillyget_SearchResultDone (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchResultDone *srd,
				const dercursor controls) {
	printf ("Got SearchResultDone\n");
	printf (" - resultCode is %zd==1 byte valued %d\n", srd->resultCode.derlen, *srd->resultCode.derptr);
	printf (" - matchedDN \"%.*s\"\n", srd->matchedDN.derlen, srd->matchedDN.derptr);
	printf (" - diagnosticMessage \"%.*s\"\n", srd->diagnosticMessage.derlen, srd->diagnosticMessage.derptr);
	if (srd->referral.derptr != NULL) {
		dercursor uris = srd->referral;
		do {
			dercursor uri = uris;
			der_enter (&uri);
			printf (" - URI \"%.*s\"\n", uri.derlen, uri.derptr);
			der_skip (&uris);
		} while (uris.derlen > 0);
	}
	return 0;
}

#if 0
/* The following function could be used as lillyget_operation, but we have
 * moved to instead use the generic lillyget_operation that looks into the
 * lil->opregistry for function pointers, setup below.  Have a look at its
 * straightforward setup; it follows similar overlay tactics as Quick DER.
 */
int lillyget_operation (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const int opcode,
				const dercursor *data,
				const dercursor controls) {
	LillyPack_BindResponse *br = (void *) data;
	LillyPack_SearchResultEntry *sre = (void *) data;
	LillyPack_SearchResultReference *srr = (void *) data;
	switch (opcode) {
	case 1:
		printf ("Got BindResponse\n");
		printf (" - resultCode in %d bytes %02x,%02x,%02x,%02x,...\n", br->resultCode.derlen, br->resultCode.derptr [0], br->resultCode.derptr [1], br->resultCode.derptr [2], br->resultCode.derptr [3]);
		printf (" - matchedDN \"%.*s\"\n", br->matchedDN.derlen, br->matchedDN.derptr);
		printf (" - diagnosticMessage \"%.*s\"\n", br->diagnosticMessage.derlen, br->diagnosticMessage.derptr);
		break;
	case 4:
		printf ("Got SearchResultEntry\n");
		printf (" - objectName \"%.*s\"\n", sre->objectName.derlen, sre->objectName.derptr);
		// partialAttribute SEQUENCE OF PartialAttribute
		dercursor pa = sre->attributes;
		der_enter (&pa);
		while (pa.derlen > 0) {
			dercursor type = pa;
			// SEQUENCE { type AttributeDescription,
			//		vals SET OF AttributeValue }
			der_enter (&type);
			printf (" - partialAttribute.type \"%.*s\"\n", type.derlen, type.derptr);
			der_skip (&pa);
			dercursor vals = pa;
			der_enter (&vals);
			while (vals.derlen > 0) {
				dercursor val = vals;
				der_enter (&val);
				printf ("    - value \"%.*s\"\n", val.derlen, val.derptr);
				der_skip (&vals);
			}
			der_skip (&pa);
		}
		break;
	case 19:
		printf ("Got SearchResultReference\n");
		dercursor uris = *srr;
		do {
			dercursor uri = uris;
			der_enter (&uri);
			printf (" - URI \"%.*s\"\n", uri.derlen, uri.derptr);
			der_skip (&uris);
		} while (uris.derlen > 0);
		break;
	default:
		printf ("Got opcode %d\n", opcode);
		//TODO// errno reporting for now; still to move to LDAPResults
		errno = ENOSYS;
		return -1;
	}
	return 0;
}
#endif


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


static const LillyOpRegistry opregistry = {
	.by_name = {
		.BindRequest = lillyget_BindRequest,
		.BindResponse = lillyget_BindResponse,
		.UnbindRequest = lillyget_UnbindRequest,
		.SearchRequest = lillyget_SearchRequest,
		.SearchResultEntry = lillyget_SearchResultEntry,
		.SearchResultReference = lillyget_SearchResultReference,
		.SearchResultDone = lillyget_SearchResultDone,
	}
};


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
	lil->opregistry = &opregistry;
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

