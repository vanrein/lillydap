/* lillydump.c -- Send a binary package over LDAP, print it after delivery.
 *
 * This program passes binary data into the lillyget_* routines, until it is
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
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <lillydap/api.h>
#include <lillydap/mem.h>

#include <quick-der/api.h>

/* Quick-DER structures contain dercursors, and every member of
 * a structure starts with a dercursor structure. Use this
 * cast-hammer to smash a member reference (e.g. rq->filter) to
 * a dercursor (or pointer thereto).
 */
#define DERCURSOR_P_CAST(x) ((dercursor *)(&(x)))
#define DERCURSOR_CAST(x) (*DERCURSOR_P_CAST(x))

# define DER_FILTER_OP(x) (0xa0 | x)
char *filterop_strings[] = {
	"AND",  /* these first three are not used */
	"OR",
	"NOT",
	"==",
	"sub",
	">=",
	"<=",
	"?",
	"~="
};

int print_attributevalueassertion(int filterop, dercursor crs)
{
	uint8_t tag;
	size_t len;
	uint8_t hlen;

	if ((filterop < 3) || (filterop > (sizeof(filterop_strings) / sizeof(char *))))
	{
		return -1;
	}

	dercursor first = crs;
	if (der_header(&first, &tag, &len, &hlen) < 0)
	{
		return -1;
	}
	if (tag != 0x04)	/* LDAPString == OCTET STRING */
	{
		return -1;
	}
	first.derlen = len;

	dercursor second = crs;
	der_skip(&second);
	if (der_header(&second, &tag, &len, &hlen) < 0)
	{
		return -1;
	}
	if (tag != 0x04)	/* LDAPString == OCTET STRING */
	{
		return -1;
	}
	second.derlen = len;

	printf("%.*s %s %.*s", (int)first.derlen, first.derptr, filterop_strings[filterop], (int)second.derlen, second.derptr);

	return 0;
}

void _filter_indent(int depth)
{
	while (depth-- > 0)
	{
		printf("  ");
	}
}

/* A print routine for the filter, mathematically optimising by pushing the
 * NOT into the structure, and letting AND and OR ripple to the outside,
 * so there is some minimal filter expression structure to be relied upon.
 */
int _print_filter (dercursor filter, int inverted, int depth) {
	int err = 0;
	uint8_t tag;
	uint8_t hlen;
	size_t len;

	/* Get the operation tag for this filter; if it's NOT,
	 * then drill into the filter inside the NOT, toggling
	 * inverted as we go.
	 */
	do {
		err = err || der_header (&filter, &tag, &len, &hlen);
		if ((err == 0) && (tag == DER_FILTER_OP(2))) {	/*NOT*/
			inverted = !inverted;
		}
		else {
			break;
		}
	} while (1);

	if (err)
	{
		return err;
	}

	switch (tag) {
	case DER_FILTER_OP(0):	/*AND*/
	case DER_FILTER_OP(1):	/*OR*/
		if (inverted) {
			tag ^= DER_FILTER_OP(0) ^ DER_FILTER_OP(1);
		}
		printf("(%c\n", (tag == DER_FILTER_OP(0)) ? '&' : '|');
		int count = 0;
		dercursor subexpr;
		if (der_iterate_first(&filter, &subexpr))
		{
			do {
				_filter_indent(depth >= 0 ? depth+1 : -1);
				printf("(");
				_print_filter(subexpr, inverted, depth >= 0 ? depth+1 : -1);
				printf(")\n");
				++count;
			} while (der_iterate_next(&subexpr));
		}
		if (!count)
		{
			/* An empty AND is 1, empty OR is 0 */
			printf("%c", (tag == DER_FILTER_OP(0)) ? '1' : '0');
		}
		printf(")\n");
		break;
	case DER_FILTER_OP(3):	/* equality */
	case DER_FILTER_OP(4):	/* substrings */
	case DER_FILTER_OP(5):	/* >= */
	case DER_FILTER_OP(6):	/* <= */
	case DER_FILTER_OP(7):	/* present */
	case DER_FILTER_OP(8):	/* approx */
		printf("%s", inverted ? "!(" : "");
		if ((tag == DER_FILTER_OP(4)) || (tag == DER_FILTER_OP(7))) {
			printf("TAG=%02x P=%p L=%zu", tag, filter.derptr, filter.derlen);
		} else {
			/* The rest use AttributeValueAssertion */
			err = err || print_attributevalueassertion(tag & (~DER_FILTER_OP(0)), filter);
		}
		printf("%s", inverted ? ")" : "");
		break;
	default:
		printf ("OP: (%s TAG=%02x,%p,%d%s)\n", inverted? "NOT(": "", tag, filter.derptr, (int) filter.derlen, inverted? ")": "");
	}
#undef DER_FILTER_OP

	return err? -1: 0;
}

int print_filter (dercursor filter) {
	return _print_filter(filter, 0, 0);
}

int lillyget_BindRequest (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_BindRequest *br,
				const dercursor controls) {
	printf ("Got BindRequest\n");
	printf (" - version in %zu bytes %02x,...\n", br->version.derlen, br->version.derptr [0]);
	printf (" - name \"%.*s\"\n", (int)br->name.derlen, br->name.derptr);
	if (br->authentication.simple.derptr != NULL) {
		printf (" - simple authentication with \"%.*s\"\n", (int)br->authentication.simple.derlen, br->authentication.simple.derptr);
	}
	if (br->authentication.sasl.mechanism.derptr != NULL) {
		printf (" - SASL mechanism \"%.*s\"\n", (int)br->authentication.sasl.mechanism.derlen, br->authentication.sasl.mechanism.derptr);
		if (br->authentication.sasl.credentials.derptr != NULL) {
			printf (" - SASL credentias \"%.*s\"\n", (int)br->authentication.sasl.credentials.derlen, br->authentication.sasl.credentials.derptr);
		}
	}
	lillymem_endpool (qpool);
	return 0;
}

int lillyget_BindResponse (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_BindResponse *br,
				const dercursor controls) {
	printf ("Got BindResponse\n");
	printf (" - resultCode in %zu bytes %02x,%02x,%02x,%02x,...\n", br->resultCode.derlen, br->resultCode.derptr [0], br->resultCode.derptr [1], br->resultCode.derptr [2], br->resultCode.derptr [3]);
	printf (" - matchedDN \"%.*s\"\n", (int)br->matchedDN.derlen, br->matchedDN.derptr);
	printf (" - diagnosticMessage \"%.*s\"\n", (int)br->diagnosticMessage.derlen, br->diagnosticMessage.derptr);
	lillymem_endpool (qpool);
	return 0;
}

int lillyget_UnbindRequest (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_UnbindRequest *ur,
				const dercursor controls) {
	printf ("Got UnbindRequest\n");
	printf ("  - payload length is %s\n", (ur->derptr == NULL) ? "absent": (ur->derlen == 0) ? "empty" : "filled?!?");
	lillymem_endpool (qpool);
	return 0;
}

int lillyget_SearchRequest (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchRequest *sr,
				const dercursor controls) {
	printf ("Got SearchRequest\n");
	printf (" - baseObject \"%.*s\"\n", (int)sr->baseObject.derlen, sr->baseObject.derptr);
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
	// filter
	printf (" - filter =\n");
	print_filter (DERCURSOR_CAST(sr->filter));
	printf ("\n");
	// attributes SEQUENCE OF LDAPString
	dercursor attrs = sr->attributes.wire;
	printf (" - attributes.derlen = %zd\n", attrs.derlen);
	printf (" - attributes.enter.derlen = %zd\n", attrs.derlen);
	while (attrs.derlen > 0) {
		dercursor attr = attrs;
		if (der_focus (&attr)) {
			fprintf (stderr, "ERROR while focussing on attribute of SearchRequest: %s\n", strerror (errno));
		} else {
			printf (" - attr.derlen = %zd\n", attr.derlen);
			printf (" - attributes \"%.*s\"\n", (int)attr.derlen, attr.derptr);
		}
		der_skip (&attrs);
	}
	lillymem_endpool (qpool);
	return 0;
}

int lillyget_SearchResultEntry (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchResultEntry *sre,
				const dercursor controls) {
	printf ("Got SearchResultEntry\n");
	printf (" - objectName \"%.*s\"\n", (int)sre->objectName.derlen, sre->objectName.derptr);
	// partialAttribute SEQUENCE OF PartialAttribute
	dercursor pa = sre->attributes.wire;
	der_enter (&pa);
	while (pa.derlen > 0) {
		dercursor type = pa;
		// SEQUENCE { type AttributeDescription,
		//		vals SET OF AttributeValue }
		der_enter (&type);
		printf (" - partialAttribute.type \"%.*s\"\n", (int)type.derlen, type.derptr);
		der_skip (&pa);
		dercursor vals = pa;
		der_enter (&vals);
		while (vals.derlen > 0) {
			dercursor val = vals;
			der_enter (&val);
			printf ("    - value \"%.*s\"\n", (int)val.derlen, val.derptr);
			der_skip (&vals);
		}
		der_skip (&pa);
	}
	lillymem_endpool (qpool);
	return 0;
}

int lillyget_SearchResultReference (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchResultReference *srr,
				const dercursor controls) {
	printf ("Got SearchResultReference\n");
	dercursor uris = srr->wire;
	do {
		dercursor uri = uris;
		der_enter (&uri);
		printf (" - URI \"%.*s\"\n", (int)uri.derlen, uri.derptr);
		der_skip (&uris);
	} while (uris.derlen > 0);
	lillymem_endpool (qpool);
	return 0;
}

int lillyget_SearchResultDone (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const LillyPack_SearchResultDone *srd,
				const dercursor controls) {
	printf ("Got SearchResultDone\n");
	printf (" - resultCode is %zd==1 byte valued %d\n", srd->resultCode.derlen, *srd->resultCode.derptr);
	printf (" - matchedDN \"%.*s\"\n", (int)srd->matchedDN.derlen, srd->matchedDN.derptr);
	printf (" - diagnosticMessage \"%.*s\"\n", (int)srd->diagnosticMessage.derlen, srd->diagnosticMessage.derptr);
	if (srd->referral.wire.derptr != NULL) {
		dercursor uris = srd->referral.wire;
		do {
			dercursor uri = uris;
			der_enter (&uri);
			printf (" - URI \"%.*s\"\n", (int)uri.derlen, uri.derptr);
			der_skip (&uris);
		} while (uris.derlen > 0);
	}
	lillymem_endpool (qpool);
	return 0;
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

static LillyDAP lillydap = {
	.lillyget_dercursor   = lillyget_dercursor,
	.lillyget_ldapmessage = lillyget_ldapmessage,
	.lillyget_opcode      = lillyget_opcode,
	.lillyget_operation   = lillyget_operation,
	.opregistry = &opregistry,
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
	LDAP *lil;
	lil = lillymem_alloc0 (lipo, sizeof (LDAP));
	lil->def = &lillydap;
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
	lillymem_endpool (lil->get_qpool);
	lillymem_endpool (lipo);
	exit (0);
}

