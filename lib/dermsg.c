/* LDAPMessage handling, in a generic sense.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>

#include <errno.h>

#include <quick-der/api.h>
#include <lillydap/api.h>
#include <lillydap/mem.h>


/* The LDAPMessage has a lot of variety built in, and leads to one long
 * dercursor[] array that serialises all variants and that also crosses
 * the abstraction levels that we prefer.
 * So we prefer to parse the LDAPMessage only shallowly at first.  This
 * also helps because rejection of commands can be done without parsing
 * their internals.  So here we have a shallow packer prescription to
 * counter the full-depth version from <quick-der/rfc4511.h>
 */
static const derwalk pck_ldapmsg_shallow [] = {
	DER_PACK_ENTER | DER_TAG_SEQUENCE,	// SEQUENCE { ...
	DER_PACK_STORE | DER_TAG_INTEGER,	// messageID
	DER_PACK_STORE | DER_PACK_ANY,		// protocolOp CHOICE { ... }
	DER_PACK_OPTIONAL,
	DER_PACK_STORE | DER_PACK_ANY,		// controls SEQ-OF OPTIONAL
	DER_PACK_LEAVE,				// ...}
	DER_PACK_END
};



/* DER utility: This should probably appear in Quick DER sometime soon.
 *
 * Unpack an Int32 or UInt32 from a given number of bytes.  Do not assume a header
 * around it.  The function returns the value found.
 *
 * Out of range values are returned as 0.  This value only indicates invalid
 * return when len > 1, so check for that.
 */
//TODO// SIMPLIFIED -- we know that INTEGER is clipped to 32 bits under RFC 4511
//TODO// SIMPLIFIED:CHECKIFOKAY -- is the outcome always positive too?
int32_t qder2b_unpack_int32 (dercursor data4) {
	int32_t retval = 0;
	int idx;
#if 0
	if (data4.derlen > 4) {
		goto done;
	}
#endif
#if 0
	if ((data4.derlen > 0) && (0x80 & *data4.derptr)) {
		retval = -1;
	}
#endif
	for (idx=0; idx<data4.derlen; idx++) {
		retval <<= 8;
		retval += data4.derptr [idx];
	}
done:
#if 0
	return retval;
#else
	return retval & 0x7fffffff;
#endif
}


/* Process a dercursor, meaning a <derptr,derlen> combination as an LDAPMessage
 */
//TODO// Consider adding an optional qpool, whose responsibility is passed in.
int lillyget_dercursor (LDAP *lil, LillyPool *qpool_opt, dercursor msg) {
	//
	// Unpack the DER cursor as an LDAPMessage, but stay shallow
	dercursor mid_op_ctl [3];
	if (der_unpack (&msg, pck_ldapmsg_shallow, mid_op_ctl, 1) == -1) {
		goto bail_out;
	}
	//
	// Retrieve the value of the msgid
	int32_t msgid = qder2b_unpack_int32 (mid_op_ctl [0]);;
	if (msgid <= 0) {
		errno = EINVAL;
		goto bail_out;
	}
	//
	// Now put the harvested values to use
	if (lil->lillyget_ldapmessage == NULL) {
		errno = ENOSYS;
		goto bail_out;
	}
	return lil->lillyget_ldapmessage (lil, qpool_opt, msgid, mid_op_ctl [1], mid_op_ctl [2]);
bail_out:
	if (qpool_opt != NULL) {
		lillymem_endpool (qpool_opt);
	}
	return -1;
}



