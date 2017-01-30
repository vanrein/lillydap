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
	DER_PACK_STORE | DER_TAG_SEQUENCE,	// controls SEQ-OF OPTIONAL
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
// SIMPLIFIED -- we know that INTEGER is clipped to 32 bits under RFC 4511
// SIMPLIFIED:CHECKIFOKAY -- is the outcome always positive too?
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


/* DER utility: This should probably appear in Quick DER sometime soon.
 *
 * Pack an Int32 or UInt32 and return the number of bytes.  Do not pack a header
 * around it.  The function returns the number of bytes taken, even 0 is valid.
 */
typedef uint8_t QDERBUF_INT32_T [4];
dercursor qder2b_pack_int32 (uint8_t *target_4b, int32_t value) {
	dercursor retval;
	int shift = 24;
	retval.derptr = target_4b;
	retval.derlen = 0;
	while (shift >= 0) {
		if ((retval.derlen == 0) && (shift > 0)) {
			// Skip sign-extending initial bytes
			uint32_t neutro = (value >> (shift - 1) ) & 0x000001ff;
			if ((neutro == 0x000001ff) || (neutro == 0x00000000)) {
				shift -= 8;
				continue;
			}
		}
		target_4b [retval.derlen] = (value >> shift) & 0xff;
		retval.derlen++;
		shift -= 8;
	}
	return retval;
}


/* Process a dercursor, meaning a <derptr,derlen> combination as an LDAPMessage
 */
int lillyget_dercursor (LDAP *lil, LillyPool qpool_opt, dercursor msg) {
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


/* Shallowly pack an LDAPMessage, into a DER message.
 */
int lillyput_ldapmessage (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const dercursor operation,
				const dercursor controls) {
	//
	// Allocate space for all the fields in a shallow LDAPMessage
	// (async delivery requires it, and the LillyPool makes it cheap)
	dercursor *mid_op_ctl = lillymem_alloc (qpool, 3 * sizeof (dercursor));
	uint8_t *mid_int32 = lillymem_alloc (qpool, sizeof (QDERBUF_INT32_T));
	if ((mid_int32 == NULL) || (mid_op_ctl == NULL)) {
		errno = ENOMEM;
		goto bail_out;
	}
	//
	// Set the three fields to the message ID, operation and controls
	mid_op_ctl [0] = qder2b_pack_int32 (mid_int32, msgid);
	mid_op_ctl [1] = operation;
	mid_op_ctl [2] = controls;
	//
	// Find the size of the packed DER message
	// Note: More optimal schemes are possible, passing multiple buffers
	dercursor total;
	total.derlen = der_pack (pck_ldapmsg_shallow, mid_op_ctl, NULL);
	total.derptr = lillymem_alloc (qpool, total.derlen);
	if (total.derptr == NULL) {
		errno = ENOMEM;
		goto bail_out;
	}
	der_pack (pck_ldapmsg_shallow, mid_op_ctl, total.derptr + total.derlen);
	return lillyput_dercursor (lil, qpool, total);
	//
	// We ran into a problem
bail_out:
	if (qpool != NULL) {
		lillymem_endpool (qpool);
	}
	return -1;
}
