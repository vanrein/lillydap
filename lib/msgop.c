/* LDAPMessage handling, in a generic sense.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>
#include <stdio.h>

#include <errno.h>

#include <lillydap/api.h>
#include <lillydap/mem.h>


#include "msgop.tab"


/* Receieve an LDAPMessage, which has been parsed shallowly, and split it
 * based on its operation code.  The qpool is optional; when provided, it
 * will because the responsibility of lillyget_ldapmessage() -- which it
 * may pass down to further lillyget_xxx() or other functions.
 */
int lillyget_ldapmessage (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const dercursor op,
				const dercursor controls) {
	//
	// Check the message identity for sanity
	if ((msgid == 0) || (msgid >= 0x80000000)) {
		errno = EBADMSG;
		goto bail_out;
	}
	//
	// Collect information about the operation; we will update the
	// value later if it happens to be an ExtendedRequest/Response
	uint8_t opcode = *op.derptr - DER_TAG_APPLICATION(0);
	opcode &= ~ 0x20;  // Remove constructed/not flag
	if (opcode >= 31) {
		errno = EBADMSG;
		goto bail_out;
	}
	//
	// Check if we can put the harvested values to use
	if (lil->lillyget_operation == NULL) {
		errno = ENOSYS;
		goto bail_out;
	}
	//
	// Request a memory pool for the msgid
	if (qpool == NULL) {
		qpool = lillymem_newpool ();
		if (qpool == NULL) {
			errno = ENOMEM;
			goto bail_out;
		}
	}
	//
	// Lookup the parser (and check if it is defined, and welcomed)
	// For ExtendedRequest/Response, we loop here with a new opcode
	const struct packer_info *pck;
rerun_extended:
	if ((lil->reject_ops [opcode >> 5] & (1UL << opcode)) != 0) {
		// Trigger ENOSYS with the no-packer-found check below
		pck = &opcode_reject;
	} else {
		pck = &opcode_table [opcode];
	}
	if (pck->pck_message == NULL) {
		errno = ENOSYS;
		goto bail_out;
	}
	//
	// Allocate memory for unpacking the operation.
	// We need not zero the memory because der_unpack() writes NULLs.
	dercursor *data = lillymem_alloc (lil->cnxpool, pck->len_message);
	if (data == NULL) {
		errno = ENOMEM;
		goto bail_out;
	}
	//
	// Apply the parser to the operation
	if (der_unpack ((dercursor *) &op, pck->pck_message, data, 1) == -1) {
		goto bail_out;
	}
	//
	// In case of ExtendedRequest or ExtendedResponse, continue parsing
	bool extreq  = (opcode == OPCODE_EXTENDED_REQ );
	bool extresp = (opcode == OPCODE_EXTENDED_RESP);
	if (extreq || extresp) {
		dercursor extoid = data [ extreq ? 0 : 4 ];
		const struct packer_info_ext *pcke;
		pcke = lillymsg_packinfo_ext (extoid.derptr, extoid.derlen);
		if (pcke == NULL) {
			errno = ENOSYS;
			goto bail_out;
		}
		opcode = extreq? pcke->opc_request: pcke->opc_response;
		if (opcode_table [opcode].pck_message != pck->pck_message) {
			// Looping ends because none of the OIDs leads to
			// ExtendedRequest or ExtendedResponse opcodes.
			// We will loose *data, but that is the way things
			// work under the region-based allocation idea.
			goto rerun_extended;
		}
		// We continue when the extension adds no data of its own
	}
	//
	// Pass down the information -- and the responsibility
	// The response value also comes from lillyget_operation()
	return lil->lillyget_operation (lil, qpool, msgid, opcode, data, controls);
	//
	// Upon failure, cleanup and report the failure to the upstream
bail_out:
	if (qpool != NULL) {
		lillymem_endpool (qpool);
	}
	return -1;
}


/* Prefix a header with a given tag and length.  Return the total length.
 * If the dest_opt is NULL, do not actually write the header bytes, but
 * just return the length.
 */
size_t qder2b_prefixhead (uint8_t *dest_opt, uint8_t header, size_t len) {
	int sublen = 0;
	if (len >= 0x80) {
		// Length of length prefix
		while (len > 0) {
			sublen--;
			if (dest_opt != NULL) {
				dest_opt [sublen] = (len & 0xff);
			}
			len >>= 8;
		}
		len = 0x80 - sublen;
	}
	// Simple length or length-of-length
	sublen--;
	if (dest_opt != NULL) {
		dest_opt [sublen] = len;
		dest_opt [sublen - 1] = header;
	}
	return len + 1 - sublen;
}


/* Send an operation based on the given msgid, operation and control.
//TODO// Run the same code twice, first with NULL, then loop back with a ptr
 */
int lillyput_operation (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const uint8_t opcode,
				const dercursor *data,
				const dercursor controls) {
#if 0
	if (opcode > OPCODE_EXT_UNKNOWN) {
		return -1;
	}
	if (data == NULL) {
		return -1;
	}
#endif
	//
	// Check that the upstream function is available
	if (lil->lillyput_dercursor == NULL) {
		errno = ENOSYS;
		return -1;
	}
	//
	// Count the number of bytes in the DER message
	size_t totlen = der_pack (opcode_table [opcode].pck_message,
					data, NULL);
	if (totlen == 0) {
		errno = EINVAL;
		return -1;
	}
	//
	// Count the number of bytes for the controls
	if (controls.derptr != NULL) {
		totlen += qder2b_prefixhead (NULL,
				DER_TAG_CONTEXT(0) | 0x20,
				qder2b_prefixhead (NULL,
					DER_TAG_SEQUENCE | 0x20,
					controls.derlen));
	}
	//
	// Add the number of bytes for the MessageID
	uint32_t mid = msgid;
	while (mid > 0) {
		totlen++;
		mid >>= 8;
	}
	totlen += 2;
	//
	// Prefix a SEQUENCE header to complete the LDAPMessage
	totlen = qder2b_prefixhead (NULL, DER_TAG_SEQUENCE, totlen);
	//
	// Allocate a buffer for the DER message
	dercursor dermsg;
	if ((dermsg.derptr = lillymem_alloc (qpool, totlen)) == NULL) {
		errno = ENOMEM;
		return -1;
	}
	dermsg.derlen = totlen;
	//
	// Perform the actual packing in the now-prepared buffer
	// Start counting totlen from 0 and hope to find the same again
	totlen = 0;
	//
	// If controls were provided, add them
	if (controls.derptr != NULL) {
		memcpy (dermsg.derptr + dermsg.derlen - controls.derlen,
				controls.derptr,
				controls.derlen);
		totlen = qder2b_prefixhead (NULL,
				DER_TAG_CONTEXT(0) | 0x20,
				qder2b_prefixhead (NULL,
					DER_TAG_SEQUENCE,
					controls.derlen));
	}
	//
	// Precede with the packed data
	totlen += der_pack (opcode_table [opcode].pck_message,
				data,
				dermsg.derptr + dermsg.derlen - totlen);
	//
	// Exceptional -- due to IMPLICIT TAGS
	// If packaging started with DER_PACK_STORE, we may need to set
	// the flag that this is a composite field (but not when empty)
	if (dermsg.derptr [1 + dermsg.derlen - totlen] > 0) {
		dermsg.derptr [0 + dermsg.derlen - totlen] |= 0x20;
	}
	//
	// Prefix the MessageID
	mid = msgid;
	uint8_t midlen = 0;
	while (mid > 0) {
		dermsg.derptr [dermsg.derlen - ++totlen] = (mid & 0xff);
		mid >>= 8;
		midlen++;
	}
	totlen += qder2b_prefixhead (dermsg.derptr + dermsg.derlen - totlen,
			DER_TAG_INTEGER,
			midlen) - midlen;
	//
	// Now construct the LDAPMessage as a SEQUENCE
	totlen = qder2b_prefixhead (dermsg.derptr + dermsg.derlen - totlen,
			DER_TAG_SEQUENCE | 0x20,
			totlen);
#if 0
	if (totlen != dermsg.derlen) {
		fprintf (stderr, "ERROR: Reproduced length %zd instead of %zd\n", totlen, dermsg.derlen);
	}
#endif
	//
	// Pass the resulting DER message on to lillyput_dercursor()
	return lil->lillyput_dercursor (lil, qpool, dermsg);
}

