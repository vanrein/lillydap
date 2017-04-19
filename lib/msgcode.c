/* LDAPMessage handling, in a generic sense.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>
#include <stdio.h>

#include <errno.h>

#include <lillydap/api.h>
#include <lillydap/mem.h>


#define lillymsg_packinfo_ext msgcode_lillymsg_packinfo_ext
#include "msgop.tab"


/* Receieve an LDAPMessage, which has been parsed shallowly, and determine
 * its operation code.  The qpool is optional; when provided, it will
 * because the responsibility of lillyget_ldapmessage() -- which it may
 * pass down to further lillyget_xxx() or other functions.
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
	int (*opcode_fun) (LDAP *lil,
                                LillyPool qpool,
                                const LillyMsgId msgid,
                                const uint8_t opcode,
                                const dercursor operation,
                                const dercursor controls) = NULL;
	if ((opcode < 31) && (((1UL << opcode) & LILLYGETR_ALL_RESP) != 0)) {
		// Try to override for response processing
		opcode_fun = lil->def->lillyget_opresp;
	}
	if (opcode_fun == NULL) {
		// Either a request or a non-overridden response
		opcode_fun = lil->def->lillyget_opcode;
	}
	if (opcode_fun == NULL) {
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
	// If this is an ExtendedRequest or ExtendedResponse, process any OID
	bool extreq  = (opcode == OPCODE_EXTENDED_REQ );
	bool extresp = (opcode == OPCODE_EXTENDED_RESP);
	dercursor extcrs [6];	// 2 in ExtendedRequest, 6 in ExtendedResponse
	if (extreq || extresp) {
		//
		// Apply the parser to the operation
		if (der_unpack ((dercursor *) &op,
				opcode_table [opcode].pck_message,
				extcrs, 1) == -1) {
			goto bail_out;
		}
		dercursor extoid = extcrs [ extreq ? 0 : 4 ];
		if (extoid.derptr != NULL) {
			const struct packer_info_ext *pcke;
			pcke = lillymsg_packinfo_ext ((char *)extoid.derptr, extoid.derlen);
			if (pcke == NULL) {
				errno = ENOSYS;
				goto bail_out;
			}
			opcode = extreq? pcke->opc_request: pcke->opc_response;
		} else if (extreq) {
			errno = EBADMSG;
			goto bail_out;
		} else {
			;  // Keep ExtendedResponse as opcode
		}
	}
	//
	// Call the desired backend, lillyget_operation() or lillyget_response()
	return opcode_fun (lil, qpool, msgid, opcode, op, controls);
bail_out:
	if (qpool != NULL) {
		lillymem_endpool (qpool);
	}
	return -1;
}

