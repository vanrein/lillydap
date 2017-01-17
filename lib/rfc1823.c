/* rfc1823.c -- The standard LDAP API for clients, and callbacks for servers.
 *
 * This implements RFC 1823 for clients, and supports registration for
 * the same callbacks by servers.  Other operations than defined in the
 * RFC are not supported here.
 *
 * This module is reasonably expensive in terms of computing resources, and
 * is not necessary for clients that program directly to the LillyDAP API.
 * For this reason, it will be built as a separate library archive object,
 * and only included when its symbols are mentioned.
 *
 * The implementations below are asynchronous by default.  The synchronous
 * versions are simulated here, in terms of the asynchronous operations.
 *
 * From: Rick van Rein <rick@opnefortress.nl>
 */


//TODO// What a drag this seems, now the crisp API of LillyDAP is clear  :-S


int rfc1823_lillyget_operation (LDAP *lil,
				LillyPool *pool,
				const LillyMsgId msgid,
				const uint8_t opcode,
				const dercursor *data,
				const dercursor *extdata,
				const dercursor *controls) {
	return -1;
}


