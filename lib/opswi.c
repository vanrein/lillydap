/* opswi.c -- Dispatch operations by way of their registry entry
 *
 * This replaces the generic callback with an opcode by one for specific
 * operations, so programs can simply setup a registry and setup values
 * in lil->opregistry.by_name.BindRequest and similar entries.  Note how
 * this is supportive of a static table of callback functions.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdint.h>

#include <lillydap/api.h>


int lillyget_operation (LDAP *lil,
			LillyPool qpool,
			const LillyMsgId msgid,
			const uint8_t opcode,
			const dercursor *data,
			const dercursor controls) {
#if 0
	if (lil->opregistry == NULL) {
		errno = ENOSYS;
		return -1;
	}
#endif
	if (opcode * sizeof (void (*) ()) >= sizeof (LillyOpRegistry)) {
		errno = EINVAL;
		return -1;
	}
	if (lil->def->opregistry->by_opcode [opcode] == NULL) {
		errno = ENOSYS;
		return -1;
	}
	//
	// Now start the magic... call the by_opcode overlay, which was
	// setup in the by_name overlay with its own data type.  Note
	// how the opcode parameter is no longer passed.
	return (*lil->def->opregistry->by_opcode [opcode]) (lil, qpool, msgid, data, controls);
}
