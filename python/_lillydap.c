/* Custom wrappers for Python/C interface to LillyDAP.
 *
 * The LillyDAP support in Python defines a LillyDAP class with methods
 * matching the lillyget_xxx() and lillyput_xxx() operations.  Other than
 * in C, these default to passing through traffic to the next stage of
 * parsing or packing, if one exists.
 *
 * The parsing and packing of operation-specific data, as well as delivery
 * to and pickup from operation-specific methods, is arranged in Python,
 * and makes good use of the Python port of Quick DER.  This ensures that
 * the data structures are completely parsed, with special treatment only
 * for the recursive Filter element (through a recursive iterator).
 *
 * Most of the code below tries to stay within C once it is there, thereby
 * achieving the most optimal experience with the least hops back and forth
 * between C and Python.  Since LillyDAP is built as a parser stack and a
 * packer stack that can be overridden in many places, this would have cost
 * a bit more than we would prefer.
 *
 * Although one intention of this mapping is to achieve good efficiency,
 * its main purpose is to make LDAP available for dynamic data processing
 * needs, in a similar manner as cgi-bin has done for HTTP.  The much more
 * refined data model of LDAP promises to be highly useful for applications
 * using dynamic data.  Finally, the Python port for LillyDAP can help to
 * quickly prototype software and middleware, with an option of migrating
 * to C versions soon after; the flexible linkage between C and Python
 * is hoped to accommodate the migration of individual components without
 * impact on others.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <Python.h>

#include <lillydap/api.h>

#include <quick-der/api.h>


static PyObject *lget_event (PyObject *self, PyObject *no_args) {
	//
	// No parameters -- no parsing
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lget_dercursor (PyObject *self, PyObject *args) {
	//
	// Parse parameters: msg
	char *msgptr;
	Py_ssize_t msglen;
	if (!PyArg_ParseTuple (args, "s#", &msgptr, &msglen)) {
		return NULL;
	}
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lget_ldapmessage (PyObject *self, PyObject *args) {
	//
	// Parse parameters: msgid, op, controls
	int msgid;
	char *opptr;
	Py_ssize_t oplen;
	char *ctlptr;
	Py_ssize_t ctllen;
	if (!PyArg_ParseTuple (args, "is#s#", &msgid, &opptr, &oplen, &ctlptr, &ctllen)) {
		return NULL;
	}
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lput_operation (PyObject *self, PyObject *args) {
	//
	// Parse parameters: msgid, opcode, data, controls
	int msgid;
	int opcode;
	char *dataptr;
	Py_ssize_t datalen;
	char *ctlptr;
	Py_ssize_t ctllen;
	if (!PyArg_ParseTuple (args, "iis#s#", &msgid, &opcode, &dataptr, &datalen, &ctlptr, &ctllen)) {
		return NULL;
	}
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lput_ldapmessage (PyObject *self, PyObject *args) {
	//
	// Parse parameters: msgid, op, controls
	int msgid;
	char *opptr;
	Py_ssize_t oplen;
	char *ctlptr;
	Py_ssize_t ctllen;
	if (!PyArg_ParseTuple (args, "is#s#", &msgid, &opptr, &oplen, &ctlptr, &ctllen)) {
		return NULL;
	}
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lput_dercursor (PyObject *self, PyObject *args) {
	//
	// Parse parameters: msg
	char *msgptr;
	Py_ssize_t msglen;
	if (!PyArg_ParseTuple (args, "s#", &msgptr, &msglen)) {
		return NULL;
	}
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lput_enqueue (PyObject *self, PyObject *args) {
	//
	// Parse parameters: addend
	char *addendptr;
	Py_ssize_t addendlen;
	if (!PyArg_ParseTuple (args, "s#", &addendptr, &addendlen)) {
		return NULL;
	}
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lput_cansend (PyObject *self, PyObject *no_args) {
	//
	// No parameters -- no parsing
	//TODO//
	//
	// Cleanup and return
	return NULL;
}

static PyObject *lput_event (PyObject *self, PyObject *no_args) {
	//
	// No parameters -- no parsing
	//TODO//
	//
	// Cleanup and return
	return NULL;
}



static PyMethodDef lil_methods [] = {
	{ "lillyget_event",       lget_event,       METH_NOARGS,  "Indicate to LillyDAP that data may be read" },
	{ "lillyget_dercursor",	  lget_dercursor,   METH_VARARGS, "Receive one complete top-level DER structure" },
	{ "lillyget_ldapmessage", lget_ldapmessage, METH_VARARGS, "Receive one LDAPMessage structure" },
	{ "lillyput_operation",   lput_operation,   METH_VARARGS, "Send one data operation message" },
	{ "lillyput_ldapmessage", lput_ldapmessage, METH_VARARGS, "Send one LDAPMessage structure" },
	{ "lillyput_dercursor",   lput_dercursor,   METH_VARARGS, "Send one complete top-level DER structure" },
	{ "lillyput_enqueue",     lput_enqueue,     METH_VARARGS, "Append the given text to the outgoing queue" },
	{ "lillyput_cansend",     lput_cansend,     METH_NOARGS,  "Test if the outgoing queue is non-empty" },
	{ "lillyput_event",       lput_event,       METH_NOARGS,  "Indicate to LillyDAP that data may be sent" },
	{ NULL, NULL, 0, NULL }
};


PyMODINIT_FUNC init_lillydap () {
	PyObject *mod;
	mod = Py_InitModule ("_lillydap", lil_methods);
	if (mod == NULL) {
		return;
	}
}

