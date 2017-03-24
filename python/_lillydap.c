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


#include <errno.h>

#include <Python.h>
#include <structmember.h>

#include <lillydap/api.h>

#include <quick-der/api.h>


/* The Python object that includes the LillyDAP information is called
 * PyDAP in the sequel.  Any "self" object is an instance of this
 * object because LillyDAP inherits from PyDAP.
 */

typedef struct {
	PyObject_HEAD
	LillyDAP ldap;
} PyDAP;


static PyObject *lget_event (PyObject *self, PyObject *no_args) {
	//
	// No parameters -- no parsing
	//
	// Inform the underlying code about the read event
	ssize_t bytes_read = lillyget_event (&((PyDAP *) self)->ldap);
	if (bytes_read == -1) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Construct the return value
	PyObject *retval = PyInt_FromSsize_t ((Py_ssize_t) bytes_read);
	if (retval == NULL) {
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	return retval;
}

static PyObject *lget_dercursor (PyObject *self, PyObject *args) {
	//
	// Parse parameters: msg
	char *msgptr;
	Py_ssize_t msglen;
	if (!PyArg_ParseTuple (args, "s#", &msgptr, &msglen)) {
		return NULL;
	}
	//
	// Have a memory pool
	LillyPool qpool = NULL;
	if (!lillymem_havepool (&qpool)) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Invoke the library routine
	dercursor dermsg;
	dermsg.derptr = msgptr;
	dermsg.derlen = msglen;
	if (lillyget_dercursor (&((PyDAP *) self)->ldap, qpool, dermsg) == -1) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	Py_RETURN_NONE;
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
	//
	// Have a memory pool
	LillyPool qpool = NULL;
	if (!lillymem_havepool (&qpool)) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Send the LDAPMessage up towards the queue; use stack-copied objects
	dercursor op, ctl;
	op.derptr = opptr;
	op.derlen = oplen;
	ctl.derptr = ctlptr;
	ctl.derlen = ctllen;
	if (lillyget_ldapmessage (&((PyDAP *) self)->ldap, qpool, msgid, op, ctl) == -1) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	Py_RETURN_NONE;
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
	//
	// Check correctness of the opcode
	if ((opcode < 0) || (opcode > 255)) {
		errno = EINVAL;
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Have a memory pool and allocate a dercursor
	LillyPool qpool = NULL;
	if (!lillymem_havepool (&qpool)) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	dercursor *data = lillymem_alloc (qpool, sizeof (dercursor));
	if (data == NULL) {
		errno = ENOMEM;
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Send the operation code up towards the queue
	dercursor ctl;
	data->derptr = dataptr;
	data->derlen = datalen;
	ctl.derptr = ctlptr;
	ctl.derlen = ctllen;
	if (lillyput_operation (&((PyDAP *) self)->ldap, qpool, msgid, (uint8_t) opcode, data, ctl) == -1) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	Py_RETURN_NONE;
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
	//
	// Have a memory pool
	LillyPool qpool = NULL;
	if (!lillymem_havepool (&qpool)) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Send the LDAPMessage up towards the queue; use stack-copied objects
	dercursor op, ctl;
	op.derptr = opptr;
	op.derlen = oplen;
	ctl.derptr = ctlptr;
	ctl.derlen = ctllen;
	if (lillyput_ldapmessage (&((PyDAP *) self)->ldap, qpool, msgid, op, ctl) == -1) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	Py_RETURN_NONE;
}

static PyObject *lput_dercursor (PyObject *self, PyObject *args) {
	//
	// Parse parameters: msg
	char *msgptr;
	Py_ssize_t msglen;
	if (!PyArg_ParseTuple (args, "s#", &msgptr, &msglen)) {
		return NULL;
	}
	//
	// Have a memory pool
	LillyPool qpool = NULL;
	if (!lillymem_havepool (&qpool)) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Invoke the library routine
	dercursor dermsg;
	dermsg.derptr = msgptr;
	dermsg.derlen = msglen;
	if (lillyput_dercursor (&((PyDAP *) self)->ldap, qpool, dermsg) == -1) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	Py_RETURN_NONE;
}

static PyObject *lput_enqueue (PyObject *self, PyObject *args) {
	//
	// Parse parameters: addend
	char *addendptr;
	Py_ssize_t addendlen;
	if (!PyArg_ParseTuple (args, "s#", &addendptr, &addendlen)) {
		return NULL;
	}
	//
	// Have a memory pool
	LillyPool qpool = NULL;
	if (!lillymem_havepool (&qpool)) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Submit to the queue, and let the memory self-destroy
	dercursor dermsg;
	dermsg.derptr = addendptr;
	dermsg.derlen = addendlen;
	if (lillyput_dercursor (&((PyDAP *) self)->ldap, qpool, dermsg) == -1) {
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	Py_RETURN_NONE;
}

static PyObject *lput_cansend (PyObject *self, PyObject *no_args) {
	//
	// No parameters -- no parsing
	bool can_send = lillyput_cansend (&((PyDAP *) self)->ldap);
	//
	// Cleanup and return
	if (can_send) {
		Py_RETURN_TRUE;
	} else {
		Py_RETURN_FALSE;
	}
}

static PyObject *lput_event (PyObject *self, PyObject *no_args) {
	//
	// No parameters -- no parsing
	// Inform the underlying code about the read event
	ssize_t bytes_read = lillyput_event (&((PyDAP *) self)->ldap);
	if (bytes_read == -1) {
		PyErr_SetFromErrno (PyExc_OSError);
		//TODO// refctr
		return NULL;
	}
	//
	// Construct the return value
	PyObject *retval = PyInt_FromSsize_t ((Py_ssize_t) bytes_read);
	if (retval == NULL) {
		//TODO// refctr
		return NULL;
	}
	//
	// Cleanup and return
	return retval;
}


int pyget_operation (LillyDAP *lil, LillyPool qpool,
				const LillyMsgId msgid,
				const uint8_t opcode,
				const dercursor *data,
				const dercursor controls) {
	//
	// Find the object to invoke the method on
	//TODO//
	PyObject *self = NULL;
	//
	// Invoke the method in Python
	PyObject *result = PyObject_CallMethod (self,
			"lillyget_operation", "(iis#s#)",
			(int) msgid, (int) opcode,
			data->derptr, data->derlen,
			controls.derptr, controls.derlen);
	if (result == NULL) {
		return -1;
	}
	//
	// Cleanup and report -- simply assume that None was returned
	Py_DECREF (result);
	return 0;
}


static PyObject *pydap_new (PyTypeObject *tp, PyObject *args, PyObject *kwargs) {
	PyDAP *self;
	//
	// Allocate the object to be returned
	self = (PyDAP *) tp->tp_alloc (tp, 0);
	if (self == NULL) {
		return self;
	}
	//
	// Initialise the object before any __init__ user code runs
	self->ldap.get_fd = -1;
	self->ldap.put_fd = -1;
	//
	// Setup function pointers (TODO: Need to separate static info)
	self->ldap.lillyget_dercursor   = lillyget_dercursor;
	self->ldap.lillyget_ldapmessage = lillyget_ldapmessage;
	self->ldap.lillyput_ldapmessage = lillyput_ldapmessage;
	self->ldap.lillyput_dercursor   = lillyput_dercursor;
	self->ldap.lillyget_operation   = pyget_operation;
	//
	// Return the prepared C object
	return self;
}

static void pydap_dealloc (PyDAP *self) {
	if (self->ldap.get_fd >= 0) {
		close (self->ldap.get_fd);
		self->ldap.get_fd = -1;
	}
	if (self->ldap.put_fd >= 0) {
		close (self->ldap.put_fd);
		self->ldap.put_fd = -1;
	}
}


static struct PyMemberDef pydap_members[] = {
	{ "get_fd", T_INT, offsetof (PyDAP, ldap) + offsetof (LillyDAP, get_fd), 0, "The file descriptor from which data is read when triggered by lillyget_event()" },
	{ "put_fd", T_INT, offsetof (PyDAP, ldap) + offsetof (LillyDAP, put_fd), 0, "The file descriptor to which data is written when triggered by lillyput_event() or lillyput_enqueue()" },
	{ NULL, 0, 0, 0, NULL }
};


static PyMethodDef pydap_methods [] = {
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


static PyTypeObject pydap_pytype = {
	PyVarObject_HEAD_INIT (NULL, 0)
	"_lillydap.PyDAP",		/* tp_name */
	sizeof (PyDAP),			/* tp_basicsize */
	0,				/* tp_itemsize */
	(destructor) pydap_dealloc,	/* tp_dealloc */
	0,				/* tp_print */
	0,				/* tp_getattr */
	0,				/* tp_setattr */
	0,				/* tp_compare */
	0,				/* tp_repr */
	0,				/* tp_as_number */
	0,				/* tp_as_sequence */
	0,				/* tp_as_mapping */
	0,				/* tp_hash */
	0,				/* tp_call */
	0,				/* tp_str */
	0,				/* tp_getattro */
	0,				/* tp_setattro */
	0,				/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
					/* tp_flags */
	"Python LillyDAP connector",	/* tp_doc */
	0,				/* tp_traverse */
	0,				/* tp_clear */
	0,				/* tp_richcompare */
	0,				/* tp_weaklistoffset */
	0,				/* tp_iter */
	0,				/* tp_iternext */
	pydap_methods,			/* tp_methods */
	pydap_members,			/* tp_members */
	0,				/* tp_getset */
	0,				/* tp_base */
	0,				/* tp_dict */
	0,				/* tp_descr_get */
	0,				/* tp_descr_set */
	0,				/* tp_dictoffset */
	0, //TODO// (initproc) pydap_init,		/* tp_init */
	0,				/* tp_alloc */
	pydap_new,			/* tp_new */
};


// Module-generic methods (most interesting things are in pydap_methods)
static PyMethodDef lil_methods [] = {
	{ NULL, NULL, 0, NULL }
};


PyMODINIT_FUNC init_lillydap (void) {
	//
	// Construct the PyDAP type defined herein
	if (PyType_Ready (&pydap_pytype) < 0) {
		return;
	}
	PyObject *mod;
	mod = Py_InitModule ("_lillydap", lil_methods);
	if (mod == NULL) {
		return;
	}
	//
	// Further install the PyDAP type so we can subclass/instantiate it
	Py_INCREF (&pydap_pytype);
	PyModule_AddObject (mod, "PyDAP", (PyObject *) &pydap_pytype);
}

