# lillydap.py -- package with LillyDAP bindings for Python
#
# From: Rick van Rein <rick@openfortress.nl>


import _lillydap


from quick_der.api import *

from quick_der.rfc4511 import *
from quick_der.rfc3062 import *
from quick_der.rfc3909 import *
from quick_der.rfc4373 import *
from quick_der.rfc4531 import *
from quick_der.rfc5805 import *


# A number of classes have names from RFCs that do not match how want to
# call the operations.  We resolve this with class inheritance, which
# effectively renames them.  It also helps to formulate a type (and thereby
# an operation name) for operations that expect no parameters.
#
# TODO:ALTERNATIVELY we might define ASN.1 types for these ourselves.

class StartTLSRequest (ExtendedRequest):
	pass

class StartTLSResponse (ExtendedResponse):
	pass

class PasswdModifyRequest (PasswdModifyRequestValue):
	pass

class PasswdModifyResponse (PasswdModifyResponseValue):
	pass

class CancelRequest (CancelRequestValue):
	pass

class CancelResponse (ExtendedResponse):
	pass

class WhoamiRequest (ExtendedRequest):
	pass

class WhoamiResponse (ExtendedResponse):
	pass

class StartLBURPRequest (StartLBURPRequestValue):
	pass

class StartLBURPResponse (StartLBURPResponseValue):
	pass

class EndLBURPRequest (ExtendedRequest):
	pass

class EndLBURPResponse (ExtendedResponse):
	pass

class LBURPUpdateRequest (LBURPUpdateRequestValue):
	pass

class LBURPUpdateResponse (ExtendedResponse):
	pass

class TurnRequest (TurnValue):
	pass

class TurnResponse (ExtendedResponse):
	pass

class StartTxnRequest (ExtendedRequest):
	pass

class StartTxnResponse (ExtendedResponse):
	pass

class EndTxnRequest (TxnEndReq):
	pass

class EndTxnResponse (TxnEndRes):
	pass

class AbortedTxnResponse (ExtendedResponse):
	pass


# The following lookup table maps opcodes as used by LillyDAP to the
# class for the data object for that opcode.  This table is used both
# to parse operand data and to validate its typing.  It follows the
# same order (and index numbering) as enum opcode_ext in lib/msgop.tab
opcode2dataclass = [
	BindRequest,
	BindResponse,
	UnbindRequest,
	SearchRequest,
	SearchResultEntry,
	SearchResultDone,
	ModifyRequest,
	ModifyResponse,
	AddRequest,
	AddResponse,
	DelRequest,
	DelResponse,
	ModifyDNRequest,
	ModifyDNResponse,
	CompareRequest,
	CompareResponse,
	AbandonRequest,
	None,	#17
	None,	#18
	SearchResultReference,
	None,	#20
	None,	#21
	None,	#22
	ExtendedRequest,
	ExtendedResponse,
	IntermediateResponse,
	None,	#26
	None,	#27
	None,	#28
	None,	#29
	None,	#30
	None,	#31
	StartTLSRequest,
	StartTLSResponse,
	PasswdModifyRequest,
	PasswdModifyResponse,
	WhoamiRequest,
	WhoamiResponse,
	CancelRequest,
	CancelResponse,
	StartLBURPRequest,
	StartLBURPResponse,
	EndLBURPRequest,
	EndLBURPResponse,
	LBURPUpdateRequest,
	LBURPUpdateResponse,
	TurnRequest,
	TurnResponse,
	StartTxnRequest,
	StartTxnResponse,
	EndTxnRequest,
	EndTxnResponse,
	AbortedTxnResponse,
]


class LillyDAP (_lillydap.PyDAP):
	"""LillyDAP objects represent an input and/or output connection
	   for the LDAP protocol.  Events are sent to inform the connection
	   about possibilities of sending or receiving data.  Data is
	   collected and parsed increasingly until a unit of interest for
	   further processing is found, which then leads to a method
	   callback on this object.  On the parsing side, these are the
	   lillyget_xxx() methods.  On the sending side, data is gathered
	   to close in on bytes to transmit, using lillyput_xxx() methods.
	   Each of these methods can be overridden; by default, they all
	   connect in one downward flow of lillyget_xxx() and one upward
	   flow of lillyput_xxx().
	"""

	def lillyget_operation (self, msgid, opcode, data, ctls):
		"""The lillyget_operation() method receives a partially
		   parsed operation.  What is done here is to split it up
		   into individual methods, named by the operation.  When
		   these operations are not overridden in a subclass,
		   NotImplementedError is reported.  This method also cares
		   for parsing of the data to an operation-specific data
		   structure.
		"""
		method_name = '(?)'
		try:
			cls = opcode2dataclass [opcode]
			method_name = 'lillyget_' + cls.__name__
			bound_method = getattr (self, method_name)
			if bound_method:
				print 'lillyget_operation() :- Found method for', method_name
		except:
			raise NotImplementedError, 'Method ' + method_name + ' undefined'
		print 'lillyget_operation() :- instantiating derblob', data.encode ('hex'), 'of length', len (data)
		py_data = cls (derblob=data)
		print 'lillyget_operation() :- got Python data', repr (py_data)
		return bound_method (msgid, py_data, ctls)


# Generate the lillyput_OperationByName() methods from opcode2dataclass[]
for idx in range (len (opcode2dataclass)):
	cls = opcode2dataclass [idx]
	if cls is None:
		continue
	def make_method (idx, cls):
		def generic_method (self, msgid, py_data, ctls):
			assert 1 <= msgid <= 2147483647, 'MessageID out of range'
			assert isinstance (py_data, cls), 'Data argument should be an instance of lillydap.' + cls.__name__
			data = py_data._der_pack ()
			self.lillyput_operation (msgid, idx, data, ctls)
		return generic_method
	method_name = 'lillyput_' + cls.__name__
	setattr (LillyDAP, method_name, make_method (idx, cls))


