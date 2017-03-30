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

	def lillyget_operation (self, msgid, opcode, bindata, ctls):
		"""The lillyget_operation() method receives a partially
		   parsed operation.  What is done here is to split it up
		   into individual methods, named by the operation.  When
		   these operations are not overridden in a subclass,
		   NotImplementedError is reported.  This method also cares
		   for further processing of the bindata list of strings
		   to an operation-specific data structure, including
		   nested invocations of der_unpack() to accommodate the
		   specific needs of the targeted command.
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
		print 'lillyget_operation() :- instantiating bindata', bindata
		py_data = cls (bindata=bindata)
		print 'lillyget_operation() :- got Python data', repr (py_data)
		bound_method (msgid, py_data, ctls)
		print 'lillyget_operation() :- done!'


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


# A number of types have more specific definitions in text than in ASN.1
# and so their printers can be made prettier

def _str_unicode_ (self):
	return unicode (self.get ())

def _str_ascii_ (self):
	return str (self.get ())

LDAPString.__str__ = _str_unicode_
LDAPOID.__str__ = _str_ascii_


def filter_eval (filter, callback, invert=False, **cbargs):
	"""The filter_eval() function evaluates an rfc4511.Filter expression
	   such as those that occur in a SearchRequest.
	   
	   The return value is composed from the result of callbacks that
	   evaluate elementary tests.  These results are composed as indicated
	   by the and, or and not operators.  The callbacks are invoked with
	   TODO and the cbargs.
	   
	   Normally, the return value is either True or False.  In cases
	   however, where the elementary tests return None so often that no
	   final conclusion can be reached, this function may result None
	   as well.  When the callback never returns None, then neither will
	   this function.
	   
	   This function is as lazy as possible.  A True result in an "or"
	   composition suffices, as well as a False result in an "and"
	   composition; no further filter components will then be considered.
	   Note that None always calls for further evaluation.
	   
	   The parameter "invert" may be used to invert the Filter's logic
	   result.
	   
	   TODO: Move this functionality to C code?
	"""
	while True:
		(hd,blen,hlen) = _quickder.der_header (filter)
		if hd != DER_TAG_CONTEXT(2):
			# Break on all but "not"
			break
		invert = not invert
	if hd in [ DER_TAG_CONTEXT(0), DER_TAG_CONTEXT(1) ]:
		# Find out collection function details
		if invert:
			hd ^= DER_TAG_CONTEXT(0) ^ DER_TAG_CONTEXT(1)
		if hd == DER_TAG_CONTEXT(0):
			# Found "and"
			neutral,gameover = True,False
		else:
			# Found "or"
			neutral,gameover = False,True
		# Now iterate over content
		elems = filter [-blen:]
		while elems != '':
			(hd,blen,hlen) = _quickder.der_header (elems)
			if hlen + blen < len (elems):
				raise Exception ("Malformed filter expression")
			elem = elems [hlen:hlen+blen]
			elems = elems [-blem:]
			elemval = filter_eval (elem, callback, invert, **cbargs)
			if elemval == gameover:
				return gameover
		return neutral
	else:
		elemval = filter_eval (filter [-blen:], callback, invert, **cbargs)
		if elemval is not None and invert:
			elemval = not elemval
		return elemval

