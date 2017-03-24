# lillydap.py -- package with LillyDAP bindings for Python
#
# From: Rick van Rein <rick@openfortress.nl>


import string as _lillydap #TODO# import _lillydap


from quick_der.api import *

from quick_der.rfc4511 import *
from quick_der.rfc3909 import *
from quick_der.rfc4373 import *
from quick_der.rfc5805 import *


# The following lookup table maps opcodes as used by LillyDAP to the
# class for the data object for that opcode.  This table is used both
# to parse operand data and to validate its typing.
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
	None, #TODO# StartTlsRequest,
	None, #TODO# StartTlsResponse,
	None, #TODO# PasswdModifyRequest,
	None, #TODO# PasswdModifyResponse,
	None, #TODO# WhoamiRequest,
	None, #TODO# WhoamiResponse,
	None, #TODO# CancelRequest,
	None, #TODO# CancelResponse,
	None, #TODO# StartLBURPRequest,
	None, #TODO# StartLBURPResponse,
	None, #TODO# EndLBURPRequest,
	None, #TODO# EndLBURPResponse,
	None, #TODO# LBURPUpdateRequest,
	None, #TODO# LBURPUpdateResponse,
	None, #TODO# TurnRequest,
	None, #TODO# TurnResponse,
	None, #TODO# StartTxnRequest,
	None, #TODO# StarttxnResponse,
	None, #TODO# EndTxnRequest,
	None, #TODO# EndTxnResponse,
	None, #TODO# AbortedTxnResponse,
]


class LillyDAP (object):
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

	from _lillydap import lillyget_event, lillyget_dercursor, lillyget_ldapmessage, lillyput_operation, lillyput_ldapmessage, lillyput_dercursor, lillyput_enqueue, lillyput_cansend, lillyput_event

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
		except:
			raise NotImplementedError, 'Method ' + method_name + ' undefined'
		py_data = cls (derblob=data)
		return bound_method (msgid, py_data, ctls)


# Generate the lillyput_OperationByName() methods from opcode2dataclass[]
for idx in range (len (opcode2dataclass)):
	cls = opcode2dataclass [idx]
	if cls is None:
		continue
	print 'Class is', cls
	def make_method (idx, cls):
		def generic_method (self, msgid, py_data, ctls):
			assert 1 <= msgid <= 2147483647, 'MessageID out of range'
			print 'Comparing', py_data, 'to class', cls
			assert isinstance (py_data, cls), 'Data argument should be an instance of lillydap.' + cls.__name__
			data = py_data._der_pack ()
			self.lillyput_operation (msgid, idx, data, ctls)
		return generic_method
	method_name = 'lillyput_' + cls.__name__
	setattr (LillyDAP, method_name, make_method (idx, cls))


