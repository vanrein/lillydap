#!/usr/bin/env python

from lillydap import LillyDAP, AddRequest

lil = LillyDAP ()

print 'LillyDAP instance has attributes', dir (lil)

addreq = AddRequest (derblob='\x68\x06\x04\x02DN\x30\x00')

print 'AddRequest instance has identity', id (addreq)

def lpo (msgid, opcode, data, ctls):
	print 'MessageID:', msgid
	print 'OpCode:', opcode
	print 'Data:', data.encode ('hex')
	print 'Controls:', ctls

lil.lillyput_operation = lpo

lil.lillyput_AddRequest (123, addreq, [('x',False,3)])

