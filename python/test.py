#!/usr/bin/env python

import os
import sys
sys.path.append ('../build/python/lillydap')	#TODO:AWFUL_HARDCODED_PATH#

from lillydap import LillyDAP, AddRequest

class MyLIL (LillyDAP):

	def lillyget_SearchResultEntry (self, msgid, sre, ctl):
		print 'Whee, got a search result entry!'
		print 'MessageID      =', msgid
		print 'sre.objectName =', sre.objectName
		print 'sre.attributes =', sre.attributes
		print 'Whee, we have completed our work!'

lil = MyLIL ()

print 'LillyDAP instance has attributes', dir (lil)

addreq = AddRequest (derblob='\x68\x06\x04\x02DN\x30\x00')

print 'AddRequest instance has identity', id (addreq)

def lpo (msgid, opcode, data, ctls):
	print 'MessageID:', msgid
	print 'OpCode:', opcode
	print 'Data:', data.encode ('hex')
	print 'Controls:', ctls

lil.lillyput_operation = lpo

print '<<< lillyput_AddRequest()'
lil.lillyput_AddRequest (123, addreq, [('x',False,3)])
print '>>> lillyput_AddRequest()'

(r,w) = os.pipe ()
lil.get_fd = r
lil.put_fd = sys.stdout.fileno ()
d = open ('../test/ldap/103-search-resentry.bin').read ()
os.write (w,d)
d = open ('../test/ldap/001-search-resentry-rejected.bin').read ()
os.write (w,d)
os.close (w)
print '<<< lillyput_event()'
lil.lillyget_event ()
print '>>> lillyput_event()'


