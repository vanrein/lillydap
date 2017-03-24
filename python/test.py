#!/usr/bin/env python

from lillydap import LillyDAP

lil = LillyDAP ()

print 'LillyDAP instance has attributes', dir (lil)

lil.lillyput_AddRequest (123, None, [])

