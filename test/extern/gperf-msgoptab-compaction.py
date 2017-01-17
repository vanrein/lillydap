#!/usr/bin/env python
#
# Attempt to compact the table output by gperf -- it holds empty entries
# that could perhaps go when using modular arithmetic.  Especially the
# empty entries at the beginning can go.
#
# From: Rick van Rein <rick@openfortress.nl>


# The model holds "" for non-occupied entries and something else for
# ones that are.  The trick will be to find a modulus that reduces the
# table size without causing overlapping True values.

model = [
    "", "", "", "", "", "", "", "", "",
    "", "",
    "1.3.6.1.1.8",
    "",
    "1.3.6.1.1.19",
    "1.3.6.1.1.21.3",
    "1.3.6.1.1.17.3",
    "1.3.6.1.1.17.2",
    "1.3.6.1.1.21.1",
    "1.3.6.1.1.17.1",
    "1.3.6.1.1.21.4",
    "1.3.6.1.1.17.4",
    "1.3.6.1.1.17.6",
    "1.3.6.1.1.17.5",
    "1.3.6.1.4.1.1466.20037",
    "1.3.6.1.4.1.4203.1.11.3",
    "", "",
    "1.3.6.1.4.1.4203.1.11.1"
]

min_modulus = len ([ s for s in model if s != "" ])
max_modulus = len (model)


def modmodel (m):
	rv = [ "" ] * m
	for i in range (len (model)):
		if model [i] != "":
			if rv [ i % m ] != "":
				# entry is already taken
				return None
			rv [ i % m ] = model [i]
	return rv

for m in range (max_modulus, min_modulus-1,-1):
	mod2 = modmodel (m)
	if mod2:
		print
		print '### REDUCTION FROM', max_modulus, 'TO', m
		print mod2
	else:
		print
		print '### Failed to reduce from', max_modulus, 'to', m

