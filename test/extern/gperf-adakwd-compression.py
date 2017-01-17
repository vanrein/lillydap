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
      "", "", "",
      "xor",
      "", "", "",
      "or",
      "out",
      "terminate",
      "", "",
      "reverse",
      "use",
      "else",
      "entry",
      "for",
      "", "",
      "case",
      "of",
      "",
      "at",
      "not",
      "then",
      "range",
      "return",
      "",
      "elsif",
      "task",
      "abort",
      "accept",
      "",
      "constant",
      "exception",
      "array",
      "select",
      "renames",
      "",
      "when",
      "",
      "access",
      "do",
      "abs",
      "type",
      "",
      "record",
      "declare",
      "",
      "exit",
      "raise",
      "",
      "package",
      "new",
      "procedure",
      "", "",
      "is",
      "separate",
      "goto",
      "if",
      "function",
      "subtype",
      "all",
      "null",
      "while",
      "",
      "in",
      "",
      "loop",
      "delay",
      "", "",
      "end",
      "with",
      "",
      "others",
      "", "", "",
      "delta",
      "",
      "generic",
      "rem",
      "", "",
      "pragma",
      "", "", "", "", "",
      "private",
      "and",
      "body",
      "", "", "", "", "", "",
      "digits",
      "limited",
      "", "", "", "", "", "", "", "", "",
      "",
      "mod",
      "", "", "", "", "", "",
      "begin"
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

