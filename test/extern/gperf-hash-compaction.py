#!/usr/bin/env python
#
# A test to see if we could indeed compact gperf's hash table, and notably
# its asso_table.  The idea being that this table is full of values
# MAX_HASH_VALUE+1 if the table is sparse.  Overlaying table parts can then
# help to compact it.
#
# From: Rick van Rein <rick@openfortress.nl>


keys = [
	"1.3.6.1.4.1.1466.20037",
	"1.3.6.1.4.1.4203.1.11.1",
	"1.3.6.1.4.1.4203.1.11.3",
	"1.3.6.1.1.8",
	"1.3.6.1.1.17.1",
	"1.3.6.1.1.17.2",
	"1.3.6.1.1.17.3",
	"1.3.6.1.1.17.4",
	"1.3.6.1.1.17.5",
	"1.3.6.1.1.17.6",
	"1.3.6.1.1.19",
	"1.3.6.1.1.21.1",
	"1.3.6.1.1.21.3",
	"1.3.6.1.1.21.4",
]


def hash_gperf (strr, llen):
	asso_values = [
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28,  3,  1,  0,  5,  7,  6,  0,  0,  0, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28
	]
	return llen + asso_values [ord (strr [10]) +1] + asso_values [ord (strr [llen-1])]


def hash_gperf_mod16 (strr, llen):
	asso_values = [
		28,  3,  1,  0,  5,  7,  6,  0,  0,  0, 28, 28, 28, 28, 28, 28
	]
	return llen + asso_values [(ord (strr [10]) +1) & 0x0f] + asso_values [ord (strr [llen-1]) & 0x0f]


def hash_gperf_mod9 (strr, llen):
	asso_values = [
		6,  0,  0,  0,  3,  1,  0,  5,  7,
	]
	return llen + asso_values [(ord (strr [10]) +1) % 9] + asso_values [ord (strr [llen-1]) % 9]


print 'Testing smaller asso_values tables, reduced by mod to exploit sparse tables;'
print 'the hash outcomes should be the same for all the keys; it does not matter'
print 'what the non-keys do, as strcmp() will capture those.'

print 'GPERF,GPERF_MOD16,GPERF_MOD9,KEYLEN,KEY'
for k in keys:
	print "%3d,%3d,%3d,%5d,  \"%s\"" % (hash_gperf(k, len(k)), hash_gperf_mod16(k, len(k)), hash_gperf_mod9(k, len(k)), len(k), k)

