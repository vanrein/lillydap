/* control.h -- Definitions to help with management of LDAP Controls.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef LILLYCTL_H
#define LILLYCTL_H


#include <quick-der/api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The lillyctl_index values represent the index codes used by LillyDAP
 * to address individual controls.  The values are derived from OIDs by
 * a perfect hash function built with gperf.
 */
enum lillyctl_index {
	// RFC 2649, Section 1.1, Audit Trail Mechanism:
	LILLYCTL_1_2_840_113549_6_0_0,
	// RFC 2649, Section 2, Signed Results Mechanism:
	LILLYCTL_1_2_840_113549_6_0_1,
	// RFC 2696, Section 2, The Control:
	LILLYCTL_1_2_840_113556_1_4_319,
	// RFC 2891, Section 1.1, Request Control:
	LILLYCTL_1_2_840_113556_1_4_473,
	// RFC 2891, Section 1.2, Response Control:
	LILLYCTL_1_2_840_113556_1_4_474,
	// RFC 3296, Section 3, The ManageDsaIT Control:
	LILLYCTL_2_16_840_1_113730_3_4_2,
	// RFC 3672, Section 3, Subentries control:
	LILLYCTL_1_3_6_1_4_1_4203_1_10_1,
	// RFC 3829, Section 3, Authorization Identity Request Control:
	// Note: This is sort-of deprecated by RFC 4532
	LILLYCTL_2_16_840_1_113730_3_4_16,
	// RFC 3829, Section 4, Authorization Identity Response Control:
	// Note: This is sort-of deprecated by RFC 4532
	LILLYCTL_2_16_840_1_113730_3_4_15,
	// RFC 3876, Section 2, The valuesReturnFilter Control
	LILLYCTL_1_2_826_0_1_3344810_2_3,
	// RFC 3928, Section 3.6, Sync Request Control:
	LILLYCTL_1_3_6_1_1_7_1,
	// RFC 3928, Section 3.7, Sync Update Control:
	LILLYCTL_1_3_6_1_1_7_2,
	// RFC 3928, Section 3.8, Sync Done Control:
	LILLYCTL_1_3_6_1_1_7_3,
	// RFC 4370, Section 3, Proxy Authorization Control:
	LILLYCTL_2_16_840_1_113730_3_4_18,
	// RFC 4527, Section 3.1, Pre-Read Controls
	LILLYCTL_1_3_6_1_1_13_1,
	// RFC 4527, Section 3.1, Post-Read Controls
	LILLYCTL_1_3_6_1_1_13_2,
	// RFC 4528, Section 3, The Assertion Control:
	LILLYCTL_1_3_6_1_1_12,
	// RFC 4533, Section 2.2, Sync Request Control
	LILLYCTL_1_3_6_1_4_1_4203_1_9_1_1,
	// RFC 4533, Section 2.3, Sync State Control
	LILLYCTL_1_3_6_1_4_1_4203_1_9_1_2,
	// RFC 4533, Section 2.4, Sync Done Control
	LILLYCTL_1_3_6_1_4_1_4203_1_9_1_3,
	// RFC 5805, Section 2.2, Transaction Specification Control
	LILLYCTL_1_3_6_1_1_21_2,
	// RFC 6171, Section 3, The Don't Use Copy Control
	LILLYCTL_1_3_6_1_1_22,
	// End / length marker; we usually extend the table just before it
	LILLYCTL_LAST,
	// Illegal value
	LILLYCTL_ILLEGAL = -1
};


/* The lillyctl_index() function wraps a perfect hash generated with gperf.
 * It returns LILLYCTL_ILLEGAL in case the OID is not known to LillyDAP.
 */
enum lillyctl_index lillyctl_index (char *oid);


/* The lillyctl_command codes explain what should be done in a filter for
 * a control.  Note that there is only one filter, not a composition of lines.
 *
 *  - default handling for the given OID [with overridden value]
 *  - require presence [and value]
 *  - forbid presence [when it has value]
 *  - drop when present [if it has value]
 *  - add when not present, with given value
 *  - pass through when present [with given value]
 *  - replace when present, with given value
 */
enum lillyctl_command {
	LILLYCTL_DEFAULT,
	LILLYCTL_REQUIRE,
	LILLYCTL_FORBID,
	LILLYCTL_DROP,
	LILLYCTL_ADD,
	LILLYCTL_PASS,
	LILLYCTL_REPLACE
};


/* The filter applied to a control is a command with a possible argument.
 * When a callback is added, it will be applied to this information plus
 * the data at hand.  The callback works just like lillyctl_filter()
 * specified below.
 */
struct lillyctl_filter {
	enum lillyctl_command cmd;
	dercursor optarg;
	int (*callback) (enum lillyctl_command cmd,
				dercursor optatg,
				uint8_t opcode,
				dercursor inctl,
				dercursor *outctl);
};


/* The lillyctl_filter() operation is called to apply a filter to a control.
 * A new value for the control may be setup in retval, which will be cleared
 * in any but the desired case.  The returned value is -1 and errno is set
 * when an error occurs.  When called with outctl set to NULL, an error may
 * be raised if it turns out to be necessary to return a value.
 */
int lillyctl_filter (struct lillyctl_filter *todo,
				uint8_t opcode,
				dercursor inctl,
				dercursor *outctl);


/* Each lillyctl_defaults specifies settings per control:
 *
 *  - oid in the LDAPOID form
 *  - criticality indicates desired critical flag values, or a wildcard value
 *  - opcodes for which the control is appropriate
 *  - packer for the data structure
 *  - command / value / callback to use for the control when not overridden
 */
struct lillyctl_settings {
	char *oid;
	uint8_t *opcodes;
	uint8_t criticality;	/* see LILLYCTL_CRITICAL_xxx below */
	derwalk *packer;
	struct lillyctl_filter default_handler;
};

#define LILLYCTL_CRITICAL_FALSE 0
#define LILLYCTL_CRITICAL_TRUE  1
#define LILLYCTL_CRITICAL_ANY   2


/* The setup is a constant global table with settings for each control.
 */
extern const struct lillyctl_settings lillyctl_setup [LILLYCTL_LAST];


/* The data structure that can be used to setup controls by index or by name.
 * Zero initialisation does what one might expect; it specifies filters that
 * do nothing but default operations.
 */
union lillyctl_filtertab {
	struct lillyctl_filter by_index [LILLYCTL_LAST];
	struct {
		// RFC 2649, Section 1.1, Audit Trail Mechanism:
		struct lillyctl_filter oid_1_2_840_113549_6_0_0;
		// RFC 2649, Section 2, Signed Results Mechanism:
		struct lillyctl_filter oid_1_2_840_113549_6_0_1;
		// RFC 2696, Section 2, The Control:
		struct lillyctl_filter oid_1_2_840_113556_1_4_319;
		// RFC 2891, Section 1.1, Request Control:
		struct lillyctl_filter oid_1_2_840_113556_1_4_473;
		// RFC 2891, Section 1.2, Response Control:
		struct lillyctl_filter oid_1_2_840_113556_1_4_474;
		// RFC 3296, Section 3, The ManageDsaIT Control:
		struct lillyctl_filter oid_2_16_840_1_113730_3_4_2;
		// RFC 3672, Section 3, Subentries control:
		struct lillyctl_filter oid_1_3_6_1_4_1_4203_1_10_1;
		// RFC 3829, Section 3, Authorization Identity Request Control:
		// Note: This is sort-of deprecated by RFC 4532
		struct lillyctl_filter oid_2_16_840_1_113730_3_4_16;
		// RFC 3829, Section 4, Authorization Identity Response Control:
		// Note: This is sort-of deprecated by RFC 4532
		struct lillyctl_filter oid_2_16_840_1_113730_3_4_15;
		// RFC 3876, Section 2, The valuesReturnFilter Control
		struct lillyctl_filter oid_1_2_826_0_1_3344810_2_3;
		// RFC 3928, Section 3.6, Sync Request Control:
		struct lillyctl_filter oid_1_3_6_1_1_7_1;
		// RFC 3928, Section 3.7, Sync Update Control:
		struct lillyctl_filter oid_1_3_6_1_1_7_2;
		// RFC 3928, Section 3.8, Sync Done Control:
		struct lillyctl_filter oid_1_3_6_1_1_7_3;
		// RFC 4370, Section 3, Proxy Authorization Control:
		struct lillyctl_filter oid_2_16_840_1_113730_3_4_18;
		// RFC 4527, Section 3.1, Pre-Read Controls
		struct lillyctl_filter oid_1_3_6_1_1_13_1;
		// RFC 4527, Section 3.1, Post-Read Controls
		struct lillyctl_filter oid_1_3_6_1_1_13_2;
		// RFC 4528, Section 3, The Assertion Control:
		struct lillyctl_filter oid_1_3_6_1_1_12;
		// RFC 4533, Section 2.2, Sync Request Control
		struct lillyctl_filter oid_1_3_6_1_4_1_4203_1_9_1_1;
		// RFC 4533, Section 2.3, Sync State Control
		struct lillyctl_filter oid_1_3_6_1_4_1_4203_1_9_1_2;
		// RFC 4533, Section 2.4, Sync Done Control
		struct lillyctl_filter oid_1_3_6_1_4_1_4203_1_9_1_3;
		// RFC 5805, Section 2.2, Transaction Specification Control
		struct lillyctl_filter oid_1_3_6_1_1_21_2;
		// RFC 6171, Section 3, The Don't Use Copy Control
		struct lillyctl_filter oid_1_3_6_1_1_22;
	} by_oid;
	struct {
		// RFC 2649, Section 1.1, Audit Trail Mechanism:
		struct lillyctl_filter ctl_AuditTrailMechanism;
		// RFC 2649, Section 2, Signed Results Mechanism:
		struct lillyctl_filter ctl_SignedResultsMechanism;
		// RFC 2696, Section 2, The Control:
		struct lillyctl_filter PagedResults;
		// RFC 2891, Section 1.1, Request Control:
		struct lillyctl_filter ServerSideSortingRequest;
		// RFC 2891, Section 1.2, Response Control:
		struct lillyctl_filter ServerSideSortingResponse;
		// RFC 3296, Section 3, The ManageDsaIT Control:
		struct lillyctl_filter ManageDsaIT;
		// RFC 3672, Section 3, Subentries control:
		struct lillyctl_filter Subentries;
		// RFC 3829, Section 3, Authorization Identity Request Control:
		// Note: This is sort-of deprecated by RFC 4532
		struct lillyctl_filter AuthorizationIdentityRequest;
		// RFC 3829, Section 4, Authorization Identity Response Control:
		// Note: This is sort-of deprecated by RFC 4532
		struct lillyctl_filter AuthorizationIdentityResponse;
		// RFC 3876, Section 2, The valuesReturnFilter Control
		struct lillyctl_filter ValuesReturnFilter;
		// RFC 3928, Section 3.6, Sync Request Control:
		struct lillyctl_filter LCUPSyncRequest;
		// RFC 3928, Section 3.7, Sync Update Control:
		struct lillyctl_filter LCUPSyncUpdate;
		// RFC 3928, Section 3.8, Sync Done Control:
		struct lillyctl_filter LCUPSyncDone;
		// RFC 4370, Section 3, Proxy Authorization Control:
		struct lillyctl_filter ProxyAuthorization;
		// RFC 4527, Section 3.1, Pre-Read Controls
		struct lillyctl_filter PreReadRequest;
		// RFC 4527, Section 3.1, Post-Read Controls
		struct lillyctl_filter PostReadRequest;
		// RFC 4528, Section 3, The Assertion Control:
		struct lillyctl_filter Assertion;
		// RFC 4533, Section 2.2, Sync Request Control
		struct lillyctl_filter SyncReplRequest;
		// RFC 4533, Section 2.3, Sync State Control
		struct lillyctl_filter SyncReplState;
		// RFC 4533, Section 2.4, Sync Done Control
		struct lillyctl_filter SyncReplDone;
		// RFC 5805, Section 2.2, Transaction Specification Control
		struct lillyctl_filter TransactionSpecification;
		// RFC 6171, Section 3, The Don't Use Copy Control
		struct lillyctl_filter DontUseCopy;
	} by_name;
};


#ifdef __cplusplus
}
#endif

#endif /* LILLYCTL_H */
