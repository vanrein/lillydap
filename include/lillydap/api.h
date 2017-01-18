/* lillydap.h -- LDAP library with client calls and server callbacks.
 *
 * LillyDAP is a library that supports dynamic data providers for LDAP,
 * in a similar fashion to what FastCGI or WSGI scripts do for HTTP.
 *
 * Combined with the powerful semantics of LDAP, this yields a very
 * potent platform for a great variety of data tools -- tools that need
 * to do an incredible amount of ground work when based on HTTP, REST
 * and XML and/or JSON.
 *
 * This include file is compatible with the standard API in RFC 1823.
 * In addition, it defines registration mechanisms for callback functions
 * that implement these same functions.  Finally, in the interest of
 * efficiency, it is possible to request parsing certain structures.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#ifndef LILLYDAP_H
#define LILLYDAP_H


#include <stdlib.h>
#include <stdint.h>

#include <lillydap/mem.h>

#include <quick-der/api.h>
#include <quick-der/rfc3062.h>
#include <quick-der/rfc3909.h>
#include <quick-der/rfc4373.h>
#include <quick-der/rfc4511.h>
#include <quick-der/rfc4531.h>
#include <quick-der/rfc5805.h>


/* The LillyConnection structure, also known as LDAP, describes an endpoint for
 * LDAP communication; pretty much a protocol-specific socket.  It details how
 * operations are processed and redirected, in both directions: lillyget_xxx()
 * for operations from network to this program, and lillyput_xxx() for
 * operations from this program to the network.  Note that the network may in
 * reality be short-circuited for more direct connections to other endpoints.
 *
 * Typedef aliases for struct LillyConnection are LDAP and LillyDAP.
 */
struct LillyConnection {
	//
	// Node data for this LillyDAP endpoint
	// RFC 1823 is denoted as 1.0
	uint16_t v_major, v_minor;
	uint16_t flags;
	uint16_t reserverd_flags;
	uint32_t reject_ops [2];
	struct LillyDef *def;
	struct LillyConn *rev;
	struct LillyConn *fwd;
	//
	// Connection description
	int get_fd;
	int put_fd;
	LillyPool get_qpool;
	size_t get_gotten;
	uint8_t get_head6 [6];	//TODO// overlay get_msg
	dercursor get_msg;
	struct LillySend *put_queue;
	//
	// Memory management for the connection and messages
	LillyPool cnxpool;
	struct LillyMsgLayer *msghash;
	//
	// API Layer: Receiving an LDAPMessage
	/// TODO //
	//
	// API Layer: Receive a union of parsed LDAPMessage structures
	// TODO //
	//
	// API Layer: Receive a per-operation callback based on a regitstry
	const union LillyOpRegistry *opregistry;
	int (*lillyget_switch) ();  //TODO//TYPING
	//
	// API Layer: The callback variant of the standard API for C
	// TODO //
	//
	int (*lillyget_dercursor) ();	//TODO//TYPING//MOVE_TO_STATIC
	int (*lillyget_ldapmessage) ();	//TODO//TYPING//MOVE_TO_STATIC
	int (*lillyget_operation) ();	//TODO//TYPING//MOVE_TO_STATIC
	int (*lillyput_operation) ();	//TODO//TYPING//MOVE_TO_STATIC
	int (*lillyput_dercursor) ();	//TODO//TYPING//MOVE_TO_STATIC
	// Functions to implement the standard API
	// (RFC-compatible wrappers are defined below)
	struct LillyFun *fun;
	//
	// Standard fields according to RFC 1823
	int ld_deref;
	int ld_timelimit;
	int ld_sizelimit;
	int ld_errno;
	char *ld_matched;
	char *ld_error;
};
typedef struct LillyConnection LDAP;
typedef struct LillyConnection LillyDAP;


/* Functions lillyget_xxx() represent the flow of operations from the network
 * to the program.
 */
ssize_t lillyget_event (LDAP *lil);
int lillyget_dercursor (LDAP *lil, LillyPool *qpool_opt, dercursor msg);
int lillyget_ldapmessage (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const dercursor op,
				const dercursor controls);
int lillyget_operation (LDAP *lil,
				LillyPool qpool,
				const LillyMsgId msgid,
				const int opcode,
				const dercursor *data,
				const dercursor controls);


/* Functions lillyput_xxx() represent the flow of operations from the program
 * to the network.
 */
int lillyput_operation (LDAP *lil,
				const LillyPool qpool,
				const LillyMsgId msgid,
				const uint8_t opcode,
				const dercursor *data,
				const dercursor controls);
int lillyput_dercursor (LDAP *lil, const dercursor dermsg);  //TODO//
void lillyput_enqueue (LillyDAP *lil, struct LillySend *addend);
bool lillyput_cansend (LillyDAP *lil);
int lillyput_event (LDAP *lil);


/* A parallel to ldap_open, filling the basic structure and returning
 * non-zero on success.  Set portno to LILLYDAP_NO_PORT to interpret
 * the hostname as a LillyDAP node name.
 */
#define LILLYDAP_NO_PORT 131072
int lillydap_open (LDAP *ld, size_t ld_sz, char *hostname, int portno);

static inline LDAP *ldap_open (char *h, int p) {
	LDAP *rv;
	int ok;
	rv = malloc (sizeof (LDAP));
	if (rv != NULL) {
		ok = lillydap_open (rv, sizeof (LDAP), h, p);
		if (!ok) {
			free (rv);
			rv = NULL;
		}
	}
	return rv;
}


/* Parallels to ldap_bind, ldap_simple_bind and ldap_kerberos_bind.
 * Synchronous versions are not part of LillyDAP, as they can easily
 * be implemented in terms of asynchronous ones.
 */
int lillydap_bind          (LDAP *ld, char *dn, char *cred, int mth);
int lillydap_simple_bind   (LDAP *ld, char *dn, char *cred, char *pw);
int lillydap_kerberos_bind (LDAP *ld, char *dn);


/* Flags that indicate rejection for certain requests or responses for
 * lillyget_xxx() so for incoming packets.  Note that responeses are
 * accepted by default!  The reasoning being that usually there will
 * be an opregistry that already filters out unsupported routines.
 * These flags are additionally useful, by permitting more dynamicity.
 *
 * There may be a need for multiple 32-bit words to store all the
 * flags.  The basic operations go in the first word and are prefixed
 * with LILLYGETR_, the extended operations for now fit into the second
 * word and are prefixed with LILLYGETR0_
 */

#define LILLYGETR_BIND_REQ			(1UL <<  0)
#define LILLYGETR_BIND_RESP			(1UL <<  1)
#define LILLYGETR_UNBIND_REQ			(1UL <<  2)
#define LILLYGETR_SEARCH_REQ			(1UL <<  3)
#define LILLYGETR_SEARCHRESULT_ENTRY		(1UL <<  4)
#define LILLYGETR_SEARCHRESULT_DONE		(1UL <<  5)
#define LILLYGETR_MODIFY_REQ			(1UL <<  6)
#define LILLYGETR_MODIFY_RESP			(1UL <<  7)
#define LILLYGETR_ADD_REQ			(1UL <<  8)
#define LILLYGETR_ADD_RESP			(1UL <<  9)
#define LILLYGETR_DEL_REQ			(1UL << 10)
#define LILLYGETR_DEL_RESP			(1UL << 11)
#define LILLYGETR_MODIFYDN_REQ			(1UL << 12)
#define LILLYGETR_MODIFYDN_RESP			(1UL << 13)
#define LILLYGETR_COMPARE_REQ			(1UL << 14)
#define LILLYGETR_COMPARE_RESP			(1UL << 15)
#define LILLYGETR_ABANDON_REQ			(1UL << 16)
#define LILLYGETR_SEARCHRESULT_REFERENCE	(1UL << 19)
#define LILLYGETR_EXTENDED_REQ			(1UL << 23)
#define LILLYGETR_EXTENDED_RESP			(1UL << 24)
#define LILLYGETR_INTERMEDIATE_RESP		(1UL << 25)

#define LILLYGETR0_STARTTLS_REQ			(1UL << 0)
#define LILLYGETR0_STARTTLS_RESP		(1UL << 1)
#define LILLYGETR0_PASSWDMODIFY_REQ		(1UL << 2)
#define LILLYGETR0_PASSWDMODIFY_RESP		(1UL << 3)
#define LILLYGETR0_WHOAMI_REQ			(1UL << 4)
#define LILLYGETR0_WHOAMI_RESP			(1UL << 5)
#define LILLYGETR0_CANCEL_REQ			(1UL << 6)
#define LILLYGETR0_CANCEL_RESP			(1UL << 7)
#define LILLYGETR0_STARTLBURP_REQ		(1UL << 8)
#define LILLYGETR0_STARTLBURP_RESP		(1UL << 9)
#define LILLYGETR0_ENDLBURP_REQ			(1UL << 10)
#define LILLYGETR0_ENDLBURP_RESP		(1UL << 11)
#define LILLYGETR0_LBURPUPDATE_REQ		(1UL << 12)
#define LILLYGETR0_LBURPUPDATE_RESP		(1UL << 13)
#define LILLYGETR0_TURN_REQ			(1UL << 14)
#define LILLYGETR0_TURN_RESP			(1UL << 15)
#define LILLYGETR0_STARTTXN_REQ			(1UL << 16)
#define LILLYGETR0_STARTTXN_RESP		(1UL << 17)
#define LILLYGETR0_ENDTXN_REQ			(1UL << 18)
#define LILLYGETR0_ENDTXN_RESP			(1UL << 19)
#define LILLYGETR0_ABORTEDTXN_RESP		(1UL << 20)


/* All responses caused by reading; includes StartTLS and Cancel.
 */
#define LILLYGETR_READER_RESP ( \
			LILLYGETR_BIND_RESP | \
			LILLYGETR_SEARCHRESULT_ENTRY | \
			LILLYGETR_SEARCHRESULT_DONE | \
			LILLYGETR_SEARCHRESULT_REFERENCE | \
			LILLYGETR_COMPARE_RESP | \
			LILLYGETR_INTERMEDIATE_RESP | \
			LILLYGETR_EXTENDED_RESP )
#define LILLYGETR0_READER_RESP ( \
			LILLYGETR0_STARTTLS_RESP | \
			LILLYGETR0_CANCEL_RESP )

/* All responses caused by writing; includes StartTLS and Cancel.
 */
#define LILLYGETR_WRITER_RESP ( \
			LILLYGETR_BIND_RESP | \
			LILLYGETR_MODIFY_RESP | \
			LILLYGETR_ADD_RESP | \
			LILLYGETR_DEL_RESP | \
			LILLYGETR_MODIFYDN_RESP | \
			LILLYGETR_INTERMEDIATE_RESP | \
			LILLYGETR_EXTENDED_RESP )
#define LILLYGETR0_WRITER_RESP ( \
			LILLYGETR0_STARTTLS_RESP | \
			LILLYGETR0_CANCEL_RESP )

/* All responses known to LDAP.
 */
#define LILLYGETR_ALL_RESP ( \
			LILLYGETR_READER_RESP | \
			LILLYGETR_WRITER_RESP )
#define LILLYGETR0_ALL_RESP ( \
			LILLYGETR0_READER_RESP | \
			LILLYGETR0_WRITER_RESP | \
			LILLYGETR0_PASSWDMODIFY_RESP | \
			LILLYGETR0_WHOAMI_RESP | \
			LILLYGETR0_STARTLBURP_RESP | \
			LILLYGETR0_ENDLBURP_RESP | \
			LILLYGETR0_LBURPUPDATE_RESP | \
			LILLYGETR0_TURN_RESP | \
			LILLYGETR0_ENDTXN_RESP | \
			LILLYGETR0_ABORTEDTXN_RESP )

/* All requests involved in reading; includes StartTLS and Cancel.
 */
#define LILLYGETR_READER_REQ ( \
			LILLYGETR_BIND_REQ | \
			LILLYGETR_UNBIND_REQ | \
			LILLYGETR_ABANDON_REQ | \
			LILLYGETR_SEARCH_REQ | \
			LILLYGETR_COMPARE_REQ | \
			LILLYGETR_EXTENDED_REQ )
#define LILLYGETR0_READER_REQ ( \
			LILLYGETR0_STARTTLS_REQ | \
			LILLYGETR0_CANCEL_REQ )

/* All requests involved in writing; includes Extended for StartTLS and Cancel.
 */
#define LILLYGETR_WRITER_REQ ( \
			LILLYGETR_BIND_REQ | \
			LILLYGETR_UNBIND_REQ | \
			LILLYGETR_ABANDON_REQ | \
			LILLYGETR_MODIFY_REQ | \
			LILLYGETR_ADD_REQ | \
			LILLYGETR_DEL_REQ | \
			LILLYGETR_MODIFYDN_REQ | \
			LILLYGETR_EXTENDED_REQ )
#define LILLYGETR0_WRITER_REQ ( \
			LILLYGETR0_STARTTLS_REQ | \
			LILLYGETR0_CANCEL_REQ )

/* All requests known by LDAP.
 */
#define LILLYGETR_ALL_REQ ( \
			LILLYGETR_READER_REQ | \
			LILLYGETR_WRITER_REQ )
#define LILLYGETR0_ALL_REQ ( \
			LILLYGETR0_READER_REQ | \
			LILLYGETR0_WRITER_REQ | \
			LILLYGETR0_PASSWDMODIFY_REQ | \
			LILLYGETR0_WHOAMI_REQ | \
			LILLYGETR0_STARTLBURP_REQ | \
			LILLYGETR0_ENDLBURP_REQ | \
			LILLYGETR0_LBURPUPDATE_REQ | \
			LILLYGETR0_TURN_REQ | \
			LILLYGETR0_ENDTXN_REQ )


/* We now define pleasing overlay names, matching the structure names in
 * the RFCs prefixed with LillyPack_, for example LillyPack_AddRequest.
 *
 * Since parsing of extensions is done in two stages (first find the OID
 * and then reparse the extension with included data field) there can be
 * one overlay to capture the completely parsed extended structure; as a
 * result, the user handles a single overlay holding it all.  And all this
 * comes courtesy of static definitions, so it is really compact.
 */

#define mko(spec,symbol,name) \
	typedef DER_OVLY_##spec##_##symbol LillyPack_##name
#define mkoeq(name) \
	typedef DER_OVLY_rfc4511_ExtendedRequest LillyPack_##name
#define mkoer(name) \
	typedef DER_OVLY_rfc4511_ExtendedResponse LillyPack_##name
#define mkxq(spec,symbol,name) \
	typedef struct { \
		DER_OVLY_rfc4511_LDAPOID requestName; \
		DER_OVLY_##spec##_##symbol requestValue; \
	} LillyPack_##name
#define mkxr(spec,symbol,name) \
	typedef struct { \
		dercursor resultCode; /* ENUMERATED */ \
		DER_OVLY_rfc4511_LDAPDN matchedDN; \
		DER_OVLY_rfc4511_LDAPString diagnosticMessage; \
		DER_OVLY_rfc4511_Referral; \
		DER_OVLY_rfc4511_LDAPOID responseName; \
		DER_OVLY_##spec##_##symbol responseValue; \
	} LillyPack_##name

// RFC 3062 operations
mko (rfc3062, PasswdModifyRequestValue,PasswdModifyRequest);
mko (rfc3062, PasswdModifyResponseValue,PasswdModifyResponse);

// RFC 3909 operations
mko (rfc3909, CancelRequestValue,CancelRequest);
mkoer (CancelResponse);

// RFC 4373 operations
mko (rfc4373, StartLBURPRequestValue, StartLBURPRequest);
mko (rfc4373, StartLBURPResponseValue, StartLBURPResponse);
mko (rfc4373, EndLBURPRequestValue, EndLBURPRequest);
mkoer (EndLBURPResponse);
mko (rfc4373, LBURPUpdateRequestValue, LBURPUpdateRequest);
mkoer (LBURPUpdateResponse);

// RFC 4511 operations
mko (rfc4511, BindRequest, BindRequest);
mko (rfc4511, BindResponse, BindResponse);
mko (rfc4511, UnbindRequest, UnbindRequest);
mko (rfc4511, SearchRequest, SearchRequest);
mko (rfc4511, SearchResultEntry, SearchResultEntry);
mko (rfc4511, SearchResultDone, SearchResultDone);
mko (rfc4511, ModifyRequest, ModifyRequest);
mko (rfc4511, ModifyResponse, ModifyResponse);
mko (rfc4511, AddRequest, AddRequest);
mko (rfc4511, AddResponse, AddResponse);
mko (rfc4511, DelRequest, DelRequest);
mko (rfc4511, DelResponse, DelResponse);
mko (rfc4511, ModifyDNRequest, ModifyDNRequest);
mko (rfc4511, ModifyDNResponse, ModifyDNResponse);
mko (rfc4511, CompareRequest, CompareRequest);
mko (rfc4511, CompareResponse, CompareResponse);
mko (rfc4511, AbandonRequest, AbandonRequest);
mko (rfc4511, SearchResultReference, SearchResultReference);
mko (rfc4511, ExtendedRequest, ExtendedRequest);
mko (rfc4511, ExtendedResponse, ExtendedResponse);
mko (rfc4511, IntermediateResponse, IntermediateResponse);
mkoeq (StartTLSRequest);
mkoer (StartTLSResponse);

// RFC 4531 operations
mko (rfc4531, TurnValue, TurnRequest);
mkoer (TurnResponse);

// RFC 5805 operations
mko (rfc5805, TxnEndReq, TxnEndRequest);
mko (rfc5805, TxnEndRes, TxnEndResponse);


/* Callback operation support.  We assume a table, indexed by opcode,
 * for each of the recognised operations.  In addition, we define
 * a structure that can overlay such a table.  We combine them in a
 * union structure.
 *
 * It would be a useful build-time test that the union has the same
 * size as OPCODE_EXT_UNDEF * sizeof (LillyGenericOpcode).
 */
#define nmdop(nm) int (*nm) (LDAP *lil, \
                                LillyPool qpool, \
                                const LillyMsgId msgid, \
                                const LillyPack_##nm *data, \
                                const dercursor controls)
#define nmdov(nm) int (*nm) (LDAP *lil, \
                                LillyPool qpool, \
                                const LillyMsgId msgid, \
                                const void *null_data, \
                                const dercursor controls)
#define nonop(nr) void *nullop_##nr
typedef int (*LillyGenericOpcode) (LDAP *lil,
                                LillyPool qpool,
                                const LillyMsgId msgid,
                                const dercursor *data,
                                const dercursor controls);
typedef union LillyOpRegistry {
	LillyGenericOpcode by_opcode [1];
	struct LillyCallbacks {
		nmdop (BindRequest);
		nmdop (BindResponse);
		nmdop (UnbindRequest);
		nmdop (SearchRequest);
		nmdop (SearchResultEntry);
		nmdop (SearchResultDone);
		nmdop (ModifyRequest);
		nmdop (ModifyResponse);
		nmdop (AddRequest);
		nmdop (AddResponse);
		nmdop (DelRequest);
		nmdop (DelResponse);
		nmdop (ModifyDNRequest);
		nmdop (ModifyDNResponse);
		nmdop (CompareRequest);
		nmdop (CompareResponse);
		nmdop (AbandonRequest);
		nonop (17);
		nonop (18);
		nmdop (SearchResultReference);
		nonop (20);
		nonop (21);
		nonop (22);
		nonop (23);  /* No use for nmdop(ExtendedRequest)  */
		nonop (24);  /* No use for nmdop(ExtendedResponse) */
		nmdop (IntermediateResponse);
		nonop (26);
		nonop (27);
		nonop (28);
		nonop (29);
		nonop (30);
		nonop (31);
		nmdop (StartTLSRequest);
		nmdop (StartTLSResponse);
		nmdop (PasswdModifyRequest);
		nmdop (PasswdModifyResponse);
		nmdov (WhoamiRequest);
		nmdov (WhoamiResponse);
		nmdop (CancelRequest);
		nmdov (CancelResponse);
		nmdop (StartLBURPRequest);
		nmdop (StartLBURPResponse);
		nmdop (EndLBURPRequest);
		nmdov (EndLBURPResponse);
		nmdop (LBURPUpdateRequest);
		nmdov (LBURPUpdateResponse);
		nmdop (TurnRequest);
		nmdov (TurnResponse);
		nmdov (TxnStartRequest);
		nmdov (TxnStartResponse);
		nmdop (TxnEndRequest);
		nmdop (TxnEndResponse);
		nmdov (TxnAbortedNotice);
	} by_name;
} LillyOpRegistry;

#endif /* LILLYDAP_H */
