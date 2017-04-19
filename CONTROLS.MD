# How LillyDAP handles Controls

> *Controls can make potent changes to LDAP behaviour.  Their use in most
> applications will be best done automatically, which is why LillyDAP has
> filters that can be plugged into various places of LillyDAP.*

Controls are additional OID-to-value mappings that can be sent along with
an LDAPMessage.  They can be used to indicate the willingness to interpret
certain formats or extended behaviours.

In some cases, security may be a concern.  This is at least the case with
the [Proxy Authorization Control](https://tools.ietf.org/html/rfc4370)
that should perhaps not be processed by default.  Incoming it would not
make sense unless the application supported it, and in outgoing direction
it should not be forwarded when not supported by the application.

This calls for default behaviours for each control, and the ability to
filter them at various stages of decoding.  Adding a filter does not take
much space, nor code, but it does enable flexibility in using controls.

In LillyDAP, the following functions have built-in support for controls,
which means they will look into the `LillyDAP` structure for a fixed
filter setup:

  * `lillyget_ldapmessage()` filters the controls with the first in line
    of `LillyDAP.lillyctl_recvop [opcode]`, `LillyDAP.lillyctl_recvall` and the
    built-in default incoming control filter; it will unpack controls
    through `lillyctl_unpack() specified below, inasfar as it is requested
    by the flags in `LillyDAP.control_unpack`
  * `lillyput_ldapmessage()` filters the controls with the first in line
    of `LillyDAP.lillyctl_sendop [opcode]`, `LillyDAP.lillyctl_sendall` and the
    built-in default outgoing control filter; it will repack controls
    through `lillyctl_pack()` specified below, inasfar as it is requested
    by the flags in `LillyDAP.control_unpack` &mdash; note that this is the
    same flags register as used in `lillyget_ldapmessage()`

Your own functions may perform the same operations through additional
API functions:

  * `lillyctl_filter()` applies a control filter to a `dercursor` that
    represents the `Controls`
  * `lillyctl_unpack()` and `lillyctl_pack()` will map a `dercursor`
    representing `Controls` to and from a fixed-size data structure
    that holds the control for this LDAPMessage as either `(NULL,0)`
    or as a `derarray` value pointing to the `dercursor[]` that
    unpacks the `Control` data structure known to apply to the OID;
    this behaviour will only be done for controls in
    `LillyDAP.control_unpack`, flags used in both directions; when the
    corresponding flag is 0, the entry will not be a `derarray`, but
    instead a `dercursor` set to either `(NULL,0)` when absent, or a
    standard `(ptr,len)` pair for the embedded value of the
    `controlValue`; finally, absense of the `controlValue` for a
    presented `control` is communicated as `(LILLYCTL_NOVALUE,0)`
    which may in many applications be successfully treated as an
    empty string, and in others as a separate value that must be
    distinguished; a required-absent `controlValue` is represented
    inside LillyDAP as a NULL packer reference.

Note that control filters may report a failure, for example when a required
setting is absent, or a forbidden one is presented.  This translates in a
processing error for the entire LDAPMessage.

All `Control` OIDs have a short-hand index, enumerated as `LILLYCTL_1_2_3` for
OID 1.2.3 -- and so on.  We also define aliases where possible.  We generate
an efficient mapping function from the `LDAPOID` string form of the OID to
these index values, and anything inside LillyDAP then uses these index values.
The efficient mapping function is `lillyctl_index()`.


## List of Controls

Are we missing entries?  Then please submit an
[issue](https://github.com/vanrein/lillydap/issues)
with the additional text!  We will be happy to extend the tables.

RFC 2649, Section 1.1, Audit Trail Mechanism:

    Signed directory operations is a straightforward application of
    S/MIME technology that also leverages the extensible framework that
    is provided by LDAP version 3.  LDAP version 3 is defined in [4], and
    S/MIME is defined in [2].  The security used in S/MIME is based in
    the definitions in [1].  The basic idea is that the submitter of an
    LDAP operation that changes the directory information includes an
    LDAP version 3 control that includes either a signature of the
    operation, or a request that the LDAP server sign the operation on
    the behalf of the LDAP client.  The result of the operation (in
    addition to the change of the directory information), is additional
    information that is attached to directory objects, that includes the
    audit trail of signed operations.  The LDAP control is (OID =
    1.2.840.113549.6.0.0):

       SignedOperation ::= CHOICE {
            signbyServer   NULL,
            signatureIncluded   OCTET STRING
        }

RFC 2649, Section 2, Signed Results Mechanism:

    A control is also defined that allows the LDAP v3 client to request
    that the server sign the results that it returns.  It is intended
    that this control is primarily used in concert with the LDAPSearch
    operation.  This control MAY be marked as CRITICAL.  If it is marked
    as CRITICAL and the LDAP Server supports this operation, then all
    search results MUST be returned with a signature as attached in the
    SignedResult control if it is willing to sign results for this user.
    If the server supports this control but does not wish to sign the
    results for this user then the error code unwillingToPerform(53)
    should be returned, and the LDAP search will have failed.  In this
    situation, an appropriate message (e.g. "Unwilling to sign results
    for you!") MUST be included in the errorMessage of the LDAPResult.
    If the LDAPSigType has the value FALSE then the client is requesting
    that the server not sign this operation.  This may be done in
    situations where servers are configured to always sign their
    operations.

    The LDAP control to include in the LDAP request is (OID =
    1.2.840.113549.6.0.1):

       DemandSignedResult ::=  LDAPSigType

       LDAPSigType ::= BOOLEAN

RFC 2696, Section 2, The Control:

    This control is included in the searchRequest and searchResultDone
    messages as part of the controls field of the LDAPMessage, as defined
    in Section 4.1.12 of [LDAPv3]. The structure of this control is as
    follows:

    pagedResultsControl ::= SEQUENCE {
            controlType     1.2.840.113556.1.4.319,
            criticality     BOOLEAN DEFAULT FALSE,
            controlValue    searchControlValue
    }
    
    The searchControlValue is an OCTET STRING wrapping the BER-encoded
    version of the following SEQUENCE:
    
    realSearchControlValue ::= SEQUENCE {
            size            INTEGER (0..maxInt),
                                    -- requested page size from client
                                    -- result set size estimate from server
            cookie          OCTET STRING
    }


RFC 2891, Section 1.1, Request Control:

    This control is included in the searchRequest message as part of the
    controls field of the LDAPMessage, as defined in Section 4.1.12 of
    [LDAPv3].

    The controlType is set to "1.2.840.113556.1.4.473". The criticality
    MAY be either TRUE or FALSE (where absent is also equivalent to
    FALSE) at the client's option. The controlValue is an OCTET STRING,
    whose value is the BER encoding of a value of the following SEQUENCE:

       SortKeyList ::= SEQUENCE OF SEQUENCE {
                  attributeType   AttributeDescription,
                  orderingRule    [0] MatchingRuleId OPTIONAL,
                  reverseOrder    [1] BOOLEAN DEFAULT FALSE }

RFC 2891, Section 1.2, Response Control:

    This control is included in the searchResultDone message as part of
    the controls field of the LDAPMessage, as defined in Section  4.1.12
    of [LDAPv3].

    The controlType is set to "1.2.840.113556.1.4.474". The criticality
    is FALSE (MAY be absent). The controlValue is an OCTET STRING, whose
    value is the BER encoding of a value of the following SEQUENCE:

       SortResult ::= SEQUENCE {
          sortResult  ENUMERATED {
              success                   (0), -- results are sorted
              operationsError           (1), -- server internal failure
              timeLimitExceeded         (3), -- timelimit reached before
                                             -- sorting was completed
              strongAuthRequired        (8), -- refused to return sorted
                                             -- results via insecure
                                             -- protocol
              adminLimitExceeded       (11), -- too many matching entries
                                             -- for the server to sort
              noSuchAttribute          (16), -- unrecognized attribute
                                             -- type in sort key
              inappropriateMatching    (18), -- unrecognized or
                                             -- inappropriate matching
                                             -- rule in sort key
              insufficientAccessRights (50), -- refused to return sorted
                                             -- results to this client
              busy                     (51), -- too busy to process
              unwillingToPerform       (53), -- unable to sort
              other                    (80)
              },
        attributeType [0] AttributeDescription OPTIONAL }

RFC 3296, Section 3, The ManageDsaIT Control:

    A client MAY specify the following control when issuing an add,
    compare, delete, modify, modifyDN, search request or an extended
    operation for which the control is defined.

    The control type is 2.16.840.1.113730.3.4.2.  The control criticality
    may be TRUE or, if FALSE, absent.  The control value is absent.

RFC 3672, Section 3, Subentries control:

    The subentries control MAY be sent with a searchRequest to control
    the visibility of entries and subentries which are within scope.
    Non-visible entries or subentries are not returned in response to the
    request.

    The subentries control is an LDAP Control whose controlType is
    1.3.6.1.4.1.4203.1.10.1, criticality is TRUE or FALSE (hence absent),
    and controlValue contains a BER-encoded BOOLEAN indicating
    visibility.  A controlValue containing the value TRUE indicates that
    subentries are visible and normal entries are not.  A controlValue
    containing the value FALSE indicates that normal entries are visible
    and subentries are not.

    Note that TRUE visibility has the three octet encoding { 01 01 FF }
    and FALSE visibility has the three octet encoding { 01 01 00 }.

    The controlValue SHALL NOT be absent.

RFC 3829, Section 3, Authorization Identity Request Control:

    This control MAY be included in any bind request which specifies
    protocol version 3, as part of the controls field of the LDAPMessage
    as defined in [LDAPPROT].  In a multi-step bind operation, the client
    MUST provide the control with each bind request.

    The controlType is "2.16.840.1.113730.3.4.16" and the controlValue is
    absent.

    Do however note RFC 4532, which says:
    -------------------------------------

    This specification is intended to replace the existing Authorization
    Identity Controls [RFC3829] mechanism, which uses Bind request and
    response controls to request and return the authorization identity.
    Bind controls are not protected by security layers established by the
    Bind operation that includes them.

RFC 3829, Section 4, Authorization Identity Response Control:

    This control MAY be included in any final bind response where the
    first bind request of the bind operation included an Authorization
    Identity Request Control as part of the controls field of the
    LDAPMessage as defined in [LDAPPROT].

    The controlType is "2.16.840.1.113730.3.4.15".  If the bind request
    succeeded and resulted in an identity (not anonymous), the
    controlValue contains the authorization identity (authzId), as
    defined in [AUTH] section 9, granted to the requestor.  If the bind
    request resulted in an anonymous association, the controlValue field
    is a string of zero length.  If the bind request resulted in more
    than one authzId, the primary authzId is returned in the controlValue
    field.

    Do however note RFC 4532, which says:
    -------------------------------------

    This specification is intended to replace the existing Authorization
    Identity Controls [RFC3829] mechanism, which uses Bind request and
    response controls to request and return the authorization identity.
    Bind controls are not protected by security layers established by the
    Bind operation that includes them.

RFC 3876, Section 2, The valuesReturnFilter Control

    The valuesReturnFilter control is either critical or non-critical as
    determined by the user.  It only has meaning for the Search
    operation, and SHOULD only be added to the Search operation by the
    client.  If the server supports the control and it is present on a
    Search operation, the server MUST obey the control, regardless of the
    value of the criticality flag.

   The object identifier for this control is 1.2.826.0.1.3344810.2.3.

    The controlValue is an OCTET STRING, whose value is the BER encoding
    [6], as per Section 5.1 of RFC 2251 [2], of a value of the ASN.1 [5]
    type ValuesReturnFilter.

            ValuesReturnFilter ::= SEQUENCE OF SimpleFilterItem

            SimpleFilterItem ::= CHOICE {
                    equalityMatch   [3] AttributeValueAssertion,
                    substrings      [4] SubstringFilter,
                    greaterOrEqual  [5] AttributeValueAssertion,
                    lessOrEqual     [6] AttributeValueAssertion,
                    present         [7] AttributeDescription,
                    approxMatch     [8] AttributeValueAssertion,
                    extensibleMatch [9] SimpleMatchingAssertion }

             SimpleMatchingAssertion ::= SEQUENCE {
                    matchingRule    [1] MatchingRuleId OPTIONAL,
                    type            [2] AttributeDescription OPTIONAL,
    --- at least one of the above must be present
                    matchValue      [3] AssertionValue}

RFC 3928, Section 3.6, Sync Request Control:

    The Sync Request Control is an LDAP Control [RFC2251, Section 4.1.2]
    where the controlType is the object identifier 1.3.6.1.1.7.1 and the
    controlValue, an OCTET STRING, contains a BER-encoded
    syncRequestControlValue.

       syncRequestControlValue ::= SEQUENCE {
          updateType           ENUMERATED {
                                  syncOnly       (0),
                                  syncAndPersist (1),
                                  persistOnly    (2) },
          sendCookieInterval   [0] INTEGER    OPTIONAL,
          scheme               [1] LCUPScheme OPTIONAL,
          cookie               [2] LCUPCookie OPTIONAL
         }

    The Sync Request Control is only applicable to the searchRequest
    message.  Use of this control is described below.

RFC 3928, Section 3.7, Sync Update Control:

    The Sync Update Control is an LDAP Control [RFC2251, Section 4.1.2]
    where the controlType is the object identifier 1.3.6.1.1.7.2 and the
    controlValue, an OCTET STRING, contains a BER-encoded
    syncUpdateControlValue.

       syncUpdateControlValue ::= SEQUENCE {
          stateUpdate   BOOLEAN,
          entryUUID     [0] LCUPUUID OPTIONAL, -- REQUIRED for entries --
          UUIDAttribute [1] AttributeType OPTIONAL,
          entryLeftSet  [2] BOOLEAN,
          persistPhase  [3] BOOLEAN,
          scheme        [4] LCUPScheme OPTIONAL,
          cookie        [5] LCUPCookie OPTIONAL
       }

    The Sync Update Control is only applicable to SearchResultEntry and
    SearchResultReference messages.  Although entryUUID is OPTIONAL, it
    MUST be used with SearchResultEntry messages.  Use of this control is
    described below.

RFC 3928, Section 3.8, Sync Done Control:

    The Sync Done Control is an LDAP Control [RFC2251, Section 4.1.2]
    where the controlType is the object identifier 1.3.6.1.1.7.3 and the
    controlValue contains a BER-encoded syncDoneValue.

       syncDoneValue ::= SEQUENCE {
          scheme      [0] LCUPScheme OPTIONAL,
          cookie      [1] LCUPCookie OPTIONAL
       }

    The Sync Done Control is only applicable to SearchResultDone message.
    Use of this control is described below.

RFC 4370, Section 3, Proxy Authorization Control:

    The controlType of the proxy authorization control is
    "2.16.840.1.113730.3.4.18".

    The criticality MUST be present and MUST be TRUE.  This requirement
    protects clients from submitting a request that is executed with an
    unintended authorization identity.

    Clients MUST include the criticality flag and MUST set it to TRUE.
    Servers MUST reject any request containing a Proxy Authorization
    Control without a criticality flag or with the flag set to FALSE with
    a protocolError error.  These requirements protect clients from
    submitting a request that is executed with an unintended
    authorization identity.

    The controlValue SHALL be present and SHALL either contain an authzId
    [AUTH] representing the authorization identity for the request or be
    empty if an anonymous association is to be used.

    (no limitation to opcodes)

RFC 4527, Section 3.1, Pre-Read Controls

    The Pre-Read request control is a LDAP Control [RFC4511] whose
    controlType is 1.3.6.1.1.13.1 and whose controlValue is a BER-encoded
    AttributeSelection [RFC4511], as extended by [RFC3673].  The
    criticality may be TRUE or FALSE.  This control is appropriate for
    the modifyRequest, delRequest, and modDNRequest LDAP messages.

    The corresponding response control is a LDAP Control whose
    controlType is 1.3.6.1.1.13.1 and whose the controlValue, an OCTET
    STRING, contains a BER-encoded SearchResultEntry.  The criticality
    may be TRUE or FALSE.  This control is appropriate for the
    modifyResponse, delResponse, and modDNResponse LDAP messages with a
    resultCode of success (0).

RFC 4527, Section 3.1, Post-Read Controls

    The Post-Read request control is a LDAP Control [RFC4511] whose
    controlType is 1.3.6.1.1.13.2 and whose controlValue, an OCTET
    STRING, contains a BER-encoded AttributeSelection [RFC4511], as
    extended by [RFC3673].  The criticality may be TRUE or FALSE.  This
    control is appropriate for the addRequest, modifyRequest, and
    modDNRequest LDAP messages.

    The corresponding response control is a LDAP Control whose
    controlType is 1.3.6.1.1.13.2 and whose controlValue is a BER-encoded
    SearchResultEntry.  The criticality may be TRUE or FALSE.  This
    control is appropriate for the addResponse, modifyResponse, and
    modDNResponse LDAP messages with a resultCode of success (0).

RFC 4528, Section 3, The Assertion Control:

    The assertion control is an LDAP Control [RFC4511] whose controlType
    is 1.3.6.1.1.12 and whose controlValue is a BER-encoded Filter
    [Protocol, Section 4.5.1].  The criticality may be TRUE or FALSE.
    There is no corresponding response control.

    The control is appropriate for both LDAP interrogation and update
    operations [RFC4511], including Add, Compare, Delete, Modify,
    ModifyDN (rename), and Search.  It is inappropriate for Abandon,
    Bind, Unbind, and StartTLS operations.

RFC 4533, Section 2.2, Sync Request Control

    The Sync Request Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.1 and the
    controlValue, an OCTET STRING, contains a BER-encoded
    syncRequestValue.  The criticality field is either TRUE or FALSE.

       syncRequestValue ::= SEQUENCE {
           mode ENUMERATED {
               -- 0 unused
               refreshOnly       (1),
               -- 2 reserved
               refreshAndPersist (3)
           },
           cookie     syncCookie OPTIONAL,
           reloadHint BOOLEAN DEFAULT FALSE
       }

    The Sync Request Control is only applicable to the SearchRequest
    Message.

RFC 4533, Section 2.3, Sync State Control

    The Sync State Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.2 and the
    controlValue, an OCTET STRING, contains a BER-encoded syncStateValue.
    The criticality is FALSE.

       syncStateValue ::= SEQUENCE {
           state ENUMERATED {
               present (0),
               add (1),
               modify (2),
               delete (3)
           },
           entryUUID syncUUID,
           cookie    syncCookie OPTIONAL
       }

    The Sync State Control is only applicable to SearchResultEntry and
    SearchResultReference Messages.


RFC 4533, Section 2.4, Sync Done Control

    The Sync Done Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.3 and the
    controlValue contains a BER-encoded syncDoneValue.  The criticality
    is FALSE (and hence absent).

       syncDoneValue ::= SEQUENCE {
           cookie          syncCookie OPTIONAL,
           refreshDeletes  BOOLEAN DEFAULT FALSE
       }

    The Sync Done Control is only applicable to the SearchResultDone
    Message.

RFC 5805, Section 2.2, Transaction Specification Control

    A Transaction Specification Control is an LDAPControl where the
    controlType is 1.3.6.1.1.21.2, the criticality is TRUE, and the
    controlValue is a transaction identifier.  The control is appropriate
    for update requests including Add, Delete, Modify, and ModifyDN
    (Rename) requests [RFC4511], as well as the Password Modify requests
    [RFC3062].

RFC 6171, Section 3, The Don't Use Copy Control

    The Don't Use Copy control is an LDAP Control [RFC4511] whose
    controlType is 1.3.6.1.1.22 and controlValue is absent.  The
    criticality MUST be TRUE.  There is no corresponding response
    control.

    (no limitation to opcodes)

