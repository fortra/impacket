# Copyright (c) 2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Authors: Alberto Solino (@agsolino)
#          Kacper Nowak (@kacpern)
#
# Description:
#   RFC 4511 Minimalistic implementation. We don't need much functionality yet
#   If we need more complex use cases we might opt to use a third party implementation
#   Keep in mind the APIs are still unstable, might require to re-write your scripts
#   as we change them.
#   Adding [MS-ADTS] specific functionality
#

from pyasn1.codec.ber import encoder, decoder
from pyasn1.type import univ, namedtype, namedval, tag, constraint

__all__ = [
    # constants
    'RESULT_SUCCESS', 'RESULT_OPERATIONSERROR', 'RESULT_PROTOCOLERROR', 'RESULT_TIMELIMITEXCEEDED',
    'RESULT_SIZELIMITEXCEEDED', 'RESULT_COMPAREFALSE', 'RESULT_COMPARETRUE', 'RESULT_AUTHMETHODNOTSUPPORTED',
    'RESULT_STRONGERAUTHREQUIRED', 'RESULT_REFERRAL', 'RESULT_ADMINLIMITEXCEEDED',
    'RESULT_UNAVAILABLECRITICALEXTENSION', 'RESULT_CONFIDENTIALITYREQUIRED', 'RESULT_SASLBINDINPROGRESS',
    'RESULT_NOSUCHATTRIBUTE', 'RESULT_UNDEFINEDATTRIBUTETYPE', 'RESULT_INAPPROPRIATEMATCHING',
    'RESULT_CONSTRAINTVIOLATION', 'RESULT_ATTRIBUTEORVALUEEXISTS', 'RESULT_INVALIDATTRIBUTESYNTAX',
    'RESULT_NOSUCHOBJECT', 'RESULT_ALIASPROBLEM', 'RESULT_INVALIDDNSYNTAX', 'RESULT_ALIASDEREFERENCINGPROBLEM',
    'RESULT_INAPPROPRIATEAUTHENTICATION', 'RESULT_INVALIDCREDENTIALS', 'RESULT_INSUFFICIENTACCESSRIGHTS',
    'RESULT_BUSY', 'RESULT_UNAVAILABLE', 'RESULT_UNWILLINGTOPERFORM', 'RESULT_LOOPDETECT', 'RESULT_NAMINGVIOLATION',
    'RESULT_OBJECTCLASSVIOLATION', 'RESULT_NOTALLOWEDONNONLEAF', 'RESULT_NOTALLOWEDONRDN', 'RESULT_ENTRYALREADYEXISTS',
    'RESULT_OBJECTCLASSMODSPROHIBITED', 'RESULT_AFFECTSMULTIPLEDSAS', 'RESULT_OTHER', 'SCOPE_BASE', 'SCOPE_ONE',
    'SCOPE_SUB', 'DEREF_NEVER', 'DEREF_SEARCH', 'DEREF_FIND', 'DEREF_ALWAYS', 'OPERATION_ADD', 'OPERATION_DELETE',
    'OPERATION_REPLACE', 'CONTROL_PAGEDRESULTS', 'KNOWN_CONTROLS', 'NOTIFICATION_DISCONNECT', 'KNOWN_NOTIFICATIONS',
    # classes
    'ResultCode', 'Scope', 'DerefAliases', 'Operation', 'MessageID', 'LDAPString', 'LDAPOID', 'LDAPDN',
    'RelativeLDAPDN', 'AttributeDescription', 'AttributeValue', 'AssertionValue', 'MatchingRuleID', 'URI',
    'AttributeValueAssertion', 'PartialAttribute', 'PartialAttributeList', 'Attribute', 'AttributeList',
    'AttributeSelection', 'Referral', 'LDAPResult', 'SaslCredentials', 'AuthenticationChoice', 'BindRequest',
    'BindResponse', 'UnbindRequest', 'SubstringFilter', 'MatchingRuleAssertion', 'Filter', 'SearchRequest',
    'SearchResultEntry', 'SearchResultReference', 'SearchResultDone', 'ModifyRequest', 'ModifyResponse', 'AddRequest',
    'AddResponse', 'DelRequest', 'DelResponse', 'ModifyDNRequest', 'ModifyDNResponse', 'CompareRequest',
    'CompareResponse', 'AbandonRequest', 'ExtendedRequest', 'ExtendedResponse', 'IntermediateResponse', 'Control',
    'Controls', 'SimplePagedSearchControlValue', 'SimplePagedResultsControl', 'LDAPMessage'
]

# Result code
RESULT_SUCCESS = 0
RESULT_OPERATIONSERROR = 1
RESULT_PROTOCOLERROR = 2
RESULT_TIMELIMITEXCEEDED = 3
RESULT_SIZELIMITEXCEEDED = 4
RESULT_COMPAREFALSE = 5
RESULT_COMPARETRUE = 6
RESULT_AUTHMETHODNOTSUPPORTED = 7
RESULT_STRONGERAUTHREQUIRED = 8
RESULT_REFERRAL = 10
RESULT_ADMINLIMITEXCEEDED = 11
RESULT_UNAVAILABLECRITICALEXTENSION = 12
RESULT_CONFIDENTIALITYREQUIRED = 13
RESULT_SASLBINDINPROGRESS = 14
RESULT_NOSUCHATTRIBUTE = 16
RESULT_UNDEFINEDATTRIBUTETYPE = 17
RESULT_INAPPROPRIATEMATCHING = 18
RESULT_CONSTRAINTVIOLATION = 19
RESULT_ATTRIBUTEORVALUEEXISTS = 20
RESULT_INVALIDATTRIBUTESYNTAX = 21
RESULT_NOSUCHOBJECT = 32
RESULT_ALIASPROBLEM = 33
RESULT_INVALIDDNSYNTAX = 34
RESULT_ALIASDEREFERENCINGPROBLEM = 36
RESULT_INAPPROPRIATEAUTHENTICATION = 48
RESULT_INVALIDCREDENTIALS = 49
RESULT_INSUFFICIENTACCESSRIGHTS = 50
RESULT_BUSY = 51
RESULT_UNAVAILABLE = 52
RESULT_UNWILLINGTOPERFORM = 53
RESULT_LOOPDETECT = 54
RESULT_NAMINGVIOLATION = 64
RESULT_OBJECTCLASSVIOLATION = 65
RESULT_NOTALLOWEDONNONLEAF = 66
RESULT_NOTALLOWEDONRDN = 67
RESULT_ENTRYALREADYEXISTS = 68
RESULT_OBJECTCLASSMODSPROHIBITED = 69
RESULT_AFFECTSMULTIPLEDSAS = 71
RESULT_OTHER = 80

# Search scope
SCOPE_BASE = 0
SCOPE_ONE = 1
SCOPE_SUB = 2

# Alias dereferencing
DEREF_NEVER = 0
DEREF_SEARCH = 1
DEREF_FIND = 2
DEREF_ALWAYS = 3

# Modify operation
OPERATION_ADD = 0
OPERATION_DELETE = 1
OPERATION_REPLACE = 2

# Controls
CONTROL_PAGEDRESULTS = '1.2.840.113556.1.4.319'

KNOWN_CONTROLS = {}

# Unsolicited notifications
NOTIFICATION_DISCONNECT = '1.3.6.1.4.1.1466.20036'

KNOWN_NOTIFICATIONS = {NOTIFICATION_DISCONNECT: 'Notice of Disconnection'}

maxInt = univ.Integer(2147483647)


class DefaultSequence(univ.Sequence):
    def getComponentByPosition(self, idx):
        component = univ.Sequence.getComponentByPosition(self, idx)
        if component is None:
            return self.setComponentByPosition(idx).getComponentByPosition(idx)
        else:
            return component


class DefaultChoice(univ.Choice):
    def getComponentByPosition(self, idx):
        component = univ.Choice.getComponentByPosition(self, idx)
        if component is None:
            return self.setComponentByPosition(idx).getComponentByPosition(idx)
        else:
            return component


class ResultCode(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('success', RESULT_SUCCESS),
        ('operationsError', RESULT_OPERATIONSERROR),
        ('protocolError', RESULT_PROTOCOLERROR),
        ('timeLimitExceeded', RESULT_TIMELIMITEXCEEDED),
        ('sizeLimitExceeded', RESULT_SIZELIMITEXCEEDED),
        ('compareFalse', RESULT_COMPAREFALSE),
        ('compareTrue', RESULT_COMPARETRUE),
        ('authMethodNotSupported', RESULT_AUTHMETHODNOTSUPPORTED),
        ('strongerAuthRequired', RESULT_STRONGERAUTHREQUIRED),
        ('referral', RESULT_REFERRAL),
        ('adminLimitExceeded', RESULT_ADMINLIMITEXCEEDED),
        ('unavailableCriticalExtension', RESULT_UNAVAILABLECRITICALEXTENSION),
        ('confidentialityRequired', RESULT_CONFIDENTIALITYREQUIRED),
        ('saslBindInProgress', RESULT_SASLBINDINPROGRESS),
        ('noSuchAttribute', RESULT_NOSUCHATTRIBUTE),
        ('undefinedAttributeType', RESULT_UNDEFINEDATTRIBUTETYPE),
        ('inappropriateMatching', RESULT_INAPPROPRIATEMATCHING),
        ('constraintViolation', RESULT_CONSTRAINTVIOLATION),
        ('attributeOrValueExists', RESULT_ATTRIBUTEORVALUEEXISTS),
        ('invalidAttributeSyntax', RESULT_INVALIDATTRIBUTESYNTAX),
        ('noSuchObject', RESULT_NOSUCHOBJECT),
        ('aliasProblem', RESULT_ALIASPROBLEM),
        ('invalidDNSyntax', RESULT_INVALIDDNSYNTAX),
        ('aliasDereferencingProblem', RESULT_ALIASDEREFERENCINGPROBLEM),
        ('inappropriateAuthentication', RESULT_INAPPROPRIATEAUTHENTICATION),
        ('invalidCredentials', RESULT_INVALIDCREDENTIALS),
        ('insufficientAccessRights', RESULT_INSUFFICIENTACCESSRIGHTS),
        ('busy', RESULT_BUSY),
        ('unavailable', RESULT_UNAVAILABLE),
        ('unwillingToPerform', RESULT_UNWILLINGTOPERFORM),
        ('loopDetect', RESULT_LOOPDETECT),
        ('namingViolation', RESULT_NAMINGVIOLATION),
        ('objectClassViolation', RESULT_OBJECTCLASSVIOLATION),
        ('notAllowedOnNonLeaf', RESULT_NOTALLOWEDONNONLEAF),
        ('notAllowedOnRDN', RESULT_NOTALLOWEDONRDN),
        ('entryAlreadyExists', RESULT_ENTRYALREADYEXISTS),
        ('objectClassModsProhibited', RESULT_OBJECTCLASSMODSPROHIBITED),
        ('affectsMultipleDSAs', RESULT_AFFECTSMULTIPLEDSAS),
        ('other', RESULT_OTHER),
    )


class Scope(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('baseObject', SCOPE_BASE),
        ('singleLevel', SCOPE_ONE),
        ('wholeSubtree', SCOPE_SUB),
    )


class DerefAliases(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('neverDerefAliases', DEREF_NEVER),
        ('derefInSearching', DEREF_SEARCH),
        ('derefFindingBaseObj', DEREF_FIND),
        ('derefAlways', DEREF_ALWAYS),
    )


class Operation(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('add', OPERATION_ADD),
        ('delete', OPERATION_DELETE),
        ('replace', OPERATION_REPLACE),
    )


class MessageID(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, maxInt)


class LDAPString(univ.OctetString):
    encoding = 'utf-8'


class LDAPOID(univ.OctetString):
    pass


class LDAPDN(LDAPString):
    pass


class RelativeLDAPDN(LDAPString):
    pass


class AttributeDescription(LDAPString):
    pass


class AttributeValue(univ.OctetString):
    pass


class AssertionValue(univ.OctetString):
    pass


class MatchingRuleID(LDAPString):
    pass


class URI(LDAPString):
    pass


class AttributeValueAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attributeDesc', AttributeDescription()),
        namedtype.NamedType('assertionValue', AssertionValue())
    )


class PartialAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('vals', univ.SetOf(componentType=AttributeValue()))
    )


class PartialAttributeList(univ.SequenceOf):
    componentType = PartialAttribute()


class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType(
            'vals',
            univ.SetOf(componentType=AttributeValue()).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, maxInt))
        )
    )


class AttributeList(univ.SequenceOf):
    componentType = Attribute()


class AttributeSelection(univ.SequenceOf):
    componentType = LDAPString()


class Referral(univ.SequenceOf):
    componentType = URI()
    subtypeSpec = constraint.ValueSizeConstraint(1, maxInt)


class LDAPResult(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType(
            'referral', Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        )
    )


class SaslCredentials(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mechanism', LDAPString()),
        namedtype.OptionalNamedType('credentials', univ.OctetString())
    )


class AuthenticationChoice(DefaultChoice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'simple',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.NamedType(
            'sasl',
            SaslCredentials().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
        ),
        namedtype.NamedType(
            'sicilyPackageDiscovery',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9))
        ),
        namedtype.NamedType(
            'sicilyNegotiate',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))
        ),
        namedtype.NamedType(
            'sicilyResponse',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))
        )
    )


class BindRequest(DefaultSequence):
    tagSet = DefaultSequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(1, 127))),
        namedtype.NamedType('name', LDAPDN()),
        namedtype.NamedType('authentication', AuthenticationChoice())
    )


class BindResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType(
            'referral',
            Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        ),
        namedtype.OptionalNamedType(
            'serverSaslCreds',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
        )
    )


class UnbindRequest(univ.Null):
    tagSet = univ.Null.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2))


class SubstringFilter(DefaultSequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType(
            'substrings',
            univ.SequenceOf(componentType=univ.Choice(componentType=namedtype.NamedTypes(
                namedtype.NamedType(
                    'initial',
                    AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
                ),
                namedtype.NamedType(
                    'any',
                    AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
                ),
                namedtype.NamedType(
                    'final',
                    AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
                )
            )))
        )
    )


class MatchingRuleAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'matchingRule',
            MatchingRuleID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        ),
        namedtype.OptionalNamedType(
            'type',
            AttributeDescription().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        ),
        namedtype.NamedType(
            'matchValue',
            AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        ),
        namedtype.DefaultedNamedType(
            'dnAttributes',
            univ.Boolean().subtype(
                value=False,
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
            )
        )
    )


class Filter(DefaultChoice):
    pass


Filter.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        'and',
        univ.SetOf(componentType=Filter()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    ),
    namedtype.NamedType(
        'or',
        univ.SetOf(componentType=Filter()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
    ),
    namedtype.NamedType(
        'not',
        Filter().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))
    ),
    namedtype.NamedType(
        'equalityMatch',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))
    ),
    namedtype.NamedType(
        'substrings',
        SubstringFilter().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))
    ),
    namedtype.NamedType(
        'greaterOrEqual',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))
    ),
    namedtype.NamedType(
        'lessOrEqual',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))
    ),
    namedtype.NamedType(
        'present',
        AttributeDescription().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
    ),
    namedtype.NamedType(
        'approxMatch',
        AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))
    ),
    namedtype.NamedType(
        'extensibleMatch',
        MatchingRuleAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9))
    )
)


class SearchRequest(DefaultSequence):
    tagSet = DefaultSequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('baseObject', LDAPDN()),
        namedtype.NamedType('scope', Scope()),
        namedtype.NamedType('derefAliases', DerefAliases()),
        namedtype.NamedType(
            'sizeLimit', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))
        ),
        namedtype.NamedType(
            'timeLimit', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))
        ),
        namedtype.NamedType('typesOnly', univ.Boolean()),
        namedtype.NamedType('filter', Filter()),
        namedtype.NamedType('attributes', AttributeSelection())
    )


class SearchResultEntry(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 4))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('objectName', LDAPDN()),
        namedtype.NamedType('attributes', PartialAttributeList())
    )


class SearchResultReference(univ.SequenceOf):
    tagSet = univ.SequenceOf.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 19))
    componentType = URI()
    subtypeSpec = constraint.ValueSizeConstraint(1, maxInt)


class SearchResultDone(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 5))


class ModifyRequest(DefaultSequence):
    tagSet = DefaultSequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 6))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('object', LDAPDN()),
        namedtype.NamedType(
            'changes',
            univ.SequenceOf(componentType=univ.Sequence(componentType=namedtype.NamedTypes(
                namedtype.NamedType('operation', Operation()), namedtype.NamedType('modification', PartialAttribute())
            )))
        )
    )


class ModifyResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 7))


class AddRequest(DefaultSequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 8))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('attributes', AttributeList())
    )


class AddResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 9))


class DelRequest(LDAPDN):
    tagSet = LDAPDN.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 10))


class DelResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11))


class ModifyDNRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 12))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('newrdn', RelativeLDAPDN()),
        namedtype.NamedType('deleteoldrdn', univ.Boolean()),
        namedtype.OptionalNamedType(
            'newSuperior', LDAPDN().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        )
    )


class ModifyDNResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 13))


class CompareRequest(DefaultSequence):
    tagSet = DefaultSequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 14))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('ava', AttributeValueAssertion())
    )


class CompareResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 15))


class AbandonRequest(MessageID):
    tagSet = MessageID.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 16))


class ExtendedRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 23))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'requestName', LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.OptionalNamedType(
            'requestValue', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        )
    )


class ExtendedResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 24))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType(
            'referral',
            Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))
        ),
        namedtype.OptionalNamedType(
            'responseName',
            LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))
        ),
        namedtype.OptionalNamedType(
            'responseValue',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))
        )
    )


class IntermediateResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 25))
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'responseName',
            LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        namedtype.OptionalNamedType(
            'responseValue',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
        )
    )


class Control(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlType', LDAPOID()),
        namedtype.DefaultedNamedType('criticality', univ.Boolean().subtype(value=False)),
        namedtype.OptionalNamedType('controlValue', univ.OctetString())
    )

    def setComponentByPosition(self, idx, value=None,
                               verifyConstraints=True,
                               exactTypes=False,
                               matchTags=True,
                               matchConstraints=True):
        if idx == 0:  # controlType
            try:
                cls = KNOWN_CONTROLS[value]
                if self.__class__ != cls:
                    self.__class__ = cls
            except KeyError:
                pass
        return univ.Sequence.setComponentByPosition(self, idx, value=value,
                                                    verifyConstraints=verifyConstraints,
                                                    exactTypes=exactTypes,
                                                    matchTags=matchTags,
                                                    matchConstraints=matchConstraints)


class Controls(univ.SequenceOf):
    componentType = Control()


class SimplePagedSearchControlValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('size', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))),
        namedtype.NamedType('cookie', univ.OctetString()),
    )


class SimplePagedResultsControl(Control):
    def __init__(self, criticality=None, size=1000, cookie='', **kwargs):
        Control.__init__(self, **kwargs)
        self['controlType'] = CONTROL_PAGEDRESULTS
        if criticality is not None:
            self['criticality'] = criticality
        self._size = size
        self._cookie = cookie
        self._encodeControlValue()

    def _encodeControlValue(self):
        self['controlValue'] = encoder.encode(SimplePagedSearchControlValue().setComponents(self._size, self._cookie))

    def _decodeControlValue(self):
        (self._size, self._cookie), _ = decoder.decode(self['controlValue'], asn1Spec=SimplePagedSearchControlValue())

    def getCriticality(self):
        return self['criticality']

    def setCriticality(self, value):
        self['criticality'] = value

    def getSize(self):
        self._decodeControlValue()
        return self._size

    def setSize(self, value):
        self._size = value
        self._encodeControlValue()

    def getCookie(self):
        self._decodeControlValue()
        return self._cookie

    def setCookie(self, value):
        self._cookie = value
        self._encodeControlValue()


KNOWN_CONTROLS[CONTROL_PAGEDRESULTS] = SimplePagedResultsControl


class LDAPMessage(DefaultSequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('messageID', MessageID()),
        namedtype.NamedType('protocolOp', univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('bindRequest', BindRequest()),
            namedtype.NamedType('bindResponse', BindResponse()),
            namedtype.NamedType('unbindRequest', UnbindRequest()),
            namedtype.NamedType('searchRequest', SearchRequest()),
            namedtype.NamedType('searchResEntry', SearchResultEntry()),
            namedtype.NamedType('searchResDone', SearchResultDone()),
            namedtype.NamedType('searchResRef', SearchResultReference()),
            namedtype.NamedType('modifyRequest', ModifyRequest()),
            namedtype.NamedType('modifyResponse', ModifyResponse()),
            namedtype.NamedType('addRequest', AddRequest()),
            namedtype.NamedType('addResponse', AddResponse()),
            namedtype.NamedType('delRequest', DelRequest()),
            namedtype.NamedType('delResponse', DelResponse()),
            namedtype.NamedType('modDNRequest', ModifyDNRequest()),
            namedtype.NamedType('modDNResponse', ModifyDNResponse()),
            namedtype.NamedType('compareRequest', CompareRequest()),
            namedtype.NamedType('compareResponse', CompareResponse()),
            namedtype.NamedType('abandonRequest', AbandonRequest()),
            namedtype.NamedType('extendedReq', ExtendedRequest()),
            namedtype.NamedType('extendedResp', ExtendedResponse()),
            namedtype.NamedType('intermediateResponse', IntermediateResponse())
        ))),
        namedtype.OptionalNamedType(
            'controls',
            Controls().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        ),
        # fix AD nonconforming to RFC4511
        namedtype.OptionalNamedType(
            'responseName',
            LDAPOID().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))
        ),
        namedtype.OptionalNamedType(
            'responseValue',
            univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11))
        )
    )
