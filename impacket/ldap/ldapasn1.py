# Copyright (c) 2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   RFC 4511 Minimalistic implementation. We don't need much functionality yet
#   If we need more complex use cases we might opt to use a third party implementation
#   Keep in mind the APIs are still unstable, might require to re-write your scripts
#   as we change them.
#   Adding [MS-ADTS] specific functionality
#
# ToDo:
# [ ]
#

from pyasn1.type.univ import Sequence, Integer, Choice, SequenceOf, OctetString, Boolean, Enumerated, SetOf
from pyasn1.type.constraint import ValueRangeConstraint, ValueSizeConstraint
from pyasn1.type.namedtype import NamedType, OptionalNamedType, NamedTypes
from pyasn1.type.tag import Tag, tagClassContext, tagFormatConstructed, tagClassApplication, tagFormatSimple
from pyasn1.type.namedval import NamedValues

################################################################################
# CONSTANTS
################################################################################
MAXINT = 2147483647

# Search Scope constants
SCOPE_BASE  = 0
SCOPE_ONE   = 1
SCOPE_SUB   = 2

# Search deref
DEREF_NEVER  = 0
DEREF_SEARC  = 1
DEREF_FIND   = 2
DEREF_ALWAYS = 3

################################################################################
# CLASSES
################################################################################

class Integer7Bit(Integer):
    # INTEGER (1 ..  127)
    subtypeSpec = ValueRangeConstraint(1, 127)

class IntegerPositive(Integer):
    subtypeSpec = Integer.subtypeSpec + ValueRangeConstraint(0, MAXINT)

class LDAPString(OctetString):
    """
        LDAPString ::= OCTET STRING -- UTF-8 encoded,
                                    -- [ISO10646] characters
    """
    encoding = 'utf-8'
    pass

class LDAPDN(LDAPString):
    """
        LDAPDN ::= LDAPString -- Constrained to <distinguishedName>
                              -- [RFC4514]
    """
    pass

class AuthSimple(OctetString):
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))
    encoding = 'utf-8'

class Credentials(OctetString):
    encoding = 'utf-8'

class SaslCredentials(Sequence):
    """
        SaslCredentials ::= SEQUENCE {
             mechanism               LDAPString,
             credentials             OCTET STRING OPTIONAL }
    """
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 3))
    componentType = NamedTypes(
        NamedType('mechanism', LDAPString()),
        OptionalNamedType('credentials', Credentials())
    )

class SicilyPackageDiscovery(OctetString):
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 9))
    encoding = 'utf-8'

class SicilyNegotiate(OctetString):
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 10))
    encoding = 'utf-8'

class SicilyResponse(OctetString):
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 11))
    encoding = 'utf-8'

class AuthenticationChoice(Choice):
    """
        AuthenticationChoice ::= CHOICE {
            simple [0]                 OCTET STRING,
            sasl [3]                   SaslCredentials
            sicilyPackageDiscovery [9] OCTET STRING
            sicilyNegotiate [10]       OCTET STRING
            sicilyResponse [11]        OCTET STRING  }
    """
    componentType = NamedTypes(
        NamedType('simple', AuthSimple()),
        NamedType('sasl', SaslCredentials()),
        NamedType('sicilyPackageDiscovery', SicilyPackageDiscovery()),
        NamedType('sicilyNegotiate', SicilyNegotiate()),
        NamedType('sicilyResponse', SicilyResponse()),
    )

class BindRequest(Sequence):
    """
        BindRequest ::= [APPLICATION 0] SEQUENCE {
             version                 INTEGER (1 ..  127),
             name                    LDAPDN,
             authentication          AuthenticationChoice }
    """
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 0))
    componentType = NamedTypes(
        NamedType('version', Integer7Bit()),
        NamedType('name', LDAPDN()),
        NamedType('authentication', AuthenticationChoice()),
    )

class URI(LDAPString):
    pass

class Referral(SequenceOf):
    """
        Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
    """
    tagSet = SequenceOf.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 3))
    componentType = URI()

class ResultCode(Enumerated):
    """
     resultCode         ENUMERATED {
          success                      (0),
          operationsError              (1),
          protocolError                (2),
          timeLimitExceeded            (3),
          sizeLimitExceeded            (4),
          compareFalse                 (5),
          compareTrue                  (6),
          authMethodNotSupported       (7),
          strongerAuthRequired         (8),
               -- 9 reserved --
          referral                     (10),
          adminLimitExceeded           (11),
          unavailableCriticalExtension (12),
          confidentialityRequired      (13),
          saslBindInProgress           (14),
          noSuchAttribute              (16),
          undefinedAttributeType       (17),
          inappropriateMatching        (18),
          constraintViolation          (19),
          attributeOrValueExists       (20),
          invalidAttributeSyntax       (21),
               -- 22-31 unused --
          noSuchObject                 (32),
          aliasProblem                 (33),
          invalidDNSyntax              (34),
               -- 35 reserved for undefined isLeaf --
          aliasDereferencingProblem    (36),
               -- 37-47 unused --
          inappropriateAuthentication  (48),
          invalidCredentials           (49),
          insufficientAccessRights     (50),
          busy                         (51),
          unavailable                  (52),
          unwillingToPerform           (53),
          loopDetect                   (54),
               -- 55-63 unused --
          namingViolation              (64),
          objectClassViolation         (65),
          notAllowedOnNonLeaf          (66),
          notAllowedOnRDN              (67),
          entryAlreadyExists           (68),
          objectClassModsProhibited    (69),
               -- 70 reserved for CLDAP --
          affectsMultipleDSAs          (71),
               -- 72-79 unused --
          other                        (80),
          ...  },
    """
    namedValues = NamedValues(
        ('success', 0),
        ('operationsError', 1),
        ('protocolError', 2),
        ('timeLimitExceeded', 3),
        ('sizeLimitExceeded', 4),
        ('compareFalse', 5),
        ('compareTrue', 6),
        ('authMethodNotSupported', 7),
        ('strongerAuthRequired', 8),
        ('referral', 10),
        ('adminLimitExceeded', 11),
        ('unavailableCriticalExtension', 12),
        ('confidentialityRequired', 13),
        ('saslBindInProgress', 14),
        ('noSuchAttribute', 16),
        ('undefinedAttributeType', 17),
        ('inappropriateMatching', 18),
        ('constraintViolatio', 19),
        ('attributeOrValueExists', 20),
        ('invalidAttributeSyntax', 21),
        ('noSuchObject', 32),
        ('aliasProblem', 33),
        ('invalidDNSyntaxn', 34),
        ('aliasDereferencingProblem', 36),
        ('inappropriateAuthentication', 48),
        ('invalidCredentials', 49),
        ('insufficientAccessRights', 50),
        ('busy', 51),
        ('unavailable', 52),
        ('unwillingToPerform', 53),
        ('loopDetect', 54),
        ('namingViolation', 64),
        ('objectClassViolation', 65),
        ('notAllowedOnNonLeaf', 66),
        ('notAllowedOnRDN', 67),
        ('entryAlreadyExists', 68),
        ('objectClassModsProhibited', 69),
        ('affectsMultipleDSAs', 71),
        ('other', 80),
    )

class ServerSaslCreds(OctetString):
    # serverSaslCreds    [7] OCTET STRING OPTIONAL
    tagSet = OctetString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 7))

class BindResponse(Sequence):
    """
        BindResponse ::= [APPLICATION 1] SEQUENCE {
             COMPONENTS OF LDAPResult,
             serverSaslCreds    [7] OCTET STRING OPTIONAL }
    """
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 1))
    componentType = NamedTypes(
        NamedType('resultCode', ResultCode()),
        NamedType('matchedDN', LDAPDN()),
        NamedType('diagnosticMessage', LDAPString()),
        OptionalNamedType('referral', Referral()),
        OptionalNamedType('serverSaslCreds', ServerSaslCreds()),
    )

class Scope(Enumerated):
    """
         scope           ENUMERATED {
              baseObject              (0),
              singleLevel             (1),
              wholeSubtree            (2),
              ...  },
    """
    namedValues = NamedValues(
        ('baseObject', 0),
        ('singleLevel', 1),
        ('wholeSubtree', 2),
    )

class DeRefAliases(Enumerated):
    """
         derefAliases    ENUMERATED {
              neverDerefAliases       (0),
              derefInSearching        (1),
              derefFindingBaseObj     (2),
              derefAlways             (3) }
    """
    namedValues = NamedValues(
        ('neverDerefAliases', 0),
        ('derefInSearching', 1),
        ('derefFindingBaseObj', 2),
        ('derefAlways', 3),
    )

class And(SetOf):
    # and             [0] SET SIZE (1..MAX) OF filter Filter
    tagSet = SetOf.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 0))
    subtypeSpec = SetOf.subtypeSpec + ValueSizeConstraint(1, MAXINT)

class Or(SetOf):
    # or              [1] SET SIZE (1..MAX) OF filter Filter
    tagSet = SetOf.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 1))
    subtypeSpec = SetOf.subtypeSpec + ValueSizeConstraint(1, MAXINT)

class Not(Choice):
    # not             [2] Filter
    pass

class AttributeDescription(LDAPString):
    """
        AttributeDescription::= LDAPString
        -- Constrained
        to < attributedescription >
        -- [RFC4512]
    """
    pass


class AttributeValue(OctetString):
    # AttributeValue::= OCTET STRING
    pass

class AttributeValueAssertion(Sequence):
    """
    AttributeValueAssertion::= SEQUENCE
    {
        attributeDesc AttributeDescription,
        assertionValue AssertionValue}
    """
    componentType = NamedTypes(
        NamedType('attributeDesc', AttributeDescription()),
        NamedType('assertionValue', AttributeValue()),
    )

class EqualityMatch(AttributeValueAssertion):
    # equalityMatch   [3] AttributeValueAssertion
    tagSet = AttributeValueAssertion.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 3))

class GreaterOrEqual(AttributeValueAssertion):
    # greaterOrEqual   [5] AttributeValueAssertion
    tagSet = AttributeValueAssertion.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 5))

class LessOrEqual(AttributeValueAssertion):
    # lessOrEqual   [6] AttributeValueAssertion
    tagSet = AttributeValueAssertion.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 6))

class Present(AttributeDescription):
    # Present   [7] AttributeValueAssertion
    tagSet = AttributeDescription.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 7))

class ApproxMatch(AttributeValueAssertion):
    # approxMatch   [8] AttributeValueAssertion
    tagSet = AttributeValueAssertion.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 7))

class AssertionValue(OctetString):
    # AssertionValue ::= OCTET STRING
    encoding = 'utf-8'

class InitialAssertion(AssertionValue):
    # initial [0] AssertionValue,  -- can occur at most once
    tagSet = AssertionValue.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 0))

class AnyAssertion(AssertionValue):
    # any     [1] AssertionValue
    tagSet = AssertionValue.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 1))

class FinalAssertion(AssertionValue):
    # final   [2] AssertionValue } -- can occur at most once
    tagSet = AssertionValue.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 2))

class SubString(Choice):
    """
    substring CHOICE {
                  initial [0] AssertionValue,  -- can occur at most once
                  any     [1] AssertionValue,
                  final   [2] AssertionValue } -- can occur at most once
             }
    """
    componentType = NamedTypes(
        NamedType('initial', InitialAssertion()),
        NamedType('any', AnyAssertion()),
        NamedType('final', FinalAssertion()),
    )

class SubStrings(SequenceOf):
    """
         substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
              initial [0] AssertionValue,  -- can occur at most once
              any     [1] AssertionValue,
              final   [2] AssertionValue } -- can occur at most once
         }
    """
    componentType = SubString()
    subtypeSpec = SequenceOf.subtypeSpec + ValueSizeConstraint(1, MAXINT)

class SubstringFilter(Sequence):
    """
        SubstringFilter ::= SEQUENCE {
             type           AttributeDescription,
             substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
                  initial [0] AssertionValue,  -- can occur at most once
                  any     [1] AssertionValue,
                  final   [2] AssertionValue } -- can occur at most once
             }
    """
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 4))
    componentType = NamedTypes(
        NamedType('type', AttributeDescription()),
        NamedType('substrings', SubStrings()),
    )

class TypeDescription(AttributeDescription):
    # type            [2] AttributeDescription OPTIONAL
    tagSet = AttributeDescription.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 2))

class matchValueAssertion(AssertionValue):
    # matchValue      [3] AssertionValue
    tagSet = AssertionValue.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 3))

class MatchingRuleId(LDAPString):
    # matchingRule    [1] MatchingRuleId OPTIONAL
    tagSet = LDAPString.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 1))
    pass

class DnAttributes(Boolean):
    # dnAttributes    [4] BOOLEAN DEFAULT FALSE }
    tagSet = Boolean.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatSimple, 4))
    defaultValue = Boolean(False)

class MatchingRuleAssertion(Sequence):
    """
        MatchingRuleAssertion ::= SEQUENCE {
             matchingRule    [1] MatchingRuleId OPTIONAL,
             type            [2] AttributeDescription OPTIONAL,
             matchValue      [3] AssertionValue,
             dnAttributes    [4] BOOLEAN DEFAULT FALSE }
    """
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 9))
    componentType = NamedTypes(
        OptionalNamedType('matchingRule', MatchingRuleId()),
        OptionalNamedType('type', TypeDescription()),
        NamedType('matchValue', matchValueAssertion()),
        NamedType('dnAttributes', DnAttributes()),
    )
class Filter(Choice):
    """
        Filter ::= CHOICE {
             and             [0] SET SIZE (1..MAX) OF filter Filter,
             or              [1] SET SIZE (1..MAX) OF filter Filter,
             not             [2] Filter,
             equalityMatch   [3] AttributeValueAssertion,
             substrings      [4] SubstringFilter,
             greaterOrEqual  [5] AttributeValueAssertion,
             lessOrEqual     [6] AttributeValueAssertion,
             present         [7] AttributeDescription,
             approxMatch     [8] AttributeValueAssertion,
             extensibleMatch [9] MatchingRuleAssertion,
             ...  }
    """
    componentType = NamedTypes(
        NamedType('and', And()),
        NamedType('or', Or()),
        NamedType('not', Not()),
        NamedType('equalityMatch', EqualityMatch()),
        NamedType('substrings', SubstringFilter()),
        NamedType('greaterOrEqual', GreaterOrEqual()),
        NamedType('lessOrEqual', LessOrEqual()),
        NamedType('present', Present()),
        NamedType('approxMatch', ApproxMatch()),
        NamedType('extensibleMatch', MatchingRuleAssertion()),
    )

# Similar trick to what we did with DRSUAPI (pNextEntInf). Trying to cheat Python, using Filter() now with And(),
# Or() and Not() now that is defined
And.componentType = Filter()
Or.componentType = Filter()
Not.componentType = NamedTypes(NamedType('notFilter', Filter()))
Not.tagSet = Filter.tagSet.tagExplicitly(Tag(tagClassContext, tagFormatConstructed, 2))

class Selector(LDAPString):
    pass

class AttributeSelection(SequenceOf):
    """
        AttributeSelection ::= SEQUENCE OF selector LDAPString
                       -- The LDAPString is constrained to
                       -- <attributeSelector> in Section 4.5.1.8
    """
    componentType = Selector()

class SearchRequest(Sequence):
    """
        SearchRequest ::= [APPLICATION 3] SEQUENCE {
             baseObject      LDAPDN,
             scope           ENUMERATED {
                  baseObject              (0),
                  singleLevel             (1),
                  wholeSubtree            (2),
                  ...  },
             derefAliases    ENUMERATED {
                  neverDerefAliases       (0),
                  derefInSearching        (1),
                  derefFindingBaseObj     (2),
                  derefAlways             (3) },
             sizeLimit       INTEGER (0 ..  maxInt),
             timeLimit       INTEGER (0 ..  maxInt),
             typesOnly       BOOLEAN,
             filter          Filter,
             attributes      AttributeSelection }
    """
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 3))
    componentType = NamedTypes(
        NamedType('baseObject', LDAPDN()),
        NamedType('scope', Scope()),
        NamedType('derefAliases', DeRefAliases()),
        NamedType('sizeLimit', IntegerPositive()),
        NamedType('timeLimit', IntegerPositive()),
        NamedType('typesOnly', Boolean()),
        NamedType('filter', Filter()),
        NamedType('attributes', AttributeSelection()),
    )

class AttributeValue(OctetString):
    # AttributeValue ::= OCTET STRING
    encoding = 'utf-8'

class Vals(SetOf):
    componentType = AttributeValue()

class PartialAttribute(Sequence):
    """
        PartialAttribute ::= SEQUENCE {
             type       AttributeDescription,
             vals       SET OF value AttributeValue }

    """
    componentType = NamedTypes(
        NamedType('type', AttributeDescription()),
        NamedType('vals', Vals()),
    )

class PartialAttributeList(SequenceOf):
    """
        PartialAttributeList ::= SEQUENCE OF
                             partialAttribute PartialAttribute
    """
    componentType = PartialAttribute()

class Attributes(PartialAttributeList):
    pass

class SearchResultEntry(Sequence):
    """
        SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
             objectName      LDAPDN,
             attributes      PartialAttributeList }
    """
    tagSet = Sequence.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 4))
    componentType = NamedTypes(
        NamedType('objectName', LDAPDN()),
        NamedType('attributes', Attributes()),
    )

class LDAPResult(Sequence):
    """
        LDAPResult ::= SEQUENCE {
             resultCode         ENUMERATED {
                  success                      (0),
                  operationsError              (1),
                  protocolError                (2),
                  timeLimitExceeded            (3),
                  sizeLimitExceeded            (4),
                  compareFalse                 (5),
                  compareTrue                  (6),
                  authMethodNotSupported       (7),
                  strongerAuthRequired         (8),
                       -- 9 reserved --
                  referral                     (10),
                  adminLimitExceeded           (11),
                  unavailableCriticalExtension (12),
                  confidentialityRequired      (13),
                  saslBindInProgress           (14),
                  noSuchAttribute              (16),
                  undefinedAttributeType       (17),
                  inappropriateMatching        (18),
                  constraintViolation          (19),
                  attributeOrValueExists       (20),
                  invalidAttributeSyntax       (21),
                       -- 22-31 unused --
                  noSuchObject                 (32),
                  aliasProblem                 (33),
                  invalidDNSyntax              (34),
                       -- 35 reserved for undefined isLeaf --
                  aliasDereferencingProblem    (36),
                       -- 37-47 unused --
                  inappropriateAuthentication  (48),
                  invalidCredentials           (49),
                  insufficientAccessRights     (50),
                  busy                         (51),
                  unavailable                  (52),
                  unwillingToPerform           (53),
                  loopDetect                   (54),
                       -- 55-63 unused --
                  namingViolation              (64),
                  objectClassViolation         (65),
                  notAllowedOnNonLeaf          (66),
                  notAllowedOnRDN              (67),
                  entryAlreadyExists           (68),
                  objectClassModsProhibited    (69),
                       -- 70 reserved for CLDAP --
                  affectsMultipleDSAs          (71),
                       -- 72-79 unused --
                  other                        (80),
                  ...  },
             matchedDN          LDAPDN,
             diagnosticMessage  LDAPString,
             referral           [3] Referral OPTIONAL }
    """
    componentType = NamedTypes(
        NamedType('resultCode', ResultCode()),
        NamedType('matchedDN', LDAPDN()),
        NamedType('diagnosticMessage', LDAPString()),
        OptionalNamedType('referral', Referral()),
    )

class SearchResultDone(LDAPResult):
    # SearchResultDone ::= [APPLICATION 5] LDAPResult
    tagSet = LDAPResult.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 5))

class SearchResultReference(SequenceOf):
    """
        SearchResultReference ::= [APPLICATION 19] SEQUENCE
                                  SIZE (1..MAX) OF uri URI

    """
    tagSet = SequenceOf.tagSet.tagImplicitly(Tag(tagClassApplication, tagFormatConstructed, 19))
    componentType = URI()
    subtypeSpec = SequenceOf.subtypeSpec + ValueSizeConstraint(1, MAXINT)

class ProtocolOp(Choice):
    """
        protocolOp      CHOICE {
        bindRequest           BindRequest,
        bindResponse          BindResponse,
        unbindRequest         UnbindRequest,
        searchRequest         SearchRequest,
        searchResEntry        SearchResultEntry,
        searchResDone         SearchResultDone,
        searchResRef          SearchResultReference,
        modifyRequest         ModifyRequest,
        modifyResponse        ModifyResponse,
        addRequest            AddRequest,
        addResponse           AddResponse,
        delRequest            DelRequest,
        delResponse           DelResponse,
        modDNRequest          ModifyDNRequest,
        modDNResponse         ModifyDNResponse,
        compareRequest        CompareRequest,
        compareResponse       CompareResponse,
        abandonRequest        AbandonRequest,
        extendedReq           ExtendedRequest,
        extendedResp          ExtendedResponse,
        ...,
        intermediateResponse  IntermediateResponse },
    """
    # For now we just implement a few choices
    componentType = NamedTypes(
        NamedType('bindRequest', BindRequest()),
        NamedType('bindResponse', BindResponse()),
        NamedType('searchRequest', SearchRequest()),
        NamedType('searchResEntry', SearchResultEntry()),
        NamedType('searchResDone', SearchResultDone()),
        NamedType('searchResRef', SearchResultReference()),
    )

class LDAPOID(OctetString):
    """
        LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
                                 -- [RFC4512]
    """
    pass

class Control(Sequence):
    """
        Control ::= SEQUENCE {
                 controlType             LDAPOID,
                 criticality             BOOLEAN DEFAULT FALSE,
                 controlValue            OCTET STRING OPTIONAL }
    """
    componentType = NamedTypes(
        NamedType('controlType', LDAPOID()),
        NamedType('criticality', Boolean(False)),
        OptionalNamedType('controlValue', OctetString()),
    )

class Controls(SequenceOf):
    # Controls ::= SEQUENCE OF control Control
    tagSet = SequenceOf.tagSet.tagImplicitly(Tag(tagClassContext, tagFormatConstructed, 0))
    componentType = Control()

class MessageID(IntegerPositive):
    # MessageID ::= INTEGER (0 ..  maxInt)
    pass

class LDAPMessage(Sequence):
    """
        LDAPMessage ::= SEQUENCE {
             messageID       MessageID,
             protocolOp      CHOICE {
                  bindRequest           BindRequest,
                  bindResponse          BindResponse,
                  unbindRequest         UnbindRequest,
                  searchRequest         SearchRequest,
                  searchResEntry        SearchResultEntry,
                  searchResDone         SearchResultDone,
                  searchResRef          SearchResultReference,
                  modifyRequest         ModifyRequest,
                  modifyResponse        ModifyResponse,
                  addRequest            AddRequest,
                  addResponse           AddResponse,
                  delRequest            DelRequest,
                  delResponse           DelResponse,
                  modDNRequest          ModifyDNRequest,
                  modDNResponse         ModifyDNResponse,
                  compareRequest        CompareRequest,
                  compareResponse       CompareResponse,
                  abandonRequest        AbandonRequest,
                  extendedReq           ExtendedRequest,
                  extendedResp          ExtendedResponse,
                  ...,
                  intermediateResponse  IntermediateResponse },
             controls       [0] Controls OPTIONAL }

        MessageID ::= INTEGER (0 ..  maxInt)

        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
    """
    componentType = NamedTypes(
        NamedType('messageID', MessageID()),
        NamedType('protocolOp', ProtocolOp()),
        OptionalNamedType('controls', Controls())
        )
