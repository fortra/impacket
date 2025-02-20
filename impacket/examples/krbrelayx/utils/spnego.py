from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful
from impacket.krb5.asn1 import _application_tag, _sequence_component, _sequence_optional_component, AP_REQ, AP_REP
from pyasn1.codec.der import decoder, encoder

MechTypes = {
    '1.3.6.1.4.1.311.2.2.10': 'NTLMSSP - Microsoft NTLM Security Support Provider',
    '1.2.840.48018.1.2.2': 'MS KRB5 - Microsoft Kerberos 5',
    '1.2.840.113554.1.2.2': 'KRB5 - Kerberos 5',
    '1.2.840.113554.1.2.2.3': 'KRB5 - Kerberos 5 - User to User',
    '1.3.6.1.4.1.311.2.2.30': 'NEGOEX - SPNEGO Extended Negotiation Security Mechanism'
}

TypesMech = dict((v,k) for k, v in MechTypes.items())

class ContextFlags(univ.BitString):
    namedValues = namedval.NamedValues(
        ('delegFlag', 0),
        ('mutualFlag', 1),
        ('replayFlag', 2),
        ('sequenceFlag', 3),
        ('anonFlag', 4),
        ('confFlag', 5),
        ('integFlag', 6)
    )

class NegResult(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('accept_completed', 0),
        ('accept_incomplete', 1),
        ('reject', 2),
        ('request_mic', 3)
    )

class MechType(univ.ObjectIdentifier):
    pass


class MechTypeList(univ.SequenceOf):
    componentType = MechType()


class NegHints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component('hintName', 0, char.GeneralString()),
        _sequence_optional_component('hintAddress', 1, univ.OctetString())
    )


class NegTokenInit(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('mechTypes', 0, MechTypeList()),
        _sequence_optional_component('reqFlags', 1, ContextFlags()),
        _sequence_optional_component('mechToken', 2, univ.OctetString()),
        _sequence_optional_component('mechListMIC', 3, univ.OctetString())
    )


class NegTokenInit2(univ.Sequence):
    """
    negTokenInit2 is a Microsoft extension of negTokenInit, initiating SPNEGO from the server
    See [MS-SPNG] for details. The negHints field should always contain the hintname
    "not_defined_in_RFC4178@please_ignore"
    """
    componentType = namedtype.NamedTypes(
        _sequence_component('mechTypes', 0, MechTypeList()),
        _sequence_optional_component('reqFlags', 1, ContextFlags()),
        _sequence_optional_component('mechToken', 2, univ.OctetString()),
        _sequence_optional_component('negHints', 3, NegHints()),
        _sequence_optional_component('mechListMIC', 4, univ.OctetString())
    )

class NegTokenResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component('negResult', 0, NegResult()),
        _sequence_optional_component('supportedMech', 1, MechType()),
        _sequence_optional_component('responseToken', 2, univ.OctetString()),
        _sequence_optional_component('mechListMIC', 3, univ.OctetString())
    )

class NegotiationToken(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('negTokenInit', NegTokenInit().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('negTokenResp', NegTokenResp().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )

class GSSAPIHeader_SPNEGO_Init(univ.Sequence):
    """
    GSSAPI Header containing SPNEGO negTokenInit or negTokenResp
    """
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tokenOid', univ.ObjectIdentifier()),
        namedtype.NamedType('innerContextToken', NegotiationToken())
    )

class GSSAPIHeader_SPNEGO_Init2(univ.Sequence):
    """
    GSSAPI Header containing SPNEGO negTokenInit2
    negTokenInit2 is a Microsoft extension, initiating SPNEGO from the server
    See [MS-SPNG] for details
    """
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tokenOid', univ.ObjectIdentifier()),
        _sequence_component('innerContextToken', 0, NegTokenInit2())
    )

class GSSAPIHeader_KRB5_AP_REQ(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tokenOid', univ.ObjectIdentifier()),
        # Actualy this is a constant 0x0001, but this decodes as an asn1 boolean
        namedtype.NamedType('krb5_ap_req', univ.Boolean()),
        namedtype.NamedType('apReq', AP_REQ()),
    )

class GSSAPIHeader_KRB5_AP_REP(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tokenOid', univ.ObjectIdentifier()),
        # Actualy this is a constant 0x0002, but this decodes as an asn1 integer
        namedtype.NamedType('krb5_ap_rep', univ.Integer()),
        namedtype.NamedType('apRep', AP_REP()),
    )
