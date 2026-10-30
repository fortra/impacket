from pyasn1.codec.ber import decoder, encoder

from impacket.examples.ntlmrelayx.servers.socksplugins.ldap import LDAPSocksRelay
from impacket.ldap.ldapasn1 import (
    AttributeSelection,
    BindRequest,
    LDAPDN,
    LDAPMessage,
    LDAPString,
    ResultCode,
)


class FakeSocket:
    def __init__(self, recv_data):
        self.recv_data = list(recv_data)
        self.sent_data = []

    def recv(self, _size):
        if len(self.recv_data) == 0:
            return b''
        return self.recv_data.pop(0)

    def sendall(self, data):
        self.sent_data.append(data)


def get_relay(root_dse=None, sock=None):
    active_relays = {'data': {'LDAP_INFO': root_dse or {}}}
    return LDAPSocksRelay('dc.test.local', 389, sock, active_relays)


def get_requested_attributes(*attributes):
    selection = AttributeSelection()
    for pos, attribute in enumerate(attributes):
        selection.setComponentByPosition(pos, LDAPString(attribute))
    return selection


def get_response_attributes(response):
    attributes = {}
    for partial_attribute in response['attributes']:
        name = partial_attribute['type'].asOctets().decode('utf-8')
        values = [
            value.asOctets().decode('utf-8')
            for value in partial_attribute['vals']
        ]
        attributes[name] = values
    return attributes


def test_rootdse_wildcard_expands_cached_attributes():
    relay = get_relay({
        'namingContexts': [
            'DC=test,DC=local',
            'CN=Configuration,DC=test,DC=local',
        ],
        'defaultNamingContext': 'DC=test,DC=local',
    })

    response = relay.build_RootDSE_response(get_requested_attributes('*'))
    attributes = get_response_attributes(response)

    assert '*' not in attributes
    assert attributes['namingContexts'] == [
        'DC=test,DC=local',
        'CN=Configuration,DC=test,DC=local',
    ]
    assert attributes['defaultNamingContext'] == ['DC=test,DC=local']


def test_rootdse_empty_attribute_selection_expands_cached_attributes():
    relay = get_relay({'defaultNamingContext': 'DC=test,DC=local'})

    response = relay.build_RootDSE_response(AttributeSelection())
    attributes = get_response_attributes(response)

    assert attributes == {'defaultNamingContext': ['DC=test,DC=local']}


def test_rootdse_multivalued_attributes_are_encoded_separately():
    relay = get_relay({
        'namingContexts': [
            'DC=test,DC=local',
            'CN=Configuration,DC=test,DC=local',
        ],
        'supportedControl': [
            '1.2.840.113556.1.4.319',
            '1.2.840.113556.1.4.473',
        ],
    })

    response = relay.build_RootDSE_response(
        get_requested_attributes('namingContexts', 'supportedControl')
    )
    attributes = get_response_attributes(response)

    assert attributes['namingContexts'] == [
        'DC=test,DC=local',
        'CN=Configuration,DC=test,DC=local',
    ]
    assert attributes['supportedControl'] == [
        '1.2.840.113556.1.4.319',
        '1.2.840.113556.1.4.473',
    ]


def test_rootdse_missing_attributes_are_omitted():
    relay = get_relay({'defaultNamingContext': 'DC=test,DC=local'})

    response = relay.build_RootDSE_response(
        get_requested_attributes('missingAttribute', 'defaultNamingContext')
    )
    attributes = get_response_attributes(response)

    assert attributes == {'defaultNamingContext': ['DC=test,DC=local']}


def test_rootdse_no_attrs_selector_returns_no_attributes():
    relay = get_relay({'defaultNamingContext': 'DC=test,DC=local'})

    response = relay.build_RootDSE_response(get_requested_attributes('1.1'))

    assert len(response['attributes']) == 0


def test_sasl_bind_without_credentials_returns_protocol_error():
    bind_request = BindRequest()
    bind_request['version'] = 3
    bind_request['name'] = LDAPDN('')
    sasl = bind_request['authentication'].getComponentByName('sasl')
    sasl['mechanism'] = LDAPString('GSS-SPNEGO')
    bind_request['authentication'].setComponentByName('sasl', sasl)

    message = LDAPMessage()
    message['messageID'] = 1
    message['protocolOp'].setComponentByType(bind_request.getTagSet(), bind_request)

    sock = FakeSocket([encoder.encode(message)])
    relay = get_relay(sock=sock)

    assert relay.skipAuthentication() is False

    response_message, _ = decoder.decode(sock.sent_data[0], asn1Spec=LDAPMessage())
    bind_response = response_message['protocolOp'].getComponent()
    assert bind_response['resultCode'] == ResultCode('protocolError')
