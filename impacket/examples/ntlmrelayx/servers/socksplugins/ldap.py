import calendar
import select
import socket
import struct
import time
import binascii
import threading
from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type import univ

from impacket import LOG, ntlm
from impacket.examples.ntlmrelayx.servers.socksserver import SocksRelay
from impacket.ldap.ldap import LDAPSessionError
from impacket.ldap.ldapasn1 import KNOWN_NOTIFICATIONS, LDAPDN, NOTIFICATION_DISCONNECT, BindRequest, BindResponse, LDAPMessage, LDAPString, ResultCode
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
            messages = self.recv()
            LOG.debug(f'Received {len(messages)} message(s)')

            for message in messages:
                msg_component = message['protocolOp'].getComponent()
                if msg_component.isSameTypeWith(BindRequest):
                    # BindRequest received

                    if msg_component['name'] == LDAPDN('') and msg_component['authentication'] == univ.OctetString(''):
                        # First bind message without authentication
                        # Replying with a request for NTLM authentication

                        LOG.debug('Got empty bind request')

                        bindresponse = BindResponse()
                        bindresponse['resultCode'] = ResultCode('success')
                        bindresponse['matchedDN'] = LDAPDN('NTLM')
                        bindresponse['diagnosticMessage'] = LDAPString('')
                        self.send(bindresponse, message['messageID'])

                        # Let's receive next messages
                        continue

                    elif msg_component['name'] == LDAPDN('NTLM'):
                        # Requested NTLM authentication

                        LOG.debug('Got NTLM bind request')

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
                        self.send(bindresponse, message['messageID'])

                    else:
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
                        self.send(bindresponse, message['messageID'])

                        return True

    def recv(self):
        '''Receive LDAP messages during the SOCKS client LDAP authentication.'''

        data = b''
        done = False
        while not done:
            recvData = self.socksSocket.recv(self.MSG_SIZE)
            if len(recvData) < self.MSG_SIZE:
                done = True
            data += recvData

        response = []
        while len(data) > 0:
            try:
                message, remaining = decoder.decode(data, asn1Spec=LDAPMessage())
            except SubstrateUnderrunError:
                # We need more data
                remaining = data + self.socksSocket.recv(self.MSG_SIZE)
            else:
                if message['messageID'] == 0:  # unsolicited notification
                    name = message['protocolOp']['extendedResp']['responseName'] or message['responseName']
                    notification = KNOWN_NOTIFICATIONS.get(name, "Unsolicited Notification '%s'" % name)
                    if name == NOTIFICATION_DISCONNECT:  # Server has disconnected
                        self.close()
                    raise LDAPSessionError(
                        error=int(message['protocolOp']['extendedResp']['resultCode']),
                        errorString='%s -> %s: %s' % (notification,
                                                      message['protocolOp']['extendedResp']['resultCode'].prettyPrint(),
                                                      message['protocolOp']['extendedResp']['diagnosticMessage'])
                    )
                response.append(message)
            data = remaining

        return response
    
    def send(self, response, message_id, controls=None):
        '''Send LDAP messages during the SOCKS client LDAP authentication.'''

        message = LDAPMessage()
        message['messageID'] = message_id
        message['protocolOp'].setComponentByType(response.getTagSet(), response)
        if controls is not None:
            message['controls'].setComponents(*controls)

        data = encoder.encode(message)

        return self.socksSocket.sendall(data)

    def tunnelConnection(self):
        '''Charged of tunneling the rest of the connection.'''

        self.stop_event = threading.Event()
        self.server_is_gone = False

        # Client to Server
        c2s = threading.Thread(target=self.recv_from_send_to, args=(self.socksSocket, self.session, False))
        c2s.daemon = True
        # Server to Client
        s2c = threading.Thread(target=self.recv_from_send_to, args=(self.session, self.socksSocket, True))
        s2c.daemon = True

        c2s.start()
        s2c.start()

        # Should wait until the client or server closes connection
        c2s.join()
        s2c.join()

        if self.server_is_gone:
            # There was an error with the server socket
            # Raising an exception so that the socksserver.py module can remove the current relay
            # from the available ones
            raise BrokenPipeError('Broken pipe: LDAP server is gone')
        
        # Free the relay so that it can be reused
        self.activeRelays[self.username]['inUse'] = False

        LOG.debug('Finished tunnelling')

        return True

    def recv_from_send_to(self, recv_from: socket.socket, send_to: socket.socket, recv_from_is_server: bool):
        '''
        Simple helper that receives data on the recv_from socket and sends it to send_to socket.

        The recv_from_is_server allows to properly stop the relay when the server closes connection.
        '''

        while not self.stop_event.is_set():
            is_ready, a, b = select.select([recv_from], [], [], 1.0)

            if not is_ready:
                continue

            try:
                data = recv_from.recv(LDAPSocksRelay.MSG_SIZE)
            except Exception:
                if recv_from_is_server:
                    self.server_is_gone = True

                self.stop_event.set()
                return

            LOG.debug(f'Received {len(data)} byte(s) from {"server" if recv_from_is_server else "client"}')

            if data == b'':
                if recv_from_is_server:
                    self.server_is_gone = True

                self.stop_event.set()
                return
            
            try:
                send_to.send(data)
            except Exception:
                if not recv_from_is_server:
                    self.server_is_gone = True

                self.stop_event.set()
                return

