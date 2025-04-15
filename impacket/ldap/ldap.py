# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   RFC 4511 Minimalistic implementation. We don't need much functionality yet
#   If we need more complex use cases we might opt to use a third party implementation
#   Keep in mind the APIs are still unstable, might require to re-write your scripts
#   as we change them.
#   Adding [MS-ADTS] specific functionality
#
# Authors:
#   Alberto Solino (@agsolino)
#   Kacper Nowak (@kacpern)
#
# ToDo:
#   [x] Implement Paging Search, especially important for big requests
#

import re
import socket
from binascii import unhexlify
import random

from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type.univ import noValue

from impacket import LOG
from impacket.ldap.ldapasn1 import Filter, Control, SimplePagedResultsControl, ResultCode, Scope, DerefAliases, Operation, \
    KNOWN_CONTROLS, CONTROL_PAGEDRESULTS, NOTIFICATION_DISCONNECT, KNOWN_NOTIFICATIONS, BindRequest, SearchRequest, \
    SearchResultDone, LDAPMessage
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3, VERSION, MAC
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, SPNEGOCipher, TypesMech

try:
    import OpenSSL
    from OpenSSL import SSL, crypto
except:
    LOG.critical("pyOpenSSL is not installed, can't continue")
    raise

__all__ = [
    'LDAPConnection', 'LDAPFilterSyntaxError', 'LDAPFilterInvalidException', 'LDAPSessionError', 'LDAPSearchError',
    'Control', 'SimplePagedResultsControl', 'ResultCode', 'Scope', 'DerefAliases', 'Operation',
    'CONTROL_PAGEDRESULTS', 'KNOWN_CONTROLS', 'NOTIFICATION_DISCONNECT', 'KNOWN_NOTIFICATIONS',
]

# https://tools.ietf.org/search/rfc4515#section-3
DESCRIPTION = r'(?:[a-z][a-z0-9\-]*)'
NUMERIC_OID = r'(?:(?:\d|[1-9]\d+)(?:\.(?:\d|[1-9]\d+))*)'
OID = r'(?:%s|%s)' % (DESCRIPTION, NUMERIC_OID)
OPTIONS = r'(?:(?:;[a-z0-9\-]+)*)'
ATTRIBUTE = r'(%s%s)' % (OID, OPTIONS)
DN = r'(:dn)'
MATCHING_RULE = r'(?::(%s))' % OID

RE_OPERATOR = re.compile(r'([:<>~]?=)')
RE_ATTRIBUTE = re.compile(r'^%s$' % ATTRIBUTE, re.I)
RE_EX_ATTRIBUTE_1 = re.compile(r'^%s%s?%s?$' % (ATTRIBUTE, DN, MATCHING_RULE), re.I)
RE_EX_ATTRIBUTE_2 = re.compile(r'^(){0}%s?%s$' % (DN, MATCHING_RULE), re.I)


class LDAPConnection:
    def __init__(self, url, baseDN='', dstIp=None, signing=True):
        """
        LDAPConnection class

        :param string url:
        :param string baseDN:
        :param string dstIp:

        :return: a LDAP instance, if not raises a LDAPSessionError exception
        """
        self._SSL = False
        self._dstPort = 0
        self._dstHost = 0
        self._socket = None
        self._baseDN = baseDN
        self._dstIp = dstIp
        self.__signing = signing

        if url.startswith('ldap://'):
            self._dstPort = 389
            self._SSL = False
            self._dstHost = url[7:]
        elif url.startswith('ldaps://'):
            self._dstPort = 636
            self._SSL = True
            self.__signing = False
            self._dstHost = url[8:]
        elif url.startswith('gc://'):
            self._dstPort = 3268
            self._SSL = False
            self.__signing = False
            self._dstHost = url[5:]
        else:
            raise LDAPSessionError(errorString="Unknown URL prefix: '%s'" % url)

        self.__binded = False

        ### SASL Auth LDAP Signing arguments
        self.sequenceNumber = 0
        
        # Kerberos
        self.__auth_type = None
        self.__gss = None
        self.__sessionKey = None

        # NTLM
        self.__spnego_cipher_blob = None

        # Try to connect
        if self._dstIp is not None:
            targetHost = self._dstIp
        else:
            targetHost = self._dstHost

        LOG.debug('Connecting to %s, port %d, SSL %s, signing %s' % (targetHost, self._dstPort, self._SSL, self.__signing))
        try:
            af, socktype, proto, _, sa = socket.getaddrinfo(targetHost, self._dstPort, 0, socket.SOCK_STREAM)[0]
            self._socket = socket.socket(af, socktype, proto)
        except socket.error as e:
            raise socket.error('Connection error (%s:%d)' % (targetHost, self._dstPort), e)

        if self._SSL is False:
            self._socket.connect(sa)
        else:
            # Switching to TLS now
            ctx = SSL.Context(SSL.TLS_METHOD)
            ctx.set_cipher_list('ALL:@SECLEVEL=0'.encode('utf-8'))
            SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00040000
            ctx.set_options(SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
            self._socket = SSL.Connection(ctx, self._socket)
            self._socket.connect(sa)
            self._socket.do_handshake()

    def generateChannelBindingValue(self):
        # From: https://github.com/ly4k/ldap3/commit/87f5760e5a68c2f91eac8ba375f4ea3928e2b9e0#diff-c782b790cfa0a948362bf47d72df8ddd6daac12e5757afd9d371d89385b27ef6R1383
        from hashlib import md5
        # Ugly but effective, to get the digest of the X509 DER in bytes
        peer_cert_digest_str = self._socket.get_peer_certificate().digest('sha256').decode()
        peer_cert_digest_bytes = bytes.fromhex(peer_cert_digest_str.replace(':', ''))
    
        channel_binding_struct = b''
        initiator_address = b'\x00'*8
        acceptor_address = b'\x00'*8

        # https://datatracker.ietf.org/doc/html/rfc5929#section-4
        application_data_raw = b'tls-server-end-point:' + peer_cert_digest_bytes
        len_application_data = len(application_data_raw).to_bytes(4, byteorder='little', signed = False)
        application_data = len_application_data
        application_data += application_data_raw
        channel_binding_struct += initiator_address
        channel_binding_struct += acceptor_address
        channel_binding_struct += application_data
        return md5(channel_binding_struct).digest()

    def kerberosLogin(self, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None,
                      TGS=None, useCache=True):
        """
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format
        :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False

        :return: True, raises a LDAPSessionError if error.
        """

        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0' + lmhash
            if len(nthash) % 2:
                nthash = '0' + nthash
            try:  # just in case they were converted already
                lmhash = unhexlify(lmhash)
                nthash = unhexlify(nthash)
            except TypeError:
                pass

        # Importing down here so pyasn1 is not required if kerberos is not used.
        from impacket.krb5.ccache import CCache
        from impacket.krb5.gssapi import GSSAPI, GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, GSS_C_SEQUENCE_FLAG, GSS_C_REPLAY_FLAG
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, CheckSumField
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        import datetime

        if TGT is not None or TGS is not None:
            useCache = False

        targetName = 'ldap/%s' % self._dstHost
        if useCache:
            domain, user, TGT, TGS = CCache.parseFile(domain, user, targetName)

        # First of all, we need to get a TGT for the user
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                        aesKey, kdcHost)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            serverName = Principal(targetName, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                    sessionKey)
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

            # Let's build a NegTokenInit with a Kerberos REQ_AP

        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.now(datetime.timezone.utc)

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)
        
        authenticator['cksum'] = noValue
        authenticator['cksum']['cksumtype'] = 0x8003

        chkField = CheckSumField()
        chkField['Lgth'] = 16

        chkField['Flags'] = GSS_C_SEQUENCE_FLAG | GSS_C_REPLAY_FLAG

        # If TLS is used, setup channel binding
        
        if self._SSL:
            chkField['Bnd'] = self.generateChannelBindingValue()
        if self.__signing:
            chkField['Flags'] |= GSS_C_CONF_FLAG
            chkField['Flags'] |= GSS_C_INTEG_FLAG
        authenticator['cksum']['checksum'] = chkField.getData()
        authenticator['seq-number'] = 0
        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
        blob['MechToken'] = encoder.encode(apReq)
        
        # Done with the Kerberos saga, now let's get into LDAP

        bindRequest = BindRequest()
        bindRequest['version'] = 3
        bindRequest['name'] = 'user'
        bindRequest['authentication']['sasl']['mechanism'] = 'GSS-SPNEGO'
        bindRequest['authentication']['sasl']['credentials'] = blob.getData()
        
        response = self.sendReceive(bindRequest)[0]['protocolOp']
        if response['bindResponse']['resultCode'] != ResultCode('success'):
            raise LDAPSessionError(
                errorString='Error in bindRequest -> %s: %s' % (response['bindResponse']['resultCode'].prettyPrint(),
                                                                response['bindResponse']['diagnosticMessage'])
            )
        
        self.__auth_type = "KRB5"
        self.__binded = True

        if self.__signing:
            self.__sessionKey = sessionKey
            self.__gss = GSSAPI(cipher)

        return True

    def login(self, user='', password='', domain='', lmhash='', nthash='', authenticationChoice='sasl'):
        """
        logins into the target system

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string authenticationChoice: type of authentication protocol to use (default NTLM)

        :return: True, raises a LDAPSessionError if error.
        """
        bindRequest = BindRequest()
        bindRequest['version'] = 3

        if authenticationChoice == 'simple':
            if '.' in domain:
                bindRequest['name'] = user + '@' + domain
            elif domain:
                bindRequest['name'] = domain + '\\' + user
            else:
                bindRequest['name'] = user
            bindRequest['authentication']['simple'] = password
            response = self.sendReceive(bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyPackageDiscovery':
            bindRequest['name'] = user
            bindRequest['authentication']['sicilyPackageDiscovery'] = ''
            response = self.sendReceive(bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyNegotiate':
            # Deal with NTLM Authentication
            if lmhash != '' or nthash != '':
                if len(lmhash) % 2:
                    lmhash = '0' + lmhash
                if len(nthash) % 2:
                    nthash = '0' + nthash
                try:  # just in case they were converted already
                    lmhash = unhexlify(lmhash)
                    nthash = unhexlify(nthash)
                except TypeError:
                    pass

            bindRequest['name'] = user

            # NTLM Negotiate
            negotiate = getNTLMSSPType1('', domain)
            bindRequest['authentication']['sicilyNegotiate'] = negotiate.getData()
            response = self.sendReceive(bindRequest)[0]['protocolOp']
            if response['bindResponse']['resultCode'] != ResultCode('success'):
                raise LDAPSessionError(
                    errorString='Error in bindRequest during the NTLMAuthNegotiate request -> %s: %s' %
                                (response['bindResponse']['resultCode'].prettyPrint(),
                                 response['bindResponse']['diagnosticMessage'])
                )

            # NTLM Challenge
            type2 = response['bindResponse']['matchedDN']

            # If TLS is used, setup channel binding
            channel_binding_value = b''
            if self._SSL:
                channel_binding_value = self.generateChannelBindingValue()

            # NTLM Auth
            type3, exportedSessionKey = getNTLMSSPType3(negotiate, bytes(type2), user, password, domain, lmhash, nthash, channel_binding_value=channel_binding_value)
            bindRequest['authentication']['sicilyResponse'] = type3.getData()
            response = self.sendReceive(bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sasl':
            if lmhash != '' or nthash != '':
                if len(lmhash) % 2:
                    lmhash = '0' + lmhash
                if len(nthash) % 2:
                    nthash = '0' + nthash
                try:
                    lmhash = unhexlify(lmhash)
                    nthash = unhexlify(nthash)
                except TypeError:
                    pass

            bindRequest['name'] = ''
            self.version = VERSION()
            self.version['ProductMajorVersion'], self.version['ProductMinorVersion'], self.version['ProductBuild'] = 10, 0, 19041
            # NTLM Negotiate
            negotiate = getNTLMSSPType1('', domain, signingRequired=self.__signing, use_ntlmv2=True, version=self.version)

            blob = SPNEGO_NegTokenInit()
            blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
            blob['MechToken'] = negotiate.getData()

            bindRequest['authentication']['sasl']['mechanism'] = 'GSS-SPNEGO'
            bindRequest['authentication']['sasl']['credentials'] = blob.getData()
            response = self.sendReceive(bindRequest)[0]['protocolOp']
            if response['bindResponse']['resultCode'] != ResultCode('saslBindInProgress'):
                raise LDAPSessionError(
                    errorString='Error in bindRequest during the NTLMAuthNegotiate request -> %s: %s' %
                                (response['bindResponse']['resultCode'].prettyPrint(),
                                 response['bindResponse']['diagnosticMessage'])
                )

            # NTLM Challenge
            serverSaslCreds = response['bindResponse']['serverSaslCreds']
            spnegoTokenResp = SPNEGO_NegTokenResp(serverSaslCreds.asOctets())
            type2 = spnegoTokenResp['ResponseToken']
            
            # channel binding
            channel_binding_value = b''
            if self._SSL:
                channel_binding_value = self.generateChannelBindingValue()
            
            # NTLM Auth
            type3, exportedSessionKey = getNTLMSSPType3(negotiate, type2, user, password, domain, lmhash, nthash, service='ldap', version=self.version, use_ntlmv2=True, channel_binding_value=channel_binding_value)
            blob = SPNEGO_NegTokenResp()
            blob['ResponseToken'] = type3.getData()
            if self.__signing:
                self.__spnego_cipher_blob = SPNEGOCipher(flags=negotiate['flags'], randomSessionKey=exportedSessionKey)
                blob['mechListMIC'] = self.__spnego_cipher_blob.sign(b'0\x0c\x06\n+\x06\x01\x04\x01\x827\x02\x02\n', 0, reset_cipher=True).getData()
            bindRequest['authentication']['sasl']['mechanism'] = 'GSS-SPNEGO'
            bindRequest['authentication']['sasl']['credentials'] = blob.getData()
            response = self.sendReceive(bindRequest)[0]['protocolOp']
        else:
            raise LDAPSessionError(errorString="Unknown authenticationChoice: '%s'" % authenticationChoice)

        if response['bindResponse']['resultCode'] != ResultCode('success'):
            raise LDAPSessionError(
                errorString='Error in bindRequest -> %s: %s' % (response['bindResponse']['resultCode'].prettyPrint(),
                                                                response['bindResponse']['diagnosticMessage'])
            )
        
        self.__auth_type = f"NTLM-{authenticationChoice}"
        self.__binded = True
        return True

    def encrypt(self, data):
        if self.__auth_type == "KRB5":
            data, signature = self.__gss.GSS_Wrap_LDAP(self.__sessionKey, data, self.sequenceNumber)
            data = signature + data
            data = len(data).to_bytes(4, byteorder = 'big', signed = False) + data
        elif self.__auth_type == "NTLM-sasl":
            signature, data = self.__spnego_cipher_blob.encrypt(data)
            data = signature.getData() + data
            data = len(data).to_bytes(4, byteorder = 'big', signed = False) + data
        else:
            raise(f"Encryption not implemented for {self.__auth_type} protocol")
        return data

    def decrypt(self, data):
        if self.__auth_type == "KRB5":
            data = data[4:]
            data, _ = self.__gss.GSS_Unwrap_LDAP(self.__sessionKey, data, 0, direction='init')
        elif self.__auth_type == "NTLM-sasl":
            data= data[4:]
            signature, data = self.__spnego_cipher_blob.decrypt(data)
        else:
            raise(f"Decryption not implemented for {self.__auth_type} protocol")
        return data

    def search(self, searchBase=None, scope=None, derefAliases=None, sizeLimit=0, timeLimit=0, typesOnly=False,
               searchFilter='(objectClass=*)', attributes=None, searchControls=None, perRecordCallback=None):
        if searchBase is None:
            searchBase = self._baseDN
        if scope is None:
            scope = Scope('wholeSubtree')
        if derefAliases is None:
            derefAliases = DerefAliases('neverDerefAliases')
        if attributes is None:
            attributes = []

        searchRequest = SearchRequest()
        searchRequest['baseObject'] = searchBase
        searchRequest['scope'] = scope
        searchRequest['derefAliases'] = derefAliases
        searchRequest['sizeLimit'] = sizeLimit
        searchRequest['timeLimit'] = timeLimit
        searchRequest['typesOnly'] = typesOnly
        searchRequest['filter'] = self._parseFilter(searchFilter)
        searchRequest['attributes'].setComponents(*attributes)

        done = False
        answers = []
        # We keep asking records until we get a SearchResultDone packet and all controls are handled
        while not done:
            response = self.sendReceive(searchRequest, searchControls)
            for message in response:
                searchResult = message['protocolOp'].getComponent()
                if searchResult.isSameTypeWith(SearchResultDone()):
                    if searchResult['resultCode'] == ResultCode('success'):
                        done = self._handleControls(searchControls, message['controls'])
                    else:
                        raise LDAPSearchError(
                            error=int(searchResult['resultCode']),
                            errorString='Error in searchRequest -> %s: %s' % (searchResult['resultCode'].prettyPrint(),
                                                                              searchResult['diagnosticMessage']),
                            answers=answers
                        )
                else:
                    if perRecordCallback is None:
                        answers.append(searchResult)
                    else:
                        perRecordCallback(searchResult)

        return answers

    def _handleControls(self, requestControls, responseControls):
        done = True
        if requestControls is not None:
            for requestControl in requestControls:
                if responseControls is not None:
                    for responseControl in responseControls:
                        if str(requestControl['controlType']) == CONTROL_PAGEDRESULTS:
                            if str(responseControl['controlType']) == CONTROL_PAGEDRESULTS:
                                if hasattr(responseControl, 'getCookie') is not True:
                                    responseControl = decoder.decode(encoder.encode(responseControl),
                                                                 asn1Spec=KNOWN_CONTROLS[CONTROL_PAGEDRESULTS]())[0]
                                if responseControl.getCookie():
                                    done = False
                                requestControl.setCookie(responseControl.getCookie())
                                break
                        else:
                            # handle different controls here
                            pass
        return done

    def close(self):
        if self._socket is not None:
            self._socket.close()

    def send(self, request, controls=None):
        message = LDAPMessage()
        message['messageID'] = random.randrange(1, 2147483647)
        message['protocolOp'].setComponentByType(request.getTagSet(), request)
        if controls is not None:
            message['controls'].setComponents(*controls)

        data = encoder.encode(message)

        if self.__binded and self.__signing:
            data = self.encrypt(data)
            self.sequenceNumber += 1
        return self._socket.sendall(data)

    def recv(self):
        REQUEST_SIZE = 8192
        data = b''
        done = False
        while not done:
            recvData = self._socket.recv(REQUEST_SIZE)
            if len(recvData) < REQUEST_SIZE:
                done = True
            data += recvData

        response = []
        if self.__binded and self.__signing:
                data = self.decrypt(data)
        while len(data) > 0:
            try:
                # need to decrypt before
                message, remaining = decoder.decode(data, asn1Spec=LDAPMessage())
            except SubstrateUnderrunError:
                # We need more data
                remaining = data + self._socket.recv(REQUEST_SIZE)
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

    def sendReceive(self, request, controls=None):
        self.send(request, controls)
        return self.recv()

    def _parseFilter(self, filterStr):
        try:
            filterStr = filterStr.decode()
        except AttributeError:
            pass
        filterList = list(reversed(filterStr))
        searchFilter = self._consumeCompositeFilter(filterList)
        if filterList:  # we have not consumed the whole filter string
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % filterList[-1])
        return searchFilter

    def _consumeCompositeFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':  # filter must start with a '('
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        try:
            operator = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if operator not in ['!', '&', '|']:  # must be simple filter in this case
            filterList.extend([operator, c])
            return self._consumeSimpleFilter(filterList)

        filters = []
        while True:
            try:
                filters.append(self._consumeCompositeFilter(filterList))
            except LDAPFilterSyntaxError:
                break

        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != ')':  # filter must end with a ')'
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        return self._compileCompositeFilter(operator, filters)

    def _consumeSimpleFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':  # filter must start with a '('
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        filter = []
        while True:
            try:
                c = filterList.pop()
            except IndexError:
                raise LDAPFilterSyntaxError('EOL while parsing search filter')
            if c == ')':  # we pop till we find a ')'
                break
            elif c == '(':  # should be no unencoded parenthesis
                filterList.append(c)
                raise LDAPFilterSyntaxError("unexpected token: '('")
            else:
                filter.append(c)

        filterStr = ''.join(filter)
        try:
            # https://tools.ietf.org/search/rfc4515#section-3
            attribute, operator, value = RE_OPERATOR.split(filterStr, 1)
        except ValueError:
            raise LDAPFilterInvalidException("invalid filter: '(%s)'" % filterStr)

        return self._compileSimpleFilter(attribute, operator, value)

    @staticmethod
    def _compileCompositeFilter(operator, filters):
        searchFilter = Filter()
        if operator == '!':
            if len(filters) != 1:
                raise LDAPFilterInvalidException("'not' filter must have exactly one element")
            searchFilter['not'].setComponents(*filters)
        elif operator == '&':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'and' filter must have at least one element")
            searchFilter['and'].setComponents(*filters)
        elif operator == '|':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'or' filter must have at least one element")
            searchFilter['or'].setComponents(*filters)

        return searchFilter

    @staticmethod
    def _compileSimpleFilter(attribute, operator, value):
        searchFilter = Filter()
        if operator == ':=':  # extensibleMatch
            match = RE_EX_ATTRIBUTE_1.match(attribute) or RE_EX_ATTRIBUTE_2.match(attribute)
            if not match:
                raise LDAPFilterInvalidException("invalid filter attribute: '%s'" % attribute)
            attribute, dn, matchingRule = match.groups()
            if attribute:
                searchFilter['extensibleMatch']['type'] = attribute
            if dn:
                searchFilter['extensibleMatch']['dnAttributes'] = bool(dn)
            if matchingRule:
                searchFilter['extensibleMatch']['matchingRule'] = matchingRule
            searchFilter['extensibleMatch']['matchValue'] = LDAPConnection._processLdapString(value)
        else:
            if not RE_ATTRIBUTE.match(attribute):
                raise LDAPFilterInvalidException("invalid filter attribute: '%s'" % attribute)
            if value == '*' and operator == '=':  # present
                searchFilter['present'] = attribute
            elif '*' in value and operator == '=':  # substring
                assertions = [LDAPConnection._processLdapString(assertion) for assertion in value.split('*')]
                choice = searchFilter['substrings']['substrings'].getComponentType()
                substrings = []
                if assertions[0]:
                    substrings.append(choice.clone().setComponentByName('initial', assertions[0]))
                for assertion in assertions[1:-1]:
                    substrings.append(choice.clone().setComponentByName('any', assertion))
                if assertions[-1]:
                    substrings.append(choice.clone().setComponentByName('final', assertions[-1]))
                searchFilter['substrings']['type'] = attribute
                searchFilter['substrings']['substrings'].setComponents(*substrings)
            elif '*' not in value:  # simple
                value = LDAPConnection._processLdapString(value)
                if operator == '=':
                    searchFilter['equalityMatch'].setComponents(attribute, value)
                elif operator == '~=':
                    searchFilter['approxMatch'].setComponents(attribute, value)
                elif operator == '>=':
                    searchFilter['greaterOrEqual'].setComponents(attribute, value)
                elif operator == '<=':
                    searchFilter['lessOrEqual'].setComponents(attribute, value)
            else:
                raise LDAPFilterInvalidException("invalid filter '(%s%s%s)'" % (attribute, operator, value))

        return searchFilter


    @classmethod
    def _processLdapString(cls, ldapstr):
        def replace_escaped_chars(match):
            return chr(int(match.group(1), 16))  # group(1) == "XX" (valid hex)

        escaped_chars = re.compile(r'\\([0-9a-fA-F]{2})')  # Capture any sequence of "\XX" (where XX is a valid hex)
        return re.sub(escaped_chars, replace_escaped_chars, ldapstr)


class LDAPFilterSyntaxError(SyntaxError):
    pass


class LDAPFilterInvalidException(Exception):
    pass


class LDAPSessionError(Exception):
    """
    This is the exception every client should catch
    """

    def __init__(self, error=0, packet=0, errorString=''):
        Exception.__init__(self)
        self.error = error
        self.packet = packet
        self.errorString = errorString

    def getErrorCode(self):
        return self.error

    def getErrorPacket(self):
        return self.packet

    def getErrorString(self):
        return self.errorString

    def __str__(self):
        return self.errorString


class LDAPSearchError(LDAPSessionError):
    def __init__(self, error=0, packet=0, errorString='', answers=None):
        LDAPSessionError.__init__(self, error, packet, errorString)
        if answers is None:
            answers = []
        self.answers = answers

    def getAnswers(self):
        return self.answers
