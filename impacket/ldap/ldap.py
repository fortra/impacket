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
# [ ] Implement Paging Search, especially important for big requests
#

import socket
import os
from binascii import unhexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import SubstrateUnderrunError

from impacket import LOG
from impacket.ldap.ldapasn1 import BindRequest, Integer7Bit, LDAPDN, AuthenticationChoice, AuthSimple, LDAPMessage, \
    SCOPE_SUB, SearchRequest, Scope, DEREF_NEVER, DeRefAliases, IntegerPositive, Boolean, AttributeSelection, \
    SaslCredentials, LDAPString, ProtocolOp, Credentials
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

try:
    import OpenSSL
    from OpenSSL import SSL, crypto
except:
    LOG.critical("pyOpenSSL is not installed, can't continue")
    raise

class LDAPConnection:
    def __init__(self,url, baseDN='dc=net', dstIp = None):
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
        self._messageId = 1
        self._dstIp = dstIp

        if url.startswith("ldap://"):
            self._dstPort = 389
            self._SSL = False
            self._dstHost = url[7:]
        elif url.startswith("ldaps://"):
            #raise LDAPSessionError(errorString = 'LDAPS still not supported')
            self._dstPort = 636
            self._SSL = True
            self._dstHost = url[8:]
        else:
            raise LDAPSessionError(errorString = 'Unknown URL prefix %s' % url)

        # Try to connect
        if self._dstIp is not None:
            targetHost = self._dstIp
        else:
            targetHost = self._dstHost

        LOG.debug('Connecting to %s, port %s, SSL %s' % (targetHost, self._dstPort, self._SSL))
        try:
            af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, self._dstPort, 0, socket.SOCK_STREAM)[0]
            self._socket = socket.socket(af, socktype, proto)
        except socket.error, e:
            raise socket.error("Connection error (%s:%s)" % (targetHost, 88), e)

        if self._SSL is False:
            self._socket.connect(sa)
        else:
            # Switching to TLS now
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            #ctx.set_cipher_list('RC4')
            self._socket = SSL.Connection(ctx, self._socket)
            self._socket.connect(sa)
            self._socket.do_handshake()

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
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try:  # just in case they were converted already
                lmhash = unhexlify(lmhash)
                nthash = unhexlify(nthash)
            except:
                pass

        # Importing down here so pyasn1 is not required if kerberos is not used.
        from impacket.krb5.ccache import CCache
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        from pyasn1.codec.der import decoder, encoder
        import datetime

        if TGT is not None or TGS is not None:
            useCache = False

        if useCache is True:
            try:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            except:
                # No cache present
                pass
            else:
                # retrieve user and domain information from CCache file if needed
                if user == '' and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]['data']
                if domain == '':
                    domain = ccache.principal.realm['data']
                LOG.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
                principal = 'ldap/%s@%s' % (self._dstHost.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        LOG.debug('Using TGT from cache')
                    else:
                        LOG.debug("No valid credentials found in cache. ")
                else:
                    TGS = creds.toTGS()
                    LOG.debug('Using TGS from cache')

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
            serverName = Principal('ldap/%s' % self._dstHost,
                                   type=constants.PrincipalNameType.NT_SRV_INST.value)
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

        opts = list()
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

        # Key Usage 11
        # AP-REQ Authenticator (includes application authenticator
        # subkey), encrypted with the application session key
        # (Section 5.5.1)
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = None
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)

        # Done with the Kerberos saga, now let's get into LDAP

        bindRequest = BindRequest()
        bindRequest['version'] = Integer7Bit(3)
        bindRequest['name'] = LDAPDN(user)
        credentials = SaslCredentials()
        credentials['mechanism'] = LDAPString('GSS-SPNEGO')
        credentials['credentials'] = Credentials(blob.getData())
        bindRequest['authentication'] = AuthenticationChoice().setComponentByName('sasl', credentials)

        resp = self.sendReceive('bindRequest', bindRequest)[0]['protocolOp']

        if resp['bindResponse']['resultCode'] != 0:
            raise LDAPSessionError(errorString='Error in bindRequest -> %s:%s' % (
            resp['bindResponse']['resultCode'].prettyPrint(), resp['bindResponse']['diagnosticMessage']))

        return True

    def login(self, user='', password='', domain = '', lmhash = '', nthash = '', authenticationChoice = 'sicilyNegotiate'):
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
        bindRequest['version'] = Integer7Bit(3)
        bindRequest['name'] = LDAPDN(user)

        if authenticationChoice == 'simple':
            bindRequest['authentication'] = AuthenticationChoice().setComponentByName(authenticationChoice, AuthSimple(password))
            resp = self.sendReceive('bindRequest', bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyPackageDiscovery':
            bindRequest['authentication'] = AuthenticationChoice().setComponentByName(authenticationChoice, '')
            resp = self.sendReceive('bindRequest', bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyNegotiate':
            # Deal with NTLM Authentication
            if lmhash != '' or nthash != '':
                if len(lmhash) % 2:     lmhash = '0%s' % lmhash
                if len(nthash) % 2:     nthash = '0%s' % nthash
                try:  # just in case they were converted already
                    lmhash = unhexlify(lmhash)
                    nthash = unhexlify(nthash)
                except:
                    pass

            # NTLM Negotiate
            negotiate = getNTLMSSPType1('',domain)
            bindRequest['authentication'] = AuthenticationChoice().setComponentByName('sicilyNegotiate', negotiate)
            resp = self.sendReceive('bindRequest', bindRequest)[0]['protocolOp']

            # NTLM Challenge
            type2 = resp['bindResponse']['matchedDN']

            # NTLM Auth
            type3, exportedSessionKey = getNTLMSSPType3(negotiate, str(type2), user, password, domain, lmhash, nthash)
            bindRequest['authentication'] = AuthenticationChoice().setComponentByName('sicilyResponse', type3)
            resp = self.sendReceive('bindRequest', bindRequest)[0]['protocolOp']
        else:
            raise LDAPSessionError(errorString='Unknown authenticationChoice %s' % authenticationChoice)

        if resp['bindResponse']['resultCode'] != 0:
            raise LDAPSessionError(errorString = 'Error in bindRequest -> %s:%s' % (resp['bindResponse']['resultCode'].prettyPrint(), resp['bindResponse']['diagnosticMessage'] ))

        return True

    def search(self, searchBase=None, searchFilter=None, scope=SCOPE_SUB, attributes=None, derefAliases=DEREF_NEVER,
               sizeLimit=0):
        # ToDo: For now we need to specify a filter as a Filter instance, meaning, we have to programmatically build it
        # ToDo: We have to create functions to parse and compile a text searchFilter into a Filter instance.
        if searchBase is None:
            searchBase = self._baseDN

        searchRequest = SearchRequest()
        searchRequest['baseObject'] = LDAPDN(searchBase)
        searchRequest['scope'] = Scope(scope)
        searchRequest['derefAliases'] = DeRefAliases(derefAliases)
        searchRequest['sizeLimit'] = IntegerPositive(sizeLimit)
        searchRequest['timeLimit'] = IntegerPositive(0)
        searchRequest['typesOnly'] = Boolean(False)
        searchRequest['filter'] = searchFilter
        searchRequest['attributes'] = AttributeSelection()
        if attributes is not None:
            for i,item in enumerate(attributes):
                searchRequest['attributes'][i] = item

        done = False
        answers = []
        # We keep asking records until we get a searchResDone packet
        while not done:
            resp = self.sendReceive('searchRequest', searchRequest)
            for item in resp:
                protocolOp = item['protocolOp']
                if protocolOp.getName() == 'searchResDone':
                    done = True
                    if protocolOp['searchResDone']['resultCode'] != 0:
                        raise LDAPSearchError(error = int(protocolOp['searchResDone']['resultCode']), errorString = 'Error in searchRequest -> %s:%s' % (protocolOp['searchResDone']['resultCode'].prettyPrint(), protocolOp['searchResDone']['diagnosticMessage'] ), answers=answers)
                else:
                    answers.append(item['protocolOp'][protocolOp.getName()])

        return answers


    def close(self):
        if self._socket is not None:
            self._socket.close()

    def send(self, protocolOp, message):
        ldapMessage = LDAPMessage( )
        ldapMessage['messageID'] = IntegerPositive(self._messageId)
        ldapMessage['protocolOp'] = ProtocolOp().setComponentByName(protocolOp, message)

        data = encoder.encode(ldapMessage)

        return self._socket.sendall(data)

    def recv(self):
        REQUEST_SIZE = 8192
        data = ''
        done = False
        while not done:
            recvData = self._socket.recv(REQUEST_SIZE)
            if len(recvData) < REQUEST_SIZE:
                done = True
            data += recvData

        answers = []

        while len(data) > 0:
            try:
                ldapMessage, remaining = decoder.decode(data, asn1Spec = LDAPMessage())
            except SubstrateUnderrunError:
                # We need more data
                remaining = data + self._socket.recv(REQUEST_SIZE)
            else:
                answers.append(ldapMessage)
            data = remaining

        self._messageId += 1
        return answers

    def sendReceive(self, protocolOp, message):
        self.send(protocolOp, message)
        return self.recv()

class LDAPSessionError(Exception):
    """
    This is the exception every client should catch
    """
    def __init__( self, error = 0, packet=0, errorString=''):
        Exception.__init__(self)
        self.error = error
        self.packet = packet
        self.errorString = errorString

    def getErrorCode( self ):
        return self.error

    def getErrorPacket( self ):
        return self.packet

    def getErrorString( self ):
        return self.errorString

    def __str__( self ):
        return self.errorString

class LDAPSearchError(LDAPSessionError):
    def __init__( self, error = 0, packet=0, errorString='', answers = []):
        LDAPSessionError.__init__(self, error, packet, errorString)
        self.answers = answers

    def getAnswers( self ):
        return self.answers


