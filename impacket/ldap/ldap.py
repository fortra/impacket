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
# ToDo:
# [x] Implement Paging Search, especially important for big requests
#

import os
import re
import socket

from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError

from impacket import LOG
from impacket.ldap.ldapasn1 import *
from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

try:
    import OpenSSL
    from OpenSSL import SSL, crypto
except:
    LOG.critical("pyOpenSSL is not installed, can't continue")
    raise

__all__ = [
    'LDAPConnection', 'LDAPFilterSyntaxError', 'LDAPFilterInvalidException', 'LDAPSessionError', 'LDAPSearchError',
    'Control', 'SimplePagedResultsControl',
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
]

# https://tools.ietf.org/search/rfc4515#section-3
DESC = r'(?:[a-z][a-z0-9\-]*)'
NUM_OID = r'(?:(?:\d|[1-9]\d+)(?:\.(?:\d|[1-9]\d+))*)'
OID = r'(?:{0}|{1})'.format(DESC, NUM_OID)
OPTIONS = r'(?:(?:;[a-z0-9\-]+)*)'
ATTR = r'({0}{1})'.format(OID, OPTIONS)
DN = r'(?::(dn))'
RULE = r'(?::({0}))'.format(OID)

RE_OPERATOR = re.compile(r'([:<>~]?=)')
RE_ATTRIBUTE = re.compile(r'^{0}$'.format(ATTR), re.I)
RE_EX_ATTRIBUTE_1 = re.compile(r'^{0}{1}?{2}?$'.format(ATTR, DN, RULE), re.I)
RE_EX_ATTRIBUTE_2 = re.compile(r'^(){{0}}{0}?{1}$'.format(DN, RULE), re.I)


class LDAPConnection:
    def __init__(self, url, baseDN='', dstIp=None):
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

        if url.startswith('ldap://'):
            self._dstPort = 389
            self._SSL = False
            self._dstHost = url[7:]
        elif url.startswith('ldaps://'):
            self._dstPort = 636
            self._SSL = True
            self._dstHost = url[8:]
        else:
            raise LDAPSessionError(errorString='Unknown URL prefix {0}'.format(url))

        # Try to connect
        if self._dstIp is not None:
            targetHost = self._dstIp
        else:
            targetHost = self._dstHost

        LOG.debug('Connecting to {0}, port {1:d}, SSL {2}'.format(targetHost, self._dstPort, self._SSL))
        try:
            af, socktype, proto, _, sa = socket.getaddrinfo(targetHost, self._dstPort, 0, socket.SOCK_STREAM)[0]
            self._socket = socket.socket(af, socktype, proto)
        except socket.error as e:
            raise socket.error('Connection error ({0}:{1})'.format(targetHost, 88), e)

        if self._SSL is False:
            self._socket.connect(sa)
        else:
            # Switching to TLS now
            ctx = SSL.Context(SSL.TLSv1_METHOD)
            # ctx.set_cipher_list('RC4')
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
            if len(lmhash) % 2:
                lmhash = '0' + lmhash
            if len(nthash) % 2:
                nthash = '0' + nthash
            try:  # just in case they were converted already
                lmhash = lmhash.decode('hex')
                nthash = nthash.decode('hex')
            except TypeError:
                pass

        # Importing down here so pyasn1 is not required if kerberos is not used.
        from impacket.krb5.ccache import CCache
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        import datetime

        if TGT is not None or TGS is not None:
            useCache = False

        if useCache:
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
                LOG.debug('Using Kerberos Cache: {0}'.format(os.getenv('KRB5CCNAME')))
                principal = 'ldap/{0}@{1}'.format(self._dstHost.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = 'krbtgt/{0}@{1}'.format(domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        LOG.debug('Using TGT from cache')
                    else:
                        LOG.debug('No valid credentials found in cache')
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
            serverName = Principal('ldap/{0}'.format(self._dstHost),
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

        opts = []
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
        bindRequest['version'] = 3
        bindRequest['name'] = user
        bindRequest['authentication']['sasl']['mechanism'] = 'GSS-SPNEGO'
        bindRequest['authentication']['sasl']['credentials'] = blob.getData()

        resp = self.sendReceive(bindRequest)[0]['protocolOp']

        if resp['bindResponse']['resultCode'] != RESULT_SUCCESS:
            raise LDAPSessionError(errorString='Error in bindRequest -> {0}: {1}'.format(
                resp['bindResponse']['resultCode'].prettyPrint(), resp['bindResponse']['diagnosticMessage']))

        return True

    def login(self, user='', password='', domain='', lmhash='', nthash='', authenticationChoice='sicilyNegotiate'):
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
        bindRequest['name'] = user

        if authenticationChoice == 'simple':
            if '.' in domain:
                name = user + '@' + domain
            elif domain:
                name = domain + '\\' + user
            else:
                name = user
            bindRequest['name'] = name
            bindRequest['authentication']['simple'] = password
            resp = self.sendReceive(bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyPackageDiscovery':
            bindRequest['authentication']['sicilyPackageDiscovery'] = ''
            resp = self.sendReceive(bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyNegotiate':
            # Deal with NTLM Authentication
            if lmhash != '' or nthash != '':
                if len(lmhash) % 2:
                    lmhash = '0' + lmhash
                if len(nthash) % 2:
                    nthash = '0' + nthash
                try:  # just in case they were converted already
                    lmhash = lmhash.decode('hex')
                    nthash = nthash.decode('hex')
                except TypeError:
                    pass

            # NTLM Negotiate
            negotiate = getNTLMSSPType1('', domain)
            bindRequest['authentication']['sicilyNegotiate'] = negotiate
            resp = self.sendReceive(bindRequest)[0]['protocolOp']

            # NTLM Challenge
            type2 = resp['bindResponse']['matchedDN']

            # NTLM Auth
            type3, exportedSessionKey = getNTLMSSPType3(negotiate, str(type2), user, password, domain, lmhash, nthash)
            bindRequest['authentication']['sicilyResponse'] = type3
            resp = self.sendReceive(bindRequest)[0]['protocolOp']
        else:
            raise LDAPSessionError(errorString='Unknown authenticationChoice {0}'.format(authenticationChoice))

        if resp['bindResponse']['resultCode'] != RESULT_SUCCESS:
            raise LDAPSessionError(errorString='Error in bindRequest -> {0}: {1}'.format(
                resp['bindResponse']['resultCode'].prettyPrint(), resp['bindResponse']['diagnosticMessage']))

        return True

    def search(self, searchBase=None, scope=SCOPE_SUB, searchFilter='(objectClass=*)', attributes=None,
               derefAliases=DEREF_NEVER, sizeLimit=0, searchControls=None):
        if searchBase is None:
            searchBase = self._baseDN
        if attributes is None:
            attributes = []

        searchRequest = SearchRequest()
        searchRequest['baseObject'] = searchBase
        searchRequest['scope'] = scope
        searchRequest['derefAliases'] = derefAliases
        searchRequest['sizeLimit'] = sizeLimit
        searchRequest['timeLimit'] = 0
        searchRequest['typesOnly'] = False
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
                    if searchResult['resultCode'] == RESULT_SUCCESS:
                        done = self._handleControls(searchControls, message['controls'])
                    else:
                        raise LDAPSearchError(error=int(searchResult['resultCode']),
                                              errorString='Error in searchRequest -> {0}: {1}'.format(
                                                  searchResult['resultCode'].prettyPrint(),
                                                  searchResult['diagnosticMessage']),
                                              answers=answers)
                else:
                    answers.append(searchResult)

        return answers

    def _handleControls(self, requestControls, resultControls):
        done = True
        if requestControls is not None:
            for requestControl in requestControls:
                if resultControls is not None:
                    for resultControl in resultControls:
                        if requestControl['controlType'] == CONTROL_PAGEDRESULTS:
                            if resultControl['controlType'] == CONTROL_PAGEDRESULTS:
                                if resultControl.getCookie():
                                    done = False
                                requestControl.setCookie(resultControl.getCookie())
                                break
                        else:
                            # handle different controls here
                            pass
        return done

    def close(self):
        if self._socket is not None:
            self._socket.close()

    def send(self, request, controls=None):
        if controls is None:
            controls = []

        message = LDAPMessage()
        message['messageID'] = self._messageId
        message['protocolOp'].setComponentByType(request.tagSet, request)
        message['controls'].setComponents(*controls)

        data = encoder.encode(message)

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

        response = []
        while len(data) > 0:
            try:
                message, remaining = decoder.decode(data, asn1Spec=LDAPMessage())
            except SubstrateUnderrunError:
                # We need more data
                remaining = data + self._socket.recv(REQUEST_SIZE)
            else:
                if message['messageID'] == 0:  # unsolicited notification
                    extendedResponse = message['protocolOp']['extendedResp']
                    responseName = extendedResponse['responseName'] or message['responseName']
                    notification = KNOWN_NOTIFICATIONS.get(responseName,
                                                           "Unsolicited Notification '{0}'".format(responseName))
                    if responseName == NOTIFICATION_DISCONNECT:  # Server has disconnected
                        self.close()
                    raise LDAPSessionError(error=int(extendedResponse['resultCode']),
                                           errorString="{0} -> {1}: {2}".format(
                                               notification,
                                               extendedResponse['resultCode'].prettyPrint(),
                                               extendedResponse['diagnosticMessage']))
                response.append(message)
            data = remaining

        self._messageId += 1
        return response

    def sendReceive(self, request, controls=None):
        self.send(request, controls)
        return self.recv()

    def _parseFilter(self, filterStr):
        filterList = list(reversed(unicode(filterStr)))
        searchFilter = self._consumeCompositeFilter(filterList)
        if filterList:  # we have not consumed the whole filter string
            raise LDAPFilterSyntaxError("unexpected token: '{0}'".format(filterList[-1]))
        return searchFilter

    def _consumeCompositeFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':  # filter must start with a '('
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '{0}'".format(c))

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
            raise LDAPFilterSyntaxError("unexpected token: '{0}'".format(c))

        return self._compileCompositeFilter(operator, filters)

    def _consumeSimpleFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':  # filter must start with a '('
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '{0}'".format(c))

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
            raise LDAPFilterInvalidException("invalid filter: '({0})'".format(filterStr))

        return self._compileSimpleFilter(attribute, operator, value)

    @staticmethod
    def _compileCompositeFilter(operator, filters):
        searchFilter = Filter()
        if operator == '!':
            if len(filters) != 1:
                raise LDAPFilterInvalidException("'not' filter must have exactly one element")
            name = 'not'
        elif operator == '&':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'and' filter must have at least one element")
            name = 'and'
        elif operator == '|':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'or' filter must have at least one element")
            name = 'or'
        searchFilter[name].setComponents(*filters)

        return searchFilter

    @staticmethod
    def _compileSimpleFilter(attribute, operator, value):
        searchFilter = Filter()
        if operator == ':=':  # extensibleMatch
            match = RE_EX_ATTRIBUTE_1.match(attribute) or RE_EX_ATTRIBUTE_2.match(attribute)
            if not match:
                raise LDAPFilterInvalidException("invalid filter attribute: '{0}'".format(attribute))
            attribute, dn, matchingRule = match.groups()
            if attribute:
                searchFilter['extensibleMatch']['type'] = attribute
            if dn:
                searchFilter['extensibleMatch']['dnAttributes'] = bool(dn)
            if matchingRule:
                searchFilter['extensibleMatch']['matchingRule'] = matchingRule
            searchFilter['extensibleMatch']['matchValue'] = value
        else:
            if not RE_ATTRIBUTE.match(attribute):
                raise LDAPFilterInvalidException("invalid filter attribute: '{0}'".format(attribute))
            if value == '*' and operator == '=':  # present
                searchFilter['present'] = attribute
            elif '*' in value and operator == '=':  # substring
                assertions = value.split('*')
                choice = searchFilter['substrings']['substrings'].getComponentType()
                substrings = []
                for i, assertion in enumerate(assertions):
                    if i == 0:
                        name = 'initial'
                    elif i == len(assertions) - 1:
                        name = 'final'
                    else:
                        name = 'any'
                    if assertion or name == 'any':
                        substrings.append(choice.clone().setComponentByName(name, assertion))
                searchFilter['substrings']['type'] = attribute
                searchFilter['substrings']['substrings'].setComponents(*substrings)
            elif '*' not in value:  # simple
                if operator == '=':
                    name = 'equalityMatch'
                elif operator == '~=':
                    name = 'approxMatch'
                elif operator == '>=':
                    name = 'greaterOrEqual'
                elif operator == '<=':
                    name = 'lessOrEqual'
                searchFilter[name].setComponents(attribute, value)
            else:
                raise LDAPFilterInvalidException("invalid filter '({0}{1}{2})'".format(attribute, operator, value))

        return searchFilter


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
    def __init__(self, error=0, packet=0, errorString='', answers=[]):
        LDAPSessionError.__init__(self, error, packet, errorString)
        self.answers = answers

    def getAnswers(self):
        return self.answers
