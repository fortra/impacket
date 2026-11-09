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
#   For MS-RPCH
#   Can be programmed to be used in relay attacks
#   Probably for future MAPI
#
# Authors:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#

import os
import re
import ssl
import base64
import struct
import binascii
import datetime

try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection

from impacket import ntlm, LOG

# Auth types
AUTH_AUTO      = 'Auto'
AUTH_BASIC     = 'Basic'
AUTH_NTLM      = 'NTLM'
AUTH_NEGOTIATE = 'Negotiate'
AUTH_BEARER    = 'Bearer'
AUTH_DIGEST    = 'Digest'

################################################################################
# CLASSES
################################################################################
class HTTPClientSecurityProvider:
    def __init__(self, auth_type=AUTH_AUTO):
        self.__username = None
        self.__password = None
        self.__domain   = None
        self.__lmhash   = ''
        self.__nthash   = ''
        self.__aesKey   = ''
        self.__TGT      = None
        self.__TGS      = None
        self.__kdcHost = None
        self.__useCache = True

        self.__auth_type = auth_type

        self.__auth_types = []
        self.__ntlmssp_info = None
        self.__hostname = None

    def set_auth_type(self, auth_type):
        self.__auth_type = auth_type

    def get_auth_type(self):
        return self.__auth_type

    def get_auth_types(self):
        return self.__auth_types

    def get_ntlmssp_info(self):
        return self.__ntlmssp_info

    def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None, kdcHost=None):
        self.__username = username
        self.__password = password
        self.__domain   = domain

        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash

            try: # just in case they were converted already
                self.__lmhash = binascii.unhexlify(lmhash)
                self.__nthash = binascii.unhexlify(nthash)
            except:
                self.__lmhash = lmhash
                self.__nthash = nthash
                pass

        self.__aesKey = aesKey
        self.__TGT    = TGT
        self.__TGS    = TGS
        self.__kdcHost = kdcHost

    def parse_www_authenticate(self, header):
        ret = []

        if 'NTLM' in header:
            ret.append(AUTH_NTLM)
        if 'Basic' in header:
            ret.append(AUTH_BASIC)
        if 'Negotiate' in header:
            ret.append(AUTH_NEGOTIATE)
        if 'Bearer' in header:
            ret.append(AUTH_BEARER)
        if 'Digest' in header:
            ret.append(AUTH_DIGEST)

        return ret

    def connect(self, protocol, host_L6, hostname=None):
        self.__hostname = hostname
        if protocol == 'http':
            return HTTPConnection(host_L6)
        else:
            try:
                uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                return HTTPSConnection(host_L6, context=uv_context)
            except AttributeError:
                return HTTPSConnection(host_L6)

    def get_auth_headers(self, http_obj, method, path, headers):
        if self.__auth_type == AUTH_BASIC:
            return self.get_auth_headers_basic(http_obj, method, path, headers)
        elif self.__auth_type in [AUTH_AUTO, AUTH_NTLM]:
            return self.get_auth_headers_auto(http_obj, method, path, headers)
        elif self.__auth_type == AUTH_NEGOTIATE:
            return self.get_auth_headers_kerberos(http_obj, method, path, headers)
        else:
            raise Exception('%s auth type not supported' % self.__auth_type)

    def get_auth_headers_basic(self, http_obj, method, path, headers):
        if self.__lmhash != '' or self.__nthash != '' or \
           self.__aesKey != '' or self.__TGT != None or self.__TGS != None:
            raise Exception('Basic authentication in HTTP connection used, '
                            'so set a plaintext credentials to connect.')

        if self.__domain == '':
            auth_line = self.__username + ':' + self.__password
        else:
            auth_line = self.__domain + '\\' + self.__username + ':' + self.__password

        auth_line_http = 'Basic %s' % base64.b64encode(auth_line.encode('UTF-8')).decode('ascii')

        # Format: auth_headers, reserved, ...
        return {'Authorization': auth_line_http}, None

    # It's important that the class contains the separate method that
    # gets NTLM Type 1 value, as this way the class can be programmed to
    # be used in relay attacks
    def send_ntlm_type1(self, http_obj, method, path, headers, negotiateMessage):
        auth_headers = headers.copy()
        auth_headers['Content-Length'] = '0'
        auth_headers['Authorization']  = 'NTLM %s' % base64.b64encode(negotiateMessage).decode('ascii')
        http_obj.request(method, path, headers=auth_headers)
        res = http_obj.getresponse()
        res.read()

        if res.status != 401:
            raise Exception('Status code returned: %d. '
                            'Authentication does not seem required for url %s'
                            % (res.status, path)
                )

        if res.getheader('WWW-Authenticate') is None:
           raise Exception('No authentication requested by '
                           'the server for url %s' % path)

        if self.__auth_types == []:
            self.__auth_types = self.parse_www_authenticate(res.getheader('WWW-Authenticate'))

        if AUTH_NTLM not in self.__auth_types:
            # NTLM auth not supported for url
            return None, None

        try:
            serverChallengeBase64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})',
                                              res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
        except (IndexError, KeyError, AttributeError):
            raise Exception('No NTLM challenge returned from server for url %s' % path)

        if not self.__ntlmssp_info:
            challenge = ntlm.NTLMAuthChallenge(serverChallenge)
            self.__ntlmssp_info = ntlm.AV_PAIRS(challenge['TargetInfoFields'])

        # Format: serverChallenge, reserved, ...
        return serverChallenge, None

    def get_auth_headers_auto(self, http_obj, method, path, headers):
        auth = ntlm.getNTLMSSPType1(domain=self.__domain)
        serverChallenge = self.send_ntlm_type1(http_obj, method, path, headers, auth.getData())[0]

        if serverChallenge is not None:
            self.__auth_type = AUTH_NTLM

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, serverChallenge, self.__username,
                                                             self.__password, self.__domain,
                                                             self.__lmhash, self.__nthash)

            auth_line_http = 'NTLM %s' % base64.b64encode(type3.getData()).decode('ascii')
        else:
            if self.__auth_type == AUTH_AUTO and AUTH_BASIC in self.__auth_types:
                self.__auth_type = AUTH_BASIC
                return self.get_auth_headers_basic(http_obj, method, path, headers)
            else:
                raise Exception('No supported auth offered by URL: %s' % self.__auth_types)

        # Format: auth_headers, reserved, ...
        return {'Authorization': auth_line_http}, None

    def get_auth_headers_kerberos(self, http_obj, method, path, headers):
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        from impacket.krb5.gssapi import KRB5_AP_REQ
        from impacket.krb5.ccache import CCache
        from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, ASN1_OID, asn1encode, ASN1_AID
        from pyasn1.codec.der import decoder, encoder
        from pyasn1.type.univ import noValue

        if self.__TGT is not None or self.__TGS is not None:
            self.__useCache = False

        if self.__useCache is True:
            try:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            except:
                # No cache present
                pass
            else:
                LOG.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
                # retrieve domain information from CCache file if needed
                if self.__domain == '':
                    self.__domain = ccache.principal.realm['data'].decode('utf-8')
                    LOG.debug('Domain retrieved from CCache: %s' % self.__domain)

                principal = 'HTTP/%s@%s' % (self.__hostname, self.__domain.upper())
                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = 'krbtgt/%s@%s' % (self.__domain.upper(),self.__domain.upper())
                    creds =  ccache.getCredential(principal)
                    if creds is not None:
                        self.__TGT = creds.toTGT()
                        LOG.debug('Using TGT from cache')
                    else:
                        LOG.debug("No valid credentials found in cache. ")
                else:
                    self.__TGS = creds.toTGS(principal)
                    LOG.debug('Using TGS from cache')

                # retrieve user information from CCache file if needed
                if self.__username == '' and creds is not None:
                    self.__username = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                    LOG.debug('Username retrieved from CCache: %s' % self.__username)
                elif self.__username == '' and len(ccache.principal.components) > 0:
                    self.__username = ccache.principal.components[0]['data'].decode('utf-8')
                    LOG.debug('Username retrieved from CCache: %s' % self.__username)


        # First of all, we need to get a TGT for the user
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if self.__TGT is None:
            if self.__TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            tgt = self.__TGT['KDC_REP']
            cipher = self.__TGT['cipher']
            sessionKey = self.__TGT['sessionKey']

        if self.__TGS is None:
            serverName = Principal('HTTP/%s' % (self.__hostname), type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.__domain, self.__kdcHost, tgt, cipher, sessionKey)
        else:
            tgs = self.__TGS['KDC_REP']
            cipher = self.__TGS['cipher']
            sessionKey = self.__TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

        blob = SPNEGO_NegTokenInit()

        # Kerberos
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        # Let's extract the ticket from the TGS
        tgs = decoder.decode(tgs, asn1Spec = TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        # Now let's build the AP_REQ
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        #Handle mutual authentication
        opts = list()
        opts.append(constants.APOptions.mutual_required.value)

        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.__domain
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

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = struct.pack('B', ASN1_AID) + asn1encode( struct.pack('B', ASN1_OID) + asn1encode(
            TypesMech['KRB5 - Kerberos 5'] ) + KRB5_AP_REQ + encoder.encode(apReq))

        auth_line_http = 'Negotiate %s' % base64.b64encode(blob.getData()).decode('ascii')
        return {'Authorization': auth_line_http}, None
