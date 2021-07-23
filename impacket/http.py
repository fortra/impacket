# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
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

import re
import ssl
import base64
import binascii

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

        self.__auth_type = auth_type

        self.__auth_types = []
        self.__ntlmssp_info = None

    def set_auth_type(self, auth_type):
        self.__auth_type = auth_type

    def get_auth_type(self):
        return self.__auth_type

    def get_auth_types(self):
        return self.__auth_types

    def get_ntlmssp_info(self):
        return self.__ntlmssp_info

    def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None):
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

    def connect(self, protocol, host_L6):
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
        if self.__aesKey != '' or self.__TGT != None or self.__TGS != None:
            raise Exception('NTLM authentication in HTTP connection used, ' \
                            'cannot use Kerberos.')

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
