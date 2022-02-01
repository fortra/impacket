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
#   This script will add a computer account to the domain and set its password.
#   Allows to use SAMR over SMB (this way is used by modern Windows computer when
#   adding machines through the GUI) and LDAPS.
#   Plain LDAP is not supported, as it doesn't allow setting the password.
#
# Author:
#   JaGoTu (@jagotu)
#
# Reference for:
#   SMB, SAMR, LDAP
#
# ToDo:
#   [ ]: Complete the process of joining a client computer to a domain via the SAMR protocol
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

import ldap3
import argparse
import logging
import sys
import string
import random
import ssl
import os
from binascii import unhexlify


class ADDCOMPUTER:
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
        self.__computerName = cmdLineOptions.computer_name
        self.__computerPassword = cmdLineOptions.computer_pass
        self.__method = cmdLineOptions.method
        self.__port = cmdLineOptions.port
        self.__domainNetbios = cmdLineOptions.domain_netbios
        self.__noAdd = cmdLineOptions.no_add
        self.__delete = cmdLineOptions.delete
        self.__targetIp = cmdLineOptions.dc_ip
        self.__baseDN = cmdLineOptions.baseDN
        self.__computerGroup = cmdLineOptions.computer_group

        if self.__targetIp is not None:
            self.__kdcHost = self.__targetIp

        if self.__method not in ['SAMR', 'LDAPS']:
            raise ValueError("Unsupported method %s" % self.__method)

        if self.__doKerberos and cmdLineOptions.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use -dc-host.")

        if self.__method == 'LDAPS' and not '.' in self.__domain:
                logging.warning('\'%s\' doesn\'t look like a FQDN. Generating baseDN will probably fail.' % self.__domain)

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        if self.__computerName is None:
            if self.__noAdd:
                raise ValueError("You have to provide a computer name when using -no-add.")
            elif self.__delete:
                raise ValueError("You have to provide a computer name when using -delete.")
        else:
            if self.__computerName[-1] != '$':
                self.__computerName += '$'

        if self.__computerPassword is None:
            self.__computerPassword = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

        if self.__target is None:
            if not '.' in self.__domain:
                logging.warning('No DC host set and \'%s\' doesn\'t look like a FQDN. DNS resolution of short names will probably fail.' % self.__domain)
            self.__target = self.__domain

        if self.__port is None:
            if self.__method == 'SAMR':
                self.__port = 445
            elif self.__method == 'LDAPS':
                self.__port = 636

        if self.__domainNetbios is None:
            self.__domainNetbios = self.__domain

        if self.__method == 'LDAPS' and self.__baseDN is None:
             # Create the baseDN
            domainParts = self.__domain.split('.')
            self.__baseDN = ''
            for i in domainParts:
                self.__baseDN += 'dc=%s,' % i
            # Remove last ','
            self.__baseDN = self.__baseDN[:-1]

        if self.__method == 'LDAPS' and self.__computerGroup is None:
            self.__computerGroup = 'CN=Computers,' + self.__baseDN



    def run_samr(self):
        if self.__targetIp is not None:
            stringBinding = epm.hept_map(self.__targetIp, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        else:
            stringBinding = epm.hept_map(self.__target, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(self.__port)

        if self.__targetIp is not None:
            rpctransport.setRemoteHost(self.__targetIp)
            rpctransport.setRemoteName(self.__target)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)

        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.doSAMRAdd(rpctransport)

    def run_ldaps(self):
        connectTo = self.__target
        if self.__targetIp is not None:
            connectTo = self.__targetIp
        try:
            user = '%s\\%s' % (self.__domain, self.__username)
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            try:
                ldapServer = ldap3.Server(connectTo, use_ssl=True, port=self.__port, get_info=ldap3.ALL, tls=tls)
                if self.__doKerberos:
                    ldapConn = ldap3.Connection(ldapServer)
                    self.LDAP3KerberosLogin(ldapConn, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
                elif self.__hashes is not None:
                    ldapConn = ldap3.Connection(ldapServer, user=user, password=self.__hashes, authentication=ldap3.NTLM)
                    ldapConn.bind()
                else:
                    ldapConn = ldap3.Connection(ldapServer, user=user, password=self.__password, authentication=ldap3.NTLM)
                    ldapConn.bind()

            except ldap3.core.exceptions.LDAPSocketOpenError:
                #try tlsv1
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1)
                ldapServer = ldap3.Server(connectTo, use_ssl=True, port=self.__port, get_info=ldap3.ALL, tls=tls)
                if self.__doKerberos:
                    ldapConn = ldap3.Connection(ldapServer)
                    self.LDAP3KerberosLogin(ldapConn, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
                elif self.__hashes is not None:
                    ldapConn = ldap3.Connection(ldapServer, user=user, password=self.__hashes, authentication=ldap3.NTLM)
                    ldapConn.bind()
                else:
                    ldapConn = ldap3.Connection(ldapServer, user=user, password=self.__password, authentication=ldap3.NTLM)
                    ldapConn.bind()



            if self.__noAdd or self.__delete:
                if not self.LDAPComputerExists(ldapConn, self.__computerName):
                    raise Exception("Account %s not found in %s!" % (self.__computerName, self.__baseDN))

                computer = self.LDAPGetComputer(ldapConn, self.__computerName)

                if self.__delete:
                    res = ldapConn.delete(computer.entry_dn)
                    message = "delete"
                else:
                    res = ldapConn.modify(computer.entry_dn, {'unicodePwd': [(ldap3.MODIFY_REPLACE, ['"{}"'.format(self.__computerPassword).encode('utf-16-le')])]})
                    message = "set password for"


                if not res:
                    if ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                        raise Exception("User %s doesn't have right to %s %s!" % (self.__username, message, self.__computerName))
                    else:
                        raise Exception(str(ldapConn.result))
                else:
                    if self.__noAdd:
                        logging.info("Succesfully set password of %s to %s." % (self.__computerName, self.__computerPassword))
                    else:
                        logging.info("Succesfully deleted %s." % self.__computerName)

            else:
                if self.__computerName is not None:
                    if self.LDAPComputerExists(ldapConn, self.__computerName):
                        raise Exception("Account %s already exists! If you just want to set a password, use -no-add." % self.__computerName)
                else:
                    while True:
                        self.__computerName = self.generateComputerName()
                        if not self.LDAPComputerExists(ldapConn, self.__computerName):
                            break


                computerHostname = self.__computerName[:-1]
                computerDn = ('CN=%s,%s' % (computerHostname, self.__computerGroup))

                # Default computer SPNs
                spns = [
                    'HOST/%s' % computerHostname,
                    'HOST/%s.%s' % (computerHostname, self.__domain),
                    'RestrictedKrbHost/%s' % computerHostname,
                    'RestrictedKrbHost/%s.%s' % (computerHostname, self.__domain),
                ]
                ucd = {
                    'dnsHostName': '%s.%s' % (computerHostname, self.__domain),
                    'userAccountControl': 0x1000,
                    'servicePrincipalName': spns,
                    'sAMAccountName': self.__computerName,
                    'unicodePwd': ('"%s"' % self.__computerPassword).encode('utf-16-le')
                }

                res = ldapConn.add(computerDn, ['top','person','organizationalPerson','user','computer'], ucd)
                if not res:
                    if ldapConn.result['result'] == ldap3.core.results.RESULT_UNWILLING_TO_PERFORM:
                        error_code = int(ldapConn.result['message'].split(':')[0].strip(), 16)
                        if error_code == 0x216D:
                            raise Exception("User %s machine quota exceeded!" % self.__username)
                        else:
                            raise Exception(str(ldapConn.result))
                    elif ldapConn.result['result'] == ldap3.core.results.RESULT_INSUFFICIENT_ACCESS_RIGHTS:
                        raise Exception("User %s doesn't have right to create a machine account!" % self.__username)
                    else:
                        raise Exception(str(ldapConn.result))
                else:
                    logging.info("Successfully added machine account %s with password %s." % (self.__computerName, self.__computerPassword))
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()

            logging.critical(str(e))


    def LDAPComputerExists(self, connection, computerName):
        connection.search(self.__baseDN, '(sAMAccountName=%s)' % computerName)
        return len(connection.entries) ==1

    def LDAPGetComputer(self, connection, computerName):
        connection.search(self.__baseDN, '(sAMAccountName=%s)' % computerName)
        return connection.entries[0]

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
        # try to open connection if closed
        if connection.closed:
            connection.open(read_server_info=False)

        connection.sasl_in_progress = True
        response = connection.post_send_single_response(connection.send('bindRequest', request, None))
        connection.sasl_in_progress = False
        if response[0]['result'] != 0:
            raise Exception(response)

        connection.bound = True

        return True

    def generateComputerName(self):
        return 'DESKTOP-' + (''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + '$')

    def doSAMRAdd(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        servHandle = None
        domainHandle = None
        userHandle = None
        try:
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            samrConnectResponse = samr.hSamrConnect5(dce, '\\\\%s\x00' % self.__target,
                samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN )
            servHandle = samrConnectResponse['ServerHandle']

            samrEnumResponse = samr.hSamrEnumerateDomainsInSamServer(dce, servHandle)
            domains = samrEnumResponse['Buffer']['Buffer']
            domainsWithoutBuiltin = list(filter(lambda x : x['Name'].lower() != 'builtin', domains))

            if len(domainsWithoutBuiltin) > 1:
                domain = list(filter(lambda x : x['Name'].lower() == self.__domainNetbios, domains))
                if len(domain) != 1:
                    logging.critical("This server provides multiple domains and '%s' isn't one of them.", self.__domainNetbios)
                    logging.critical("Available domain(s):")
                    for domain in domains:
                        logging.error(" * %s" % domain['Name'])
                    logging.critical("Consider using -domain-netbios argument to specify which one you meant.")
                    raise Exception()
                else:
                    selectedDomain = domain[0]['Name']
            else:
                selectedDomain = domainsWithoutBuiltin[0]['Name']

            samrLookupDomainResponse = samr.hSamrLookupDomainInSamServer(dce, servHandle, selectedDomain)
            domainSID = samrLookupDomainResponse['DomainId']

            if logging.getLogger().level == logging.DEBUG:
                logging.info("Opening domain %s..." % selectedDomain)
            samrOpenDomainResponse = samr.hSamrOpenDomain(dce, servHandle, samr.DOMAIN_LOOKUP | samr.DOMAIN_CREATE_USER , domainSID)
            domainHandle = samrOpenDomainResponse['DomainHandle']


            if self.__noAdd or self.__delete:
                try:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000073:
                        raise Exception("Account %s not found in domain %s!" % (self.__computerName, selectedDomain))
                    else:
                        raise

                userRID = checkForUser['RelativeIds']['Element'][0]
                if self.__delete:
                    access = samr.DELETE
                    message = "delete"
                else:
                    access = samr.USER_FORCE_PASSWORD_CHANGE
                    message = "set password for"
                try:
                    openUser = samr.hSamrOpenUser(dce, domainHandle, access, userRID)
                    userHandle = openUser['UserHandle']
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        raise Exception("User %s doesn't have right to %s %s!" % (self.__username, message, self.__computerName))
                    else:
                        raise
            else:
                if self.__computerName is not None:
                    try:
                        checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        raise Exception("Account %s already exists! If you just want to set a password, use -no-add." % self.__computerName)
                    except samr.DCERPCSessionError as e:
                        if e.error_code != 0xc0000073:
                            raise
                else:
                    foundUnused = False
                    while not foundUnused:
                        self.__computerName = self.generateComputerName()
                        try:
                            checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                        except samr.DCERPCSessionError as e:
                            if e.error_code == 0xc0000073:
                                foundUnused = True
                            else:
                                raise

                try:
                    createUser = samr.hSamrCreateUser2InDomain(dce, domainHandle, self.__computerName, samr.USER_WORKSTATION_TRUST_ACCOUNT, samr.USER_FORCE_PASSWORD_CHANGE,)
                except samr.DCERPCSessionError as e:
                    if e.error_code == 0xc0000022:
                        raise Exception("User %s doesn't have right to create a machine account!" % self.__username)
                    elif e.error_code == 0xc00002e7:
                        raise Exception("User %s machine quota exceeded!" % self.__username)
                    else:
                        raise

                userHandle = createUser['UserHandle']

            if self.__delete:
                samr.hSamrDeleteUser(dce, userHandle)
                logging.info("Successfully deleted %s." % self.__computerName)
                userHandle = None
            else:
                samr.hSamrSetPasswordInternal4New(dce, userHandle, self.__computerPassword)
                if self.__noAdd:
                    logging.info("Successfully set password of %s to %s." % (self.__computerName, self.__computerPassword))
                else:
                    checkForUser = samr.hSamrLookupNamesInDomain(dce, domainHandle, [self.__computerName])
                    userRID = checkForUser['RelativeIds']['Element'][0]
                    openUser = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, userRID)
                    userHandle = openUser['UserHandle']
                    req = samr.SAMPR_USER_INFO_BUFFER()
                    req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
                    req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT
                    samr.hSamrSetInformationUser2(dce, userHandle, req)
                    logging.info("Successfully added machine account %s with password %s." % (self.__computerName, self.__computerPassword))

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()

            logging.critical(str(e))
        finally:
            if userHandle is not None:
                samr.hSamrCloseHandle(dce, userHandle)
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if servHandle is not None:
                samr.hSamrCloseHandle(dce, servHandle)
            dce.disconnect()

    def run(self):
        if self.__method == 'SAMR':
            self.run_samr()
        elif self.__method == 'LDAPS':
            self.run_ldaps()

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Adds a computer account to domain")

    if sys.version_info.major == 2 and sys.version_info.minor == 7 and sys.version_info.micro < 16: #workaround for https://bugs.python.org/issue11874
        parser.add_argument('account', action='store', help='[domain/]username[:password] Account used to authenticate to DC.')
    else:
        parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('-domain-netbios', action='store', metavar='NETBIOSNAME', help='Domain NetBIOS name. Required if the DC has multiple domains.')
    parser.add_argument('-computer-name', action='store', metavar='COMPUTER-NAME$', help='Name of computer to add.'
                                                                                 'If omitted, a random DESKTOP-[A-Z0-9]{8} will be used.')
    parser.add_argument('-computer-pass', action='store', metavar='password', help='Password to set to computer'
                                                                                 'If omitted, a random [A-Za-z0-9]{32} will be used.')
    parser.add_argument('-no-add', action='store_true', help='Don\'t add a computer, only set password on existing one.')
    parser.add_argument('-delete', action='store_true', help='Delete an existing computer.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-method', choices=['SAMR', 'LDAPS'], default='SAMR', help='Method of adding the computer.'
                                                                                'SAMR works over SMB.'
                                                                                'LDAPS has some certificate requirements'
                                                                                'and isn\'t always available.')


    parser.add_argument('-port', type=int, choices=[139, 445, 636],
                       help='Destination port to connect to. SAMR defaults to 445, LDAPS to 636.')

    group = parser.add_argument_group('LDAP')
    group.add_argument('-baseDN', action='store', metavar='DC=test,DC=local', help='Set baseDN for LDAP.'
                                                                                    'If ommited, the domain part (FQDN) '
                                                                                    'specified in the account parameter will be used.')
    group.add_argument('-computer-group', action='store', metavar='CN=Computers,DC=test,DC=local', help='Group to which the account will be added.'
                                                                                                        'If omitted, CN=Computers will be used,')

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


        executer = ADDCOMPUTER(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
