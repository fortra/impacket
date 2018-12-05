#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: DCE/RPC SAMR dumper.
#
# Author:
#  Javier Kohen <jkohen@coresecurity.com>
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC for SAMR

import sys
import logging
import argparse
import codecs

from datetime import datetime
from impacket.examples import logger
from impacket import version
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smb import SMB_DIALECT

class ListUsersException(Exception):
    pass

class SAMRDump:
    def __init__(self, username='', password='', domain='', hashes=None,
                 aesKey=None, doKerberos=False, kdcHost=None, port=445, csvOutput=False):

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__port = port
        self.__csvOutput = csvOutput

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def dump(self, remoteName, remoteHost):
        """Dumps the list of users and shares registered present at
        remoteName. remoteName is a valid host name or IP address.
        """

        entries = []

        logging.info('Retrieving endpoint list from %s' % remoteName)

        stringbinding = 'ncacn_np:%s[\pipe\samr]' % remoteName
        logging.debug('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport,'preferred_dialect'):
            rpctransport.preferred_dialect(SMB_DIALECT)
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aesKey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        try:
            entries = self.__fetchList(rpctransport)
        except Exception, e:
            logging.critical(str(e))

        # Display results.

        if self.__csvOutput is True:
            print '#Name,RID,FullName,PrimaryGroupId,BadPasswordCount,LogonCount,PasswordLastSet,PasswordDoesNotExpire,AccountIsDisabled,UserComment,ScriptPath'

        for entry in entries:
            (username, uid, user) = entry
            pwdLastSet = (user['PasswordLastSet']['HighPart'] << 32) + user['PasswordLastSet']['LowPart']
            if pwdLastSet == 0:
                pwdLastSet = '<never>'
            else:
                pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(pwdLastSet)))

            if user['UserAccountControl'] & samr.USER_DONT_EXPIRE_PASSWORD:
                dontExpire = 'True'
            else:
                dontExpire = 'False'

            if user['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED:
                accountDisabled = 'True'
            else:
                accountDisabled = 'False'

            if self.__csvOutput is True:
                print '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s' % (username, uid, user['FullName'], user['PrimaryGroupId'],
                                                      user['BadPasswordCount'], user['LogonCount'],pwdLastSet,
                                                      dontExpire, accountDisabled, user['UserComment'].replace(',','.'),
                                                      user['ScriptPath']  )
            else:
                base = "%s (%d)" % (username, uid)
                print base + '/FullName:', user['FullName']
                print base + '/UserComment:', user['UserComment']
                print base + '/PrimaryGroupId:', user['PrimaryGroupId']
                print base + '/BadPasswordCount:', user['BadPasswordCount']
                print base + '/LogonCount:', user['LogonCount']
                print base + '/PasswordLastSet:',pwdLastSet
                print base + '/PasswordDoesNotExpire:',dontExpire
                print base + '/AccountIsDisabled:',accountDisabled
                print base + '/ScriptPath:', user['ScriptPath']

        if entries:
            num = len(entries)
            if 1 == num:
                logging.info('Received one entry.')
            else:
                logging.info('Received %d entries.' % num)
        else:
            logging.info('No entries received.')


    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        try:
            resp = samr.hSamrConnect(dce)
            serverHandle = resp['ServerHandle'] 

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = resp['Buffer']['Buffer']

            print 'Found domain(s):'
            for domain in domains:
                print " . %s" % domain['Name']

            logging.info("Looking up users in domain %s" % domains[0]['Name'])

            resp = samr.hSamrLookupDomainInSamServer(dce, serverHandle,domains[0]['Name'] )

            resp = samr.hSamrOpenDomain(dce, serverHandle = serverHandle, domainId = resp['DomainId'])
            domainHandle = resp['DomainHandle']

            status = STATUS_MORE_ENTRIES
            enumerationContext = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, enumerationContext = enumerationContext)
                except DCERPCException, e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise 
                    resp = e.get_packet()

                for user in resp['Buffer']['Buffer']:
                    r = samr.hSamrOpenUser(dce, domainHandle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                    print "Found user: %s, uid = %d" % (user['Name'], user['RelativeId'] )
                    info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                    entries.append(entry)
                    samr.hSamrCloseHandle(dce, r['UserHandle'])

                enumerationContext = resp['EnumerationContext'] 
                status = resp['ErrorCode']

        except ListUsersException, e:
            logging.critical("Error listing users: %s" % e)

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "This script downloads the list of users for the "
                                                                    "target system.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-csv', action='store_true', help='Turn CSV output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store',metavar = "ip address", help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. If '
                       'ommited it will use whatever was specified as target. This is useful when target is the NetBIOS '
                       'name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]
        
    if domain is None:
        domain = ''

    if options.target_ip is None:
        options.target_ip = remoteName

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    dumper = SAMRDump(username, password, domain, options.hashes, options.aesKey, options.k, options.dc_ip, int(options.port), options.csv)
    dumper.dump(remoteName, options.target_ip)
