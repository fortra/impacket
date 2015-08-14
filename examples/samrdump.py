#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
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

from impacket.examples import logger
from impacket import version
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5 import transport, samr
from impacket.dcerpc.v5.rpcrt import DCERPCException


class ListUsersException(Exception):
    pass

class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
        }


    def __init__(self, protocols = None,
                 username = '', password = '', domain = '', hashes = None, aesKey=None, doKerberos = False):
        if not protocols:
            self.__protocols = SAMRDump.KNOWN_PROTOCOLS.keys()
        else:
            self.__protocols = [protocols]

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')


    def dump(self, addr):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """

        logging.info('Retrieving endpoint list from %s' % addr)

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = SAMRDump.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            logging.info("Trying protocol %s..." % protocol)
            rpctransport = transport.SMBTransport(addr, port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, doKerberos = self.__doKerberos)

            try:
                entries = self.__fetchList(rpctransport)
            except Exception, e:
                logging.critical(str(e))
            else:
                # Got a response. No need for further iterations.
                break

        # Display results.

        for entry in entries:
            (username, uid, user) = entry
            base = "%s (%d)" % (username, uid)
            print base + '/FullName:', user['FullName']
            print base + '/UserComment:', user['UserComment']
            print base + '/PrimaryGroupId:', user['PrimaryGroupId']
            print base + '/BadPasswordCount:', user['BadPasswordCount']
            print base + '/LogonCount:', user['LogonCount']

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
    print version.BANNER

    parser = argparse.ArgumentParser(add_help = True, description = "This script downloads the list of users for the target system.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('protocol', choices=SAMRDump.KNOWN_PROTOCOLS.keys(), nargs='?', default='445/SMB', help='transport protocol (default 445/SMB)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if domain is None:
        domain = ''

    if options.aesKey is not None:
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    dumper = SAMRDump(options.protocol, username, password, domain, options.hashes, options.aesKey, options.k)
    dumper.dump(address)
