#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: DCE/RPC SAMR dumper.
#
# Author:
#  Javier Kohen <jkohen@coresecurity.com>
#  Alberto Solino <bethus@gmail.com>
#
# Reference for:
#  DCE/RPC for SAMR

import socket
import string
import sys
import types

from impacket import uuid, version
from impacket.dcerpc import transport, samr
import argparse


class ListUsersException(Exception):
    pass

class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
        }


    def __init__(self, protocols = None,
                 username = '', password = '', domain = '', hashes = None):
        if not protocols:
            protocols = SAMRDump.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__protocols = [protocols]
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')


    def dump(self, addr):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """

        encoding = sys.getdefaultencoding()

        print 'Retrieving endpoint list from %s' % addr

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = SAMRDump.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            rpctransport = transport.SMBTransport(addr, port, r'\samr', self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

            try:
                entries = self.__fetchList(rpctransport)
            except Exception, e:
                print 'Protocol failed: %s' % e
                raise
            else:
                # Got a response. No need for further iterations.
                break


        # Display results.

        for entry in entries:
            (username, uid, user) = entry
            base = "%s (%d)" % (username, uid)
            print base + '/Enabled:', ('false', 'true')[user.is_enabled()]
            print base + '/Last Logon:', user.get_logon_time()
            print base + '/Last Logoff:', user.get_logoff_time()
            print base + '/Kickoff:', user.get_kickoff_time()
            print base + '/Last PWD Set:', user.get_pwd_last_set()
            print base + '/PWD Can Change:', user.get_pwd_can_change()
            print base + '/PWD Must Change:', user.get_pwd_must_change()
            print base + '/Group id: %d' % user.get_group_id()
            print base + '/Bad pwd count: %d' % user.get_bad_pwd_count()
            print base + '/Logon count: %d' % user.get_logon_count()
            items = user.get_items()
            for i in samr.MSRPCUserInfo.ITEMS.keys():
                name = items[samr.MSRPCUserInfo.ITEMS[i]].get_name()
                name = name.encode(encoding, 'replace')
                print base + '/' + i + ':', name

        if entries:
            num = len(entries)
            if 1 == num:
                print 'Received one entry.'
            else:
                print 'Received %d entries.' % num
        else:
            print 'No entries received.'


    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()

        encoding = sys.getdefaultencoding()
        entries = []

        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        rpcsamr = samr.DCERPCSamr(dce)

        try:
            resp = rpcsamr.connect()
            if resp.get_return_code() != 0:
                raise ListUsersException, 'Connect error'

            _context_handle = resp.get_context_handle()
            resp = rpcsamr.enumdomains(_context_handle)
            if resp.get_return_code() != 0:
                raise ListUsersException, 'EnumDomain error'

            domains = resp.get_domains().elements()

            print 'Found domain(s):'
            for i in range(0, resp.get_entries_num()):
                print " . %s" % domains[i].get_name()

            print "Looking up users in domain %s" % domains[0].get_name()
            resp = rpcsamr.lookupdomain(_context_handle, domains[0])
            if resp.get_return_code() != 0:
                raise ListUsersException, 'LookupDomain error'

            resp = rpcsamr.opendomain(_context_handle, resp.get_domain_sid())
            if resp.get_return_code() != 0:
                raise ListUsersException, 'OpenDomain error'

            domain_context_handle = resp.get_context_handle()
            resp = rpcsamr.enumusers(domain_context_handle)
            if resp.get_return_code() != 0 and resp.get_return_code() != 0x105:
                raise ListUsersException, 'OpenDomainUsers error'

            done = False
            while done is False:
                for user in resp.get_users().elements():
                    uname = user.get_name().encode(encoding, 'replace')
                    uid = user.get_id()

                    r = rpcsamr.openuser(domain_context_handle, uid)
                    print "Found user: %s, uid = %d" % (uname, uid)

                    if r.get_return_code() == 0:
                        info = rpcsamr.queryuserinfo(r.get_context_handle()).get_user_info()
                        entry = (uname, uid, info)
                        entries.append(entry)
                        c = rpcsamr.closerequest(r.get_context_handle())

                # Do we have more users?
                if resp.get_return_code() == 0x105:
                    resp = rpcsamr.enumusers(domain_context_handle, resp.get_resume_handle())
                else:
                    done = True
        except ListUsersException, e:
            print "Error listing users: %s" % e

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('protocol', choices=SAMRDump.KNOWN_PROTOCOLS.keys(), nargs='?', default='445/SMB', help='transport protocol (default 445/SMB)')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    dumper = SAMRDump(options.protocol, username, password, domain, options.hashes)
    dumper.dump(address)
