#!/usr/bin/python
# Copyright (c) 2003 CORE Security Technologies
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
#
# Reference for:
#  DCE/RPC.

import socket
import string
import sys
import types

from impacket import uuid
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, samr


class ListUsersException(Exception):
    pass

class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
        }


    def __init__(self, protocols = None,
                 username = '', password = ''):
        if not protocols:
            protocols = SAMRDump.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = protocols


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
            rpctransport = transport.SMBTransport(addr, port, r'\samr', self.__username, self.__password)

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
        dce = dcerpc.DCERPC_v5(rpctransport)

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
            if resp.get_return_code() != 0:
                raise ListUsersException, 'OpenDomainUsers error'

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
        except ListUsersException, e:
            print "Error listing users: %s" % e

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s [username[:password]@]<address> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % SAMRDump.KNOWN_PROTOCOLS.keys()
        print "Username and password are only required for certain transports, eg. SMB."
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        dumper = SAMRDump(sys.argv[2:], username, password)
    else:
        dumper = SAMRDump(username = username, password = password)
    dumper.dump(address)
