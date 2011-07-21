#!/usr/bin/python
# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# SVCCTL services common functions for manipulating services
#
# Author:
#  Alberto Solino
#
# Reference for:
#  DCE/RPC.
# TODO: 
# [ ] Check errors
# [ ] Add Creating a Service

import socket
import string
import sys
import types
import hexdump

from impacket import uuid, ntlm
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, svcctl

class SVCCTL:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        '135/TCP': (r'ncacn_ip_tcp:%s', 135),
        '135/UDP': (r'ncadg_ip_udp:%s', 135),
        }


    def __init__(self, username, password, protocol, service_name, action):
        if not protocol:
            protocol = SVCCTL.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocol = protocol
        self.__service_name = service_name
        self.__action = action


    def run(self, addr):

        # Try all requested protocols until one works.
        for protocol in self.__protocol:
            protodef = SVCCTL.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username,self.__password)

            try:
                self.doStuff(rpctransport)
            except Exception, e:
                print 'Protocol failed: %s' % e
                raise
            else:
                # Got a response. No need for further iterations.
                break


    def doStuff(self, rpctransport):
        # UDP only works over DCE/RPC version 4.
        if isinstance(rpctransport, transport.UDPTransport):
            dce = dcerpc_v4.DCERPC_v4(rpctransport)
        else:
            dce = dcerpc.DCERPC_v5(rpctransport)

        dce.connect()
        dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        rpc = svcctl.DCERPCSvcCtl(dce)
        ans = rpc.OpenSCManagerW()
        scManagerHandle = ans['ContextHandle']
        ans = rpc.OpenServiceW(scManagerHandle, self.__service_name.encode('utf-16le'))
        serviceHandle = ans['ContextHandle']
        if self.__action.upper() == 'START':
            print "Starting service %s" % self.__service_name
            rpc.StartServiceW(serviceHandle)
        elif self.__action.upper() == 'STOP':
            print "Stopping service %s" % self.__service_name
            rpc.StopService(serviceHandle)
        elif self.__action.upper() == 'DELETE':
            print "Deleting service %s" % self.__service_name
            rpc.DeleteService(serviceHandle)
        else:
            print "Unknown action %s" % self.__action

        rpc.CloseServiceHandle(serviceHandle)
        rpc.CloseServiceHandle(scManagerHandle)

        dce.disconnect()

        return 


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s [username[:password]@]<address> <servicename> <action> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % SVCCTL.KNOWN_PROTOCOLS.keys()
        print "Username and password are only required for certain transports, eg. SMB."
        print "Action: START/STOP/DELETE"
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        services = SVCCTL(username, password, sys.argv[4:], sys.argv[2], sys.argv[3])
    else:
        services = SVCCTL(username = username, password = password)
    services.run(address)
