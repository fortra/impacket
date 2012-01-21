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
#import hexdump

from impacket import uuid, ntlm
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, svcctl

class SVCCTL:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        '135/TCP': (r'ncacn_ip_tcp:%s', 135),
        '135/UDP': (r'ncadg_ip_udp:%s', 135),
        }


    def __init__(self, username, password, protocol, service_name=None, action=None):
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

        #dce.set_credentials(self.__username, self.__password)
        dce.connect()
        #dce.set_max_fragment_size(1)
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        rpc = svcctl.DCERPCSvcCtl(dce)
        ans = rpc.OpenSCManagerW()
        scManagerHandle = ans['ContextHandle']
        ans = rpc.OpenServiceW(scManagerHandle, self.__service_name.encode('utf-16le'))
        serviceHandle = ans['ContextHandle']
        if self.__action.upper() == 'START':
            print "Starting service %s" % self.__service_name
            rpc.StartServiceW(serviceHandle)
            rpc.CloseServiceHandle(serviceHandle)
        elif self.__action.upper() == 'STOP':
            print "Stopping service %s" % self.__service_name
            rpc.StopService(serviceHandle)
            rpc.CloseServiceHandle(serviceHandle)
        elif self.__action.upper() == 'DELETE':
            print "Deleting service %s" % self.__service_name
            rpc.DeleteService(serviceHandle)
            rpc.CloseServiceHandle(serviceHandle)
        elif self.__action.upper() == 'STATUS':
            print "Querying status for %s" % self.__service_name
            resp = rpc.QueryServiceStatus(serviceHandle)
            print "%30s - " % (self.__service_name),
            state = resp['CurrentState']
            if state == svcctl.SERVICE_CONTINUE_PENDING:
               print "CONTINUE PENDING"
            elif state == svcctl.SERVICE_PAUSE_PENDING:
               print "PAUSE PENDING"
            elif state == svcctl.SERVICE_PAUSED:
               print "PAUSED"
            elif state == svcctl.SERVICE_RUNNING:
               print "RUNNING"
            elif state == svcctl.SERVICE_START_PENDING:
               print "START PENDING"
            elif state == svcctl.SERVICE_STOP_PENDING:
               print "STOP PENDING"
            elif state == svcctl.SERVICE_STOPPED:
               print "STOPPED"
            else:
               print "UNKOWN"
        elif self.__action.upper() == 'LIST':
            print "Listing services available on target"
            #resp = rpc.EnumServicesStatusW(scManagerHandle, svcctl.SERVICE_WIN32_SHARE_PROCESS )
            #resp = rpc.EnumServicesStatusW(scManagerHandle, svcctl.SERVICE_WIN32_OWN_PROCESS )
            #resp = rpc.EnumServicesStatusW(scManagerHandle, serviceType = svcctl.SERVICE_FILE_SYSTEM_DRIVER, serviceState = svcctl.SERVICE_STATE_ALL )
            resp = rpc.EnumServicesStatusW(scManagerHandle)
            for i in range(len(resp)):
                print "%30s - %70s - " % (resp[i]['ServiceName'].decode('utf-16'), resp[i]['DisplayName'].decode('utf-16')),
                state = resp[i]['CurrentState']
                if state == svcctl.SERVICE_CONTINUE_PENDING:
                   print "CONTINUE PENDING"
                elif state == svcctl.SERVICE_PAUSE_PENDING:
                   print "PAUSE PENDING"
                elif state == svcctl.SERVICE_PAUSED:
                   print "PAUSED"
                elif state == svcctl.SERVICE_RUNNING:
                   print "RUNNING"
                elif state == svcctl.SERVICE_START_PENDING:
                   print "START PENDING"
                elif state == svcctl.SERVICE_STOP_PENDING:
                   print "STOP PENDING"
                elif state == svcctl.SERVICE_STOPPED:
                   print "STOPPED"
                else:
                   print "UNKOWN"
            print "Total Services: %d" % len(resp)

        else:
            print "Unknown action %s" % self.__action

        rpc.CloseServiceHandle(scManagerHandle)

        dce.disconnect()

        return 


# Process command-line arguments.
if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print "Usage: %s [username[:password]@]<address> <servicename> <action> [protocol list...]" % sys.argv[0]
        print "Available protocols: %s" % SVCCTL.KNOWN_PROTOCOLS.keys()
        print "Username and password are only required for certain transports, eg. SMB."
        print "Action: START/STOP/DELETE/STATUS/LIST"
        print "(for LIST specify a random servicename)"
        sys.exit(1)

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(sys.argv[1]).groups('')

    if len(sys.argv) > 2:
        services = SVCCTL(username, password, sys.argv[4:], sys.argv[2], sys.argv[3])
    else:
        services = SVCCTL(username = username, password = password)
    services.run(address)
