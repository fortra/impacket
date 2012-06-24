#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
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
import argparse
#import hexdump

from impacket import uuid, ntlm, version
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, svcctl

class SVCCTL:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        '135/TCP': (r'ncacn_ip_tcp:%s', 135),
        '135/UDP': (r'ncadg_ip_udp:%s', 135),
        }


    def __init__(self, username, password, protocol, service_name=None, action=None, display_name = None, binary_path = None):
        if not protocol:
            protocol = SVCCTL.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocol = [protocol]
        self.__service_name = service_name
        self.__display_name = display_name
        self.__binary_path = binary_path
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
                print e
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
        if self.__action.upper() != 'LIST' and self.__action.upper() != 'CREATE':
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
        elif self.__action.upper() == 'CONFIG':
            print "Querying service config for %s" % self.__service_name
            resp = rpc.QueryServiceConfigW(serviceHandle)
            print "TYPE              : %2d - " % resp['QueryConfig']['ServiceType'],
            if resp['QueryConfig']['ServiceType'] == 0x1:
                print "SERVICE_KERNLE_DRIVER"
            elif resp['QueryConfig']['ServiceType'] == 0x2:
                print "SERVICE_FILE_SYSTEM_DRIVER"
            elif resp['QueryConfig']['ServiceType'] == 0x10:
                print "SERVICE_WIN32_OWN_PROCESS"
            elif resp['QueryConfig']['ServiceType'] == 0x20:
                print "SERVICE_WIN32_SHARE_PROCESS"
            else:
                print "UNKOWN"
            print "START_TYPE        : %2d - " % resp['QueryConfig']['StartType'],
            if resp['QueryConfig']['StartType'] == 0x0:
                print "BOOT START"
            elif resp['QueryConfig']['StartType'] == 0x1:
                print "SYSTEM START"
            elif resp['QueryConfig']['StartType'] == 0x2:
                print "AUTO START"
            elif resp['QueryConfig']['StartType'] == 0x3:
                print "DEMAND START"
            elif resp['QueryConfig']['StartType'] == 0x4:
                print "DISABLED"
            else:
                print "UNKOWN"

            print "ERROR_CONTROL     : %2d - " % resp['QueryConfig']['ErrorControl'],
            if resp['QueryConfig']['ErrorControl'] == 0x0:
                print "IGNORE"
            elif resp['QueryConfig']['ErrorControl'] == 0x1:
                print "NORMAL"
            elif resp['QueryConfig']['ErrorControl'] == 0x2:
                print "SEVERE"
            elif resp['QueryConfig']['ErrorControl'] == 0x3:
                print "CRITICAL"
            else:
                print "UNKOWN"
            print "BINARY_PATH_NAME  : %s" % resp['QueryConfig']['BinaryPathName'].decode('utf-16le')
            print "LOAD_ORDER_GROUP  : %s" % resp['QueryConfig']['LoadOrderGroup'].decode('utf-16le')
            print "TAG               : %d" % resp['QueryConfig']['TagID']
            print "DISPLAY_NAME      : %s" % resp['QueryConfig']['DisplayName'].decode('utf-16le')
            print "DEPENDENCIES      : %s" % resp['QueryConfig']['Dependencies'].decode('utf-16le').replace('/',' - ')
            print "SERVICE_START_NAME: %s" % resp['QueryConfig']['ServiceStartName'].decode('utf-16le')
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
        elif self.__action.upper() == 'CREATE':
            resp = rpc.CreateServiceW(scManagerHandle,self.__service_name.encode('utf-16le'), self.__display_name.encode('utf-16le'), self.__binary_path.encode('utf-16le'))
        else:
            print "Unknown action %s" % self.__action

        rpc.CloseServiceHandle(scManagerHandle)

        dce.disconnect()

        return 


# Process command-line arguments.
if __name__ == '__main__':

    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[username[:password]@]<address>')
    subparsers = parser.add_subparsers(help='actions', dest='action')
 
    # A start command
    start_parser = subparsers.add_parser('start', help='starts the service')
    start_parser.add_argument('-name', action='store', required=True, help='service name')

    # A stop command
    stop_parser = subparsers.add_parser('stop', help='stops the service')
    stop_parser.add_argument('-name', action='store', required=True, help='service name')

    # A delete command
    delete_parser = subparsers.add_parser('delete', help='deletes the service')
    delete_parser.add_argument('-name', action='store', required=True, help='service name')

    # A status command
    status_parser = subparsers.add_parser('status', help='returns service status')
    status_parser.add_argument('-name', action='store', required=True, help='service name')

    # A config command
    config_parser = subparsers.add_parser('config', help='returns service configuration')
    config_parser.add_argument('-name', action='store', required=True, help='service name')

    # A list command
    list_parser = subparsers.add_parser('list', help='list available services')

    # A create command
    create_parser = subparsers.add_parser('create', help='create a service')
    create_parser.add_argument('-name', action='store', required=True, help='service name')
    create_parser.add_argument('-display', action='store', required=True, help='display name')
    create_parser.add_argument('-path', action='store', required=True, help='binary path')

    parser.add_argument('protocol', choices=SVCCTL.KNOWN_PROTOCOLS.keys() , default='445/SMB', help='transport protocol')
    options = parser.parse_args()

    import re

    username, password, address = re.compile('(?:([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    try:
        service_name = options.name
    except:
        service_name = None

    if options.action.upper() == 'CREATE':
        display_name = options.display
        path = options.path
    else:
        display_name = None
        path = None
        

    services = SVCCTL(username, password, options.protocol, service_name , options.action.upper(), display_name, path)
    try:
        services.run(address)
    except Exception, e:
        print e
