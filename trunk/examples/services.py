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
        }


    def __init__(self, username, password, domain, options):
        self.__username = username
        self.__password = password
        self.__protocol = SVCCTL.KNOWN_PROTOCOLS.keys()
        self.__options = options
        self.__action = options.action.upper()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if options.hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')



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
                rpctransport.set_credentials(self.__username,self.__password, self.__domain, self.__lmhash, self.__nthash)

            try:
                self.doStuff(rpctransport)
            except Exception, e:
                #import traceback
                #traceback.print_exc()
                print e
                break
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
        if self.__action != 'LIST' and self.__action != 'CREATE':
            ans = rpc.OpenServiceW(scManagerHandle, self.__options.name.encode('utf-16le'))
            serviceHandle = ans['ContextHandle']

        if self.__action == 'START':
            print "Starting service %s" % self.__options.name
            rpc.StartServiceW(serviceHandle)
            rpc.CloseServiceHandle(serviceHandle)
        elif self.__action == 'STOP':
            print "Stopping service %s" % self.__options.name
            rpc.StopService(serviceHandle)
            rpc.CloseServiceHandle(serviceHandle)
        elif self.__action == 'DELETE':
            print "Deleting service %s" % self.__options.name
            rpc.DeleteService(serviceHandle)
            rpc.CloseServiceHandle(serviceHandle)
        elif self.__action == 'CONFIG':
            print "Querying service config for %s" % self.__options.name
            resp = rpc.QueryServiceConfigW(serviceHandle)
            print "TYPE              : %2d - " % resp['QueryConfig']['ServiceType'],
            if resp['QueryConfig']['ServiceType'] & 0x1:
                print "SERVICE_KERNLE_DRIVER ",
            if resp['QueryConfig']['ServiceType'] & 0x2:
                print "SERVICE_FILE_SYSTEM_DRIVER ",
            if resp['QueryConfig']['ServiceType'] & 0x10:
                print "SERVICE_WIN32_OWN_PROCESS ",
            if resp['QueryConfig']['ServiceType'] & 0x20:
                print "SERVICE_WIN32_SHARE_PROCESS ",
            if resp['QueryConfig']['ServiceType'] & 0x100:
                print "SERVICE_INTERACTIVE_PROCESS ",
            print ""
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
        elif self.__action == 'STATUS':
            print "Querying status for %s" % self.__options.name
            resp = rpc.QueryServiceStatus(serviceHandle)
            print "%30s - " % (self.__options.name),
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
        elif self.__action == 'LIST':
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
        elif self.__action == 'CREATE':
            resp = rpc.CreateServiceW(scManagerHandle,self.__options.name.encode('utf-16le'), self.__options.display.encode('utf-16le'), self.__options.path.encode('utf-16le'))
        elif self.__action == 'CHANGE':
            if self.__options.start_type is not None:
                start_type = int(self.__options.start_type)
            else:
                start_type = None
            if self.__options.service_type is not None:
                service_type = int(self.__options.service_type)
            else:
                service_type = None

            if self.__options.display is not None:
                display = self.__options.display.encode('utf-16le')
            else:
                display = None
 
            if self.__options.path is not None:
                path = self.__options.path.encode('utf-16le')
            else:
                path = None
 
            start_name = None
            password = None
#            if self.__options.start_name is not None:
#                start_name = self.__options.start_name.encode('utf-16le')
#            else:
#                start_name = None
#
#            if self.__options.password is not None:
#                password = self.__options.password.encode('utf-16le')
#            else:
#                password = None
 

            resp = rpc.ChangeServiceConfigW(serviceHandle,  display, path, service_type, start_type, start_name, password)
            rpc.CloseServiceHandle(serviceHandle)
        else:
            print "Unknown action %s" % self.__action

        rpc.CloseServiceHandle(scManagerHandle)

        dce.disconnect()

        return 


# Process command-line arguments.
if __name__ == '__main__':

    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<address>')
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

    # A change command
    create_parser = subparsers.add_parser('change', help='change a service configuration')
    create_parser.add_argument('-name', action='store', required=True, help='service name')
    create_parser.add_argument('-display', action='store', required=False, help='display name')
    create_parser.add_argument('-path', action='store', required=False, help='binary path')
    create_parser.add_argument('-service_type', action='store', required=False, help='service type')
    create_parser.add_argument('-start_type', action='store', required=False, help='service start type')
    #create_parser.add_argument('-start_name', action='store', required=False, help='string that specifies the name of the account under which the service should run')
    #create_parser.add_argument('-password', action='store', required=False, help='string that contains the password of the account whose name was specified by the start_name parameter')

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

    services = SVCCTL(username, password, domain, options)
    try:
        services.run(address)
    except Exception, e:
        print e
