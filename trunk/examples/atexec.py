#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# ATSVC example for some functions implemented, creates, enums, runs, delete jobs
# This example executes a command on the target machine through the Task Scheduler 
# service. Returns the output of such command
#
# Author:
#  Alberto Solino (bethus@gmail.com)
#
# Reference for:
#  DCE/RPC for ATSVC

import socket
import string
import sys
import types
import argparse
import time
import random

from impacket import uuid, ntlm, version
from impacket.dcerpc import transport, ndrutils, atsvc
from struct import unpack

class ATSVC_EXEC:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\atsvc]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\atsvc]', 445),
        }


    def __init__(self, username = '', password = '', domain = '', hashes = None, command = None):
        self.__username = username
        self.__password = password
        self.__protocols = ATSVC_EXEC.KNOWN_PROTOCOLS.keys()
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__command = command
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):

        # Try all requested protocols until one works.
        entries = []
        for protocol in self.__protocols:
            protodef = ATSVC_EXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]

            print "Trying protocol %s..." % protocol
            stringbinding = protodef[0] % addr

            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_dport(port)
            if hasattr(rpctransport, 'set_credentials'):
                # This method exists only for selected protocol sequences.
                rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            try:
                self.doStuff(rpctransport)
            except Exception, e:
                print 'Protocol failed: %s' % e
            else:
                # Got a response. No need for further iterations.
                break


    def doStuff(self, rpctransport):
        def output_callback(data):
            print data

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_max_fragment_size(16)
        dce.bind(atsvc.MSRPC_UUID_ATSVC)
        at = atsvc.DCERPCAtSvc(dce)
        tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'

        # Check [MS-TSCH] Section 2.3.4
        atInfo = atsvc.AT_INFO()
        atInfo['JobTime']            = 0
        atInfo['DaysOfMonth']        = 0
        atInfo['DaysOfWeek']         = 0
        atInfo['Flags']              = 0
        atInfo['Command']            = ndrutils.NDRUniqueStringW()
        atInfo['Command']['Data']    = ('%%COMSPEC%% /C %s > %%SYSTEMROOT%%\\Temp\\%s\x00' % (self.__command, tmpFileName)).encode('utf-16le')

        resp = at.NetrJobAdd(('\\\\%s'% rpctransport.get_dip()),atInfo)
        jobId = resp['JobID']

        #resp = at.NetrJobEnum(rpctransport.get_dip())

        # Switching context to TSS
        dce2 = dce.alter_ctx(atsvc.MSRPC_UUID_TSS)
        # Now atsvc should use that new context
        at = atsvc.DCERPCAtSvc(dce2)

        # Leaving this code to show how to enumerate jobs
        #path = '\\'
        #resp = at.SchRpcEnumTasks(path)
        #if resp['Count'] == 1:
        #    print resp['TaskName']['Data']
        #    if resp['ErrorCode'] == atsvc.S_FALSE:
        #        i = 1
        #        done = False
        #        while done is not True:
        #            # More items
        #            try:
        #                resp = at.SchRpcEnumTasks(path,startIndex=i)
        #            except:
        #                break
        #            if resp['Count'] == 1:
        #                 print resp['TaskName']['Data'] 
        #                 i += 1
        #            elif resp['ErrorCode'] != atsvc.S_FALSE:
        #                done = True

        resp = at.SchRpcRun('\\At%d' % jobId)
        # On the first run, it takes a while the remote target to start executing the job
        # so I'm setting this sleep.. I don't like sleeps.. but this is just an example
        # Best way would be to check the task status before attempting to read the file
        time.sleep(3)
        # Switching back to the old ctx_id
        at = atsvc.DCERPCAtSvc(dce)
        resp = at.NetrJobDel('\\\\%s'% rpctransport.get_dip(), jobId, jobId)

        smbConnection = rpctransport.get_smb_connection()
        while True:
            try:
                smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
                break
            except Exception, e:
                if str(e).find('SHARING') > 0:
                    time.sleep(3)
                else:
                    raise
        smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)
 
        dce.disconnect()


# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER
    print "WARNING: This will work ONLY on Windows >= Vista"

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', action='store', nargs='*', default = ' ', help='command to execute at the target ')

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

    atsvc_exec = ATSVC_EXEC(username, password, domain, options.hashes, ' '.join(options.command))
    atsvc_exec.play(address)
