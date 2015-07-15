#!/usr/bin/python
# Copyright (c) 2003-2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# ATSVC example for some functions implemented, creates, enums, runs, delete jobs
# This example executes a command on the target machine through the Task Scheduler 
# service. Returns the output of such command
#
# Author:
#  Alberto Solino (@agsolino)
#
# Reference for:
#  DCE/RPC for ATSVC

import string
import sys
import argparse
import time
import random
import logging

from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5 import tsch, atsvc, transport
from impacket.dcerpc.v5.dtypes import NULL


class ATSVC_EXEC:
    def __init__(self, username='', password='', domain='', hashes=None, aesKey=None, doKerberos=False, command=None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__command = command
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def play(self, addr):
        stringbinding = r'ncacn_np:%s[\pipe\atsvc]' % addr
        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                         self.__aesKey)
            rpctransport.set_kerberos(self.__doKerberos)
        try:
            self.doStuff(rpctransport)
        except Exception, e:
            #import traceback
            #traceback.print_exc()
            logging.error(e)

    def doStuff(self, rpctransport):
        def output_callback(data):
            print data

        dce = rpctransport.get_dce_rpc()

        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        #dce.set_max_fragment_size(16)
        dce.bind(atsvc.MSRPC_UUID_ATSVC)
        tmpFileName = ''.join([random.choice(string.letters) for _ in range(8)]) + '.tmp'

        # Check [MS-TSCH] Section 2.3.4
        atInfo = atsvc.AT_INFO()
        atInfo['JobTime']    = NULL
        atInfo['DaysOfMonth']= 0
        atInfo['DaysOfWeek'] = 0
        atInfo['Flags']      = 0
        atInfo['Command']    = ('%%COMSPEC%% /C %s > %%SYSTEMROOT%%\\Temp\\%s 2>&1\x00' % (self.__command, tmpFileName))

        resp = atsvc.hNetrJobAdd(dce, NULL ,atInfo)
        jobId = resp['pJobId']

        #resp = at.NetrJobEnum(rpctransport.get_dip())

        # Switching context to TSS
        dce2 = dce.alter_ctx(tsch.MSRPC_UUID_TSCHS)

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

        tsch.hSchRpcRun(dce2, '\\At%d' % jobId)
        # On the first run, it takes a while the remote target to start executing the job
        # so I'm setting this sleep.. I don't like sleeps.. but this is just an example
        # Best way would be to check the task status before attempting to read the file
        time.sleep(3)
        # Switching back to the old ctx_id
        atsvc.hNetrJobDel(dce, NULL, jobId, jobId)

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
    # Init the example's logger theme
    logger.init()

    logging.warning("This will work ONLY on Windows >= Vista")

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('command', action='store', nargs='*', default = ' ', help='command to execute at the target ')
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

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    atsvc_exec = ATSVC_EXEC(username, password, domain, options.hashes, options.aesKey, options.k, ' '.join(options.command))
    atsvc_exec.play(address)
