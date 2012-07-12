# Copyright (c) 2003-2012 CORE Security Technologies)
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino
# TODO:
# [-] Functions should return NT error codes
# [-] Handling errors in all situations, right now it's just raising exceptions. 
# [*] Standard authentication support
# [ ] Organize the connectionData stuff
# [*] Add capability to send a bad user ID if the user is not authenticated,
#     right now you can ask for any command without actually being authenticated
# [ ] PATH TRAVERSALS EVERYWHERE.. BE WARNED!
# [ ] Check the credentials.. now we're just letting everybody to log in.
# [ ] Check error situation (now many places assume the right data is coming)
# [ ] Implement IPC to the main process so the connectionData is on a single place
# [ ] Hence.. implement locking
# estamos en la B

from impacket import smb
from impacket import nmb
from impacket import ntlm
from structure import Structure
import traceback
import sys
import calendar
import socket
import time
import datetime
import struct
import ConfigParser
import SocketServer
import threading
import logging
import logging.config
import ntpath
import os
import glob
import fnmatch
import errno
import sys

# For signing
import hashlib

# Utility functions
# and general functions. 
# There are some common functions that can be accessed from more than one SMB 
# command (or either TRANSACTION). That's why I'm putting them here
# TODO: Return NT ERROR Codes

def getFileTime(t):
    t *= 10000000
    t += 116444736000000000
    return t

def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
    return t

def getSMBDate(t):
    # TODO: Fix this :P
    d = datetime.date.fromtimestamp(t)
    year = d.year - 1980
    ret = (year << 8) + (d.month << 4) + d.day
    return ret

def getSMBTime(t):
    # TODO: Fix this :P
    d = datetime.datetime.fromtimestamp(t)
    return (d.hour << 8) + (d.minute << 4) + d.second 

def getShares(connId, smbServer):
    config = smbServer.getServerConfig()
    sections = config.sections()
    # Remove the global one
    del(sections[sections.index('global')])
    shares = {}
    for i in sections:
        shares[i] = dict(config.items(i))
    return shares

def searchShare(connId, share, smbServer):
    config = smbServer.getServerConfig()
    if config.has_section(share):
       return dict(config.items(share))
    else:
       return None

def openFile(path,fileName, accessMode, fileAttributes, openMode):
    fileName = os.path.normpath(fileName.replace('\\','/'))
    errorCode = 0
    if len(fileName) > 0:
       # strip leading '/'
       fileName = fileName[1:]
    pathName = os.path.join(path,fileName)
    mode = 0
    # Check the Open Mode
    if openMode & 0x10:
        # If the file does not exist, create it.
        mode = os.O_CREAT
    else:
        # If file does not exist, return an error
        if os.path.exists(pathName) is not True:
            errorCode = STATUS_NO_SUCH_FILE
            return 0,mode, pathName, errorCode

    if os.path.isdir(pathName) and (fileAttributes & smb.ATTR_DIRECTORY) == 0:
        # Request to open a normal file and this is actually a directory
            errorCode = STATUS_FILE_IS_A_DIRECTORY
            return 0, mode, pathName, errorCode
    # Check the Access Mode
    if accessMode & 0x7 == 1:
       mode |= os.O_WRONLY
    elif accessMode & 0x7 == 2:
       mode |= os.O_RDWR
    else:
       mode = os.O_RDONLY

    try:
        if sys.platform == 'win32':
            mode |= os.O_BINARY
        fid = os.open(pathName, mode)
    except Exception, e:
        print "openFile: %s,%s" % (pathName, mode) ,e
        fid = 0
        errorCode = STATUS_ACCESS_DENIED

    return fid, mode, pathName, errorCode

def queryFsInformation(path, filename, level=0):

    fileName = os.path.normpath(filename.replace('\\','/'))
    if len(fileName) > 0:
       # strip leading '/'
       fileName = fileName[1:]
    pathName = os.path.join(path,fileName)
    fileSize = os.path.getsize(pathName)
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
    if level == smb.SMB_QUERY_FS_ATTRIBUTE_INFO:
        data = smb.SMBQueryFsAttributeInfo()
        data['FileSystemAttributes']      = smb.FILE_CASE_SENSITIVE_SEARCH |                                                  smb.FILE_CASE_PRESERVED_NAMES
        data['MaxFilenNameLengthInBytes'] = 255
        data['LengthOfFileSystemName']    = len('XTFS')
        data['FileSystemName']            = 'XTFS'
        return data.getData()
    elif level == smb.SMB_INFO_VOLUME:
        data = smb.SMBQueryFsInfoVolume()
        data['VolumeLabel']               = 'SHARE'
        return data.getData()
    elif level == smb.SMB_QUERY_FS_VOLUME_INFO:
        data = smb.SMBQueryFsVolumeInfo()
        data['VolumeLabel']               = 'SHARE'
        data['VolumeCreationTime']        = getFileTime(ctime)
        return data.getData() 
    elif level == smb.SMB_QUERY_FS_SIZE_INFO:
        data = smb.SMBQueryFsSizeInfo()
        return data.getData()
    else:
        lastWriteTime = mtime
        attribs = 0
        if os.path.isdir(pathName):
            attribs |= smb.SMB_FILE_ATTRIBUTE_DIRECORY
        if os.path.isfile(pathName):
            attribs |= smb.SMB_FILE_ATTRIBUTE_NORMAL
        fileAttributes = attribs
        return fileSize, lastWriteTime, fileAttributes

def findFirst2(path, fileName, level, searchAttributes):  
     # TODO: Depending on the level, this could be done much simpler
     
     #print "FindFirs2 path:%s, filename:%s" % (path, fileName)
     fileName = os.path.normpath(fileName.replace('\\','/'))
     if len(fileName) > 0:
        # strip leading '/'
        fileName = fileName[1:]
     pathName = os.path.join(path,fileName)
     files = []

     if pathName.find('*') == -1 and pathName.find('?') == -1:
         # No search patterns
         pattern = ''
     else:
         pattern = os.path.basename(pathName)
         dirName = os.path.dirname(pathName)

     # Always add . and .. Not that important for Windows, but Samba whines if 
     # not present (for * search only)
     if pattern == '*':
         files.append(os.path.join(dirName,'.'))
         files.append(os.path.join(dirName,'..'))

     if pattern != '':
         for file in os.listdir(dirName):
             if fnmatch.fnmatch(file.lower(),pattern.lower()):
                entry = os.path.join(dirName, file)
                if os.path.isdir(entry):
                    if searchAttributes & smb.ATTR_DIRECTORY:
                        files.append(entry)
                else:
                    files.append(entry)
     else:
         if os.path.exists(pathName):
             files.append(pathName)

     searchResult = []
     searchCount = len(files)
     errorCode = STATUS_SUCCESS
     eaErrorOffset = 0

     for i in files:
        if level == smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
            item = smb.SMBFindFileBothDirectoryInfo()
        elif level == smb.SMB_FIND_FILE_DIRECTORY_INFO:
            item = smb.SMBFindFileDirectoryInfo()
        elif level == smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO:
            item = smb.SMBFindFileFullDirectoryInfo()
        elif level == smb.SMB_FIND_INFO_STANDARD:
            item = smb.SMBFindInfoStandard()
        elif level == smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
            item = smb.SMBFindFileIdFullDirectoryInfo()
        elif level == smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
            item = smb.SMBFindFileIdBothDirectoryInfo()
        elif level == smb.SMB_FIND_FILE_NAMES_INFO:
            item = smb.SMBFindFileNamesInfo()
        else:
            print "Wrong level %d!" % level
            
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(i)
        if os.path.isdir(i):
           item['ExtFileAttributes'] = smb.ATTR_DIRECTORY
        else:
           item['ExtFileAttributes'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE

        item['FileName'] = os.path.basename(i)

        if level == smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO or level == smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO:
           item['EaSize']            = 0
           item['EndOfFile']         = size
           item['AllocationSize']    = size
           item['CreationTime']      = getFileTime(ctime)
           item['LastAccessTime']    = getFileTime(atime)
           item['LastWriteTime']     = getFileTime(mtime)
           item['LastChangeTime']    = getFileTime(mtime)
           item['ShortName']         = '\x00'*24
           item['FileName']          = os.path.basename(i)
           item['NextEntryOffset']   = len(item)
        elif level == smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO or level == smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO:
           item['EaSize']            = 0
           item['EndOfFile']         = size
           item['AllocationSize']    = size
           item['CreationTime']      = getFileTime(ctime)
           item['LastAccessTime']    = getFileTime(atime)
           item['LastWriteTime']     = getFileTime(mtime)
           item['LastChangeTime']    = getFileTime(mtime)
           item['NextEntryOffset']   = len(item)
        elif level == smb.SMB_FIND_INFO_STANDARD:
           item['EaSize']            = size
           item['CreationDate']      = getSMBDate(ctime)
           item['CreationTime']      = getSMBTime(ctime)
           item['LastAccessDate']    = getSMBDate(atime)
           item['LastAccessTime']    = getSMBTime(atime)
           item['LastWriteDate']     = getSMBDate(mtime)
           item['LastWriteTime']     = getSMBTime(mtime)
        searchResult.append(item)

     # No more files
     if level >= smb.SMB_FIND_FILE_DIRECTORY_INFO and searchCount > 0:
         searchResult[-1]['NextEntryOffset'] = 0

     return searchResult, searchCount, errorCode

def queryFileInformation(path, filename, level):
    #print "queryFileInfo path: %s, filename: %s, level:0x%x" % (path,filename,level)
    return queryPathInformation(path,filename, level)

def queryPathInformation(path, filename, level):
    # TODO: Depending on the level, this could be done much simpler
  #print "queryPathInfo path: %s, filename: %s, level:0x%x" % (path,filename,level)
  try:
    errorCode = 0
    fileName = os.path.normpath(filename.replace('\\','/'))
    if len(fileName) > 0 and path != '':
       # strip leading '/'
       fileName = fileName[1:]
    pathName = os.path.join(path,fileName)
    if os.path.exists(pathName):
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
        if level == smb.SMB_QUERY_FILE_BASIC_INFO:
            infoRecord = smb.SMBQueryFileBasicInfo()
            infoRecord['CreationTime']         = getFileTime(ctime)
            infoRecord['LastAccessTime']       = getFileTime(atime)
            infoRecord['LastWriteTime']        = getFileTime(mtime)
            infoRecord['LastChangeTime']       = getFileTime(mtime)
            if os.path.isdir(pathName):
               infoRecord['ExtFileAttributes'] = smb.ATTR_DIRECTORY
            else:
               infoRecord['ExtFileAttributes'] = smb.ATTR_NORMAL
        elif level == smb.SMB_QUERY_FILE_STANDARD_INFO:
            infoRecord = smb.SMBQueryFileStandardInfo()
            infoRecord['AllocationSize']       = size
            infoRecord['EndOfFile']            = size
            if os.path.isdir(pathName):
               infoRecord['Directory']         = 1
            else:
               infoRecord['Directory']         = 0
        elif level == smb.SMB_QUERY_FILE_ALL_INFO:
            infoRecord = smb.SMBQueryFileAllInfo()
            infoRecord['CreationTime']         = getFileTime(ctime)
            infoRecord['LastAccessTime']       = getFileTime(atime)
            infoRecord['LastWriteTime']        = getFileTime(mtime)
            infoRecord['LastChangeTime']       = getFileTime(mtime)
            if os.path.isdir(pathName):
               infoRecord['ExtFileAttributes'] = smb.ATTR_DIRECTORY
            else:
               infoRecord['ExtFileAttributes'] = smb.ATTR_NORMAL
            infoRecord['AllocationSize']       = size
            infoRecord['EndOfFile']            = size
            if os.path.isdir(pathName):
               infoRecord['Directory']         = 1
            else:
               infoRecord['Directory']         = 0
            infoRecord['FileName']             = filename
        elif level == smb.SMB_QUERY_FILE_EA_INFO:
            infoRecord = smb.SMBQueryFileEaInfo()
        else:
            print 'Unknown level for query path info! 0x%x' % level
            # UNSUPPORTED
            return None, STATUS_NOT_SUPPORTED

        return infoRecord, errorCode
    else:
        # NOT FOUND
        return None, STATUS_OBJECT_NAME_NOT_FOUND
  except Exception, e:
      print 'queryPathInfo: %s' % e
      raise

def queryDiskInformation(path):
# TODO: Do something useful here :)
# For now we just return fake values
   totalUnits = 65535
   freeUnits = 65535
   return totalUnits, freeUnits

# Here we implement the NT transaction handlers
class NTTRANSCommands():
    def default(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        pass

# Here we implement the NT transaction handlers
class TRANSCommands():
    def lanMan(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        # Minimal [MS-RAP] implementation, just to return the shares
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        if struct.unpack('<H',parameters[:2])[0] == 0:
            # NetShareEnum Request
            netShareEnum = smb.SMBNetShareEnum(parameters)
            if netShareEnum['InfoLevel'] == 1:
                shares = getShares(connId, smbServer)
                respParameters = smb.SMBNetShareEnumResponse()
                respParameters['EntriesReturned']  = len(shares)
                respParameters['EntriesAvailable'] = len(shares)
                tailData = ''
                for i in shares:
                    # NetShareInfo1 len == 20
                    entry = smb.NetShareInfo1()
                    entry['NetworkName'] = i + '\x00'*(13-len(i))
                    entry['Type']        = int(shares[i]['share type'])
                    # (beto) If offset == 0 it crashes explorer.exe on windows 7
                    entry['RemarkOffsetLow'] = 20 * len(shares) + len(tailData)
                    respData += entry.getData()
                    if shares[i].has_key('comment'):
                        tailData += shares[i]['comment'] + '\x00'
                    else:
                        tailData += '\x00'
                respData += tailData
            else:
                # We don't support other info levels
                errorCode = STATUS_NOT_SUPPORTED
        elif struct.unpack('<H',parameters[:2])[0] == 13:
            # NetrServerGetInfo Request
            request = smb.SMBNetShareEnum(parameters)
            respParameters = smb.SMBNetServerGetInfoResponse()
            netServerInfo = smb.SMBNetServerInfo1()
            netServerInfo['ServerName'] = smbServer.getServerName()
            respData = str(netServerInfo)
            respParameters['TotalBytesAvailable'] = len(respData)
        elif struct.unpack('<H',parameters[:2])[0] == 1:
            # NetrShareGetInfo Request
            request = smb.SMBNetShareGetInfo(parameters)
            respParameters = smb.SMBNetShareGetInfoResponse()
            shares = getShares(connId, smbServer)
            share = shares[request['ShareName'].upper()]
            shareInfo = smb.NetShareInfo1() 
            shareInfo['NetworkName'] = request['ShareName'].upper() + '\x00'
            shareInfo['Type']        = int(share['share type'])
            respData = shareInfo.getData()
            if share.has_key('comment'):
                shareInfo['RemarkOffsetLow'] = len(respData)
                respData += share['comment'] + '\x00'
            respParameters['TotalBytesAvailable'] = len(respData)
     
        else:
            # We don't know how to handle anything else
            errorCode = STATUS_NOT_SUPPORTED

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def transactNamedPipe(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        SMBCommand  = smb.SMBCommand(recvPacket['Data'][0])
        transParameters= smb.SMBTransaction_Parameters(SMBCommand['Parameters'])

        # Extract the FID
        fid = struct.unpack('<H', transParameters['Setup'][2:])[0]

        if connData['OpenedFiles'].has_key(fid):
            fileHandle = connData['OpenedFiles'][fid]['FileHandle']
            if fileHandle != PIPE_FILE_DESCRIPTOR:
                (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.fstat(fileHandle)
                os.write(fileHandle,data)
                respData = os.read(fileHandle,data)
            else:
                sock = connData['OpenedFiles'][fid]['Socket']
                sock.send(data)
                respData = sock.recv(maxDataCount)
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

# Here we implement the transaction2 handlers
class TRANS2Commands():
    # All these commands return setup, parameters, data, errorCode
    def setPathInformation(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        setPathInfoParameters = smb.SMBSetPathInformation_Parameters(parameters)
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path     = connData['ConnectedShares'][recvPacket['Tid']]['path']
            fileName = setPathInfoParameters['FileName']
            fileName = os.path.normpath(fileName.replace('\\','/'))
            if len(fileName) > 0 and path != '':
               # strip leading '/'
               fileName = fileName[1:]
            pathName = os.path.join(path,fileName)
            if os.path.exists(pathName):
                informationLevel = setPathInfoParameters['InformationLevel']
                if informationLevel == smb.SMB_SET_FILE_BASIC_INFO:
                    infoRecord = smb.SMBSetFileBasicInfo(data)
                    # Creation time won't be set,  the other ones we play with.
                    atime = infoRecord['LastAccessTime']
                    if atime == 0:
                        atime = -1
                    else:
                        atime = getUnixTime(atime)
                    mtime = infoRecord['LastWriteTime']
                    if mtime == 0:
                        mtime = -1
                    else:
                        mtime = getUnixTime(mtime)
                    if mtime != -1 or atime != -1:
                        os.utime(pathName,(atime,mtime))
                else:
                    smbServer.log('Unknown level for set path info! 0x%x' % setPathInfoParameters['InformationLevel'], logging.ERROR)
                    # UNSUPPORTED
                    errorCode =  STATUS_NOT_SUPPORTED
            else:
                errorCode = STATUS_OBJECT_NAME_NOT_FOUND

            if errorCode == STATUS_SUCCESS:
                respParameters = smb.SMBSetPathInformationResponse_Parameters()

        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode


    def setFileInformation(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        setFileInfoParameters = smb.SMBSetFileInformation_Parameters(parameters)

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            if connData['OpenedFiles'].has_key(setFileInfoParameters['FID']):
                fileName = connData['OpenedFiles'][setFileInfoParameters['FID']]['FileName']
                informationLevel = setFileInfoParameters['InformationLevel']
                if informationLevel == smb.SMB_SET_FILE_DISPOSITION_INFO:
                    infoRecord = smb.SMBSetFileDispositionInfo(parameters)
                    if infoRecord['DeletePending'] > 0:
                       # Mark this file for removal after closed
                       connData['OpenedFiles'][setFileInfoParameters['FID']]['DeleteOnClose'] = True
                       respParameters = smb.SMBSetFileInformationResponse_Parameters()
                elif informationLevel == smb.SMB_SET_FILE_BASIC_INFO:
                    infoRecord = smb.SMBSetFileBasicInfo(data)
                    # Creation time won't be set,  the other ones we play with.
                    atime = infoRecord['LastAccessTime']
                    if atime == 0:
                        atime = -1
                    else:
                        atime = getUnixTime(atime)
                    mtime = infoRecord['LastWriteTime']
                    if mtime == 0:
                        mtime = -1
                    else:
                        mtime = getUnixTime(mtime)
                    os.utime(fileName,(atime,mtime))
                elif informationLevel == smb.SMB_SET_FILE_END_OF_FILE_INFO:
                    # We do nothing here, end of file will be set alone
                    infoRecord = smb.SMBSetFileEndOfFileInfo(data)
                else:
                    smbServer.log('Unknown level for set file info! 0x%x' % setFileInfoParameters['InformationLevel'], logging.ERROR)
                    # UNSUPPORTED
                    errorCode =  STATUS_NOT_SUPPORTED
            else:
                errorCode = STATUS_NO_SUCH_FILE

            if errorCode == STATUS_SUCCESS:
                respParameters = smb.SMBSetFileInformationResponse_Parameters()
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def queryFileInformation(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS 

        queryFileInfoParameters = smb.SMBQueryFileInformation_Parameters(parameters)

        if len(data) > 0: 
           queryFileInfoData = smb.SMBQueryFileInformation_Data(data)
  
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path     = connData['ConnectedShares'][recvPacket['Tid']]['path']
            if connData['OpenedFiles'].has_key(queryFileInfoParameters['FID']):
                fileName = connData['OpenedFiles'][queryFileInfoParameters['FID']]['FileName']

                infoRecord, errorCode = queryFileInformation('', fileName, queryFileInfoParameters['InformationLevel'])

                if infoRecord is not None:
                    respParameters = smb.SMBQueryFileInformationResponse_Parameters()
                    respData = infoRecord
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def queryPathInformation(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = 0

        queryPathInfoParameters = smb.SMBQueryPathInformation_Parameters(parameters)
        if len(data) > 0: 
           queryPathInfoData = smb.SMBQueryPathInformation_Data(data)
  
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            try:
               infoRecord, errorCode = queryPathInformation(path, queryPathInfoParameters['FileName'], queryPathInfoParameters['InformationLevel'])
            except Exception, e:
               smbServer.log("queryPathInformation: %s" % e,logging.ERROR)

            if infoRecord is not None:
                respParameters = smb.SMBQueryPathInformationResponse_Parameters()
                respData = infoRecord
        else:
            errorCode = STATUS_SMB_BAD_TID
           
        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def queryFsInformation(self, connId, smbServer, recvPacket, parameters, data, maxDataCount = 0):
        connData = smbServer.getConnectionData(connId)
        errorCode = 0
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            data = queryFsInformation(connData['ConnectedShares'][recvPacket['Tid']]['path'], '', struct.unpack('<H',parameters)[0])

        smbServer.setConnectionData(connId, connData)

        return '','', data, errorCode

    def findNext2(self, connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        findNext2Parameters = smb.SMBFindNext2_Parameters(parameters)
        if (len(data) > 0):
            findNext2Data = smb.SMBFindNext2_Data(data)
        else:
            findNext2Data = ''

        sid = findNext2Parameters['SID']
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            if connData['SIDs'].has_key(sid):
                searchResult = connData['SIDs'][sid]
                respParameters = smb.SMBFindNext2Response_Parameters()
                endOfSearch = 1
                searchCount = 1
                totalData = 0
                for i in enumerate(searchResult):
                    data = i[1].getData()
                    lenData = len(data)
                    if (totalData+lenData) >= maxDataCount or (i[0]+1) >= findNext2Parameters['SearchCount']:
                        # We gotta stop here and continue on a find_next2
                        endOfSearch = 0
                        connData['SIDs'][sid] = searchResult[i[0]:]
                        respParameters['LastNameOffset'] = totalData
                        break
                    else:
                        searchCount +=1
                        respData += data
                        totalData += lenData
                    
                # Have we reached the end of the search or still stuff to send?
                if endOfSearch > 0:
                    # Let's remove the SID from our ConnData
                    del(connData['SIDs'][sid])

                respParameters['EndOfSearch'] = endOfSearch
                respParameters['SearchCount'] = searchCount
            else: 
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID   

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    def findFirst2(self, connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = ''
        respParameters = ''
        respData = ''
        errorCode = STATUS_SUCCESS
        findFirst2Parameters = smb.SMBFindFirst2_Parameters(parameters)
        if (len(data) > 0):
            findFirst2Data = smb.SMBFindFirst2_Data(data)
        else:
            findFirst2Data = ''

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']

            searchResult, searchCount, errorCode = findFirst2(path, 
                          findFirst2Parameters['FileName'], 
                          findFirst2Parameters['InformationLevel'], 
                          findFirst2Parameters['SearchAttributes'] )

            respParameters = smb.SMBFindFirst2Response_Parameters()
            endOfSearch = 1
            sid = 0x80 # default SID
            searchCount = 0
            totalData = 0
            for i in enumerate(searchResult):
                #i[1].dump()
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

# Here we implement the commands handlers
class SMBCommands():

    def smbTransaction(self, connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])
        respParameters = smb.SMBTransactionResponse_Parameters()
        respData       = smb.SMBTransactionResponse_Data()

        transParameters= smb.SMBTransaction_Parameters(SMBCommand['Parameters'])

        # Do the stuff
        if transParameters['ParameterCount'] != transParameters['TotalParameterCount']:
            # TODO: Handle partial parameters 
            raise Exception("Unsupported partial parameters in TRANSACT2!")
        else:
            transData = smb.SMBTransaction_SData()
            # Standard says servers shouldn't trust Parameters and Data comes 
            # in order, so we have to parse the offsets, ugly   

            paramCount = transParameters['ParameterCount']
            transData['Trans_ParametersLength'] = paramCount
            dataCount = transParameters['DataCount']
            transData['Trans_DataLength'] = dataCount
            transData.fromString(SMBCommand['Data'])
            if transParameters['ParameterOffset'] > 0:
                paramOffset = transParameters['ParameterOffset'] - 63 - transParameters['SetupLength']
                transData['Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset+paramCount]
            else:
                transData['Trans_Parameters'] = ''

            if transParameters['DataOffset'] > 0:
                dataOffset = transParameters['DataOffset'] - 63 - transParameters['SetupLength']
                transData['Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else: 
                transData['Trans_Data'] = ''
            
            # Call the handler for this TRANSACTION
            if transParameters['SetupCount'] == 0:
                # No subcommand, let's play with the Name
                command = transData['Name']
            else:
                command = struct.unpack('<H', transParameters['Setup'][:2])[0]
            
            if transCommands.has_key(command):
               # Call the TRANS subcommand
               setup = ''
               parameters = ''
               data = ''
               try: 
                   setup, parameters, data, errorCode = transCommands[command](connId,
                                smbServer, 
                                recvPacket, 
                                transData['Trans_Parameters'], 
                                transData['Trans_Data'],
                                transParameters['MaxDataCount'])
               except Exception, e:
                   #print 'Transaction: %s' % e,e
                   smbServer.log('Transaction: (%r,%s)' % (command, e), logging.ERROR)
                   errorCode = STATUS_ACCESS_DENIED
                   #raise

               if setup == '' and parameters == '' and data == '':
                   # Something wen't wrong
                   respParameters = ''
                   respData = ''
               else:
                   # Build the answer
                   data = str(data)
                   remainingData = len(data)
                   parameters = str(parameters)
                   remainingParameters = len(parameters)
                   commands = []
                   dataDisplacement = 0
                   while remainingData > 0 or remainingParameters > 0: 
                       respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                       respParameters = smb.SMBTransactionResponse_Parameters()
                       respData       = smb.SMBTransaction2Response_Data()

                       respParameters['TotalParameterCount'] = len(parameters)
                       respParameters['ParameterCount']      = len(parameters)
                       respData['Trans_ParametersLength']    = len(parameters)
                       respParameters['TotalDataCount']      = len(data)
                       respParameters['DataDisplacement']    = dataDisplacement

                       # TODO: Do the same for parameters
                       if len(data) >  transParameters['MaxDataCount']:
                           # Answer doesn't fit in this packet
                           print "Lowering answer from %d to %d" % (len(data),transParameters['MaxDataCount']) 
                           respParameters['DataCount'] = transParameters['MaxDataCount']
                       else:
                           respParameters['DataCount'] = len(data)

                       respData['Trans_DataLength']          = respParameters['DataCount']
                       respParameters['SetupCount']          = len(setup)
                       respParameters['Setup']               = setup
                       # TODO: Make sure we're calculating the pad right
                       if (len(parameters) > 0):
                           #padLen = 4 - (55 + len(setup)) % 4 
                           padLen = (4 - (55 + len(setup)) % 4 ) % 4
                           padBytes = '\xFF' * padLen
                           respData['Pad1'] = padBytes
                           respParameters['ParameterOffset'] = 55 + len(setup) + padLen 
                       else:
                           padLen = 0
                           respParameters['ParameterOffset'] = 0
                           respData['Pad1']                  = ''

                       if (len(data) > 0):
                           #pad2Len = 4 - (55 + len(setup) + padLen + len(parameters)) % 4
                           pad2Len = (4 - (55 + len(setup) + padLen + len(parameters)) % 4) % 4
                           respData['Pad2'] = '\xFF' * pad2Len
                           respParameters['DataOffset'] = 55 + len(setup) + padLen + len(parameters) + pad2Len
                       else:
                           respParameters['DataOffset'] = 0
                           respData['Pad2']             = ''

                       respData['Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                       respData['Trans_Data']       = data[:respParameters['DataCount']] 
                       respSMBCommand['Parameters'] = respParameters
                       respSMBCommand['Data']       = respData 

                       data = data[respParameters['DataCount']:]
                       remainingData -= respParameters['DataCount']
                       dataDisplacement += respParameters['DataCount'] + 1

                       parameters = parameters[respParameters['ParameterCount']:]
                       remainingParameters -= respParameters['ParameterCount']
                       commands.append(respSMBCommand)

                   smbServer.setConnectionData(connId, connData)
                   return commands, None, errorCode

            else:
               smbServer.log("Unsupported Transact command %r" % command, logging.ERROR)
               respParameters = ''
               respData = ''
               errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    def smbNTTransact(self, connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])
        respParameters = smb.SMBNTTransactionResponse_Parameters()
        respData       = smb.SMBNTTransactionResponse_Data()

        NTTransParameters= smb.SMBNTTransaction_Parameters(SMBCommand['Parameters'])
        # Do the stuff
        if NTTransParameters['ParameterCount'] != NTTransParameters['TotalParameterCount']:
            # TODO: Handle partial parameters 
            raise Exception("Unsupported partial parameters in NTTrans!")
        else:
            NTTransData = smb.SMBNTTransaction_Data()
            # Standard says servers shouldn't trust Parameters and Data comes 
            # in order, so we have to parse the offsets, ugly   

            paramCount = NTTransParameters['ParameterCount']
            NTTransData['NT_Trans_ParametersLength'] = paramCount
            dataCount = NTTransParameters['DataCount']
            NTTransData['NT_Trans_DataLength'] = dataCount

            if NTTransParameters['ParameterOffset'] > 0:
                paramOffset = NTTransParameters['ParameterOffset'] - 73 - NTTransParameters['SetupLength']
                NTTransData['NT_Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset+paramCount]
            else:
                NTTransData['NT_Trans_Parameters'] = ''

            if NTTransParameters['DataOffset'] > 0:
                dataOffset = NTTransParameters['DataOffset'] - 73 - NTTransParameters['SetupLength']
                NTTransData['NT_Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else: 
                NTTransData['NT_Trans_Data'] = ''

            # Call the handler for this TRANSACTION
            command = NTTransParameters['Function']
            if transCommands.has_key(command):
               # Call the NT TRANS subcommand
               setup = ''
               parameters = ''
               data = ''
               try: 
                   setup, parameters, data, errorCode = transCommands[command](connId,
                                smbServer, 
                                recvPacket, 
                                NTTransData['NT_Trans_Parameters'], 
                                NTTransData['NT_Trans_Data'],
                                NTTransParameters['MaxDataCount'])
               except Exception, e:
                   smbServer.log('NTTransaction: (0x%x,%s)' % (command, e), logging.ERROR)
                   errorCode = STATUS_ACCESS_DENIED
                   #raise

               if setup == '' and parameters == '' and data == '':
                   # Something wen't wrong
                   respParameters = ''
                   respData = ''
                   if errorCode == STATUS_SUCCESS:
                       errorCode = STATUS_ACCESS_DENIED 
               else:
                   # Build the answer
                   data = str(data)
                   remainingData = len(data)
                   parameters = str(parameters)
                   remainingParameters = len(parameters)
                   commands = []
                   dataDisplacement = 0
                   while remainingData > 0 or remainingParameters > 0: 
                       respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                       respParameters = smb.SMBNTTransactionResponse_Parameters()
                       respData       = smb.SMBNTTransactionResponse_Data()

                       respParameters['TotalParameterCount'] = len(parameters)
                       respParameters['ParameterCount']      = len(parameters)
                       respData['Trans_ParametersLength']    = len(parameters)
                       respParameters['TotalDataCount']      = len(data)
                       respParameters['DataDisplacement']    = dataDisplacement
                       # TODO: Do the same for parameters
                       if len(data) >  NTTransParameters['MaxDataCount']:
                           # Answer doesn't fit in this packet
                           print "Lowering answer from %d to %d" % (len(data),NTTransParameters['MaxDataCount']) 
                           respParameters['DataCount'] = NTTransParameters['MaxDataCount']
                       else:
                           respParameters['DataCount'] = len(data)

                       respData['NT_Trans_DataLength']          = respParameters['DataCount']
                       respParameters['SetupCount']          = len(setup)
                       respParameters['Setup']               = setup
                       # TODO: Make sure we're calculating the pad right
                       if (len(parameters) > 0):
                           #padLen = 4 - (71 + len(setup)) % 4 
                           padLen = (4 - (73 + len(setup)) % 4 ) % 4
                           padBytes = '\xFF' * padLen
                           respData['Pad1'] = padBytes
                           respParameters['ParameterOffset'] = 73 + len(setup) + padLen 
                       else:
                           padLen = 0
                           respParameters['ParameterOffset'] = 0
                           respData['Pad1']                  = ''

                       if (len(data) > 0):
                           #pad2Len = 4 - (71 + len(setup) + padLen + len(parameters)) % 4
                           pad2Len = (4 - (73 + len(setup) + padLen + len(parameters)) % 4) % 4
                           respData['Pad2'] = '\xFF' * pad2Len
                           respParameters['DataOffset'] = 73 + len(setup) + padLen + len(parameters) + pad2Len
                       else:
                           respParameters['DataOffset'] = 0
                           respData['Pad2']             = ''

                       respData['NT_Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                       respData['NT_Trans_Data']       = data[:respParameters['DataCount']] 
                       respSMBCommand['Parameters'] = respParameters
                       respSMBCommand['Data']       = respData 

                       data = data[respParameters['DataCount']:]
                       remainingData -= respParameters['DataCount']
                       dataDisplacement += respParameters['DataCount'] + 1

                       parameters = parameters[respParameters['ParameterCount']:]
                       remainingParameters -= respParameters['ParameterCount']
                       commands.append(respSMBCommand)

                   smbServer.setConnectionData(connId, connData)
                   return commands, None, errorCode

            else:
               #smbServer.log("Unsupported NTTransact command 0x%x" % command, logging.ERROR)
               respParameters = ''
               respData = ''
               errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode


    def smbTransaction2(self, connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])
        respParameters = smb.SMBTransaction2Response_Parameters()
        respData       = smb.SMBTransaction2Response_Data()

        trans2Parameters= smb.SMBTransaction2_Parameters(SMBCommand['Parameters'])

        # Do the stuff
        if trans2Parameters['ParameterCount'] != trans2Parameters['TotalParameterCount']:
            # TODO: Handle partial parameters 
            #print "Unsupported partial parameters in TRANSACT2!"
            raise Exception("Unsupported partial parameters in TRANSACT2!")
        else:
            trans2Data = smb.SMBTransaction2_Data()
            # Standard says servers shouldn't trust Parameters and Data comes 
            # in order, so we have to parse the offsets, ugly   

            paramCount = trans2Parameters['ParameterCount']
            trans2Data['Trans_ParametersLength'] = paramCount
            dataCount = trans2Parameters['DataCount']
            trans2Data['Trans_DataLength'] = dataCount

            if trans2Parameters['ParameterOffset'] > 0:
                paramOffset = trans2Parameters['ParameterOffset'] - 63 - trans2Parameters['SetupLength']
                trans2Data['Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset+paramCount]
            else:
                trans2Data['Trans_Parameters'] = ''

            if trans2Parameters['DataOffset'] > 0:
                dataOffset = trans2Parameters['DataOffset'] - 63 - trans2Parameters['SetupLength']
                trans2Data['Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else: 
                trans2Data['Trans_Data'] = ''

            # Call the handler for this TRANSACTION
            command = struct.unpack('<H', trans2Parameters['Setup'])[0]
            if transCommands.has_key(command):
               # Call the TRANS2 subcommand
               setup = ''
               parameters = ''
               data = ''
               try: 
                   setup, parameters, data, errorCode = transCommands[command](connId,
                                smbServer, 
                                recvPacket, 
                                trans2Data['Trans_Parameters'], 
                                trans2Data['Trans_Data'],
                                trans2Parameters['MaxDataCount'])
               except Exception, e:
                   smbServer.log('Transaction2: (0x%x,%s)' % (command, e), logging.ERROR)
                   traceback.print_exc()
                   errorCode = STATUS_ACCESS_DENIED
                   raise

               if setup == '' and parameters == '' and data == '':
                   # Something wen't wrong
                   respParameters = ''
                   respData = ''
               else:
                   # Build the answer
                   data = str(data)
                   remainingData = len(data)
                   parameters = str(parameters)
                   remainingParameters = len(parameters)
                   commands = []
                   dataDisplacement = 0
                   while remainingData > 0 or remainingParameters > 0: 
                       respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                       respParameters = smb.SMBTransaction2Response_Parameters()
                       respData       = smb.SMBTransaction2Response_Data()

                       respParameters['TotalParameterCount'] = len(parameters)
                       respParameters['ParameterCount']      = len(parameters)
                       respData['Trans_ParametersLength']    = len(parameters)
                       respParameters['TotalDataCount']      = len(data)
                       respParameters['DataDisplacement']    = dataDisplacement
                       # TODO: Do the same for parameters
                       if len(data) >  trans2Parameters['MaxDataCount']:
                           # Answer doesn't fit in this packet
                           print "Lowering answer from %d to %d" % (len(data),trans2Parameters['MaxDataCount']) 
                           respParameters['DataCount'] = trans2Parameters['MaxDataCount']
                       else:
                           respParameters['DataCount'] = len(data)

                       respData['Trans_DataLength']          = respParameters['DataCount']
                       respParameters['SetupCount']          = len(setup)
                       respParameters['Setup']               = setup
                       # TODO: Make sure we're calculating the pad right
                       if (len(parameters) > 0):
                           #padLen = 4 - (55 + len(setup)) % 4 
                           padLen = (4 - (55 + len(setup)) % 4 ) % 4
                           padBytes = '\xFF' * padLen
                           respData['Pad1'] = padBytes
                           respParameters['ParameterOffset'] = 55 + len(setup) + padLen 
                       else:
                           padLen = 0
                           respParameters['ParameterOffset'] = 0
                           respData['Pad1']                  = ''

                       if (len(data) > 0):
                           #pad2Len = 4 - (55 + len(setup) + padLen + len(parameters)) % 4
                           pad2Len = (4 - (55 + len(setup) + padLen + len(parameters)) % 4) % 4
                           respData['Pad2'] = '\xFF' * pad2Len
                           respParameters['DataOffset'] = 55 + len(setup) + padLen + len(parameters) + pad2Len
                       else:
                           respParameters['DataOffset'] = 0
                           respData['Pad2']             = ''

                       respData['Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                       respData['Trans_Data']       = data[:respParameters['DataCount']] 
                       respSMBCommand['Parameters'] = respParameters
                       respSMBCommand['Data']       = respData 

                       data = data[respParameters['DataCount']:]
                       remainingData -= respParameters['DataCount']
                       dataDisplacement += respParameters['DataCount'] + 1

                       parameters = parameters[respParameters['ParameterCount']:]
                       remainingParameters -= respParameters['ParameterCount']
                       commands.append(respSMBCommand)

                   smbServer.setConnectionData(connId, connData)
                   return commands, None, errorCode

            else:
               smbServer.log("Unsupported Transact/2 command 0x%x" % command, logging.ERROR)
               respParameters = ''
               respData = ''
               errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    def smbComLockingAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_LOCKING_ANDX)
        respParameters        = ''
        respData              = ''

        # I'm actually doing nothing.. just make MacOS happy ;)
        errorCode = STATUS_SUCCESS

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    def smbComClose(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_CLOSE)
        respParameters        = ''
        respData              = ''

        comClose =  smb.SMBClose_Parameters(SMBCommand['Parameters'])

        errorCode = 0xFF
        if connData['OpenedFiles'].has_key(comClose['FID']):
             errorCode = STATUS_SUCCESS
             fileHandle = connData['OpenedFiles'][comClose['FID']]['FileHandle']
             try:
                 if fileHandle == PIPE_FILE_DESCRIPTOR:
                     connData['OpenedFiles'][comClose['FID']]['Socket'].close()
                 elif fileHandle != VOID_FILE_DESCRIPTOR:
                     os.close(fileHandle)
             except Exception, e:
                 smbServer.log("comClose %s" % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
             else:
                 # Check if the file was marked for removal
                 if connData['OpenedFiles'][comClose['FID']]['DeleteOnClose'] == True:
                     try:
                         os.remove(connData['OpenedFiles'][comClose['FID']]['FileName'])
                     except Exception, e:
                         smbServer.log("comClose %s" % e, logging.ERROR)
                         errorCode = STATUS_ACCESS_DENIED
                 del(connData['OpenedFiles'][comClose['FID']])
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComWrite(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_WRITE)
        respParameters        = smb.SMBWriteResponse_Parameters()
        respData              = ''

        comWriteParameters =  smb.SMBWrite_Parameters(SMBCommand['Parameters'])
        comWriteData = smb.SMBWrite_Data(SMBCommand['Data'])

        errorCode = 0xff
        if connData['OpenedFiles'].has_key(comWriteParameters['Fid']):
             fileHandle = connData['OpenedFiles'][comWriteParameters['Fid']]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     # TODO: Handle big size files
                     (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.fstat(fileHandle)
                     os.lseek(fileHandle,comWriteParameters['Offset'],os.SEEK_SET)
                     os.write(fileHandle,comWriteData['Data'])
                 else:
                     sock = connData['OpenedFiles'][comWriteParameters['Fid']]['Socket']
                     sock.send(comWriteData['Data'])
                 respParameters['Count']    = comWriteParameters['Count']
             except Exception, e:
                 smbServer.log('smbComWrite: %s' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE


        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComCreateDirectory(self, connId, smbServer, SMBCommand,recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_CREATE_DIRECTORY)
        respParameters        = ''
        respData              = ''

        comCreateDirectoryData=  smb.SMBCreateDirectory_Data(SMBCommand['Data'])

        errorCode = 0xff
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             fileName = os.path.normpath(comCreateDirectoryData['DirectoryName'].replace('\\','/'))
             if len(fileName) > 0:
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             if os.path.exists(pathName):
                errorCode = STATUS_OBJECT_NAME_COLLISION

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.mkdir(pathName)
                 except Exception, e:
                     smbServer.log("smbComCreateDirectory: %s" % e, logging.ERROR)
                     errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID


        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComRename(self, connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_RENAME)
        respParameters        = ''
        respData              = ''

        comRenameData      =  smb.SMBRename_Data(SMBCommand['Data'])
        comRenameParameters=  smb.SMBRename_Parameters(SMBCommand['Parameters'])

        errorCode = 0xff
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             oldFileName = os.path.normpath(comRenameData['OldFileName'].replace('\\','/'))
             newFileName = os.path.normpath(comRenameData['NewFileName'].replace('\\','/'))
             if len(oldFileName) > 0:
                # strip leading '/'
                oldFileName = oldFileName[1:]
             oldPathName = os.path.join(path,oldFileName)
             if len(newFileName) > 0:
                # strip leading '/'
                newFileName = newFileName[1:]
             newPathName = os.path.join(path,newFileName)

             if os.path.exists(oldPathName) is not True:
                errorCode = STATUS_NO_SUCH_FILE

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.rename(oldPathName,newPathName)
                 except OSError, e:
                     smbServer.log("smbComRename: %s" % e, logging.ERROR)
                     errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID


        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComDelete(self, connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_DELETE)
        respParameters        = ''
        respData              = ''

        comDeleteData         =  smb.SMBDelete_Data(SMBCommand['Data'])
        comDeleteParameters   =  smb.SMBDelete_Parameters(SMBCommand['Parameters'])

        errorCode = 0xff
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             fileName = os.path.normpath(comDeleteData['FileName'].replace('\\','/'))
             if len(fileName) > 0:
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             if os.path.exists(pathName) is not True:
                errorCode = STATUS_NO_SUCH_FILE

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.remove(pathName)
                 except OSError, e:
                     smbServer.log("smbComDelete: %s" % e, logging.ERROR)
                     errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    def smbComDeleteDirectory(self, connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_DELETE_DIRECTORY)
        respParameters        = ''
        respData              = ''

        comDeleteDirectoryData=  smb.SMBDeleteDirectory_Data(SMBCommand['Data'])

        errorCode = 0xff
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             errorCode = STATUS_SUCCESS
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             fileName = os.path.normpath(comDeleteDirectoryData['DirectoryName'].replace('\\','/'))
             if len(fileName) > 0:
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             if os.path.exists(pathName) is not True:
                errorCode = STATUS_NO_SUCH_FILE

             # TODO: More checks here in the future.. Specially when we support
             # user access
             else:
                 try:
                     os.rmdir(pathName)
                 except OSError, e:
                     smbServer.log("smbComDeleteDirectory: %s" % e,logging.ERROR)
                     if e.errno == errno.ENOTEMPTY:
                         errorCode = STATUS_DIRECTORY_NOT_EMPTY
                     else:
                         errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode


    def smbComWriteAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_WRITE_ANDX)
        respParameters        = smb.SMBWriteAndXResponse_Parameters()
        respData              = ''

        if SMBCommand['WordCount'] == 0x0C:
            writeAndX =  smb.SMBWriteAndX_Parameters2(SMBCommand['Parameters'])
        else:
            writeAndX =  smb.SMBWriteAndX_Parameters(SMBCommand['Parameters'])
        writeAndXData = smb.SMBWriteAndX_Data()
        writeAndXData['DataLength'] = writeAndX['DataLength']
        writeAndXData.fromString(SMBCommand['Data'])

        errorCode = 0xff
        if connData['OpenedFiles'].has_key(writeAndX['Fid']):
             fileHandle = connData['OpenedFiles'][writeAndX['Fid']]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     # TODO: Handle big size files
                     (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.fstat(fileHandle)
                     os.lseek(fileHandle,writeAndX['Offset'],os.SEEK_SET)
                     os.write(fileHandle,writeAndXData['Data'])
                 else:
                     sock = connData['OpenedFiles'][writeAndX['Fid']]['Socket']
                     sock.write(writeAndXData['Data'])

                 respParameters['Count']    = writeAndX['DataLength']
                 respParameters['Available']= 0xff
             except Exception, e:
                 smbServer.log('smbComWriteAndx: %s' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComRead(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_READ)
        respParameters        = smb.SMBReadResponse_Parameters()
        respData              = smb.SMBReadResponse_Data()

        comReadParameters =  smb.SMBRead_Parameters(SMBCommand['Parameters'])

        errorCode = 0xff
        if connData['OpenedFiles'].has_key(comReadParameters['Fid']):
             fileHandle = connData['OpenedFiles'][comReadParameters['Fid']]['FileHandle']
             errorCode = STATUS_SUCCESS
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     # TODO: Handle big size files
                     (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.fstat(fileHandle)
                     os.lseek(fileHandle,comReadParameters['Offset'],os.SEEK_SET)
                     content = os.read(fileHandle,comReadParameters['Count'])
                 else:
                     sock = connData['OpenedFiles'][comReadParameters['Fid']]['Socket']
                     content = sock.recv(comReadParameters['Count'])
                 respParameters['Count']    = len(content)
                 respData['DataLength']     = len(content)
                 respData['Data']           = content
             except Exception, e:
                 smbServer.log('smbComRead: %s ' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComReadAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)
        respParameters        = smb.SMBReadAndXResponse_Parameters()
        respData              = ''

        if SMBCommand['WordCount'] == 0x0A:
            readAndX =  smb.SMBReadAndX_Parameters2(SMBCommand['Parameters'])
        else:
            readAndX =  smb.SMBReadAndX_Parameters(SMBCommand['Parameters'])

        errorCode = 0xff
        if connData['OpenedFiles'].has_key(readAndX['Fid']):
             fileHandle = connData['OpenedFiles'][readAndX['Fid']]['FileHandle']
             errorCode = 0
             try:
                 if fileHandle != PIPE_FILE_DESCRIPTOR:
                     # TODO: Handle big size files
                     (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.fstat(fileHandle)
                     os.lseek(fileHandle,readAndX['Offset'],os.SEEK_SET)
                     content = os.read(fileHandle,readAndX['MaxCount'])
                 else:
                     sock = connData['OpenedFiles'][readAndX['Fid']]['Socket']
                     content = sock.recv(readAndX['MaxCount'])
                 respParameters['Remaining']    = 0xffff
                 respParameters['DataCount']    = len(content)
                 respParameters['DataOffset']   = 59
                 respParameters['DataCount_Hi'] = 0
                 respData = content
             except Exception, e:
                 smbServer.log('smbComReadAndX: %s ' % e, logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_HANDLE

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode
         
    def smbQueryInformation(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION)
        respParameters = smb.SMBQueryInformationResponse_Parameters()
        respData       = ''

        queryInformation= smb.SMBQueryInformation_Data(SMBCommand['Data'])

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            fileSize, lastWriteTime, fileAttributes = queryFsInformation(
                connData['ConnectedShares'][recvPacket['Tid']]['path'], 
                queryInformation['FileName'])

            respParameters['FileSize']       = fileSize
            respParameters['LastWriteTime']  = lastWriteTime
            respParameters['FileAttributes'] = fileAttributes
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            errorCode = STATUS_SMB_BAD_TID
            respParameters  = ''
            respData        = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    def smbQueryInformationDisk(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION_DISK)
        respParameters = smb.SMBQueryInformationDiskResponse_Parameters()
        respData       = ''

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            totalUnits, freeUnits = queryDiskInformation(
                        connData['ConnectedShares'][recvPacket['Tid']]['path'])

            respParameters['TotalUnits']    = totalUnits
            respParameters['BlocksPerUnit'] = 1
            respParameters['BlockSize']     = 1
            respParameters['FreeUnits']     = freeUnits
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            respData  = ''
            respParameters = ''
            errorCode = STATUS_SMB_BAD_TID


        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode
        
    def smbComEcho(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
        respParameters = smb.SMBEchoResponse_Parameters()
        respData       = smb.SMBEchoResponse_Data()

        echoParameters = smb.SMBEcho_Parameters(SMBCommand['Parameters'])
        echoData       = smb.SMBEcho_Data(SMBCommand['Data'])

        respParameters['SequenceNumber'] = 1
        respData['Data']                 = echoData['Data']

        respSMBCommand['Parameters']     = respParameters
        respSMBCommand['Data']           = respData 

        errorCode = STATUS_SUCCESS
        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    def smbComTreeDisconnect(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_TREE_DISCONNECT)

        # Check if the Tid matches the Tid trying to disconnect
        respParameters = ''
        respData = ''

        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
            smbServer.log("Disconnecting Share(%d:%s)" % (recvPacket['Tid'],connData['ConnectedShares'][recvPacket['Tid']]['shareName']))
            del(connData['ConnectedShares'][recvPacket['Tid']])
            errorCode = STATUS_SUCCESS
        else:
            # STATUS_SMB_BAD_TID
            errorCode = STATUS_SMB_BAD_TID

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData 

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    def smbComLogOffAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_LOGOFF_ANDX)

        # Check if the Uid matches the user trying to logoff
        respParameters = ''
        respData = ''
        if recvPacket['Uid'] != connData['Uid']:
            # STATUS_SMB_BAD_UID
            errorCode = STATUS_SMB_BAD_UID
        else:
            errorCode = STATUS_SUCCESS

        respSMBCommand['Parameters']   = respParameters
        respSMBCommand['Data']         = respData 
        connData['Uid'] = 0

        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComQueryInformation2(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION2)
        respParameters        = smb.SMBQueryInformation2Response_Parameters()
        respData              = ''

        queryInformation2 = smb.SMBQueryInformation2_Parameters(SMBCommand['Parameters'])
        errorCode = 0xFF
        if connData['OpenedFiles'].has_key(queryInformation2['Fid']):
             errorCode = STATUS_SUCCESS
             pathName = connData['OpenedFiles'][queryInformation2['Fid']]['FileName']
             try:
                 (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
                 respParameters['CreateDate']         = getSMBDate(ctime)
                 respParameters['CreationTime']       = getSMBTime(ctime)
                 respParameters['LastAccessDate']     = getSMBDate(atime)
                 respParameters['LastAccessTime']     = getSMBTime(atime)
                 respParameters['LastWriteDate']      = getSMBDate(mtime)
                 respParameters['LastWriteTime']      = getSMBTime(mtime)
                 respParameters['FileDataSize']       = size
                 respParameters['FileAllocationSize'] = size
                 attribs = 0
                 if os.path.isdir(pathName):
                     attribs = smb.SMB_FILE_ATTRIBUTE_DIRECORY
                 if os.path.isfile(pathName):
                     attribs = smb.SMB_FILE_ATTRIBUTE_NORMAL
                 respParameters['FileAttributes'] = attribs
             except Exception, e:
                 smbServer.log('smbComQueryInformation2 %s' % e,logging.ERROR)
                 errorCode = STATUS_ACCESS_DENIED

        if errorCode > 0:
            respParameters = ''
            respData       = ''

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComNtCreateAndX(self, connId, smbServer, SMBCommand, recvPacket):
        # TODO: Fully implement this
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
        respParameters        = smb.SMBNtCreateAndXResponse_Parameters()
        respData              = ''

        ntCreateAndXParameters = smb.SMBNtCreateAndX_Parameters(SMBCommand['Parameters'])
        ntCreateAndXData       = smb.SMBNtCreateAndX_Data(SMBCommand['Data'])

        #if ntCreateAndXParameters['CreateFlags'] & 0x10:  # NT_CREATE_REQUEST_EXTENDED_RESPONSE
        #    respParameters        = smb.SMBNtCreateAndXExtendedResponse_Parameters()
        #    respParameters['VolumeGUID'] = '\x00'

        errorCode = 0xFF
        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             # If we have a rootFid, the path is relative to that fid
             errorCode = STATUS_SUCCESS
             if ntCreateAndXParameters['RootFid'] > 0:
                 path = connData['OpenedFiles'][ntCreateAndXParameters['RootFid']]['FileName']
                 print "RootFid present %s!" % path
             else:
                 if connData['ConnectedShares'][recvPacket['Tid']].has_key('path'):
                     path = connData['ConnectedShares'][recvPacket['Tid']]['path']
                 else:
                     path = 'NONE'
                     errorCode = STATUS_ACCESS_DENIED

             deleteOnClose = False

             fileName = os.path.normpath(ntCreateAndXData['FileName'].replace('\\','/'))
             if len(fileName) > 0:
                # strip leading '/'
                fileName = fileName[1:]
             pathName = os.path.join(path,fileName)
             createDisposition = ntCreateAndXParameters['Disposition']
             mode = 0

             if createDisposition == smb.FILE_SUPERSEDE:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb.FILE_OVERWRITE_IF == smb.FILE_OVERWRITE_IF:
                 mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb.FILE_OVERWRITE == smb.FILE_OVERWRITE:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC 
                 else:
                     errorCode = STATUS_NO_SUCH_FILE
             elif createDisposition & smb.FILE_OPEN_IF == smb.FILE_OPEN_IF:
                 if os.path.exists(pathName) is True:
                     mode |= os.O_TRUNC 
                 else:
                     mode |= os.O_TRUNC | os.O_CREAT
             elif createDisposition & smb.FILE_CREATE == smb.FILE_CREATE:
                 if os.path.exists(pathName) is True:
                     errorCode = STATUS_OBJECT_NAME_COLLISION
                 else:
                     mode |= os.O_CREAT
             elif createDisposition & smb.FILE_OPEN == smb.FILE_OPEN:
                 if os.path.exists(pathName) is not True and smbServer.getRegisteredNamedPipes().has_key(pathName) is not True:
                     errorCode = STATUS_NO_SUCH_FILE

             if errorCode == STATUS_SUCCESS:
                 desiredAccess = ntCreateAndXParameters['AccessMask']
                 if desiredAccess & smb.FILE_READ_DATA:
                     mode |= os.O_RDONLY
                 if desiredAccess & smb.FILE_WRITE_DATA:
                     if desiredAccess & smb.FILE_READ_DATA:
                         mode |= os.O_RDWR | os.O_APPEND
                     else: 
                         mode |= os.O_WRONLY | os.O_APPEND

                 createOptions =  ntCreateAndXParameters['CreateOptions']
                 if mode & os.O_CREAT == os.O_CREAT:
                     if createOptions & smb.FILE_DIRECTORY_FILE == smb.FILE_DIRECTORY_FILE: 
                         # Let's create the directory
                         os.mkdir(pathName)
                         mode = os.O_RDONLY

                 if createOptions & smb.FILE_NON_DIRECTORY_FILE == smb.FILE_NON_DIRECTORY_FILE:
                     # If the file being opened is a directory, the server MUST fail the request with
                     # STATUS_FILE_IS_A_DIRECTORY in the Status field of the SMB Header in the server
                     # response.
                     if os.path.isdir(pathName) is True:
                        errorCode = STATUS_FILE_IS_A_DIRECTORY

                 if createOptions & smb.FILE_DELETE_ON_CLOSE == smb.FILE_DELETE_ON_CLOSE:
                     deleteOnClose = True
                 
                 if errorCode == STATUS_SUCCESS:
                     try:
                         if os.path.isdir(pathName) and sys.platform == 'win32':
                            fid = VOID_FILE_DESCRIPTOR
                         else:
                            if sys.platform == 'win32':
                               mode |= os.O_BINARY
                            if smbServer.getRegisteredNamedPipes().has_key(pathName):
                                fid = PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[pathName])
                            else:
                                fid = os.open(pathName, mode)
                     except Exception, e:
                         smbServer.log("NTCreateAndX: %s,%s,%s" % (pathName,mode,e),logging.ERROR)
                         print e
                         fid = 0
                         errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode == STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            if len(connData['OpenedFiles']) == 0:
               fakefid = 1
            else:
               fakefid = connData['OpenedFiles'].keys()[-1] + 1
            respParameters['Fid'] = fakefid
            respParameters['CreateAction'] = createDisposition
            if fid == PIPE_FILE_DESCRIPTOR:
                respParameters['FileAttributes'] = 0x80
                respParameters['IsDirectory'] = 0
                respParameters['CreateTime']     = 0
                respParameters['LastAccessTime'] = 0
                respParameters['LastWriteTime']  = 0
                respParameters['LastChangeTime'] = 0
                respParameters['AllocationSize'] = 4096
                respParameters['EndOfFile']      = 0
                respParameters['FileType']       = 2
                respParameters['IPCState']       = 0x5ff
            else:
                if os.path.isdir(pathName):
                    respParameters['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECORY
                    respParameters['IsDirectory'] = 1
                else:
                    respParameters['IsDirectory'] = 0
                    respParameters['FileAttributes'] = ntCreateAndXParameters['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = queryPathInformation('',pathName,level= smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respParameters['CreateTime']     = respInfo['CreationTime']
                    respParameters['LastAccessTime'] = respInfo['LastAccessTime']
                    respParameters['LastWriteTime']  = respInfo['LastWriteTime']
                    respParameters['LastChangeTime'] = respInfo['LastChangeTime']
                    respParameters['FileAttributes'] = respInfo['ExtFileAttributes']
                    respParameters['AllocationSize'] = respInfo['AllocationSize']
                    respParameters['EndOfFile']      = respInfo['EndOfFile']
                else:
                    respParameters = ''
                    respData       = ''

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose']  = deleteOnClose
                if fid == PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respParameters = ''
            respData       = ''
        
        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComOpenAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_OPEN_ANDX)
        respParameters        = smb.SMBOpenAndXResponse_Parameters()
        respData              = ''

        openAndXParameters = smb.SMBOpenAndX_Parameters(SMBCommand['Parameters'])
        openAndXData       = smb.SMBOpenAndX_Data(SMBCommand['Data'])

        # Get the Tid associated
        if connData['ConnectedShares'].has_key(recvPacket['Tid']):
             path = connData['ConnectedShares'][recvPacket['Tid']]['path']
             openedFile, mode, pathName, errorCode = openFile(path,
                     openAndXData['FileName'], 
                     openAndXParameters['DesiredAccess'], 
                     openAndXParameters['FileAttributes'], 
                     openAndXParameters['OpenMode'])
        else:
           errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            fid = len(connData['OpenedFiles']) + 1 
            if len(connData['OpenedFiles']) == 0:
               fid = 1
            else:
               fid = connData['OpenedFiles'].keys()[-1] + 1
            respParameters['Fid'] = fid
            if mode & os.O_CREAT:
                # File did not exist and was created
                respParameters['Action'] = 0x2
            elif mode & os.O_RDONLY:
                # File existed and was opened
                respParameters['Action'] = 0x1
            elif mode & os.O_APPEND:
                # File existed and was opened
                respParameters['Action'] = 0x1
            else:
                # File existed and was truncated
                respParameters['Action'] = 0x3
            
            # Let's store the fid for the connection
            #smbServer.log('Opening file %s' % pathName)
            connData['OpenedFiles'][fid] = {}
            connData['OpenedFiles'][fid]['FileHandle'] = openedFile
            connData['OpenedFiles'][fid]['FileName'] = pathName
            connData['OpenedFiles'][fid]['DeleteOnClose']  = False
        else:
            respParameters = ''
            respData       = ''
        
        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode
        
    def smbComTreeConnectAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS
        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']
        resp['Pid'] = connData['Pid']

        respSMBCommand        = smb.SMBCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX)
        respParameters        = smb.SMBTreeConnectAndXResponse_Parameters()
        respData              = smb.SMBTreeConnectAndXResponse_Data()

        treeConnectAndXParameters = smb.SMBTreeConnectAndX_Parameters(SMBCommand['Parameters'])

        if treeConnectAndXParameters['Flags'] & 0x8:
            respParameters        = smb.SMBTreeConnectAndXExtendedResponse_Parameters()

        treeConnectAndXData                    = smb.SMBTreeConnectAndX_Data()
        treeConnectAndXData['_PasswordLength'] = treeConnectAndXParameters['PasswordLength']
        treeConnectAndXData.fromString(SMBCommand['Data'])
        
        errorCode = STATUS_SUCCESS
        ## Process here the request, does the share exist?
        path = ntpath.basename(treeConnectAndXData['Path'])
        share = searchShare(connId, path, smbServer) 
        if share is not None:
            # Simple way to generate a Tid
            if len(connData['ConnectedShares']) == 0:
               tid = 1
            else:
               tid = connData['ConnectedShares'].keys()[-1] + 1
            connData['ConnectedShares'][tid] = share
            connData['ConnectedShares'][tid]['shareName'] = path
            resp['Tid'] = tid
            #smbServer.log("Connecting Share(%d:%s)" % (tid,path))
        else:
            smbServer.log("TreeConnectAndX not found %s" % path, logging.ERROR)
            errorCode = STATUS_OBJECT_PATH_NOT_FOUND
            resp['ErrorCode']   = errorCode >> 16
            resp['ErrorClass']  = errorCode & 0xff
        ##
        respParameters['OptionalSupport'] = smb.SMB.SMB_SUPPORT_SEARCH_BITS

        if path == 'IPC$':
            respData['Service']               = 'IPC'
        else:
            respData['Service']               = 'A:'
        respData['PadLen']                = 0
        respData['NativeFileSystem']      = 'NTFS'

        respSMBCommand['Parameters']             = respParameters
        respSMBCommand['Data']                   = respData 

        resp['Uid'] = connData['Uid']
        resp.addCommand(respSMBCommand)
        smbServer.setConnectionData(connId, connData)

        return None, [resp], errorCode

    def smbComSessionSetupAndX(self, connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus = False)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)

        if connData['_dialects_parameters']['Capabilities'] & smb.SMB.CAP_EXTENDED_SECURITY:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            respData       = smb.SMBSessionSetupAndX_Extended_Response_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Extended_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']

            if struct.unpack('B',sessionSetupData['SecurityBlob'][0])[0] != smb.ASN1_AID:
               # If there no GSSAPI ID, it must be an AUTH packet
               blob = smb.SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
               token = blob['ResponseToken']
            else:
               # NEGOTIATE packet
               blob =  smb.SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
               token = blob['MechToken']

            # Here we only handle NTLMSSP, depending on what stage of the 
            # authentication we are, we act on it
            messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                # Let's store it in the connection data
                connData['NEGOTIATE_MESSAGE'] = negotiateMessage
                # Let's build the answer flags
                # TODO: Parse all the flags. With this we're leaving some clients out 

                ansFlags = 0

                if negotiateMessage['flags'] & ntlm.NTLMSSP_KEY_56:
                   ansFlags |= ntlm.NTLMSSP_KEY_56
                if negotiateMessage['flags'] & ntlm.NTLMSSP_KEY_128:
                   ansFlags |= ntlm.NTLMSSP_KEY_128
                if negotiateMessage['flags'] & ntlm.NTLMSSP_KEY_EXCHANGE:
                   ansFlags |= ntlm.NTLMSSP_KEY_EXCHANGE
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NTLM2_KEY:
                   ansFlags |= ntlm.NTLMSSP_NTLM2_KEY
                if negotiateMessage['flags'] & ntlm.NTLMSSP_UNICODE:
                   ansFlags |= ntlm.NTLMSSP_UNICODE
                if negotiateMessage['flags'] & ntlm.NTLMSSP_OEM:
                   ansFlags |= ntlm.NTLMSSP_OEM

                ansFlags |= ntlm.NTLMSSP_VERSION | ntlm.NTLMSSP_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NTLM_KEY | ntlm.NTLMSSP_TARGET

                # Generate the AV_PAIRS
                av_pairs = ntlm.AV_PAIRS()
                # TODO: Put the proper data from SMBSERVER config
                av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = smbServer.getServerName().encode('utf-16le')
                av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = smbServer.getServerDomain().encode('utf-16le')
                av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )

                challengeMessage = ntlm.NTLMAuthChallenge()
                challengeMessage['flags']            = ansFlags
                challengeMessage['domain_len']       = len(smbServer.getServerDomain().encode('utf-16le'))
                challengeMessage['domain_max_len']   = challengeMessage['domain_len']
                challengeMessage['domain_offset']    = 40 + 16
                # TODO: Use a real challenge
                # TODO: let the user choose the challenge :)
                challengeMessage['challenge']        = 'A' * 8 
                challengeMessage['domain_name']      = smbServer.getServerDomain().encode('utf-16le')
                challengeMessage['TargetInfoFields_len']     = len(av_pairs)
                challengeMessage['TargetInfoFields_max_len'] = len(av_pairs)
                challengeMessage['TargetInfoFields'] = av_pairs
                challengeMessage['TargetInfoFields_offset']  = 40 + 16 + len(challengeMessage['domain_name'])
                challengeMessage['Version']          = '\xff'*8
                challengeMessage['VersionLen']       = 8

                respToken = smb.SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = '\x01'  
                respToken['SupportedMech'] = smb.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = challengeMessage.getData()

                # Setting the packet to STATUS_MORE_PROCESSING
                errorCode = STATUS_MORE_PROCESSING_REQUIRED
                # Let's set up an UID for this connection and store it 
                # in the connection's data
                # Picking a fixed value
                # TODO: Manage more UIDs for the same session
                connData['Uid'] = 10
                # Let's store it in the connection data
                connData['CHALLENGE_MESSAGE'] = challengeMessage

            elif messageType == 0x02:
                # CHALLENGE_MESSAGE
                raise Exception('Challenge Message raise, not implemented!')
            elif messageType == 0x03:
                # AUTHENTICATE_MESSAGE, here we deal with authentication
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)
                smbServer.log("AUTHENTICATE_MESSAGE (%s\\%s,%s)" % (authenticateMessage['domain_name'], authenticateMessage['user_name'], authenticateMessage['host_name']))
                # TODO: Check the credentials! Now granting permissions

                respToken = smb.SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegResult'] = '\x00'

                # Status SUCCESS
                errorCode = STATUS_SUCCESS
                smbServer.log('User %s\\%s authenticated successfully' % (authenticateMessage['user_name'], authenticateMessage['host_name']))
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
            else:
                raise("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters['SecurityBlobLength'] = len(respToken)

            respData['SecurityBlobLength'] = respParameters['SecurityBlobLength'] 
            respData['SecurityBlob']       = respToken.getData()

        else:
            # Process Standard Security
            respParameters = smb.SMBSessionSetupAndXResponse_Parameters()
            respData       = smb.SMBSessionSetupAndXResponse_Data()
            sessionSetupParameters = smb.SMBSessionSetupAndX_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Data()
            sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
            sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']
            # Do the verification here, for just now we grant access
            # TODO: Manage more UIDs for the same session
            errorCode = STATUS_SUCCESS
            connData['Uid'] = 10
            respParameters['Action'] = 0
            smbServer.log('User %s\\%s authenticated successfully (basic)' % (sessionSetupData['PrimaryDomain'], sessionSetupData['Account']))


        respData['NativeOS']     = smbServer.getServerOS()
        respData['NativeLanMan'] = smbServer.getServerOS()
        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data']       = respData 

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        # For now, just switching to nobody
        #os.setregid(65534,65534)
        #os.setreuid(65534,65534)
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    def smbComNegotiate(self, connId, smbServer, SMBCommand, recvPacket ):
        connData = smbServer.getConnectionData(connId, checkStatus = False)
        connData['Pid'] = recvPacket['Pid']

        SMBCommand = smb.SMBCommand(recvPacket['Data'][0])
        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)
        
        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Pid'] = connData['Pid']
        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']

        # TODO: We support more dialects, and parse them accordingly
        dialects = SMBCommand['Data'].split('\x02')
        try: 
           index = dialects.index('NT LM 0.12\x00') - 1
           # Let's fill the data for NTLM
           if recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY:
                    resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS
                    _dialects_data = smb.SMBExtended_Security_Data()
                    _dialects_data['ServerGUID'] = 'A'*16
                    blob = smb.SPNEGO_NegTokenInit()
                    blob['MechTypes'] = [smb.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
                    _dialects_data['SecurityBlob'] = blob.getData()
        
                    _dialects_parameters = smb.SMBExtended_Security_Parameters()
                    _dialects_parameters['Capabilities']    = smb.SMB.CAP_EXTENDED_SECURITY | smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS 
                    #_dialects_parameters['Capabilities']    = 0x8001e3fc

           else:
                    resp['Flags2'] = smb.SMB.FLAGS2_NT_STATUS
                    _dialects_parameters = smb.SMBNTLMDialect_Parameters()
                    _dialects_data= smb.SMBNTLMDialect_Data()
                    if connData.has_key('EncryptionKey'):
                        _dialects_data['Challenge'] = connData['EncryptionKey']
                    else:
                        # TODO: Handle random challenges, now one that can be used with rainbow tables
                        _dialects_data['Challenge'] = '\x11\x22\x33\x44\x55\x66\x77\x88'
                    _dialects_parameters['Capabilities']    = smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS
                    _dialects_data['Payload'] = ''

           _dialects_parameters['DialectIndex']    = index
           _dialects_parameters['SecurityMode']    = smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
           _dialects_parameters['MaxMpxCount']     = 50
           _dialects_parameters['MaxNumberVcs']    = 1
           if sys.platform == 'win32':
               _dialects_parameters['MaxBufferSize']   = 1500
               _dialects_parameters['MaxRawSize']      = 1500
           else:
               _dialects_parameters['MaxBufferSize']   = 64000
               _dialects_parameters['MaxRawSize']      = 65536
           _dialects_parameters['SessionKey']      = 0
           _dialects_parameters['LowDateTime']     = 0
           _dialects_parameters['HighDateTime']    = 0
           _dialects_parameters['ServerTimeZone']  = 0 
           _dialects_parameters['ChallengeLength'] = len(str(_dialects_data))


           respSMBCommand['Data']           = _dialects_data
           respSMBCommand['Parameters']     = _dialects_parameters
           connData['_dialects_data']       = _dialects_data
           connData['_dialects_parameters'] = _dialects_parameters

        except Exception, e:
           # No NTLM throw an error
           smbServer.log('smbComNegotiate: %s' % e, logging.ERROR)
           respSMBCommand['Data'] = struct.pack('<H',0xffff) 

       
        smbServer.setConnectionData(connId, connData)

        resp.addCommand(respSMBCommand)
        
        return None, [resp], STATUS_SUCCESS

    def default(self, connId, smbServer, SMBCommand, recvPacket):
        # By default we return an SMB Packet with error not implemented
        smbServer.log("Not implemented command: 0x%x" % recvPacket['Command'],logging.ERROR)
        packet = smb.NewSMBPacket()
        packet['Flags1']  = smb.SMB.FLAGS1_REPLY
        packet['Flags2']  = smb.SMB.FLAGS2_NT_STATUS 
        packet['Command'] = recvPacket['Command']
        packet['Pid']     = recvPacket['Pid']
        packet['Tid']     = recvPacket['Tid']
        packet['Mid']     = recvPacket['Mid']
        packet['Uid']     = recvPacket['Uid']
        packet['Data']    = '\x00\x00\x00'
        errorCode = STATUS_NOT_IMPLEMENTED
        packet['ErrorCode']   = errorCode >> 16
        packet['ErrorClass']  = errorCode & 0xff

        return None, [packet], errorCode
        

class SMBSERVERHandler(SocketServer.BaseRequestHandler):

    def __init__(self, request, client_address, server, select_poll = False):
        self.__SMB = server
        self.__ip, self.__port = client_address
        self.__request = request
        self.__connId = threading.currentThread().getName()
        self.__timeOut = 60*5
        self.__select_poll = select_poll
        #self.__connId = os.getpid()
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        self.__SMB.log("Incoming connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.addConnection(self.__connId, self.__ip, self.__port)
        while True:
            try:
                # Firt of all let's get the NETBIOS packet
                session = nmb.NetBIOSTCPSession(self.__SMB.getServerName(),'HOST', self.__ip, sess_port = self.__port, sock = self.__request, select_poll = self.__select_poll)
                try:
                    p = session.recv_packet(self.__timeOut)
                except nmb.NetBIOSTimeout:
                    raise

                if p.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                   # Someone is requesting a session, we're gonna accept them all :)
                   _, rn, my = p.get_trailer().split(' ')
                   remote_name = nmb.decode_name('\x20'+rn)
                   myname = nmb.decode_name('\x20'+my) 
                   self.__SMB.log("NetBIOS Session request (%s,%s,%s)" % (self.__ip, remote_name[1].strip(), myname[1])) 
                   r = nmb.NetBIOSSessionPacket()
                   r.set_type(nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                   r.set_trailer(p.get_trailer())
                   self.__request.send(r.rawData())
                else:
                   resp = self.__SMB.processRequest(self.__connId, p.get_trailer())
                   # Send all the packets recevied. Except for big transactions this should be
                   # a single packet
                   for i in resp:
                       session.send_packet(str(i))
            except Exception, e:
                print "Handle: %s" % e
                break

    def finish(self):
        # Thread/process is dying, we should tell the main SMB thread to remove all this thread data
        self.__SMB.log("Closing down connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.removeConnection(self.__connId)
        return SocketServer.BaseRequestHandler.finish(self)

class SMBSERVER(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
#class SMBSERVER(SocketServer.ForkingMixIn, SocketServer.TCPServer):
    def __init__(self, server_address, handler_class=SMBSERVERHandler, config_parser = None):
        SocketServer.TCPServer.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address, handler_class)

        # Server name and OS to be presented whenever is necessary
        self.__serverName   = ''
        self.__serverOS     = ''
        self.__serverDomain = ''

        # Our ConfigParser data
        self.__serverConfig = None

        # Explicit configuration data, specified as an already-modified ConfigParser
        self.__configParser = config_parser

        # Our credentials to be used during the server's lifetime
        self.__credentials = {}

        # Our log file
        self.__logFile = ''

        # Registered Named Pipes, format is PipeName,Socket
        self.__registeredNamedPipes = {}
 
        # Our list of commands we will answer, by default the NOT IMPLEMENTED one
        self.__smbCommandsHandler = SMBCommands()
        self.__smbTrans2Handler   = TRANS2Commands()
        self.__smbTransHandler    = TRANSCommands()
        self.__smbNTTransHandler  = NTTRANSCommands()

        self.__smbNTTransCommands = {
        # NT IOCTL, can't find doc for this
        0xff                               :self.__smbNTTransHandler.default
        }

        self.__smbTransCommands  = {
'\\PIPE\\LANMAN'                       :self.__smbTransHandler.lanMan,
smb.SMB.TRANS_TRANSACT_NMPIPE          :self.__smbTransHandler.transactNamedPipe,
        }
        self.__smbTrans2Commands = {

 smb.SMB.TRANS2_FIND_FIRST2            :self.__smbTrans2Handler.findFirst2,
 smb.SMB.TRANS2_FIND_NEXT2             :self.__smbTrans2Handler.findNext2,
 smb.SMB.TRANS2_QUERY_FS_INFORMATION   :self.__smbTrans2Handler.queryFsInformation,
 smb.SMB.TRANS2_QUERY_PATH_INFORMATION :self.__smbTrans2Handler.queryPathInformation,
 smb.SMB.TRANS2_QUERY_FILE_INFORMATION :self.__smbTrans2Handler.queryFileInformation,
 smb.SMB.TRANS2_SET_FILE_INFORMATION   :self.__smbTrans2Handler.setFileInformation,
 smb.SMB.TRANS2_SET_PATH_INFORMATION   :self.__smbTrans2Handler.setPathInformation

        }

        self.__smbCommands = { 
 smb.SMB.SMB_COM_CREATE_DIRECTORY:   self.__smbCommandsHandler.smbComCreateDirectory, 
 smb.SMB.SMB_COM_DELETE_DIRECTORY:   self.__smbCommandsHandler.smbComDeleteDirectory, 
 smb.SMB.SMB_COM_RENAME:             self.__smbCommandsHandler.smbComRename, 
 smb.SMB.SMB_COM_DELETE:             self.__smbCommandsHandler.smbComDelete, 
 smb.SMB.SMB_COM_NEGOTIATE:          self.__smbCommandsHandler.smbComNegotiate, 
 smb.SMB.SMB_COM_SESSION_SETUP_ANDX: self.__smbCommandsHandler.smbComSessionSetupAndX,
 smb.SMB.SMB_COM_LOGOFF_ANDX:        self.__smbCommandsHandler.smbComLogOffAndX,
 smb.SMB.SMB_COM_TREE_CONNECT_ANDX:  self.__smbCommandsHandler.smbComTreeConnectAndX,
 smb.SMB.SMB_COM_TREE_DISCONNECT:    self.__smbCommandsHandler.smbComTreeDisconnect,
 smb.SMB.SMB_COM_ECHO:               self.__smbCommandsHandler.smbComEcho,
 smb.SMB.SMB_COM_QUERY_INFORMATION:  self.__smbCommandsHandler.smbQueryInformation,
 smb.SMB.SMB_COM_TRANSACTION2:       self.__smbCommandsHandler.smbTransaction2,
 smb.SMB.SMB_COM_TRANSACTION:        self.__smbCommandsHandler.smbTransaction,
 # Not needed for now
 smb.SMB.SMB_COM_NT_TRANSACT:        self.__smbCommandsHandler.smbNTTransact,
 smb.SMB.SMB_COM_QUERY_INFORMATION_DISK: self.__smbCommandsHandler.smbQueryInformationDisk,
 smb.SMB.SMB_COM_OPEN_ANDX:          self.__smbCommandsHandler.smbComOpenAndX,
 smb.SMB.SMB_COM_QUERY_INFORMATION2: self.__smbCommandsHandler.smbComQueryInformation2,
 smb.SMB.SMB_COM_READ_ANDX:          self.__smbCommandsHandler.smbComReadAndX,
 smb.SMB.SMB_COM_READ:               self.__smbCommandsHandler.smbComRead,
 smb.SMB.SMB_COM_WRITE_ANDX:         self.__smbCommandsHandler.smbComWriteAndX,
 smb.SMB.SMB_COM_WRITE:              self.__smbCommandsHandler.smbComWrite,
 smb.SMB.SMB_COM_CLOSE:              self.__smbCommandsHandler.smbComClose,
 smb.SMB.SMB_COM_LOCKING_ANDX:       self.__smbCommandsHandler.smbComLockingAndX,
 smb.SMB.SMB_COM_NT_CREATE_ANDX:     self.__smbCommandsHandler.smbComNtCreateAndX,
 0xFF:                               self.__smbCommandsHandler.default
}

        # List of active connections
        self.__activeConnections = {}
  
    def getCredentials(self):
        return self.__credentials

    def removeConnection(self, name):
        try:
           del(self.__activeConnections[name])
        except:
           pass
        self.log("Remaining connections %s" % self.__activeConnections.keys())

    def addConnection(self, name, ip, port):
        self.__activeConnections[name] = {}
        # Let's init with some know stuff we will need to have
        # TODO: Document what's in there
        #print "Current Connections", self.__activeConnections.keys()
        self.__activeConnections[name]['PacketNum']       = 0
        self.__activeConnections[name]['ClientIP']        = ip
        self.__activeConnections[name]['ClientPort']      = port
        self.__activeConnections[name]['Uid']             = 0
        self.__activeConnections[name]['ConnectedShares'] = {}
        self.__activeConnections[name]['OpenedFiles']     = {}
        # SID results for findfirst2
        self.__activeConnections[name]['SIDs']            = {}


    def setConnectionData(self, connId, data):
        self.__activeConnections[connId] = data
        #print "setConnectionData" 
        #print self.__activeConnections

    def getConnectionData(self, connId, checkStatus = True):
        conn = self.__activeConnections[connId]
        if checkStatus is True:
            if conn.has_key('Authenticated') is not True:
                # Can't keep going further
                raise Exception("User not Authenticated!")
        return conn

    def getRegisteredNamedPipes(self):
        return self.__registeredNamedPipes

    def registerNamedPipe(self, pipeName, address):
        self.__registeredNamedPipes[pipeName] = address
        return True

    def hookTransaction(self, transCommand, callback):
        # If you call this function, callback will replace 
        # the current Transaction sub command.
        # (don't get confused with the Transaction smbCommand)
        # If the transaction sub command doesn't not exist, it is added
        # If the transaction sub command exists, it returns the original function         # replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, recvPacket, parameters, data, maxDataCount=0)
        #
        # WHERE:
        #
        # connId      : the connection Id, used to grab/update information about 
        #               the current connection
        # smbServer   : the SMBServer instance available for you to ask 
        #               configuration data
        # recvPacket  : the full SMBPacket that triggered this command
        # parameters  : the transaction parameters
        # data        : the transaction data
        # maxDataCount: the max amount of data that can be transfered agreed 
        #               with the client
        #
        # and MUST return:
        # respSetup, respParameters, respData, errorCode
        #
        # WHERE:
        #
        # respSetup: the setup response of the transaction
        # respParameters: the parameters response of the transaction
        # respData: the data reponse of the transaction
        # errorCode: the NT error code 

        if self.__smbTransCommands[transCommand].has_key(transCommand):
           originalCommand = self.__smbTransCommands[transCommand]
        else:
           originalCommand = None 

        self.__smbTransCommands[transCommand] = callback
        return originalCommand

    def hookTransaction2(self, transCommand, callback):
        # Here we should add to __smbTrans2Commands
        # Same description as Transaction
        if self.__smbTrans2Commands[transCommand].has_key(transCommand):
           originalCommand = self.__smbTrans2Commands[transCommand]
        else:
           originalCommand = None 

        self.__smbTrans2Commands[transCommand] = callback
        return originalCommand

    def hookNTTransaction(self, transCommand, callback):
        # Here we should add to __smbNTTransCommands
        # Same description as Transaction
        if self.__smbNTTransCommands[transCommand].has_key(transCommand):
           originalCommand = self.__smbNTTransCommands[transCommand]
        else:
           originalCommand = None 

        self.__smbNTTransCommands[transCommand] = callback
        return originalCommand

    def hookSmbCommand(self, smbCommand, callback):
        # Here we should add to self.__smbCommands
        # If you call this function, callback will replace 
        # the current smbCommand.
        # If smbCommand doesn't not exist, it is added
        # If SMB command exists, it returns the original function replaced
        #
        # callback MUST be declared as:
        # callback(connId, smbServer, SMBCommand, recvPacket)
        #
        # WHERE:
        #
        # connId    : the connection Id, used to grab/update information about 
        #             the current connection
        # smbServer : the SMBServer instance available for you to ask 
        #             configuration data
        # SMBCommand: the SMBCommand itself, with its data and parameters. 
        #             Check smb.py:SMBCommand() for a reference
        # recvPacket: the full SMBPacket that triggered this command
        #
        # and MUST return:
        # <list of respSMBCommands>, <list of packets>, errorCode
        # <list of packets> has higher preference over commands, in case you 
        # want to change the whole packet 
        # errorCode: the NT error code 
        #
        # For SMB_COM_TRANSACTION2, SMB_COM_TRANSACTION and SMB_COM_NT_TRANSACT
        # the callback function is slightly different:
        #
        # callback(connId, smbServer, SMBCommand, recvPacket, transCommands)
        #
        # WHERE:
        # 
        # transCommands: a list of transaction subcommands already registered
        #

        if self.__smbCommands.has_key(smbCommand):
           originalCommand = self.__smbCommands[smbCommand]
        else:
           originalCommand = None 

        self.__smbCommands[smbCommand] = callback
        return originalCommand
  
    def log(self, msg, level=logging.INFO):
        self.__log.log(level,msg)

    def getServerName(self):
        return self.__serverName

    def getServerOS(self):
        return self.__serverOS
  
    def getServerDomain(self):
        return self.__serverDomain
  
    def getServerConfig(self):
        return self.__serverConfig

    def verify_request(self, request, client_address):
        # TODO: Control here the max amount of processes we want to launch
        # returning False, closes the connection
        return True

    def processRequest(self, connId, data):

        # TODO: Process batched commands.
        packet      = smb.NewSMBPacket(data = data)
        SMBCommand  = smb.SMBCommand(packet['Data'][0])

        try:
            # Search out list of implemented commands
            # We provide them with:
            # connId      : representing the data for this specific connection
            # self        : the SMBSERVER if they want to ask data to it
            # SMBCommand  : the SMBCommand they are expecting to process
            # packet      : the received packet itself, in case they need more data than the actual command
            # Only for Transactions
            # transCommand: a list of transaction subcommands
            # We expect to get:
            # respCommands: a list of answers for the commands processed
            # respPacket  : if the commands chose to directly craft packet/s, we use this and not the previous
            #               this MUST be a list
            # errorCode   : self explanatory
            if packet['Command'] == smb.SMB.SMB_COM_TRANSACTION2:
                respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                              connId, 
                              self, 
                              SMBCommand,
                              packet,
                              self.__smbTrans2Commands)
            elif packet['Command'] == smb.SMB.SMB_COM_NT_TRANSACT:
                respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                              connId, 
                              self, 
                              SMBCommand,
                              packet,
                              self.__smbNTTransCommands)
            elif packet['Command'] == smb.SMB.SMB_COM_TRANSACTION:
                respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                              connId, 
                              self, 
                              SMBCommand,
                              packet,
                              self.__smbTransCommands)
            else:
                if self.__smbCommands.has_key(packet['Command']):
                   respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                               connId, 
                               self, 
                               SMBCommand,
                               packet)
                else:
                   respCommands, respPackets, errorCode = self.__smbCommands[255](connId, self, SMBCommand, packet)   

        except Exception, e:
            # Something wen't wrong, defaulting to Bad user ID
            self.log('processRequest (0x%x,%s)' % (packet['Command'],e), logging.ERROR)
            raise
            packet['Flags1'] |= smb.SMB.FLAGS1_REPLY
            packet['Flags2'] = 0
            errorCode = STATUS_SMB_BAD_UID
            packet['ErrorCode']   = errorCode >> 16
            packet['ErrorClass']  = errorCode & 0xff
            return [packet]

        # We prepare the response packet to commands don't need to bother about that.
        connData    = self.getConnectionData(connId, False)

        # Force reconnection loop.. This is just a test.. client will send me back credentials :)
        #connData['PacketNum'] += 1
        #if connData['PacketNum'] == 15:
        #    connData['PacketNum'] = 0
        #    # Something wen't wrong, defaulting to Bad user ID
        #    self.log('Sending BAD USER ID!', logging.ERROR)
        #    #raise
        #    packet['Flags1'] |= smb.SMB.FLAGS1_REPLY
        #    packet['Flags2'] = 0
        #    errorCode = STATUS_SMB_BAD_UID
        #    packet['ErrorCode']   = errorCode >> 16
        #    packet['ErrorClass']  = errorCode & 0xff
        #    return [packet]

        self.setConnectionData(connId, connData)    

        packetsToSend = []
        if respPackets is None:
            for respCommand in respCommands:
                respPacket           = smb.NewSMBPacket()
                respPacket['Flags1'] = smb.SMB.FLAGS1_REPLY

                # TODO this should come from a per session configuration
                respPacket['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES
                #respPacket['Flags1'] = 0x98
                #respPacket['Flags2'] = 0xc807
                

                respPacket['Tid']    = packet['Tid']
                respPacket['Mid']    = packet['Mid']
                respPacket['Pid']    = packet['Pid']
                respPacket['Uid']    = connData['Uid']
        
                respPacket['ErrorCode']   = errorCode >> 16
                respPacket['_reserved']   = errorCode >> 8 & 0xff
                respPacket['ErrorClass']  = errorCode & 0xff
                respPacket.addCommand(respCommand)
            
                packetsToSend.append(respPacket)
        else:
            # The SMBCommand took care of building the packet
            packetsToSend = respPackets

        return packetsToSend

    def processConfigFile(self, configFile = None):
        # TODO: Do a real config parser
        if self.__configParser is None:
            if configFile is None:
                configFile = self.__configFile
            self.__serverConfig = ConfigParser.ConfigParser()
            self.__serverConfig.read(configFile)
        else:
           self.__serverConfig = self.__configParser

        self.__serverName   = self.__serverConfig.get('global','server_name')
        self.__serverOS     = self.__serverConfig.get('global','server_os')
        self.__serverDomain = self.__serverConfig.get('global','server_domain')
        self.__logFile      = self.__serverConfig.get('global','log_file')
        logging.basicConfig(filename = self.__logFile, 
                         level = logging.DEBUG, 
                         format="%(asctime)s: %(levelname)s: %(message)s", 
                         datefmt = '%m/%d/%Y %I:%M:%S %p')
        self.__log        = logging.getLogger()

        # Process the credentials
        credentials_fname = self.__serverConfig.get('global','credentials_file')
        if credentials_fname is not "":
            cred = open(credentials_fname)
            line = cred.readline()
            while line:
                name, domain, lmhash, nthash = line.split(':')
                self.__credentials[name] = (domain, lmhash, nthash.strip('\r\n'))
                line = cred.readline()
            cred.close()
        self.log('Config file parsed')     

# NT ERRORS and STATUS codes
STATUS_SUCCESS                       = 0x00000000
STATUS_FILE_IS_A_DIRECTORY           = 0xC00000BA
STATUS_ACCESS_DENIED                 = 0xC0000022
STATUS_MORE_PROCESSING_REQUIRED      = 0xC0000016
STATUS_NOT_SUPPORTED                 = 0xC00000BB
STATUS_OBJECT_NAME_NOT_FOUND         = 0xC0000034
STATUS_OBJECT_PATH_NOT_FOUND         = 0xC000003A
STATUS_SMB_BAD_TID                   = 0x00050002
STATUS_SMB_BAD_UID                   = 0x005B0002
STATUS_NO_SUCH_FILE                  = 0xC000000F
STATUS_OBJECT_NAME_COLLISION         = 0xC0000035
STATUS_DIRECTORY_NOT_EMPTY           = 0xC0000101
STATUS_INVALID_HANDLE                = 0xC0000008
STATUS_NOT_IMPLEMENTED               = 0xC0000002
STATUS_LOGON_FAILURE                 = 0xC000006d

# For windows platforms, opening a directory is not an option, so we set a void FD
VOID_FILE_DESCRIPTOR = -1
PIPE_FILE_DESCRIPTOR = -2
