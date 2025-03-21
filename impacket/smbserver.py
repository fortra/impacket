# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#   Alberto Solino (@agsolino)
#
# TODO:
#   [-] Functions should return NT error codes
#   [-] Handling errors in all situations, right now it's just raising exceptions.
#   [*] Standard authentication support
#   [ ] Organize the connectionData stuff
#   [*] Add capability to send a bad user ID if the user is not authenticated,
#       right now you can ask for any command without actually being authenticated
#   [ ] PATH TRAVERSALS EVERYWHERE.. BE WARNED!
#   [ ] Check error situation (now many places assume the right data is coming)
#   [ ] Implement IPC to the main process so the connectionData is on a single place
#   [ ] Hence.. implement locking
# estamos en la B

import calendar
import socket
import time
import datetime
import struct
import threading
import logging
import logging.config
import ntpath
import os
import fnmatch
import errno
import sys
import random
import shutil
import string
import hashlib
import hmac

from binascii import unhexlify, hexlify, a2b_hex
from six import b, ensure_str
from six.moves import configparser, socketserver

# For signing
from impacket import smb, nmb, ntlm, uuid
from impacket import smb3structs as smb2
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, MechTypes, SPNEGO_NegTokenResp, ASN1_AID, \
    ASN1_SUPPORTED_MECH
from impacket.nt_errors import STATUS_NO_MORE_FILES, STATUS_NETWORK_NAME_DELETED, STATUS_INVALID_PARAMETER, \
    STATUS_FILE_CLOSED, STATUS_MORE_PROCESSING_REQUIRED, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_DIRECTORY_NOT_EMPTY, \
    STATUS_FILE_IS_A_DIRECTORY, STATUS_NOT_IMPLEMENTED, STATUS_INVALID_HANDLE, STATUS_OBJECT_NAME_COLLISION, \
    STATUS_NO_SUCH_FILE, STATUS_CANCELLED, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS, STATUS_ACCESS_DENIED, \
    STATUS_NOT_SUPPORTED, STATUS_INVALID_DEVICE_REQUEST, STATUS_FS_DRIVER_REQUIRED, STATUS_INVALID_INFO_CLASS, \
    STATUS_LOGON_FAILURE, STATUS_OBJECT_PATH_SYNTAX_BAD

# Setting LOG to current's module name
LOG = logging.getLogger(__name__)

# These ones not defined in nt_errors
STATUS_SMB_BAD_UID = 0x005B0002
STATUS_SMB_BAD_TID = 0x00050002


# Utility functions
# and general functions.
# There are some common functions that can be accessed from more than one SMB
# command (or either TRANSACTION). That's why I'm putting them here
# TODO: Return NT ERROR Codes

def computeNTLMv2(identity, lmhash, nthash, serverChallenge, authenticateMessage, ntlmChallenge, type1):
    # Let's calculate the NTLMv2 Response

    responseKeyNT = ntlm.NTOWFv2(identity, '', authenticateMessage['domain_name'].decode('utf-16le'), nthash)
    responseKeyLM = ntlm.LMOWFv2(identity, '', authenticateMessage['domain_name'].decode('utf-16le'), lmhash)

    ntProofStr = authenticateMessage['ntlm'][:16]
    temp = authenticateMessage['ntlm'][16:]
    ntProofStr2 = ntlm.hmac_md5(responseKeyNT, serverChallenge + temp)
    lmChallengeResponse = authenticateMessage['lanman']
    sessionBaseKey = ntlm.hmac_md5(responseKeyNT, ntProofStr)

    responseFlags = type1['flags']

    # Let's check the return flags
    if (ntlmChallenge['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) == 0:
        # No extended session security, taking it out
        responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    if (ntlmChallenge['flags'] & ntlm.NTLMSSP_NEGOTIATE_128) == 0:
        # No support for 128 key len, taking it out
        responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_128
    if (ntlmChallenge['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH) == 0:
        # No key exchange supported, taking it out
        responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
    if (ntlmChallenge['flags'] & ntlm.NTLMSSP_NEGOTIATE_SEAL) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_SEAL
    if (ntlmChallenge['flags'] & ntlm.NTLMSSP_NEGOTIATE_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_SIGN
    if (ntlmChallenge['flags'] & ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN) == 0:
        # No sign available, taking it out
        responseFlags &= 0xffffffff ^ ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN

    keyExchangeKey = ntlm.KXKEY(ntlmChallenge['flags'], sessionBaseKey, lmChallengeResponse,
                                ntlmChallenge['challenge'], '',
                                lmhash, nthash, True)

    # If we set up key exchange, let's fill the right variables
    if ntlmChallenge['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
        exportedSessionKey = authenticateMessage['session_key']
        exportedSessionKey = ntlm.generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey)
    else:
        encryptedRandomSessionKey = None
        # [MS-NLMP] page 46
        exportedSessionKey = keyExchangeKey

    # Do they match?
    if ntProofStr == ntProofStr2:
        # Yes!, process login
        return STATUS_SUCCESS, exportedSessionKey
    else:
        return STATUS_LOGON_FAILURE, exportedSessionKey


def outputToJohnFormat(challenge, username, domain, lmresponse, ntresponse):
    # We don't want to add a possible failure here, since this is an
    # extra bonus. We try, if it fails, returns nothing
    # ToDo: Document the parameter's types (bytes / string) and check all the places where it's called
    ret_value = ''
    if type(challenge) is not bytes:
        challenge = challenge.decode('latin-1')

    try:
        if len(ntresponse) > 24:
            # Extended Security - NTLMv2
            ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                username.decode('utf-16le'), domain.decode('utf-16le'), hexlify(challenge).decode('latin-1'),
                hexlify(ntresponse).decode('latin-1')[:32],
                hexlify(ntresponse).decode()[32:]), 'hash_version': 'ntlmv2'}
        else:
            # NTLMv1
            ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                username.decode('utf-16le'), domain.decode('utf-16le'), hexlify(lmresponse).decode('latin-1'),
                hexlify(ntresponse).decode('latin-1'),
                hexlify(challenge).decode()), 'hash_version': 'ntlm'}
    except:
        # Let's try w/o decoding Unicode
        try:
            if len(ntresponse) > 24:
                # Extended Security - NTLMv2
                ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                    username.decode('latin-1'), domain.decode('latin-1'), hexlify(challenge).decode('latin-1'),
                    hexlify(ntresponse)[:32].decode('latin-1'), hexlify(ntresponse)[32:].decode('latin-1')),
                             'hash_version': 'ntlmv2'}
            else:
                # NTLMv1
                ret_value = {'hash_string': '%s::%s:%s:%s:%s' % (
                    username, domain, hexlify(lmresponse).decode('latin-1'), hexlify(ntresponse).decode('latin-1'),
                    hexlify(challenge).decode('latin-1')), 'hash_version': 'ntlm'}
        except Exception as e:
            import traceback
            traceback.print_exc()
            LOG.error("outputToJohnFormat: %s" % e)
            pass

    return ret_value


def writeJohnOutputToFile(hash_string, hash_version, file_name):
    fn_data = os.path.splitext(file_name)
    if hash_version == "ntlmv2":
        output_filename = fn_data[0] + "_ntlmv2" + fn_data[1]
    else:
        output_filename = fn_data[0] + "_ntlm" + fn_data[1]

    with open(output_filename, "a") as f:
        f.write(hash_string)
        f.write('\n')


def decodeSMBString(flags, text):
    if flags & smb.SMB.FLAGS2_UNICODE:
        return text.decode('utf-16le')
    else:
        return text


def encodeSMBString(flags, text):
    if flags & smb.SMB.FLAGS2_UNICODE:
        return (text).encode('utf-16le')
    else:
        return text.encode('ascii')


def getFileTime(t):
    t *= 10000000
    t += 116444736000000000
    return t


def getUnixTime(t):
    t -= 116444736000000000
    t //= 10000000
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
    del (sections[sections.index('global')])
    shares = {}
    for i in sections:
        shares[i] = dict(config.items(i))
    return shares


def searchShare(connId, share, smbServer):
    share = ensure_str(share)
    config = smbServer.getServerConfig()
    if config.has_section(share):
        return dict(config.items(share))
    else:
        return None


def normalize_path(file_name, path=None):
    """Normalizes a path by replacing "\" with "/" and stripping potential
    leading "/" chars. If a path is provided, only strip leading '/' when
    the path is empty.

    :param file_name: file name to normalize
    :type file_name: string

    :param path: path to normalize
    :type path: string

    :return normalized file name
    :rtype string
    """
    file_name = os.path.normpath(file_name.replace('\\', '/'))
    if len(file_name) > 0 and (file_name[0] == '/' or file_name[0] == '\\'):
        if path is None or path != '':
            # Strip leading "/"
            file_name = file_name[1:]
    return file_name


def isInFileJail(path, file_name):
    """Validates if a provided file name path is inside a path. This function is used
    to check for path traversals.

    :param path: base path to check
    :type path: string
    :param file_name: file name to validate
    :type file_name: string

    :return whether the file name is inside the base path or not
    :rtype bool
    """
    path_name = os.path.join(path, file_name)
    share_real_path = os.path.realpath(path)
    return os.path.commonprefix((os.path.realpath(path_name), share_real_path)) == share_real_path


def openFile(path, fileName, accessMode, fileAttributes, openMode):
    fileName = normalize_path(fileName)
    pathName = os.path.join(path, fileName)
    errorCode = 0
    mode = 0

    if not isInFileJail(path, fileName):
        LOG.error("Path not in current working directory")
        errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD
        return 0, mode, pathName, errorCode

    # Check the Open Mode
    if openMode & 0x10:
        # If the file does not exist, create it.
        mode = os.O_CREAT
    else:
        # If file does not exist, return an error
        if os.path.exists(pathName) is not True:
            errorCode = STATUS_NO_SUCH_FILE
            return 0, mode, pathName, errorCode

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
    except Exception as e:
        LOG.error("openFile: %s,%s" % (pathName, mode), e)
        fid = 0
        errorCode = STATUS_ACCESS_DENIED

    return fid, mode, pathName, errorCode


def queryFsInformation(path, filename, level=None, pktFlags=smb.SMB.FLAGS2_UNICODE):
    if pktFlags & smb.SMB.FLAGS2_UNICODE:
        encoding = 'utf-16le'
    else:
        encoding = 'ascii'

    fileName = normalize_path(filename)
    pathName = os.path.join(path, fileName)
    fileSize = os.path.getsize(pathName)
    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)

    if level is None:
        lastWriteTime = mtime
        attribs = 0
        if os.path.isdir(pathName):
            attribs |= smb.SMB_FILE_ATTRIBUTE_DIRECTORY
        if os.path.isfile(pathName):
            attribs |= smb.SMB_FILE_ATTRIBUTE_NORMAL
        fileAttributes = attribs
        return fileSize, lastWriteTime, fileAttributes

    elif level == smb.SMB_QUERY_FS_ATTRIBUTE_INFO or level == smb2.SMB2_FILESYSTEM_ATTRIBUTE_INFO:
        data = smb.SMBQueryFsAttributeInfo()
        data['FileSystemAttributes'] = smb.FILE_CASE_SENSITIVE_SEARCH | smb.FILE_CASE_PRESERVED_NAMES
        data['MaxFilenNameLengthInBytes'] = 255
        data['LengthOfFileSystemName'] = len('XTFS') * 2
        data['FileSystemName'] = 'XTFS'.encode('utf-16le')
        return data.getData()
    elif level == smb.SMB_INFO_VOLUME:
        data = smb.SMBQueryFsInfoVolume(flags=pktFlags)
        data['VolumeLabel'] = 'SHARE'.encode(encoding)
        return data.getData()
    elif level == smb.SMB_QUERY_FS_VOLUME_INFO or level == smb2.SMB2_FILESYSTEM_VOLUME_INFO:
        data = smb.SMBQueryFsVolumeInfo()
        data['VolumeLabel'] = ''
        data['VolumeCreationTime'] = getFileTime(ctime)
        return data.getData()
    elif level == smb.SMB_QUERY_FS_SIZE_INFO:
        data = smb.SMBQueryFsSizeInfo()
        return data.getData()
    elif level == smb.SMB_QUERY_FS_DEVICE_INFO or level == smb2.SMB2_FILESYSTEM_DEVICE_INFO:
        data = smb.SMBQueryFsDeviceInfo()
        data['DeviceType'] = smb.FILE_DEVICE_DISK
        return data.getData()
    elif level == smb.FILE_FS_FULL_SIZE_INFORMATION:
        data = smb.SMBFileFsFullSizeInformation()
        return data.getData()
    elif level == smb.FILE_FS_SIZE_INFORMATION:
        data = smb.FileFsSizeInformation()
        return data.getData()
    else:
        return None


def findFirst2(path, fileName, level, searchAttributes, pktFlags=smb.SMB.FLAGS2_UNICODE, isSMB2=False):
    # TODO: Depending on the level, this could be done much simpler

    # Let's choose the right encoding depending on the request
    if pktFlags & smb.SMB.FLAGS2_UNICODE:
        encoding = 'utf-16le'
    else:
        encoding = 'ascii'

    fileName = normalize_path(fileName)
    pathName = os.path.join(path, fileName)

    if not isInFileJail(path, fileName):
        LOG.error("Path not in current working directory")
        return [], 0, STATUS_OBJECT_PATH_SYNTAX_BAD

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
        files.append(os.path.join(dirName, '.'))
        files.append(os.path.join(dirName, '..'))

    if pattern != '':
        if not os.path.exists(dirName):
            return None, 0, STATUS_OBJECT_NAME_NOT_FOUND

        for file in os.listdir(dirName):
            if fnmatch.fnmatch(file.lower(), pattern.lower()):
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

    for i in files:
        if level == smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO or level == smb2.SMB2_FILE_BOTH_DIRECTORY_INFO:
            item = smb.SMBFindFileBothDirectoryInfo(flags=pktFlags)
        elif level == smb.SMB_FIND_FILE_DIRECTORY_INFO or level == smb2.SMB2_FILE_DIRECTORY_INFO:
            item = smb.SMBFindFileDirectoryInfo(flags=pktFlags)
        elif level == smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO or level == smb2.SMB2_FULL_DIRECTORY_INFO:
            item = smb.SMBFindFileFullDirectoryInfo(flags=pktFlags)
        elif level == smb.SMB_FIND_INFO_STANDARD:
            item = smb.SMBFindInfoStandard(flags=pktFlags)
        elif level == smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO or level == smb2.SMB2_FILE_ID_FULL_DIRECTORY_INFO:
            item = smb.SMBFindFileIdFullDirectoryInfo(flags=pktFlags)
        elif level == smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO or level == smb2.SMB2_FILE_ID_BOTH_DIRECTORY_INFO:
            item = smb.SMBFindFileIdBothDirectoryInfo(flags=pktFlags)
        elif level == smb.SMB_FIND_FILE_NAMES_INFO or level == smb2.SMB2_FILE_NAMES_INFO:
            item = smb.SMBFindFileNamesInfo(flags=pktFlags)
        else:
            LOG.error("Wrong level %d!" % level)
            return searchResult, searchCount, STATUS_NOT_SUPPORTED

        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(i)
        if os.path.isdir(i):
            item['ExtFileAttributes'] = smb.ATTR_DIRECTORY
        else:
            item['ExtFileAttributes'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE

        item['FileName'] = os.path.basename(i).encode(encoding)

        if level in [smb.SMB_FIND_FILE_BOTH_DIRECTORY_INFO, smb2.SMB2_FILE_BOTH_DIRECTORY_INFO,
                     smb.SMB_FIND_FILE_ID_BOTH_DIRECTORY_INFO, smb2.SMB2_FILE_ID_BOTH_DIRECTORY_INFO]:
            item['EaSize'] = 0
            item['EndOfFile'] = size
            item['AllocationSize'] = size
            item['CreationTime'] = getFileTime(ctime)
            item['LastAccessTime'] = getFileTime(atime)
            item['LastWriteTime'] = getFileTime(mtime)
            item['LastChangeTime'] = getFileTime(mtime)
            item['ShortName'] = '\x00' * 24
            item['FileName'] = os.path.basename(i).encode(encoding)
            padLen = (8 - (len(item) % 8)) % 8
            item['NextEntryOffset'] = len(item) + padLen
        elif level in [smb.SMB_FIND_FILE_DIRECTORY_INFO, smb2.SMB2_FILE_DIRECTORY_INFO]:
            item['EndOfFile'] = size
            item['AllocationSize'] = size
            item['CreationTime'] = getFileTime(ctime)
            item['LastAccessTime'] = getFileTime(atime)
            item['LastWriteTime'] = getFileTime(mtime)
            item['LastChangeTime'] = getFileTime(mtime)
            item['FileName'] = os.path.basename(i).encode(encoding)
            padLen = (8 - (len(item) % 8)) % 8
            item['NextEntryOffset'] = len(item) + padLen
        elif level in [smb.SMB_FIND_FILE_FULL_DIRECTORY_INFO, smb.SMB_FIND_FILE_ID_FULL_DIRECTORY_INFO,
                       smb2.SMB2_FULL_DIRECTORY_INFO, smb2.SMB2_FILE_ID_FULL_DIRECTORY_INFO]:
            item['EaSize'] = 0
            item['EndOfFile'] = size
            item['AllocationSize'] = size
            item['CreationTime'] = getFileTime(ctime)
            item['LastAccessTime'] = getFileTime(atime)
            item['LastWriteTime'] = getFileTime(mtime)
            item['LastChangeTime'] = getFileTime(mtime)
            padLen = (8 - (len(item) % 8)) % 8
            item['NextEntryOffset'] = len(item) + padLen
        elif level == smb.SMB_FIND_INFO_STANDARD:
            item['EaSize'] = size
            item['CreationDate'] = getSMBDate(ctime)
            item['CreationTime'] = getSMBTime(ctime)
            item['LastAccessDate'] = getSMBDate(atime)
            item['LastAccessTime'] = getSMBTime(atime)
            item['LastWriteDate'] = getSMBDate(mtime)
            item['LastWriteTime'] = getSMBTime(mtime)
        elif level in [smb.SMB_FIND_FILE_NAMES_INFO, smb2.SMB2_FILE_NAMES_INFO]:
            padLen = (8 - (len(item) % 8)) % 8
            item['NextEntryOffset'] = len(item) + padLen
        searchResult.append(item)

    # No more files
    if (level >= smb.SMB_FIND_FILE_DIRECTORY_INFO or isSMB2 is True) and searchCount > 0:
        searchResult[-1]['NextEntryOffset'] = 0

    return searchResult, searchCount, errorCode


def queryFileInformation(path, filename, level):
    # print "queryFileInfo path: %s, filename: %s, level:0x%x" % (path,filename,level)
    return queryPathInformation(path, filename, level)


def queryPathInformation(path, filename, level):
    # TODO: Depending on the level, this could be done much simpler
    try:
        errorCode = 0
        fileName = normalize_path(filename, path)
        pathName = os.path.join(path, fileName)

        if not isInFileJail(path, fileName):
            LOG.error("Path not in current working directory")
            return None, STATUS_OBJECT_PATH_SYNTAX_BAD

        if os.path.exists(pathName):
            (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
            if os.path.isdir(pathName):
                fileAttributes = smb.ATTR_DIRECTORY
            else:
                fileAttributes = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE

            if level == smb.SMB_QUERY_FILE_BASIC_INFO:
                infoRecord = smb.SMBQueryFileBasicInfo()
                infoRecord['CreationTime'] = getFileTime(ctime)
                infoRecord['LastAccessTime'] = getFileTime(atime)
                infoRecord['LastWriteTime'] = getFileTime(mtime)
                infoRecord['LastChangeTime'] = getFileTime(mtime)
                infoRecord['ExtFileAttributes'] = fileAttributes
            elif level == smb2.SMB2_FILE_BASIC_INFO:
                infoRecord = smb2.FILE_BASIC_INFORMATION()
                infoRecord['CreationTime'] = getFileTime(ctime)
                infoRecord['LastAccessTime'] = getFileTime(atime)
                infoRecord['LastWriteTime'] = getFileTime(mtime)
                infoRecord['ChangeTime'] = getFileTime(mtime)
                infoRecord['FileAttributes'] = fileAttributes
            elif level == smb.SMB_QUERY_FILE_STANDARD_INFO:
                infoRecord = smb.SMBQueryFileStandardInfo()
                infoRecord['AllocationSize'] = size
                infoRecord['EndOfFile'] = size
                if os.path.isdir(pathName):
                    infoRecord['Directory'] = 1
                else:
                    infoRecord['Directory'] = 0
            elif level == smb2.SMB2_FILE_STANDARD_INFO:
                infoRecord = smb2.FILE_STANDARD_INFORMATION()
                infoRecord['AllocationSize'] = size
                infoRecord['EndOfFile'] = size
                infoRecord['NumberOfLinks'] = 0
                if os.path.isdir(pathName):
                    infoRecord['Directory'] = 1
                else:
                    infoRecord['Directory'] = 0
            elif level == smb.SMB_QUERY_FILE_ALL_INFO:
                infoRecord = smb.SMBQueryFileAllInfo()
                infoRecord['CreationTime'] = getFileTime(ctime)
                infoRecord['LastAccessTime'] = getFileTime(atime)
                infoRecord['LastWriteTime'] = getFileTime(mtime)
                infoRecord['LastChangeTime'] = getFileTime(mtime)
                infoRecord['ExtFileAttributes'] = fileAttributes
                infoRecord['AllocationSize'] = size
                infoRecord['EndOfFile'] = size
                if os.path.isdir(pathName):
                    infoRecord['Directory'] = 1
                else:
                    infoRecord['Directory'] = 0
                infoRecord['FileName'] = filename.encode('utf-16le')
            elif level == smb2.SMB2_FILE_ALL_INFO:
                infoRecord = smb2.FILE_ALL_INFORMATION()
                infoRecord['BasicInformation'] = smb2.FILE_BASIC_INFORMATION()
                infoRecord['StandardInformation'] = smb2.FILE_STANDARD_INFORMATION()
                infoRecord['InternalInformation'] = smb2.FILE_INTERNAL_INFORMATION()
                infoRecord['EaInformation'] = smb2.FILE_EA_INFORMATION()
                infoRecord['AccessInformation'] = smb2.FILE_ACCESS_INFORMATION()
                infoRecord['PositionInformation'] = smb2.FILE_POSITION_INFORMATION()
                infoRecord['ModeInformation'] = smb2.FILE_MODE_INFORMATION()
                infoRecord['AlignmentInformation'] = smb2.FILE_ALIGNMENT_INFORMATION()
                infoRecord['NameInformation'] = smb2.FILE_NAME_INFORMATION()
                infoRecord['BasicInformation']['CreationTime'] = getFileTime(ctime)
                infoRecord['BasicInformation']['LastAccessTime'] = getFileTime(atime)
                infoRecord['BasicInformation']['LastWriteTime'] = getFileTime(mtime)
                infoRecord['BasicInformation']['ChangeTime'] = getFileTime(mtime)
                if os.path.isdir(pathName):
                    infoRecord['BasicInformation']['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                    infoRecord['StandardInformation']['Directory'] = 1
                    infoRecord['EaInformation']['EaSize'] = smb.ATTR_DIRECTORY
                else:
                    infoRecord['BasicInformation']['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_NORMAL | smb.SMB_FILE_ATTRIBUTE_ARCHIVE
                    infoRecord['StandardInformation']['Directory'] = 0
                    infoRecord['EaInformation']['EaSize'] = smb.ATTR_NORMAL | smb.ATTR_ARCHIVE
                infoRecord['StandardInformation']['AllocationSize'] = size
                infoRecord['StandardInformation']['EndOfFile'] = size
                infoRecord['StandardInformation']['NumberOfLinks'] = nlink
                infoRecord['StandardInformation']['DeletePending'] = 0
                infoRecord['InternalInformation']['IndexNumber'] = ino
                infoRecord['AccessInformation']['AccessFlags'] = 0 #
                infoRecord['PositionInformation']['CurrentByteOffset'] = 0 #
                infoRecord['ModeInformation']['mode'] = mode
                infoRecord['AlignmentInformation']['AlignmentRequirement'] = 0 #
                infoRecord['NameInformation']['FileName'] = fileName.encode('utf-16le')
                infoRecord['NameInformation']['FileNameLength'] = len(fileName.encode('utf-16le'))
            elif level == smb2.SMB2_FILE_NETWORK_OPEN_INFO:
                infoRecord = smb.SMBFileNetworkOpenInfo()
                infoRecord['CreationTime'] = getFileTime(ctime)
                infoRecord['LastAccessTime'] = getFileTime(atime)
                infoRecord['LastWriteTime'] = getFileTime(mtime)
                infoRecord['ChangeTime'] = getFileTime(mtime)
                infoRecord['AllocationSize'] = size
                infoRecord['EndOfFile'] = size
                infoRecord['FileAttributes'] = fileAttributes
            elif level == smb.SMB_QUERY_FILE_EA_INFO or level == smb2.SMB2_FILE_EA_INFO:
                infoRecord = smb.SMBQueryFileEaInfo()
            elif level == smb.SMB_QUERY_FILE_STREAM_INFO or level == smb2.SMB2_FILE_STREAM_INFO:
                infoRecord = smb.SMBFileStreamInformation()
            elif level == smb2.SMB2_ATTRIBUTE_TAG_INFO:
                infoRecord = smb2.FILE_ATTRIBUTE_TAG_INFORMATION()
                infoRecord['FileAttributes'] = fileAttributes
            else:
                LOG.error('Unknown level for query path info! 0x%x' % level)
                # UNSUPPORTED
                return None, STATUS_NOT_SUPPORTED

            return infoRecord, errorCode
        else:
            # NOT FOUND
            return None, STATUS_OBJECT_NAME_NOT_FOUND
    except Exception as e:
        LOG.error('queryPathInfo: %s' % e)
        raise


def queryDiskInformation(path):
    # TODO: Do something useful here :)
    # For now we just return fake values
    totalUnits = 65535
    freeUnits = 65535
    return totalUnits, freeUnits


# Here we implement the NT transaction handlers
class NTTRANSCommands:
    def default(self, connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        pass


# Here we implement the NT transaction handlers
class TRANSCommands:
    @staticmethod
    def lanMan(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        # Minimal [MS-RAP] implementation, just to return the shares
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        errorCode = STATUS_SUCCESS
        if struct.unpack('<H', parameters[:2])[0] == 0:
            # NetShareEnum Request
            netShareEnum = smb.SMBNetShareEnum(parameters)
            if netShareEnum['InfoLevel'] == 1:
                shares = getShares(connId, smbServer)
                respParameters = smb.SMBNetShareEnumResponse()
                respParameters['EntriesReturned'] = len(shares)
                respParameters['EntriesAvailable'] = len(shares)
                tailData = ''
                for i in shares:
                    # NetShareInfo1 len == 20
                    entry = smb.NetShareInfo1()
                    entry['NetworkName'] = i + '\x00' * (13 - len(i))
                    entry['Type'] = int(shares[i]['share type'])
                    # (beto) If offset == 0 it crashes explorer.exe on windows 7
                    entry['RemarkOffsetLow'] = 20 * len(shares) + len(tailData)
                    respData += entry.getData()
                    if 'comment' in shares[i]:
                        tailData += shares[i]['comment'] + '\x00'
                    else:
                        tailData += '\x00'
                respData += tailData
            else:
                # We don't support other info levels
                errorCode = STATUS_NOT_SUPPORTED
        elif struct.unpack('<H', parameters[:2])[0] == 13:
            # NetrServerGetInfo Request
            respParameters = smb.SMBNetServerGetInfoResponse()
            netServerInfo = smb.SMBNetServerInfo1()
            netServerInfo['ServerName'] = smbServer.getServerName()
            respData = netServerInfo.getData()
            respParameters['TotalBytesAvailable'] = len(respData)
        elif struct.unpack('<H', parameters[:2])[0] == 1:
            # NetrShareGetInfo Request
            request = smb.SMBNetShareGetInfo(parameters)
            respParameters = smb.SMBNetShareGetInfoResponse()
            shares = getShares(connId, smbServer)
            share = shares[request['ShareName'].upper()]
            shareInfo = smb.NetShareInfo1()
            shareInfo['NetworkName'] = request['ShareName'].upper() + '\x00'
            shareInfo['Type'] = int(share['share type'])
            respData = shareInfo.getData()
            if 'comment' in share:
                shareInfo['RemarkOffsetLow'] = len(respData)
                respData += share['comment'] + '\x00'
            respParameters['TotalBytesAvailable'] = len(respData)

        else:
            # We don't know how to handle anything else
            errorCode = STATUS_NOT_SUPPORTED

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def transactNamedPipe(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        errorCode = STATUS_SUCCESS
        SMBCommand = smb.SMBCommand(recvPacket['Data'][0])
        transParameters = smb.SMBTransaction_Parameters(SMBCommand['Parameters'])

        # Extract the FID
        fid = struct.unpack('<H', transParameters['Setup'][2:])[0]

        if fid in connData['OpenedFiles']:
            fileHandle = connData['OpenedFiles'][fid]['FileHandle']
            if fileHandle != PIPE_FILE_DESCRIPTOR:
                os.write(fileHandle, data)
                respData = os.read(fileHandle, data)
            else:
                sock = connData['OpenedFiles'][fid]['Socket']
                sock.send(data)
                respData = sock.recv(maxDataCount)
        else:
            errorCode = STATUS_INVALID_HANDLE

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode


# Here we implement the transaction2 handlers
class TRANS2Commands:
    # All these commands return setup, parameters, data, errorCode
    @staticmethod
    def setPathInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        errorCode = STATUS_SUCCESS
        setPathInfoParameters = smb.SMBSetPathInformation_Parameters(flags=recvPacket['Flags2'], data=parameters)
        if recvPacket['Tid'] in connData['ConnectedShares']:
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            fileName = normalize_path(decodeSMBString(recvPacket['Flags2'], setPathInfoParameters['FileName']), path)
            pathName = os.path.join(path, fileName)

            if isInFileJail(path, fileName):
                smbServer.log("Path not in current working directory")
                errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD

            elif os.path.exists(pathName):
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
                        os.utime(pathName, (atime, mtime))
                else:
                    smbServer.log('Unknown level for set path info! 0x%x' % setPathInfoParameters['InformationLevel'],
                                  logging.ERROR)
                    # UNSUPPORTED
                    errorCode = STATUS_NOT_SUPPORTED
            else:
                errorCode = STATUS_OBJECT_NAME_NOT_FOUND

            if errorCode == STATUS_SUCCESS:
                respParameters = smb.SMBSetPathInformationResponse_Parameters()

        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def setFileInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        errorCode = STATUS_SUCCESS
        setFileInfoParameters = smb.SMBSetFileInformation_Parameters(parameters)

        if recvPacket['Tid'] in connData['ConnectedShares']:
            if setFileInfoParameters['FID'] in connData['OpenedFiles']:
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
                    os.utime(fileName, (atime, mtime))
                elif informationLevel == smb.SMB_SET_FILE_END_OF_FILE_INFO:
                    fileHandle = connData['OpenedFiles'][setFileInfoParameters['FID']]['FileHandle']
                    infoRecord = smb.SMBSetFileEndOfFileInfo(data)
                    if infoRecord['EndOfFile'] > 0:
                        os.lseek(fileHandle, infoRecord['EndOfFile'] - 1, 0)
                        os.write(fileHandle, b'\x00')
                else:
                    smbServer.log('Unknown level for set file info! 0x%x' % setFileInfoParameters['InformationLevel'],
                                  logging.ERROR)
                    # UNSUPPORTED
                    errorCode = STATUS_NOT_SUPPORTED
            else:
                errorCode = STATUS_NO_SUCH_FILE

            if errorCode == STATUS_SUCCESS:
                respParameters = smb.SMBSetFileInformationResponse_Parameters()
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def queryFileInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''

        queryFileInfoParameters = smb.SMBQueryFileInformation_Parameters(parameters)

        if recvPacket['Tid'] in connData['ConnectedShares']:
            if queryFileInfoParameters['FID'] in connData['OpenedFiles']:
                pathName = connData['OpenedFiles'][queryFileInfoParameters['FID']]['FileName']

                infoRecord, errorCode = queryFileInformation(os.path.dirname(pathName), os.path.basename(pathName),
                                                             queryFileInfoParameters['InformationLevel'])

                if infoRecord is not None:
                    respParameters = smb.SMBQueryFileInformationResponse_Parameters()
                    respData = infoRecord
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def queryPathInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        errorCode = 0

        queryPathInfoParameters = smb.SMBQueryPathInformation_Parameters(flags=recvPacket['Flags2'], data=parameters)

        if recvPacket['Tid'] in connData['ConnectedShares']:
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            try:
                infoRecord, errorCode = queryPathInformation(path, decodeSMBString(recvPacket['Flags2'],
                                                                                   queryPathInfoParameters['FileName']),
                                                             queryPathInfoParameters['InformationLevel'])
            except Exception as e:
                smbServer.log("queryPathInformation: %s" % e, logging.ERROR)

            if infoRecord is not None:
                respParameters = smb.SMBQueryPathInformationResponse_Parameters()
                respData = infoRecord
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def queryFsInformation(connId, smbServer, recvPacket, parameters, data, maxDataCount=0):
        connData = smbServer.getConnectionData(connId)
        errorCode = 0
        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            data = queryFsInformation(connData['ConnectedShares'][recvPacket['Tid']]['path'], '',
                                      struct.unpack('<H', parameters)[0], pktFlags=recvPacket['Flags2'])

        smbServer.setConnectionData(connId, connData)

        return b'', b'', data, errorCode

    @staticmethod
    def findNext2(connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        errorCode = STATUS_SUCCESS
        findNext2Parameters = smb.SMBFindNext2_Parameters(flags=recvPacket['Flags2'], data=parameters)

        sid = findNext2Parameters['SID']
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if sid in connData['SIDs']:
                searchResult = connData['SIDs'][sid]
                respParameters = smb.SMBFindNext2Response_Parameters()
                endOfSearch = 1
                searchCount = 1
                totalData = 0
                for i in enumerate(searchResult):
                    data = i[1].getData()
                    lenData = len(data)
                    if (totalData + lenData) >= maxDataCount or (i[0] + 1) >= findNext2Parameters['SearchCount']:
                        # We gotta stop here and continue on a find_next2
                        endOfSearch = 0
                        connData['SIDs'][sid] = searchResult[i[0]:]
                        respParameters['LastNameOffset'] = totalData
                        break
                    else:
                        searchCount += 1
                        respData += data
                        totalData += lenData

                # Have we reached the end of the search or still stuff to send?
                if endOfSearch > 0:
                    # Let's remove the SID from our ConnData
                    del (connData['SIDs'][sid])

                respParameters['EndOfSearch'] = endOfSearch
                respParameters['SearchCount'] = searchCount
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode

    @staticmethod
    def findFirst2(connId, smbServer, recvPacket, parameters, data, maxDataCount):
        connData = smbServer.getConnectionData(connId)

        respSetup = b''
        respParameters = b''
        respData = b''
        findFirst2Parameters = smb.SMBFindFirst2_Parameters(recvPacket['Flags2'], data=parameters)

        if recvPacket['Tid'] in connData['ConnectedShares']:
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']

            searchResult, searchCount, errorCode = findFirst2(path,
                                                              decodeSMBString(recvPacket['Flags2'],
                                                                              findFirst2Parameters['FileName']),
                                                              findFirst2Parameters['InformationLevel'],
                                                              findFirst2Parameters['SearchAttributes'],
                                                              pktFlags=recvPacket['Flags2'])

            if searchCount > 0:
                respParameters = smb.SMBFindFirst2Response_Parameters()
                endOfSearch = 1
                sid = 0x80  # default SID
                searchCount = 0
                totalData = 0
                for i in enumerate(searchResult):
                    # i[1].dump()
                    data = i[1].getData()
                    lenData = len(data)
                    if (totalData + lenData) >= maxDataCount or (i[0] + 1) > findFirst2Parameters['SearchCount']:
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
                        searchCount += 1
                        respData += data

                        padLen = (8 - (lenData % 8)) % 8
                        respData += b'\xaa' * padLen
                        totalData += lenData + padLen

                respParameters['SID'] = sid
                respParameters['EndOfSearch'] = endOfSearch
                respParameters['SearchCount'] = searchCount

            # If we've empty files and errorCode was not already set, we return NO_SUCH_FILE
            elif errorCode == 0:
                errorCode = STATUS_NO_SUCH_FILE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)

        return respSetup, respParameters, respData, errorCode


# Here we implement the commands handlers
class SMBCommands:

    @staticmethod
    def smbTransaction(connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])

        transParameters = smb.SMBTransaction_Parameters(SMBCommand['Parameters'])

        # Do the stuff
        if transParameters['ParameterCount'] != transParameters['TotalParameterCount']:
            # TODO: Handle partial parameters
            raise Exception("Unsupported partial parameters in TRANSACT2!")
        else:
            transData = smb.SMBTransaction_SData(flags=recvPacket['Flags2'])
            # Standard says servers shouldn't trust Parameters and Data comes
            # in order, so we have to parse the offsets, ugly

            paramCount = transParameters['ParameterCount']
            transData['Trans_ParametersLength'] = paramCount
            dataCount = transParameters['DataCount']
            transData['Trans_DataLength'] = dataCount
            transData.fromString(SMBCommand['Data'])
            if transParameters['ParameterOffset'] > 0:
                paramOffset = transParameters['ParameterOffset'] - 63 - transParameters['SetupLength']
                transData['Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset + paramCount]
            else:
                transData['Trans_Parameters'] = b''

            if transParameters['DataOffset'] > 0:
                dataOffset = transParameters['DataOffset'] - 63 - transParameters['SetupLength']
                transData['Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else:
                transData['Trans_Data'] = b''

            # Call the handler for this TRANSACTION
            if transParameters['SetupCount'] == 0:
                # No subcommand, let's play with the Name
                command = decodeSMBString(recvPacket['Flags2'], transData['Name'])
            else:
                command = struct.unpack('<H', transParameters['Setup'][:2])[0]

            if command in transCommands:
                # Call the TRANS subcommand
                setup = b''
                parameters = b''
                data = b''
                try:
                    setup, parameters, data, errorCode = transCommands[command](connId,
                                                                                smbServer,
                                                                                recvPacket,
                                                                                transData['Trans_Parameters'],
                                                                                transData['Trans_Data'],
                                                                                transParameters['MaxDataCount'])
                except Exception as e:
                    # print 'Transaction: %s' % e,e
                    smbServer.log('Transaction: (%r,%s)' % (command, e), logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
                    # raise

                if setup == b'' and parameters == b'' and data == b'':
                    # Something wen't wrong
                    respParameters = b''
                    respData = b''
                else:
                    # Build the answer
                    if hasattr(data, 'getData'):
                        data = data.getData()
                    remainingData = len(data)
                    if hasattr(parameters, 'getData'):
                        parameters = parameters.getData()
                    remainingParameters = len(parameters)
                    commands = []
                    dataDisplacement = 0
                    while remainingData > 0 or remainingParameters > 0:
                        respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                        respParameters = smb.SMBTransactionResponse_Parameters()
                        respData = smb.SMBTransaction2Response_Data()

                        respParameters['TotalParameterCount'] = len(parameters)
                        respParameters['ParameterCount'] = len(parameters)
                        respData['Trans_ParametersLength'] = len(parameters)
                        respParameters['TotalDataCount'] = len(data)
                        respParameters['DataDisplacement'] = dataDisplacement

                        # TODO: Do the same for parameters
                        if len(data) > transParameters['MaxDataCount']:
                            # Answer doesn't fit in this packet
                            LOG.debug("Lowering answer from %d to %d" % (len(data), transParameters['MaxDataCount']))
                            respParameters['DataCount'] = transParameters['MaxDataCount']
                        else:
                            respParameters['DataCount'] = len(data)

                        respData['Trans_DataLength'] = respParameters['DataCount']
                        respParameters['SetupCount'] = len(setup)
                        respParameters['Setup'] = setup
                        # TODO: Make sure we're calculating the pad right
                        if len(parameters) > 0:
                            # padLen = 4 - (55 + len(setup)) % 4
                            padLen = (4 - (55 + len(setup)) % 4) % 4
                            padBytes = b'\xFF' * padLen
                            respData['Pad1'] = padBytes
                            respParameters['ParameterOffset'] = 55 + len(setup) + padLen
                        else:
                            padLen = 0
                            respParameters['ParameterOffset'] = 0
                            respData['Pad1'] = b''

                        if len(data) > 0:
                            # pad2Len = 4 - (55 + len(setup) + padLen + len(parameters)) % 4
                            pad2Len = (4 - (55 + len(setup) + padLen + len(parameters)) % 4) % 4
                            respData['Pad2'] = b'\xFF' * pad2Len
                            respParameters['DataOffset'] = 55 + len(setup) + padLen + len(parameters) + pad2Len
                        else:
                            respParameters['DataOffset'] = 0
                            respData['Pad2'] = b''

                        respData['Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                        respData['Trans_Data'] = data[:respParameters['DataCount']]
                        respSMBCommand['Parameters'] = respParameters
                        respSMBCommand['Data'] = respData

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
                respParameters = b''
                respData = b''
                errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbNTTransact(connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])

        NTTransParameters = smb.SMBNTTransaction_Parameters(SMBCommand['Parameters'])
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
                NTTransData['NT_Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset + paramCount]
            else:
                NTTransData['NT_Trans_Parameters'] = b''

            if NTTransParameters['DataOffset'] > 0:
                dataOffset = NTTransParameters['DataOffset'] - 73 - NTTransParameters['SetupLength']
                NTTransData['NT_Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else:
                NTTransData['NT_Trans_Data'] = b''

            # Call the handler for this TRANSACTION
            command = NTTransParameters['Function']
            if command in transCommands:
                # Call the NT TRANS subcommand
                setup = b''
                parameters = b''
                data = b''
                try:
                    setup, parameters, data, errorCode = transCommands[command](connId,
                                                                                smbServer,
                                                                                recvPacket,
                                                                                NTTransData['NT_Trans_Parameters'],
                                                                                NTTransData['NT_Trans_Data'],
                                                                                NTTransParameters['MaxDataCount'])
                except Exception as e:
                    smbServer.log('NTTransaction: (0x%x,%s)' % (command, e), logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
                    # raise

                if setup == b'' and parameters == b'' and data == b'':
                    # Something wen't wrong
                    respParameters = b''
                    respData = b''
                    if errorCode == STATUS_SUCCESS:
                        errorCode = STATUS_ACCESS_DENIED
                else:
                    # Build the answer
                    if hasattr(data, 'getData'):
                        data = data.getData()
                    remainingData = len(data)
                    if hasattr(parameters, 'getData'):
                        parameters = parameters.getData()
                    remainingParameters = len(parameters)
                    commands = []
                    dataDisplacement = 0
                    while remainingData > 0 or remainingParameters > 0:
                        respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                        respParameters = smb.SMBNTTransactionResponse_Parameters()
                        respData = smb.SMBNTTransactionResponse_Data()

                        respParameters['TotalParameterCount'] = len(parameters)
                        respParameters['ParameterCount'] = len(parameters)
                        respData['Trans_ParametersLength'] = len(parameters)
                        respParameters['TotalDataCount'] = len(data)
                        respParameters['DataDisplacement'] = dataDisplacement
                        # TODO: Do the same for parameters
                        if len(data) > NTTransParameters['MaxDataCount']:
                            # Answer doesn't fit in this packet
                            LOG.debug("Lowering answer from %d to %d" % (len(data), NTTransParameters['MaxDataCount']))
                            respParameters['DataCount'] = NTTransParameters['MaxDataCount']
                        else:
                            respParameters['DataCount'] = len(data)

                        respData['NT_Trans_DataLength'] = respParameters['DataCount']
                        respParameters['SetupCount'] = len(setup)
                        respParameters['Setup'] = setup
                        # TODO: Make sure we're calculating the pad right
                        if len(parameters) > 0:
                            # padLen = 4 - (71 + len(setup)) % 4
                            padLen = (4 - (73 + len(setup)) % 4) % 4
                            padBytes = b'\xFF' * padLen
                            respData['Pad1'] = padBytes
                            respParameters['ParameterOffset'] = 73 + len(setup) + padLen
                        else:
                            padLen = 0
                            respParameters['ParameterOffset'] = 0
                            respData['Pad1'] = b''

                        if len(data) > 0:
                            # pad2Len = 4 - (71 + len(setup) + padLen + len(parameters)) % 4
                            pad2Len = (4 - (73 + len(setup) + padLen + len(parameters)) % 4) % 4
                            respData['Pad2'] = b'\xFF' * pad2Len
                            respParameters['DataOffset'] = 73 + len(setup) + padLen + len(parameters) + pad2Len
                        else:
                            respParameters['DataOffset'] = 0
                            respData['Pad2'] = b''

                        respData['NT_Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                        respData['NT_Trans_Data'] = data[:respParameters['DataCount']]
                        respSMBCommand['Parameters'] = respParameters
                        respSMBCommand['Data'] = respData

                        data = data[respParameters['DataCount']:]
                        remainingData -= respParameters['DataCount']
                        dataDisplacement += respParameters['DataCount'] + 1

                        parameters = parameters[respParameters['ParameterCount']:]
                        remainingParameters -= respParameters['ParameterCount']
                        commands.append(respSMBCommand)

                    smbServer.setConnectionData(connId, connData)
                    return commands, None, errorCode

            else:
                # smbServer.log("Unsupported NTTransact command 0x%x" % command, logging.ERROR)
                respParameters = b''
                respData = b''
                errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbTransaction2(connId, smbServer, SMBCommand, recvPacket, transCommands):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(recvPacket['Command'])

        trans2Parameters = smb.SMBTransaction2_Parameters(SMBCommand['Parameters'])

        # Do the stuff
        if trans2Parameters['ParameterCount'] != trans2Parameters['TotalParameterCount']:
            # TODO: Handle partial parameters
            # print "Unsupported partial parameters in TRANSACT2!"
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
                trans2Data['Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset + paramCount]
            else:
                trans2Data['Trans_Parameters'] = b''

            if trans2Parameters['DataOffset'] > 0:
                dataOffset = trans2Parameters['DataOffset'] - 63 - trans2Parameters['SetupLength']
                trans2Data['Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
            else:
                trans2Data['Trans_Data'] = b''

            # Call the handler for this TRANSACTION
            command = struct.unpack('<H', trans2Parameters['Setup'])[0]
            if command in transCommands:
                # Call the TRANS2 subcommand
                try:
                    setup, parameters, data, errorCode = transCommands[command](connId,
                                                                                smbServer,
                                                                                recvPacket,
                                                                                trans2Data['Trans_Parameters'],
                                                                                trans2Data['Trans_Data'],
                                                                                trans2Parameters['MaxDataCount'])
                except Exception as e:
                    smbServer.log('Transaction2: (0x%x,%s)' % (command, e), logging.ERROR)
                    # import traceback
                    # traceback.print_exc()
                    raise

                if setup == b'' and parameters == b'' and data == b'':
                    # Something wen't wrong
                    respParameters = b''
                    respData = b''
                else:
                    # Build the answer
                    if hasattr(data, 'getData'):
                        data = data.getData()
                    remainingData = len(data)
                    if hasattr(parameters, 'getData'):
                        parameters = parameters.getData()
                    remainingParameters = len(parameters)
                    commands = []
                    dataDisplacement = 0
                    while remainingData > 0 or remainingParameters > 0:
                        respSMBCommand = smb.SMBCommand(recvPacket['Command'])
                        respParameters = smb.SMBTransaction2Response_Parameters()
                        respData = smb.SMBTransaction2Response_Data()

                        respParameters['TotalParameterCount'] = len(parameters)
                        respParameters['ParameterCount'] = len(parameters)
                        respData['Trans_ParametersLength'] = len(parameters)
                        respParameters['TotalDataCount'] = len(data)
                        respParameters['DataDisplacement'] = dataDisplacement
                        # TODO: Do the same for parameters
                        if len(data) > trans2Parameters['MaxDataCount']:
                            # Answer doesn't fit in this packet
                            LOG.debug("Lowering answer from %d to %d" % (len(data), trans2Parameters['MaxDataCount']))
                            respParameters['DataCount'] = trans2Parameters['MaxDataCount']
                        else:
                            respParameters['DataCount'] = len(data)

                        respData['Trans_DataLength'] = respParameters['DataCount']
                        respParameters['SetupCount'] = len(setup)
                        respParameters['Setup'] = setup
                        # TODO: Make sure we're calculating the pad right
                        if len(parameters) > 0:
                            # padLen = 4 - (55 + len(setup)) % 4
                            padLen = (4 - (55 + len(setup)) % 4) % 4
                            padBytes = b'\xFF' * padLen
                            respData['Pad1'] = padBytes
                            respParameters['ParameterOffset'] = 55 + len(setup) + padLen
                        else:
                            padLen = 0
                            respParameters['ParameterOffset'] = 0
                            respData['Pad1'] = b''

                        if len(data) > 0:
                            # pad2Len = 4 - (55 + len(setup) + padLen + len(parameters)) % 4
                            pad2Len = (4 - (55 + len(setup) + padLen + len(parameters)) % 4) % 4
                            respData['Pad2'] = b'\xFF' * pad2Len
                            respParameters['DataOffset'] = 55 + len(setup) + padLen + len(parameters) + pad2Len
                        else:
                            respParameters['DataOffset'] = 0
                            respData['Pad2'] = b''

                        respData['Trans_Parameters'] = parameters[:respParameters['ParameterCount']]
                        respData['Trans_Data'] = data[:respParameters['DataCount']]
                        respSMBCommand['Parameters'] = respParameters
                        respSMBCommand['Data'] = respData

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
                respParameters = b''
                respData = b''
                errorCode = STATUS_NOT_IMPLEMENTED

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComLockingAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_LOCKING_ANDX)
        respParameters = b''
        respData = b''

        # I'm actually doing nothing.. just make MacOS happy ;)
        errorCode = STATUS_SUCCESS

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComClose(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_CLOSE)
        respParameters = b''
        respData = b''

        comClose = smb.SMBClose_Parameters(SMBCommand['Parameters'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if comClose['FID'] in connData['OpenedFiles']:
                errorCode = STATUS_SUCCESS
                fileHandle = connData['OpenedFiles'][comClose['FID']]['FileHandle']
                try:
                    if fileHandle == PIPE_FILE_DESCRIPTOR:
                        connData['OpenedFiles'][comClose['FID']]['Socket'].close()
                    elif fileHandle != VOID_FILE_DESCRIPTOR:
                        os.close(fileHandle)
                except Exception as e:
                    smbServer.log("comClose %s" % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
                else:
                    # Check if the file was marked for removal
                    if connData['OpenedFiles'][comClose['FID']]['DeleteOnClose'] is True:
                        try:
                            os.remove(connData['OpenedFiles'][comClose['FID']]['FileName'])
                        except Exception as e:
                            smbServer.log("comClose %s" % e, logging.ERROR)
                            errorCode = STATUS_ACCESS_DENIED
                    del (connData['OpenedFiles'][comClose['FID']])
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComWrite(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_WRITE)
        respParameters = smb.SMBWriteResponse_Parameters()
        respData = b''

        comWriteParameters = smb.SMBWrite_Parameters(SMBCommand['Parameters'])
        comWriteData = smb.SMBWrite_Data(SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if comWriteParameters['Fid'] in connData['OpenedFiles']:
                fileHandle = connData['OpenedFiles'][comWriteParameters['Fid']]['FileHandle']
                errorCode = STATUS_SUCCESS
                try:
                    if fileHandle != PIPE_FILE_DESCRIPTOR:
                        # TODO: Handle big size files
                        # If we're trying to write past the file end we just skip the write call (Vista does this)
                        if os.lseek(fileHandle, 0, 2) >= comWriteParameters['Offset']:
                            os.lseek(fileHandle, comWriteParameters['Offset'], 0)
                            os.write(fileHandle, comWriteData['Data'])
                    else:
                        sock = connData['OpenedFiles'][comWriteParameters['Fid']]['Socket']
                        sock.send(comWriteData['Data'])
                    respParameters['Count'] = comWriteParameters['Count']
                except Exception as e:
                    smbServer.log('smbComWrite: %s' % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComFlush(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_FLUSH)
        respParameters = b''
        respData = b''

        comFlush = smb.SMBFlush_Parameters(SMBCommand['Parameters'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if comFlush['FID'] in connData['OpenedFiles']:
                errorCode = STATUS_SUCCESS
                fileHandle = connData['OpenedFiles'][comFlush['FID']]['FileHandle']
                try:
                    os.fsync(fileHandle)
                except Exception as e:
                    smbServer.log("comFlush %s" % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComCreateDirectory(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_CREATE_DIRECTORY)
        respParameters = b''
        respData = b''

        comCreateDirectoryData = smb.SMBCreateDirectory_Data(flags=recvPacket['Flags2'], data=SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            errorCode = STATUS_SUCCESS
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            fileName = normalize_path(decodeSMBString(recvPacket['Flags2'], comCreateDirectoryData['DirectoryName']))
            pathName = os.path.join(path, fileName)

            if not isInFileJail(path, fileName):
                smbServer.log("Path not in current working directory", logging.ERROR)
                errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD

            elif os.path.exists(pathName):
                errorCode = STATUS_OBJECT_NAME_COLLISION

            else:
                try:
                    os.mkdir(pathName)
                except Exception as e:
                    smbServer.log("smbComCreateDirectory: %s" % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComRename(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_RENAME)
        respParameters = b''
        respData = b''

        comRenameData = smb.SMBRename_Data(flags=recvPacket['Flags2'], data=SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            errorCode = STATUS_SUCCESS
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            oldFileName = normalize_path(decodeSMBString(recvPacket['Flags2'], comRenameData['OldFileName']))
            oldPathName = os.path.join(path, oldFileName)
            newFileName = normalize_path(decodeSMBString(recvPacket['Flags2'], comRenameData['NewFileName']))
            newPathName = os.path.join(path, newFileName)

            if not isInFileJail(path, oldFileName) or not isInFileJail(path, newFileName):
                smbServer.log("Path not in current working directory", logging.ERROR)
                errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD

            elif not os.path.exists(oldPathName):
                errorCode = STATUS_NO_SUCH_FILE

            else:
                try:
                    os.rename(oldPathName, newPathName)
                except OSError as e:
                    smbServer.log("smbComRename: %s" % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComDelete(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_DELETE)
        respParameters = b''
        respData = b''

        comDeleteData = smb.SMBDelete_Data(flags=recvPacket['Flags2'], data=SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            errorCode = STATUS_SUCCESS
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            fileName = normalize_path(decodeSMBString(recvPacket['Flags2'], comDeleteData['FileName']))
            pathName = os.path.join(path, fileName)

            if not isInFileJail(path, fileName):
                smbServer.log("Path not in current working directory", logging.ERROR)
                errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD

            elif not os.path.exists(pathName):
                errorCode = STATUS_NO_SUCH_FILE

            else:
                try:
                    os.remove(pathName)
                except OSError as e:
                    smbServer.log("smbComDelete: %s" % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComDeleteDirectory(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_DELETE_DIRECTORY)
        respParameters = b''
        respData = b''

        comDeleteDirectoryData = smb.SMBDeleteDirectory_Data(flags=recvPacket['Flags2'], data=SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            errorCode = STATUS_SUCCESS
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            fileName = normalize_path(decodeSMBString(recvPacket['Flags2'], comDeleteDirectoryData['DirectoryName']))
            pathName = os.path.join(path, fileName)

            if not isInFileJail(path, fileName):
                smbServer.log("Path not in current working directory", logging.ERROR)
                errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD

            elif not os.path.exists(pathName):
                errorCode = STATUS_NO_SUCH_FILE

            else:
                try:
                    os.rmdir(pathName)
                except OSError as e:
                    smbServer.log("smbComDeleteDirectory: %s" % e, logging.ERROR)
                    if e.errno == errno.ENOTEMPTY:
                        errorCode = STATUS_DIRECTORY_NOT_EMPTY
                    else:
                        errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComWriteAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_WRITE_ANDX)
        respParameters = smb.SMBWriteAndXResponse_Parameters()
        respData = b''

        if SMBCommand['WordCount'] == 0x0C:
            writeAndX = smb.SMBWriteAndX_Parameters_Short(SMBCommand['Parameters'])
            writeAndXData = smb.SMBWriteAndX_Data_Short()
        else:
            writeAndX = smb.SMBWriteAndX_Parameters(SMBCommand['Parameters'])
            writeAndXData = smb.SMBWriteAndX_Data()
        writeAndXData['DataLength'] = writeAndX['DataLength']
        writeAndXData['DataOffset'] = writeAndX['DataOffset']
        writeAndXData.fromString(SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if writeAndX['Fid'] in connData['OpenedFiles']:
                fileHandle = connData['OpenedFiles'][writeAndX['Fid']]['FileHandle']
                errorCode = STATUS_SUCCESS
                try:
                    if fileHandle != PIPE_FILE_DESCRIPTOR:
                        offset = writeAndX['Offset']
                        if 'HighOffset' in writeAndX.fields:
                            offset += (writeAndX['HighOffset'] << 32)
                        # If we're trying to write past the file end we just skip the write call (Vista does this)
                        if os.lseek(fileHandle, 0, 2) >= offset:
                            os.lseek(fileHandle, offset, 0)
                            os.write(fileHandle, writeAndXData['Data'])
                    else:
                        sock = connData['OpenedFiles'][writeAndX['Fid']]['Socket']
                        sock.send(writeAndXData['Data'])

                    respParameters['Count'] = writeAndX['DataLength']
                    respParameters['Available'] = 0xff
                except Exception as e:
                    smbServer.log('smbComWriteAndx: %s' % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComRead(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_READ)
        respParameters = smb.SMBReadResponse_Parameters()
        respData = smb.SMBReadResponse_Data()

        comReadParameters = smb.SMBRead_Parameters(SMBCommand['Parameters'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if comReadParameters['Fid'] in connData['OpenedFiles']:
                fileHandle = connData['OpenedFiles'][comReadParameters['Fid']]['FileHandle']
                errorCode = STATUS_SUCCESS
                try:
                    if fileHandle != PIPE_FILE_DESCRIPTOR:
                        # TODO: Handle big size files
                        os.lseek(fileHandle, comReadParameters['Offset'], 0)
                        content = os.read(fileHandle, comReadParameters['Count'])
                    else:
                        sock = connData['OpenedFiles'][comReadParameters['Fid']]['Socket']
                        content = sock.recv(comReadParameters['Count'])
                    respParameters['Count'] = len(content)
                    respData['DataLength'] = len(content)
                    respData['Data'] = content
                except Exception as e:
                    smbServer.log('smbComRead: %s ' % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComReadAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_READ_ANDX)
        respParameters = smb.SMBReadAndXResponse_Parameters()
        respData = b''

        if SMBCommand['WordCount'] == 0x0A:
            readAndX = smb.SMBReadAndX_Parameters2(SMBCommand['Parameters'])
        else:
            readAndX = smb.SMBReadAndX_Parameters(SMBCommand['Parameters'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if readAndX['Fid'] in connData['OpenedFiles']:
                fileHandle = connData['OpenedFiles'][readAndX['Fid']]['FileHandle']
                errorCode = 0
                try:
                    if fileHandle != PIPE_FILE_DESCRIPTOR:
                        offset = readAndX['Offset']
                        if 'HighOffset' in readAndX.fields:
                            offset += (readAndX['HighOffset'] << 32)
                        os.lseek(fileHandle, offset, 0)
                        content = os.read(fileHandle, readAndX['MaxCount'])
                    else:
                        sock = connData['OpenedFiles'][readAndX['Fid']]['Socket']
                        content = sock.recv(readAndX['MaxCount'])
                    respParameters['Remaining'] = 0xffff
                    respParameters['DataCount'] = len(content)
                    respParameters['DataOffset'] = 59
                    respParameters['DataCount_Hi'] = 0
                    respData = content
                except Exception as e:
                    smbServer.log('smbComReadAndX: %s ' % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbQueryInformation(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION)
        respParameters = smb.SMBQueryInformationResponse_Parameters()
        respData = b''

        queryInformation = smb.SMBQueryInformation_Data(flags=recvPacket['Flags2'], data=SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            fileName = normalize_path(decodeSMBString(recvPacket['Flags2'], queryInformation['FileName']))
            if not isInFileJail(path, fileName):
                smbServer.log("Path not in current working directory", logging.ERROR)
                errorCode = STATUS_OBJECT_PATH_SYNTAX_BAD

            else:
                fileSize, lastWriteTime, fileAttributes = queryFsInformation(path, fileName, pktFlags=recvPacket['Flags2'])

                respParameters['FileSize'] = fileSize
                respParameters['LastWriteTime'] = lastWriteTime
                respParameters['FileAttributes'] = fileAttributes
                errorCode = STATUS_SUCCESS
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbQueryInformationDisk(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION_DISK)
        respParameters = smb.SMBQueryInformationDiskResponse_Parameters()
        respData = b''

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            totalUnits, freeUnits = queryDiskInformation(
                connData['ConnectedShares'][recvPacket['Tid']]['path'])

            respParameters['TotalUnits'] = totalUnits
            respParameters['BlocksPerUnit'] = 1
            respParameters['BlockSize'] = 1
            respParameters['FreeUnits'] = freeUnits
            errorCode = STATUS_SUCCESS
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respData = b''
            respParameters = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComEcho(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
        respParameters = smb.SMBEchoResponse_Parameters()
        respData = smb.SMBEchoResponse_Data()

        echoData = smb.SMBEcho_Data(SMBCommand['Data'])

        respParameters['SequenceNumber'] = 1
        respData['Data'] = echoData['Data']

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        errorCode = STATUS_SUCCESS
        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComTreeDisconnect(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_TREE_DISCONNECT)

        # Check if the Tid matches the Tid trying to disconnect
        respParameters = b''
        respData = b''

        if recvPacket['Tid'] in connData['ConnectedShares']:
            smbServer.log("Disconnecting Share(%d:%s)" % (
            recvPacket['Tid'], connData['ConnectedShares'][recvPacket['Tid']]['shareName']))
            del (connData['ConnectedShares'][recvPacket['Tid']])
            errorCode = STATUS_SUCCESS
        else:
            errorCode = STATUS_SMB_BAD_TID

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComLogOffAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_LOGOFF_ANDX)

        # Check if the Uid matches the user trying to logoff
        respParameters = b''
        respData = b''
        if recvPacket['Uid'] != connData['Uid']:
            errorCode = STATUS_SMB_BAD_UID
        else:
            errorCode = STATUS_SUCCESS

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        connData['Uid'] = 0
        connData['Authenticated'] = False

        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComQueryInformation2(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_QUERY_INFORMATION2)
        respParameters = smb.SMBQueryInformation2Response_Parameters()
        respData = b''

        queryInformation2 = smb.SMBQueryInformation2_Parameters(SMBCommand['Parameters'])
        errorCode = 0xFF

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            if queryInformation2['Fid'] in connData['OpenedFiles']:
                errorCode = STATUS_SUCCESS
                pathName = connData['OpenedFiles'][queryInformation2['Fid']]['FileName']
                try:
                    (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(pathName)
                    respParameters['CreateDate'] = getSMBDate(ctime)
                    respParameters['CreationTime'] = getSMBTime(ctime)
                    respParameters['LastAccessDate'] = getSMBDate(atime)
                    respParameters['LastAccessTime'] = getSMBTime(atime)
                    respParameters['LastWriteDate'] = getSMBDate(mtime)
                    respParameters['LastWriteTime'] = getSMBTime(mtime)
                    respParameters['FileDataSize'] = size
                    respParameters['FileAllocationSize'] = size
                    attribs = 0
                    if os.path.isdir(pathName):
                        attribs = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                    if os.path.isfile(pathName):
                        attribs = smb.SMB_FILE_ATTRIBUTE_NORMAL
                    respParameters['FileAttributes'] = attribs
                except Exception as e:
                    smbServer.log('smbComQueryInformation2 %s' % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode > 0:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComNtCreateAndX(connId, smbServer, SMBCommand, recvPacket):
        # TODO: Fully implement this
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_CREATE_ANDX)
        respParameters = smb.SMBNtCreateAndXResponse_Parameters()
        respData = b''

        ntCreateAndXParameters = smb.SMBNtCreateAndX_Parameters(SMBCommand['Parameters'])
        ntCreateAndXData = smb.SMBNtCreateAndX_Data(flags=recvPacket['Flags2'], data=SMBCommand['Data'])

        # if ntCreateAndXParameters['CreateFlags'] & 0x10:  # NT_CREATE_REQUEST_EXTENDED_RESPONSE
        #    respParameters        = smb.SMBNtCreateAndXExtendedResponse_Parameters()
        #    respParameters['VolumeGUID'] = '\x00'

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            # If we have a rootFid, the path is relative to that fid
            errorCode = STATUS_SUCCESS
            if ntCreateAndXParameters['RootFid'] > 0:
                path = connData['OpenedFiles'][ntCreateAndXParameters['RootFid']]['FileName']
                LOG.debug("RootFid present %s!" % path)
            else:
                if 'path' in connData['ConnectedShares'][recvPacket['Tid']]:
                    path = connData['ConnectedShares'][recvPacket['Tid']]['path']
                else:
                    path = 'NONE'
                    errorCode = STATUS_ACCESS_DENIED

            deleteOnClose = False

            fileName = normalize_path(decodeSMBString(recvPacket['Flags2'], ntCreateAndXData['FileName']))
            if not isInFileJail(path, fileName):
                LOG.error("Path not in current working directory")
                respSMBCommand['Parameters'] = b''
                respSMBCommand['Data'] = b''
                return [respSMBCommand], None, STATUS_OBJECT_PATH_SYNTAX_BAD

            pathName = os.path.join(path, fileName)
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
                mode |= os.O_CREAT
            elif createDisposition & smb.FILE_CREATE == smb.FILE_CREATE:
                if os.path.exists(pathName) is True:
                    errorCode = STATUS_OBJECT_NAME_COLLISION
                else:
                    mode |= os.O_CREAT
            elif createDisposition & smb.FILE_OPEN == smb.FILE_OPEN:
                if os.path.exists(pathName) is not True and (
                        str(pathName) in smbServer.getRegisteredNamedPipes()) is not True:
                    errorCode = STATUS_NO_SUCH_FILE

            if errorCode == STATUS_SUCCESS:
                desiredAccess = ntCreateAndXParameters['AccessMask']
                if (desiredAccess & smb.FILE_READ_DATA) or (desiredAccess & smb.GENERIC_READ):
                    mode |= os.O_RDONLY
                if (desiredAccess & smb.FILE_WRITE_DATA) or (desiredAccess & smb.GENERIC_WRITE):
                    if (desiredAccess & smb.FILE_READ_DATA) or (desiredAccess & smb.GENERIC_READ):
                        mode |= os.O_RDWR  # | os.O_APPEND
                    else:
                        mode |= os.O_WRONLY  # | os.O_APPEND
                if desiredAccess & smb.GENERIC_ALL:
                    mode |= os.O_RDWR  # | os.O_APPEND

                createOptions = ntCreateAndXParameters['CreateOptions']
                if mode & os.O_CREAT == os.O_CREAT:
                    if createOptions & smb.FILE_DIRECTORY_FILE == smb.FILE_DIRECTORY_FILE:
                        try:
                            # Let's create the directory
                            os.mkdir(pathName)
                            mode = os.O_RDONLY
                        except Exception as e:
                            smbServer.log("NTCreateAndX: %s,%s,%s" % (pathName, mode, e), logging.ERROR)
                            errorCode = STATUS_ACCESS_DENIED
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
                            if str(pathName) in smbServer.getRegisteredNamedPipes():
                                fid = PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[str(pathName)])
                            else:
                                fid = os.open(pathName, mode)
                    except Exception as e:
                        smbServer.log("NTCreateAndX: %s,%s,%s" % (pathName, mode, e), logging.ERROR)
                        # print e
                        fid = 0
                        errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            if len(connData['OpenedFiles']) == 0:
                fakefid = 1
            else:
                fakefid = list(connData['OpenedFiles'].keys())[-1] + 1
            respParameters['Fid'] = fakefid
            respParameters['CreateAction'] = createDisposition
            if fid == PIPE_FILE_DESCRIPTOR:
                respParameters['FileAttributes'] = 0x80
                respParameters['IsDirectory'] = 0
                respParameters['CreateTime'] = 0
                respParameters['LastAccessTime'] = 0
                respParameters['LastWriteTime'] = 0
                respParameters['LastChangeTime'] = 0
                respParameters['AllocationSize'] = 4096
                respParameters['EndOfFile'] = 0
                respParameters['FileType'] = 2
                respParameters['IPCState'] = 0x5ff
            else:
                if os.path.isdir(pathName):
                    respParameters['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                    respParameters['IsDirectory'] = 1
                else:
                    respParameters['IsDirectory'] = 0
                    respParameters['FileAttributes'] = ntCreateAndXParameters['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = queryPathInformation(path, fileName, level=smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respParameters['CreateTime'] = respInfo['CreationTime']
                    respParameters['LastAccessTime'] = respInfo['LastAccessTime']
                    respParameters['LastWriteTime'] = respInfo['LastWriteTime']
                    respParameters['LastChangeTime'] = respInfo['LastChangeTime']
                    respParameters['FileAttributes'] = respInfo['ExtFileAttributes']
                    respParameters['AllocationSize'] = respInfo['AllocationSize']
                    respParameters['EndOfFile'] = respInfo['EndOfFile']
                else:
                    respParameters = b''
                    respData = b''

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose'] = deleteOnClose
                if fid == PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComOpenAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_OPEN_ANDX)
        respParameters = smb.SMBOpenAndXResponse_Parameters()
        respData = b''

        openAndXParameters = smb.SMBOpenAndX_Parameters(SMBCommand['Parameters'])
        openAndXData = smb.SMBOpenAndX_Data(flags=recvPacket['Flags2'], data=SMBCommand['Data'])

        # Get the Tid associated
        if recvPacket['Tid'] in connData['ConnectedShares']:
            path = connData['ConnectedShares'][recvPacket['Tid']]['path']
            openedFile, mode, pathName, errorCode = openFile(path,
                                                             decodeSMBString(recvPacket['Flags2'],
                                                                             openAndXData['FileName']),
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
                fid = list(connData['OpenedFiles'].keys())[-1] + 1
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
            # smbServer.log('Opening file %s' % pathName)
            connData['OpenedFiles'][fid] = {}
            connData['OpenedFiles'][fid]['FileHandle'] = openedFile
            connData['OpenedFiles'][fid]['FileName'] = pathName
            connData['OpenedFiles'][fid]['DeleteOnClose'] = False
        else:
            respParameters = b''
            respData = b''

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComTreeConnectAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | \
                         recvPacket['Flags2'] & smb.SMB.FLAGS2_UNICODE

        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']
        resp['Pid'] = connData['Pid']

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_TREE_CONNECT_ANDX)
        respParameters = smb.SMBTreeConnectAndXResponse_Parameters()
        respData = smb.SMBTreeConnectAndXResponse_Data()

        treeConnectAndXParameters = smb.SMBTreeConnectAndX_Parameters(SMBCommand['Parameters'])

        if treeConnectAndXParameters['Flags'] & 0x8:
            respParameters = smb.SMBTreeConnectAndXExtendedResponse_Parameters()

        treeConnectAndXData = smb.SMBTreeConnectAndX_Data(flags=recvPacket['Flags2'])
        treeConnectAndXData['_PasswordLength'] = treeConnectAndXParameters['PasswordLength']
        treeConnectAndXData.fromString(SMBCommand['Data'])

        errorCode = STATUS_SUCCESS

        ## Process here the request, does the share exist?
        UNCOrShare = decodeSMBString(recvPacket['Flags2'], treeConnectAndXData['Path'])

        # Is this a UNC?
        if ntpath.ismount(UNCOrShare):
            path = UNCOrShare.split('\\')[3]
        else:
            path = ntpath.basename(UNCOrShare)

        share = searchShare(connId, path, smbServer)
        if share is not None:
            # Simple way to generate a Tid
            if len(connData['ConnectedShares']) == 0:
                tid = 1
            else:
                tid = list(connData['ConnectedShares'].keys())[-1] + 1
            connData['ConnectedShares'][tid] = share
            connData['ConnectedShares'][tid]['shareName'] = path
            resp['Tid'] = tid
            # smbServer.log("Connecting Share(%d:%s)" % (tid,path))
        else:
            smbServer.log("TreeConnectAndX not found %s" % path, logging.ERROR)
            errorCode = STATUS_OBJECT_PATH_NOT_FOUND
            resp['ErrorCode'] = errorCode >> 16
            resp['ErrorClass'] = errorCode & 0xff
        ##
        respParameters['OptionalSupport'] = smb.SMB.SMB_SUPPORT_SEARCH_BITS

        if path == 'IPC$':
            respData['Service'] = 'IPC'
        else:
            respData['Service'] = path
        respData['PadLen'] = 0
        respData['NativeFileSystem'] = encodeSMBString(recvPacket['Flags2'], 'NTFS').decode()

        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        resp['Uid'] = connData['Uid']
        resp.addCommand(respSMBCommand)

        # Sign the packet if needed
        if connData['SignatureEnabled']:
            smbServer.signSMBv1(connData, resp, connData['SigningSessionKey'], connData['SigningChallengeResponse'])
        smbServer.setConnectionData(connId, connData)

        return None, [resp], errorCode

    @staticmethod
    def smbComSessionSetupAndX(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus=False)

        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)

        # From [MS-SMB]
        # When extended security is being used (see section 3.2.4.2.4), the
        # request MUST take the following form
        # [..]
        # WordCount (1 byte): The value of this field MUST be 0x0C.
        if SMBCommand['WordCount'] == 12:
            # Extended security. Here we deal with all SPNEGO stuff
            respParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters()
            respData = smb.SMBSessionSetupAndX_Extended_Response_Data(flags=recvPacket['Flags2'])
            sessionSetupParameters = smb.SMBSessionSetupAndX_Extended_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(SMBCommand['Data'])
            connData['Capabilities'] = sessionSetupParameters['Capabilities']

            rawNTLM = False
            if struct.unpack('B', sessionSetupData['SecurityBlob'][0:1])[0] == ASN1_AID:
                # NEGOTIATE packet
                blob = SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
                token = blob['MechToken']
                if len(blob['MechTypes'][0]) > 0:
                    # Is this GSSAPI NTLM or something else we don't support?
                    mechType = blob['MechTypes'][0]
                    if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']:
                        # Nope, do we know it?
                        if mechType in MechTypes:
                            mechStr = MechTypes[mechType]
                        else:
                            mechStr = hexlify(mechType)
                        smbServer.log("Unsupported MechType '%s'" % mechStr, logging.DEBUG)
                        # We don't know the token, we answer back again saying
                        # we just support NTLM.
                        # ToDo: Build this into a SPNEGO_NegTokenResp()
                        respToken = b'\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
                        respParameters['SecurityBlobLength'] = len(respToken)
                        respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
                        respData['SecurityBlob'] = respToken
                        respData['NativeOS'] = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
                        respData['NativeLanMan'] = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
                        respSMBCommand['Parameters'] = respParameters
                        respSMBCommand['Data'] = respData
                        return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED

            elif struct.unpack('B', sessionSetupData['SecurityBlob'][0:1])[0] == ASN1_SUPPORTED_MECH:
                # AUTH packet
                blob = SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
                token = blob['ResponseToken']
            else:
                # No GSSAPI stuff, raw NTLMSSP
                rawNTLM = True
                token = sessionSetupData['SecurityBlob']

            # Here we only handle NTLMSSP, depending on what stage of the
            # authentication we are, we act on it
            messageType = struct.unpack('<L', token[len('NTLMSSP\x00'):len('NTLMSSP\x00') + 4])[0]

            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
                # Let's store it in the connection data
                connData['NEGOTIATE_MESSAGE'] = negotiateMessage
                # Let's build the answer flags
                # TODO: Parse all the flags. With this we're leaving some clients out

                ansFlags = 0

                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_56:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_56
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_128:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_128
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
                if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                    ansFlags |= ntlm.NTLMSSP_NEGOTIATE_UNICODE
                if negotiateMessage['flags'] & ntlm.NTLM_NEGOTIATE_OEM:
                    ansFlags |= ntlm.NTLM_NEGOTIATE_OEM

                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_REQUEST_TARGET

                # Generate the AV_PAIRS
                av_pairs = ntlm.AV_PAIRS()
                # TODO: Put the proper data from SMBSERVER config
                av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = av_pairs[
                    ntlm.NTLMSSP_AV_DNS_HOSTNAME] = smbServer.getServerName().encode('utf-16le')
                av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = av_pairs[
                    ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = smbServer.getServerDomain().encode('utf-16le')
                av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack('<q', (
                            116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))

                challengeMessage = ntlm.NTLMAuthChallenge()
                challengeMessage['flags'] = ansFlags
                challengeMessage['domain_len'] = len(smbServer.getServerDomain().encode('utf-16le'))
                challengeMessage['domain_max_len'] = challengeMessage['domain_len']
                challengeMessage['domain_offset'] = 40 + 16
                challengeMessage['challenge'] = smbServer.getSMBChallenge()
                challengeMessage['domain_name'] = smbServer.getServerDomain().encode('utf-16le')
                challengeMessage['TargetInfoFields_len'] = len(av_pairs)
                challengeMessage['TargetInfoFields_max_len'] = len(av_pairs)
                challengeMessage['TargetInfoFields'] = av_pairs
                challengeMessage['TargetInfoFields_offset'] = 40 + 16 + len(challengeMessage['domain_name'])
                challengeMessage['Version'] = b'\xff' * 8
                challengeMessage['VersionLen'] = 8

                if rawNTLM is False:
                    respToken = SPNEGO_NegTokenResp()
                    # accept-incomplete. We want more data
                    respToken['NegState'] = b'\x01'
                    respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                    respToken['ResponseToken'] = challengeMessage.getData()
                else:
                    respToken = challengeMessage

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
                smbServer.log("AUTHENTICATE_MESSAGE (%s\\%s,%s)" % (
                    authenticateMessage['domain_name'].decode('utf-16le'),
                    authenticateMessage['user_name'].decode('utf-16le'),
                    authenticateMessage['host_name'].decode('utf-16le')))
                # Do we have credentials to check?
                if len(smbServer.getCredentials()) > 0:
                    identity = authenticateMessage['user_name'].decode('utf-16le').lower()
                    # Do we have this user's credentials?
                    if identity in smbServer.getCredentials():
                        # Process data:
                        # Let's parse some data and keep it to ourselves in case it is asked
                        uid, lmhash, nthash = smbServer.getCredentials()[identity]

                        errorCode, sessionKey = computeNTLMv2(identity, lmhash, nthash, smbServer.getSMBChallenge(),
                                                              authenticateMessage, connData['CHALLENGE_MESSAGE'],
                                                              connData['NEGOTIATE_MESSAGE'])

                        if sessionKey is not None:
                            connData['SignatureEnabled'] = False
                            connData['SigningSessionKey'] = sessionKey
                            connData['SignSequenceNumber'] = 1
                    else:
                        errorCode = STATUS_LOGON_FAILURE
                else:
                    # No credentials provided, let's grant access
                    errorCode = STATUS_SUCCESS

                if errorCode == STATUS_SUCCESS:
                    connData['Authenticated'] = True
                    respToken = SPNEGO_NegTokenResp()
                    # accept-completed
                    respToken['NegState'] = b'\x00'

                    smbServer.log(
                        'User %s\\%s authenticated successfully' % (authenticateMessage['host_name'].decode('utf-16le'),
                                                                    authenticateMessage['user_name'].decode(
                                                                        'utf-16le')))
                    # Let's store it in the connection data
                    connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
                    try:
                        jtr_dump_path = smbServer.getJTRdumpPath()
                        ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                            authenticateMessage['user_name'],
                                                            authenticateMessage['domain_name'],
                                                            authenticateMessage['lanman'], authenticateMessage['ntlm'])
                        smbServer.log(ntlm_hash_data['hash_string'])
                        if jtr_dump_path != '':
                            writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                                  jtr_dump_path)
                    except:
                        smbServer.log("Could not write NTLM Hashes to the specified JTR_Dump_Path %s" % jtr_dump_path)
                else:
                    respToken = SPNEGO_NegTokenResp()
                    respToken['NegState'] = b'\x02'
                    smbServer.log("Could not authenticate user!")
                if smbServer.auth_callback is not None:
                    try:
                        smbServer.auth_callback(
                            smbServer=smbServer,
                            connData=connData,
                            domain_name=authenticateMessage['domain_name'].decode('utf-16le'),
                            user_name=authenticateMessage['user_name'].decode('utf-16le'),
                            host_name=authenticateMessage['host_name'].decode('utf-16le')
                        )
                    except Exception as e:
                        print("[!] Could not call auth_callback: %s" % e)

            else:
                raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

            respParameters['SecurityBlobLength'] = len(respToken)
            respData['SecurityBlobLength'] = respParameters['SecurityBlobLength']
            respData['SecurityBlob'] = respToken.getData()

        else:
            # Process Standard Security
            respParameters = smb.SMBSessionSetupAndXResponse_Parameters()
            respData = smb.SMBSessionSetupAndXResponse_Data()
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
            connData['Authenticated'] = True
            respParameters['Action'] = 0
            smbServer.log('User %s\\%s authenticated successfully (basic)' % (
            sessionSetupData['PrimaryDomain'], sessionSetupData['Account']))
            try:
                jtr_dump_path = smbServer.getJTRdumpPath()
                ntlm_hash_data = outputToJohnFormat(b'', b(sessionSetupData['Account']),
                                                    b(sessionSetupData['PrimaryDomain']), sessionSetupData['AnsiPwd'],
                                                    sessionSetupData['UnicodePwd'])
                smbServer.log(ntlm_hash_data['hash_string'])
                if jtr_dump_path != '':
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], jtr_dump_path)
            except:
                smbServer.log("Could not write NTLM Hashes to the specified JTR_Dump_Path %s" % jtr_dump_path)

        respData['NativeOS'] = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
        respData['NativeLanMan'] = encodeSMBString(recvPacket['Flags2'], smbServer.getServerOS())
        respSMBCommand['Parameters'] = respParameters
        respSMBCommand['Data'] = respData

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        # For now, just switching to nobody
        # os.setregid(65534,65534)
        # os.setreuid(65534,65534)
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smbComNegotiate(connId, smbServer, SMBCommand, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus=False)
        connData['Pid'] = recvPacket['Pid']

        SMBCommand = smb.SMBCommand(recvPacket['Data'][0])
        respSMBCommand = smb.SMBCommand(smb.SMB.SMB_COM_NEGOTIATE)

        resp = smb.NewSMBPacket()
        resp['Flags1'] = smb.SMB.FLAGS1_REPLY
        resp['Pid'] = connData['Pid']
        resp['Tid'] = recvPacket['Tid']
        resp['Mid'] = recvPacket['Mid']

        # TODO: We support more dialects, and parse them accordingly
        dialects = SMBCommand['Data'].split(b'\x02')
        try:
            index = dialects.index(b'NT LM 0.12\x00') - 1
            # Let's fill the data for NTLM
            if recvPacket['Flags2'] & smb.SMB.FLAGS2_EXTENDED_SECURITY:
                resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_UNICODE
                # resp['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS
                _dialects_data = smb.SMBExtended_Security_Data()
                _dialects_data['ServerGUID'] = b'A' * 16
                blob = SPNEGO_NegTokenInit()
                blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
                _dialects_data['SecurityBlob'] = blob.getData()

                _dialects_parameters = smb.SMBExtended_Security_Parameters()
                _dialects_parameters[
                    'Capabilities'] = smb.SMB.CAP_EXTENDED_SECURITY | smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS | smb.SMB.CAP_UNICODE
                _dialects_parameters['ChallengeLength'] = 0

            else:
                resp['Flags2'] = smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_UNICODE
                _dialects_parameters = smb.SMBNTLMDialect_Parameters()
                _dialects_data = smb.SMBNTLMDialect_Data()
                _dialects_data['Payload'] = ''
                if 'EncryptionKey' in connData:
                    _dialects_data['Challenge'] = connData['EncryptionKey']
                    _dialects_parameters['ChallengeLength'] = len(_dialects_data.getData())
                else:
                    # TODO: Handle random challenges, now one that can be used with rainbow tables
                    _dialects_data['Challenge'] = b'\x11\x22\x33\x44\x55\x66\x77\x88'
                    _dialects_parameters['ChallengeLength'] = 8
                _dialects_parameters['Capabilities'] = smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_NT_SMBS

                # Let's see if we need to support RPC_REMOTE_APIS
            config = smbServer.getServerConfig()
            if config.has_option('global', 'rpc_apis'):
                if config.getboolean('global', 'rpc_apis') is True:
                    _dialects_parameters['Capabilities'] |= smb.SMB.CAP_RPC_REMOTE_APIS

            _dialects_parameters['DialectIndex'] = index
            # _dialects_parameters['SecurityMode']    = smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER | smb.SMB.SECURITY_SIGNATURES_REQUIRED
            _dialects_parameters['SecurityMode'] = smb.SMB.SECURITY_AUTH_ENCRYPTED | smb.SMB.SECURITY_SHARE_USER
            _dialects_parameters['MaxMpxCount'] = 1
            _dialects_parameters['MaxNumberVcs'] = 1
            _dialects_parameters['MaxBufferSize'] = 64000
            _dialects_parameters['MaxRawSize'] = 65536
            _dialects_parameters['SessionKey'] = 0
            _dialects_parameters['LowDateTime'] = 0
            _dialects_parameters['HighDateTime'] = 0
            _dialects_parameters['ServerTimeZone'] = 0

            respSMBCommand['Data'] = _dialects_data
            respSMBCommand['Parameters'] = _dialects_parameters
            connData['_dialects_data'] = _dialects_data
            connData['_dialects_parameters'] = _dialects_parameters

        except Exception as e:
            # No NTLM throw an error
            smbServer.log('smbComNegotiate: %s' % e, logging.ERROR)
            respSMBCommand['Data'] = struct.pack('<H', 0xffff)

        smbServer.setConnectionData(connId, connData)

        resp.addCommand(respSMBCommand)

        return None, [resp], STATUS_SUCCESS

    @staticmethod
    def default(connId, smbServer, SMBCommand, recvPacket):
        # By default we return an SMB Packet with error not implemented
        smbServer.log("Not implemented command: 0x%x" % recvPacket['Command'], logging.DEBUG)
        packet = smb.NewSMBPacket()
        packet['Flags1'] = smb.SMB.FLAGS1_REPLY
        packet['Flags2'] = smb.SMB.FLAGS2_NT_STATUS
        packet['Command'] = recvPacket['Command']
        packet['Pid'] = recvPacket['Pid']
        packet['Tid'] = recvPacket['Tid']
        packet['Mid'] = recvPacket['Mid']
        packet['Uid'] = recvPacket['Uid']
        packet['Data'] = b'\x00\x00\x00'
        errorCode = STATUS_NOT_IMPLEMENTED
        packet['ErrorCode'] = errorCode >> 16
        packet['ErrorClass'] = errorCode & 0xff

        return None, [packet], errorCode


class SMB2Commands:
    @staticmethod
    def smb2Negotiate(connId, smbServer, recvPacket, isSMB1=False):
        connData = smbServer.getConnectionData(connId, checkStatus=False)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags'] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status'] = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command'] = smb2.SMB2_NEGOTIATE
        respPacket['SessionID'] = 0
        if isSMB1 is False:
            respPacket['MessageID'] = recvPacket['MessageID']
        else:
            respPacket['MessageID'] = 0
        respPacket['TreeID'] = 0

        respSMBCommand = smb2.SMB2Negotiate_Response()

        respSMBCommand['SecurityMode'] = 1
        if isSMB1 is True:
            # Let's first parse the packet to see if the client supports SMB2
            SMBCommand = smb.SMBCommand(recvPacket['Data'][0])

            dialects = SMBCommand['Data'].split(b'\x02')
            if b'SMB 2.002\x00' in dialects or b'SMB 2.???\x00' in dialects:
                respSMBCommand['DialectRevision'] = smb2.SMB2_DIALECT_002
            else:
                # Client does not support SMB2 fallbacking
                raise Exception('SMB2 not supported, fallbacking')
        else:
            respSMBCommand['DialectRevision'] = smb2.SMB2_DIALECT_002
        respSMBCommand['ServerGuid'] = b'A' * 16
        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaxTransactSize'] = 65536
        respSMBCommand['MaxReadSize'] = 65536
        respSMBCommand['MaxWriteSize'] = 65536
        respSMBCommand['SystemTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['ServerStartTime'] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand['SecurityBufferOffset'] = 0x80

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]

        respSMBCommand['Buffer'] = blob.getData()
        respSMBCommand['SecurityBufferLength'] = len(respSMBCommand['Buffer'])

        respPacket['Data'] = respSMBCommand

        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], STATUS_SUCCESS

    @staticmethod
    def smb2SessionSetup(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus=False)

        respSMBCommand = smb2.SMB2SessionSetup_Response()

        sessionSetupData = smb2.SMB2SessionSetup(recvPacket['Data'])

        connData['Capabilities'] = sessionSetupData['Capabilities']

        securityBlob = sessionSetupData['Buffer']

        rawNTLM = False
        if struct.unpack('B', securityBlob[0:1])[0] == ASN1_AID:
            # NEGOTIATE packet
            blob = SPNEGO_NegTokenInit(securityBlob)
            token = blob['MechToken']
            if len(blob['MechTypes'][0]) > 0:
                # Is this GSSAPI NTLM or something else we don't support?
                mechType = blob['MechTypes'][0]
                if mechType != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']:
                    # Nope, do we know it?
                    if mechType in MechTypes:
                        mechStr = MechTypes[mechType]
                    else:
                        mechStr = hexlify(mechType)
                    smbServer.log("Unsupported MechType '%s'" % mechStr, logging.DEBUG)
                    # We don't know the token, we answer back again saying
                    # we just support NTLM.
                    # ToDo: Build this into a SPNEGO_NegTokenResp()
                    respToken = b'\xa1\x15\x30\x13\xa0\x03\x0a\x01\x03\xa1\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a'
                    respSMBCommand['SecurityBufferOffset'] = 0x48
                    respSMBCommand['SecurityBufferLength'] = len(respToken)
                    respSMBCommand['Buffer'] = respToken

                    return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED
        elif struct.unpack('B', securityBlob[0:1])[0] == ASN1_SUPPORTED_MECH:
            # AUTH packet
            blob = SPNEGO_NegTokenResp(securityBlob)
            token = blob['ResponseToken']
        else:
            # No GSSAPI stuff, raw NTLMSSP
            rawNTLM = True
            token = securityBlob

        # Here we only handle NTLMSSP, depending on what stage of the
        # authentication we are, we act on it
        messageType = struct.unpack('<L', token[len('NTLMSSP\x00'):len('NTLMSSP\x00') + 4])[0]

        if messageType == 0x01:
            # NEGOTIATE_MESSAGE
            negotiateMessage = ntlm.NTLMAuthNegotiate()
            negotiateMessage.fromString(token)
            # Let's store it in the connection data
            connData['NEGOTIATE_MESSAGE'] = negotiateMessage
            # Let's build the answer flags
            # TODO: Parse all the flags. With this we're leaving some clients out

            ansFlags = 0

            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_56:
                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_56
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_128:
                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_128
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_UNICODE
            if negotiateMessage['flags'] & ntlm.NTLM_NEGOTIATE_OEM:
                ansFlags |= ntlm.NTLM_NEGOTIATE_OEM
            if negotiateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_SIGN:
                ansFlags |= ntlm.NTLMSSP_NEGOTIATE_SIGN

            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_REQUEST_TARGET

            # Generate the AV_PAIRS
            av_pairs = ntlm.AV_PAIRS()
            # TODO: Put the proper data from SMBSERVER config
            av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = av_pairs[
                ntlm.NTLMSSP_AV_DNS_HOSTNAME] = smbServer.getServerName().encode('utf-16le')
            av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = av_pairs[
                ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = smbServer.getServerDomain().encode('utf-16le')
            av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack('<q', (
                        116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))

            challengeMessage = ntlm.NTLMAuthChallenge()
            challengeMessage['flags'] = ansFlags
            challengeMessage['domain_len'] = len(smbServer.getServerDomain().encode('utf-16le'))
            challengeMessage['domain_max_len'] = challengeMessage['domain_len']
            challengeMessage['domain_offset'] = 40 + 16
            challengeMessage['challenge'] = smbServer.getSMBChallenge()
            challengeMessage['domain_name'] = smbServer.getServerDomain().encode('utf-16le')
            challengeMessage['TargetInfoFields_len'] = len(av_pairs)
            challengeMessage['TargetInfoFields_max_len'] = len(av_pairs)
            challengeMessage['TargetInfoFields'] = av_pairs
            challengeMessage['TargetInfoFields_offset'] = 40 + 16 + len(challengeMessage['domain_name'])
            challengeMessage['Version'] = b'\xff' * 8
            challengeMessage['VersionLen'] = 8

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegState'] = b'\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = challengeMessage.getData()
            else:
                respToken = challengeMessage

            # Setting the packet to STATUS_MORE_PROCESSING
            errorCode = STATUS_MORE_PROCESSING_REQUIRED
            # Let's set up an UID for this connection and store it
            # in the connection's data
            # Picking a fixed value
            # TODO: Manage more UIDs for the same session
            connData['Uid'] = random.randint(1, 0xffffffff)
            # Let's store it in the connection data
            connData['CHALLENGE_MESSAGE'] = challengeMessage

        elif messageType == 0x02:
            # CHALLENGE_MESSAGE
            raise Exception('Challenge Message raise, not implemented!')
        elif messageType == 0x03:
            # AUTHENTICATE_MESSAGE, here we deal with authentication
            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
            authenticateMessage.fromString(token)
            smbServer.log("AUTHENTICATE_MESSAGE (%s\\%s,%s)" % (
                authenticateMessage['domain_name'].decode('utf-16le'),
                authenticateMessage['user_name'].decode('utf-16le'),
                authenticateMessage['host_name'].decode('utf-16le')))

            isGuest = False
            isAnonymus = False

            # TODO: Check the credentials! Now granting permissions
            # Do we have credentials to check?
            if len(smbServer.getCredentials()) > 0:
                identity = authenticateMessage['user_name'].decode('utf-16le').lower()
                # Do we have this user's credentials?
                if identity in smbServer.getCredentials():
                    # Process data:
                    # Let's parse some data and keep it to ourselves in case it is asked
                    uid, lmhash, nthash = smbServer.getCredentials()[identity]

                    errorCode, sessionKey = computeNTLMv2(identity, lmhash, nthash, smbServer.getSMBChallenge(),
                                                          authenticateMessage, connData['CHALLENGE_MESSAGE'],
                                                          connData['NEGOTIATE_MESSAGE'])

                    if sessionKey is not None:
                        connData['SignatureEnabled'] = True
                        connData['SigningSessionKey'] = sessionKey
                        connData['SignSequenceNumber'] = 1
                else:
                    errorCode = STATUS_LOGON_FAILURE
            else:
                # No credentials provided, let's grant access
                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_ANONYMOUS:
                    isAnonymus = True
                    if smbServer._SMBSERVER__anonymousLogon == False:
                        errorCode = STATUS_ACCESS_DENIED
                    else:
                        errorCode = STATUS_SUCCESS
                else:
                    isGuest = True
                    errorCode = STATUS_SUCCESS

            if errorCode == STATUS_SUCCESS:
                connData['Authenticated'] = True
                respToken = SPNEGO_NegTokenResp()
                # accept-completed
                respToken['NegState'] = b'\x00'
                smbServer.log('User %s\\%s authenticated successfully' % (
                    authenticateMessage['host_name'].decode('utf-16le'),
                    authenticateMessage['user_name'].decode('utf-16le')))
                # Let's store it in the connection data
                connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
                try:
                    jtr_dump_path = smbServer.getJTRdumpPath()
                    ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                        authenticateMessage['user_name'],
                                                        authenticateMessage['domain_name'],
                                                        authenticateMessage['lanman'], authenticateMessage['ntlm'])
                    smbServer.log(ntlm_hash_data['hash_string'])
                    if jtr_dump_path != '':
                        writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                              jtr_dump_path)
                except:
                    smbServer.log("Could not write NTLM Hashes to the specified JTR_Dump_Path %s" % jtr_dump_path)

                if isGuest:
                    respSMBCommand['SessionFlags'] = 1
                elif isAnonymus:
                    respSMBCommand['SessionFlags'] = 2

            else:
                respToken = SPNEGO_NegTokenResp()
                respToken['NegState'] = b'\x02'
                smbServer.log("Could not authenticate user!")

            if smbServer.auth_callback is not None:
                try:
                    smbServer.auth_callback(
                        smbServer=smbServer,
                        connData=connData,
                        domain_name=authenticateMessage['domain_name'].decode('utf-16le'),
                        user_name=authenticateMessage['user_name'].decode('utf-16le'),
                        host_name=authenticateMessage['host_name'].decode('utf-16le')
                    )
                except Exception as e:
                    print("[!] Could not call auth_callback: %s" % e)

        else:
            raise Exception("Unknown NTLMSSP MessageType %d" % messageType)

        respSMBCommand['SecurityBufferOffset'] = 0x48
        respSMBCommand['SecurityBufferLength'] = len(respToken)
        respSMBCommand['Buffer'] = respToken.getData()

        # From now on, the client can ask for other commands
        connData['Authenticated'] = True
        # For now, just switching to nobody
        # os.setregid(65534,65534)
        # os.setreuid(65534,65534)
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2TreeConnect(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respPacket = smb2.SMB2Packet()
        respPacket['Flags'] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket['Status'] = STATUS_SUCCESS
        respPacket['CreditRequestResponse'] = 1
        respPacket['Command'] = recvPacket['Command']
        respPacket['SessionID'] = connData['Uid']
        respPacket['Reserved'] = recvPacket['Reserved']
        respPacket['MessageID'] = recvPacket['MessageID']
        respPacket['TreeID'] = recvPacket['TreeID']

        respSMBCommand = smb2.SMB2TreeConnect_Response()

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

        share = searchShare(connId, path.upper(), smbServer)
        if share is not None:
            # Simple way to generate a Tid
            if len(connData['ConnectedShares']) == 0:
                tid = 1
            else:
                tid = list(connData['ConnectedShares'].keys())[-1] + 1
            connData['ConnectedShares'][tid] = share
            connData['ConnectedShares'][tid]['shareName'] = path
            respPacket['TreeID'] = tid
            smbServer.log("Connecting Share(%d:%s)" % (tid, path))
        else:
            smbServer.log("SMB2_TREE_CONNECT not found %s" % path, logging.ERROR)
            errorCode = STATUS_OBJECT_PATH_NOT_FOUND
            respPacket['Status'] = errorCode
        ##

        if path.upper() == 'IPC$':
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_PIPE
            respSMBCommand['ShareFlags'] = 0x30
        else:
            respSMBCommand['ShareType'] = smb2.SMB2_SHARE_TYPE_DISK
            respSMBCommand['ShareFlags'] = 0x0

        respSMBCommand['Capabilities'] = 0
        respSMBCommand['MaximalAccess'] = 0x000f01ff

        respPacket['Data'] = respSMBCommand

        # Sign the packet if needed
        if connData['SignatureEnabled']:
            smbServer.signSMBv2(respPacket, connData['SigningSessionKey'])
        smbServer.setConnectionData(connId, connData)

        return None, [respPacket], errorCode

    @staticmethod
    def smb2Create(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Create_Response()

        ntCreateRequest = smb2.SMB2Create(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'
        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            # If we have a rootFid, the path is relative to that fid
            errorCode = STATUS_SUCCESS
            if 'path' in connData['ConnectedShares'][recvPacket['TreeID']]:
                path = connData['ConnectedShares'][recvPacket['TreeID']]['path']
            else:
                path = 'NONE'
                errorCode = STATUS_ACCESS_DENIED

            deleteOnClose = False

            fileName = normalize_path(ntCreateRequest['Buffer'][:ntCreateRequest['NameLength']].decode('utf-16le'))

            if not isInFileJail(path, fileName):
                LOG.error("Path not in current working directory")
                return [smb2.SMB2Error()], None, STATUS_OBJECT_PATH_SYNTAX_BAD

            pathName = os.path.join(path, fileName)
            createDisposition = ntCreateRequest['CreateDisposition']
            mode = 0

            if createDisposition == smb2.FILE_SUPERSEDE:
                mode |= os.O_TRUNC | os.O_CREAT
            elif createDisposition & smb2.FILE_OVERWRITE_IF == smb2.FILE_OVERWRITE_IF:
                mode |= os.O_TRUNC | os.O_CREAT
            elif createDisposition & smb2.FILE_OVERWRITE == smb2.FILE_OVERWRITE:
                if os.path.exists(pathName) is True:
                    mode |= os.O_TRUNC
                else:
                    errorCode = STATUS_NO_SUCH_FILE
            elif createDisposition & smb2.FILE_OPEN_IF == smb2.FILE_OPEN_IF:
                mode |= os.O_CREAT
            elif createDisposition & smb2.FILE_CREATE == smb2.FILE_CREATE:
                if os.path.exists(pathName) is True:
                    errorCode = STATUS_OBJECT_NAME_COLLISION
                else:
                    mode |= os.O_CREAT
            elif createDisposition & smb2.FILE_OPEN == smb2.FILE_OPEN:
                if os.path.exists(pathName) is not True and (
                        str(pathName) in smbServer.getRegisteredNamedPipes()) is not True:
                    errorCode = STATUS_NO_SUCH_FILE

            if errorCode == STATUS_SUCCESS:
                desiredAccess = ntCreateRequest['DesiredAccess']
                if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                    mode |= os.O_RDONLY
                if (desiredAccess & smb2.FILE_WRITE_DATA) or (desiredAccess & smb2.GENERIC_WRITE):
                    if (desiredAccess & smb2.FILE_READ_DATA) or (desiredAccess & smb2.GENERIC_READ):
                        mode |= os.O_RDWR  # | os.O_APPEND
                    else:
                        mode |= os.O_WRONLY  # | os.O_APPEND
                if desiredAccess & smb2.GENERIC_ALL:
                    mode |= os.O_RDWR  # | os.O_APPEND

                createOptions = ntCreateRequest['CreateOptions']
                if mode & os.O_CREAT == os.O_CREAT:
                    if createOptions & smb2.FILE_DIRECTORY_FILE == smb2.FILE_DIRECTORY_FILE:
                        try:
                            # Let's create the directory
                            os.mkdir(pathName)
                            mode = os.O_RDONLY
                        except Exception as e:
                            smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName, mode, e), logging.ERROR)
                            errorCode = STATUS_ACCESS_DENIED
                if createOptions & smb2.FILE_NON_DIRECTORY_FILE == smb2.FILE_NON_DIRECTORY_FILE:
                    # If the file being opened is a directory, the server MUST fail the request with
                    # STATUS_FILE_IS_A_DIRECTORY in the Status field of the SMB Header in the server
                    # response.
                    if os.path.isdir(pathName) is True:
                        errorCode = STATUS_FILE_IS_A_DIRECTORY

                if createOptions & smb2.FILE_DELETE_ON_CLOSE == smb2.FILE_DELETE_ON_CLOSE:
                    deleteOnClose = True

                if errorCode == STATUS_SUCCESS:
                    try:
                        if os.path.isdir(pathName) and sys.platform == 'win32':
                            fid = VOID_FILE_DESCRIPTOR
                        else:
                            if sys.platform == 'win32':
                                mode |= os.O_BINARY
                            if ensure_str(pathName) in smbServer.getRegisteredNamedPipes():
                                fid = PIPE_FILE_DESCRIPTOR
                                sock = socket.socket()
                                sock.connect(smbServer.getRegisteredNamedPipes()[ensure_str(pathName)])
                            else:
                                fid = os.open(pathName, mode)
                    except Exception as e:
                        smbServer.log("SMB2_CREATE: %s,%s,%s" % (pathName, mode, e), logging.ERROR)
                        # print e
                        fid = 0
                        errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_SMB_BAD_TID

        if errorCode == STATUS_SUCCESS:
            # Simple way to generate a fid
            fakefid = uuid.generate()

            respSMBCommand['FileID'] = fakefid
            respSMBCommand['CreateAction'] = createDisposition

            if fid == PIPE_FILE_DESCRIPTOR:
                respSMBCommand['CreationTime'] = 0
                respSMBCommand['LastAccessTime'] = 0
                respSMBCommand['LastWriteTime'] = 0
                respSMBCommand['ChangeTime'] = 0
                respSMBCommand['AllocationSize'] = 4096
                respSMBCommand['EndOfFile'] = 0
                respSMBCommand['FileAttributes'] = 0x80

            else:
                if os.path.isdir(pathName):
                    respSMBCommand['FileAttributes'] = smb.SMB_FILE_ATTRIBUTE_DIRECTORY
                else:
                    respSMBCommand['FileAttributes'] = ntCreateRequest['FileAttributes']
                # Let's get this file's information
                respInfo, errorCode = queryPathInformation(path, fileName, level=smb.SMB_QUERY_FILE_ALL_INFO)
                if errorCode == STATUS_SUCCESS:
                    respSMBCommand['CreationTime'] = respInfo['CreationTime']
                    respSMBCommand['LastAccessTime'] = respInfo['LastAccessTime']
                    respSMBCommand['LastWriteTime'] = respInfo['LastWriteTime']
                    respSMBCommand['LastChangeTime'] = respInfo['LastChangeTime']
                    respSMBCommand['FileAttributes'] = respInfo['ExtFileAttributes']
                    respSMBCommand['AllocationSize'] = respInfo['AllocationSize']
                    respSMBCommand['EndOfFile'] = respInfo['EndOfFile']

            if errorCode == STATUS_SUCCESS:
                # Let's store the fid for the connection
                # smbServer.log('Create file %s, mode:0x%x' % (pathName, mode))
                connData['OpenedFiles'][fakefid] = {}
                connData['OpenedFiles'][fakefid]['FileHandle'] = fid
                connData['OpenedFiles'][fakefid]['FileName'] = pathName
                connData['OpenedFiles'][fakefid]['DeleteOnClose'] = deleteOnClose
                connData['OpenedFiles'][fakefid]['Open'] = {}
                connData['OpenedFiles'][fakefid]['Open']['EnumerationLocation'] = 0
                connData['OpenedFiles'][fakefid]['Open']['EnumerationSearchPattern'] = ''
                if fid == PIPE_FILE_DESCRIPTOR:
                    connData['OpenedFiles'][fakefid]['Socket'] = sock
        else:
            respSMBCommand = smb2.SMB2Error()

        if errorCode == STATUS_SUCCESS:
            connData['LastRequest']['SMB2_CREATE'] = respSMBCommand
        smbServer.setConnectionData(connId, connData)

        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Close(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Close_Response()

        closeRequest = smb2.SMB2Close(recvPacket['Data'])

        if closeRequest['FileID'].getData() == b'\xff' * 16:
            # Let's take the data from the lastRequest
            if 'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = closeRequest['FileID'].getData()
        else:
            fileID = closeRequest['FileID'].getData()

        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            if fileID in connData['OpenedFiles']:
                errorCode = STATUS_SUCCESS
                fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
                pathName = connData['OpenedFiles'][fileID]['FileName']
                infoRecord = None
                try:
                    if fileHandle == PIPE_FILE_DESCRIPTOR:
                        connData['OpenedFiles'][fileID]['Socket'].close()
                    elif fileHandle != VOID_FILE_DESCRIPTOR:
                        os.close(fileHandle)
                        infoRecord, errorCode = queryFileInformation(os.path.dirname(pathName), os.path.basename(pathName),
                                                                     smb2.SMB2_FILE_NETWORK_OPEN_INFO)
                except Exception as e:
                    smbServer.log("SMB2_CLOSE %s" % e, logging.ERROR)
                    errorCode = STATUS_INVALID_HANDLE
                else:
                    # Check if the file was marked for removal
                    if connData['OpenedFiles'][fileID]['DeleteOnClose'] is True:
                        try:
                            if os.path.isdir(pathName):
                                shutil.rmtree(connData['OpenedFiles'][fileID]['FileName'])
                            else:
                                os.remove(connData['OpenedFiles'][fileID]['FileName'])
                        except Exception as e:
                            smbServer.log("SMB2_CLOSE %s" % e, logging.ERROR)
                            errorCode = STATUS_ACCESS_DENIED

                    # Now fill out the response
                    if infoRecord is not None:
                        respSMBCommand['CreationTime'] = infoRecord['CreationTime']
                        respSMBCommand['LastAccessTime'] = infoRecord['LastAccessTime']
                        respSMBCommand['LastWriteTime'] = infoRecord['LastWriteTime']
                        respSMBCommand['ChangeTime'] = infoRecord['ChangeTime']
                        respSMBCommand['AllocationSize'] = infoRecord['AllocationSize']
                        respSMBCommand['EndofFile'] = infoRecord['EndOfFile']
                        respSMBCommand['FileAttributes'] = infoRecord['FileAttributes']
                    if errorCode == STATUS_SUCCESS:
                        del (connData['OpenedFiles'][fileID])
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2QueryInfo(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2QueryInfo_Response()

        queryInfo = smb2.SMB2QueryInfo(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        respSMBCommand['OutputBufferOffset'] = 0x48
        respSMBCommand['Buffer'] = b'\x00'

        if queryInfo['FileID'].getData() == b'\xff' * 16:
            # Let's take the data from the lastRequest
            if 'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = queryInfo['FileID'].getData()
        else:
            fileID = queryInfo['FileID'].getData()

        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            if fileID in connData['OpenedFiles']:
                fileName = connData['OpenedFiles'][fileID]['FileName']

                if queryInfo['InfoType'] == smb2.SMB2_0_INFO_FILE:
                    if queryInfo['FileInfoClass'] == smb2.SMB2_FILE_INTERNAL_INFO:
                        # No need to call queryFileInformation, we have the data here
                        infoRecord = smb2.FILE_INTERNAL_INFORMATION()
                        infoRecord['IndexNumber'] = fileID
                    else:
                        infoRecord, errorCode = queryFileInformation(os.path.dirname(fileName),
                                                                     os.path.basename(fileName),
                                                                     queryInfo['FileInfoClass'])
                elif queryInfo['InfoType'] == smb2.SMB2_0_INFO_FILESYSTEM:
                    if queryInfo['FileInfoClass'] == smb2.SMB2_FILE_EA_INFO:
                        infoRecord = b'\x00' * 4
                    else:
                        infoRecord = queryFsInformation(os.path.dirname(fileName), os.path.basename(fileName),
                                                        queryInfo['FileInfoClass'])
                elif queryInfo['InfoType'] == smb2.SMB2_0_INFO_SECURITY:
                    # Failing for now, until we support it
                    infoRecord = None
                    errorCode = STATUS_ACCESS_DENIED
                else:
                    smbServer.log("queryInfo not supported (%x)" % queryInfo['InfoType'], logging.ERROR)

                if infoRecord is not None:
                    respSMBCommand['OutputBufferLength'] = len(infoRecord)
                    respSMBCommand['Buffer'] = infoRecord
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2SetInfo(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2SetInfo_Response()

        setInfo = smb2.SMB2SetInfo(recvPacket['Data'])

        errorCode = STATUS_SUCCESS

        if setInfo['FileID'].getData() == b'\xff' * 16:
            # Let's take the data from the lastRequest
            if 'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = setInfo['FileID'].getData()
        else:
            fileID = setInfo['FileID'].getData()

        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            path = connData['ConnectedShares'][recvPacket['TreeID']]['path']
            if fileID in connData['OpenedFiles']:
                pathName = connData['OpenedFiles'][fileID]['FileName']

                if setInfo['InfoType'] == smb2.SMB2_0_INFO_FILE:
                    # The file information is being set
                    informationLevel = setInfo['FileInfoClass']
                    if informationLevel == smb2.SMB2_FILE_DISPOSITION_INFO:
                        infoRecord = smb.SMBSetFileDispositionInfo(setInfo['Buffer'])
                        if infoRecord['DeletePending'] > 0:
                            if os.path.isdir(pathName) and os.listdir(pathName):
                                errorCode = STATUS_DIRECTORY_NOT_EMPTY
                            else:
                                # Mark this file for removal after closed
                                connData['OpenedFiles'][fileID]['DeleteOnClose'] = True
                    elif informationLevel == smb2.SMB2_FILE_BASIC_INFO:
                        infoRecord = smb.SMBSetFileBasicInfo(setInfo['Buffer'])
                        # Creation time won't be set,  the other ones we play with.
                        atime = infoRecord['LastWriteTime']
                        if atime == 0:
                            atime = -1
                        else:
                            atime = getUnixTime(atime)
                        mtime = infoRecord['ChangeTime']
                        if mtime == 0:
                            mtime = -1
                        else:
                            mtime = getUnixTime(mtime)
                        if atime > 0 and mtime > 0:
                            os.utime(pathName, (atime, mtime))
                    elif informationLevel == smb2.SMB2_FILE_END_OF_FILE_INFO:
                        fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
                        infoRecord = smb.SMBSetFileEndOfFileInfo(setInfo['Buffer'])
                        if infoRecord['EndOfFile'] > 0:
                            os.lseek(fileHandle, infoRecord['EndOfFile'] - 1, 0)
                            os.write(fileHandle, b'\x00')
                    elif informationLevel == smb2.SMB2_FILE_RENAME_INFO:
                        renameInfo = smb2.FILE_RENAME_INFORMATION_TYPE_2(setInfo['Buffer'])
                        newFileName = normalize_path(renameInfo['FileName'].decode('utf-16le'))
                        newPathName = os.path.join(path, newFileName)
                        if not isInFileJail(path, newFileName):
                            smbServer.log("Path not in current working directory", logging.ERROR)
                            return [smb2.SMB2Error()], None, STATUS_OBJECT_PATH_SYNTAX_BAD

                        if renameInfo['ReplaceIfExists'] == 0 and os.path.exists(newPathName):
                            return [smb2.SMB2Error()], None, STATUS_OBJECT_NAME_COLLISION
                        try:
                            os.rename(pathName, newPathName)
                            connData['OpenedFiles'][fileID]['FileName'] = newPathName
                        except Exception as e:
                            smbServer.log("smb2SetInfo: %s" % e, logging.ERROR)
                            errorCode = STATUS_ACCESS_DENIED
                    elif informationLevel == smb2.SMB2_FILE_ALLOCATION_INFO:
                        # See https://github.com/samba-team/samba/blob/master/source3/smbd/smb2_trans2.c#LL5201C8-L5201C39
                        smbServer.log("Warning: SMB2_FILE_ALLOCATION_INFO not implemented")
                        errorCode = STATUS_SUCCESS
                    else:
                        smbServer.log('Unknown level for set file info! 0x%x' % informationLevel, logging.ERROR)
                        # UNSUPPORTED
                        errorCode = STATUS_NOT_SUPPORTED
                # elif setInfo['InfoType'] == smb2.SMB2_0_INFO_FILESYSTEM:
                #    # The underlying object store information is being set.
                #    setInfo = queryFsInformation('/', fileName, queryInfo['FileInfoClass'])
                # elif setInfo['InfoType'] == smb2.SMB2_0_INFO_SECURITY:
                #    # The security information is being set.
                #    # Failing for now, until we support it
                #    infoRecord = None
                #    errorCode = STATUS_ACCESS_DENIED
                # elif setInfo['InfoType'] == smb2.SMB2_0_INFO_QUOTA:
                #    # The underlying object store quota information is being set.
                #    setInfo = queryFsInformation('/', fileName, queryInfo['FileInfoClass'])
                else:
                    smbServer.log("setInfo not supported (%x)" % setInfo['InfoType'], logging.ERROR)

            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Write(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Write_Response()
        writeRequest = smb2.SMB2Write(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'

        if writeRequest['FileID'].getData() == b'\xff' * 16:
            # Let's take the data from the lastRequest
            if 'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = writeRequest['FileID'].getData()
        else:
            fileID = writeRequest['FileID'].getData()

        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            if fileID in connData['OpenedFiles']:
                fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
                errorCode = STATUS_SUCCESS
                try:
                    if fileHandle != PIPE_FILE_DESCRIPTOR:
                        offset = writeRequest['Offset']
                        # If we're trying to write past the file end we just skip the write call (Vista does this)
                        if os.lseek(fileHandle, 0, 2) >= offset:
                            os.lseek(fileHandle, offset, 0)
                            os.write(fileHandle, writeRequest['Buffer'])
                    else:
                        sock = connData['OpenedFiles'][fileID]['Socket']
                        sock.send(writeRequest['Buffer'])

                    respSMBCommand['Count'] = writeRequest['Length']
                    respSMBCommand['Remaining'] = 0xff
                except Exception as e:
                    smbServer.log('SMB2_WRITE: %s' % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Read(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Read_Response()
        readRequest = smb2.SMB2Read(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'

        if readRequest['FileID'].getData() == b'\xff' * 16:
            # Let's take the data from the lastRequest
            if 'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = readRequest['FileID'].getData()
        else:
            fileID = readRequest['FileID'].getData()

        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            if fileID in connData['OpenedFiles']:
                fileHandle = connData['OpenedFiles'][fileID]['FileHandle']
                errorCode = 0
                try:
                    if fileHandle != PIPE_FILE_DESCRIPTOR:
                        offset = readRequest['Offset']
                        os.lseek(fileHandle, offset, 0)
                        content = os.read(fileHandle, readRequest['Length'])
                    else:
                        sock = connData['OpenedFiles'][fileID]['Socket']
                        content = sock.recv(readRequest['Length'])

                    respSMBCommand['DataOffset'] = 0x50
                    respSMBCommand['DataLength'] = len(content)
                    respSMBCommand['DataRemaining'] = 0
                    respSMBCommand['Buffer'] = content
                except Exception as e:
                    smbServer.log('SMB2_READ: %s ' % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Flush(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Flush_Response()
        flushRequest = smb2.SMB2Flush(recvPacket['Data'])

        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            if flushRequest['FileID'].getData() in connData['OpenedFiles']:
                fileHandle = connData['OpenedFiles'][flushRequest['FileID'].getData()]['FileHandle']
                errorCode = STATUS_SUCCESS
                try:
                    os.fsync(fileHandle)
                except Exception as e:
                    smbServer.log("SMB2_FLUSH %s" % e, logging.ERROR)
                    errorCode = STATUS_ACCESS_DENIED
            else:
                errorCode = STATUS_INVALID_HANDLE
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2QueryDirectory(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)
        respSMBCommand = smb2.SMB2QueryDirectory_Response()
        queryDirectoryRequest = smb2.SMB2QueryDirectory(recvPacket['Data'])

        respSMBCommand['Buffer'] = b'\x00'

        # The server MUST locate the tree connection, as specified in section 3.3.5.2.11.
        if (recvPacket['TreeID'] in connData['ConnectedShares']) is False:
            return [smb2.SMB2Error()], None, STATUS_NETWORK_NAME_DELETED

        # Next, the server MUST locate the open for the directory to be queried
        # If no open is found, the server MUST fail the request with STATUS_FILE_CLOSED
        if queryDirectoryRequest['FileID'].getData() == b'\xff' * 16:
            # Let's take the data from the lastRequest
            if 'SMB2_CREATE' in connData['LastRequest']:
                fileID = connData['LastRequest']['SMB2_CREATE']['FileID']
            else:
                fileID = queryDirectoryRequest['FileID'].getData()
        else:
            fileID = queryDirectoryRequest['FileID'].getData()

        if (fileID in connData['OpenedFiles']) is False:
            return [smb2.SMB2Error()], None, STATUS_FILE_CLOSED

        # If the open is not an open to a directory, the request MUST be failed
        # with STATUS_INVALID_PARAMETER.
        if os.path.isdir(connData['OpenedFiles'][fileID]['FileName']) is False:
            return [smb2.SMB2Error()], None, STATUS_INVALID_PARAMETER

        # If any other information class is specified in the FileInformationClass
        # field of the SMB2 QUERY_DIRECTORY Request, the server MUST fail the
        # operation with STATUS_INVALID_INFO_CLASS.
        if queryDirectoryRequest['FileInformationClass'] not in (
                smb2.FILE_DIRECTORY_INFORMATION, smb2.FILE_FULL_DIRECTORY_INFORMATION,
                smb2.FILEID_FULL_DIRECTORY_INFORMATION,
                smb2.FILE_BOTH_DIRECTORY_INFORMATION, smb2.FILEID_BOTH_DIRECTORY_INFORMATION,
                smb2.FILENAMES_INFORMATION):
            return [smb2.SMB2Error()], None, STATUS_INVALID_INFO_CLASS

        # If SMB2_REOPEN is set in the Flags field of the SMB2 QUERY_DIRECTORY
        # Request, the server SHOULD<326> set Open.EnumerationLocation to 0
        # and Open.EnumerationSearchPattern to an empty string.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_REOPEN:
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = 0
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = ''

        # If SMB2_RESTART_SCANS is set in the Flags field of the SMB2
        # QUERY_DIRECTORY Request, the server MUST set
        # Open.EnumerationLocation to 0.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_RESTART_SCANS:
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = 0

        # If Open.EnumerationLocation is 0 and Open.EnumerationSearchPattern
        # is an empty string, then Open.EnumerationSearchPattern MUST be set
        # to the search pattern specified in the SMB2 QUERY_DIRECTORY by
        # FileNameOffset and FileNameLength. If FileNameLength is 0, the server
        # SHOULD<327> set Open.EnumerationSearchPattern as "*" to search all entries.

        pattern = queryDirectoryRequest['Buffer'].decode('utf-16le')
        if connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] == 0 and \
                connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] == '':
            if pattern == '':
                pattern = '*'
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = pattern

        # If SMB2_INDEX_SPECIFIED is set and FileNameLength is not zero,
        # the server MUST set Open.EnumerationSearchPattern to the search pattern
        # specified in the request by FileNameOffset and FileNameLength.
        if queryDirectoryRequest['Flags'] & smb2.SMB2_INDEX_SPECIFIED and \
                queryDirectoryRequest['FileNameLength'] > 0:
            connData['OpenedFiles'][fileID]['Open']['EnumerationSearchPattern'] = pattern

        pathName = os.path.join(os.path.normpath(connData['OpenedFiles'][fileID]['FileName']), pattern)
        searchResult, searchCount, errorCode = findFirst2(os.path.dirname(pathName),
                                                          os.path.basename(pathName),
                                                          queryDirectoryRequest['FileInformationClass'],
                                                          smb.ATTR_DIRECTORY, isSMB2=True)

        if errorCode != STATUS_SUCCESS:
            return [smb2.SMB2Error()], None, errorCode

        if searchCount > 2 and pattern == '*':
            # strip . and ..
            searchCount -= 2
            searchResult = searchResult[2:]

        if searchCount == 0 and connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] == 0:
            return [smb2.SMB2Error()], None, STATUS_NO_SUCH_FILE

        if connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] < 0:
            return [smb2.SMB2Error()], None, STATUS_NO_MORE_FILES

        totalData = 0
        respData = b''
        for nItem in range(connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'], searchCount):
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] += 1
            if queryDirectoryRequest['Flags'] & smb2.SL_RETURN_SINGLE_ENTRY:
                # If single entry is requested we must clear the NextEntryOffset
                searchResult[nItem]['NextEntryOffset'] = 0
            data = searchResult[nItem].getData()
            lenData = len(data)
            padLen = (8 - (lenData % 8)) % 8

            # For larger directory we might reach the OutputBufferLength so we need to set 
            # the NextEntryOffset to 0 for the last entry the will fit the buffer
            try:
                # Check if the next data will exceed the OutputBufferLength
                nextData = searchResult[nItem + 1].getData()
                lenNextData = len(nextData)
                nextTotalData = totalData + lenData + padLen + lenNextData
                if nextTotalData >= queryDirectoryRequest['OutputBufferLength']:
                    # Set the NextEntryOffset to 0 and get the data again
                    searchResult[nItem]['NextEntryOffset'] = 0
                    data = searchResult[nItem].getData()
            except IndexError:
                pass

            if (totalData + lenData) >= queryDirectoryRequest['OutputBufferLength']:
                connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] -= 1
                break
            else:
                respData += data + b'\x00' * padLen
                totalData += lenData + padLen

            if queryDirectoryRequest['Flags'] & smb2.SL_RETURN_SINGLE_ENTRY:
                break

        if connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] >= searchCount:
            connData['OpenedFiles'][fileID]['Open']['EnumerationLocation'] = -1

        respSMBCommand['OutputBufferOffset'] = 0x48
        respSMBCommand['OutputBufferLength'] = totalData
        respSMBCommand['Buffer'] = respData

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2ChangeNotify(connId, smbServer, recvPacket):

        return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED

    @staticmethod
    def smb2Echo(connId, smbServer, recvPacket):

        respSMBCommand = smb2.SMB2Echo_Response()

        return [respSMBCommand], None, STATUS_SUCCESS

    @staticmethod
    def smb2TreeDisconnect(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2TreeDisconnect_Response()

        # Get the Tid associated
        if recvPacket['TreeID'] in connData['ConnectedShares']:
            smbServer.log("Disconnecting Share(%d:%s)" % (
                recvPacket['TreeID'], connData['ConnectedShares'][recvPacket['TreeID']]['shareName']))
            del (connData['ConnectedShares'][recvPacket['TreeID']])
            errorCode = STATUS_SUCCESS
        else:
            errorCode = STATUS_SMB_BAD_TID

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Logoff(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Logoff_Response()

        if recvPacket['SessionID'] != connData['Uid']:
            # STATUS_SMB_BAD_UID
            errorCode = STATUS_SMB_BAD_UID
        else:
            errorCode = STATUS_SUCCESS

        connData['Uid'] = 0
        connData['Authenticated'] = False

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Ioctl(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Ioctl_Response()
        ioctlRequest = smb2.SMB2Ioctl(recvPacket['Data'])

        ioctls = smbServer.getIoctls()
        if ioctlRequest['CtlCode'] in ioctls:
            outputData, errorCode = ioctls[ioctlRequest['CtlCode']](connId, smbServer, ioctlRequest)
            if errorCode == STATUS_SUCCESS:
                respSMBCommand['CtlCode'] = ioctlRequest['CtlCode']
                respSMBCommand['FileID'] = ioctlRequest['FileID']
                respSMBCommand['InputOffset'] = 0
                respSMBCommand['InputCount'] = 0
                respSMBCommand['OutputOffset'] = 0x70
                respSMBCommand['OutputCount'] = len(outputData)
                respSMBCommand['Flags'] = 0
                respSMBCommand['Buffer'] = outputData
            else:
                respSMBCommand = outputData
        else:
            smbServer.log("Ioctl not implemented command: 0x%x" % ioctlRequest['CtlCode'], logging.DEBUG)
            errorCode = STATUS_INVALID_DEVICE_REQUEST
            respSMBCommand = smb2.SMB2Error()

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Lock(connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId)

        respSMBCommand = smb2.SMB2Lock_Response()

        # I'm actually doing nothing.. just make MacOS happy ;)
        errorCode = STATUS_SUCCESS

        smbServer.setConnectionData(connId, connData)
        return [respSMBCommand], None, errorCode

    @staticmethod
    def smb2Cancel(connId, smbServer, recvPacket):
        # I'm actually doing nothing
        return [smb2.SMB2Error()], None, STATUS_CANCELLED

    @staticmethod
    def default(connId, smbServer, recvPacket):
        # By default we return an SMB Packet with error not implemented
        smbServer.log("Not implemented command: 0x%x" % recvPacket['Command'], logging.DEBUG)
        return [smb2.SMB2Error()], None, STATUS_NOT_SUPPORTED


class Ioctls:
    @staticmethod
    def fsctlDfsGetReferrals(connId, smbServer, ioctlRequest):
        return smb2.SMB2Error(), STATUS_FS_DRIVER_REQUIRED

    @staticmethod
    def fsctlPipeTransceive(connId, smbServer, ioctlRequest):
        connData = smbServer.getConnectionData(connId)

        ioctlResponse = ''

        if ioctlRequest['FileID'].getData() in connData['OpenedFiles']:
            fileHandle = connData['OpenedFiles'][ioctlRequest['FileID'].getData()]['FileHandle']
            errorCode = STATUS_SUCCESS
            try:
                if fileHandle != PIPE_FILE_DESCRIPTOR:
                    errorCode = STATUS_INVALID_DEVICE_REQUEST
                else:
                    sock = connData['OpenedFiles'][ioctlRequest['FileID'].getData()]['Socket']
                    sock.sendall(ioctlRequest['Buffer'])
                    ioctlResponse = sock.recv(ioctlRequest['MaxOutputResponse'])
            except Exception as e:
                smbServer.log('fsctlPipeTransceive: %s ' % e, logging.ERROR)
                errorCode = STATUS_ACCESS_DENIED
        else:
            errorCode = STATUS_INVALID_DEVICE_REQUEST

        smbServer.setConnectionData(connId, connData)
        return ioctlResponse, errorCode

    @staticmethod
    def fsctlValidateNegotiateInfo(connId, smbServer, ioctlRequest):
        connData = smbServer.getConnectionData(connId)

        errorCode = STATUS_SUCCESS

        validateNegotiateInfo = smb2.VALIDATE_NEGOTIATE_INFO(ioctlRequest['Buffer'])
        validateNegotiateInfoResponse = smb2.VALIDATE_NEGOTIATE_INFO_RESPONSE()
        validateNegotiateInfoResponse['Capabilities'] = 0
        validateNegotiateInfoResponse['Guid'] = b'A' * 16
        validateNegotiateInfoResponse['SecurityMode'] = 1
        validateNegotiateInfoResponse['Dialect'] = smb2.SMB2_DIALECT_002

        smbServer.setConnectionData(connId, connData)
        return validateNegotiateInfoResponse.getData(), errorCode


class SMBSERVERHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server, select_poll=False):
        self.__SMB = server
        # In case of AF_INET6 the client_address contains 4 items, ignore the last 2
        self.__ip, self.__port = client_address[:2]
        self.__request = request
        self.__connId = threading.current_thread().name
        self.__timeOut = 60 * 5
        self.__select_poll = select_poll
        # self.__connId = os.getpid()
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        self.__SMB.log("Incoming connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.addConnection(self.__connId, self.__ip, self.__port)
        while True:
            try:
                # First of all let's get the NETBIOS packet
                session = nmb.NetBIOSTCPSession(self.__SMB.getServerName(), 'HOST', self.__ip, sess_port=self.__port,
                                                sock=self.__request, select_poll=self.__select_poll)
                try:
                    p = session.recv_packet(self.__timeOut)
                except nmb.NetBIOSTimeout:
                    raise
                except nmb.NetBIOSError:
                    break

                if p.get_type() == nmb.NETBIOS_SESSION_REQUEST:
                    # Someone is requesting a session, we're gonna accept them all :)
                    _, rn, my = p.get_trailer().split(b' ')
                    remote_name = nmb.decode_name(b'\x20' + rn)
                    myname = nmb.decode_name(b'\x20' + my)
                    self.__SMB.log(
                        "NetBIOS Session request (%s,%s,%s)" % (self.__ip, remote_name[1].strip(), myname[1]))
                    r = nmb.NetBIOSSessionPacket()
                    r.set_type(nmb.NETBIOS_SESSION_POSITIVE_RESPONSE)
                    r.set_trailer(p.get_trailer())
                    self.__request.send(r.rawData())
                else:
                    resp = self.__SMB.processRequest(self.__connId, p.get_trailer())
                    # Send all the packets received. Except for big transactions this should be
                    # a single packet
                    for i in resp:
                        if hasattr(i, 'getData'):
                            session.send_packet(i.getData())
                        else:
                            session.send_packet(i)
            except Exception as e:
                self.__SMB.log("Handle: %s" % e)
                # import traceback
                # traceback.print_exc()
                break

    def finish(self):
        # Thread/process is dying, we should tell the main SMB thread to remove all this thread data
        self.__SMB.log("Closing down connection (%s,%d)" % (self.__ip, self.__port))
        self.__SMB.removeConnection(self.__connId)
        return socketserver.BaseRequestHandler.finish(self)


class SMBSERVER(socketserver.ThreadingMixIn, socketserver.TCPServer):
    # class SMBSERVER(socketserver.ForkingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, handler_class=SMBSERVERHandler, config_parser=None):
        socketserver.TCPServer.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, server_address, handler_class)

        # Server name and OS to be presented whenever is necessary
        self.__serverName = ''
        self.__serverOS = ''
        self.__serverDomain = ''
        self.__challenge = ''
        self.__log = None

        # Our ConfigParser data
        self.__serverConfig = config_parser

        # Our credentials to be used during the server's lifetime
        self.__credentials = {}

        # Our log file
        self.__logFile = ''

        # Registered Named Pipes, format is PipeName,Socket
        self.__registeredNamedPipes = {}

        # JTR dump path
        self.__jtr_dump_path = ''

        # SMB2 Support flag = default not active
        self.__SMB2Support = False

        # Allow anonymous logon
        self.__anonymousLogon = True

        self.auth_callback = None

        # Our list of commands we will answer, by default the NOT IMPLEMENTED one
        self.__smbCommandsHandler = SMBCommands()
        self.__smbTrans2Handler = TRANS2Commands()
        self.__smbTransHandler = TRANSCommands()
        self.__smbNTTransHandler = NTTRANSCommands()
        self.__smb2CommandsHandler = SMB2Commands()
        self.__IoctlHandler = Ioctls()

        self.__smbNTTransCommands = {
            # NT IOCTL, can't find doc for this
            0xff: self.__smbNTTransHandler.default
        }

        self.__smbTransCommands = {
            '\\PIPE\\LANMAN': self.__smbTransHandler.lanMan,
            smb.SMB.TRANS_TRANSACT_NMPIPE: self.__smbTransHandler.transactNamedPipe,
        }
        self.__smbTrans2Commands = {
            smb.SMB.TRANS2_FIND_FIRST2: self.__smbTrans2Handler.findFirst2,
            smb.SMB.TRANS2_FIND_NEXT2: self.__smbTrans2Handler.findNext2,
            smb.SMB.TRANS2_QUERY_FS_INFORMATION: self.__smbTrans2Handler.queryFsInformation,
            smb.SMB.TRANS2_QUERY_PATH_INFORMATION: self.__smbTrans2Handler.queryPathInformation,
            smb.SMB.TRANS2_QUERY_FILE_INFORMATION: self.__smbTrans2Handler.queryFileInformation,
            smb.SMB.TRANS2_SET_FILE_INFORMATION: self.__smbTrans2Handler.setFileInformation,
            smb.SMB.TRANS2_SET_PATH_INFORMATION: self.__smbTrans2Handler.setPathInformation
        }

        self.__smbCommands = {
            smb.SMB.SMB_COM_FLUSH: self.__smbCommandsHandler.smbComFlush,
            smb.SMB.SMB_COM_CREATE_DIRECTORY: self.__smbCommandsHandler.smbComCreateDirectory,
            smb.SMB.SMB_COM_DELETE_DIRECTORY: self.__smbCommandsHandler.smbComDeleteDirectory,
            smb.SMB.SMB_COM_RENAME: self.__smbCommandsHandler.smbComRename,
            smb.SMB.SMB_COM_DELETE: self.__smbCommandsHandler.smbComDelete,
            smb.SMB.SMB_COM_NEGOTIATE: self.__smbCommandsHandler.smbComNegotiate,
            smb.SMB.SMB_COM_SESSION_SETUP_ANDX: self.__smbCommandsHandler.smbComSessionSetupAndX,
            smb.SMB.SMB_COM_LOGOFF_ANDX: self.__smbCommandsHandler.smbComLogOffAndX,
            smb.SMB.SMB_COM_TREE_CONNECT_ANDX: self.__smbCommandsHandler.smbComTreeConnectAndX,
            smb.SMB.SMB_COM_TREE_DISCONNECT: self.__smbCommandsHandler.smbComTreeDisconnect,
            smb.SMB.SMB_COM_ECHO: self.__smbCommandsHandler.smbComEcho,
            smb.SMB.SMB_COM_QUERY_INFORMATION: self.__smbCommandsHandler.smbQueryInformation,
            smb.SMB.SMB_COM_TRANSACTION2: self.__smbCommandsHandler.smbTransaction2,
            smb.SMB.SMB_COM_TRANSACTION: self.__smbCommandsHandler.smbTransaction,
            # Not needed for now
            smb.SMB.SMB_COM_NT_TRANSACT: self.__smbCommandsHandler.smbNTTransact,
            smb.SMB.SMB_COM_QUERY_INFORMATION_DISK: self.__smbCommandsHandler.smbQueryInformationDisk,
            smb.SMB.SMB_COM_OPEN_ANDX: self.__smbCommandsHandler.smbComOpenAndX,
            smb.SMB.SMB_COM_QUERY_INFORMATION2: self.__smbCommandsHandler.smbComQueryInformation2,
            smb.SMB.SMB_COM_READ_ANDX: self.__smbCommandsHandler.smbComReadAndX,
            smb.SMB.SMB_COM_READ: self.__smbCommandsHandler.smbComRead,
            smb.SMB.SMB_COM_WRITE_ANDX: self.__smbCommandsHandler.smbComWriteAndX,
            smb.SMB.SMB_COM_WRITE: self.__smbCommandsHandler.smbComWrite,
            smb.SMB.SMB_COM_CLOSE: self.__smbCommandsHandler.smbComClose,
            smb.SMB.SMB_COM_LOCKING_ANDX: self.__smbCommandsHandler.smbComLockingAndX,
            smb.SMB.SMB_COM_NT_CREATE_ANDX: self.__smbCommandsHandler.smbComNtCreateAndX,
            0xFF: self.__smbCommandsHandler.default
        }

        self.__smb2Ioctls = {
            smb2.FSCTL_DFS_GET_REFERRALS: self.__IoctlHandler.fsctlDfsGetReferrals,
            # smb2.FSCTL_PIPE_PEEK:                    self.__IoctlHandler.fsctlPipePeek,
            # smb2.FSCTL_PIPE_WAIT:                    self.__IoctlHandler.fsctlPipeWait,
            smb2.FSCTL_PIPE_TRANSCEIVE: self.__IoctlHandler.fsctlPipeTransceive,
            # smb2.FSCTL_SRV_COPYCHUNK:                self.__IoctlHandler.fsctlSrvCopyChunk,
            # smb2.FSCTL_SRV_ENUMERATE_SNAPSHOTS:      self.__IoctlHandler.fsctlSrvEnumerateSnapshots,
            # smb2.FSCTL_SRV_REQUEST_RESUME_KEY:       self.__IoctlHandler.fsctlSrvRequestResumeKey,
            # smb2.FSCTL_SRV_READ_HASH:                self.__IoctlHandler.fsctlSrvReadHash,
            # smb2.FSCTL_SRV_COPYCHUNK_WRITE:          self.__IoctlHandler.fsctlSrvCopyChunkWrite,
            # smb2.FSCTL_LMR_REQUEST_RESILIENCY:       self.__IoctlHandler.fsctlLmrRequestResiliency,
            # smb2.FSCTL_QUERY_NETWORK_INTERFACE_INFO: self.__IoctlHandler.fsctlQueryNetworkInterfaceInfo,
            # smb2.FSCTL_SET_REPARSE_POINT:            self.__IoctlHandler.fsctlSetReparsePoint,
            # smb2.FSCTL_DFS_GET_REFERRALS_EX:         self.__IoctlHandler.fsctlDfsGetReferralsEx,
            # smb2.FSCTL_FILE_LEVEL_TRIM:              self.__IoctlHandler.fsctlFileLevelTrim,
            smb2.FSCTL_VALIDATE_NEGOTIATE_INFO: self.__IoctlHandler.fsctlValidateNegotiateInfo,
        }

        self.__smb2Commands = {
            smb2.SMB2_NEGOTIATE: self.__smb2CommandsHandler.smb2Negotiate,
            smb2.SMB2_SESSION_SETUP: self.__smb2CommandsHandler.smb2SessionSetup,
            smb2.SMB2_LOGOFF: self.__smb2CommandsHandler.smb2Logoff,
            smb2.SMB2_TREE_CONNECT: self.__smb2CommandsHandler.smb2TreeConnect,
            smb2.SMB2_TREE_DISCONNECT: self.__smb2CommandsHandler.smb2TreeDisconnect,
            smb2.SMB2_CREATE: self.__smb2CommandsHandler.smb2Create,
            smb2.SMB2_CLOSE: self.__smb2CommandsHandler.smb2Close,
            smb2.SMB2_FLUSH: self.__smb2CommandsHandler.smb2Flush,
            smb2.SMB2_READ: self.__smb2CommandsHandler.smb2Read,
            smb2.SMB2_WRITE: self.__smb2CommandsHandler.smb2Write,
            smb2.SMB2_LOCK: self.__smb2CommandsHandler.smb2Lock,
            smb2.SMB2_IOCTL: self.__smb2CommandsHandler.smb2Ioctl,
            smb2.SMB2_CANCEL: self.__smb2CommandsHandler.smb2Cancel,
            smb2.SMB2_ECHO: self.__smb2CommandsHandler.smb2Echo,
            smb2.SMB2_QUERY_DIRECTORY: self.__smb2CommandsHandler.smb2QueryDirectory,
            smb2.SMB2_CHANGE_NOTIFY: self.__smb2CommandsHandler.smb2ChangeNotify,
            smb2.SMB2_QUERY_INFO: self.__smb2CommandsHandler.smb2QueryInfo,
            smb2.SMB2_SET_INFO: self.__smb2CommandsHandler.smb2SetInfo,
            # smb2.SMB2_OPLOCK_BREAK:    self.__smb2CommandsHandler.smb2SessionSetup,
            0xFF: self.__smb2CommandsHandler.default
        }

        # List of active connections
        self.__activeConnections = {}

    def getIoctls(self):
        return self.__smb2Ioctls

    def getCredentials(self):
        return self.__credentials

    def removeConnection(self, name):
        try:
            del (self.__activeConnections[name])
        except:
            pass
        self.log("Remaining connections %s" % list(self.__activeConnections.keys()))

    def addConnection(self, name, ip, port):
        self.__activeConnections[name] = {}
        # Let's init with some know stuff we will need to have
        # TODO: Document what's in there
        # print "Current Connections", self.__activeConnections.keys()
        self.__activeConnections[name]['PacketNum'] = 0
        self.__activeConnections[name]['ClientIP'] = ip
        self.__activeConnections[name]['ClientPort'] = port
        self.__activeConnections[name]['Uid'] = 0
        self.__activeConnections[name]['ConnectedShares'] = {}
        self.__activeConnections[name]['OpenedFiles'] = {}
        # SID results for findfirst2
        self.__activeConnections[name]['SIDs'] = {}
        self.__activeConnections[name]['LastRequest'] = {}
        self.__activeConnections[name]['SignatureEnabled'] = False
        self.__activeConnections[name]['SigningChallengeResponse'] = ''
        self.__activeConnections[name]['SigningSessionKey'] = b''
        self.__activeConnections[name]['Authenticated'] = False

    def getActiveConnections(self):
        return self.__activeConnections

    def setConnectionData(self, connId, data):
        self.__activeConnections[connId] = data
        # print "setConnectionData"
        # print self.__activeConnections

    def getConnectionData(self, connId, checkStatus=True):
        conn = self.__activeConnections[connId]
        if checkStatus is True:
            if ('Authenticated' in conn) is not True:
                # Can't keep going further
                raise Exception("User not Authenticated!")
        return conn

    def getRegisteredNamedPipes(self):
        return self.__registeredNamedPipes

    def registerNamedPipe(self, pipeName, address):
        self.__registeredNamedPipes[str(pipeName)] = address
        return True

    def unregisterNamedPipe(self, pipeName):
        if pipeName in self.__registeredNamedPipes:
            del (self.__registeredNamedPipes[str(pipeName)])
            return True
        return False

    def unregisterTransaction(self, transCommand):
        if transCommand in self.__smbTransCommands:
            del (self.__smbTransCommands[transCommand])

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
        # maxDataCount: the max amount of data that can be transferred agreed
        #               with the client
        #
        # and MUST return:
        # respSetup, respParameters, respData, errorCode
        #
        # WHERE:
        #
        # respSetup: the setup response of the transaction
        # respParameters: the parameters response of the transaction
        # respData: the data response of the transaction
        # errorCode: the NT error code

        if transCommand in self.__smbTransCommands:
            originalCommand = self.__smbTransCommands[transCommand]
        else:
            originalCommand = None

        self.__smbTransCommands[transCommand] = callback
        return originalCommand

    def unregisterTransaction2(self, transCommand):
        if transCommand in self.__smbTrans2Commands:
            del (self.__smbTrans2Commands[transCommand])

    def hookTransaction2(self, transCommand, callback):
        # Here we should add to __smbTrans2Commands
        # Same description as Transaction
        if transCommand in self.__smbTrans2Commands:
            originalCommand = self.__smbTrans2Commands[transCommand]
        else:
            originalCommand = None

        self.__smbTrans2Commands[transCommand] = callback
        return originalCommand

    def unregisterNTTransaction(self, transCommand):
        if transCommand in self.__smbNTTransCommands:
            del (self.__smbNTTransCommands[transCommand])

    def hookNTTransaction(self, transCommand, callback):
        # Here we should add to __smbNTTransCommands
        # Same description as Transaction
        if transCommand in self.__smbNTTransCommands:
            originalCommand = self.__smbNTTransCommands[transCommand]
        else:
            originalCommand = None

        self.__smbNTTransCommands[transCommand] = callback
        return originalCommand

    def unregisterSmbCommand(self, smbCommand):
        if smbCommand in self.__smbCommands:
            del (self.__smbCommands[smbCommand])

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

        if smbCommand in self.__smbCommands:
            originalCommand = self.__smbCommands[smbCommand]
        else:
            originalCommand = None

        self.__smbCommands[smbCommand] = callback
        return originalCommand

    def unregisterSmb2Command(self, smb2Command):
        if smb2Command in self.__smb2Commands:
            del (self.__smb2Commands[smb2Command])

    def hookSmb2Command(self, smb2Command, callback):
        if smb2Command in self.__smb2Commands:
            originalCommand = self.__smb2Commands[smb2Command]
        else:
            originalCommand = None

        self.__smb2Commands[smb2Command] = callback
        return originalCommand

    def log(self, msg, level=logging.INFO):
        self.__log.log(level, msg)

    def getServerName(self):
        return self.__serverName

    def getServerOS(self):
        return self.__serverOS

    def getServerDomain(self):
        return self.__serverDomain

    def getSMBChallenge(self):
        return self.__challenge

    def getServerConfig(self):
        return self.__serverConfig

    def setServerConfig(self, config):
        self.__serverConfig = config

    def getJTRdumpPath(self):
        return self.__jtr_dump_path

    def getDumpHashes(self):
        return self.__dump_hashes

    def getAuthCallback(self):
        return self.auth_callback

    def setAuthCallback(self, callback):
        self.auth_callback = callback

    def verify_request(self, request, client_address):
        # TODO: Control here the max amount of processes we want to launch
        # returning False, closes the connection
        return True

    def signSMBv1(self, connData, packet, signingSessionKey, signingChallengeResponse):
        # This logic MUST be applied for messages sent in response to any of the higher-layer actions and in
        # compliance with the message sequencing rules.
        #  * The client or server that sends the message MUST provide the 32-bit sequence number for this
        #    message, as specified in sections 3.2.4.1 and 3.3.4.1.
        #  * The SMB_FLAGS2_SMB_SECURITY_SIGNATURE flag in the header MUST be set.
        #  * To generate the signature, a 32-bit sequence number is copied into the
        #    least significant 32 bits of the SecuritySignature field and the remaining
        #    4 bytes are set to 0x00.
        #  * The MD5 algorithm, as specified in [RFC1321], MUST be used to generate a hash of the SMB
        #    message from the start of the SMB Header, which is defined as follows.
        #    CALL MD5Init( md5context )
        #    CALL MD5Update( md5context, Connection.SigningSessionKey )
        #    CALL MD5Update( md5context, Connection.SigningChallengeResponse )
        #    CALL MD5Update( md5context, SMB message )
        #    CALL MD5Final( digest, md5context )
        #    SET signature TO the first 8 bytes of the digest
        # The resulting 8-byte signature MUST be copied into the SecuritySignature field of the SMB Header,
        # after which the message can be transmitted.

        # print "seq(%d) signingSessionKey %r, signingChallengeResponse %r" % (connData['SignSequenceNumber'], signingSessionKey, signingChallengeResponse)
        packet['SecurityFeatures'] = struct.pack('<q', connData['SignSequenceNumber'])
        # Sign with the sequence
        m = hashlib.md5()
        m.update(signingSessionKey)
        m.update(signingChallengeResponse)
        if hasattr(packet, 'getData'):
            m.update(packet.getData())
        else:
            m.update(packet)
        # Replace sequence with acual hash
        packet['SecurityFeatures'] = m.digest()[:8]
        connData['SignSequenceNumber'] += 2

    def signSMBv2(self, packet, signingSessionKey, padLength=0):
        packet['Signature'] = b'\x00' * 16
        packet['Flags'] |= smb2.SMB2_FLAGS_SIGNED
        packetData = packet.getData() + b'\x00' * padLength
        signature = hmac.new(signingSessionKey, packetData, hashlib.sha256).digest()
        packet['Signature'] = signature[:16]
        # print "%s" % packet['Signature'].encode('hex')

    def processRequest(self, connId, data):

        # TODO: Process batched commands.
        isSMB2 = False
        SMBCommand = None
        try:
            packet = smb.NewSMBPacket(data=data)
            SMBCommand = smb.SMBCommand(packet['Data'][0])
        except:
            # Maybe a SMB2 packet?
            packet = smb2.SMB2Packet(data=data)
            connData = self.getConnectionData(connId, False)
            self.signSMBv2(packet, connData['SigningSessionKey'])
            isSMB2 = True

        connData = self.getConnectionData(connId, False)

        # We might have compound requests
        compoundedPacketsResponse = []
        compoundedPackets = []
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
            if isSMB2 is False:
                # Is the client authenticated already?
                if connData['Authenticated'] is False and packet['Command'] not in (
                smb.SMB.SMB_COM_NEGOTIATE, smb.SMB.SMB_COM_SESSION_SETUP_ANDX):
                    # Nope.. in that case he should only ask for a few commands, if not throw him out.
                    errorCode = STATUS_ACCESS_DENIED
                    respPackets = None
                    respCommands = [smb.SMBCommand(packet['Command'])]
                else:
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
                        if packet['Command'] in self.__smbCommands:
                            if self.__SMB2Support is True:
                                if packet['Command'] == smb.SMB.SMB_COM_NEGOTIATE:
                                    try:
                                        respCommands, respPackets, errorCode = self.__smb2Commands[smb2.SMB2_NEGOTIATE](
                                            connId, self, packet, True)
                                        isSMB2 = True
                                    except Exception as e:
                                        import traceback
                                        traceback.print_exc()
                                        self.log('SMB2_NEGOTIATE: %s' % e, logging.ERROR)
                                        # If something went wrong, let's fallback to SMB1
                                        respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                            connId,
                                            self,
                                            SMBCommand,
                                            packet)
                                        # self.__SMB2Support = False
                                        pass
                                else:
                                    respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                        connId,
                                        self,
                                        SMBCommand,
                                        packet)
                            else:
                                respCommands, respPackets, errorCode = self.__smbCommands[packet['Command']](
                                    connId,
                                    self,
                                    SMBCommand,
                                    packet)
                        else:
                            respCommands, respPackets, errorCode = self.__smbCommands[255](connId, self, SMBCommand,
                                                                                           packet)

                compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                compoundedPackets.append(packet)

            else:
                # Is the client authenticated already?
                if connData['Authenticated'] is False and packet['Command'] not in (
                smb2.SMB2_NEGOTIATE, smb2.SMB2_SESSION_SETUP):
                    # Nope.. in that case he should only ask for a few commands, if not throw him out.
                    errorCode = STATUS_ACCESS_DENIED
                    respPackets = None
                    respCommands = ['']
                    compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                    compoundedPackets.append(packet)
                else:
                    done = False
                    while not done:
                        if packet['Command'] in self.__smb2Commands:
                            if self.__SMB2Support is True:
                                respCommands, respPackets, errorCode = self.__smb2Commands[packet['Command']](
                                    connId,
                                    self,
                                    packet)
                            else:
                                respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                        else:
                            respCommands, respPackets, errorCode = self.__smb2Commands[255](connId, self, packet)
                        # Let's store the result for this compounded packet
                        compoundedPacketsResponse.append((respCommands, respPackets, errorCode))
                        compoundedPackets.append(packet)
                        if packet['NextCommand'] != 0:
                            data = data[packet['NextCommand']:]
                            packet = smb2.SMB2Packet(data=data)
                        else:
                            done = True

        except Exception as e:
            # import traceback
            # traceback.print_exc()
            # Something wen't wrong, defaulting to Bad user ID
            self.log('processRequest (0x%x,%s)' % (packet['Command'], e), logging.ERROR)
            raise

        # We prepare the response packet to commands don't need to bother about that.
        connData = self.getConnectionData(connId, False)

        # Force reconnection loop.. This is just a test.. client will send me back credentials :)
        # connData['PacketNum'] += 1
        # if connData['PacketNum'] == 15:
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
        for packetNum in range(len(compoundedPacketsResponse)):
            respCommands, respPackets, errorCode = compoundedPacketsResponse[packetNum]
            packet = compoundedPackets[packetNum]
            if respPackets is None:
                for respCommand in respCommands:
                    if isSMB2 is False:
                        respPacket = smb.NewSMBPacket()
                        respPacket['Flags1'] = smb.SMB.FLAGS1_REPLY

                        # TODO this should come from a per session configuration
                        respPacket[
                            'Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES | \
                                        packet['Flags2'] & smb.SMB.FLAGS2_UNICODE
                        # respPacket['Flags2'] = smb.SMB.FLAGS2_EXTENDED_SECURITY | smb.SMB.FLAGS2_NT_STATUS | smb.SMB.FLAGS2_LONG_NAMES
                        # respPacket['Flags1'] = 0x98
                        # respPacket['Flags2'] = 0xc807

                        respPacket['Tid'] = packet['Tid']
                        respPacket['Mid'] = packet['Mid']
                        respPacket['Pid'] = packet['Pid']
                        respPacket['Uid'] = connData['Uid']

                        respPacket['ErrorCode'] = errorCode >> 16
                        respPacket['_reserved'] = errorCode >> 8 & 0xff
                        respPacket['ErrorClass'] = errorCode & 0xff
                        respPacket.addCommand(respCommand)

                        if connData['SignatureEnabled']:
                            respPacket['Flags2'] |= smb.SMB.FLAGS2_SMB_SECURITY_SIGNATURE
                            self.signSMBv1(connData, respPacket, connData['SigningSessionKey'],
                                           connData['SigningChallengeResponse'])

                        packetsToSend.append(respPacket)
                    else:
                        respPacket = smb2.SMB2Packet()
                        respPacket['Flags'] = smb2.SMB2_FLAGS_SERVER_TO_REDIR
                        if packetNum > 0:
                            respPacket['Flags'] |= smb2.SMB2_FLAGS_RELATED_OPERATIONS
                        respPacket['Status'] = errorCode
                        respPacket['CreditRequestResponse'] = packet['CreditRequestResponse']
                        respPacket['Command'] = packet['Command']
                        respPacket['CreditCharge'] = packet['CreditCharge']
                        # respPacket['CreditCharge'] = 0
                        respPacket['Reserved'] = packet['Reserved']
                        respPacket['SessionID'] = connData['Uid']
                        respPacket['MessageID'] = packet['MessageID']
                        respPacket['TreeID'] = packet['TreeID']
                        if hasattr(respCommand, 'getData'):
                            respPacket['Data'] = respCommand.getData()
                        else:
                            respPacket['Data'] = str(respCommand)

                        packetsToSend.append(respPacket)
            else:
                # The SMBCommand took care of building the packet
                packetsToSend = respPackets

        if isSMB2 is True:
            # Let's build a compound answer and sign it
            finalData = []
            totalPackets = len(packetsToSend)
            for idx, packet in enumerate(packetsToSend):
                padLen = -len(packet) % 8
                if idx + 1 < totalPackets:
                    packet['NextCommand'] = len(packet) + padLen

                if connData['SignatureEnabled']:
                    self.signSMBv2(packet, connData['SigningSessionKey'], padLength=padLen)

                if hasattr(packet, 'getData'):
                    finalData.append(packet.getData() + padLen * b'\x00')
                else:
                    finalData.append(packet + padLen * b'\x00')

            packetsToSend = [b"".join(finalData)]

        # We clear the compound requests
        connData['LastRequest'] = {}

        return packetsToSend

    def processConfigFile(self, configFile=None):
        # TODO: Do a real config parser
        if self.__serverConfig is None:
            if configFile is None:
                configFile = 'smb.conf'
            self.__serverConfig = configparser.ConfigParser()
            self.__serverConfig.read(configFile)

        self.__serverName = self.__serverConfig.get('global', 'server_name')
        self.__serverOS = self.__serverConfig.get('global', 'server_os')
        self.__serverDomain = self.__serverConfig.get('global', 'server_domain')
        self.__logFile = self.__serverConfig.get('global', 'log_file')
        if self.__serverConfig.has_option('global', 'challenge'):
            self.__challenge = unhexlify(self.__serverConfig.get('global', 'challenge'))
        else:
            self.__challenge = b'A' * 8

        if self.__serverConfig.has_option("global", "jtr_dump_path"):
            self.__jtr_dump_path = self.__serverConfig.get("global", "jtr_dump_path")

        if self.__serverConfig.has_option("global", "dump_hashes"):
            self.__dump_hashes = self.__serverConfig.getboolean("global", "dump_hashes")
        else:
            self.__dump_hashes = False

        if self.__serverConfig.has_option("global", "SMB2Support"):
            self.__SMB2Support = self.__serverConfig.getboolean("global", "SMB2Support")
        else:
            self.__SMB2Support = False

        if self.__serverConfig.has_option("global", "anonymous_logon"):
            self.__anonymousLogon = self.__serverConfig.getboolean("global", "anonymous_logon")
        else:
            self.__anonymousLogon = True

        if self.__logFile != 'None':
            logging.basicConfig(filename=self.__logFile,
                                level=logging.DEBUG,
                                format="%(asctime)s: %(levelname)s: %(message)s",
                                datefmt='%m/%d/%Y %I:%M:%S %p',
                                force=True)
        self.__log = LOG

        # Process the credentials
        credentials_fname = self.__serverConfig.get('global', 'credentials_file')
        if credentials_fname != "":
            cred = open(credentials_fname)
            line = cred.readline()
            while line:
                name, uid, lmhash, nthash = line.split(':')
                self.__credentials[name.lower()] = (uid, lmhash, nthash.strip('\r\n'))
                line = cred.readline()
            cred.close()
        self.log('Config file parsed')

    def addCredential(self, name, uid, lmhash, nthash):
        # If we have hashes, normalize them
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash
            try:  # just in case they were converted already
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass
        self.__credentials[name.lower()] = (uid, lmhash, nthash)


# For windows platforms, opening a directory is not an option, so we set a void FD
VOID_FILE_DESCRIPTOR = -1
PIPE_FILE_DESCRIPTOR = -2

######################################################################
# HELPER CLASSES
######################################################################

from impacket.dcerpc.v5.rpcrt import DCERPCServer
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.srvs import NetrShareEnum, NetrShareEnumResponse, SHARE_INFO_1, NetrServerGetInfo, \
    NetrServerGetInfoResponse, NetrShareGetInfo, NetrShareGetInfoResponse
from impacket.dcerpc.v5.wkst import NetrWkstaGetInfo, NetrWkstaGetInfoResponse
from impacket.system_errors import ERROR_INVALID_LEVEL


class WKSTServer(DCERPCServer):
    def __init__(self):
        DCERPCServer.__init__(self)
        self.wkssvcCallBacks = {
            0: self.NetrWkstaGetInfo,
        }
        self.addCallbacks(('6BFFD098-A112-3610-9833-46C3F87E345A', '1.0'), '\\PIPE\\wkssvc', self.wkssvcCallBacks)

    def NetrWkstaGetInfo(self, data):
        request = NetrWkstaGetInfo(data)
        self.log("NetrWkstaGetInfo Level: %d" % request['Level'])

        answer = NetrWkstaGetInfoResponse()

        if request['Level'] not in (100, 101):
            answer['ErrorCode'] = ERROR_INVALID_LEVEL
            return answer

        answer['WkstaInfo']['tag'] = request['Level']

        if request['Level'] == 100:
            # Windows. Decimal value 500.
            answer['WkstaInfo']['WkstaInfo100']['wki100_platform_id'] = 0x000001F4
            answer['WkstaInfo']['WkstaInfo100']['wki100_computername'] = NULL
            answer['WkstaInfo']['WkstaInfo100']['wki100_langroup'] = NULL
            answer['WkstaInfo']['WkstaInfo100']['wki100_ver_major'] = 5
            answer['WkstaInfo']['WkstaInfo100']['wki100_ver_minor'] = 0
        else:
            # Windows. Decimal value 500.
            answer['WkstaInfo']['WkstaInfo101']['wki101_platform_id'] = 0x000001F4
            answer['WkstaInfo']['WkstaInfo101']['wki101_computername'] = NULL
            answer['WkstaInfo']['WkstaInfo101']['wki101_langroup'] = NULL
            answer['WkstaInfo']['WkstaInfo101']['wki101_ver_major'] = 5
            answer['WkstaInfo']['WkstaInfo101']['wki101_ver_minor'] = 0
            answer['WkstaInfo']['WkstaInfo101']['wki101_lanroot'] = NULL

        return answer


class SRVSServer(DCERPCServer):
    def __init__(self):
        DCERPCServer.__init__(self)

        self._shares = {}
        self.__serverConfig = None
        self.__logFile = None

        self.srvsvcCallBacks = {
            15: self.NetrShareEnum,
            16: self.NetrShareGetInfo,
            21: self.NetrServerGetInfo,
        }

        self.addCallbacks(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'), '\\PIPE\\srvsvc', self.srvsvcCallBacks)

    def setServerConfig(self, config):
        self.__serverConfig = config

    def processConfigFile(self, configFile=None):
        if configFile is not None:
            self.__serverConfig = configparser.ConfigParser()
            self.__serverConfig.read(configFile)
        sections = self.__serverConfig.sections()
        # Let's check the log file
        self.__logFile = self.__serverConfig.get('global', 'log_file')
        if self.__logFile != 'None':
            logging.basicConfig(filename=self.__logFile,
                                level=logging.DEBUG,
                                format="%(asctime)s: %(levelname)s: %(message)s",
                                datefmt='%m/%d/%Y %I:%M:%S %p')

        # Remove the global one
        del (sections[sections.index('global')])
        self._shares = {}
        for i in sections:
            self._shares[i] = dict(self.__serverConfig.items(i))

    def NetrShareGetInfo(self, data):
        request = NetrShareGetInfo(data)
        self.log("NetrGetShareInfo Level: %d" % request['Level'])

        s = request['NetName'][:-1].upper()
        answer = NetrShareGetInfoResponse()
        if s in self._shares:
            share = self._shares[s]

            answer['InfoStruct']['tag'] = 1
            answer['InfoStruct']['ShareInfo1']['shi1_netname'] = s + '\x00'
            answer['InfoStruct']['ShareInfo1']['shi1_type'] = share['share type']
            answer['InfoStruct']['ShareInfo1']['shi1_remark'] = share['comment'] + '\x00'
            answer['ErrorCode'] = 0
        else:
            answer['InfoStruct']['tag'] = 1
            answer['InfoStruct']['ShareInfo1'] = NULL
            answer['ErrorCode'] = 0x0906  # WERR_NET_NAME_NOT_FOUND

        return answer

    def NetrServerGetInfo(self, data):
        request = NetrServerGetInfo(data)
        self.log("NetrServerGetInfo Level: %d" % request['Level'])
        answer = NetrServerGetInfoResponse()
        answer['InfoStruct']['tag'] = 101
        # PLATFORM_ID_NT = 500
        answer['InfoStruct']['ServerInfo101']['sv101_platform_id'] = 500
        answer['InfoStruct']['ServerInfo101']['sv101_name'] = request['ServerName']
        # Windows 7 = 6.1
        answer['InfoStruct']['ServerInfo101']['sv101_version_major'] = 6
        answer['InfoStruct']['ServerInfo101']['sv101_version_minor'] = 1
        # Workstation = 1
        answer['InfoStruct']['ServerInfo101']['sv101_type'] = 1
        answer['InfoStruct']['ServerInfo101']['sv101_comment'] = NULL
        answer['ErrorCode'] = 0
        return answer

    def NetrShareEnum(self, data):
        request = NetrShareEnum(data)
        self.log("NetrShareEnum Level: %d" % request['InfoStruct']['Level'])
        shareEnum = NetrShareEnumResponse()
        shareEnum['InfoStruct']['Level'] = 1
        shareEnum['InfoStruct']['ShareInfo']['tag'] = 1
        shareEnum['TotalEntries'] = len(self._shares)
        shareEnum['InfoStruct']['ShareInfo']['Level1']['EntriesRead'] = len(self._shares)
        shareEnum['ErrorCode'] = 0

        for i in self._shares:
            shareInfo = SHARE_INFO_1()
            shareInfo['shi1_netname'] = i + '\x00'
            shareInfo['shi1_type'] = self._shares[i]['share type']
            shareInfo['shi1_remark'] = self._shares[i]['comment'] + '\x00'
            shareEnum['InfoStruct']['ShareInfo']['Level1']['Buffer'].append(shareInfo)

        return shareEnum


class SimpleSMBServer:
    """
    SimpleSMBServer class - Implements a simple, customizable SMB Server

    :param string listenAddress: the address you want the server to listen on
    :param integer listenPort: the port number you want the server to listen on
    :param string configFile: a file with all the servers' configuration. If no file specified, this class will create the basic parameters needed to run. You will need to add your shares manually tho. See addShare() method
    """

    def __init__(self, listenAddress='0.0.0.0', listenPort=445, configFile=''):
        if configFile != '':
            self.__server = SMBSERVER((listenAddress, listenPort))
            self.__server.processConfigFile(configFile)
            self.__smbConfig = None
        else:
            # Here we write a mini config for the server
            self.__smbConfig = configparser.ConfigParser()
            self.__smbConfig.add_section('global')
            self.__smbConfig.set('global', 'server_name',
                                 ''.join([random.choice(string.ascii_letters) for _ in range(8)]))
            self.__smbConfig.set('global', 'server_os', ''.join([random.choice(string.ascii_letters) for _ in range(8)])
                                 )
            self.__smbConfig.set('global', 'server_domain',
                                 ''.join([random.choice(string.ascii_letters) for _ in range(8)])
                                 )
            self.__smbConfig.set('global', 'log_file', 'None')
            self.__smbConfig.set('global', 'rpc_apis', 'yes')
            self.__smbConfig.set('global', 'credentials_file', '')
            self.__smbConfig.set('global', 'challenge', "A" * 16)

            # IPC always needed
            self.__smbConfig.add_section('IPC$')
            self.__smbConfig.set('IPC$', 'comment', '')
            self.__smbConfig.set('IPC$', 'read only', 'yes')
            self.__smbConfig.set('IPC$', 'share type', '3')
            self.__smbConfig.set('IPC$', 'path', '')
            self.__server = SMBSERVER((listenAddress, listenPort), config_parser=self.__smbConfig)
            self.__server.processConfigFile()

        # Now we have to register the MS-SRVS server. This specially important for
        # Windows 7+ and Mavericks clients since they WON'T (specially OSX)
        # ask for shares using MS-RAP.

        self.__srvsServer = SRVSServer()
        self.__srvsServer.daemon = True
        self.__wkstServer = WKSTServer()
        self.__wkstServer.daemon = True
        self.__server.registerNamedPipe('srvsvc', ('127.0.0.1', self.__srvsServer.getListenPort()))
        self.__server.registerNamedPipe('wkssvc', ('127.0.0.1', self.__wkstServer.getListenPort()))

    def start(self):
        self.__srvsServer.start()
        self.__wkstServer.start()
        self.__server.serve_forever()

    def stop(self):
        self.__server.server_close()

    def registerNamedPipe(self, pipeName, address):
        return self.__server.registerNamedPipe(pipeName, address)

    def unregisterNamedPipe(self, pipeName):
        return self.__server.unregisterNamedPipe(pipeName)

    def getRegisteredNamedPipes(self):
        return self.__server.getRegisteredNamedPipes()

    def addShare(self, shareName, sharePath, shareComment='', shareType='0', readOnly='no'):
        share = shareName.upper()
        self.__smbConfig.add_section(share)
        self.__smbConfig.set(share, 'comment', shareComment)
        self.__smbConfig.set(share, 'read only', readOnly)
        self.__smbConfig.set(share, 'share type', shareType)
        self.__smbConfig.set(share, 'path', sharePath)
        self.__server.setServerConfig(self.__smbConfig)
        self.__srvsServer.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()
        self.__srvsServer.processConfigFile()

    def removeShare(self, shareName):
        self.__smbConfig.remove_section(shareName.upper())
        self.__server.setServerConfig(self.__smbConfig)
        self.__srvsServer.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()
        self.__srvsServer.processConfigFile()

    def setSMBChallenge(self, challenge):
        if challenge != '':
            self.__smbConfig.set('global', 'challenge', challenge)
            self.__server.setServerConfig(self.__smbConfig)
            self.__server.processConfigFile()

    def setLogFile(self, logFile):
        self.__smbConfig.set('global', 'log_file', logFile)
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()

    def setCredentialsFile(self, logFile):
        self.__smbConfig.set('global', 'credentials_file', logFile)
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()

    def addCredential(self, name, uid, lmhash, nthash):
        self.__server.addCredential(name, uid, lmhash, nthash)

    def setSMB2Support(self, value):
        if value is True:
            self.__smbConfig.set("global", "SMB2Support", "True")
        else:
            self.__smbConfig.set("global", "SMB2Support", "False")
        self.__server.setServerConfig(self.__smbConfig)
        self.__server.processConfigFile()

    def getAuthCallback(self):
        return self.__server.getAuthCallback()

    def setAuthCallback(self, callback):
        self.__server.setAuthCallback(callback)
