#!/usr/bin/env python
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
# Description:
#   This script allows the user to query and modify file / directory attributes - utilizing pure SMB.
#
# Author:
#   Raz Kissos (@covertivy)
#

from __future__ import division
from __future__ import print_function
from __future__ import annotations
import sys
import argparse
import logging
import ntpath
from dataclasses import dataclass

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket import smbconnection
from impacket.nmb import SMB_SESSION_PORT
from impacket.smb import (
    SMB_DIALECT, 
    FILE_READ_ATTRIBUTES,
    FILE_WRITE_ATTRIBUTES,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_SHARE_DELETE,
    SMB_QUERY_FILE_BASIC_INFO,
    SMB_SET_FILE_BASIC_INFO,
    SMBQueryFileBasicInfo,
    SMBSetFileBasicInfo,
)
from impacket.smb3structs import (
    SMB2_FILE_BASIC_INFO,
    FILE_BASIC_INFORMATION,
)


ATTRIB_QUERY_ACTION = 'query'
ATTRIB_SET_ACTION = 'set'
VALID_ATTRIB_ACTIONS = (ATTRIB_QUERY_ACTION, ATTRIB_SET_ACTION)

# All Knwon File Attributes according to [MS-FSCC] 2.6 File Attributes.
FILE_ATTRIBUTE_READONLY                 = 0x00000001
FILE_ATTRIBUTE_HIDDEN                   = 0x00000002
FILE_ATTRIBUTE_SYSTEM                   = 0x00000004
FILE_ATTRIBUTE_VOLUME                   = 0x00000008
FILE_ATTRIBUTE_DIRECTORY                = 0x00000010
FILE_ATTRIBUTE_ARCHIVE                  = 0x00000020
FILE_ATTRIBUTE_NORMAL                   = 0x00000080
FILE_ATTRIBUTE_TEMPORARY                = 0x00000100
FILE_ATTRIBUTE_SPARSE_FILE              = 0x00000200
FILE_ATTRIBUTE_REPARSE_POINT            = 0x00000400
FILE_ATTRIBUTE_COMPRESSED               = 0x00000800
FILE_ATTRIBUTE_OFFLINE                  = 0x00001000
FILE_ATTRIBUTE_NOT_CONTENT_INDEXED      = 0x00002000
FILE_ATTRIBUTE_ENCRYPTED                = 0x00004000
FILE_ATTRIBUTE_NO_SCRUB_DATA            = 0x00020000
FILE_ATTRIBUTE_RECALL_ON_OPEN           = 0x00040000
FILE_ATTRIBUTE_PINNED                   = 0x00080000
FILE_ATTRIBUTE_UNPINNED                 = 0x00100000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS    = 0x00400000


@dataclass
class FileAttributes:
    readonly: bool = False
    hidden: bool = False
    system: bool = False
    volume: bool = False
    directory: bool = False
    archive: bool = False
    normal: bool = False
    temporary: bool = False
    sparse_file: bool = False
    reparse_point: bool = False
    compressed: bool = False
    offline: bool = False
    not_content_indexed: bool = False
    encrypted: bool = False
    no_scrub_data: bool = False
    recall_on_open: bool = False
    pinned: bool = False
    unpinned: bool = False
    recall_on_data_access: bool = False
    
    def pack(self) -> int:
        return \
        (FILE_ATTRIBUTE_READONLY                if self.readonly                else 0) | \
        (FILE_ATTRIBUTE_HIDDEN                  if self.hidden                  else 0) | \
        (FILE_ATTRIBUTE_SYSTEM                  if self.system                  else 0) | \
        (FILE_ATTRIBUTE_VOLUME                  if self.volume                  else 0) | \
        (FILE_ATTRIBUTE_DIRECTORY               if self.directory               else 0) | \
        (FILE_ATTRIBUTE_ARCHIVE                 if self.archive                 else 0) | \
        (FILE_ATTRIBUTE_NORMAL                  if self.normal                  else 0) | \
        (FILE_ATTRIBUTE_TEMPORARY               if self.temporary               else 0) | \
        (FILE_ATTRIBUTE_SPARSE_FILE             if self.sparse_file             else 0) | \
        (FILE_ATTRIBUTE_REPARSE_POINT           if self.reparse_point           else 0) | \
        (FILE_ATTRIBUTE_COMPRESSED              if self.compressed              else 0) | \
        (FILE_ATTRIBUTE_OFFLINE                 if self.offline                 else 0) | \
        (FILE_ATTRIBUTE_NOT_CONTENT_INDEXED     if self.not_content_indexed     else 0) | \
        (FILE_ATTRIBUTE_ENCRYPTED               if self.encrypted               else 0) | \
        (FILE_ATTRIBUTE_NO_SCRUB_DATA           if self.no_scrub_data           else 0) | \
        (FILE_ATTRIBUTE_RECALL_ON_OPEN          if self.recall_on_open          else 0) | \
        (FILE_ATTRIBUTE_PINNED                  if self.pinned                  else 0) | \
        (FILE_ATTRIBUTE_UNPINNED                if self.unpinned                else 0) | \
        (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS   if self.recall_on_data_access   else 0)
    
    @classmethod
    def unpack(cls, data: int) -> FileAttributes:
        return cls(
            readonly              = bool(data & FILE_ATTRIBUTE_READONLY),
            hidden                = bool(data & FILE_ATTRIBUTE_HIDDEN),
            system                = bool(data & FILE_ATTRIBUTE_SYSTEM),
            volume                = bool(data & FILE_ATTRIBUTE_VOLUME),
            directory             = bool(data & FILE_ATTRIBUTE_DIRECTORY),
            archive               = bool(data & FILE_ATTRIBUTE_ARCHIVE),
            normal                = bool(data & FILE_ATTRIBUTE_NORMAL),
            temporary             = bool(data & FILE_ATTRIBUTE_TEMPORARY),
            sparse_file           = bool(data & FILE_ATTRIBUTE_SPARSE_FILE),
            reparse_point         = bool(data & FILE_ATTRIBUTE_REPARSE_POINT),
            compressed            = bool(data & FILE_ATTRIBUTE_COMPRESSED),
            offline               = bool(data & FILE_ATTRIBUTE_OFFLINE),
            not_content_indexed   = bool(data & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
            encrypted             = bool(data & FILE_ATTRIBUTE_ENCRYPTED),
            no_scrub_data         = bool(data & FILE_ATTRIBUTE_NO_SCRUB_DATA),
            recall_on_open        = bool(data & FILE_ATTRIBUTE_RECALL_ON_OPEN),
            pinned                = bool(data & FILE_ATTRIBUTE_PINNED),
            unpinned              = bool(data & FILE_ATTRIBUTE_UNPINNED),
            recall_on_data_access = bool(data & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS),
        )

    @staticmethod
    def repr_attribs(data: int) -> str:
        return FileAttributes.unpack(data).__repr__()
    
    def __repr__(self) -> str:
        return \
            ('R' if self.readonly    else '-') + \
            ('H' if self.hidden      else '-') + \
            ('S' if self.system      else '-') + \
            ('V' if self.volume      else '-') + \
            ('D' if self.directory   else '-') + \
            ('A' if self.archive     else '-') + \
            ('N' if self.normal      else '-') + \
            ('T' if self.temporary   else '-') + \
            ('C' if self.compressed  else '-') + \
            ('O' if self.offline     else '-') + \
            ('E' if self.encrypted   else '-') + \
            ('P' if self.pinned      else '-') + \
            ('U' if self.unpinned    else '-')
        

def attrib_query(connection: smbconnection.SMBConnection, tid: int, fid: int) -> FileAttributes:
    if connection.getDialect() == SMB_DIALECT:
        basicinfo = SMBQueryFileBasicInfo(connection.queryInfo(tid, fid, SMB_QUERY_FILE_BASIC_INFO))
        attributes = basicinfo['ExtFileAttributes']
    else:
        basicinfo = FILE_BASIC_INFORMATION(connection.queryInfo(tid, fid, SMB2_FILE_BASIC_INFO))
        attributes = basicinfo['FileAttributes']
    
    logging.debug(f"Got file / directory {attributes = }")
    return FileAttributes.unpack(attributes)

def attrib_set(connection: smbconnection.SMBConnection, tid: int, fid: int, attribs: FileAttributes) -> None:
    if connection.getDialect() == SMB_DIALECT:
        info_data = SMBSetFileBasicInfo()
        info_data['CreationTime'] = 0
        info_data['LastAccessTime'] = 0
        info_data['LastWriteTime'] = 0
        info_data['ChangeTime'] = 0
        info_data['ExtFileAttributes'] = attribs.pack()
        fileInfoClass = SMB_SET_FILE_BASIC_INFO
    else:
        info_data = FILE_BASIC_INFORMATION()
        info_data['CreationTime'] = 0
        info_data['LastAccessTime'] = 0
        info_data['LastWriteTime'] = 0
        info_data['ChangeTime'] = 0
        info_data['FileAttributes'] = attribs.pack()
        fileInfoClass = SMB2_FILE_BASIC_INFO
    
    logging.debug(f"Setting file / directory attributes = {attribs.pack()}")
    
    connection.setInfo(tid, fid, fileInfoClass, info_data)


def main():
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "File Attribute Modification Utility implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument("share", type=str, help="The share in which the desired file to query or modify resides.")
    parser.add_argument("path", type=str, help="The path of the desired file whose attributes we wish to query or modify.")
    
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='Don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-p', '--port', default=SMB_SESSION_PORT, type=int, metavar="destination port", help='Destination port to connect to the SMB Server.')
    group.add_argument('-dc-ip', action='store', metavar="ip address",
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in '
                            'the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')
    group.add_argument('-t', '--timeout', default=60, type=int, metavar="seconds", help='Set connection timeout (seconds).')

    subcommands = parser.add_subparsers(dest="action")
    
    query_parser = subcommands.add_parser(ATTRIB_QUERY_ACTION, help="Query current file / directory attributes.")
    
    set_parser = subcommands.add_parser(ATTRIB_SET_ACTION, help="Modify file / directory attributes.")    
    set_parser.add_argument('-r', '--readonly', dest='readonly', action='store_true', help="A file or directory that is read-only. For a file, applications can read the file but cannot write to it or delete it. For a directory, applications cannot delete it, but applications can create and delete files from that directory.")
    set_parser.add_argument('-H', '--hidden', dest='hidden', action='store_true', help="A file or directory that is hidden. Files and directories marked with this attribute do not appear in an ordinary directory listing.")
    set_parser.add_argument('-s', '--system', dest='system', action='store_true', help="A file or directory that the operating system uses a part of or uses exclusively.")
    set_parser.add_argument('-a', '--archive', dest='archive', action='store_true', help="A file or directory that requires to be archived. Applications use this attribute to mark files for backup or removal.")
    set_parser.add_argument('-n', '--normal', dest='normal', action='store_true', help="A file that does not have other attributes set. This flag is used to clear all other flags by specifying it with no other flags set.")
    set_parser.add_argument('-t', '--temporary', dest='temporary', action='store_true', help="A file that is being used for temporary storage. The operating system can choose to store this file's data in memory rather than on mass storage, writing the data to mass storage only if data remains in the file when the file is closed.")
    set_parser.add_argument('-c', '--compressed', dest='compressed', action='store_true', help="A file or directory that is compressed. For a file, all of the data in the file is compressed. For a directory, compression is the default for newly created files and subdirectories.")
    set_parser.add_argument('-o', '--offline', dest='offline', action='store_true', help="The data in this file is not available immediately. This attribute indicates that the file data is physically moved to offline storage. This attribute is used by Remote Storage, which is hierarchical storage management software.")
    set_parser.add_argument('-e', '--encrypted', dest='encrypted', action='store_true', help="A file or directory that is encrypted. For a file, all data streams in the file are encrypted. For a directory, encryption is the default for newly created files and subdirectories.")
    set_parser.add_argument('-p', '--pinned', dest='pinned', action='store_true', help="This attribute indicates user intent that the file or directory should be kept fully present locally even when not being actively accessed. This attribute is for use with hierarchical storage management software.")
    set_parser.add_argument('-u', '--unpinned', dest='unpinned', action='store_true', help="This attribute indicates that the file or directory should not be kept fully present locally except when being actively accessed. This attribute is for use with hierarchical storage management software.")
    
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.action not in VALID_ATTRIB_ACTIONS:
        logging.error("Invalid action '{action}'".format(action=options.action))
    
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
    
    share = options.share
    path = ntpath.normpath(options.path)

    try:
        connection = smbconnection.SMBConnection(address, options.target_ip, sess_port=int(options.port), timeout=int(options.timeout))
        if options.k is True:
            connection.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip)
        else:
            connection.login(username, password, domain, lmhash, nthash)

        tid = connection.connectTree(share)
        
        if options.action == 'query':
            desiredAccess = FILE_READ_ATTRIBUTES
        elif options.action == 'set':
            desiredAccess = FILE_WRITE_ATTRIBUTES
        
        fid = connection.openFile(
            tid, 
            path, 
            shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,   # Allow other processes to interact with the file / directory.
            creationOption=0,                                                   # Open both a file or a directory without limitation.
            desiredAccess=desiredAccess                                         # Request only the permissions we need.
        )
        
        try:
            if options.action == 'query':
                print(attrib_query(connection, tid, fid), share, path)
            elif options.action == 'set':
                attribs = FileAttributes(
                    readonly      = options.readonly,
                    hidden        = options.hidden,
                    system        = options.system,
                    archive       = options.archive,
                    normal        = options.normal,
                    temporary     = options.temporary,
                    compressed    = options.compressed,
                    offline       = options.offline,
                    encrypted     = options.encrypted,
                    pinned        = options.pinned,
                    unpinned      = options.unpinned,
                )
                attrib_set(connection, tid, fid, attribs)
                print(attribs, share, path)
        finally:
            connection.closeFile(tid, fid)
            connection.disconnectTree(tid)
            connection.close()
        
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


if __name__ == "__main__":
    main()
