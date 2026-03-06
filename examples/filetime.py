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
#   This script can be used in order to query & modify file timestamps - utilizing pure SMB.
#   This is a PoC using my implementation of the `set_info` method in the `smb.py` file.
#   The script mimics the syntax & logic to both the linux `touch` and `stat` binaries.
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
from typing import Tuple
from collections import namedtuple
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

import argparse
import datetime
from impacket import smbconnection
from impacket.smb import SMB_DIALECT, FILE_READ_DATA, FILE_WRITE_DATA, FILE_WRITE_ATTRIBUTES, SMB_SET_FILE_BASIC_INFO, POSIXtoFT, FTtoPOSIX, SMBSetFileBasicInfo
from impacket.smb3 import FILE_BASIC_INFORMATION
from impacket.smb3structs import SMB2_DIALECT_311, SMB2_FILE_BASIC_INFO


FILETIME_READ_ACTION = 'stat'
FILETIME_WRITE_ACTION = 'touch'
VALID_FILETIME_ACTIONS = (FILETIME_READ_ACTION, FILETIME_WRITE_ACTION)


@dataclass
class FileTimes:
    creation_time: int = None
    last_access_time: int = None
    last_write_time: int = None
    change_time: int = None
    
    def pretty_repr(self):
        return """
CreationTime: {creation_time}
LastAccessTime: {last_access_time}
LastWriteTime: {last_write_time}
ChangeTime: {change_time}
""".format(
        creation_time="N/A" if self.creation_time is None else datetime.datetime.fromtimestamp(FTtoPOSIX(self.creation_time)).isoformat(),
        last_access_time="N/A" if self.last_access_time is None else datetime.datetime.fromtimestamp(FTtoPOSIX(self.last_access_time)).isoformat(),
        last_write_time="N/A" if self.last_write_time is None else datetime.datetime.fromtimestamp(FTtoPOSIX(self.last_write_time)).isoformat(),
        change_time="N/A" if self.change_time is None else datetime.datetime.fromtimestamp(FTtoPOSIX(self.change_time)).isoformat(),
    )

def filetime_query(connection: smbconnection.SMBConnection, tid: int, fid: int) -> FileTimes:
    if connection.getDialect() == SMB_DIALECT:
        basicinfo = SMBQueryFileBasicInfo(connection.queryInfo(tid, fid, SMB_QUERY_FILE_BASIC_INFO))
    else:
        basicinfo = FILE_BASIC_INFORMATION(connection.queryInfo(tid, fid, SMB2_FILE_BASIC_INFO))
    
    filetimes = FileTimes(
        creation_time=basicinfo['CreationTime'],
        last_access_time=basicinfo['LastAccessTime'],
        last_write_time=basicinfo['LastWriteTime'],
        change_time=basicinfo['ChangeTime'],
    )
    
    logging.debug(f"Got file / directory {filetimes = }")
    return filetimes

def filetime_set(connection: smbconnection.SMBConnection, tid: int, fid: int, filetimes: FileTimes) -> None:
    if connection.getDialect() == SMB_DIALECT:
        info_data = SMBSetFileBasicInfo()
        info_data['ExtFileAttributes'] = 0
        fileInfoClass = SMB_SET_FILE_BASIC_INFO
    else:
        info_data = FILE_BASIC_INFORMATION()
        info_data['FileAttributes'] = 0
        fileInfoClass = SMB2_FILE_BASIC_INFO
    
    info_data['CreationTime'] = filetimes.creation_time if filetimes.creation_time is not None else 0
    info_data['LastAccessTime'] = filetimes.last_access_time if filetimes.last_access_time is not None else 0
    info_data['LastWriteTime'] = filetimes.last_write_time if filetimes.last_write_time is not None else 0
    info_data['ChangeTime'] = filetimes.change_time if filetimes.change_time is not None else 0
    
    logging.debug(f"Setting file / directory filetimes = {filetimes}")
    connection.setInfo(tid, fid, fileInfoClass, info_data)


def main():
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "File / Directory Timestamp Querying & Modification Utility implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument("share", type=str, help="The share in which the desired file / directory to query or modify resides.")
    parser.add_argument("path", type=str, help="The path of the desired file / directory whose timestamps we wish to query or modify.")
    
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
    
    query_parser = subcommands.add_parser(FILETIME_READ_ACTION, description="Show current file / directory timestamps.")
    
    touch_parser = subcommands.add_parser(FILETIME_WRITE_ACTION, description="Modify file / directory timestamps.")
    touch_parser.add_argument('-c', '--create', action='store_true', help='Change the "CreationTime" of the file / directory.')
    touch_parser.add_argument('-a', '--access', action='store_true', help='Change the "LastAccessTime" of the file / directory.')
    touch_parser.add_argument('-w', '--write', action='store_true', help='Change the "LastWriteTime" of the file / directory.')
    touch_parser.add_argument('-m', '--modify', action='store_true', help='Change the "ChangeTime" of the file / directory.')
    
    touch_parser.add_argument('-r', '--reference', default=None, metavar=('<share>', '<path>'), nargs=2, help='Specify a file / directory to reference and copy the timestamps of (format is <share> <path>).')
    touch_parser.add_argument('-t', '--timestamp', default=None, metavar="STAMP", help='Specify a timestamp to set for the selected filetimes (format: YYYY-MM-DD_HH:MM:SS.mmmmmm).')
    
    touch_parser.add_argument('-v', '--validate', action='store_true', help='Query the file after touching to verify the changes.')
    
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
    
    if options.action not in VALID_FILETIME_ACTIONS:
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
    
    if options.action == FILETIME_WRITE_ACTION:
        if all((options.reference, options.timestamp)) or all((not options.reference, not options.timestamp)):
            logging.error("Error! Must select one touch method! Either by reference or by timestamp!")
            sys.exit(1)
        
        if options.reference:
            if len(options.reference) != 2:
                logging.error("Error! Reference must be in the following format: <share> <path>!")
                sys.exit(1)
            else:
                ref_share = options.reference[0]
                ref_path = options.reference[1]
        elif options.timestamp:
            try:
                touch_timestamp = datetime.datetime.fromisoformat(options.timestamp)
            except Exception as exc:
                logging.error("Error parsing timestamp, make sure it is valid ISO format!")
                logging.debug(str(exc))
                sys.exit(1)
    try:
        connection = smbconnection.SMBConnection(address, options.target_ip, sess_port=int(options.port), timeout=int(options.timeout))
        if options.k is True:
            connection.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip)
        else:
            connection.login(username, password, domain, lmhash, nthash)

        if options.action == FILETIME_WRITE_ACTION:
            if options.reference:
                try:
                    ref_tid = connection.connectTree(ref_share)
                    ref_fid = connection.openFile(
                        ref_tid, 
                        ref_path, 
                        shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,   # Allow other processes to interact with the file / directory.
                        creationOption=0,                                                   # Open both a file or a directory without limitation.
                        desiredAccess=FILE_READ_ATTRIBUTES                                  # Request only the permissions we need.
                    )
                    logging.debug(f"Querying Reference FileTimes from '{ref_path}' on share '{ref_share}'!")
                    new_filetimes = filetime_query(connection, ref_tid, ref_fid)
                finally:
                    connection.closeFile(ref_tid, ref_fid)
                    connection.disconnectTree(ref_tid)
            elif options.timestamp:
                logging.debug(f"Got TimeStamp: '{options.timestamp}'!")
                new_filetimes = FileTimes(
                    POSIXtoFT(touch_timestamp.timestamp()),
                    POSIXtoFT(touch_timestamp.timestamp()),
                    POSIXtoFT(touch_timestamp.timestamp()),
                    POSIXtoFT(touch_timestamp.timestamp()),
                )
            
            # Keep only desired filetime changes.
            if not options.create:
                new_filetimes.creation_time = None
            if not options.access:
                new_filetimes.last_access_time = None
            if not options.write:
                new_filetimes.last_write_time = None
            if not options.modify:
                new_filetimes.change_time = None
        
        try:
            tid = connection.connectTree(share)
        
            if options.action == FILETIME_READ_ACTION:
                desiredAccess = FILE_READ_ATTRIBUTES
            elif options.action == FILETIME_WRITE_ACTION:
                desiredAccess = FILE_WRITE_ATTRIBUTES
                if options.validate:
                    desiredAccess |= FILE_READ_ATTRIBUTES
            
            fid = connection.openFile(
                tid, 
                path, 
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,   # Allow other processes to interact with the file / directory.
                creationOption=0,                                                   # Open both a file or a directory without limitation.
                desiredAccess=desiredAccess                                         # Request only the permissions we need.
            )
            
            if options.action == FILETIME_READ_ACTION:
                logging.info(f"Queried FileTimes for '{path}' on share '{share}'!")
                print(filetime_query(connection, tid, fid).pretty_repr())
            elif options.action == FILETIME_WRITE_ACTION:
                logging.info(f"Changing FileTimes for '{path}' on share '{share}'!")
                print(new_filetimes.pretty_repr())
                filetime_set(connection, tid, fid, new_filetimes)
                if options.validate:
                    logging.info(f"Validating Updated FileTimes for '{path}' on share '{share}'!")
                    print(filetime_query(connection, tid, fid).pretty_repr())
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
