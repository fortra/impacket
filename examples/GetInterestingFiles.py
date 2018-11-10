#!/usr/bin/env python
# Copyright (c) 2003-2018 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: A script to look for interesting files in a network share and dowload them.
#              The files are deemed interesting if their names contain a certain string
#              Inspired by the Find-InterestingFile function from Powersploit's PowerView module
# Author:
#  Imed Bounab (@imaibou)
#
#
# Reference for:
#  SMB DCE/RPC
#
import sys
import logging
import argparse
import fnmatch
import os
from impacket.examples import logger
from impacket import version
from impacket.smbconnection import SMBConnection

class GetInterestingFiles():
    def __init__(self, smbClient, sharename, path, filters, output_path, debth, max_file_size, download_files):
        self.smb = smbClient
        self.share = sharename
        self.path=path
        self.depth=debth
        self.max_file_size=max_file_size
        self.filters=filters
        self.output_path=output_path
        self.download_files=download_files
        if not os.path.exists(output_path):
            os.makedirs(output_path)
        if self.output_path[-1:]!='/':
            self.output_path+='/'

    def check_share(self, sharename):
        shares = self.smb.listShares()
        for share in shares:
            if share['shi1_netname'][:-1]==sharename:
                return True
        return False

    def ls_share(self, path):
        try:
            return self.smb.listPath(self.share, path+"*")
        except:
            return []

    def get_share_file(self, filename):
        fh = open(self.output_path+filename.replace('\\','_'),'wb')
        try:
            self.smb.getFile(self.share, filename, fh.write)
            fh.close()
        except:
            fh.close()
            os.remove(self.output_path+filename.replace('\\','_'))
            raise

    def do_recursive(self):
        if not self.check_share(self.share):
            logging.error("error: no share with the name %s on the remote server" %(self.share))
            return
        self.smb.connectTree(self.share)
        current_level=[self.path]
        next_level=[]
        current_depth=1
        while not (not current_level and not next_level):
            for path in current_level:
                tmp_filenames=[]
                filenames=set()
                ls=self.ls_share(path)
                for f in ls[2:]:
                    if f.is_directory() > 0 and (current_depth<=self.depth or self.depth==0):
                        next_level.append(path+f.get_longname()+'\\')
                    elif f.is_directory() <=0:
                        if f.get_filesize()<=self.max_file_size or self.max_file_size==0:
                            tmp_filenames.append(f.get_longname().lower())
                        else:
                            logging.debug("Found a file %s with size %d, so too big for downloading" % (
                            path+f.get_longname() ,f.get_filesize()))
                for file_filter in self.filters:
                    filenames=filenames | set(fnmatch.filter(tmp_filenames, file_filter))

                if self.download_files:
                    for file in filenames:
                        try:
                            self.get_share_file(path+file)
                            logging.debug("Downloaded interesting file %s" % (path+file))
                        except:
                            logging.debug("Found interesting file but could not download %s" % (path+file))
                else:
                    for file in filenames:
                        logging.info("Found interesting file %s" % (path+file))
            current_depth+=1
            current_level=next_level
            next_level=[]

def main():
    # Init the example's logger theme
    logger.init()
    print version.BANNER
    parser = argparse.ArgumentParser(add_help = True, description = "SMB client implementation.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ff', type=argparse.FileType('r'), help='file containing search filters, one filter each line. filters are used '
                                                                 'to assess whether or not a filename is interesting. Wildcards are accepted.'
                                                                 ' If no file is provided, the following filters will apply: "*password*", '
                                                                    '"*sensitive*", "*admin*", "*login*", "*secret*", "unattend*.xml", '
                                                                    '"*.vmdk", "*creds*", "*credential*", "*.config", "*.kdbx"')
    parser.add_argument('-share', action="store", metavar = "Share name", help='Required. Name of the share to search in', required=True)
    parser.add_argument('-of', action="store", metavar = "Output folder",default='saved_files/', help='Folder on the local machine where the interesting files will be saved. '
                                                                                                      'Defaults to "saved_files"')
    parser.add_argument('-path', action="store", metavar = "PATH", default='\\', help='Path in the selected share to start the search. '
                                                                                      'Defaults to the root folder "\\"')
    parser.add_argument('-depth', action="store", metavar = "Number", default=0, help='Depth of the search in the share subfolders. Defaults to 0 (no depth limit)', type=int)
    parser.add_argument('-max_file_size', action="store", metavar = "Number", default=0, help='Maximum size of interesting files in bytes. If exceeded, the file will not be downloaded. '
                                                                                        'Defaults to 0 (no file size limit)', type=int)
    parser.add_argument('-list-only', action="store_true", help='Switch: only list interesting files and don\'t download them')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
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

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

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
        smbClient = SMBConnection(address, options.target_ip, sess_port=int(options.port))
        if options.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, options.aesKey, options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        filters=[]
        if options.ff is not None:
            for line in options.ff.readlines():
                filters.append(line.replace('\n','').lower())
        else:
            filters=["*password*", "*sensitive*", "*admin*", "*login*", "*secret*", "unattend*.xml", "*.vmdk", "*creds*", "*credential*", "*.config", "*.kdbx"]
        if options.list_only is True:
            download_files=False
        else:
            download_files=True

        logging.debug("Starting the search with the following filters: %s" % (', '.join('"{0}"'.format(f) for f in filters)))

        finder = GetInterestingFiles(smbClient, options.share, options.path, filters, options.of, options.depth, options.max_file_size, download_files)
        finder.do_recursive()

        logging.info("Search completed. saved files (if any) are to be found in the following folder: %s" % (options.of))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))

if __name__ == "__main__":
    main()
