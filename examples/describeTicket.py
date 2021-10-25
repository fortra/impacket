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
#   Python script that describes the values of the ticket (TGT or Service Ticket).
#
# Authors:
#   Remi Gascou (@podalirius_)
#   Charlie Bromberg (@_nwodtuhs)



import argparse
import logging
import sys
import traceback
import argparse
import os
import re
from binascii import unhexlify

from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5 import constants
from impacket import version
from impacket.examples import logger, utils
from datetime import datetime
from impacket.krb5 import crypto, constants, types
import base64

def parse_ccache(ticketfile):
    ccache = CCache.loadFile(ticketfile)
    for creds in ccache.credentials:
        logging.info("%-25s: %s" % ("UserName", creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')))
        logging.info("%-25s: %s" % ("UserRealm", creds['client'].prettyPrint().split(b'@')[1].decode('utf-8')))
        logging.info("%-25s: %s" % ("ServiceName", creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')))
        logging.info("%-25s: %s" % ("ServiceRealm", creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')))
        logging.info("%-25s: %s" % ("StartTime", datetime.fromtimestamp(creds['time']['starttime']).strftime("%d/%m/%Y %H:%H:%S %p")))
        logging.info("%-25s: %s" % ("EndTime", datetime.fromtimestamp(creds['time']['endtime']).strftime("%d/%m/%Y %H:%H:%S %p")))
        logging.info("%-25s: %s" % ("RenewTill", datetime.fromtimestamp(creds['time']['renew_till']).strftime("%d/%m/%Y %H:%H:%S %p")))
        flags = []
        for k in constants.TicketFlags:
            if ((creds['tktflags'] >> (31 - k.value)) & 1) == 1:
                flags.append(constants.TicketFlags(k.value).name)
        logging.info("%-25s: (0x%x) %s" % ("Flags", creds['tktflags'], ", ".join(flags)))
        logging.info("%-25s: %s" % ("KeyType", constants.EncryptionTypes(creds["key"]["keytype"]).name))
        logging.info("%-25s: %s" % ("Base64(key)", base64.b64encode(creds["key"]["keyvalue"]).decode("utf-8")))


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Ticket describor')

    parser.add_argument('ticket', action='store', help='Path to ticket.ccache')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    # Authentication arguments
    group = parser.add_argument_group('Kerberos Keys (of your account with unconstrained delegation)')
    group.add_argument('-p', '--krbpass', action="store", metavar="PASSWORD", help='Account password')
    group.add_argument('-hp', '--krbhexpass', action="store", metavar="HEXPASSWORD", help='Hex-encoded password')
    group.add_argument('-s', '--krbsalt', action="store", metavar="USERNAME", help='Case sensitive (!) salt. Used to calculate Kerberos keys.'
                                                                                   'Only required if specifying password instead of keys.')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    return args


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


def main():
    print(version.BANNER)
    args = parse_args()
    init_logger(args)

    try:
        parse_ccache(args.ticket)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))

if __name__ == '__main__':
    main()

