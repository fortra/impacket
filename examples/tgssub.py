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
#   Python equivalent to Rubeus tgssub: Substitute an sname or SPN into an existing service ticket
#   New value can be of many forms
#   - (service class only) cifs
#   - (service class with hostname) cifs/service
#   - (service class with hostname and realm) cifs/service@DOMAIN.FQDN
#
# Authors:
#   Charlie Bromberg (@_nwodtuhs)

import logging
import sys
import traceback
import argparse


from impacket import version
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache

def substitute_sname(args):
    ccache = CCache.loadFile(args.inticket)
    cred_number = 0
    logging.info('Number of credentials in cache: %d' % len(ccache.credentials))
    if cred_number > 1:
        logging.debug("More than one credentials in cache, modifying all of them")
    for creds in ccache.credentials:
        sname = creds['server'].prettyPrint()
        service_class = sname.split(b'@')[0].split(b'/')[0].decode('utf-8')
        hostname = sname.split(b'@')[0].split(b'/')[1].decode('utf-8')
        service_realm = sname.split(b'@')[1].decode('utf-8')
        if '@' in args.altservice:
            new_service_realm = args.altservice.split('@')[1].upper()
            if not '.' in new_service_realm:
                logging.debug("New service realm is not FQDN, you may encounter errors")
            if '/' in args.altservice:
                new_hostname = args.altservice.split('@')[0].split('/')[1]
                new_service_class = args.altservice.split('@')[0].split('/')[0]
            else:
                logging.debug("No service hostname in new SPN, using the current one (%s)" % hostname)
                new_hostname = hostname
                new_service_class = args.altservice.split('@')[0]
        else:
            logging.debug("No service realm in new SPN, using the current one (%s)" % service_realm)
            new_service_realm = service_realm
            if '/' in args.altservice:
                new_hostname = args.altservice.split('/')[1]
                new_service_class = args.altservice.split('/')[0]
            else:
                logging.debug("No service hostname in new SPN, using the current one (%s)" % hostname)
                new_hostname = hostname
                new_service_class = args.altservice
        new_sname = "%s/%s@%s" % (new_service_class, new_hostname, new_service_realm)
        logging.info('Changing sname from %s to %s' % (sname.decode("utf-8"), new_sname))
        creds['server'].fromPrincipal(Principal(new_sname, type=constants.PrincipalNameType.NT_PRINCIPAL.value))
    logging.info('Saving ticket in %s' % args.outticket)
    ccache.saveFile(args.outticket)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Substitute an sname or SPN into an existing service ticket')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-in', dest='inticket', action="store", metavar="TICKET.CCACHE", help='input ticket to modify', required=True)
    parser.add_argument('-out', dest='outticket', action="store", metavar="TICKET.CCACHE", help='output ticket', required=True)
    parser.add_argument('-altservice', action="store", metavar="SERVICE", help='New sname/SPN', required=True)

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
        substitute_sname(args)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))

if __name__ == '__main__':
    main()
