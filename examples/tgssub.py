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
from impacket.krb5 import constants, types
from impacket.krb5.asn1 import TGS_REP, Ticket
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache, CountedOctetString
from pyasn1.codec.der import decoder, encoder

def substitute_sname(args):
    ccache = CCache.loadFile(args.inticket)
    cred_number = len(ccache.credentials)
    logging.info('Number of credentials in cache: %d' % cred_number)
    if cred_number > 1:
        raise ValueError("More than one credentials in cache, this is not handled at the moment")
    credential = ccache.credentials[0]
    tgs = credential.toTGS()
    decodedST = decoder.decode(tgs['KDC_REP'], asn1Spec=TGS_REP())[0]
    tgs = ccache.credentials[0].toTGS()
    sname = decodedST['ticket']['sname']['name-string']
    if len(decodedST['ticket']['sname']['name-string']) == 1:
        logging.debug("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), automatically filling the substitution service will fail")
        logging.debug("Original sname is: %s" % sname[0])
        if '/' not in args.altservice:
            raise ValueError("Substitution service must include service class AND name (i.e. CLASS/HOSTNAME@REALM, or CLASS/HOSTNAME)")
        service_class, service_hostname = ('', sname[0])
        service_realm = decodedST['ticket']['realm']
    elif len(decodedST['ticket']['sname']['name-string']) == 2:
        service_class, service_hostname = decodedST['ticket']['sname']['name-string']
        service_realm = decodedST['ticket']['realm']
    else:
        logging.debug("Original sname is: %s" % '/'.join(sname))
        raise ValueError("Original sname is not formatted as usual (i.e. CLASS/HOSTNAME), something's wrong here...")
    if '@' in args.altservice:
        new_service_realm = args.altservice.split('@')[1].upper()
        if not '.' in new_service_realm:
            logging.debug("New service realm is not FQDN, you may encounter errors")
        if '/' in args.altservice:
            new_service_hostname = args.altservice.split('@')[0].split('/')[1]
            new_service_class = args.altservice.split('@')[0].split('/')[0]
        else:
            logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
            new_service_hostname = service_hostname
            new_service_class = args.altservice.split('@')[0]
    else:
        logging.debug("No service realm in new SPN, using the current one (%s)" % service_realm)
        new_service_realm = service_realm
        if '/' in args.altservice:
            new_service_hostname = args.altservice.split('/')[1]
            new_service_class = args.altservice.split('/')[0]
        else:
            logging.debug("No service hostname in new SPN, using the current one (%s)" % service_hostname)
            new_service_hostname = service_hostname
            new_service_class = args.altservice
    current_service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
    new_service = "%s/%s@%s" % (new_service_class, new_service_hostname, new_service_realm)
    logging.info('Changing service from %s to %s' % (current_service, new_service))
    # the values are changed in the ticket
    decodedST['ticket']['sname']['name-string'][0] = new_service_class
    decodedST['ticket']['sname']['name-string'][1] = new_service_hostname
    decodedST['ticket']['realm'] = new_service_realm

    ticket = encoder.encode(decodedST)
    credential.ticket = CountedOctetString()
    credential.ticket['data'] = encoder.encode(decodedST['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
    credential.ticket['length'] = len(credential.ticket['data'])
    ccache.credentials[0] = credential

    # the values need to be changed in the ccache credentials
    # we already checked everything above, we can simply do the second replacement here
    ccache.credentials[0]['server'].fromPrincipal(Principal(new_service, type=constants.PrincipalNameType.NT_PRINCIPAL.value))
    logging.info('Saving ticket in %s' % args.outticket)
    ccache.saveFile(args.outticket)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Substitute an sname or SPN into an existing service ticket')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-in', dest='inticket', action="store", metavar="TICKET.CCACHE", help='input ticket to modify', required=True)
    parser.add_argument('-out', dest='outticket', action="store", metavar="TICKET.CCACHE", help='output ticket', required=True)
    parser.add_argument('-altservice', action="store", metavar="SERVICE", help='New sname/SPN', required=True)
    parser.add_argument('-force', action='store_true', help='Force the service substitution without taking the original into consideration')

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
