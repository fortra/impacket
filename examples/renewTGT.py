#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  Performs TGT renewal
#
# Author:
#   Matt Creel (@Tw1sm)
#

from __future__ import division
from __future__ import print_function
import argparse
import logging
import random
import datetime
import os

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.examples import logger
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, EncTGSRepPart
from impacket.krb5.crypto import Key, _enctype_table, Enctype, string_to_key
from impacket.krb5.kerberosv5 import sendReceive
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, KerberosTime, Ticket

####
# modified for https://github.com/fortra/impacket/blob/master/impacket/krb5/kerberosv5.py#L367
# to perform ticket renewal
def getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey):

    # Decode the TGT
    try:
        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]
    except:
        decodedTGT = decoder.decode(tgt, asn1Spec = TGS_REP())[0]

    domain = domain.upper()
    # Extract the ticket from the TGT
    ticket = Ticket()
    ticket.from_asn1(decodedTGT['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq['ap-options'] =  constants.encodeFlags(opts)
    seq_set(apReq,'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = decodedTGT['crealm'].asOctets()

    clientName = Principal()
    clientName.from_asn1( decodedTGT, 'crealm', 'cname')

    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator['cusec'] =  now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    encodedApReq = encoder.encode(apReq)

    tgsReq = TGS_REQ()

    tgsReq['pvno'] =  5
    tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgsReq['padata'] = noValue
    tgsReq['padata'][0] = noValue
    tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq['padata'][0]['padata-value'] = encodedApReq

    reqBody = seq_set(tgsReq, 'req-body')

    opts = list()

    ####
    # flag modification - we're renewing the ticket
    opts.append( constants.KDCOptions.renew.value )

    reqBody['kdc-options'] = constants.encodeFlags(opts)
    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    reqBody['realm'] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = random.getrandbits(31)

    ####
    # etype modification - preference to request the same encryption type as the original ticket
    seq_set_iter(reqBody, 'etype', (cipher.enctype,))

    message = encoder.encode(tgsReq)

    r = sendReceive(message, domain, kdcHost)

    # Get the session key

    tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

    cipherText = tgs['enc-part']['cipher']

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plainText = cipher.decrypt(sessionKey, 8, cipherText)

    encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]

    newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())
    # Creating new cipher based on received keytype
    cipher = _enctype_table[encTGSRepPart['key']['keytype']]

    # Check we've got what we asked for
    res = decoder.decode(r, asn1Spec = TGS_REP())[0]
    spn = Principal()
    spn.from_asn1(res['ticket'], 'realm', 'sname')

    if spn.components[0] == serverName.components[0]:
        # Yes.. bye bye
        return r, cipher, sessionKey, newSessionKey


class RenewTGT:
    def __init__(self, output_file, dc_ip):
        self.__kdcHost = dc_ip
        self.__saveFileName = output_file if output_file.endswith('.ccache') else output_file + '.ccache'

    
    def saveTicket(self, ticket, sessionKey):
        ccache = CCache()
        
        ccache.fromTGS(ticket, sessionKey, sessionKey)
        creds = ccache.credentials[0]
        service_realm = creds['server'].realm['data']
        service_class = ''
        if len(creds['server'].components) == 2:
            service_class = creds['server'].components[0]['data']
            service_hostname = creds['server'].components[1]['data']
        else:
            service_hostname = creds['server'].components[0]['data']
        if len(service_class) == 0:
            service = "%s@%s" % (service_hostname, service_realm)
        else:
            service = "%s/%s@%s" % (service_class, service_hostname, service_realm)
        logging.info('Saving ticket in %s' % self.__saveFileName)
        ccache.saveFile(self.__saveFileName)


    def renew(self):
        domain, _, TGT, _ = CCache.parseFile()
        if TGT is not None:
            tgt, cipher, sessionKey = TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey']
            oldSessionKey = sessionKey
        else:
            logging.error('No TGT found in ccache file')
            exit(1)

        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logging.info('Sending TGT renewal request...')
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, self.__kdcHost, tgt, cipher, sessionKey)
        self.saveTicket(tgs, oldSessionKey)


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Renew an existing TGT from ccache file (KRB5CCNAME)")
    parser.add_argument('output_file', action='store', help='Output file')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    try:
        RenewTGT(options.output_file, options.dc_ip).renew()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
