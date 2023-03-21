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
#   Given a valid TGT, it will renew it. 
#
#   Based on getTGT.py, getST.py, describeTicket.py (ThePorgs fork), and Rubeus.
#
#   Examples:
#       ./renewTGT.py ccache -outputfile newccache
#
# Author:
#   Lou Scicchitano (@LouScicchitano)
#

from __future__ import division
from __future__ import print_function
import argparse
import datetime
import logging
import os
import random
import struct
import sys
from binascii import hexlify, unhexlify
from six import b

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, Ticket as TicketAsn1, EncTGSRepPart, PA_PAC_OPTIONS, EncTicketPart, EncKDCRepPart
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, _HMACMD5, _AES256CTS, Enctype
from impacket.krb5.constants import TicketFlags, encodeFlags
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT, sendReceive
from impacket.krb5.types import Principal, KerberosTime, Ticket

# Our random number generator
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass

class RENEWTGT:
    def __init__(self, tgt, target, domain, options):
        self.__user= target
        self.__domain = domain
        self.__options = options
        self.__kdcHost = options.dc_ip
        self.__TGT = tgt

    def run(self):
        tgt, cipher, sessionKey = self.__TGT['KDC_REP'], self.__TGT['cipher'], self.__TGT['sessionKey']
        oldSessionKey = sessionKey
        serverName = Principal("krbtgt/"+self.__domain, type=constants.PrincipalNameType.NT_SRV_INST.value)

        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(decodedTGT['ticket'])

        # build AS-REQ
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

        # build TGS-REQ
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
        #opts.append( constants.KDCOptions.forwardable.value )
        #opts.append( constants.KDCOptions.renewable.value )
        opts.append( constants.KDCOptions.renew.value )
        #opts.append( constants.KDCOptions.renewable_ok.value )
        opts.append( constants.KDCOptions.canonicalize.value )

        reqBody['kdc-options'] = constants.encodeFlags(opts)
        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        reqBody['realm'] = self.__domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = rand.getrandbits(31)
        seq_set_iter(reqBody, 'etype',
                          (
                              int(constants.EncryptionTypes.rc4_hmac.value),
                             int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                            int(constants.EncryptionTypes.des_cbc_md5.value),
                             int(cipher.enctype)
                          )
                   )
        message = encoder.encode(tgsReq)

        logging.info('Renewing TGT')
        r = sendReceive(message, self.__domain, self.__kdcHost)

        # Get the session key
        tgs = decoder.decode(r, asn1Spec = TGS_REP())[0]

        if logging.getLogger().level == logging.DEBUG:
            logging.debug('TGS_REP')
            print(tgs.prettyPrint())

        cipherText = tgs['enc-part']['cipher']

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(sessionKey, 8, cipherText)
        encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
        newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())
        # Creating new cipher based on received keytype
        cipher = _enctype_table[encTGSRepPart['key']['keytype']]
        
        # save ticket
        ccache = CCache()
        ccache.fromTGS(r, oldSessionKey, newSessionKey)
        #ccache.saveFile(self.__user + '-renewed.ccache')
        if (options.outputfile):
            ccache.saveFile(options.outputfile)
            logging.info('Renewed TGT written to %s' % (options.outputfile))
        elif (options.k):
            ccache.saveFile(os.getenv('KRB5CCNAME'))
            logging.info('Renewed TGT written to %s' % (os.getenv('KRB5CCNAME')))
        elif (options.ccache):
            ccache.saveFile(options.ccache)
            logging.info('Renewed TGT written to %s' % (options.ccache))

 
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Given a TGT, it will renew it.")
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    group = parser.add_argument_group('ticket')
    group.add_argument('-k', action="store_true", help='Grabs credentials from ccache file (KRB5CCNAME)')
    group.add_argument('-ccache', action="store",metavar = "ccache file", help='Path to ccache file on disk.')
    group.add_argument('-outputfile', action="store", metavar = "output file", help='File path to write renewed ccache.')

    group = parser.add_argument_group('authentication')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    if len(sys.argv)==1:
        parser.print_help()
        print("\nExamples: ")
        print("\t./renewTGT.py -k\n")
        print("\tit will renew the TGT in KRB5CCNAME. If you don't specify them, a password will be asked\n")
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

    try:
        # parse ccache to extract info and TGT
        ccache = None
        domain = ''
        username = ''
        TGT = None

        if (options.k):
            logging.info('Loading ccache from KRB5CCNAME: %s' % (os.getenv('KRB5CCNAME')))
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        elif (options.ccache):
            logging.info('Loading ccache from %s' % (options.ccache))
            ccache = CCache.loadFile(options.ccache)

        username = ccache.principal.components[0]['data'].decode('utf-8')
        domain = ccache.principal.realm['data'].decode('utf-8')
        TGT = ccache.credentials[0].toTGT()

        if TGT is None:
            logging.critical("No TGT found!")
            sys.exit(1)

        # check if ticket is expired
        cred = ccache.credentials[0]
        if datetime.datetime.fromtimestamp(cred['time']['endtime']) < datetime.datetime.now():
            logging.critical("Ticket is expired!")
            sys.exit(1)

        # check if ticket can still be renewed
        if datetime.datetime.fromtimestamp(cred['time']['renew_till']) < datetime.datetime.now():
            logging.critical("Ticket cannot be renewed! (RenewTill expired)")
            sys.exit(1)

        # renew the TGT
        executer = RENEWTGT(TGT, username, domain, options)
        executer.run()

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e) )
