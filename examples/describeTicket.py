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

import logging
import sys
import traceback
import argparse
from Cryptodome.Hash import MD4
from datetime import datetime
import base64
from binascii import unhexlify, hexlify
from pyasn1.codec.der import decoder
from impacket import LOG, version
from impacket.examples import logger
from impacket.dcerpc.v5.rpcrt import TypeSerialization1
from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP, EncTicketPart, AD_IF_RELEVANT
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, InvalidChecksum, string_to_key
from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER, KERB_VALIDATION_INFO, PAC_SERVER_CHECKSUM, PAC_SIGNATURE_DATA

def parse_ccache(args):
    ccache = CCache.loadFile(args.ticket)

    principal = ccache.credentials[0].header['server'].prettyPrint()
    creds = ccache.getCredential(principal.decode())
    TGS = creds.toTGS(principal)
    decodedTGS = decoder.decode(TGS['KDC_REP'], asn1Spec=TGS_REP())[0]

    for creds in ccache.credentials:
        logging.info("%-25s: %s" % ("UserName", creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')))
        logging.info("%-25s: %s" % ("UserRealm", creds['client'].prettyPrint().split(b'@')[1].decode('utf-8')))
        spn = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
        logging.info("%-25s: %s" % ("ServiceName", spn))
        logging.info("%-25s: %s" % ("ServiceRealm", creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')))
        logging.info("%-25s: %s" % ("StartTime", datetime.fromtimestamp(creds['time']['starttime']).strftime("%d/%m/%Y %H:%H:%S %p")))
        logging.info("%-25s: %s" % ("EndTime", datetime.fromtimestamp(creds['time']['endtime']).strftime("%d/%m/%Y %H:%H:%S %p")))
        logging.info("%-25s: %s" % ("RenewTill", datetime.fromtimestamp(creds['time']['renew_till']).strftime("%d/%m/%Y %H:%H:%S %p")))

        flags = []
        for k in constants.TicketFlags:
            if ((creds['tktflags'] >> (31 - k.value)) & 1) == 1:
                flags.append(constants.TicketFlags(k.value).name)
        logging.info("%-25s: (0x%x) %s" % ("Flags", creds['tktflags'], ", ".join(flags)))
        keyType = constants.EncryptionTypes(creds["key"]["keytype"]).name
        logging.info("%-25s: %s" % ("KeyType", keyType))
        logging.info("%-25s: %s" % ("Base64(key)", base64.b64encode(creds["key"]["keyvalue"]).decode("utf-8")))

        if spn.split('/')[0] != 'krbtgt':
            logging.debug("Attempting to create Kerberoast hash")
            # code adapted from Rubeus's DisplayTicket() (https://github.com/GhostPack/Rubeus/blob/3620814cd2c5f05e87cddd50211197bd932fec51/Rubeus/lib/LSA.cs)
            # if this isn't a TGT, try to display a Kerberoastable hash
            if keyType != "rc4_hmac"  and keyType != "aes256_cts_hmac_sha1_96":
                # can only display rc4_hmac ad it doesn't have a salt. DES/AES keys require the user/domain as a salt, and we don't have
                # the user account name that backs the requested SPN for the ticket, no no dice :(
                logging.debug("Service ticket uses encryption key type %s, unable to extract hash and salt" % keyType)
            elif keyType == "rc4_hmac":
                kerberoast_hash = kerberoast_from_ccache(decodedTGS = decodedTGS, spn = spn, username = args.user, domain = args.domain)
            elif args.user:
                if args.user.endswith("$"):
                    user = "host%s.%s" % (args.user.rstrip('$').lower(), args.domain.lower())
                else:
                    user = args.user
                kerberoast_hash = kerberoast_from_ccache(decodedTGS = decodedTGS, spn = spn, username = user, domain = args.domain)
            else:
                logging.error("AES256 in use but no '-u/--user' passed, unable to generate crackable hash")
            if kerberoast_hash:
                logging.info("%-25s: %s" % ("Kerberoast hash", kerberoast_hash))

    logging.debug("Handling Kerberos keys")
    ekeys = generate_kerberos_keys(args)
    # TODO : show message when decrypting ticket, unable to decrypt ticket if not enough arguments are given. Say what is missing

    # copypasta from krbrelayx.py
    # Select the correct encryption key
    etype = decodedTGS['ticket']['enc-part']['etype']
    try:
        logging.debug('Ticket is encrypted with %s (etype %d)' % (constants.EncryptionTypes(etype).name, etype))
        key = ekeys[etype]
        logging.debug('Using corresponding key: %s' % hexlify(key.contents).decode('utf-8'))
    # This raises a KeyError (pun intended) if our key is not found
    except KeyError:
        LOG.error('Could not find the correct encryption key! Ticket is encrypted with keytype %d, but keytype(s) %s were supplied',
                  decodedTGS['ticket']['enc-part']['etype'],
                  ', '.join([str(enctype) for enctype in ekeys.keys()]))
        return None

    # Recover plaintext info from ticket
    try:
        cipherText = decodedTGS['ticket']['enc-part']['cipher']
        newCipher = _enctype_table[int(etype)]
        plainText = newCipher.decrypt(key, 2, cipherText)
    except InvalidChecksum:
        logging.error('Ciphertext integrity failed. Most likely the account password or AES key is incorrect')
        if args.salt:
            logging.info('Make sure the salt/username/domain are set and with the proper values. In case of a computer account, append a "$" to the name.')
        return

    logging.debug('Ticket successfully decrypted')
    encTicketPart = decoder.decode(plainText, asn1Spec=EncTicketPart())[0]
    sessionKey = Key(encTicketPart['key']['keytype'], bytes(encTicketPart['key']['keyvalue']))
    adIfRelevant = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'], asn1Spec=AD_IF_RELEVANT())[0]
    # So here we have the PAC
    pacType = PACTYPE(adIfRelevant[0]['ad-data'].asOctets())
    parse_pac(pacType)


def parse_pac(pacType):
    buff = pacType['Buffers']

    for bufferN in range(pacType['cBuffers']):
        infoBuffer = PAC_INFO_BUFFER(buff)
        data = pacType['Buffers'][infoBuffer['Offset'] - 8:][:infoBuffer['cbBufferSize']]
        if logging.getLogger().level == logging.DEBUG:
            print("TYPE 0x%x" % infoBuffer['ulType'])
        if infoBuffer['ulType'] == 1:
            type1 = TypeSerialization1(data)
            # I'm skipping here 4 bytes with its the ReferentID for the pointer
            newdata = data[len(type1) + 4:]
            kerbdata = KERB_VALIDATION_INFO()
            kerbdata.fromString(newdata)
            kerbdata.fromStringReferents(newdata[len(kerbdata.getData()):])
            # kerbdata.dump()
            print()
            print('Domain SID:', kerbdata['LogonDomainId'].formatCanonical())
            print()
        # elif infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
        #     clientInfo = PAC_CLIENT_INFO(data)
        #     if logging.getLogger().level == logging.DEBUG:
        #         clientInfo.dump()
        #         print()
        elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
            signatureData = PAC_SIGNATURE_DATA(data)
            if logging.getLogger().level == logging.DEBUG:
                signatureData.dump()
                print()
        # elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
        #     signatureData = PAC_SIGNATURE_DATA(data)
        #     if logging.getLogger().level == logging.DEBUG:
        #         signatureData.dump()
        #         print()
        # elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
        #     upn = UPN_DNS_INFO(data)
        #     if logging.getLogger().level == logging.DEBUG:
        #         upn.dump()
        #         print(data[upn['DnsDomainNameOffset']:])
        #         print()
        # else:
        #     hexdump(data)

        if logging.getLogger().level == logging.DEBUG:
            print("#" * 80)

        buff = buff[len(infoBuffer):]

def generate_kerberos_keys(args):
    # copypasta from krbrelayx.py
    # Store Kerberos keys
    keys = {}
    if args.hashes:
        keys[int(constants.EncryptionTypes.rc4_hmac.value)] = unhexlify(args.hashes.split(':')[1])
    if args.aesKey:
        if len(args.aesKey) == 64:
            keys[int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)] = unhexlify(args.aesKey)
        else:
            keys[int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)] = unhexlify(args.aesKey)
    ekeys = {}
    for kt, key in keys.items():
        ekeys[kt] = Key(kt, key)

    allciphers = [
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value)
    ]

    # Calculate Kerberos keys from specified password/salt
    if args.password or args.hexpass:
        if not args.salt and args.user and args.domain: # https://www.thehacker.recipes/ad/movement/kerberos
            if args.user.endswith('$'):
                args.salt = "%shost%s.%s" % (args.domain.upper(), args.user.rstrip('$').lower(), args.domain.lower())
            else:
                args.salt = "%s%s" % (args.domain.upper(), args.user)
        for cipher in allciphers:
            if cipher == 23 and args.hexpass:
                # RC4 calculation is done manually for raw passwords
                md4 = MD4.new()
                md4.update(unhexlify(args.krbhexpass))
                ekeys[cipher] = Key(cipher, md4.digest().decode('utf-8'))
            else:
                # Do conversion magic for raw passwords
                if args.hexpass:
                    rawsecret = unhexlify(args.krbhexpass).decode('utf-16-le', 'replace').encode('utf-8', 'replace')
                else:
                    # If not raw, it was specified from the command line, assume it's not UTF-16
                    rawsecret = args.password
                ekeys[cipher] = string_to_key(cipher, rawsecret, args.salt)
            logging.debug('Calculated type %s (%d) Kerberos key: %s' % (constants.EncryptionTypes(cipher).name, cipher, hexlify(ekeys[cipher].contents).decode('utf-8')))
    return ekeys


def kerberoast_from_ccache(decodedTGS, spn, username, domain):
    try:
        if not domain:
            domain = decodedTGS['ticket']['realm'].upper()
        else:
            domain = domain.upper()

        if not username:
            username = "USER"

        username = username.rstrip('$')

        # Copy-pasta from GestUserSPNs.py
        if decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode)
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif decodedTGS['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username, domain, spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        else:
            logging.debug('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0], decodedTGS['ticket']['sname']['name-string'][1],
                decodedTGS['ticket']['enc-part']['etype']))
        return entry
    except Exception as e:
        logging.debug("Not able to parse ticket: %s" % e)


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Ticket describor')

    parser.add_argument('ticket', action='store', help='Path to ticket.ccache')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    # Authentication arguments
    group = parser.add_argument_group('Some account information')
    group.add_argument('-p', '--password', action="store", metavar="PASSWORD", help='placeholder')
    group.add_argument('-hp', '--hexpass', dest='hexpass', action="store", metavar="PASSWORD", help='placeholder')
    group.add_argument('-u', '--user', action="store", metavar="USER", help='placeholder') # used for kerberoast_from_ccache()
    group.add_argument('-d', '--domain', action="store", metavar="DOMAIN", help='placeholder') # used for kerberoast_from_ccache()
    group.add_argument('-s', '--salt', action="store", metavar="SALT", help='placeholder')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='placeholder')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='placeholder')
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
        parse_ccache(args)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))

if __name__ == '__main__':
    main()

