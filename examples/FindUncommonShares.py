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
#   Find uncommon SMB shares on remote machines
#
# Author:
#   Remi GASCOU (@podalirius_)
#

import argparse
import sys
import traceback
import logging
import threading
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from impacket import version
from impacket.examples import logger, utils
from impacket.smbconnection import SMBConnection, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SessionError
import ldap3
import nslookup
import json
import time
import os


COMMON_SHARES = [
    "C$", "D$",
    "ADMIN$", "IPC$",
    "PRINT$", "FAX$",
    "SYSVOL", "NETLOGON"
]


def STYPE_MASK(stype_value):
    known_flags = {
        ## One of the following values may be specified. You can isolate these values by using the STYPE_MASK value.
        # Disk drive.
        "STYPE_DISKTREE": 0x0,

        # Print queue.
        "STYPE_PRINTQ": 0x1,

        # Communication device.
        "STYPE_DEVICE": 0x2,

        # Interprocess communication (IPC).
        "STYPE_IPC": 0x3,

        ## In addition, one or both of the following values may be specified.
        # Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$).
        # Can also refer to administrative shares such as C$, D$, E$, and so forth. For more information, see Network Share Functions.
        "STYPE_SPECIAL": 0x80000000,

        # A temporary share.
        "STYPE_TEMPORARY": 0x40000000
    }
    flags = []
    if (stype_value & 0b11) == known_flags["STYPE_DISKTREE"]:
        flags.append("STYPE_DISKTREE")
    elif (stype_value & 0b11) == known_flags["STYPE_PRINTQ"]:
        flags.append("STYPE_PRINTQ")
    elif (stype_value & 0b11) == known_flags["STYPE_DEVICE"]:
        flags.append("STYPE_DEVICE")
    elif (stype_value & 0b11) == known_flags["STYPE_IPC"]:
        flags.append("STYPE_IPC")
    if (stype_value & known_flags["STYPE_SPECIAL"]) == 0:
        flags.append("STYPE_SPECIAL")
    if (stype_value & known_flags["STYPE_TEMPORARY"]) == 0:
        flags.append("STYPE_TEMPORARY")
    return flags


def get_domain_computers(target_dn, ldap_server, ldap_session):
    results = {}
    ldap_session.search(target_dn, "(objectCategory=computer)", attributes=["dNSHostName", "sAMAccountName"])
    for entry in ldap_session.response:
        if entry['type'] != 'searchResEntry':
            continue
        results[entry['dn']] = {
            'dNSHostName': entry["attributes"]['dNSHostName'],
            'sAMAccountName': entry["attributes"]['sAMAccountName']
        }
    return results


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Find uncommon SMB shares on remote machines.')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('--use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="show no information at all")
    parser.add_argument("-debug", dest="debug", action="store_true", default=False, help="Debug mode")
    parser.add_argument("-colors", dest="colors", action="store_true", default=False, help="Colored output mode")
    parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=5, required=False, help="Number of threads (default: 5)")
    parser.add_argument("-o", "--output-file", dest="output_file", type=str, default="shares.json", required=False, help="Output file to store the results in. (default: shares.json)")

    authconn = parser.add_argument_group('authentication & connection')
    authconn.add_argument('--dc-ip', required=True, action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument('--no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument('--aes-key', dest="auth_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args


def get_machine_name(args, domain):
    if args.dc_ip is not None:
        s = SMBConnection(args.dc_ip, args.dc_ip)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)

    if args.use_kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.auth_key, kdcHost=args.dc_ip)
    elif args.auth_hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session(args, domain, username, password, lmhash, nthash):
    if args.use_kerberos:
        target = get_machine_name(args, domain)
    else:
        if args.dc_ip is not None:
            target = args.dc_ip
        else:
            target = domain

    if args.use_ldaps is True:
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, args, domain, username, password, lmhash, nthash)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, args, domain, username, password, lmhash, nthash)
    else:
        return init_ldap_connection(target, None, args, domain, username, password, lmhash, nthash)


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logging.debug('Domain retrieved from CCache: %s' % domain)

            logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logging.debug('Using TGT from cache')
                else:
                    logging.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logging.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True


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


def init_smb_session(args, target_ip, domain, username, password, address, lmhash, nthash, port=445):
    smbClient = SMBConnection(address, target_ip, sess_port=int(port))
    dialect = smbClient.getDialect()
    if dialect == SMB_DIALECT:
        logging.debug("SMBv1 dialect used")
    elif dialect == SMB2_DIALECT_002:
        logging.debug("SMBv2.0 dialect used")
    elif dialect == SMB2_DIALECT_21:
        logging.debug("SMBv2.1 dialect used")
    else:
        logging.debug("SMBv3.0 dialect used")
    if args.use_kerberos is True:
        smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
    else:
        smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        logging.debug("GUEST Session Granted")
    else:
        logging.debug("USER Session Granted")
    return smbClient


def worker(args, target_name, domain, username, password, address, lmhash, nthash, lock):
    target_ip = nslookup.Nslookup(dns_servers=[args.dc_ip]).dns_lookup(target_name).answer
    if len(target_ip) != 0:
        target_ip = target_ip[0]
        try:
            smbClient = init_smb_session(args, target_ip, domain, username, password, address, lmhash, nthash)
            resp = smbClient.listShares()

            for share in resp:
                # SHARE_INFO_1 structure (lmshare.h)
                # https://docs.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_1
                sharename = share['shi1_netname'][:-1]
                sharecomment = share['shi1_remark'][:-1]
                sharetype = share['shi1_type']

                if sharename not in COMMON_SHARES:
                    lock.acquire()
                    if len(sharecomment) != 0:
                        if args.colors:
                            print("[>] Found uncommon share '\x1b[93m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' (comment: '\x1b[95m%s\x1b[0m')" % (sharename, address, sharecomment))
                        else:
                            print("[>] Found uncommon share '%s' on '%s' (comment: '%s')" % (sharename, address, sharecomment))
                    else:
                        if args.colors:
                            print("[>] Found uncommon share '\x1b[93m%s\x1b[0m' on '\x1b[96m%s\x1b[0m'" % (sharename, address))
                        else:
                            print("[>] Found uncommon share '%s' on '%s'" % (sharename, address))
                    d = {
                        "sharename": sharename,
                        "uncpath": "\\".join(['', '', target_ip, sharename, '']),
                        "computer": target_name,
                        "comment": sharecomment,
                        "type": {
                            "stype_value": sharetype,
                            "stype_flags": STYPE_MASK(sharetype)
                        }
                    }
                    f = open(args.output_file, "a")
                    f.write(json.dumps(d) + "\n")
                    f.close()
                    lock.release()
                elif args.debug:
                    if args.colors:
                        print("[>] Skipping common share '\x1b[93m%s\x1b[0m' on '\x1b[96m%s\x1b[0m' (comment: '\x1b[95m%s\x1b[0m')" % (sharename, address, sharecomment))
                    else:
                        print("[>] Skipping common share '%s' on '%s' (comment: '%s')" % (sharename, address, sharecomment))
        except Exception as e:
            print(e)
            # if logging.getLogger().level == logging.DEBUG:
            #     traceback.print_exc()
            #     logging.error(str(e))


if __name__ == '__main__':
    print(version.BANNER)
    args = parse_args()
    init_logger(args)

    auth_lm_hash = ""
    auth_nt_hash = ""
    if args.auth_hashes is not None:
        if ":" in args.auth_hashes:
            auth_lm_hash = args.auth_hashes.split(":")[0]
            auth_nt_hash = args.auth_hashes.split(":")[1]
        else:
            auth_nt_hash = args.auth_hashes

    ldap_server, ldap_session = init_ldap_session(
        args=args,
        domain=args.auth_domain,
        username=args.auth_username,
        password=args.auth_password,
        lmhash=auth_lm_hash,
        nthash=auth_nt_hash
    )

    print("[>] Extracting all computers ...")
    dn = ','.join(["DC=%s" % part for part in args.auth_domain.split('.')])
    computers = get_domain_computers(dn, ldap_server, ldap_session)
    print("[+] Found %d computers." % len(computers.keys()))
    print()

    print("[>] Enumerating shares ...")
    # Overwrite output file
    open(args.output_file, "w").close()
    # Setup thread lock to properly write in the file
    lock = threading.Lock()
    # Waits for all the threads to be completed
    with ThreadPoolExecutor(max_workers=min(args.threads, len(computers.keys()))) as tp:
        for ck in computers.keys():
            computer = computers[ck]
            tp.submit(worker, args, computer['dNSHostName'], args.auth_domain, args.auth_username, args.auth_password, computer['dNSHostName'], auth_lm_hash, auth_nt_hash, lock)
