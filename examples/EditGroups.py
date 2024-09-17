#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2024 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script to change a group on AD, this script let you read if a user is part of a group, add a user to a group or remove a user from a group, the script use ldap to read, write or remove.
# Author:
#   Fabrizzio Bridi (@Fabrizzio53)

import argparse
import logging
import sys

import ldap3
import ssl
import ldapdomaindump
from binascii import unhexlify

from impacket import version
from impacket.examples import logger, utils
from impacket.ldap import ldaptypes
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech



class Groupchanger(object):

    def __init__(self, ldap_server, ldap_session, args):

        self.ldap_server = ldap_server
        self.ldap_session = ldap_session

        self.__action = args.action
        self.__user = args.user
        self.__group = args.group
        self.__group_domain = args.group_domain
        self.__user_domain = args.user_domain

    def domain_to_ldap(self,domain):

        parts = domain.split('.')

        ldap_format = ','.join(['DC=' + part for part in parts])

        return ldap_format

    def run(self):
        
        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None

        if self.__group_domain == None:

            self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

            dn = self.domain_dumper.root

        else:
            
            self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

            dn = self.domain_to_ldap(self.__group_domain)


        print(f"[+] Checking if group {self.__group} is in the domain {dn}!")

        self.ldap_session.search(
            search_base=dn,
            search_filter=f'(&(objectClass=group)(cn={self.__group}))',
            attributes=['member']
        )

        if self.ldap_session.entries:

            print('[+] Group ' + self.__group + ' found at domain ' + dn)

        else:

            print('[-] Error: group' + self.__group + 'not found.')
            sys.exit(1)

        group_dn = self.ldap_session.entries[0].entry_dn
        members = self.ldap_session.entries[0].member

        if self.__user_domain == None:

            dn = self.domain_dumper.root

        else:
            
            dn = self.domain_to_ldap(self.__user_domain)
           
        print(f"[+] Checking if {self.__user} exists in the domain {dn} and if is already part of {self.__group}!")
            
        self.ldap_session.search(
            search_base=dn,
            search_filter=f'(&(objectClass=user)(sAMAccountName={self.__user}))',
            attributes=['distinguishedName']
        )
        
        if self.ldap_session.entries:
            print('[+] User ' + self.__user + ' found at the domain ' + dn)
        else:
            print('[-] Error: user not found.')
            sys.exit(1)

        user_dn = self.ldap_session.entries[0].distinguishedName.value

        if user_dn in members:

            print(f'[+] User {self.__user} is already a member of the group {self.__group}.')

            if self.__action == 'add':

                print(f"[+] Add action was called, since the user is already part of the group nothing got changed!")
                sys.exit(0)

            elif self.__action == 'remove':

                if self.ldap_session.modify(
                    dn=group_dn,
                    changes={'member': [(ldap3.MODIFY_DELETE, [user_dn])]}
                ):
                    print(f'[+] User {self.__user} got deleted from the group {self.__group}.')
                else:
                    print(f'[-] There was an error at deleting user {self.__user} from the group {self.__group} with error: {self.ldap_session.result["description"]}')               

        else:
            
            if self.__action == 'add':

                if self.ldap_session.modify(
                    dn=group_dn,
                    changes={'member': [(ldap3.MODIFY_ADD, [user_dn])]}
                ):
                    print(f'[+] User {self.__user} got added to the group {self.__group} successfully.')
                else:
                    print(f'[-] There was an error at adding user {self.__user} to the group {self.__group} with error: {self.ldap_session.result["description"]}')
            
            elif self.__action == "remove":

                print(f"[+] remove action was called, since the user is not in the group, nothing got changed!")
                sys.exit(0)      

            else:

                print(f"[+] User {self.__user} is not inside the group: {self.__group}.")         


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

def parse_identity(args):
    domain, username, password = utils.parse_credentials(args.identity)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and args.hashes is None and args.no_pass is False and args.aesKey is None:
        from getpass import getpass
        logging.info("No credentials supplied, supply password")
        password = getpass("Password:")

    if args.aesKey is not None:
        args.k = True

    if args.hashes is not None:
        lmhash, nthash = args.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    return domain, username, password, lmhash, nthash

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Add or remove a user from a group that you have control over.')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument('-user', action='store', metavar='username', help='The user that you want to add or remove from a group')
    parser.add_argument('-group', action='store', help='The group you want the user to be added ')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-group_domain', action='store', help='The domain the group is at, usefull when you have trusts and need to add a user to a group from another domain, by default it uses the current domain')
    parser.add_argument('-user_domain', action='store', help='The domain the user is at, usefull when you have trusts and need to add a user to a group from another domain, by default it uses the current domain')


    auth_con = parser.add_argument_group('authentication & connection')
    auth_con.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth_con.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    auth_con.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth_con.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    auth_con.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')

    dacl_parser = parser.add_argument_group("group editor")
    dacl_parser.add_argument('-action', choices=['add', 'remove', 'read'], nargs='?', default='read', help='Action to operate over the group')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()

def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None,
                         TGT=None, TGS=None, useCache=True):
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

    target = 'ldap/%s' % target
    if useCache:
        domain, user, TGT, TGS = CCache.parseFile(domain, user, target)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                    aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                sessionKey)
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

def init_ldap_connection(target, tls_version, args, domain, username, password, lmhash, nthash):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if args.dc_ip is not None:
        connect_to = args.dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if args.k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.aesKey, kdcHost=args.dc_ip)
    elif args.hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session

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

def init_ldap_session(args, domain, username, password, lmhash, nthash):
    
    if args.k:
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

def main():

    print(version.BANNER)

    args = parse_args()
  
    init_logger(args)

    if args.user is None and args.group is None:

        logging.critical('A username and a group to add should be specified!')

        sys.exit(1)

    domain, username, password, lmhash, nthash = parse_identity(args)

    if len(nthash) > 0 and lmhash == "":
        lmhash = "aad3b435b51404eeaad3b435b51404ee"

    try:

        ldap_server, ldap_session = init_ldap_session(args, domain, username, password, lmhash, nthash)

        add_to_group = Groupchanger(ldap_server, ldap_session, args)

        add_to_group.run()

    except Exception as e:

        if logging.getLogger().level == logging.DEBUG:

            import traceback

            traceback.print_exc()

        logging.error(str(e))

if __name__ == '__main__':

    main()
