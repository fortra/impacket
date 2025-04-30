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
#   Utility and helper functions for the example scripts
#
# Author:
#   Martin Gallo (@martingalloar)
#
import re


# Regular expression to parse target information
target_regex = re.compile(r"(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)")


# Regular expression to parse credentials information
credential_regex = re.compile(r"(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?")


def parse_target(target):
    """ Helper function to parse target information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>@HOSTNAME

    :param target: target to parse
    :type target: string

    :return: tuple of domain, username, password and remote name or IP address
    :rtype: (string, string, string, string)
    """
    domain, username, password, remote_name = target_regex.match(target).groups('')

    # In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    return domain, username, password, remote_name


def parse_credentials(credentials):
    """ Helper function to parse credentials information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>

    :param credentials: credentials to parse
    :type credentials: string

    :return: tuple of domain, username and password
    :rtype: (string, string, string)
    """
    domain, username, password = credential_regex.match(credentials).groups('')

    return domain, username, password

# ----------

from impacket.smbconnection import SMBConnection, SessionError
import ldap3
import ssl
from binascii import unhexlify
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

def _get_machine_name(machine, fqdn=False):
    s = SMBConnection(machine, machine)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % machine)
    else:
        s.logoff()

    if fqdn:
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())
    return s.getServerName()

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

    target = 'ldap/%s' % target
    if useCache:
        domain, user, TGT, TGS = CCache.parseFile(domain, user, target)

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
        serverName = Principal(target, type=constants.PrincipalNameType.NT_SRV_INST.value)
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
    now = datetime.datetime.now(datetime.timezone.utc)

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

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData())

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

def _init_ldap_connection(target, tls_version, domain, username, password, lmhash, nthash, k, dc_ip, aesKey):
    user = '%s\\%s' % (domain, username)
    connect_to = target
    if dc_ip is not None:
        connect_to = dc_ip
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(connect_to, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    if k:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, aesKey, kdcHost=dc_ip)
    elif lmhash == '' and nthash == '':
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session

def init_ldap_session(domain, username, password, lmhash, nthash, k, dc_ip, aesKey, use_ldaps):
    """
        k           (bool)  : use Kerberos authentication
        dc_ip       (string): ip of the domain controller
        use_ldaps   (boold) : SSL Ldap or Ldap
    """
    if k:
        if dc_ip is not None:
            target = _get_machine_name(dc_ip)
        else:
            target = _get_machine_name(domain)
    else:
        if dc_ip is not None:
            target = dc_ip
        else:
            target = domain

    if use_ldaps is True:
        try:
            return _init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, domain, username, password, lmhash, nthash, k, dc_ip, aesKey)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return _init_ldap_connection(target, ssl.PROTOCOL_TLSv1, domain, username, password, lmhash, nthash, k, dc_ip, aesKey)
    else:
        return _init_ldap_connection(target, None, domain, username, password, lmhash, nthash, k, dc_ip, aesKey)

# ----------

from impacket.ldap import ldap
import logging
def ldap_login(target, base_dn, kdc_ip, kdc_host, do_kerberos, username, password, domain, lmhash, nthash, aeskey, ldaps_flag=False, target_domain=None, fqdn=False):
    if kdc_host is not None and (target_domain is None or domain == target_domain):
        target = kdc_host
    else:
        if kdc_ip is not None and (target_domain is None or domain == target_domain):
            target = kdc_ip
        else:
            if target_domain is not None:
                target = target_domain
            else:
                target = domain

        if do_kerberos:
            logging.info('Getting machine hostname')
            target = _get_machine_name(target, fqdn)
    
    # Added ldaps flag & placed check for ldaps if flag is enabled.
    url = 'ldaps://%s' if ldaps_flag else 'ldap://%s'

    # Connect to LDAP
    try:
        ldapConnection = ldap.LDAPConnection(url % target, base_dn, kdc_ip)
        if do_kerberos is not True:
            ldapConnection.login(username, password, domain, lmhash, nthash)
        else:
            ldapConnection.kerberosLogin(username, password, domain, lmhash, nthash, aeskey, kdcHost=kdc_ip)
    except ldap.LDAPSessionError as e:
        if str(e).find('strongerAuthRequired') >= 0:
            # We need to try SSL
            ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, base_dn, kdc_ip)
            if do_kerberos is not True:
                ldapConnection.login(username, password, domain, lmhash, nthash)
            else:
                ldapConnection.kerberosLogin(username, password, domain, lmhash, nthash, aeskey, kdcHost=kdc_ip)
        else:
            if str(e).find('NTLMAuthNegotiate') >= 0:
                logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos authentication instead.")
            else:
                if kdc_ip is not None and kdc_host is not None:
                    logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They must match exactly each other.")
            raise
    return ldapConnection

# ----------

EMPTY_LM_HASH = 'AAD3B435B51404EEAAD3B435B51404EE'
def parse_identity(credentials, hashes=None, no_pass=False, aesKey=None, k=False, getpass_msg='Password:'):
    domain, username, password = parse_credentials(credentials)

    if domain is None:
        domain = ''

    if password == '' and username != '' and hashes is None and no_pass is False and aesKey is None:
        from getpass import getpass
        password = getpass(getpass_msg)

    if aesKey is not None:
        k = True

    lmhash = ''
    nthash = ''
    if hashes is not None:
        lmhash, nthash = hashes.split(':')
        if lmhash == '':
            lmhash = EMPTY_LM_HASH

    return domain, username, password, lmhash, nthash, k
