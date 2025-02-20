#!/usr/bin/env python
####################
#
# Copyright (c) 2023 Dirk-jan Mollema (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# Add an SPN to a user/computer account via LDAP
#
####################
import sys
import argparse
import random
import string
import getpass
import os
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from impacket.examples.krbrelayx.utils.kerberos import ldap_kerberos
import ldap3
from ldap3.protocol.microsoft import security_descriptor_control

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

def main():
    parser = argparse.ArgumentParser(description='Add an SPN to a user/computer account')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    parser.add_argument("host", metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to")
    parser.add_argument("-u", "--user", metavar='USERNAME', help="DOMAIN\\username for authentication")
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
    parser.add_argument("-t", "--target", metavar='TARGET', help="Computername or username to target (FQDN or COMPUTER$ name, if unspecified user with -u is target)")
    parser.add_argument("-T", "--target-type", metavar='TARGETTYPE', choices=('samname','hostname','auto'), default='auto', help="Target type (samname or hostname) If unspecified, will assume it's a hostname if there is a . in the name and a SAM name otherwise.")
    parser.add_argument("-s", "--spn", metavar='SPN', help="servicePrincipalName to add (for example: http/host.domain.local or cifs/host.domain.local)")
    parser.add_argument("-r", "--remove", action='store_true', help="Remove the SPN instead of add it")
    parser.add_argument("-c", "--clear", action='store_true', help="Clear, i.e. remove all SPNs")
    parser.add_argument("-q", "--query", action='store_true', help="Show the current target SPNs instead of modifying anything")
    parser.add_argument("-a", "--additional", action='store_true', help="Add the SPN via the msDS-AdditionalDnsHostName attribute")
    parser.add_argument('-k', '--kerberos', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
   
    args = parser.parse_args()

    if not args.query and not args.clear:
        if not args.spn:
            parser.error("-s/--spn is required when not querying (-q/--query) or clearing (--clear)")

    #Prompt for password if not set
    authentication = None
    if not args.user or not '\\' in args.user:
        print_f('Username must include a domain, use: DOMAIN\\username')
        sys.exit(1)
    domain, user = args.user.split('\\', 1)
    if not args.kerberos:
        authentication = NTLM
        sasl_mech = None
        if args.password is None:
            args.password = getpass.getpass()
    else:
        TGT = None
        TGS = None
        try:
            # Hashes
            lmhash, nthash = args.password.split(':')
            assert len(nthash) == 32
            password = ''
        except:
            # Password
            lmhash = ''
            nthash = ''
            password = args.password
        if 'KRB5CCNAME' in os.environ and os.path.exists(os.environ['KRB5CCNAME']):
            domain, user, TGT, TGS = CCache.parseFile(domain, user, 'ldap/%s' % args.host)
        if args.dc_ip is None:
            kdcHost = domain
        else:
            kdcHost = options.dc_ip
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if not TGT and not TGS:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, args.aesKey, kdcHost)
        elif TGT:
            # Has TGT
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']
        if not TGS:
            # Request TGS
            serverName = Principal('ldap/%s' % args.host, type=constants.PrincipalNameType.NT_SRV_INST.value)
            TGS = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
        else:
            # Convert to tuple expected
            TGS = (TGS['KDC_REP'], TGS['cipher'], TGS['sessionKey'], TGS['sessionKey'])
        authentication = SASL
        sasl_mech = KERBEROS

    controls = security_descriptor_control(sdflags=0x04)
    # define the server and the connection
    s = Server(args.host, get_info=ALL)
    print_m('Connecting to host...')
    c = Connection(s, user=args.user, password=args.password, authentication=authentication, sasl_mechanism=sasl_mech)
    print_m('Binding to host')
    # perform the Bind operation
    if authentication == NTLM:
        if not c.bind():
            print_f('Could not bind with specified credentials')
            print_f(c.result)
            sys.exit(1)
    else:
        ldap_kerberos(domain, kdcHost, None, userName, c, args.host, TGS)
    print_o('Bind OK')

    if args.target:
        targetuser = args.target
    else:
        targetuser = args.user.split('\\')[1]

    if ('.' in targetuser and args.target_type != 'samname') or args.target_type == 'hostname':
        if args.target_type == 'auto':
            print_m('Assuming target is a hostname. If this is incorrect use --target-type samname')
        search = '(dnsHostName=%s)' % targetuser
    else:
        search = '(SAMAccountName=%s)' % targetuser
    c.search(s.info.other['defaultNamingContext'][0], search, controls=controls, attributes=['SAMAccountName', 'servicePrincipalName', 'dnsHostName', 'msds-additionaldnshostname'])

    try:
        targetobject = c.entries[0]
        print_o('Found modification target')
    except IndexError:
        print_f('Target not found!')
        return

    if args.remove:
        operation = ldap3.MODIFY_DELETE
    elif args.clear:
        operation = ldap3.MODIFY_REPLACE
    else:
        operation = ldap3.MODIFY_ADD

    if args.query:
        # If we only want to query it
        print(targetobject)
        return


    if not args.additional:
        if args.clear:
            print_o('Printing object before clearing')
            print(targetobject)
            c.modify(targetobject.entry_dn, {'servicePrincipalName':[(operation, [])]})
        else:
            c.modify(targetobject.entry_dn, {'servicePrincipalName':[(operation, [args.spn])]})
    else:
        try:
            host = args.spn.split('/')[1]
        except IndexError:
            # Assume this is the hostname
            host = args.spn
        c.modify(targetobject.entry_dn, {'msds-additionaldnshostname':[(operation, [host])]})

    if c.result['result'] == 0:
        print_o('SPN Modified successfully')
    else:
        if c.result['result'] == 50:
            print_f('Could not modify object, the server reports insufficient rights: %s' % c.result['message'])
        elif c.result['result'] == 19:
            print_f('Could not modify object, the server reports a constrained violation')
            if args.additional:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs ending on the domain FQDN)')
            else:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs matching the hostname)')
                print_f('To add any SPN in the current domain, use --additional to add the SPN via the msDS-AdditionalDnsHostName attribute')
        else:
            print_f('The server returned an error: %s' % c.result['message'])


if __name__ == '__main__':
    main()
