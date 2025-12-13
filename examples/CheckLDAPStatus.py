#!/usr/bin/env python
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
#   Check LDAP signing status and LDAPS channel binding status.
#   First, the script use the given domain controller IP and domain 
#   name to resolve all the domain controllers. Then the checks are
#   performed against all domain controllers.
#
# Author:
#   Thomas Seigneuret (@zblurx)

import argparse
import logging
import sys
from dns.resolver import Resolver
from OpenSSL.SSL import SysCallError
from impacket import version
from impacket.examples import logger
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError

class CheckLDAP:
    def __init__(self, domain, dc_ip, timeout):
        self.domain = domain
        self.dc_ip = dc_ip
        self.timeout = timeout

    def list_dc(self):
        dc_list = []
        resolver = Resolver()
        resolver.timeout = self.timeout
        resolver.nameservers = [self.dc_ip]
        dc_query = resolver.resolve(
            f"_ldap._tcp.dc._msdcs.{self.domain}", 'SRV', tcp=True)
        for dc in dc_query:
            dc_list.append(str(dc.target).rstrip("."))
        return dc_list    
        
    def run(self):
        dc_list = self.list_dc()
        logging.info(f"Found {len(dc_list)} domain controller(s) in {self.domain}")
        for dc in dc_list:
            signing_required = self.check_ldap_signing(dc)
            channel_binding_status = self.check_ldaps_cbt(dc)
            print(f"Hostname: {dc}\n\t> LDAP Signing Required: {signing_required}\n\t> LDAPS Channel Binding Status: {channel_binding_status}")

    def check_ldaps_cbt(self, hostname):
        cbt_status = "Never"
        ldap_url = f"ldaps://{hostname}"
        try:
            ldap_connection = LDAPConnection(url=ldap_url)
            ldap_connection.channel_binding_value = None
            ldap_connection.login(user=" ", domain=self.domain)
        except LDAPSessionError as e:
            if str(e).find("data 80090346") >= 0:
                cbt_status = "Always"  # CBT is Required
            # Login failed (wrong credentials). test if we get an error with an existing, but wrong CBT -> When supported
            elif str(e).find("data 52e") >= 0:
                ldap_connection = LDAPConnection(url=ldap_url)
                new_cbv = bytearray(ldap_connection.channel_binding_value)
                new_cbv[15] = (new_cbv[3] + 1) % 256
                ldap_connection.channel_binding_value = bytes(new_cbv)
                try:
                    ldap_connection.login(user=" ", domain=self.domain)
                except LDAPSessionError as e:
                    if str(e).find("data 80090346") >= 0:
                        logging.debug(f"LDAPS channel binding is set to 'When Supported' on host {hostname}")
                        cbt_status = "When Supported"  # CBT is When Supported
            else:
                logging.debug(f"LDAPSessionError while checking for channel binding requirements (likely NTLM disabled): {e!s}")
        except SysCallError as e:
            logging.debug(f"Received SysCallError when trying to enumerate channel binding support: {e!s}")
            if e.args[1] in ["ECONNRESET", "WSAECONNRESET", "Unexpected EOF"]:
                cbt_status = "No TLS cert"
            else:
                raise
        return cbt_status

    def check_ldap_signing(self, hostname):
        signing_required = False
        ldap_url = f"ldap://{hostname}"
        try:
            ldap_connection = LDAPConnection(url=ldap_url, signing=False)
            ldap_connection.login(domain=self.domain)
            logging.debug(f"LDAP signing is not enforced on {hostname}")
        except LDAPSessionError as e:
            if str(e).find("strongerAuthRequired") >= 0:
                logging.debug(f"LDAP signing is enforced on {hostname}")
                signing_required = True
            else:
                logging.debug(f"LDAPSessionError while checking for signing requirements (likely NTLM disabled): {e!s}")
        return signing_required

if __name__ == '__main__':

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "LDAP signing and channel binding enumeration utility.")
    parser.add_argument('-dc-ip', required=True, action='store', metavar="ip address", help='IP Address of a domain controller or a DNS resolver for the domain.')
    parser.add_argument('-domain', required=True, action='store', help='<domain name>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-timeout', action='store', type=int, default=15, help='DNS timeout')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    logger.init(options.ts, options.debug)

    try:
        dumper = CheckLDAP(options.domain, options.dc_ip, options.timeout)
        logging.info(f"Targeted domain: {options.domain}")
        dumper.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
