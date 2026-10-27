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
#   DCE/RPC lookup sid brute forcer example
#
# Author:
#   Alberto Solino (@agsolino)
#
# Reference for:
#   DCE/RPC [MS-LSAT]
#

import sys
import logging
import argparse
import codecs

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException


class LSALookupSid:
    KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\lsarpc]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\lsarpc]', 'set_host': True},
        }

    def __init__(self, username='', password='', domain='', port = None,
                 hashes = None, domain_sids = False, use_kerberos = False, maxRid=4000, lookup_domain=None, lookup_names=None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__maxRid = int(maxRid)
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__domain_sids = domain_sids
        self.__lookup_domain = lookup_domain
        self.__lookup_names = lookup_names
        if lookup_names and lookup_domain:
            # Unqualified names default to the -lookup-domain domain
            self.__lookup_names = [n if '\\' in n or '@' in n else '%s\\%s' % (lookup_domain, n) for n in lookup_names]
        self.__doKerberos = use_kerberos
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def dump(self, remoteName, remoteHost):

        logging.info('Brute forcing SIDs at %s' % remoteName)

        stringbinding = self.KNOWN_PROTOCOLS[self.__port]['bindstr'] % remoteName
        logging.info('StringBinding %s'%stringbinding)
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_dport(self.__port)
        rpctransport.set_kerberos(self.__doKerberos)

        if self.KNOWN_PROTOCOLS[self.__port]['set_host']:
            rpctransport.setRemoteHost(remoteHost)

        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

        try:
            self.__bruteForce(rpctransport, self.__maxRid)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.critical(str(e))
            raise

    def __bruteForce(self, rpctransport, maxRid):
        dce = rpctransport.get_dce_rpc()
        entries = []
        dce.connect()

        # Want encryption? Uncomment next line
        # But make SIMULTANEOUS variable <= 100
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

        # Want fragmentation? Uncomment next line
        #dce.set_max_fragment_size(32)

        dce.bind(lsat.MSRPC_UUID_LSAT)
        
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        if self.__lookup_names: # resolve specific names to SIDs and skip the brute force
            try:
                resp = lsat.hLsarLookupNames(dce, policyHandle, self.__lookup_names)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    for name in self.__lookup_names:
                        print("%s: not found" % name)
                    dce.disconnect()
                    return entries
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise
            for name, item in zip(self.__lookup_names, resp['TranslatedSids']['Sids']):
                if item['Use'] == SID_NAME_USE.SidTypeUnknown:
                    print("%s: not found" % name)
                    continue
                domain = resp['ReferencedDomains']['Domains'][item['DomainIndex']]
                sid = domain['Sid'].formatCanonical()
                if item['Use'] != SID_NAME_USE.SidTypeDomain:
                    sid += '-%d' % item['RelativeId']
                print("%s: %s (%s)" % (name, sid, SID_NAME_USE.enumItems(item['Use']).name))
            dce.disconnect()
            return entries

        if self.__lookup_domain: # resolve another domain's SID by name (e.g. a trusted domain)
            try:
                resp = lsat.hLsarLookupNames(dce, policyHandle, (self.__lookup_domain,))
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    raise Exception('Could not resolve domain %s from the target' % self.__lookup_domain)
                raise
            item = resp['TranslatedSids']['Sids'][0]
            if item['Use'] != SID_NAME_USE.SidTypeDomain:
                raise Exception('%s resolved to a %s, not a domain' % (self.__lookup_domain, SID_NAME_USE.enumItems(item['Use']).name))
            domainSid = resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Sid'].formatCanonical()
        elif self.__domain_sids: # get the Domain SID
            resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
            domainSid =  resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
        else: # Get the target host SID
            resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
            domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        logging.info('Domain SID is: %s' % domainSid)

        soFar = 0
        SIMULTANEOUS = 1000
        for j in range(maxRid//SIMULTANEOUS+1):
            if (maxRid - soFar) // SIMULTANEOUS == 0:
                sidsToCheck = (maxRid - soFar) % SIMULTANEOUS
            else: 
                sidsToCheck = SIMULTANEOUS
 
            if sidsToCheck == 0:
                break

            sids = list()
            for i in range(soFar, soFar+sidsToCheck):
                sids.append(domainSid + '-%d' % i)
            try:
                lsat.hLsarLookupSids(dce, policyHandle, sids,lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    soFar += SIMULTANEOUS
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else: 
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    print("%d: %s\\%s (%s)" % (
                    soFar + n, resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'],
                    SID_NAME_USE.enumItems(item['Use']).name))
            soFar += SIMULTANEOUS

        dce.disconnect()

        return entries


# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)
    print(version.BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('maxRid', action='store', default = '4000', nargs='?', help='max Rid to check (default 4000)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-ip', action='store', metavar="ip address", help='IP Address of the target machine. '
                       'If omitted it will use whatever was specified as target. This is useful when target is the '
                       'NetBIOS name and you cannot resolve it')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')
    group.add_argument('-domain-sids', action='store_true', help='Enumerate Domain SIDs (will likely forward requests to the DC)')
    group.add_argument('-lookup-domain', action='store', metavar='DOMAIN', help='Resolve DOMAIN\'s SID through the target and '
                       'enumerate it instead (e.g. a trusted domain; requests are forwarded across the trust)')
    group.add_argument('-lookup-name', action='append', metavar='NAME', help='Resolve NAME (e.g. DOMAIN\\HOST$) to its SID '
                       'instead of brute forcing. Can be repeated. Names without a domain use -lookup-domain if given')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful when proxying through smbrelayx)')
    group.add_argument('-k', action="store_true", 
                        help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.lookup_domain and options.domain_sids:
        parser.error('-lookup-domain and -domain-sids are mutually exclusive')
    if options.lookup_name and options.domain_sids:
        parser.error('-lookup-name cannot be combined with -domain-sids')

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False:
        from getpass import getpass
        password = getpass("Password:")

    if options.target_ip is None:
        options.target_ip = remoteName

    lookup = LSALookupSid(username, password, domain, int(options.port), options.hashes, options.domain_sids, options.k, options.maxRid, options.lookup_domain, options.lookup_name)
    try:
        lookup.dump(remoteName, options.target_ip)
    except:
        pass
