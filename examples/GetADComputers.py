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
#   This script  is inspired from Alberto Solino's -> imacket-GetAdUsers. 
#   This script will make a LDAP query to DC and gather information about all the COMPUTERS present in DC.
#   Also, has the capablity of resolving the IP addresses of the idenitifed hosts by making a DNS query of A record to the DC.    
#
# Inspired from author:
#   Alberto Solino (@agsolino)
#
# Author:
#   Fowz Masood (https://www.linkedin.com/in/f-masood/)
#   Please let me know of any improvements / suggestions or bugs. 
#
#
# Reference for:
#   LDAP
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import logging
import sys
import dns.resolver
from datetime import datetime

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection, SessionError


class GetADComputers:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        #[!] in this script the value of -dc-ip option is self.__kdcIP and the value of -dc-host option is self.__kdcHost
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcPort = cmdLineOptions.dc_port
        self.__kdcHost = cmdLineOptions.dc_host
        self.__requestUser = cmdLineOptions.user
        self.__resolveIP = cmdLineOptions.resolveIP
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        # Let's calculate the header and format
        if self.__resolveIP : #resolveIP flag is used, we will try to resolve the IP address
            self.__header = ["SAM AcctName", "DNS Hostname", "OS Version", "OS", "IPAddress"]
            # Since we won't process all rows at once, this will be fixed lengths
            self.__colLen = [15, 35, 15, 35, 20]
            self.__outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)])

        else:
            self.__header = ["SAM AcctName", "DNS Hostname", "OS Version", "OS"]
            # Since we won't process all rows at once, this will be fixed lengths
            self.__colLen = [15, 35, 15, 20]
            self.__outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(self.__colLen)])

 

    def getMachineName(self, target):
        try:
            s = SMBConnection(target, target)
            s.login('', '')
        except OSError as e:
            if str(e).find('timed out') > 0:
                raise Exception('The connection is timed out. Probably 445/TCP port is closed. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except SessionError as e:
            if str(e).find('STATUS_NOT_SUPPORTED') > 0:
                raise Exception('The SMB request is not supported. Probably NTLM is disabled. Try to specify '
                                'corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            else:
                raise
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % target)
        else:
            s.logoff()
        return s.getServerName()

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def processRecord(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        sAMAccountName = ''
        dNSHostName = ''
        operatingSystem = ''
        operatingSystemVersion = ''
        try:

            if(self.__resolveIP): #will resolve the IP address
                resolvedIPAddress=''
                resolveIP = dns.resolver.Resolver()
                dns.resolver.default_resolver = dns.resolver.Resolver(configure=False) #Dont want to use the default DNS in /etc/resolv.conf
                dns.resolver.default_resolver.nameservers = [self.__kdcIP] #converting DCIP from STRING to LIST
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is True:
                            # sAMAccountName
                            sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                    if str(attribute['type']) == 'dNSHostName':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            # dNSHostName + IP resolve
                            dNSHostName = attribute['vals'][0].asOctets().decode('utf-8')
                            try:
                                answers=dns.resolver.resolve(attribute['vals'][0].asOctets().decode('utf-8'),'A',tcp=True)
                                for rdata in answers:
                                    resolvedIPAddress = rdata.address
                            except:
                                    resolvedIPAddress = '<unable to resolve>'
                    if str(attribute['type']) == 'operatingSystem':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            # operatingSystem
                            operatingSystem = attribute['vals'][0].asOctets().decode('utf-8')
                    if str(attribute['type']) == 'operatingSystemVersion':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            # operatingSystemVersion
                            operatingSystemVersion = attribute['vals'][0].asOctets().decode('utf-8')
                print((self.__outputFormat.format(*[sAMAccountName, dNSHostName, operatingSystemVersion,operatingSystem,resolvedIPAddress])))

            else: #won't resolve the IP address
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is True:
                            # sAMAccountName
                            sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                    if str(attribute['type']) == 'dNSHostName':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            # dNSHostName
                            dNSHostName = attribute['vals'][0].asOctets().decode('utf-8')
                    if str(attribute['type']) == 'operatingSystem':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            # operatingSystem
                            operatingSystem = attribute['vals'][0].asOctets().decode('utf-8')
                    if str(attribute['type']) == 'operatingSystemVersion':
                        if attribute['vals'][0].asOctets().decode('utf-8').endswith('$') is False:
                            # operatingSystemVersion
                            operatingSystemVersion = attribute['vals'][0].asOctets().decode('utf-8')
                print((self.__outputFormat.format(*[sAMAccountName, dNSHostName, operatingSystemVersion,operatingSystem])))
        
 

        except Exception as e:
            logging.debug("Exception", exc_info=True)
            logging.error('Skipping item, cannot process due to error %s' % str(e))
            pass

    def run(self):
        if self.__kdcHost is not None:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__domain

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                self.__target = self.getMachineName(self.__target)

     
        # Connect to LDAP
        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s:%s' % (self.__target, self.__kdcPort), self.baseDN, self.__kdcIP, self.__kdcPort)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s:%s' % (self.__target, self.__kdcPort), self.baseDN, self.__kdcIP, self.__kdcPort)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                     "authentication instead.")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical("If the credentials are valid, check the hostname and IP address of KDC. They "
                                         "must match exactly each other.")
                raise

        logging.info('Querying %s for information about domain.' % self.__target)
        # Print header
        print((self.__outputFormat.format(*self.__header)))
        print(('  '.join(['-' * itemLen for itemLen in self.__colLen])))
	
        # Building the search filter
        #searchFilter = '(objectCategory=computer)'
        searchFilter = '(&(objectCategory=computer)(objectClass=computer))'

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            sc = ldap.SimplePagedResultsControl(size=100)
            
            ldapConnection.search(searchFilter=searchFilter,attributes=['sAMAccountName','dNSHostName','operatingSystem','operatingSystemVersion'],sizeLimit=0, searchControls = [sc], perRecordCallback=self.processRecord)
            
        except ldap.LDAPSearchError:
                raise

        ldapConnection.close()

# Process command-line arguments.
if __name__ == '__main__':
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Queries target domain for computer data")

    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-user', action='store', metavar='username', help='Requests data for specific user ')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-resolveIP', action='store_true',  help='Tries to resolve the IP address of computer objects, by performing the nslookup on the DC.')
    
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter')

    group.add_argument('-dc-port', action='store', metavar='port', help='Port of the domain controller. '
																		'Port used to communicate with the dc, instead of the default port')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')

    


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    try:
        executer = GetADComputers(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
