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
#   This script will gather data about the domain's computers and their LAPS/LAPSv2 passwords.
#     Initial formatting for this tool came from the GetADUsers.py example script.
#
# Author(s):
#   Thomas Seigneuret (@zblurx)
#   Tyler Booth (@dru1d-foofus)
#
# Reference for:
#   LDAP
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from datetime import datetime
from impacket import version
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dpapi_ng import EncryptedPasswordBlob, KeyIdentifier, compute_kek, create_sd, decrypt_plaintext, unwrap_cek
from impacket.examples import logger
from impacket.examples.utils import parse_identity, ldap_login
from impacket.ldap import ldap, ldapasn1
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652
import argparse
import json
import logging
import sys

class GetLAPSPassword:
    @staticmethod
    def printTable(items, header, outputfile):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))
        for row in items:
                print(outputFormat.format(*row))
        
        if outputfile:
            with open(outputfile, 'w') as file:
                outputFormat_file = '\t'.join(['{%d:%ds}' % (num, width) for num, width in enumerate(colLen)]) # Added tab delimited output for files
                file.write(outputFormat_file.format(*header) + "\n")
                for row in items:
                    file.write((outputFormat_file.format(*row)).strip() + "\n") # Removed extraneous field to clean up output saved to a file

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
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__targetComputer = cmdLineOptions.computer
        self.__outputFile = cmdLineOptions.outputfile
        self.__ldaps_flag = cmdLineOptions.ldaps_flag
        self.__KDSCache = {}

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

    def getLAPSv2Decrypt(self, rawEncryptedLAPSBlob):
        try:
            encryptedLAPSBlob = EncryptedPasswordBlob(rawEncryptedLAPSBlob)
            parsed_cms_data, remaining = decoder.decode(encryptedLAPSBlob['Blob'], asn1Spec=rfc5652.ContentInfo())
            enveloped_data_blob = parsed_cms_data['content']
            parsed_enveloped_data, _ = decoder.decode(enveloped_data_blob, asn1Spec=rfc5652.EnvelopedData())
            recipient_infos = parsed_enveloped_data['recipientInfos']
            kek_recipient_info = recipient_infos[0]['kekri']
            kek_identifier = kek_recipient_info['kekid'] 
            key_id = KeyIdentifier(bytes(kek_identifier['keyIdentifier']))
            tmp,_ = decoder.decode(kek_identifier['other']['keyAttr'])
            sid = tmp['field-1'][0][0][1].asOctets().decode("utf-8") 
            target_sd = create_sd(sid)
            laps_enabled = True
        except Exception as e:
            logging.error('Cannot unpack msLAPS-EncryptedPassword blob due to error %s' % str(e))
        # Check if item is in cache
        if key_id['RootKeyId'] in self.__KDSCache:
            gke = self.__KDSCache[key_id['RootKeyId']]
        else:
            # Connect on RPC over TCP to MS-GKDI to call opnum 0 GetKey 
            stringBinding = hept_map(destHost=self.__target, remoteIf=MSRPC_UUID_GKDI, protocol = 'ncacn_ip_tcp')
            rpctransport = transport.DCERPCTransportFactory(stringBinding)
            if hasattr(rpctransport, 'set_credentials'):
                rpctransport.set_credentials(username=self.__username, password=self.__password, domain=self.__domain, lmhash=self.__lmhash, nthash=self.__nthash)
            if self.__doKerberos:
                rpctransport.set_kerberos(self.__doKerberos, kdcHost=self.__target)
            if self.__kdcIP is not None:
                rpctransport.setRemoteHost(self.__kdcIP)
                rpctransport.setRemoteName(self.__target)

            dce = rpctransport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            logging.debug("Connecting to %s" % stringBinding)
            try:
                dce.connect()
            except Exception as e:
                logging.error("Something went wrong, check error status => %s" % str(e))
                return laps_enabled
            logging.debug("Connected")
            try:
                dce.bind(MSRPC_UUID_GKDI)
            except Exception as e:
                logging.error("Something went wrong, check error status => %s" % str(e))
                return laps_enabled
            logging.debug("Successfully bound")


            logging.debug("Calling MS-GKDI GetKey")
            resp = GkdiGetKey(dce, target_sd=target_sd, l0=key_id['L0Index'], l1=key_id['L1Index'], l2=key_id['L2Index'], root_key_id=key_id['RootKeyId'])
            # Unpack GroupKeyEnvelope
            gke = GroupKeyEnvelope(b''.join(resp['pbbOut']))
        self.__KDSCache[gke['RootKeyId']] = gke

        kek = compute_kek(gke, key_id)
        enc_content_parameter = bytes(parsed_enveloped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"])
        iv, _ = decoder.decode(enc_content_parameter)
        iv = bytes(iv[0])
        
        cek = unwrap_cek(kek, bytes(kek_recipient_info['encryptedKey']))
        return decrypt_plaintext(cek, iv, remaining)

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def run(self):
        # Connect to LDAP
        ldapConnection = ldap_login(self.__target, self.baseDN, self.__kdcIP, self.__kdcHost, self.__doKerberos, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__ldaps_flag)
        # updating "self.__target" as it may have changed in the ldap_login processing
        self.__target = ldapConnection._dstHost

        # Building the search filter
        searchFilter = "(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))"  # Default search filter value
        if self.__targetComputer is not None:
            searchFilter += '(name=' + self.__targetComputer + ')'
        searchFilter += ")"

        try:
            # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
            paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)

            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['msLAPS-EncryptedPassword', 'msLAPS-PasswordExpirationTime', 'msLAPS-Password', 'sAMAccountName', \
                                         'ms-Mcs-AdmPwdExpirationTime', 'ms-MCS-AdmPwd'],
                                         searchControls=[paged_search_control])

        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                # We should never reach this code as we use paged search now
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                resp = e.getAnswers()
                pass
            else:
                raise

        entries = []
        
        logging.debug('Total of records returned %d' % len(resp))

        if len(resp) == 0:
            if self.__targetComputer is not None:
                logging.error('%s$ not found in LDAP.' % self.__targetComputer)
            else:
                logging.error("No valid entry in LDAP")
            return 
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            try:
                sAMAccountName = None
                lapsPasswordExpiration = None
                lapsUsername = None
                lapsPassword = None
                lapsv2 = False
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                    if str(attribute['type']) == 'msLAPS-EncryptedPassword':
                        lapsv2 = True
                        plaintext = self.getLAPSv2Decrypt(bytes(attribute['vals'][0]))
                        r = json.loads(plaintext[:-18].decode('utf-16le'))
                        # timestamp = r["t"]
                        lapsUsername = r["n"]
                        lapsPassword = r["p"]
                    elif str(attribute['type']) == 'ms-Mcs-AdmPwdExpirationTime' or str(attribute['type']) == 'msLAPS-PasswordExpirationTime':
                        if str(attribute['vals'][0]) != '0':
                            lapsPasswordExpiration = datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))).strftime('%Y-%m-%d %H:%M:%S')
                    elif str(attribute['type']) == 'ms-Mcs-AdmPwd':
                        lapsPassword = attribute['vals'][0].asOctets().decode('utf-8')
                if sAMAccountName is not None and lapsPassword is not None:
                    entry = [sAMAccountName,lapsUsername, lapsPassword, lapsPasswordExpiration, str(lapsv2)]
                    entry = [element if element is not None else 'N/A' for element in entry]
                    entries.append(entry)
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass

        if len(entries) == 0:
            if self.__targetComputer is not None:
                logging.error("No LAPS data returned for %s" % self.__targetComputer)
            else:
                logging.error("No LAPS data returned")
            return 
        
        self.printTable(entries,['Host','LAPS Username','LAPS Password','LAPS Password Expiration', 'LAPSv2'], self.__outputFile)

# Process command-line arguments.
if __name__ == '__main__':
    print((version.BANNER))

    parser = argparse.ArgumentParser(add_help = True, description = "Extract LAPS passwords from LDAP")

    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    parser.add_argument('-computer', action='store', metavar='computername', help='Target a specific computer by its name')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-outputfile', '-o', action='store', help='Outputs to a file.')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CcnAME) based on target parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller. If '
                                                                              'ommited it use the domain part (FQDN) '
                                                                              'specified in the target parameter')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    
    group.add_argument('-ldaps', dest='ldaps_flag', action="store_true", help='Enable LDAPS (LDAP over SSL). '
                                                                                'Required when querying a Windows Server 2025'
                                                                                'domain controller with LDAPS enforced.')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts, options.debug)

    domain, username, password, _, _, options.k = parse_identity(options.target, options.hashes, options.no_pass, options.aesKey, options.k)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    try:
        executer = GetLAPSPassword(username, password, domain, options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))