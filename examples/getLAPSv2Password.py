#!/usr/bin/env python
import argparse
import logging
import sys
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652

from impacket import version
from impacket.examples import logger
from impacket.dcerpc.v5 import transport
from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dpapi_ng import EncryptedPasswordBlob, KeyIdentifier, compute_kek, create_sd, decrypt_plaintext, unwrap_cek
from impacket.smbconnection import SMBConnection, SessionError

class LAPSv2Extract:
    def __init__(self, domain, username, password, lmhash, nthash, dc_ip, do_kerberos, aesKey, target_computer):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__dc_ip = dc_ip
        self.__username = username
        self.__password = password
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = aesKey
        self.__doKerberos = do_kerberos
        self.__targetComputer = None if target_computer == '' else target_computer

        # Create the baseDN
        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

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
        return "%s.%s" % (s.getServerName(), s.getServerDNSDomainName())

    def run(self):
        if self.__dc_ip is not None :
                self.__target = self.__dc_ip
        else:
            self.__target = self.__domain

        if self.__doKerberos:
            logging.debug('Getting machine hostname')
            self.__target = self.getMachineName(self.__target)

        # Connect to LDAP
        logging.debug("Connecting to LDAP")

        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__dc_ip)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                             self.__nthash,
                                             self.__aesKey, kdcHost=self.__dc_ip)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__dc_ip)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                                 self.__nthash,
                                                 self.__aesKey, kdcHost=self.__dc_ip)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use Kerberos "
                                     "authentication instead.")
                else:
                    if self.__dc_ip is not None:
                        logging.critical("If the credentials are valid, check the IP address of DC.")
                raise
        logging.debug("LDAP connected. Getting msLAPS-EncryptedPassword for %s.%s" % (self.__targetComputer, self.__domain))
        
        # Getting msLAPS-EncryptedPassword for target computer
        searchFilter = '(&(objectCategory=computer)(msLAPS-EncryptedPassword=*)'
        if self.__targetComputer is not None:
            searchFilter += '(name=' + self.__targetComputer + ')'
        searchFilter += ')'

        try:
            # Microsoft Active Directory set an hard limit of 1000 entries returned by any search
            paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)

            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['msLAPS-EncryptedPassword', 'msLAPS-Password', 'sAMAccountName'],
                                         searchControls=[paged_search_control])

        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                # We should never reach this code as we use paged search now
                logging.debug('sizeLimitExceeded exception caught, giving up and processing the data received')
                resp = e.getAnswers()
                pass
            else:
                raise

        entries = {}
        
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
                rawEncryptedLAPSBlob = None
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                    if str(attribute['type']) == 'msLAPS-EncryptedPassword':
                        rawEncryptedLAPSBlob = bytes(attribute['vals'][0])
                
                if sAMAccountName is not None and rawEncryptedLAPSBlob is not None:
                    entries[sAMAccountName] = rawEncryptedLAPSBlob
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))
                pass
        
        if len(entries) == 0:
            if self.__targetComputer is not None:
                logging.error("No msLAPS-EncryptedPassword blob returned for %s" % self.__targetComputer)
            else:
                logging.error("No msLAPS-EncryptedPassword blob returned")
            return 
        
        KDSCache = {}

        for sAMAccountName, rawEncryptedLAPSBlob in entries.items():
            # Unpack the encrypted blob to get KeyIdentifier and all the infos
            logging.debug('Unpacking the msLAPS-EncryptedPassword blob for %s' % sAMAccountName)
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
            except Exception as e:
                logging.error('Cannot unpack msLAPS-EncryptedPassword blob due to error %s' % str(e))
                return

            # Check if item is in cache
            if key_id['RootKeyId'] in KDSCache:
                logging.debug("Got KDS from cache")
                gke = KDSCache[key_id['RootKeyId']]
            else:
                # Connect on RPC over TCP to MS-GKDI to call opnum 0 GetKey 
                stringBinding = hept_map(destHost=self.__target, remoteIf=MSRPC_UUID_GKDI, protocol = 'ncacn_ip_tcp')
                rpctransport = transport.DCERPCTransportFactory(stringBinding)
                if hasattr(rpctransport, 'set_credentials'):
                    rpctransport.set_credentials(username=self.__username, password=self.__password, domain=self.__domain, lmhash=self.__lmhash, nthash=self.__nthash)
                if self.__doKerberos:
                    rpctransport.set_kerberos(self.__doKerberos, kdcHost=self.__target)
                if self.__dc_ip is not None:
                    rpctransport.setRemoteHost(self.__dc_ip)
                    rpctransport.setRemoteName(self.__target)

                dce = rpctransport.get_dce_rpc()
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                logging.debug("Connecting to %s" % stringBinding)
                try:
                    dce.connect()
                except Exception as e:
                    logging.error("Something went wrong, check error status => %s" % str(e))
                    return 
                logging.debug("Connected")
                try:
                    dce.bind(MSRPC_UUID_GKDI)
                except Exception as e:
                    logging.error("Something went wrong, check error status => %s" % str(e))
                    return 
                logging.debug("Successfully bound")


                logging.debug("Calling MS-GKDI GetKey")
                resp = GkdiGetKey(dce, target_sd=target_sd, l0=key_id['L0Index'], l1=key_id['L1Index'], l2=key_id['L2Index'], root_key_id=key_id['RootKeyId'])
                logging.debug("Decrypting password")
                # Unpack GroupKeyEnvelope
                gke = GroupKeyEnvelope(b''.join(resp['pbbOut']))
                KDSCache[gke['RootKeyId']] = gke

            kek = compute_kek(gke, key_id)
            logging.debug("KEK:\t%s" % kek)
            enc_content_parameter = bytes(parsed_enveloped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"])
            iv, _ = decoder.decode(enc_content_parameter)
            iv = bytes(iv[0])

            cek = unwrap_cek(kek, bytes(kek_recipient_info['encryptedKey']))
            logging.debug("CEK:\t%s" % cek)
            plaintext = decrypt_plaintext(cek, iv, remaining)
            print("%s:\t%s" % (sAMAccountName, plaintext[:-18].decode('utf-16le')))

if __name__ == '__main__':
    print(version.BANNER)
    parser = argparse.ArgumentParser(add_help = True, description = "Extract LAPSv2 local administration passwords")
    parser.add_argument('target', action='store', help='domain[/username[:password]]')
    
    parser.add_argument('-target-computer', action="store", default='', help='Extract LAPS admin password for the specified computer account name (without $).' 
                                                                                    'If not specified, will dump password for all computers')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command '
                            'line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller.')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True
    
    try:
        lapsv2extract = LAPSv2Extract(domain, username, password, lmhash, nthash, options.dc_ip, options.k, options.aesKey, options.target_computer)
        lapsv2extract.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
