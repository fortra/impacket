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
#   Example for using the DPAPI/Vault structures to unlock Windows Secrets.
#
# Author:
#   Alberto Solino (@agsolino)
#
# Examples:
#
#   You can unlock masterkeys, credentials and vaults. For the three, you will specify the file name (using -file for
#   masterkeys and credentials, and -vpol and -vcrd for vaults).
#   If no other parameter is sent, the contents of these resource will be shown, with their encrypted data as well.
#   If you specify a -key blob (in the form of '0xabcdef...') that key will be used to decrypt the contents.
#   In the case of vaults, you might need to also provide the user's sid (and the user password will be asked).
#   For system secrets, instead of a password you will need to specify the system and security hives.
#
# References:
#   All of the work done by these guys. I just adapted their work to my needs.
#   - https://www.passcape.com/index.php?section=docsys&cmd=details&id=28
#   - https://github.com/jordanbtucker/dpapick
#   - https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials (and everything else Ben did )
#   - http://blog.digital-forensics.it/2016/01/windows-revaulting.html
#   - https://www.passcape.com/windows_password_recovery_vault_explorer
#   - https://www.passcape.com/windows_password_recovery_dpapi_master_key
#

from __future__ import division
from __future__ import print_function

import struct
import argparse
import logging
import sys
from six import b
from binascii import unhexlify, hexlify
from hashlib import pbkdf2_hmac

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import HMAC, SHA1, MD4
from impacket.uuid import bin_to_string
from impacket import crypto
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import lsad
from impacket.dcerpc.v5 import bkrp
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.examples.secretsdump import LocalOperations, LSASecrets
from impacket.structure import hexdump
from impacket.dpapi import MasterKeyFile, MasterKey, CredHist, DomainKey, CredentialFile, DPAPI_BLOB, \
    CREDENTIAL_BLOB, VAULT_VCRD, VAULT_VPOL, VAULT_KNOWN_SCHEMAS, VAULT_VPOL_KEYS, P_BACKUP_KEY, PREFERRED_BACKUP_KEY, \
    PVK_FILE_HDR, PRIVATE_KEY_BLOB, privatekeyblob_to_pkcs1, DPAPI_DOMAIN_RSA_MASTER_KEY


class DPAPI:
    def __init__(self, options):
        self.options = options
        self.dpapiSystem = {}
        pass

    def getDPAPI_SYSTEM(self,secretType, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            machineKey = machineKey.split(':')[1]
            userKey = userKey.split(':')[1]
            self.dpapiSystem['MachineKey'] = unhexlify(machineKey[2:])
            self.dpapiSystem['UserKey'] = unhexlify(userKey[2:])

    def getLSA(self):
        localOperations = LocalOperations(self.options.system)
        bootKey = localOperations.getBootKey()

        lsaSecrets = LSASecrets(self.options.security, bootKey, None, isRemote=False, history=False, perSecretCallback = self.getDPAPI_SYSTEM)

        lsaSecrets.dumpSecrets()

        # Did we get the values we wanted?
        if 'MachineKey' not in self.dpapiSystem or 'UserKey' not in self.dpapiSystem:
            logging.error('Cannot grab MachineKey/UserKey from LSA, aborting...')
            sys.exit(1)



    def deriveKeysFromUser(self, sid, password):
        # Will generate two keys, one with SHA1 and another with MD4
        key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
        key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
        # For Protected users
        tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
        tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
        key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

        return key1, key2, key3

    def deriveKeysFromUserkey(self, sid, pwdhash):
        if len(pwdhash) == 20:
            # SHA1
            key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
            key2 = None
        else:
            # Assume MD4
            key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
            # For Protected users
            tmpKey = pbkdf2_hmac('sha256', pwdhash, sid.encode('utf-16le'), 10000)
            tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
            key2 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

        return key1, key2

    def run(self):
        if self.options.action.upper() == 'MASTERKEY':
            fp = open(options.file, 'rb')
            data = fp.read()
            mkf= MasterKeyFile(data)
            mkf.dump()
            data = data[len(mkf):]

            if mkf['MasterKeyLen'] > 0:
                mk = MasterKey(data[:mkf['MasterKeyLen']])
                data = data[len(mk):]

            if mkf['BackupKeyLen'] > 0:
                bkmk = MasterKey(data[:mkf['BackupKeyLen']])
                data = data[len(bkmk):]

            if mkf['CredHistLen'] > 0:
                ch = CredHist(data[:mkf['CredHistLen']])
                data = data[len(ch):]

            if mkf['DomainKeyLen'] > 0:
                dk = DomainKey(data[:mkf['DomainKeyLen']])
                data = data[len(dk):]

            if self.options.system and self.options.security and self.options.sid is None:
                # We have hives, let's try to decrypt with them
                self.getLSA()
                decryptedKey = mk.decrypt(self.dpapiSystem['UserKey'])
                if decryptedKey:
                    print('Decrypted key with UserKey')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
                decryptedKey = mk.decrypt(self.dpapiSystem['MachineKey'])
                if decryptedKey:
                    print('Decrypted key with MachineKey')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
                decryptedKey = bkmk.decrypt(self.dpapiSystem['UserKey'])
                if decryptedKey:
                    print('Decrypted Backup key with UserKey')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
                decryptedKey = bkmk.decrypt(self.dpapiSystem['MachineKey'])
                if decryptedKey:
                    print('Decrypted Backup key with MachineKey')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
            elif self.options.system and self.options.security:
                # Use SID + hash
                # We have hives, let's try to decrypt with them
                self.getLSA()
                key1, key2 = self.deriveKeysFromUserkey(self.options.sid, self.dpapiSystem['UserKey'])
                decryptedKey = mk.decrypt(key1)
                if decryptedKey:
                    print('Decrypted key with UserKey + SID')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
                decryptedKey = bkmk.decrypt(key1)
                if decryptedKey:
                    print('Decrypted Backup key with UserKey + SID')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
                decryptedKey = mk.decrypt(key2)
                if decryptedKey:
                    print('Decrypted key with UserKey + SID')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
                decryptedKey = bkmk.decrypt(key2)
                if decryptedKey:
                    print('Decrypted Backup key with UserKey + SID')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
            elif self.options.key and self.options.sid:
                key = unhexlify(self.options.key[2:])
                key1, key2 = self.deriveKeysFromUserkey(self.options.sid, key)
                decryptedKey = mk.decrypt(key1)
                if decryptedKey:
                    print('Decrypted key with key provided + SID')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
                decryptedKey = mk.decrypt(key2)
                if decryptedKey:
                    print('Decrypted key with key provided + SID')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return
            elif self.options.key:
                key = unhexlify(self.options.key[2:])
                decryptedKey = mk.decrypt(key)
                if decryptedKey:
                    print('Decrypted key with key provided')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return

            elif self.options.pvk and dk:
                pvkfile = open(self.options.pvk, 'rb').read()
                key = PRIVATE_KEY_BLOB(pvkfile[len(PVK_FILE_HDR()):])
                private = privatekeyblob_to_pkcs1(key)
                cipher = PKCS1_v1_5.new(private)

                decryptedKey = cipher.decrypt(dk['SecretData'][::-1], None)
                if decryptedKey:
                    domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey)
                    key = domain_master_key['buffer'][:domain_master_key['cbMasterKey']]
                    print('Decrypted key with domain backup key provided')
                    print('Decrypted key: 0x%s' % hexlify(key).decode('latin-1'))
                return

            elif self.options.sid and self.options.key is None:
                # Do we have a password?
                if self.options.password is None:
                    # Nope let's ask it
                    from getpass import getpass
                    password = getpass("Password:")
                else:
                    password = options.password
                key1, key2, key3 = self.deriveKeysFromUser(self.options.sid, password)

                # if mkf['flags'] & 4 ? SHA1 : MD4
                decryptedKey = mk.decrypt(key3)
                if decryptedKey:
                    print('Decrypted key with User Key (MD4 protected)')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return

                decryptedKey = mk.decrypt(key2)
                if decryptedKey:
                    print('Decrypted key with User Key (MD4)')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return

                decryptedKey = mk.decrypt(key1)
                if decryptedKey:
                    print('Decrypted key with User Key (SHA1)')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return

                decryptedKey = bkmk.decrypt(key3)
                if decryptedKey:
                    print('Decrypted Backup key with User Key (MD4 protected)')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return

                decryptedKey = bkmk.decrypt(key2)
                if decryptedKey:
                    print('Decrypted Backup key with User Key (MD4)')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return

                decryptedKey = bkmk.decrypt(key1)
                if decryptedKey:
                    print('Decrypted Backup key with User Key (SHA1)')
                    print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
                    return

            elif self.options.target is not None:
                domain, username, password, remoteName = parse_target(self.options.target)

                if domain is None:
                    domain = ''

                if password == '' and username != '' and self.options.hashes is None and self.options.no_pass is False and self.options.aesKey is None:
                    from getpass import getpass
                    password = getpass("Password:")

                if self.options.hashes is not None:
                    lmhash, nthash = self.options.hashes.split(':')
                else:
                    lmhash, nthash = '',''

                rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\PIPE\protected_storage]' % remoteName)

                if hasattr(rpctransport, 'set_credentials'):
                    # This method exists only for selected protocol sequences.
                    rpctransport.set_credentials(username, password, domain, lmhash, nthash, self.options.aesKey)
                
                rpctransport.set_kerberos(self.options.k, self.options.dc_ip)
                
                dce = rpctransport.get_dce_rpc()
                dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
                if self.options.k is True:
                    dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
                dce.connect()
                dce.bind(bkrp.MSRPC_UUID_BKRP, transfer_syntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
                
                request = bkrp.BackuprKey()
                request['pguidActionAgent'] = bkrp.BACKUPKEY_RESTORE_GUID
                request['pDataIn'] = dk.getData()
                request['cbDataIn'] = len(dk.getData())
                request['dwParam'] = 0

                resp = dce.request(request)
                
                ## Stripping heading zeros resulting from asymetric decryption
                beginning=0
                for i in range(len(resp['ppDataOut'])):
                    if resp['ppDataOut'][i]==b'\x00':
                        beginning+=1
                    else:
                        break
                masterkey=b''.join(resp['ppDataOut'][beginning:])
                print('Decrypted key using rpc call')
                print('Decrypted key: 0x%s' % hexlify(masterkey[beginning:]).decode())
                return

            else:
                # Just print key's data
                if mkf['MasterKeyLen'] > 0:
                    mk.dump()

                if mkf['BackupKeyLen'] > 0:
                    bkmk.dump()

                if mkf['CredHistLen'] > 0:
                    ch.dump()

                if mkf['DomainKeyLen'] > 0:
                    dk.dump()

        # credit to @gentilkiwi
        elif self.options.action.upper() == 'BACKUPKEYS':
            domain, username, password, address = parse_target(self.options.target)

            if password == '' and username != '' and self.options.hashes is None and self.options.no_pass is False and self.options.aesKey is None:
                from getpass import getpass
                password = getpass ("Password:")
            if self.options.hashes is not None:
                lmhash, nthash = self.options.hashes.split(':')
            else:
                lmhash, nthash = '',''
            connection = SMBConnection(address, address)
            if self.options.k:
                connection.kerberosLogin(username, password, domain, lmhash, nthash, self.options.aesKey)
            else:
                connection.login(username, password, domain, lmhash=lmhash, nthash=nthash)

            rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\lsarpc]')
            rpctransport.set_smb_connection(connection)
            dce = rpctransport.get_dce_rpc()
            if self.options.k:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            try:
                dce.connect()
                dce.bind(lsad.MSRPC_UUID_LSAD)
            except transport.DCERPCException as e:
                raise e

            resp = lsad.hLsarOpenPolicy2(dce, lsad.POLICY_GET_PRIVATE_INFORMATION)
            for keyname in ("G$BCKUPKEY_PREFERRED", "G$BCKUPKEY_P"):
                buffer = crypto.decryptSecret(connection.getSessionKey(), lsad.hLsarRetrievePrivateData(dce,
                                              resp['PolicyHandle'], keyname))
                guid = bin_to_string(buffer)
                name = "G$BCKUPKEY_{}".format(guid)
                secret = crypto.decryptSecret(connection.getSessionKey(), lsad.hLsarRetrievePrivateData(dce,
                                              resp['PolicyHandle'], name))
                keyVersion = struct.unpack('<L', secret[:4])[0]
                if keyVersion == 1:  # legacy key
                    backup_key = P_BACKUP_KEY(secret)
                    backupkey = backup_key['Data']
                    if self.options.export:
                        logging.debug("Exporting key to file {}".format(name + ".key"))
                        open(name + ".key", 'wb').write(backupkey)
                    else:
                        print("Legacy key:")
                        print("0x%s" % hexlify(backupkey).decode('latin-1'))
                        print("\n")

                elif keyVersion == 2:  # preferred key
                    backup_key = PREFERRED_BACKUP_KEY(secret)
                    pvk = backup_key['Data'][:backup_key['KeyLength']]
                    cert = backup_key['Data'][backup_key['KeyLength']:backup_key['KeyLength'] + backup_key['CertificateLength']]

                    # build pvk header (PVK_MAGIC, PVK_FILE_VERSION_0, KeySpec, PVK_NO_ENCRYPT, 0, cbPvk)
                    header = PVK_FILE_HDR()
                    header['dwMagic'] = 0xb0b5f11e
                    header['dwVersion'] = 0
                    header['dwKeySpec'] = 1
                    header['dwEncryptType'] = 0
                    header['cbEncryptData'] = 0
                    header['cbPvk'] = backup_key['KeyLength']
                    backupkey_pvk = header.getData() + pvk  # pvk blob

                    backupkey = backupkey_pvk
                    if self.options.export:
                        logging.debug("Exporting certificate to file {}".format(name + ".der"))
                        open(name + ".der", 'wb').write(cert)
                        logging.debug("Exporting private key to file {}".format(name + ".pvk"))
                        open(name + ".pvk", 'wb').write(backupkey)
                    else:
                        print("Preferred key:")
                        header.dump()
                        print("PRIVATEKEYBLOB:{%s}" % (hexlify(backupkey).decode('latin-1')))
                        print("\n")
            return


        elif self.options.action.upper() == 'CREDENTIAL':
            fp = open(options.file, 'rb')
            data = fp.read()
            cred = CredentialFile(data)
            blob = DPAPI_BLOB(cred['Data'])

            if self.options.key is not None:
                key = unhexlify(self.options.key[2:])
                decrypted = blob.decrypt(key)
                if decrypted is not None:
                    creds = CREDENTIAL_BLOB(decrypted)
                    creds.dump()
                    return
            else:
                # Just print the data
                blob.dump()

        elif self.options.action.upper() == 'VAULT':
            if options.vcrd is None and options.vpol is None:
                print('You must specify either -vcrd or -vpol parameter. Type --help for more info')
                return
            if options.vcrd is not None:
                fp = open(options.vcrd, 'rb')
                data = fp.read()
                blob = VAULT_VCRD(data)

                if self.options.key is not None:
                    key = unhexlify(self.options.key[2:])

                    cleartext = None
                    for i, entry in enumerate(blob.attributesLen):
                        if entry > 28:
                            attribute = blob.attributes[i]
                            if 'IV' in attribute.fields and len(attribute['IV']) == 16:
                                cipher = AES.new(key, AES.MODE_CBC, iv=attribute['IV'])
                            else:
                                cipher = AES.new(key, AES.MODE_CBC)
                            cleartext = cipher.decrypt(attribute['Data'])

                    if cleartext is not None:
                        # Lookup schema Friendly Name and print if we find one
                        if blob['FriendlyName'].decode('utf-16le')[:-1] in VAULT_KNOWN_SCHEMAS:
                            # Found one. Cast it and print
                            vault = VAULT_KNOWN_SCHEMAS[blob['FriendlyName'].decode('utf-16le')[:-1]](cleartext)
                            vault.dump()
                        else:
                            # otherwise
                            hexdump(cleartext)
                        return
                else:
                    blob.dump()

            elif options.vpol is not None:
                fp = open(options.vpol, 'rb')
                data = fp.read()
                vpol = VAULT_VPOL(data)
                vpol.dump()

                if self.options.key is not None:
                    key = unhexlify(self.options.key[2:])
                    blob = vpol['Blob']
                    data = blob.decrypt(key)
                    if data is not None:
                        keys = VAULT_VPOL_KEYS(data)
                        keys.dump()
                        return
        elif self.options.action.upper() == 'UNPROTECT':
            fp = open(options.file, 'rb')
            data = fp.read()
            blob = DPAPI_BLOB(data)

            if self.options.key is not None:
                key = unhexlify(self.options.key[2:])
                if self.options.entropy_file is not None:
                    fp2 = open(self.options.entropy_file, 'rb')
                    entropy = fp2.read()
                    fp2.close()
                elif self.options.entropy is not None:
                    entropy = b(self.options.entropy) + b'\x00'
                else:
                    entropy = None

                decrypted = blob.decrypt(key, entropy)
                if decrypted is not None:
                    print('Successfully decrypted data')
                    hexdump(decrypted)
                    return
            else:
                # Just print the data
                blob.dump()

        print('Cannot decrypt (specify -key or -sid whenever applicable) ')


if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Example for using the DPAPI/Vault structures to unlock Windows Secrets.")
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    subparsers = parser.add_subparsers(help='actions', dest='action')

    # A domain backup key command
    backupkeys = subparsers.add_parser('backupkeys', help='domain backup key related functions')
    backupkeys.add_argument('-t', '--target', action='store', required=True, help='[[domain/]username[:password]@]<targetName or address>')
    backupkeys.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    backupkeys.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    backupkeys.add_argument('-k', action="store_true", required=False, help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    backupkeys.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    backupkeys.add_argument('-dc-ip', action='store',metavar = "ip address", help='IP Address of the domain controller. '
                       'If omitted it will use the domain part (FQDN) specified in the target parameter')
    backupkeys.add_argument('--export', action='store_true', required=False, help='export keys to file')

    # A masterkey command
    masterkey = subparsers.add_parser('masterkey', help='masterkey related functions')
    masterkey.add_argument('-file', action='store', required=True, help='Master Key File to parse')
    masterkey.add_argument('-sid', action='store', help='SID of the user')
    masterkey.add_argument('-pvk', action='store', help='Domain backup privatekey to use for decryption')
    masterkey.add_argument('-key', action='store', help='Specific key to use for decryption')
    masterkey.add_argument('-password', action='store', help='User\'s password. If you specified the SID and not the password it will be prompted')
    masterkey.add_argument('-system', action='store', help='SYSTEM hive to parse')
    masterkey.add_argument('-security', action='store', help='SECURITY hive to parse')
    masterkey.add_argument('-t', '--target', action='store', help='The masterkey owner\'s credentails to ask the DC for decryption'
                                                                  'Format: [[domain/]username[:password]@]<targetName or address>')
    masterkey.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    masterkey.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    masterkey.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    masterkey.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    masterkey.add_argument('-dc-ip', action='store',metavar = "ip address", help='IP Address of the domain controller. '
                       'If omitted it will use the domain part (FQDN) specified in the target parameter')

    # A credential command
    credential = subparsers.add_parser('credential', help='credential related functions')
    credential.add_argument('-file', action='store', required=True, help='Credential file')
    credential.add_argument('-key', action='store', required=False, help='Key used for decryption')

    # A vault command
    vault = subparsers.add_parser('vault', help='vault credential related functions')
    vault.add_argument('-vcrd', action='store', required=False, help='Vault Credential file')
    vault.add_argument('-vpol', action='store', required=False, help='Vault Policy file')
    vault.add_argument('-key', action='store', required=False, help='Master key used for decryption')

    # A CryptUnprotectData command
    unprotect = subparsers.add_parser('unprotect', help='Provides CryptUnprotectData functionality')
    unprotect.add_argument('-file', action='store', required=True, help='File with DATA_BLOB to decrypt')
    unprotect.add_argument('-key', action='store', required=False, help='Key used for decryption')
    unprotect.add_argument('-entropy', action='store', default=None, required=False, help='String with extra entropy needed for decryption')
    unprotect.add_argument('-entropy-file', action='store', default=None, required=False, help='File with binary entropy contents (overwrites -entropy)')

    options = parser.parse_args()

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)


    try:
        executer = DPAPI(options)
        executer.run()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        print('ERROR: %s' % str(e))
