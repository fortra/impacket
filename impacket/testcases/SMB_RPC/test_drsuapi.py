###############################################################################
#  Tested so far: 
#
# DRSBind
# DRSDomainControllerInfo
# hDRSDomainControllerInfo
# DRSCrackNames(
# hDRSCrackNames
# DRSGetNT4ChangeLog
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport, epm
from impacket.dcerpc.v5 import drsuapi
from impacket.dcerpc.v5.dtypes import NULL, LPWSTR, WSTR, RPC_SID
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.winregistry import hexdump
from impacket.uuid import uuidtup_to_bin, string_to_bin


class DRSRTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding )
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(drsuapi.MSRPC_UUID_DRSUAPI, transfer_syntax = self.ts)

        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) #- 4
        drs['dwFlags'] = drsuapi.DRS_EXT_GETCHGREQ_V6 | drsuapi.DRS_EXT_GETCHGREPLY_V6 | drsuapi.DRS_EXT_GETCHGREQ_V8 | drsuapi.DRS_EXT_STRONG_ENCRYPTION
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = drsuapi.DRS_EXT_RECYCLE_BIN
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 0
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(str(drs))
        resp = dce.request(request)

        return dce, rpctransport, resp['phDrs']

    def connect2(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding )
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        #dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        dce.connect()
        dce.bind(drsuapi.MSRPC_UUID_DRSUAPI, transfer_syntax = self.ts)

        return dce, rpctransport

    def test_DRSBind(self):
        dce, rpctransport, _ = self.connect()

        request = drsuapi.DRSBind()
        request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
        drs = drsuapi.DRS_EXTENSIONS_INT()
        drs['cb'] = len(drs) - 4
        drs['dwFlags'] = 0
        drs['SiteObjGuid'] = drsuapi.NULLGUID
        drs['Pid'] = 0x1234
        drs['dwReplEpoch'] = 0
        drs['dwFlagsExt'] = drsuapi.DRS_EXT_RECYCLE_BIN
        drs['ConfigObjGUID'] = drsuapi.NULLGUID
        drs['dwExtCaps'] = 0
        request['pextClient']['cb'] = len(drs)
        request['pextClient']['rgb'] = list(str(drs))
        resp = dce.request(request)
        resp.dump()

        extension = drsuapi.DRS_EXTENSIONS_INT('\x00'*4 + ''.join(resp['ppextServer']['rgb'])+'\x00'*4)
        extension.dump()

    def test_DRSDomainControllerInfo(self):
        dce, rpctransport, hDrs = self.connect()

        request = drsuapi.DRSDomainControllerInfo()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['Domain'] = self.domain + '\x00'
        request['pmsgIn']['V1']['InfoLevel'] = 1

        resp = dce.request(request)
        resp.dump()

        request['pmsgIn']['V1']['InfoLevel'] = 2
        resp = dce.request(request)
        resp.dump()

        request['pmsgIn']['V1']['InfoLevel'] = 3
        resp = dce.request(request)
        resp.dump()

        request['pmsgIn']['V1']['InfoLevel'] = 0xffffffff
        resp = dce.request(request)
        resp.dump()

    def test_hDRSDomainControllerInfo(self):
        dce, rpctransport, hDrs = self.connect()

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 1)
        resp.dumpRaw()

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 2)
        resp.dump()

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 3)
        resp.dump()

        resp = drsuapi.hDRSDomainControllerInfo(dce, hDrs, self.domain, 0xffffffff)
        resp.dump()

    def test_DRSCrackNames(self):
        dce, rpctransport, hDrs = self.connect()

        request = drsuapi.DRSCrackNames()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['CodePage'] = 0
        request['pmsgIn']['V1']['LocaleId'] = 0
        request['pmsgIn']['V1']['dwFlags'] = 0
        request['pmsgIn']['V1']['formatOffered'] = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
        request['pmsgIn']['V1']['formatDesired'] = drsuapi.DS_USER_PRINCIPAL_NAME_FOR_LOGON
        request['pmsgIn']['V1']['cNames'] = 1
        name = LPWSTR()
        #name['Data'] = 'FREEFLY-DC\x00'
        #name['Data'] = 'CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=FREEFLY,DC=NET\x00'
        #name['Data'] = 'CN=FREEFLY-DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=FREEFLY,DC=NET\x00'
        name['Data'] = 'Administrator\x00'
        request['pmsgIn']['V1']['rpNames'].append(name)

        request.dumpRaw()
        resp = dce.request(request)
        resp.dump()

    def test_hDRSCrackNames(self):
        dce, rpctransport, hDrs = self.connect()

        name = 'Administrator'
        formatOffered = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN
        formatDesired = drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME

        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, formatOffered, formatDesired, (name,))
        resp.dump()

        name = 'CN=NTDS Settings,CN=FREEFLY-DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=FREEFLY,DC=NET'
        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME, (name,))
        resp.dump()

        name = 'CN=NTDS Settings,CN=FREEFLY-DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=FREEFLY,DC=NET'
        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, drsuapi.DS_NAME_FORMAT.DS_FQDN_1779_NAME, drsuapi.DS_STRING_SID_NAME, (name,))
        resp.dump()

    def test_DRSGetNT4ChangeLog(self):
        dce, rpctransport, hDrs = self.connect()

        request = drsuapi.DRSGetNT4ChangeLog()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['dwFlags'] = drsuapi.DRS_NT4_CHGLOG_GET_CHANGE_LOG | drsuapi.DRS_NT4_CHGLOG_GET_SERIAL_NUMBERS
        request['pmsgIn']['V1']['PreferredMaximumLength'] = 0x4000
        request['pmsgIn']['V1']['cbRestart'] = 0
        request['pmsgIn']['V1']['pRestart'] = NULL

        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') <0:
                raise

    def test_DRSGetNCChanges(self):
        # Not yet working
        dce, rpctransport, hDrs = self.connect()

        request = drsuapi.DRSGetNCChanges()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 10

        request['pmsgIn']['tag'] =10
        request['pmsgIn']['V10']['uuidDsaObjDest'] = string_to_bin('e85bbad7-0923-41cb-911e-3691d2014815')
        request['pmsgIn']['V10']['uuidInvocIdSrc'] = string_to_bin('e85bbad7-0923-41cb-911e-3691d2014815')
        #request['pmsgIn']['V10']['pNC'] = NULL

        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''
        #name = 'CN=NTDS Settings,CN=FREEFLY-DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=FREEFLY,DC=NET'
        #name = 'CN=admin,CN=Users,DC=FREEFLY,DC=NET'
        name = 'CN=krbtgt,CN=Users,DC=FREEFLY,DC=NET'
        #name = 'DC=FREEFLY,DC=NET'
        #name = 'CN=Schema,CN=Configuration,DC=FREEFLY,DC=NET'
        #name = 'CN=Aggregate,CN=Schema,CN=Configuration,DC=FREEFLY,DC=NET'
        dsName['NameLen'] = len(name)
        dsName['StringName'] = (name + '\x00')

        dsName['structLen'] = len(dsName.getData())

        request['pmsgIn']['V10']['pNC'] = dsName

        request['pmsgIn']['V10']['usnvecFrom']['usnHighObjUpdate'] = 0
        request['pmsgIn']['V10']['usnvecFrom']['usnHighPropUpdate'] = 0

        request['pmsgIn']['V10']['pUpToDateVecDest'] = NULL

        request['pmsgIn']['V10']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_PER_SYNC  #| drsuapi.DRS_CRITICAL_ONLY
        request['pmsgIn']['V10']['cMaxObjects'] = 50
        request['pmsgIn']['V10']['cMaxBytes'] = 0
        request['pmsgIn']['V10']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ | drsuapi.EXOP_REPL_SECRETS
        request['pmsgIn']['V10']['pPartialAttrSet'] = NULL
        request['pmsgIn']['V10']['pPartialAttrSetEx1'] = NULL
        request['pmsgIn']['V10']['PrefixTableDest']['pPrefixEntry'] = NULL
        #request['pmsgIn']['V10']['ulMoreFlags'] = 0

        from impacket.winregistry import hexdump
        print 'SESSION KEY'
        hexdump(dce.get_session_key())
        resp = dce.request(request)
        resp.dump()
        unicodePwdAttr = 589914
        for attr in resp['pmsgOut']['V6']['pObjects']['Entinf']['AttrBlock']['pAttr']:
            if attr['attrTyp'] == unicodePwdAttr:
                print "Found encrypted unicodePwd"
                encryptedUnicodePwd = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])
            elif attr['attrTyp'] == 0x00090092:
                import struct
                userSid = ''.join(attr['AttrVal']['pAVal'][0]['pVal'])[-4:]
                userRid = struct.unpack('<L', userSid)[0]
                print "Found RID ", userRid

        ntHash = drsuapi.DecryptAttributeValue(dce, encryptedUnicodePwd)
        # Now remove the DES layer
        ntHash = drsuapi.removeDESLayer(ntHash, userRid)
        print "User: %s" % name
        print "HTHASH ", ntHash.encode('hex')

        #userHash =

        # Bien con esto
        #from pyasn1.type import univ
        #from pyasn1.codec.ber import decoder, encoder
        #for entry in resp['pmsgOut']['V6']['PrefixTableSrc']['pPrefixEntry']:
        #    print decoder.decode('\x06' + chr(entry['prefix']['length']) + ''.join(entry['prefix']['elements']), asn1Spec = univ.ObjectIdentifier())[0]
            #entry.dump()
        #resp.dump()
        #AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        #while resp['pmsgOut']['V6']['fMoreData'] > 0:
        #    thisObject = resp['pmsgOut']['V6']['pObjects']
        #    done = False
        #    while not done:
        #        nextObject = thisObject['pNextEntInf']
        #        thisObject['pNextEntInf'] = NULL
        #        #thisObject.dump()
        #        #print thisObject['Entinf']['pName']['StringName']
        #        if thisObject['Entinf']['pName']['StringName'].find('CN=admin')>=0:
        #            #print repr(resp['pmsgOut']['V6']['usnvecTo']['usnHighObjUpdate'])
        #            #print repr(resp['pmsgOut']['V6']['usnvecTo']['usnHighPropUpdate'])
        #            thisObject.dump()
        #            import sys
        #            sys.exit(1)
        #        thisObject = nextObject
        #        #print '\n'
        #        if nextObject is '':
        #            done = True
        #
        #    print "B"*80
        #    request['pmsgIn']['V8']['uuidInvocIdSrc'] = resp['pmsgOut']['V6']
        #    request['pmsgIn']['V8']['usnvecFrom'] = resp['pmsgOut']['V6']['usnvecTo']
        #    resp = dce.request(request)
        #print "OBJECTS ", resp['pmsgOut']['V6']['cNumObjects']

    def aaaa_DRSVerifyNames(self):
        # Not Yet working
        dce, rpctransport, hDrs = self.connect()

        name = 'CN=Administrator,CN=Users,DC=FREEFLY,DC=NET'
        formatOffered = drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN_EX
        formatDesired = drsuapi.DS_USER_PRINCIPAL_NAME_FOR_LOGON
        resp = drsuapi.hDRSCrackNames(dce, hDrs, 0, formatOffered, formatDesired, (name,))
        #resp.dump()

        request = drsuapi.DRSVerifyNames()
        request['hDrs'] = hDrs
        request['dwInVersion'] = 1

        request['pmsgIn']['tag'] = 1
        request['pmsgIn']['V1']['dwFlags'] = drsuapi.DRS_VERIFY_SAM_ACCOUNT_NAMES
        request['pmsgIn']['V1']['cNames'] = 1
        #pDsName = drsuapi.PDSNAME()
        dsName = drsuapi.DSNAME()
        dsName['SidLen'] = 0
        dsName['Guid'] = drsuapi.NULLGUID
        dsName['Sid'] = ''
        dsName['NameLen'] = len(name)
        dsName['StringName'] = name + '\x00'
        dsName['structLen'] = len(dsName.getData())
        request['pmsgIn']['V1']['rpNames'].append(dsName)
        request['pmsgIn']['V1']['RequiredAttrs']['pAttr'] = NULL
        #request['pmsgIn']['V1']['RequiredAttrs']['attrCount'] = 3

        #attr = drsuapi.ATTR()
        #attr[''] =
        #attr[''] =
        #attr[''] =
        #request['pmsgIn']['V1']['RequiredAttrs']['pAttr'].append(attr)

        request['pmsgIn']['V1']['PrefixTable']['pPrefixEntry'] = NULL

        #request.dump()
        resp = dce.request(request)
        for entry in resp['pmsgOut']['V6']['PrefixTableSrc']['pPrefixEntry']:
            entry.dump()
        #resp.dump()


class SMBTransport(DRSRTests):
    def setUp(self):
        DRSRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\lsass]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(DRSRTests):
    def setUp(self):
        DRSRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')

        self.stringBinding = r'ncacn_np:%s[\PIPE\lsass]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

class TCPTransport(DRSRTests):
    def setUp(self):
        DRSRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, drsuapi.MSRPC_UUID_DRSUAPI, protocol = 'ncacn_ip_tcp')
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class TCPTransport64(DRSRTests):
    def setUp(self):
        DRSRTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = epm.hept_map(self.machine, drsuapi.MSRPC_UUID_DRSUAPI, protocol = 'ncacn_ip_tcp')
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        #suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite  = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport))
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
