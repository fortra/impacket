###############################################################################
#  Tested so far: 
#
# NetrWkstaGetInfo
# NetrWkstaUserEnum
# NetrWkstaTransportEnum
# NetrWkstaTransportAdd
# NetrUseAdd
# NetrUseGetInfo
# NetrUseDel
# NetrUseEnum
# NetrWorkstationStatisticsGet
# NetrGetJoinInformation
# NetrJoinDomain2
# NetrUnjoinDomain2
# NetrRenameMachineInDomain2
# NetrValidateName2
# NetrGetJoinableOUs2
# NetrAddAlternateComputerName
# NetrRemoveAlternateComputerName
# NetrSetPrimaryComputerName
# NetrEnumerateComputerNames
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#  
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import wkst
from impacket.dcerpc.v5.ndr import NULL


class WKSTTests(unittest.TestCase):
    def connect(self):
        rpctransport = transport.DCERPCTransportFactory(self.stringBinding)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(rpctransport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpctransport.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(wkst.MSRPC_UUID_WKST, transfer_syntax = self.ts)

        return dce, rpctransport

    def test_NetrWkstaGetInfo(self):
        dce, rpctransport = self.connect()
        request = wkst.NetrWkstaGetInfo()
        request['ServerName'] = '\x00'*10
        request['Level'] = 100
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 101
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 102
        resp = dce.request(request)
        resp.dump()

        request['Level'] = 502
        resp = dce.request(request)
        resp.dump()

    def test_hNetrWkstaGetInfo(self):
        dce, rpctransport = self.connect()
        resp = wkst.hNetrWkstaGetInfo(dce, 100)
        resp.dump()

        resp = wkst.hNetrWkstaGetInfo(dce, 101)
        resp.dump()

        resp = wkst.hNetrWkstaGetInfo(dce, 102)
        resp.dump()

        resp = wkst.hNetrWkstaGetInfo(dce, 502)
        resp.dump()

    def test_NetrWkstaUserEnum(self):
        dce, rpctransport = self.connect()
        request = wkst.NetrWkstaUserEnum()
        request['ServerName'] = '\x00'*10
        request['UserInfo']['Level'] = 0
        request['UserInfo']['WkstaUserInfo']['tag'] = 0
        request['PreferredMaximumLength'] = 8192
        resp = dce.request(request)
        resp.dump()

        request['UserInfo']['Level'] = 1
        request['UserInfo']['WkstaUserInfo']['tag'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_hNetrWkstaUserEnum(self):
        dce, rpctransport = self.connect()
        resp = wkst.hNetrWkstaUserEnum(dce, 0)
        resp.dump()

        resp = wkst.hNetrWkstaUserEnum(dce, 1)
        resp.dump()

    def test_NetrWkstaTransportEnum(self):
        dce, rpctransport = self.connect()
        request = wkst.NetrWkstaTransportEnum()
        request['ServerName'] = '\x00'*10
        request['TransportInfo']['Level'] = 0
        request['TransportInfo']['WkstaTransportInfo']['tag'] = 0
        request['PreferredMaximumLength'] = 500
        request['ResumeHandle'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hNetrWkstaTransportEnum(self):
        dce, rpctransport = self.connect()
        resp = wkst.hNetrWkstaTransportEnum(dce, 0)
        resp.dump()

    def test_NetrWkstaSetInfo(self):
        dce, rpctransport = self.connect()
        request = wkst.NetrWkstaGetInfo()
        request['ServerName'] = '\x00'*10
        request['Level'] = 502
        resp = dce.request(request)
        resp.dump()
        oldVal = resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit']

        req = wkst.NetrWkstaSetInfo()
        req['ServerName'] = '\x00'*10
        req['Level'] = 502
        req['WkstaInfo'] = resp['WkstaInfo']
        req['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] = 500
        resp2 = dce.request(req)
        resp2.dump()

        resp = dce.request(request)
        self.assertTrue(500 == resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] )

        req['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] = oldVal
        resp2 = dce.request(req)
        resp2.dump()

    def test_hNetrWkstaSetInfo(self):
        dce, rpctransport = self.connect()
        resp = wkst.hNetrWkstaGetInfo(dce, 502)
        resp.dump()
        oldVal = resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit']


        resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] = 500
        resp2 = wkst.hNetrWkstaSetInfo(dce, 502,resp['WkstaInfo']['WkstaInfo502'])
        resp2.dump()

        resp = wkst.hNetrWkstaGetInfo(dce, 502)
        resp.dump()
        self.assertTrue(500 == resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] )

        resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] = oldVal
        resp2 = wkst.hNetrWkstaSetInfo(dce, 502,resp['WkstaInfo']['WkstaInfo502'])
        resp2.dump()

    def test_NetrWkstaTransportAdd(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrWkstaTransportAdd()
        req['ServerName'] = '\x00'*10
        req['Level'] = 0
        req['TransportInfo']['wkti0_transport_name'] = 'BETO\x00'
        req['TransportInfo']['wkti0_transport_address'] = '000C29BC5CE5\x00'
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_FUNCTION') < 0:
                raise

    def test_hNetrUseAdd_hNetrUseDel_hNetrUseGetInfo_hNetrUseEnum(self):
        dce, rpctransport = self.connect()

        info1 = wkst.LPUSE_INFO_1()

        info1['ui1_local'] = 'Z:\x00'
        info1['ui1_remote'] = '\\\\127.0.0.1\\c$\x00'
        info1['ui1_password'] = NULL
        try:
            resp = wkst.hNetrUseAdd(dce, 1, info1)
            resp.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') >=0:
                # This could happen in newer OSes
                pass

        # We're not testing this call with NDR64, it fails and I can't see the contents
        if self.ts == ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'):
            return

        try:
            resp = wkst.hNetrUseEnum(dce, 2)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_PIPE_DISCONNECTED') >=0:
                # This could happen in newer OSes
                pass

        try:
            resp2 = wkst.hNetrUseGetInfo(dce, 'Z:', 3)
            resp2.dump()
        except Exception, e:
            if str(e).find('STATUS_PIPE_DISCONNECTED') >=0:
                # This could happen in newer OSes
                pass

        try:
            resp = wkst.hNetrUseDel(dce,'Z:')
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_PIPE_DISCONNECTED') >=0:
                # This could happen in newer OSes
                pass

    def test_NetrUseAdd_NetrUseDel_NetrUseGetInfo_NetrUseEnum(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrUseAdd()
        req['ServerName'] = '\x00'*10
        req['Level'] = 1
        req['InfoStruct']['tag'] = 1
        req['InfoStruct']['UseInfo1']['ui1_local'] = 'Z:\x00'
        req['InfoStruct']['UseInfo1']['ui1_remote'] = '\\\\127.0.0.1\\c$\x00'
        req['InfoStruct']['UseInfo1']['ui1_password'] = NULL
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') >=0:
                # This could happen in newer OSes
                pass

        # We're not testing this call with NDR64, it fails and I can't see the contents
        if self.ts == ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'):
            return

        req = wkst.NetrUseEnum()
        req['ServerName'] = NULL
        req['InfoStruct']['Level'] = 2
        req['InfoStruct']['UseInfo']['tag'] = 2
        req['InfoStruct']['UseInfo']['Level2']['Buffer'] = NULL
        req['PreferredMaximumLength'] = 0xffffffff
        req['ResumeHandle'] = NULL
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') >=0:
                # This could happen in newer OSes
                pass

        req = wkst.NetrUseGetInfo()
        req['ServerName'] = '\x00'*10
        req['UseName'] = 'Z:\x00'
        req['Level'] = 3
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') >=0:
                # This could happen in newer OSes
                pass


        req = wkst.NetrUseDel()
        req['ServerName'] = '\x00'*10
        req['UseName'] = 'Z:\x00'
        req['ForceLevel'] = wkst.USE_LOTS_OF_FORCE
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('rpc_s_access_denied') >=0:
                # This could happen in newer OSes
                pass


    def test_NetrWorkstationStatisticsGet(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrWorkstationStatisticsGet()
        req['ServerName'] = '\x00'*10
        req['ServiceName'] = '\x00'
        req['Level'] = 0
        req['Options'] = 0
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                raise

    def test_hNetrWorkstationStatisticsGet(self):
        dce, rpctransport = self.connect()

        try:
            resp2 = wkst.hNetrWorkstationStatisticsGet(dce, '\x00', 0, 0)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                raise

    def test_NetrGetJoinInformation(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrGetJoinInformation()
        req['ServerName'] = '\x00'*10
        req['NameBuffer'] = '\x00'

        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                raise

    def test_hNetrGetJoinInformation(self):
        dce, rpctransport = self.connect()

        try:
            resp = wkst.hNetrGetJoinInformation(dce, '\x00')
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                raise

    def test_NetrJoinDomain2(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrJoinDomain2()
        req['ServerName'] = '\x00'*10
        req['DomainNameParam'] = '172.16.123.1\\FREEFLY\x00'
        req['MachineAccountOU'] = 'OU=BETUS,DC=FREEFLY\x00'
        req['AccountName'] = NULL
        req['Password']['Buffer'] = '\x00'*512
        req['Options'] = wkst.NETSETUP_DOMAIN_JOIN_IF_JOINED
        #req.dump()
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_hNetrJoinDomain2(self):
        dce, rpctransport = self.connect()

        try:
            resp = wkst.hNetrJoinDomain2(dce,'172.16.123.1\\FREEFLY\x00','OU=BETUS,DC=FREEFLY\x00',NULL,'\x00'*512, wkst.NETSETUP_DOMAIN_JOIN_IF_JOINED)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_NetrUnjoinDomain2(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrUnjoinDomain2()
        req['ServerName'] = '\x00'*10
        req['AccountName'] = NULL
        req['Password']['Buffer'] = '\x00'*512
        #req['Password'] = NULL
        req['Options'] = wkst.NETSETUP_ACCT_DELETE
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_hNetrUnjoinDomain2(self):
        dce, rpctransport = self.connect()

        try:
            resp = wkst.hNetrUnjoinDomain2(dce, NULL, '\x00'*512, wkst.NETSETUP_ACCT_DELETE)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_NetrRenameMachineInDomain2(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrRenameMachineInDomain2()
        req['ServerName'] = '\x00'*10
        req['MachineName'] = 'BETUS\x00'
        req['AccountName'] = NULL
        req['Password']['Buffer'] = '\x00'*512
        #req['Password'] = NULL
        req['Options'] = wkst.NETSETUP_ACCT_CREATE
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_hNetrRenameMachineInDomain2(self):
        dce, rpctransport = self.connect()

        try:
            resp = wkst.hNetrRenameMachineInDomain2(dce, 'BETUS\x00', NULL, '\x00'*512, wkst.NETSETUP_ACCT_CREATE)
            resp.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_NetrValidateName2(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrValidateName2()
        req['ServerName'] = '\x00'*10
        req['NameToValidate'] = 'BETO\x00'
        req['AccountName'] = NULL
        req['Password'] = NULL
        req['NameType'] = wkst.NETSETUP_NAME_TYPE.NetSetupDomain
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('0x8001011c') < 0:
                raise

    def test_hNetrValidateName2(self):
        dce, rpctransport = self.connect()

        try:
            resp2 = wkst.hNetrValidateName2(dce, 'BETO\x00', NULL, NULL, wkst.NETSETUP_NAME_TYPE.NetSetupDomain)
            resp2.dump()
        except Exception, e:
            if str(e).find('0x8001011c') < 0:
                raise

    def test_NetrGetJoinableOUs2(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrGetJoinableOUs2()
        req['ServerName'] = '\x00'*10
        req['DomainNameParam'] = 'FREEFLY\x00'
        req['AccountName'] = NULL
        req['Password'] = NULL
        req['OUCount'] = 0
        #req.dump()
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('0x8001011c') < 0:
                raise

    def test_hNetrGetJoinableOUs2(self):
        dce, rpctransport = self.connect()

        try:
            resp = wkst.hNetrGetJoinableOUs2(dce,'FREEFLY\x00', NULL, NULL,0 )
            resp.dump()
        except Exception, e:
            if str(e).find('0x8001011c') < 0:
                raise

    def test_NetrAddAlternateComputerName(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrAddAlternateComputerName()
        req['ServerName'] = '\x00'*10
        req['AlternateName'] = 'FREEFLY\x00'
        req['DomainAccount'] = NULL
        req['EncryptedPassword'] = NULL
        #req.dump()
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0 and str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_hNetrAddAlternateComputerName(self):
        dce, rpctransport = self.connect()

        try:
            resp2= wkst.hNetrAddAlternateComputerName(dce, 'FREEFLY\x00', NULL, NULL)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0 and str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_NetrRemoveAlternateComputerName(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrRemoveAlternateComputerName()
        req['ServerName'] = '\x00'*10
        req['AlternateName'] = 'FREEFLY\x00'
        req['DomainAccount'] = NULL
        req['EncryptedPassword'] = NULL
        #req.dump()
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0 and str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_hNetrRemoveAlternateComputerName(self):
        dce, rpctransport = self.connect()

        try:
            resp2 = wkst.hNetrRemoveAlternateComputerName(dce,'FREEFLY\x00', NULL, NULL )
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0 and str(e).find('ERROR_INVALID_PASSWORD') < 0:
                raise

    def test_NetrSetPrimaryComputerName(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrSetPrimaryComputerName()
        req['ServerName'] = '\x00'*10
        req['PrimaryName'] = 'FREEFLY\x00'
        req['DomainAccount'] = NULL
        req['EncryptedPassword'] = NULL
        #req.dump()
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                    raise

    def test_hNetrSetPrimaryComputerName(self):
        dce, rpctransport = self.connect()

        try:
            resp2 = wkst.hNetrSetPrimaryComputerName(dce,'FREEFLY\x00', NULL, NULL )
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                    raise

    def test_NetrEnumerateComputerNames(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrEnumerateComputerNames()
        req['ServerName'] = '\x00'*10
        req['NameType'] = wkst.NET_COMPUTER_NAME_TYPE.NetAllComputerNames
        #req.dump()
        try:
            resp2 = dce.request(req)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_hNetrEnumerateComputerNames(self):
        dce, rpctransport = self.connect()

        try:
            resp2 = wkst.hNetrEnumerateComputerNames(dce,wkst.NET_COMPUTER_NAME_TYPE.NetAllComputerNames)
            resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise


class SMBTransport(WKSTTests):
    def setUp(self):
        WKSTTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\wkssvc]' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(WKSTTests):
    def setUp(self):
        WKSTTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\wkssvc]' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
