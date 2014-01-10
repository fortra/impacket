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

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, wkst
from impacket.dcerpc.v5.ndr import NULL
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket import system_errors

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
        #resp.dump()

        request['Level'] = 101
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 102
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 502
        resp = dce.request(request)
        #resp.dump()

    def test_NetrWkstaUserEnum(self):
        dce, rpctransport = self.connect()
        request = wkst.NetrWkstaUserEnum()
        request['ServerName'] = '\x00'*10
        request['UserInfo']['Level'] = 0
        request['UserInfo']['WkstaUserInfo']['tag'] = 0
        request['PreferredMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()

        request['UserInfo']['Level'] = 1
        request['UserInfo']['WkstaUserInfo']['tag'] = 1
        resp = dce.request(request)
        #resp.dump()

    def test_NetrWkstaTransportEnum(self):
        dce, rpctransport = self.connect()
        request = wkst.NetrWkstaTransportEnum()
        request['ServerName'] = '\x00'*10
        request['TransportInfo']['Level'] = 0
        request['TransportInfo']['WkstaTransportInfo']['tag'] = 0
        request['PreferredMaximumLength'] = 500
        request['ResumeHandle'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_NetrWkstaSetInfo(self):
        dce, rpctransport = self.connect()
        request = wkst.NetrWkstaGetInfo()
        request['ServerName'] = '\x00'*10
        request['Level'] = 502
        resp = dce.request(request)
        #resp.dump()
        oldVal = resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] 

        req = wkst.NetrWkstaSetInfo()
        req['ServerName'] = '\x00'*10
        req['Level'] = 502
        req['WkstaInfo'] = resp['WkstaInfo']
        req['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] = 500
        resp2 = dce.request(req)
        #resp2.dump()

        resp = dce.request(request)
        self.assertTrue(500 == resp['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] )

        req['WkstaInfo']['WkstaInfo502']['wki502_dormant_file_limit'] = oldVal
        resp2 = dce.request(req)
        #resp2.dump()

    def test_NetrWkstaTransportAdd(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrWkstaTransportAdd()
        req['ServerName'] = '\x00'*10
        req['Level'] = 0
        req['TransportInfo']['wkti0_transport_name'] = 'BETO\x00'
        req['TransportInfo']['wkti0_transport_address'] = '000C29BC5CE5\x00'
        try:
            resp2 = dce.request(req)
            #resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_FUNCTION') < 0: 
                raise

    def test_NetrUseAdd(self):
        dce, rpctransport = self.connect()

        # This one doesn't look to be working remotelly
        req = wkst.NetrUseAdd()
        req['ServerName'] = '\x00'*10
        req['Level'] = 0
        req['InfoStruct']['tag'] = 0 
        req['InfoStruct']['UseInfo0']['ui0_local'] = 'LPT1\x00'
        req['InfoStruct']['UseInfo0']['ui0_remote'] = '\\\\BETO\\ipc$\x00'
        try:
            resp2 = dce.request(req)
            #resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_LEVEL') < 0:
                raise

    def test_NetrUseGetInfo(self):
        dce, rpctransport = self.connect()

        # This one doesn't look to be working remotelly
        req = wkst.NetrUseGetInfo()
        req['ServerName'] = '\x00'*10
        req['UseName'] = '\\\\192.168.66.244\\IPC$\x00'
        #req['UseName'] = '\\\\vmware-host\\Shared Folders\x00'
        req['Level'] = 3
        try:
            resp2 = dce.request(req)
            #resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_CONNECTED') < 0:
                raise

    def test_NetrUseDel(self):
        dce, rpctransport = self.connect()

        # This one doesn't look to be working remotelly
        req = wkst.NetrUseDel()
        req['ServerName'] = '\x00'*10
        req['UseName'] = '\\\\192.168.66.244\\IPC$\x00'
        req['ForceLevel'] = wkst.USE_LOTS_OF_FORCE
        try:
            resp2 = dce.request(req)
            #resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_CONNECTED') < 0:
                raise

    def test_NetrUseEnum(self):
        dce, rpctransport = self.connect()

        # We're not testing this call with NDR64, it fails and I can't see the contents
        if self.ts == ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'):
            return

        # This one doesn't look to be working remotelly
        req = wkst.NetrUseEnum()
        req['ServerName'] = NULL
        req['InfoStruct']['Level'] = 2
        req['InfoStruct']['UseInfo']['tag'] = 2
        req['InfoStruct']['UseInfo']['Level2']['Buffer'] = NULL
        req['PreferredMaximumLength'] = 10
        req['ResumeHandle'] = NULL
        try:
            resp2 = dce.request(req)
            #resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                raise

    def test_NetrWorkstationStatisticsGet(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrWorkstationStatisticsGet()
        req['ServerName'] = '\x00'*10
        req['ServiceName'] = '\x00'
        req['Level'] = 0
        req['Options'] = 0
        try:
            resp2 = dce.request(req)
            #resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_INVALID_PARAMETER') < 0:
                raise

    def test_NetrGetJoinInformation(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrGetJoinInformation()
        req['ServerName'] = '\x00'*10
        req['NameBuffer'] = '\x00'
        #req.dump()
        try:
            resp2 = dce.request(req)
            #resp2.dump()
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
            #resp2.dump()
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
            #resp2.dump()
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
            #resp2.dump()
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
            #resp2.dump()
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
            #resp2.dump()
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
            #resp2.dump()
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
            #resp2.dump()
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
            #resp2.dump()
        except Exception, e:
            if str(e).find('ERROR_NOT_SUPPORTED') < 0:
                raise

    def test_NetrSetPrimaryComputerName(self):
        dce, rpctransport = self.connect()

        req = wkst.NetrEnumerateComputerNames()
        req['ServerName'] = '\x00'*10
        req['NameType'] = wkst.NET_COMPUTER_NAME_TYPE.NetAllComputerNames
        #req.dump()
        try:
            resp2 = dce.request(req)
            #resp2.dump()
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
