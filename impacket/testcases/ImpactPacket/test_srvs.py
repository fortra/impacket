###############################################################################
#  Tested so far: 
#
#  NetrConnectionEnum
#  NetrFileEnum
#  NetrFileGetInfo
#  NetrFileClose
#  NetrSessionEnum
#  NetrSessionDel
#  NetrShareAdd
#  NetrShareDel
#  NetrShareEnum
#  NetrShareEnumSticky
#  NetrShareGetInfo
#
#  Not yet:
#
#  
################################################################################

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, srvs, samr
from impacket.dcerpc.v5.ndr import NULL
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket import system_errors

class SRVSTests(unittest.TestCase):
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
        dce.bind(srvs.MSRPC_UUID_SRVS)

        return dce, rpctransport

    def test_NetrConnectionEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrConnectionEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['Qualifier'] = 'IPC$\x00'
        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['ConnectInfo']['tag'] = 1
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['ConnectInfo']['tag'] = 0
        resp = dce.request(request)
        #resp.dump()

    def test_NetrFileEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()
        request['InfoStruct']['Level'] = 3
        request['InfoStruct']['FileInfo']['tag'] = 3
        resp = dce.request(request)
        #resp.dump()

    def test_NetrFileGetInfo(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrFileGetInfo()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['FileId'] = resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id']
        request['Level'] = 2
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 3
        resp = dce.request(request)
        #resp.dump()

    def test_NetrFileClose(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrFileEnum()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['BasePath'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['FileInfo']['tag'] = 2
        request['PreferedMaximumLength'] = 8192
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrFileClose()
        request['ServerName'] = '\\\\%s\x00' % self.machine
        request['FileId'] = resp['InfoStruct']['FileInfo']['Level2']['Buffer'][0]['fi2_id']
        resp = dce.request(request)
        #resp.dump()

    def test_NetrSessionEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrSessionEnum()
        request['ServerName'] = NULL
        request['ClientName'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 0
        request['InfoStruct']['SessionInfo']['tag'] = 0
        request['InfoStruct']['SessionInfo']['Level0']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 1
        request['InfoStruct']['SessionInfo']['tag'] = 1
        request['InfoStruct']['SessionInfo']['Level1']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 2
        request['InfoStruct']['SessionInfo']['tag'] = 2
        request['InfoStruct']['SessionInfo']['Level2']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 10
        request['InfoStruct']['SessionInfo']['tag'] = 10
        request['InfoStruct']['SessionInfo']['Level10']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['Level'] = 502
        request['InfoStruct']['SessionInfo']['tag'] = 502
        request['InfoStruct']['SessionInfo']['Level502']['Buffer'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_NetrSessionDel(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrSessionEnum()
        request['ServerName'] = NULL
        request['ClientName'] = NULL
        request['UserName'] = NULL
        request['InfoStruct']['Level'] = 502
        request['InfoStruct']['SessionInfo']['tag'] = 502
        request['InfoStruct']['SessionInfo']['Level502']['Buffer'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrSessionDel()
        request['ServerName'] = NULL
        request['ClientName'] = resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_cname'] 
        request['UserName'] = resp['InfoStruct']['SessionInfo']['Level502']['Buffer'][0]['sesi502_username'] 
        try:
            resp = dce.request(request)
            #resp.dump()
        except Exception, e:
            if e.get_error_code() != 0x908:
                raise

    def test_NetrShareAdd_NetrShareDel(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareAdd()
        request['ServerName'] = NULL
        request['Level'] = 2
        request['InfoStruct']['tag'] = 2
        request['InfoStruct']['ShareInfo2']['shi2_netname'] = 'BETUSHARE\x00'
        request['InfoStruct']['ShareInfo2']['shi2_type'] = srvs.STYPE_TEMPORARY
        request['InfoStruct']['ShareInfo2']['shi2_remark'] = 'My Remark\x00'
        request['InfoStruct']['ShareInfo2']['shi2_max_uses'] = 0xFFFFFFFF
        request['InfoStruct']['ShareInfo2']['shi2_path'] = 'c:\\tmp\x00'
        request['InfoStruct']['ShareInfo2']['shi2_passwd'] = NULL
        resp = dce.request(request)
        #resp.dump()

        request = srvs.NetrShareDel()
        request['ServerName'] = NULL
        request['NetName'] = 'BETUSHARE\x00'
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareEnum(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareEnum()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['ShareInfo']['tag'] = 0
        request['InfoStruct']['ShareInfo']['Level0']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 0
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 1
        request['InfoStruct']['ShareInfo']['Level1']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 1
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 2
        request['InfoStruct']['ShareInfo']['Level2']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 2
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 501
        request['InfoStruct']['ShareInfo']['Level501']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 501
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 502
        request['InfoStruct']['ShareInfo']['Level502']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 502
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 503
        request['InfoStruct']['ShareInfo']['Level503']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 503
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareEnumSticky(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareEnumSticky()
        request['ServerName'] = NULL
        request['PreferedMaximumLength'] = 0xffffffff
        request['ResumeHandle'] = NULL
        request['InfoStruct']['ShareInfo']['tag'] = 502
        request['InfoStruct']['ShareInfo']['Level502']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 502
        resp = dce.request(request)
        #resp.dump()

        request['InfoStruct']['ShareInfo']['tag'] = 503
        request['InfoStruct']['ShareInfo']['Level503']['Buffer'] = NULL
        request['InfoStruct']['Level'] = 503
        resp = dce.request(request)
        #resp.dump()

    def test_NetrShareGetInfo(self):
        dce, rpctransport = self.connect()
        request = srvs.NetrShareGetInfo()
        request['ServerName'] = NULL
        request['NetName'] = 'IPC$\x00'
        request['Level'] = 0
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 1
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 2
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 501
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 502
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 503
        resp = dce.request(request)
        #resp.dump()

        request['Level'] = 1005
        resp = dce.request(request)
        #resp.dump()


class SMBTransport(SRVSTests):
    def setUp(self):
        SRVSTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\srvsvc]' % self.machine

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
    unittest.TextTestRunner(verbosity=1).run(suite)
