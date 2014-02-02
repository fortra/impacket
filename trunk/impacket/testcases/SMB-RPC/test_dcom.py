###############################################################################
#  Tested so far: 
#
# ServerAlive
# ServerAlive2
# ComplexPing
# SimplePing
# RemoteCreateInstance
#
#  Not yet:
#
# ResolveOxid
# ResolveOxid2
# RemoteActivation
# RemoteGetClassObject
# 
# Shouldn't dump errors against a win7
#
################################################################################

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, dcom
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.dtypes import *
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin, generate
from impacket import system_errors, ntlm

class DCOMTests(unittest.TestCase):
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
        dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        dce.connect()

        return dce, rpctransport

    def test_ServerAlive(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcom.ServerAlive()
        resp = dce.request(request)
        #resp.dump()

    def test_ServerAlive2(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcom.ServerAlive2()
        resp = dce.request(request)
        #resp.dump()

    def test_ComplexPing_SimplePing(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcom.ComplexPing()
        request['pSetId'] = 0
        resp = dce.request(request)
        #resp.dump()

        request = dcom.SimplePing()
        request['pSetId'] = resp['pSetId']
        resp = dce.request(request)
        #resp.dump()

    def test_ResolveOxid(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcom.ResolveOxid()
        request['cRequestedProtseqs'] = 10
        request['arRequestedProtseqs'] = (1,2,3,4,5,6,7,8,9,10)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('OR_INVALID_OXID') < 0:
                raise

    def test_ResolveOxid2(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcom.ResolveOxid2()
        request['cRequestedProtseqs'] = 10
        request['arRequestedProtseqs'] = (1,2,3,4,5,6,7,8,9,10)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('OR_INVALID_OXID') < 0:
                raise

    def tes_RemoteActivation(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IActivation, transfer_syntax=self.ts)
        request = dcom.RemoteActivation()
        request['pwszObjectName'] = 'BETOBETO\x00'
        request['cRequestedProtseqs'] = 10
        request['aRequestedProtseqs'] = (1,2,3,4,5,6,7,8,9,10)
        request['ORPCthis']['extensions'] = NULL
        request['pObjectStorage'] = NULL
        request['pIIDs'] = NULL
        resp = dce.request(request)
        resp.dump()

    def tes_RemoteGetClassObject(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IRemoteSCMActivator, transfer_syntax=self.ts)
        request = dcom.RemoteGetClassObject()
        request['ORPCthis']['extensions'] = NULL
        request['pActProperties'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_RemoteCreateInstance(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IRemoteSCMActivator, transfer_syntax=self.ts)

        request = dcom.RemoteCreateInstance()
        request['ORPCthis']['cid'] = generate()
        request['ORPCthis']['extensions'] = NULL
        request['ORPCthis']['flags'] = 1
        request['pUnkOuter'] = NULL

        activationBLOB = dcom.ACTIVATION_BLOB()
        activationBLOB['CustomHeader']['destCtx'] = 2
        activationBLOB['CustomHeader']['pdwReserved'] = NULL
        clsid = dcom.CLSID()
        clsid['Data'] = dcom.CLSID_InstantiationInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)
        clsid = dcom.CLSID()
        clsid['Data'] = dcom.CLSID_ActivationContextInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)
        clsid = dcom.CLSID()
        clsid['Data'] = dcom.CLSID_ServerLocationInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)
        clsid = dcom.CLSID()
        clsid['Data'] = dcom.CLSID_ScmRequestInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)

        properties = ''
        # InstantiationInfo
        instantiationInfo = dcom.InstantiationInfoData()
        instantiationInfo['classId'] = string_to_bin('ECABB0C4-7F19-11D2-978E-0000F8757E2A')
        instantiationInfo['cIID'] = 1

        iid = dcom.IID()
        iid['Data'] = string_to_bin('23C9DD26-2355-4FE2-84DE-F779A238ADBD')

        instantiationInfo['pIID'].append(iid)

        dword = DWORD()
        marshaled = instantiationInfo.getData()+instantiationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activationBLOB['CustomHeader']['pSizes'].append(dword)
        instantiationInfo['thisSize'] = dword['Data']

        properties += marshaled + '\xFA'*pad

        # ActivationContextInfoData
        activationInfo = dcom.ActivationContextInfoData()
        activationInfo['pIFDClientCtx'] = NULL
        activationInfo['pIFDPrototypeCtx'] = NULL

        dword = DWORD()
        marshaled = activationInfo.getData()+activationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled + '\xFA'*pad

        # ServerLocation
        locationInfo = dcom.LocationInfoData()
        locationInfo['machineName'] = NULL

        dword = DWORD()
        dword['Data'] = len(locationInfo.getData())
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += locationInfo.getData()+locationInfo.getDataReferents()

        # ScmRequestInfo
        scmInfo = dcom.ScmRequestInfoData()
        scmInfo['pdwReserved'] = NULL
        #scmInfo['remoteRequest']['ClientImpLevel'] = 2
        scmInfo['remoteRequest']['cRequestedProtseqs'] = 1
        scmInfo['remoteRequest']['pRequestedProtseqs'].append(7)

        dword = DWORD()
        marshaled = scmInfo.getData()+scmInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled + '\xFA'*pad

        activationBLOB['Property'] = properties


        objrefcustom = dcom.OBJREF_CUSTOM()
        objrefcustom['iid'] = dcom.IID_IActivationPropertiesIn[:-4]
        objrefcustom['clsid'] = dcom.CLSID_ActivationPropertiesIn

        objrefcustom['pObjectData'] = activationBLOB.getData()
        objrefcustom['ObjectReferenceSize'] = len(objrefcustom['pObjectData'])+8

        request['pActProperties']['ulCntData'] = len(str(objrefcustom))
        request['pActProperties']['abData'] = list(str(objrefcustom))
        resp = dce.request(request)
        #resp.dump()

    def tes_RemQueryInterface(self):
        dce, rpctransport = self.connect()
        dce.bind(dcom.IID_IRemUnknown2, transfer_syntax=self.ts)
        request = dcom.RemQueryInterface()
        resp = dce.request(request)
        resp.dump()

class TCPTransport(DCOMTests):
    def setUp(self):
        DCOMTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s' % self.machine
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class TCPTransport64(DCOMTests):
    def setUp(self):
        DCOMTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('TCPTransport', 'username')
        self.domain   = configFile.get('TCPTransport', 'domain')
        self.serverName = configFile.get('TCPTransport', 'servername')
        self.password = configFile.get('TCPTransport', 'password')
        self.machine  = configFile.get('TCPTransport', 'machine')
        self.hashes   = configFile.get('TCPTransport', 'hashes')
        self.stringBinding = r'ncacn_ip_tcp:%s' % self.machine
        self.ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')


# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(TCPTransport)
        #suite.addTests(unittest.TestLoader().loadTestsFromTestCase(SMBTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
