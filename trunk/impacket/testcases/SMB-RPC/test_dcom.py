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
from impacket.dcerpc.v5 import epm, dcomrt
from impacket.dcerpc.v5.dcom import comev, scmp, vds, oaut, comev
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

    def tes_ServerAlive(self):
        dce, rpctransport = self.connect()
        dce.bind(dcomrt.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcomrt.ServerAlive()
        resp = dce.request(request)
        #resp.dump()

    def tes_ServerAlive2(self):
        dce, rpctransport = self.connect()
        dce.bind(dcomrt.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcomrt.ServerAlive2()
        resp = dce.request(request)
        #resp.dump()

    def tes_ComplexPing_SimplePing(self):
        dce, rpctransport = self.connect()
        dce.bind(dcomrt.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcomrt.ComplexPing()
        request['pSetId'] = 0
        resp = dce.request(request)
        #resp.dump()

        request = dcomrt.SimplePing()
        request['pSetId'] = resp['pSetId']
        resp = dce.request(request)
        #resp.dump()

    def tes_ResolveOxid(self):
        dce, rpctransport = self.connect()
        dce.bind(dcomrt.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcomrt.ResolveOxid()
        request['cRequestedProtseqs'] = 10
        request['arRequestedProtseqs'] = (1,2,3,4,5,6,7,8,9,10)
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('OR_INVALID_OXID') < 0:
                raise

    def tes_ResolveOxid2(self):
        dce, rpctransport = self.connect()
        dce.bind(dcomrt.IID_IObjectExporter, transfer_syntax=self.ts)
        request = dcomrt.ResolveOxid2()
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
        dce.bind(dcomrt.IID_IActivation, transfer_syntax=self.ts)
        request = dcomrt.RemoteActivation()
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
        dce.bind(dcomrt.IID_IRemoteSCMActivator, transfer_syntax=self.ts)
        request = dcomrt.RemoteGetClassObject()
        request['ORPCthis']['extensions'] = NULL
        request['pActProperties'] = NULL
        resp = dce.request(request)
        resp.dump()

    def tes_RemoteCreateInstance(self):
        dce, rpctransport = self.connect()
        dce.bind(dcomrt.IID_IRemoteSCMActivator, transfer_syntax=self.ts)

        ORPCthis = dcomrt.ORPCTHIS()
        ORPCthis['cid'] = generate()
        ORPCthis['extensions'] = NULL
        ORPCthis['flags'] = 1

        request = dcomrt.RemoteCreateInstance()
        request['ORPCthis'] = ORPCthis
        request['pUnkOuter'] = NULL

        activationBLOB = dcomrt.ACTIVATION_BLOB()
        activationBLOB['CustomHeader']['destCtx'] = 2
        activationBLOB['CustomHeader']['pdwReserved'] = NULL
        clsid = dcomrt.CLSID()
        clsid['Data'] = dcomrt.CLSID_InstantiationInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)
        clsid = dcomrt.CLSID()
        clsid['Data'] = dcomrt.CLSID_ActivationContextInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)
        clsid = dcomrt.CLSID()
        clsid['Data'] = dcomrt.CLSID_ServerLocationInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)
        clsid = dcomrt.CLSID()
        clsid['Data'] = dcomrt.CLSID_ScmRequestInfo
        activationBLOB['CustomHeader']['pclsid'].append(clsid)

        properties = ''
        # InstantiationInfo
        instantiationInfo = dcomrt.InstantiationInfoData()
        CLSID_EventSystem = '4E14FBA2-2E22-11D1-9964-00C04FBBB345'
        #instantiationInfo['classId'] = string_to_bin('ECABB0C4-7F19-11D2-978E-0000F8757E2A')
        #instantiationInfo['classId'] = string_to_bin('EE3D513B-93A7-4e90-9458-7F8602547363')
        instantiationInfo['classId'] = string_to_bin(CLSID_EventSystem)
        instantiationInfo['classId'] = string_to_bin('0b5a2c52-3eb9-470a-96e2-6c6d4570e40f')
        instantiationInfo['cIID'] = 1

        iid = dcomrt.IID()
        #iid['Data'] = string_to_bin('23C9DD26-2355-4FE2-84DE-F779A238ADBD')
        IVssSnapshotMgmt = 'FA7DF749-66E7-4986-A27F-E2F04AE53772'
        iid['Data'] = string_to_bin(IVssSnapshotMgmt)

        instantiationInfo['pIID'].append(iid)

        dword = DWORD()
        marshaled = instantiationInfo.getData()+instantiationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activationBLOB['CustomHeader']['pSizes'].append(dword)
        instantiationInfo['thisSize'] = dword['Data']

        properties += marshaled + '\xFA'*pad

        # ActivationContextInfoData
        activationInfo = dcomrt.ActivationContextInfoData()
        activationInfo['pIFDClientCtx'] = NULL
        activationInfo['pIFDPrototypeCtx'] = NULL

        dword = DWORD()
        marshaled = activationInfo.getData()+activationInfo.getDataReferents()
        pad = (8 - (len(marshaled) % 8)) % 8
        dword['Data'] = len(marshaled) + pad
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += marshaled + '\xFA'*pad

        # ServerLocation
        locationInfo = dcomrt.LocationInfoData()
        locationInfo['machineName'] = NULL

        dword = DWORD()
        dword['Data'] = len(locationInfo.getData())
        activationBLOB['CustomHeader']['pSizes'].append(dword)

        properties += locationInfo.getData()+locationInfo.getDataReferents()

        # ScmRequestInfo
        scmInfo = dcomrt.ScmRequestInfoData()
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


        objrefcustom = dcomrt.OBJREF_CUSTOM()
        objrefcustom['iid'] = dcomrt.IID_IActivationPropertiesIn[:-4]
        objrefcustom['clsid'] = dcomrt.CLSID_ActivationPropertiesIn

        objrefcustom['pObjectData'] = activationBLOB.getData()
        objrefcustom['ObjectReferenceSize'] = len(objrefcustom['pObjectData'])+8

        request['pActProperties']['ulCntData'] = len(str(objrefcustom))
        request['pActProperties']['abData'] = list(str(objrefcustom))
        resp = dce.request(request)

        objRefType = dcomrt.OBJREF(''.join(resp['ppActProperties']['abData']))['flags']
        dcomrt.OBJREF(''.join(resp['ppActProperties']['abData'])).dump()
        if objRefType == dcomrt.FLAGS_OBJREF_CUSTOM:
            objRef = dcomrt.OBJREF_CUSTOM(''.join(resp['ppActProperties']['abData']))
        elif objRefType == dcomrt.FLAGS_OBJREF_HANDLER:
            objRef = dcomrt.OBJREF_HANDLER(''.join(resp['ppActProperties']['abData']))
        elif objRefType == dcomrt.FLAGS_OBJREF_STANDARD:
            objRef = dcomrt.OBJREF_STANDARD(''.join(resp['ppActProperties']['abData']))
        elif objRefType == dcomrt.FLAGS_OBJREF_EXTENDED:
            objRef = dcomrt.OBJREF_EXTENDED(''.join(resp['ppActProperties']['abData']))
        else:
            print "Unknown OBJREF Type! 0x%x" % objRefType


        activationBlob = dcomrt.ACTIVATION_BLOB(objRef['pObjectData'])

        propOutput = activationBlob['Property'][:activationBlob['CustomHeader']['pSizes'][0]['Data']]
        scmReply = activationBlob['Property'][activationBlob['CustomHeader']['pSizes'][0]['Data']:activationBlob['CustomHeader']['pSizes'][0]['Data']+activationBlob['CustomHeader']['pSizes'][1]['Data']]

        scmr = dcomrt.ScmReplyInfoData()
        scmr.fromString(scmReply)
        # Processing the scmReply
        scmReply = scmReply[len(scmr.getData()):]
        hexdump(scmReply)
        scmr.fromStringReferents(scmReply)
        scmr.dump()
        Oxids = ''.join(pack('<H', x) for x in scmr['remoteReply']['pdsaOxidBindings']['aStringArray'])
        strBindings = Oxids[:scmr['remoteReply']['pdsaOxidBindings']['wSecurityOffset']*2]
        securityBindings = Oxids[scmr['remoteReply']['pdsaOxidBindings']['wSecurityOffset']*2:]
        print "\nBindings "
        done = False
        stringBindings = list()
        while not done:
            if strBindings[0] == '\x00' and strBindings[1] == '\x00':
                done = True
            else:
                binding = dcomrt.STRINGBINDING(strBindings)
                binding.dump()
                stringBindings.append(binding)
                print "\n"
                strBindings = strBindings[len(binding):]
        print "Security Bindings"
        done = False
        while not done:
            if securityBindings[0] == '\x00' and securityBindings[1] == '\x00':
                done = True
            else:
                secBinding = dcomrt.SECURITYBINDING(securityBindings)
                secBinding.dump()
                print "\n"
                securityBindings = securityBindings[len(secBinding):]

        # Processing the Properties Output
        propsOut = dcomrt.PropsOutInfo(propOutput)
        propOutput = propOutput[len(propsOut):]
        propsOut.fromStringReferents(propOutput)

        objRefType = dcomrt.OBJREF(''.join(propsOut['ppIntfData'][0]['abData'][4:]))['flags']
        if objRefType == dcomrt.FLAGS_OBJREF_CUSTOM:
            objRef = dcomrt.OBJREF_CUSTOM(''.join(propsOut['ppIntfData'][0]['abData'][4:]))
        elif objRefType == dcomrt.FLAGS_OBJREF_HANDLER:
            objRef = dcomrt.OBJREF_HANDLER(''.join(propsOut['ppIntfData'][0]['abData'][4:]))
        elif objRefType == dcomrt.FLAGS_OBJREF_STANDARD:
            objRef = dcomrt.OBJREF_STANDARD(''.join(propsOut['ppIntfData'][0]['abData'][4:]))
        elif objRefType == dcomrt.FLAGS_OBJREF_EXTENDED:
            objRef = dcomrt.OBJREF_EXTENDED(''.join(propsOut['ppIntfData'][0]['abData'][4:]))
        else:
            print "Unknown OBJREF Type! 0x%x" % objRefType

        objRef.dump()
        print '\n'
  
        iPid = objRef['std']['ipid']
        stringBinding = 'ncacn_ip_tcp:' + stringBindings[1]['aNetworkAddr'][:-1]
        print stringBinding
        print '\n'

        dcomInterface = transport.DCERPCTransportFactory(stringBinding)
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''
        if hasattr(dcomInterface, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            dcomInterface.set_credentials(self.username,self.password, self.domain, lmhash, nthash)
        dce = dcomInterface.get_dce_rpc()
        #dce.set_auth_level(ntlm.NTLM_AUTH_PKT_INTEGRITY)
        dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)
        dce.connect()
        dce.bind(string_to_bin(IVssSnapshotMgmt), transfer_syntax=self.ts)

        ORPCthis['flags'] = 0

        req = dcomrt.GetProviderMgmtInterface()
        req['ORPCthis'] = ORPCthis
        req['ProviderId'] = string_to_bin('AE1C7110-2F60-11d3-8A39-00C04F72D8E3')
        req['InterfaceId'] = string_to_bin('214A0F28-B737-4026-B847-4F9E37D79529')
        #resp = dce.request(req, uuid = iPid)
        #resp.dump()
     
        req = dcomrt.QueryVolumesSupportedForSnapshots()
        req['ORPCthis'] = ORPCthis
        req['ProviderId'] = string_to_bin('B5946137-7B9F-4925-AF80-51ABD60B20D5')
        req['IContext'] = 31
        resp = dce.request(req, uuid = iPid)
        #resp.dump()

        objRefType = dcomrt.OBJREF(''.join(resp['ppEnum']['abData']))['flags']
        if objRefType == dcomrt.FLAGS_OBJREF_CUSTOM:
            objRef = dcomrt.OBJREF_CUSTOM(''.join(resp['ppEnum']['abData']))
        elif objRefType == dcomrt.FLAGS_OBJREF_HANDLER:
            objRef = dcomrt.OBJREF_HANDLER(''.join(resp['ppEnum']['abData']))
        elif objRefType == dcomrt.FLAGS_OBJREF_STANDARD:
            objRef = dcomrt.OBJREF_STANDARD(''.join(resp['ppEnum']['abData']))
        elif objRefType == dcomrt.FLAGS_OBJREF_EXTENDED:
            objRef = dcomrt.OBJREF_EXTENDED(''.join(resp['ppEnum']['abData']))
        else:
            print "Unknown OBJREF Type! 0x%x" % objRefType

        objRef.dump()
        print '\n'

    def tes_hRemoteCreateInstance(self):
        dce, rpctransport = self.connect()

        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(scmp.CLSID_ShadowCopyProvider, scmp.IID_IVssSnapshotMgmt)
        iVssSnapshotMgmt = scmp.IVssSnapshotMgmt(iInterface)
        #iVssSnapshotMgmt.RemRelease()
        
        iVssEnumMgmtObject = iVssSnapshotMgmt.QueryVolumesSupportedForSnapshots(scmp.IID_ShadowCopyProvider, 31) 
        resp = iVssEnumMgmtObject.Next(10)
        #iVssEnumObject = iVssSnapshotMgmt.QuerySnapshotsByVolume('C:\x00')

        #iProviderMgmtInterface = iVssSnapshotMgmt.GetProviderMgmtInterface()
        #enumObject =iProviderMgmtInterface.QueryDiffAreasOnVolume('C:\x00')
        #iVssSnapshotMgmt.RemQueryInterface(1, (scmp.IID_IVssEnumMgmtObject,))
        #iVssSnapshotMgmt.RemAddRef()
        #iVssSnapshotMgmt = dcom.hRemoteCreateInstance(dce, scmp.CLSID_ShadowCopyProvider, dcom.IID_IRemUnknown)
    
        #iVssEnumMgmtObject.RemQueryInterface(1, (scmp.IID_IVssEnumMgmtObject,))

    def tes_vds(self):
        dce, rpctransport = self.connect()

        #objExporter = dcom.IObjectExporter(dce)
        #objExporter.ComplexPing()
        #objExporter.ComplexPing()

        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(vds.CLSID_VirtualDiskService, vds.IID_IVdsServiceInitialization)
        serviceInitialization = vds.IVdsServiceInitialization(iInterface)
        serviceInitialization.Initialize()
        
        iInterface = serviceInitialization.RemQueryInterface(1, (vds.IID_IVdsService,))
        vdsService = vds.IVdsService(iInterface)
   
        resp = vdsService.IsServiceReady()
        while resp['ErrorCode'] == 1:
            print "Waiting.. "
            resp = vdsService.IsServiceReady()

        vdsService.WaitForServiceReady()
        vdsService.GetProperties()
        enumObject = vdsService.QueryProviders(1)
        interfaces = enumObject.Next(1)
        iii = interfaces[0].RemQueryInterface(1, (vds.IID_IVdsProvider,))
        provider = vds.IVdsProvider(iii)
        resp = provider.GetProperties()
        resp.dump()

    def tes_RemQueryInterface(self):
        dce, rpctransport = self.connect()
        dce.bind(dcomrt.IID_IRemUnknown2, transfer_syntax=self.ts)
        request = dcomrt.RemQueryInterface()
        resp = dce.request(request)
        resp.dump()

    def tes_oaut(self):
        dce, rpctransport = self.connect()
        IID_IDispatch = string_to_bin('00020400-0000-0000-C000-000000000046')
        IID_ITypeInfo = string_to_bin('00020401-0000-0000-C000-000000000046')
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(string_to_bin('4E14FBA2-2E22-11D1-9964-00C04FBBB345'), IID_IDispatch)
        iDispatch = oaut.IDispatch(iInterface)
        kk = iDispatch.GetTypeInfoCount()
        kk.dump()
        iTypeInfo = iDispatch.GetTypeInfo()
        iTypeInfo.GetTypeAttr()

    def test_comev(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        iEventSystem = comev.IEventSystem(iInterface)
        iEventSystem.get_EventObjectChangeEventClassID()

        objCollection = iEventSystem.Query('EventSystem.EventSubscriptionCollection', 'ALL')

        resp = objCollection.get_Count()
        count = resp['pCount']

        evnObj = objCollection.get_NewEnum()
        #for i in range(count):
        for i in range(1):
            iUnknown = evnObj.Next(1)[0]
            es = iUnknown.RemQueryInterface(1, (comev.IID_IEventSubscription3,))
            es = comev.IEventSubscription3(es)

            es.get_SubscriptionID()
            #print es.get_SubscriptionName()['pbstrSubscriptionName']['asData']
            ##es.get_PublisherID()
            #es.get_EventClassID()
            #es.get_MethodName()
            ##es.get_SubscriberCLSID()
            #es.get_SubscriberInterface()
            #es.get_PerUser()
            #es.get_OwnerSID()
            #es.get_Enabled()
            ##es.get_Description()
            ##es.get_MachineName()
            ##es.GetPublisherProperty()
            #es.GetPublisherPropertyCollection()
            ##es.GetSubscriberProperty()
            #es.GetSubscriberPropertyCollection()
            #es.get_InterfaceID()
            es.RemRelease()


        objCollection = iEventSystem.Query('EventSystem.EventClassCollection', 'ALL')
        resp = objCollection.get_Count()
        count = resp['pCount']

        #objCollection.get_Item('EventClassID={D5978630-5B9F-11D1-8DD2-00AA004ABD5E}')
        evnObj = objCollection.get_NewEnum()
        for i in range(count):

            iUnknown = evnObj.Next(1)[0]

            ev = iUnknown.RemQueryInterface(1, (comev.IID_IEventClass2,))
            ev = comev.IEventClass2(ev)

            ev.get_EventClassID() 
            #ev.get_EventClassName() 
            #ev.get_OwnerSID() 
            #ev.get_FiringInterfaceID() 
            #ev.get_Description() 
            #try:
            #    ev.get_TypeLib() 
            #except:
            #    pass

            #ev.get_PublisherID()
            #ev.get_MultiInterfacePublisherFilterCLSID()
            #ev.get_AllowInprocActivation()
            #ev.get_FireInParallel()
            ev.RemRelease()

        print "="*80

        #eventSubscription.get_SubscriptionID()


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
