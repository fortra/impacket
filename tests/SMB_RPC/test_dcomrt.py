###############################################################################
#  Tested so far: 
#
# Since DCOM is more high level, I'll always use the helper classes
# ServerAlive
# ServerAlive2
# ComplexPing
# SimplePing
# RemoteCreateInstance
# ResolveOxid
# ResolveOxid2
# RemoteActivation
# RemRelease
# RemoteGetClassObject
#
#  Not yet:
#
# 
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5.dcom import scmp, vds, oaut, comev
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket import ntlm


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
        objExporter = dcomrt.IObjectExporter(dce)
        resp = objExporter.ServerAlive()
        #resp.dump()

    def test_ServerAlive2(self):
        dce, rpctransport = self.connect()
        objExporter = dcomrt.IObjectExporter(dce)
        stringBindings = objExporter.ServerAlive2()
        #for binding in stringBindings:
        #    binding.dump()

    def test_ComplexPing_SimplePing(self):
        dce, rpctransport = self.connect()
        objExporter = dcomrt.IObjectExporter(dce)
        resp = objExporter.ComplexPing()
        resp = objExporter.SimplePing(resp['pSetId'])

    def test_ResolveOxid(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        objExporter = dcomrt.IObjectExporter(dce)
        stringBindings = objExporter.ResolveOxid(iInterface.get_oxid(), (7,))
        #for binding in stringBindings:
        #    binding.dump()

    def test_ResolveOxid2(self):
        dce, rpctransport = self.connect()
        #scm = dcomrt.IRemoteSCMActivator(dce)
        #iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        scm = dcomrt.IActivation(dce)
        iInterface = scm.RemoteActivation(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        objExporter = dcomrt.IObjectExporter(dce)
        stringBindings = objExporter.ResolveOxid2(iInterface.get_oxid(), (7,))
        #for binding in stringBindings:
        #    binding.dump()

    def test_RemoteActivation(self):
        dce, rpctransport = self.connect()
        scm = dcomrt.IActivation(dce)
        iInterface = scm.RemoteActivation(comev.CLSID_EventSystem, comev.IID_IEventSystem)

    def test_RemoteGetClassObject(self):
        dce, rpctransport = self.connect()
        IID_IClassFactory = uuidtup_to_bin(('00000001-0000-0000-C000-000000000046','0.0'))
        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteGetClassObject(comev.CLSID_EventSystem, IID_IClassFactory)
        iInterface.RemRelease()


    def test_RemQueryInterface(self):
        dcom = dcomrt.DCOMConnection(self.machine, self.username, self.password, self.domain)
        iInterface = dcom.CoCreateInstanceEx(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        iEventSystem = comev.IEventSystem(iInterface)
        iEventSystem.RemQueryInterface(1, (comev.IID_IEventSystem,))
        dcom.disconnect()

    def test_RemRelease(self):
        dcom = dcomrt.DCOMConnection(self.machine, self.username, self.password, self.domain)
        iInterface = dcom.CoCreateInstanceEx(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        iEventSystem = comev.IEventSystem(iInterface)
        iEventSystem.RemRelease()
        dcom.disconnect()

    def test_RemoteCreateInstance(self):
        dce, rpctransport = self.connect()

        scm = dcomrt.IRemoteSCMActivator(dce)
        iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)

    def tes_scmp(self):
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

    def tes_comev(self):
        if len(self.hashes) > 0:
            lmhash, nthash = self.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        dcom = dcomrt.DCOMConnection(self.machine, self.username, self.password, self.domain, lmhash, nthash)
        iInterface = dcom.CoCreateInstanceEx(comev.CLSID_EventSystem, comev.IID_IEventSystem)

        #scm = dcomrt.IRemoteSCMActivator(dce)
        
        #iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem, comev.IID_IEventSystem)
        #iInterface = scm.RemoteCreateInstance(comev.CLSID_EventSystem,oaut.IID_IDispatch)
        iDispatch = oaut.IDispatch(iInterface)
        #scm = dcomrt.IRemoteSCMActivator(dce)
        #resp = iDispatch.GetIDsOfNames(('Navigate\x00', 'ExecWB\x00'))
        #resp.dump()
        iEventSystem = comev.IEventSystem(iInterface)
        iTypeInfo = iEventSystem.GetTypeInfo()
        resp = iTypeInfo.GetTypeAttr()
        #resp.dump()
        for i in range(1,resp['ppTypeAttr']['cFuncs']):
            resp = iTypeInfo.GetFuncDesc(i)
            #resp.dump()
            resp2 = iTypeInfo.GetNames(resp['ppFuncDesc']['memid'])
            #resp2.dump()
            resp = iTypeInfo.GetDocumentation(resp['ppFuncDesc']['memid'])
            #resp.dump()
        #iEventSystem.get_EventObjectChangeEventClassID()
        iEventSystem.RemRelease()
        iTypeInfo.RemRelease()

        objCollection = iEventSystem.Query('EventSystem.EventSubscriptionCollection', 'ALL')

        resp = objCollection.get_Count()
        count = resp['pCount']

        evnObj = objCollection.get_NewEnum()
        #for i in range(count-1):
        for i in range(3):
            iUnknown = evnObj.Next(1)[0]
            es = iUnknown.RemQueryInterface(1, (comev.IID_IEventSubscription3,))
            es = comev.IEventSubscription3(es)

            #es.get_SubscriptionID()
            print es.get_SubscriptionName()['pbstrSubscriptionName']['asData']
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
        #for i in range(count-1):
        for i in range(3):

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

        dcom.disconnect()
        #eventSubscription.get_SubscriptionID()


    # def tes_ie(self):
    #     dce, rpctransport = self.connect()
    #     scm = dcomrt.IRemoteSCMActivator(dce)
    #
    #     #iInterface = scm.RemoteCreateInstance(string_to_bin('0002DF01-0000-0000-C000-000000000046'),ie.IID_WebBrowser)
    #     iInterface = scm.RemoteCreateInstance(string_to_bin('72C24DD5-D70A-438B-8A42-98424B88AFB8'),dcomrt.IID_IRemUnknown)
    #
    #     iDispatch = ie.IWebBrowser(iInterface)
    #     resp = iDispatch.GetIDsOfNames(('Navigate',))
    #     print resp
    #     #sys.exit(1)
    #     iTypeInfo = iDispatch.GetTypeInfo()
    #     resp = iTypeInfo.GetTypeAttr()
    #     #resp.dump()
    #     for i in range(0,resp['ppTypeAttr']['cFuncs']):
    #         resp = iTypeInfo.GetFuncDesc(i)
    #         #resp.dump()
    #         #resp2 = iTypeInfo.GetNames(resp['ppFuncDesc']['memid'])
    #         #print resp2['rgBstrNames'][0]['asData']
    #         resp = iTypeInfo.GetDocumentation(resp['ppFuncDesc']['memid'])
    #         print resp['pBstrName']['asData']
    #     #iEventSystem.get_EventObjectChangeEventClassID()
    #     print "ACA"
    #     iTypeInfo.RemRelease()
    #     iDispatch.RemRelease()
    #
    #     sys.exit(1)

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
        suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TCPTransport64))
    unittest.TextTestRunner(verbosity=1).run(suite)
