###############################################################################
#  Tested so far: 
#  LsarOpenPolicy2
#  LsarOpenPolicy
#  LsarQueryInformationPolicy2
#  LsarQueryInformationPolicy
#  LsarQueryDomainInformationPolicy
#  LsarEnumerateAccounts
#  LsarEnumerateAccountsWithUserRight
#  LsarEnumerateTrustedDomainsEx
#  LsarEnumerateTrustedDomains
#  LsarOpenAccount
#  LsarClose
#  LsarCreateAccount
#  LsarDeleteObject
#  LsarEnumeratePrivilegesAccount
#  LsarGetSystemAccessAccount
#  LsarSetSystemAccessAccount
#  LsarAddPrivilegesToAccount
#  LsarRemovePrivilegesFromAccount
#  LsarEnumerateAccountRights
#  LsarAddAccountRights
#  LsarRemoveAccountRights
#  LsarCreateSecret
#  LsarOpenSecret
#  LsarSetSecret
#  LsarQuerySecret
#  LsarRetrievePrivateData
#  LsarStorePrivateData
#  LsarEnumeratePrivileges
#  LsarLookupPrivilegeValue
#  LsarLookupPrivilegeName
#  LsarLookupPrivilegeDisplayName
#  LsarQuerySecurityObject
#  LsarSetSecurityObject
#  LsarQueryForestTrustInformation
#
#  Not yet:
#
################################################################################

import sys
import unittest
import ConfigParser
from struct import pack, unpack

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm, lsad
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.dtypes import *
from impacket.winregistry import hexdump
from impacket.uuid import string_to_bin, uuidtup_to_bin
from impacket import system_errors

class LSADTests(unittest.TestCase):
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
        dce.bind(lsad.MSRPC_UUID_LSAD)
        request = lsad.LsarOpenPolicy2()
        request['SystemName'] = NULL
        request['ObjectAttributes']['RootDirectory'] = NULL
        request['ObjectAttributes']['ObjectName'] = NULL
        request['ObjectAttributes']['SecurityDescriptor'] = NULL
        request['ObjectAttributes']['SecurityQualityOfService'] = NULL
        request['DesiredAccess'] = MAXIMUM_ALLOWED | lsad.POLICY_CREATE_SECRET | DELETE | lsad.POLICY_VIEW_LOCAL_INFORMATION
        resp = dce.request(request)

        return dce, rpctransport, resp['PolicyHandle']

    def test_LsarOpenPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarOpenPolicy()
        request['SystemName'] = NULL
        request['ObjectAttributes']['RootDirectory'] = NULL
        request['ObjectAttributes']['ObjectName'] = NULL
        request['ObjectAttributes']['SecurityDescriptor'] = NULL
        request['ObjectAttributes']['SecurityQualityOfService'] = NULL
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

    def test_LsarQueryInformationPolicy2(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy2()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditLogInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPdAccountInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation
        resp = dce.request(request)
        #resp.dump()

    def test_LsarQueryInformationPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditLogInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPdAccountInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt
        resp = dce.request(request)
        #resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation
        resp = dce.request(request)
        #resp.dump()

    def test_LsarQueryDomainInformationPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryDomainInformationPolicy()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainQualityOfServiceInformation
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_PARAMETER') < 0:
                raise

        request['InformationClass'] = lsad.POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainEfsInformation
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') < 0:
                raise

        request['InformationClass'] = lsad.POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainKerberosTicketInformation
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') < 0:
                raise

    def test_LsarEnumerateAccounts(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarEnumerateAccounts()
        request['PolicyHandle'] = policyHandle
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        #resp.dump()
        #for i in range(resp['EnumerationBuffer']['EntriesRead']):
        #    print resp['EnumerationBuffer']['Information'][i]['Sid'].formatCanonical()

    def test_LsarEnumerateAccountsWithUserRight(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarEnumerateAccountsWithUserRight()
        request['PolicyHandle'] = policyHandle
        request['UserRight'] = 'SeSystemtimePrivilege'
        resp = dce.request(request)
        #resp.dump()

    def test_LsarEnumerateTrustedDomainsEx(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarEnumerateTrustedDomainsEx()
        request['PolicyHandle'] = policyHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 0xffffffff
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_MORE_ENTRIES') < 0:
                raise

    def test_LsarEnumerateTrustedDomains(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarEnumerateTrustedDomains()
        request['PolicyHandle'] = policyHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 0xffffffff
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_MORE_ENTRIES') < 0:
                raise

    def test_LsarOpenAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarEnumerateAccounts()
        request['PolicyHandle'] = policyHandle
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarOpenAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'] = resp['EnumerationBuffer']['Information'][0]['Sid']
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarClose()
        request['ObjectHandle'] = resp['AccountHandle']
        resp = dce.request(request)
        #resp.dump()

    def test_LsarCreateAccount_LsarDeleteObject(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy2()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        resp = dce.request(request)

        sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        sid = sid + '-9999'

        request = lsad.LsarCreateAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarDeleteObject()
        request['ObjectHandle'] = resp['AccountHandle']
        resp = dce.request(request)
        #resp.dump()

    def test_LsarEnumeratePrivilegesAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        request = lsad.LsarOpenAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarEnumeratePrivilegesAccount()
        request['AccountHandle'] = resp['AccountHandle']
        resp = dce.request(request)
        #resp.dump()

    def test_LsarGetSystemAccessAccount_LsarSetSystemAccessAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        request = lsad.LsarOpenAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarGetSystemAccessAccount()
        request['AccountHandle'] = resp['AccountHandle']
        resp2 = dce.request(request)
        #resp.dump()

        request = lsad.LsarSetSystemAccessAccount()
        request['AccountHandle'] = resp['AccountHandle']
        request['SystemAccess'] = resp2['SystemAccess']
        resp = dce.request(request)
        #resp.dump()

    def test_LsarAddPrivilegesToAccount_LsarRemovePrivilegesFromAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy2()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        resp = dce.request(request)

        sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        sid = sid + '-9999'

        request = lsad.LsarCreateAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['DesiredAccess'] = MAXIMUM_ALLOWED | lsad.ACCOUNT_ADJUST_PRIVILEGES
        resp = dce.request(request)
        #resp.dump()
        accountHandle = resp['AccountHandle']

        request = lsad.LsarAddPrivilegesToAccount()
        request['AccountHandle'] = accountHandle
        request['Privileges']['PrivilegeCount'] = 1
        request['Privileges']['Control'] = 0
        attribute = lsad.LSAPR_LUID_AND_ATTRIBUTES()
        attribute['Luid']['LowPart'] = 0
        attribute['Luid']['HighPart'] = 3
        attribute['Attributes'] = 3
        request['Privileges']['Privilege'].append(attribute)
        try:
            resp = dce.request(request)
            resp.dump()
        except:
            request = lsad.LsarDeleteObject()
            request['ObjectHandle'] = accountHandle
            resp = dce.request(request)
            return

        request = lsad.LsarRemovePrivilegesFromAccount()
        request['AccountHandle'] = accountHandle
        request['AllPrivileges'] = 1
        request['Privileges'] = NULL
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarDeleteObject()
        request['ObjectHandle'] = accountHandle
        resp = dce.request(request)
        #resp.dump()

    def test_LsarEnumerateAccountRights(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        request = lsad.LsarEnumerateAccountRights()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        resp = dce.request(request)
        #resp.dump()

    def test_LsarAddAccountRights_LsarRemoveAccountRights(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-504'

        request = lsad.LsarAddAccountRights()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['UserRights']['EntriesRead'] = 1
        right = RPC_UNICODE_STRING()
        right['Data'] = 'SeChangeNotifyPrivilege'
        request['UserRights']['UserRights'].append(right)
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarRemoveAccountRights()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['UserRights']['EntriesRead'] = 1
        right = RPC_UNICODE_STRING()
        right['Data'] = 'SeChangeNotifyPrivilege'
        request['UserRights']['UserRights'].append(right)
        resp = dce.request(request)
        #resp.dump()

    def test_LsarCreateSecret_LsarOpenSecret(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarCreateSecret()
        request['PolicyHandle'] = policyHandle
        request['SecretName'] = 'MYSECRET'
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarOpenSecret()
        request['PolicyHandle'] = policyHandle
        request['SecretName'] = 'MYSECRET'
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp0 = dce.request(request)
        #resp0.dump()

        request = lsad.LsarSetSecret()
        request['SecretHandle'] = resp0['SecretHandle']
        request['EncryptedCurrentValue']['Length'] = 16
        request['EncryptedCurrentValue']['MaximumLength'] = 16
        request['EncryptedCurrentValue']['Buffer'] = list('A'*16)
        request['EncryptedOldValue']['Length'] = 16
        request['EncryptedOldValue']['MaximumLength'] = 16
        request['EncryptedOldValue']['Buffer'] = list('A'*16)
        #request['EncryptedCurrentValue'] = NULL
        #request['EncryptedOldValue'] = NULL
        try:
            resp = dce.request(request)
            #resp.dump()
        except: 
            pass

        request = lsad.LsarDeleteObject()
        request['ObjectHandle'] = resp0['SecretHandle']
        resp = dce.request(request)
        #resp.dump()

    def test_LsarQuerySecret(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarOpenSecret()
        request['PolicyHandle'] = policyHandle
        request['SecretName'] = 'DPAPI_SYSTEM'
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp0 = dce.request(request)
        #resp0.dump()

        request = lsad.LsarQuerySecret()
        request['SecretHandle'] = resp0['SecretHandle']
        request['EncryptedCurrentValue']['Buffer'] = NULL
        request['EncryptedOldValue']['Buffer'] = NULL
        request['OldValueSetTime'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_LsarRetrievePrivateData_LsarStorePrivateData(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarRetrievePrivateData()
        request['PolicyHandle'] = policyHandle
        request['KeyName'] = 'DPAPI_SYSTEM'
        resp0 = dce.request(request)
        #resp0.dump()

        request = lsad.LsarStorePrivateData()
        request['PolicyHandle'] = policyHandle
        request['KeyName'] = 'BETUS'
        request['EncryptedData'] = resp0['EncryptedData']
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarStorePrivateData()
        request['PolicyHandle'] = policyHandle
        request['KeyName'] = 'BETUS'
        request['EncryptedData'] = NULL
        resp = dce.request(request)
        #resp.dump()

    def test_LsarEnumeratePrivileges(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarEnumeratePrivileges()
        request['PolicyHandle'] = policyHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        #resp.dump()

        self.assertTrue( resp['EnumerationBuffer']['Entries'] == len(resp['EnumerationBuffer']['Privileges'] ) )

    def test_LsarLookupPrivilegeValue_LsarLookupPrivilegeName(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarLookupPrivilegeValue()
        request['PolicyHandle'] = policyHandle
        request['Name'] = u'SeTimeZonePrivilege'
        resp = dce.request(request)
        #resp.dump()

        request = lsad.LsarLookupPrivilegeName()
        request['PolicyHandle'] = policyHandle
        request['Value'] = resp['Value']
        resp = dce.request(request)
        #resp.dump()

        self.assertTrue( resp['Name'] == 'SeTimeZonePrivilege')

    def test_LsarLookupPrivilegeDisplayName(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarLookupPrivilegeDisplayName()
        request['PolicyHandle'] = policyHandle
        request['Name'] = u'SeTimeZonePrivilege'
        request['ClientLanguage'] = 1
        request['ClientSystemDefaultLanguage'] = 1
        resp = dce.request(request)
        #resp.dump()

    def test_LsarQuerySecurityObject_LsarSetSecurityObject(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarQuerySecurityObject()
        request['PolicyHandle'] = policyHandle
        request['SecurityInformation'] = lsad.OWNER_SECURITY_INFORMATION
        resp = dce.request(request)
        #resp.dump()

        self.assertTrue( resp['SecurityDescriptor']['Length'] == len(resp['SecurityDescriptor']['SecurityDescriptor']) )

        request = lsad.LsarSetSecurityObject()
        request['PolicyHandle'] = policyHandle
        request['SecurityInformation'] = lsad.OWNER_SECURITY_INFORMATION
        request['SecurityDescriptor'] = resp['SecurityDescriptor']
        resp = dce.request(request)
        #resp.dump()

    def test_LsarQueryForestTrustInformation(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarQueryForestTrustInformation()
        request['PolicyHandle'] = policyHandle
        request['TrustedDomainName'] = 'CORE'
        request['HighestRecordType'] = lsad.LSA_FOREST_TRUST_RECORD_TYPE.ForestTrustTopLevelName
        try:
            resp = dce.request(request)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_DOMAIN_STATE') < 0:
                raise

class SMBTransport(LSADTests):
    def setUp(self):
        LSADTests.setUp(self)
        configFile = ConfigParser.ConfigParser()
        configFile.read('dcetests.cfg')
        self.username = configFile.get('SMBTransport', 'username')
        self.domain   = configFile.get('SMBTransport', 'domain')
        self.serverName = configFile.get('SMBTransport', 'servername')
        self.password = configFile.get('SMBTransport', 'password')
        self.machine  = configFile.get('SMBTransport', 'machine')
        self.hashes   = configFile.get('SMBTransport', 'hashes')
        self.stringBinding = r'ncacn_np:%s[\PIPE\lsarpc]' % self.machine

# Process command-line arguments.
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        testcase = sys.argv[1]
        suite = unittest.TestLoader().loadTestsFromTestCase(globals()[testcase])
    else:
        suite = unittest.TestLoader().loadTestsFromTestCase(SMBTransport)
    unittest.TextTestRunner(verbosity=1).run(suite)
