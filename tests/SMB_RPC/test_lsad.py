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
#  LsarSetInformationPolicy
#  LsarSetInformationPolicy2
#
#  Not yet:
#
# Shouldn't dump errors against a win7
#
################################################################################

import unittest
import ConfigParser

from impacket.dcerpc.v5 import transport, epm, lsad
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, RPC_UNICODE_STRING, DELETE

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
        dce.bind(lsad.MSRPC_UUID_LSAD, transfer_syntax = self.ts)
        resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsad.POLICY_CREATE_SECRET | DELETE | lsad.POLICY_VIEW_LOCAL_INFORMATION)

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
        resp.dump()

    def test_hLsarOpenPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarOpenPolicy(dce)
        resp.dump()

    def test_LsarQueryInformationPolicy2(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy2()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditLogInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPdAccountInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation
        resp = dce.request(request)
        resp.dump()

    def test_hLsarQueryInformationPolicy2(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditLogInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPdAccountInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation)
        resp.dump()

    def test_LsarQueryInformationPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditLogInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPdAccountInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt
        resp = dce.request(request)
        resp.dump()

        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation
        resp = dce.request(request)
        resp.dump()

    def test_hLsarQueryInformationPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditLogInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPdAccountInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyLsaServerRoleInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyReplicaSourceInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformationInt)
        resp.dump()

        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyLocalAccountDomainInformation)
        resp.dump()

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

    def test_hLsarQueryDomainInformationPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        try:
            resp = lsad.hLsarQueryDomainInformationPolicy(dce, policyHandle, lsad.POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainQualityOfServiceInformation)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_INVALID_PARAMETER') < 0:
                raise

        try:
            resp = lsad.hLsarQueryDomainInformationPolicy(dce, policyHandle, lsad.POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainEfsInformation)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') < 0:
                raise

        try:
            resp = lsad.hLsarQueryDomainInformationPolicy(dce, policyHandle, lsad.POLICY_DOMAIN_INFORMATION_CLASS.PolicyDomainKerberosTicketInformation)
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
        resp.dump()
        #for i in range(resp['EnumerationBuffer']['EntriesRead']):
        #    print resp['EnumerationBuffer']['Information'][i]['Sid'].formatCanonical()

    def test_hLsarEnumerateAccounts(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarEnumerateAccounts(dce, policyHandle)
        resp.dump()
        #for i in range(resp['EnumerationBuffer']['EntriesRead']):
        #    print resp['EnumerationBuffer']['Information'][i]['Sid'].formatCanonical()

    def test_LsarEnumerateAccountsWithUserRight(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarEnumerateAccountsWithUserRight()
        request['PolicyHandle'] = policyHandle
        request['UserRight'] = 'SeSystemtimePrivilege'
        resp = dce.request(request)
        resp.dump()

    def test_hLsarEnumerateAccountsWithUserRight(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarEnumerateAccountsWithUserRight(dce,policyHandle, 'SeSystemtimePrivilege')
        resp.dump()

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

    def test_hLsarEnumerateTrustedDomainsEx(self):
        dce, rpctransport, policyHandle = self.connect()
        try:
            resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policyHandle)
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

    def test_hLsarEnumerateTrustedDomains(self):
        dce, rpctransport, policyHandle = self.connect()
        try:
            resp = lsad.hLsarEnumerateTrustedDomains(dce, policyHandle)
            resp.dump()
        except Exception, e:
            if str(e).find('STATUS_NO_MORE_ENTRIES') < 0:
                raise

    def test_hLsarOpenAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarEnumerateAccounts(dce, policyHandle)
        resp.dump()

        resp = lsad.hLsarOpenAccount(dce, policyHandle, resp['EnumerationBuffer']['Information'][0]['Sid'].formatCanonical())
        resp.dump()

        resp = lsad.hLsarClose(dce, resp['AccountHandle'])
        resp.dump()

    def test_LsarOpenAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarEnumerateAccounts()
        request['PolicyHandle'] = policyHandle
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarOpenAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'] = resp['EnumerationBuffer']['Information'][0]['Sid']
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarClose()
        request['ObjectHandle'] = resp['AccountHandle']
        resp = dce.request(request)
        resp.dump()

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
        resp.dump()

        request = lsad.LsarDeleteObject()
        request['ObjectHandle'] = resp['AccountHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hLsarCreateAccount_hLsarDeleteObject(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle,lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)

        sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        sid = sid + '-9999'

        resp = lsad.hLsarCreateAccount(dce, policyHandle, sid)
        resp.dump()

        resp = lsad.hLsarDeleteObject(dce,resp['AccountHandle'])
        resp.dump()

    def test_LsarEnumeratePrivilegesAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        request = lsad.LsarOpenAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarEnumeratePrivilegesAccount()
        request['AccountHandle'] = resp['AccountHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hLsarEnumeratePrivilegesAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        resp = lsad.hLsarOpenAccount(dce, policyHandle, sid)
        resp.dump()

        resp = lsad.hLsarEnumeratePrivilegesAccount(dce,resp['AccountHandle'] )
        resp.dump()

    def test_LsarGetSystemAccessAccount_LsarSetSystemAccessAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        request = lsad.LsarOpenAccount()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarGetSystemAccessAccount()
        request['AccountHandle'] = resp['AccountHandle']
        resp2 = dce.request(request)
        resp.dump()

        request = lsad.LsarSetSystemAccessAccount()
        request['AccountHandle'] = resp['AccountHandle']
        request['SystemAccess'] = resp2['SystemAccess']
        resp = dce.request(request)
        resp.dump()

    def test_hLsarGetSystemAccessAccount_hLsarSetSystemAccessAccount(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        resp = lsad.hLsarOpenAccount(dce, policyHandle, sid)
        resp.dump()

        resp2 = lsad.hLsarGetSystemAccessAccount(dce, resp['AccountHandle'])
        resp2.dump()

        resp = lsad.hLsarSetSystemAccessAccount(dce,resp['AccountHandle'],resp2['SystemAccess'])
        resp.dump()

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
        resp.dump()
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
        resp.dump()

    def test_hLsarAddPrivilegesToAccount_hLsarRemovePrivilegesFromAccount(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle,lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)

        sid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()
        sid = sid + '-9999'

        resp = lsad.hLsarCreateAccount(dce, policyHandle, sid)
        accountHandle = resp['AccountHandle']

        attributes = list()
        attribute = lsad.LSAPR_LUID_AND_ATTRIBUTES()
        attribute['Luid']['LowPart'] = 0
        attribute['Luid']['HighPart'] = 3
        attribute['Attributes'] = 3
        attributes.append(attribute)
        try:
            resp = lsad.hLsarAddPrivilegesToAccount(dce,accountHandle, attributes)
            resp.dump()
        except:
            resp = lsad.hLsarDeleteObject(dce, accountHandle)
            return

        resp = lsad.hLsarRemovePrivilegesFromAccount(dce, accountHandle, NULL, 1)
        resp.dump()

        resp = lsad.hLsarDeleteObject(dce,accountHandle )
        resp.dump()

    def test_LsarEnumerateAccountRights(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        request = lsad.LsarEnumerateAccountRights()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        resp = dce.request(request)
        resp.dump()

    def test_hLsarEnumerateAccountRights(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-544'

        resp = lsad.hLsarEnumerateAccountRights(dce, policyHandle, sid)
        resp.dump()

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
        resp.dump()

        request = lsad.LsarRemoveAccountRights()
        request['PolicyHandle'] = policyHandle
        request['AccountSid'].fromCanonical(sid)
        request['UserRights']['EntriesRead'] = 1
        right = RPC_UNICODE_STRING()
        right['Data'] = 'SeChangeNotifyPrivilege'
        request['UserRights']['UserRights'].append(right)
        resp = dce.request(request)
        resp.dump()

    def test_hLsarAddAccountRights_hLsarRemoveAccountRights(self):
        dce, rpctransport, policyHandle = self.connect()
        sid = 'S-1-5-32-504'

        resp = lsad.hLsarAddAccountRights(dce, policyHandle, sid, ('SeChangeNotifyPrivilege', ))
        resp.dump()
        resp = lsad.hLsarRemoveAccountRights(dce, policyHandle, sid, ('SeChangeNotifyPrivilege', ))
        resp.dump()

    def test_LsarCreateSecret_LsarOpenSecret(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarCreateSecret()
        request['PolicyHandle'] = policyHandle
        request['SecretName'] = 'MYSECRET'
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarOpenSecret()
        request['PolicyHandle'] = policyHandle
        request['SecretName'] = 'MYSECRET'
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp0 = dce.request(request)
        resp0.dump()

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
            resp.dump()
        except: 
            pass

        request = lsad.LsarDeleteObject()
        request['ObjectHandle'] = resp0['SecretHandle']
        resp = dce.request(request)
        resp.dump()

    def test_hLsarCreateSecret_hLsarOpenSecret(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsad.hLsarCreateSecret(dce, policyHandle, 'MYSECRET')
        resp.dump()

        resp0 = lsad.hLsarOpenSecret(dce, policyHandle, 'MYSECRET')
        resp0.dump()

        try:
            resp = lsad.hLsarSetSecret(dce, resp0['SecretHandle'], 'A'*16, 'A'*16)
            resp.dump()
        except: 
            pass

        resp = lsad.hLsarDeleteObject(dce,resp0['SecretHandle'])
        resp.dump()

    def test_LsarQuerySecret(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarOpenSecret()
        request['PolicyHandle'] = policyHandle
        request['SecretName'] = 'DPAPI_SYSTEM'
        request['DesiredAccess'] = MAXIMUM_ALLOWED
        resp0 = dce.request(request)
        resp0.dump()

        request = lsad.LsarQuerySecret()
        request['SecretHandle'] = resp0['SecretHandle']
        request['EncryptedCurrentValue']['Buffer'] = NULL
        request['EncryptedOldValue']['Buffer'] = NULL
        request['OldValueSetTime'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hLsarQuerySecret(self):
        dce, rpctransport, policyHandle = self.connect()

        resp0 = lsad.hLsarOpenSecret(dce, policyHandle, 'DPAPI_SYSTEM')
        resp0.dump()

        resp = lsad.hLsarQuerySecret(dce, resp0['SecretHandle'])
        resp.dump()

    def test_LsarRetrievePrivateData_LsarStorePrivateData(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarRetrievePrivateData()
        request['PolicyHandle'] = policyHandle
        request['KeyName'] = 'DPAPI_SYSTEM'
        resp0 = dce.request(request)
        resp0.dump()

        request = lsad.LsarStorePrivateData()
        request['PolicyHandle'] = policyHandle
        request['KeyName'] = 'BETUS'
        request['EncryptedData'] = resp0['EncryptedData']
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarStorePrivateData()
        request['PolicyHandle'] = policyHandle
        request['KeyName'] = 'BETUS'
        request['EncryptedData'] = NULL
        resp = dce.request(request)
        resp.dump()

    def test_hLsarRetrievePrivateData_hLsarStorePrivateData(self):
        dce, rpctransport, policyHandle = self.connect()

        resp0 = lsad.hLsarRetrievePrivateData(dce,policyHandle,'DPAPI_SYSTEM')
        #hexdump(resp0)

        resp = lsad.hLsarStorePrivateData(dce, policyHandle, 'BETUS', resp0)
        resp.dump()

        resp = lsad.hLsarStorePrivateData(dce, policyHandle, 'BETUS', NULL)
        resp.dump()

    def test_LsarEnumeratePrivileges(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarEnumeratePrivileges()
        request['PolicyHandle'] = policyHandle
        request['EnumerationContext'] = 0
        request['PreferedMaximumLength'] = 0xffffffff
        resp = dce.request(request)
        resp.dump()

        self.assertTrue( resp['EnumerationBuffer']['Entries'] == len(resp['EnumerationBuffer']['Privileges'] ) )

    def test_hLsarEnumeratePrivileges(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsad.hLsarEnumeratePrivileges(dce, policyHandle)
        resp.dump()

        self.assertTrue( resp['EnumerationBuffer']['Entries'] == len(resp['EnumerationBuffer']['Privileges'] ) )

    def test_LsarLookupPrivilegeValue_LsarLookupPrivilegeName(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarLookupPrivilegeValue()
        request['PolicyHandle'] = policyHandle
        request['Name'] = u'SeTimeZonePrivilege'
        resp = dce.request(request)
        resp.dump()

        request = lsad.LsarLookupPrivilegeName()
        request['PolicyHandle'] = policyHandle
        request['Value'] = resp['Value']
        resp = dce.request(request)
        resp.dump()

        self.assertTrue( resp['Name'] == 'SeTimeZonePrivilege')

    def test_hLsarLookupPrivilegeValue_hLsarLookupPrivilegeName(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsad.hLsarLookupPrivilegeValue(dce, policyHandle,'SeTimeZonePrivilege' )
        resp.dump()

        resp = lsad.hLsarLookupPrivilegeName(dce, policyHandle, resp['Value'])
        resp.dump()

        self.assertTrue( resp['Name'] == 'SeTimeZonePrivilege')

    def test_LsarLookupPrivilegeDisplayName(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarLookupPrivilegeDisplayName()
        request['PolicyHandle'] = policyHandle
        request['Name'] = u'SeTimeZonePrivilege'
        request['ClientLanguage'] = 1
        request['ClientSystemDefaultLanguage'] = 1
        resp = dce.request(request)
        resp.dump()

    def test_LsarQuerySecurityObject_LsarSetSecurityObject(self):
        dce, rpctransport, policyHandle = self.connect()

        request = lsad.LsarQuerySecurityObject()
        request['PolicyHandle'] = policyHandle
        request['SecurityInformation'] = lsad.OWNER_SECURITY_INFORMATION
        resp = dce.request(request)
        resp.dump()

        self.assertTrue( resp['SecurityDescriptor']['Length'] == len(resp['SecurityDescriptor']['SecurityDescriptor']) )

        request = lsad.LsarSetSecurityObject()
        request['PolicyHandle'] = policyHandle
        request['SecurityInformation'] = lsad.OWNER_SECURITY_INFORMATION
        request['SecurityDescriptor'] = resp['SecurityDescriptor']
        resp = dce.request(request)
        resp.dump()

    def test_hLsarQuerySecurityObject_hLsarSetSecurityObject(self):
        dce, rpctransport, policyHandle = self.connect()

        resp = lsad.hLsarQuerySecurityObject(dce, policyHandle, lsad.OWNER_SECURITY_INFORMATION)
        #hexdump(resp)

        resp = lsad.hLsarSetSecurityObject(dce, policyHandle, lsad.OWNER_SECURITY_INFORMATION,resp)
        resp.dump()

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
            if str(e).find('STATUS_NO_SUCH_DOMAIN') < 0:
                raise

    def test_LsarSetInformationPolicy2(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy2()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation
        resp = dce.request(request)
        resp.dump()
        oldValue = resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode']

        req = lsad.LsarSetInformationPolicy2()
        req['PolicyHandle'] = policyHandle
        req['InformationClass'] = request['InformationClass']
        req['PolicyInformation'] = resp['PolicyInformation']
        req['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = 0
        resp2 = dce.request(req)
        resp2.dump()

        resp = dce.request(request)
        resp.dump()

        req['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = oldValue
        resp2 = dce.request(req)
        resp2.dump()
        ################################################################################ 

        #request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
        #resp = dce.request(request)
        #resp.dump()
        #oldValue = resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Name']

        #req = lsad.LsarSetInformationPolicy2()
        #req['PolicyHandle'] = policyHandle
        #req['InformationClass'] = request['InformationClass']
        #req['PolicyInformation'] = resp['PolicyInformation']
        #req['PolicyInformation']['PolicyPrimaryDomainInfo']['Name'] = 'BETUS'
        #resp2 = dce.request(req)
        #resp2.dump()

        #resp = dce.request(request)
        #resp.dump()

        #self.assertTrue( 'BETUS' == resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Name'] )

        #req['PolicyInformation']['PolicyPrimaryDomainInfo']['Name'] = oldValue
        #resp2 = dce.request(req)
        #resp2.dump()

        ################################################################################ 

        #request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        #resp = dce.request(request)
        #resp.dump()
        #oldValue = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainName']

        #req = lsad.LsarSetInformationPolicy2()
        #req['PolicyHandle'] = policyHandle
        #req['InformationClass'] = request['InformationClass']
        #req['PolicyInformation'] = resp['PolicyInformation']
        #req['PolicyInformation']['PolicyAccountDomainInfo']['DomainName'] = 'BETUS'
        #resp2 = dce.request(req)
        #resp2.dump()

        #resp = dce.request(request)
        #resp.dump()

        #self.assertTrue( 'BETUS' == resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainName'] )

        #req['PolicyInformation']['PolicyAccountDomainInfo']['DomainName'] = oldValue
        #resp2 = dce.request(req)
        #resp2.dump()

        ################################################################################ 

        # ToDo rest of the Information Classes

    def test_hLsarSetInformationPolicy2(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation)
        resp.dump()
        oldValue = resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode']

        resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = 0
        resp2 = lsad.hLsarSetInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation, resp['PolicyInformation'] )
        resp2.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation)
        resp.dump()

        resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = oldValue
        resp2 = lsad.hLsarSetInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation, resp['PolicyInformation'] )
        resp2.dump()

    def test_LsarSetInformationPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        request = lsad.LsarQueryInformationPolicy()
        request['PolicyHandle'] = policyHandle
        request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation
        resp = dce.request(request)
        resp.dump()
        oldValue = resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode']

        req = lsad.LsarSetInformationPolicy()
        req['PolicyHandle'] = policyHandle
        req['InformationClass'] = request['InformationClass']
        req['PolicyInformation'] = resp['PolicyInformation']
        req['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = 0
        resp2 = dce.request(req)
        resp2.dump()

        resp = dce.request(request)
        resp.dump()

        req['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = oldValue
        resp2 = dce.request(req)
        resp2.dump()
        ################################################################################ 

        #request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
        #resp = dce.request(request)
        #resp.dump()
        #oldValue = resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Name']

        #req = lsad.LsarSetInformationPolicy()
        #req['PolicyHandle'] = policyHandle
        #req['InformationClass'] = request['InformationClass']
        #req['PolicyInformation'] = resp['PolicyInformation']
        #req['PolicyInformation']['PolicyPrimaryDomainInfo']['Name'] = 'BETUS'
        #resp2 = dce.request(req)
        #resp2.dump()

        #resp = dce.request(request)
        #resp.dump()
        #self.assertTrue( 'BETUS' == resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Name'] )

        #req['PolicyInformation']['PolicyPrimaryDomainInfo']['Name'] = oldValue
        #resp2 = dce.request(req)
        #resp2.dump()

        ################################################################################ 

        #request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
        #resp = dce.request(request)
        #resp.dump()
        #oldValue = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainName']

        #req = lsad.LsarSetInformationPolicy()
        #req['PolicyHandle'] = policyHandle
        #req['InformationClass'] = request['InformationClass']
        #req['PolicyInformation'] = resp['PolicyInformation']
        #req['PolicyInformation']['PolicyAccountDomainInfo']['DomainName'] = 'BETUS'
        #resp2 = dce.request(req)
        #resp2.dump()

        #resp = dce.request(request)
        #resp.dump()

        #self.assertTrue( 'BETUS' == resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainName'] )

        #req['PolicyInformation']['PolicyAccountDomainInfo']['DomainName'] = oldValue
        #resp2 = dce.request(req)
        #resp2.dump()

        ################################################################################ 

        # ToDo rest of the Information Classes

    def test_hLsarSetInformationPolicy(self):
        dce, rpctransport, policyHandle = self.connect()
        resp = lsad.hLsarQueryInformationPolicy(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation)
        resp.dump()
        oldValue = resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode']

        resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = 0
        resp2 = lsad.hLsarSetInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation, resp['PolicyInformation'] )
        resp2.dump()

        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation)
        resp.dump()

        resp['PolicyInformation']['PolicyAuditEventsInfo']['AuditingMode'] = oldValue
        resp2 = lsad.hLsarSetInformationPolicy2(dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyAuditEventsInformation, resp['PolicyInformation'] )
        resp2.dump()

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
        self.ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

class SMBTransport64(LSADTests):
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
