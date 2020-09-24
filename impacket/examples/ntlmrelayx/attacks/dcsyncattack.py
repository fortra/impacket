# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  HTTP protocol relay attack
#
# ToDo:
#
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, NTDSHashes

PROTOCOL_ATTACK_CLASS = "DCSYNCAttack"

class DCSYNCAttack(ProtocolAttack):
    """
    This is the default HTTP attack. This attack only dumps the root page, though
    you can add any complex attack below. self.client is an instance of urrlib.session
    For easy advanced attacks, use the SOCKS option and use curl or a browser to simply
    proxy through ntlmrelayx
    """
    PLUGIN_NAMES = ["DCSYNC"]
    def run(self):
        return
