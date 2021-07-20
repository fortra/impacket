# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
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
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
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
