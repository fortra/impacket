# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Authors:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#   Based on @agsolino and @_dirkjan code
#

from impacket import LOG

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.attacks.rpcattacks.parattack import PARAttack
from impacket.examples.ntlmrelayx.attacks.rpcattacks.tschattack import TSCHRPCAttack

PROTOCOL_ATTACK_CLASS = "RPCAttack"





class RPCAttack(ProtocolAttack, TSCHRPCAttack, PARAttack):
    PLUGIN_NAMES = ["RPC"]

    def __init__(self, config, dce, username):
        ProtocolAttack.__init__(self, config, dce, username)
        self.dce = dce
        self.rpctransport = dce.get_rpc_transport()
        self.stringbinding = self.rpctransport.get_stringbinding()

    def run(self):
        # Here PUT YOUR CODE!

        # Assume the endpoint is TSCH
        # TODO: support relaying RPC to different endpoints
        # TODO: support for providing a shell
        # TODO: support for getting an output
        if self.config.rpc_mode == "TSCH":
            if self.config.command is not None:
                TSCHRPCAttack._run(self)
            else:
                LOG.error("No command provided to attack")
        elif self.config.rpc_mode == "PAR":
            PARAttack._run(self)

