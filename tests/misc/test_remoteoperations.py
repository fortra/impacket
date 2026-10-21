#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from unittest import mock

from impacket import system_errors
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples import regsecrets, secretsdump


class _RemoteOperationsLifecycleTests:
    # Module holding the RemoteOperations class under test, set by the concrete test classes
    module = None

    def newRemoteOps(self, smbConnection=None):
        return self.module.RemoteOperations(smbConnection, False)

    def setPrivate(self, remoteOps, name, value):
        setattr(remoteOps, '_RemoteOperations__' + name, value)

    def patchModule(self, name):
        return mock.patch('%s.%s' % (self.module.__name__, name))

    def test_with_returns_instance_and_calls_finish(self):
        remoteOps = self.newRemoteOps()
        with mock.patch.object(remoteOps, 'finish') as finish:
            with remoteOps as ctx:
                self.assertIs(ctx, remoteOps)
            finish.assert_called_once_with()

    def test_with_calls_finish_when_body_raises(self):
        remoteOps = self.newRemoteOps()
        with mock.patch.object(remoteOps, 'finish') as finish:
            with self.assertRaises(RuntimeError):
                with remoteOps:
                    raise RuntimeError('body failed')
            finish.assert_called_once_with()

    def test_cleanup_error_does_not_hide_body_exception(self):
        remoteOps = self.newRemoteOps()
        with mock.patch.object(remoteOps, 'finish', side_effect=OSError('cleanup failed')):
            with self.assertLogs('impacket', level='ERROR'):
                with self.assertRaises(RuntimeError):
                    with remoteOps:
                        raise RuntimeError('body failed')

    def test_cleanup_error_is_raised_when_body_succeeds(self):
        remoteOps = self.newRemoteOps()
        with mock.patch.object(remoteOps, 'finish', side_effect=OSError('cleanup failed')):
            with self.assertRaises(OSError):
                with remoteOps:
                    pass

    def test_finish_twice_restores_and_disconnects_only_once(self):
        remoteOps = self.newRemoteOps()
        # State left by enableRegistry() on a target where RemoteRegistry was stopped and disabled
        self.setPrivate(remoteOps, 'shouldStop', True)
        self.setPrivate(remoteOps, 'disabled', True)
        self.setPrivate(remoteOps, 'serviceHandle', 'service-handle')
        rrpDce = mock.Mock()
        scmrDce = mock.Mock()
        self.setPrivate(remoteOps, 'rrp', rrpDce)
        self.setPrivate(remoteOps, 'scmr', scmrDce)
        with self.patchModule('scmr') as scmr:
            remoteOps.finish()
            remoteOps.finish()
        scmr.hRControlService.assert_called_once()
        scmr.hRChangeServiceConfigW.assert_called_once()
        rrpDce.disconnect.assert_called_once_with()
        scmrDce.disconnect.assert_called_once_with()

    def test_failed_restore_is_retried_by_next_finish(self):
        remoteOps = self.newRemoteOps()
        self.setPrivate(remoteOps, 'shouldStop', True)
        self.setPrivate(remoteOps, 'serviceHandle', 'service-handle')
        with self.patchModule('scmr') as scmr:
            scmr.hRControlService.side_effect = [OSError('transient'), None]
            with self.assertRaises(OSError):
                remoteOps.finish()
            remoteOps.finish()
        self.assertEqual(scmr.hRControlService.call_count, 2)

    def test_start_type_is_restored_when_service_is_not_running(self):
        # enableRegistry() switched a disabled service to manual, then failed to start it
        remoteOps = self.newRemoteOps()
        self.setPrivate(remoteOps, 'shouldStop', True)
        self.setPrivate(remoteOps, 'disabled', True)
        self.setPrivate(remoteOps, 'serviceHandle', 'service-handle')
        with self.patchModule('scmr') as scmr:
            scmr.hRControlService.side_effect = DCERPCException(error_code=system_errors.ERROR_SERVICE_NOT_ACTIVE)
            remoteOps.finish()
            remoteOps.finish()
        scmr.hRControlService.assert_called_once()
        scmr.hRChangeServiceConfigW.assert_called_once()

    def test_other_stop_errors_are_raised(self):
        remoteOps = self.newRemoteOps()
        self.setPrivate(remoteOps, 'shouldStop', True)
        self.setPrivate(remoteOps, 'serviceHandle', 'service-handle')
        with self.patchModule('scmr') as scmr:
            scmr.hRControlService.side_effect = DCERPCException(error_code=system_errors.ERROR_ACCESS_DENIED)
            with self.assertRaises(DCERPCException):
                remoteOps.finish()

    def newRemoteOpsWithTempService(self):
        smbConnection = mock.Mock()
        smbConnection.getCredentials.return_value = ('user', 'password', 'DOMAIN', '', '', '', None, None)
        remoteOps = self.newRemoteOps(smbConnection)
        self.setPrivate(remoteOps, 'tmpServiceName', 'AbCdEfGh')
        self.setPrivate(remoteOps, 'serviceHandle', 'service-handle')
        return remoteOps

    def test_temp_service_cleanup_runs_once_when_service_does_not_exist(self):
        # wmiexec and mmcexec record a temporary service name without creating the service
        remoteOps = self.newRemoteOpsWithTempService()
        with self.patchModule('transport') as transport, self.patchModule('scmr') as scmr:
            scmr.hROpenServiceW.side_effect = Exception('SCMR SessionError: code: 0x424 - ERROR_SERVICE_DOES_NOT_EXIST')
            remoteOps.finish()
            remoteOps.finish()
        transport.DCERPCTransportFactory.assert_called_once()

    def test_temp_service_cleanup_runs_once_after_deleting_it(self):
        remoteOps = self.newRemoteOpsWithTempService()
        with self.patchModule('transport') as transport, self.patchModule('scmr') as scmr:
            remoteOps.finish()
            remoteOps.finish()
        transport.DCERPCTransportFactory.assert_called_once()
        scmr.hRDeleteService.assert_called_once()

    def test_temp_service_cleanup_is_retried_after_a_connection_error(self):
        remoteOps = self.newRemoteOpsWithTempService()
        with self.patchModule('transport') as transport, self.patchModule('scmr'):
            dce = transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value
            dce.connect.side_effect = [OSError('timed out'), None]
            remoteOps.finish()
            remoteOps.finish()
        self.assertEqual(transport.DCERPCTransportFactory.call_count, 2)


class SecretsdumpRemoteOperationsTests(_RemoteOperationsLifecycleTests, unittest.TestCase):
    module = secretsdump


class RegsecretsRemoteOperationsTests(_RemoteOperationsLifecycleTests, unittest.TestCase):
    module = regsecrets

    def test_registry_handle_is_closed_only_once(self):
        remoteOps = self.newRemoteOps()
        self.setPrivate(remoteOps, 'rrp', mock.Mock())
        self.setPrivate(remoteOps, 'regHandle', 'hklm-handle')
        with self.patchModule('rrp') as rrp:
            remoteOps.finish()
            remoteOps.finish()
        rrp.hBaseRegCloseKey.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=1)
