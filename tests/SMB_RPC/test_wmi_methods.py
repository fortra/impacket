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
# Remote method-dispatch regression tests. Run directly:
#   python tests/SMB_RPC/test_wmi_methods.py 'domain/user:password@target'
#
from pathlib import Path
import sys

if __name__ == '__main__' and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from impacket.dcerpc.v5.dcom import wmi
from tests.SMB_RPC import test_wmi_next


class WMIMethodTests(test_wmi_next.WMIRemoteTests):
    def test_wrong_argument_count_raises_type_error(self):
        process, _ = self.services.GetObject('Win32_Process')
        # Create takes three arguments. Neither call can start a process.
        for arguments in ((), (None, None, None, None)):
            with self.subTest(argument_count=len(arguments)):
                with self.assertRaisesRegex(TypeError, r'Create\(\) takes 3 argument\(s\)'):
                    process.Create(*arguments)

    def test_remote_method_error_is_propagated(self):
        process, _ = self.services.GetObject('Win32_Process')
        # GetOwner requires a process instance. Calling it on the class makes
        # the server reject ExecMethod; the wrapper must propagate that error.
        with self.assertRaises(wmi.DCERPCSessionError) as ctx:
            process.GetOwner()
        self.assertEqual(
            ctx.exception.get_error_code(),
            wmi.WBEMSTATUS.enumItems.WBEM_E_INVALID_METHOD_PARAMETERS.value,
        )


if __name__ == '__main__':
    sys.exit(test_wmi_next.main(WMIMethodTests))
