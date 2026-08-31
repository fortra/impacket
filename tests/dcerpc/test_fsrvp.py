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
# Tested so far:
#   GetSupportedVersion
#   SetContext
#   StartShadowCopySet
#   AddToShadowCopySet
#   CommitShadowCopySet
#   ExposeShadowCopySet
#   RecoveryCompleteShadowCopySet
#   AbortShadowCopySet
#   IsPathSupported
#   IsPathShadowCopied
#   GetShareMapping
#   DeleteShareMapping
#   PrepareShadowCopySet
#
# Install the service:
# Add-WindowsFeature -Name File-Services,FS-VSS-Agent
# Set-Service -Name "FSSAgent" -StartupType Automatic
# Also, you need to expose share, for example, "Windows". We can't make shadow copies for special share like C$
SHARE_NAME = "Windows"

from tests.dcerpc import DCERPCTests
import pytest
from impacket.dcerpc.v5 import fsrvp, rpcrt
from impacket.uuid import string_to_bin
import uuid
import unittest


@pytest.mark.remote
class FSRVPTests(DCERPCTests, unittest.TestCase):
    iface_uuid = fsrvp.MSRPC_UUID_FSRVP
    authn = True
    authn_level = rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    string_binding = r"ncacn_np:{0.machine}[%s]" % fsrvp.MSRPC_NAMED_PIPE_FSRVP

    def test_fsrvp(self):
        global SHARE_NAME
        # All test are passed in one function because almost all functions depend on each other and must be called sequentially.
        dce, transport = self.connect()
        # Shadow copy preparation
        # According to the documentation https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/e9f295cf-0f5c-4eec-8cfc-f2a031ae7805
        is_path_supported = fsrvp.hIsPathSupported(dce, r"\\%s\%s" % (self.machine, SHARE_NAME))
        self.assertEqual(is_path_supported["SupportedByThisProvider"], 1)
        machine_name = is_path_supported["OwnerMachineName"][:-1:]
        version_call = fsrvp.hGetSupportedVersion(dce) # Always MinVersion == MaxVersion == 1
        self.assertEqual(version_call["MinVersion"], 1)
        self.assertEqual(version_call["MaxVersion"], 1)
        fsrvp.hSetContext(dce, fsrvp.ContextValues.CTX_FILE_SHARE_BACKUP)
        client_set_id = string_to_bin(str(uuid.uuid4()))
        start_shadow_copy_set = fsrvp.hStartShadowCopySet(dce, client_set_id)
        shadow_copy_set_id = start_shadow_copy_set['pShadowCopySetId']
        client_shadow_copy_id = string_to_bin(str(uuid.uuid4()))
        add_to_shadow_copy = fsrvp.hAddToShadowCopySet(dce, client_shadow_copy_id, shadow_copy_set_id, f"\\\\{machine_name}\\{SHARE_NAME}")
        shadow_copy_id = add_to_shadow_copy['ShadowCopyId']
        prepare_shadow_copy = fsrvp.hPrepareShadowCopySet(dce, shadow_copy_set_id, 30000)
        self.assertEqual(prepare_shadow_copy['ErrorCode'], 0) # Server ready to create a shadow copy
        # Shadow copy creation
        fsrvp.hCommitShadowCopySet(dce, shadow_copy_set_id, 30000)
        fsrvp.hExposeShadowCopySet(dce, shadow_copy_set_id, 30000)
        share_mapping = fsrvp.hGetShareMapping(dce, shadow_copy_id, shadow_copy_set_id, f'\\\\{machine_name}\\{SHARE_NAME}')
        share_name = share_mapping['ShareMapping']['ShareMapping1']['ShadowCopyShareName'] # Server are exposed shadow copy of share to this share name
        fsrvp.hRecoveryCompleteShadowCopySet(dce, shadow_copy_set_id)
        # Check if path shadow copied:
        is_path_shadow_copied = fsrvp.hIsPathShadowCopied(dce, f'\\\\{machine_name}\\{SHARE_NAME}')
        self.assertEqual(is_path_shadow_copied["ShadowCopyPresent"], 1)
        # Shadow copy deletion
        delete_share_mapping = fsrvp.hDeleteShareMapping(dce, shadow_copy_set_id, shadow_copy_id, f'\\\\{machine_name}\\{SHARE_NAME}')

    def test_abort_shadow_copy(self):
        global SHARE_NAME
        dce, transport = self.connect()
        is_path_supported = fsrvp.hIsPathSupported(dce, r"\\%s\%s" % (self.machine, SHARE_NAME))
        self.assertEqual(is_path_supported["SupportedByThisProvider"], 1)
        machine_name = is_path_supported["OwnerMachineName"][:-1:]
        version_call = fsrvp.hGetSupportedVersion(dce)
        self.assertEqual(version_call["MinVersion"], 1)
        self.assertEqual(version_call["MaxVersion"], 1)
        fsrvp.hSetContext(dce, fsrvp.ContextValues.CTX_FILE_SHARE_BACKUP)
        client_set_id = string_to_bin(str(uuid.uuid4()))
        start_shadow_copy_set = fsrvp.hStartShadowCopySet(dce, client_set_id)
        shadow_copy_set_id = start_shadow_copy_set['pShadowCopySetId']
        fsrvp.hAbortShadowCopySet(dce, shadow_copy_set_id)


# Process command-line arguments.
if __name__ == "__main__":
    unittest.main(verbosity=1)
