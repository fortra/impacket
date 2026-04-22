import unittest

from impacket.dcerpc.v5 import tsts


class TSTSTests(unittest.TestCase):
    SYSTEM_SID = bytes([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])

    def test_binary_sid_to_string_returns_canonical_sid(self):
        self.assertEqual(tsts.binary_sid_to_string(self.SYSTEM_SID), 'S-1-5-18')

    def test_get_all_processes_info_get_sid_with_populated_pointer(self):
        resp = tsts.RpcWinStationGetAllProcessesResponse()
        resp['pResult'] = 0
        resp['pNumberOfProcesses'] = 1

        entry = tsts.TS_ALL_PROCESSES_INFO()
        entry.fields['pTsProcessInfo'].fields['Data']['UniqueProcessId'] = 123
        entry.fields['pTsProcessInfo'].fields['Data']['SessionId'] = 1
        entry['SizeOfSid'] = 12
        entry.fields['pSid'].fields['Data']['Data'] = self.SYSTEM_SID

        resp.fields['ppTsAllProcessesInfo'].fields['Data']['Data'] = [entry]
        resp['ErrorCode'] = 1

        parsed = tsts.RpcWinStationGetAllProcessesResponse(resp.getData())

        self.assertEqual(parsed['ppTsAllProcessesInfo'][0].getSid(), 'SYSTEM')


if __name__ == '__main__':
    unittest.main(verbosity=1)
