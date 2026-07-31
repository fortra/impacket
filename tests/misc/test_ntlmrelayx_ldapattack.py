# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.

import datetime
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack


UTC = datetime.timezone.utc


class TestLDAPAttackDumpPre2k(unittest.TestCase):
    @staticmethod
    def _entry(sam, pwd_last_set, when_created):
        return {
            'type': 'searchResEntry',
            'attributes': {
                'sAMAccountName': sam,
                'userAccountControl': 0x1000,
                'pwdLastSet': pwd_last_set,
                'whenCreated': when_created,
                'distinguishedName': 'CN=%s,DC=example,DC=com' % sam.rstrip('$'),
                'operatingSystem': 'Windows Server 2022',
            },
        }

    def test_detects_near_equal_creation_timestamp_and_deduplicates(self):
        created = datetime.datetime(2026, 5, 27, 20, 51, 22, tzinfo=UTC)
        matching_entry = self._entry('PRE2KLAB1$', created + datetime.timedelta(milliseconds=750), created)
        non_matching_entry = self._entry('JOINEDPC$', created + datetime.timedelta(seconds=2), created)

        client = MagicMock()
        responses = [
            [matching_entry],
            [],
            [matching_entry, non_matching_entry],
        ]

        def search(*args, **kwargs):
            client.response = responses.pop(0)
            return True

        client.search.side_effect = search

        with tempfile.TemporaryDirectory() as lootdir:
            config = SimpleNamespace(addcomputer=None, interactive=False, lootdir=lootdir)
            attack = LDAPAttack(config, client, 'EXAMPLE/relayuser')
            attack.dumpPre2k(SimpleNamespace(root='DC=example,DC=com'))

            with open(next(iter(Path(lootdir).iterdir()))) as dump_file:
                dumped = json.load(dump_file)

        self.assertEqual(['PRE2KLAB1$'], [candidate['sAMAccountName'] for candidate in dumped])
        self.assertEqual('pre2klab1', dumped[0]['predictedPassword'])

        self.assertEqual(3, client.search.call_count)
        self.assertIn('(pwdLastSet=*)', client.search.call_args_list[2].args[1])
        self.assertIn('(whenCreated=*)', client.search.call_args_list[2].args[1])


if __name__ == '__main__':
    unittest.main(verbosity=1)
