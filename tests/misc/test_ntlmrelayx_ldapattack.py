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

from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack


class _DomainDumper:
    root = "DC=example,DC=com"


class LDAPAttackTests(unittest.TestCase):
    def test_get_computer_container_uses_configured_container(self):
        attack = LDAPAttack.__new__(LDAPAttack)
        attack.config = mock.Mock(addcomputercontainer="OU=Workstations,DC=example,DC=com")
        attack.client = mock.Mock()

        self.assertEqual(
            attack.getComputerContainer(_DomainDumper()),
            "OU=Workstations,DC=example,DC=com",
        )
        attack.client.search.assert_not_called()

    def test_get_computer_container_falls_back_to_default_container(self):
        attack = LDAPAttack.__new__(LDAPAttack)
        attack.config = mock.Mock(addcomputercontainer=None)
        attack.client = mock.Mock()
        attack.client.entries = [
            {
                "wellKnownObjects": [
                    b"B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=example,DC=com",
                ],
            },
        ]

        self.assertEqual(
            attack.getComputerContainer(_DomainDumper()),
            "CN=Computers,DC=example,DC=com",
        )
        attack.client.search.assert_called_once_with(
            "DC=example,DC=com",
            "(ObjectClass=domain)",
            attributes=["wellKnownObjects"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
