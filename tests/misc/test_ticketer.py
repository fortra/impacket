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
# Description:
#   ticketer.py unit tests
#
import datetime
import unittest
from types import SimpleNamespace

from examples.ticketer import TICKETER
from impacket.krb5.asn1 import EncTicketPart
from impacket.krb5.types import KerberosTime


class TicketerTests(unittest.TestCase):
    def build_options(self):
        return SimpleNamespace(
            spn=None,
            keytab=None,
            request=False,
            hashes=None,
            aesKey='a' * 64,
            nthash=None,
            groups='513,512,520,518,519',
            user_id='500',
            extra_sid=None,
            extra_pac=False,
            old_pac=False,
            duration='87600',
            domain_sid='S-1-5-21-1-2-3',
            impersonate=None,
        )

    def test_customizeTicket_request_reuses_requested_lifetime(self):
        options = self.build_options()
        ticketer = TICKETER('baduser', 'Password123!', 'a.local', options)

        kdcRep, pacInfos = ticketer.createBasicTicket()

        authtime = datetime.datetime(2026, 4, 28, 23, 25, 32, tzinfo=datetime.timezone.utc)
        starttime = datetime.datetime(2026, 4, 28, 23, 25, 32, tzinfo=datetime.timezone.utc)
        endtime = datetime.datetime(2026, 4, 29, 9, 25, 32, tzinfo=datetime.timezone.utc)
        renewTill = datetime.datetime(2026, 4, 29, 23, 25, 4, tzinfo=datetime.timezone.utc)

        options.request = True
        requested_times = EncTicketPart()
        requested_times['authtime'] = KerberosTime.to_asn1(authtime)
        requested_times['starttime'] = KerberosTime.to_asn1(starttime)
        requested_times['endtime'] = KerberosTime.to_asn1(endtime)
        requested_times['renew-till'] = KerberosTime.to_asn1(renewTill)
        ticketer._TICKETER__requested_ticket_times = {
            'authtime': requested_times['authtime'],
            'starttime': requested_times['starttime'],
            'endtime': requested_times['endtime'],
            'renew-till': requested_times['renew-till'],
        }

        encRepPart, encTicketPart, _ = ticketer.customizeTicket(kdcRep, pacInfos)

        self.assertEqual(str(encTicketPart['authtime']), '20260428232532Z')
        self.assertEqual(str(encTicketPart['starttime']), '20260428232532Z')
        self.assertEqual(str(encTicketPart['endtime']), '20260429092532Z')
        self.assertEqual(str(encTicketPart['renew-till']), '20260429232504Z')
        self.assertEqual(str(encRepPart['endtime']), '20260429092532Z')
        self.assertEqual(str(encRepPart['renew-till']), '20260429232504Z')


if __name__ == "__main__":
    unittest.main(verbosity=1)
