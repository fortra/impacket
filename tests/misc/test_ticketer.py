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
from unittest import mock
from types import SimpleNamespace

from examples.ticketer import TICKETER
from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue

from impacket.krb5.asn1 import EncASRepPart, EncTGSRepPart, EncTicketPart
from impacket.krb5.constants import EncryptionTypes, PrincipalNameType, TicketFlags, encodeFlags
from impacket.krb5.types import KerberosTime


class TicketerTests(unittest.TestCase):
    @staticmethod
    def build_options(**overrides):
        options = SimpleNamespace(
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
            user='administrator',
            dc_ip='10.0.0.1',
        )
        for key, value in overrides.items():
            setattr(options, key, value)
        return options

    @staticmethod
    def build_encoded_reply_part(replyPartSpec, include_starttime=True, include_renew_till=True):
        authtime = datetime.datetime(2026, 4, 28, 23, 25, 32, tzinfo=datetime.timezone.utc)
        starttime = datetime.datetime(2026, 4, 28, 23, 25, 32, tzinfo=datetime.timezone.utc)
        endtime = datetime.datetime(2026, 4, 29, 9, 25, 32, tzinfo=datetime.timezone.utc)
        renewTill = datetime.datetime(2026, 4, 29, 23, 25, 4, tzinfo=datetime.timezone.utc)

        part = replyPartSpec()
        part['key'] = noValue
        part['key']['keytype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value
        part['key']['keyvalue'] = b'A' * 32
        part['last-req'] = noValue
        part['last-req'][0] = noValue
        part['last-req'][0]['lr-type'] = 0
        part['last-req'][0]['lr-value'] = KerberosTime.to_asn1(authtime)
        part['nonce'] = 123456789
        part['key-expiration'] = KerberosTime.to_asn1(endtime)
        part['flags'] = encodeFlags([TicketFlags.forwardable.value, TicketFlags.renewable.value])
        part['authtime'] = KerberosTime.to_asn1(authtime)
        if include_starttime:
            part['starttime'] = KerberosTime.to_asn1(starttime)
        part['endtime'] = KerberosTime.to_asn1(endtime)
        if include_renew_till:
            part['renew-till'] = KerberosTime.to_asn1(renewTill)
        part['srealm'] = 'A.LOCAL'
        part['sname'] = noValue
        part['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
        part['sname']['name-string'] = noValue
        part['sname']['name-string'][0] = 'krbtgt'
        part['sname']['name-string'][1] = 'A.LOCAL'

        return encoder.encode(part)

    def test_extract_reply_ticket_times_as_rep(self):
        # Covers helper decryption/decoding for requested TGTs and verifies
        # the AS-REP reply key usage. Reuse behavior is covered separately below.
        class FakeCipher:
            def __init__(self, plaintext):
                self.plaintext = plaintext
                self.calls = []

            def decrypt(self, replyKey, keyUsage, cipherText):
                self.calls.append((replyKey, keyUsage, cipherText))
                return self.plaintext

        options = self.build_options()
        ticketer = TICKETER('baduser', 'Password123!', 'a.local', options)
        fakeCipher = FakeCipher(self.build_encoded_reply_part(EncASRepPart))

        with mock.patch.dict(
            'examples.ticketer._enctype_table',
            {EncryptionTypes.aes256_cts_hmac_sha1_96.value: fakeCipher},
            clear=False,
        ):
            extracted = ticketer._extract_reply_ticket_times(
                {'enc-part': {'etype': EncryptionTypes.aes256_cts_hmac_sha1_96.value, 'cipher': b'ciphertext'}},
                b'reply-key',
            )

        self.assertEqual(fakeCipher.calls, [(b'reply-key', 3, b'ciphertext')])
        self.assertEqual(str(extracted['authtime']), '20260428232532Z')
        self.assertEqual(str(extracted['starttime']), '20260428232532Z')
        self.assertEqual(str(extracted['endtime']), '20260429092532Z')
        self.assertEqual(str(extracted['renew-till']), '20260429232504Z')

    def test_extract_reply_ticket_times_tgs_rep(self):
        # Covers helper decryption/decoding for requested service tickets and
        # verifies the TGS-REP reply key usage.
        class FakeCipher:
            def __init__(self, plaintext):
                self.plaintext = plaintext
                self.calls = []

            def decrypt(self, replyKey, keyUsage, cipherText):
                self.calls.append((replyKey, keyUsage, cipherText))
                return self.plaintext

        options = self.build_options(spn='cifs/fileserver.a.local')
        ticketer = TICKETER('baduser', 'Password123!', 'a.local', options)
        fakeCipher = FakeCipher(self.build_encoded_reply_part(EncTGSRepPart))

        with mock.patch.dict(
            'examples.ticketer._enctype_table',
            {EncryptionTypes.aes256_cts_hmac_sha1_96.value: fakeCipher},
            clear=False,
        ):
            extracted = ticketer._extract_reply_ticket_times(
                {'enc-part': {'etype': EncryptionTypes.aes256_cts_hmac_sha1_96.value, 'cipher': b'ciphertext'}},
                b'reply-key',
            )

        self.assertEqual(fakeCipher.calls, [(b'reply-key', 8, b'ciphertext')])
        self.assertEqual(str(extracted['authtime']), '20260428232532Z')
        self.assertEqual(str(extracted['starttime']), '20260428232532Z')
        self.assertEqual(str(extracted['endtime']), '20260429092532Z')
        self.assertEqual(str(extracted['renew-till']), '20260429232504Z')

    def test_extract_reply_ticket_times_missing_optional_fields_uses_fallbacks(self):
        # Covers the helper fallback behavior when the KDC omits optional
        # starttime or renew-till values.
        class FakeCipher:
            def __init__(self, plaintext):
                self.plaintext = plaintext

            def decrypt(self, replyKey, keyUsage, cipherText):
                return self.plaintext

        options = self.build_options()
        ticketer = TICKETER('baduser', 'Password123!', 'a.local', options)
        fakeCipher = FakeCipher(self.build_encoded_reply_part(
            EncASRepPart,
            include_starttime=False,
            include_renew_till=False,
        ))

        with mock.patch.dict(
            'examples.ticketer._enctype_table',
            {EncryptionTypes.aes256_cts_hmac_sha1_96.value: fakeCipher},
            clear=False,
        ):
            extracted = ticketer._extract_reply_ticket_times(
                {'enc-part': {'etype': EncryptionTypes.aes256_cts_hmac_sha1_96.value, 'cipher': b'ciphertext'}},
                b'reply-key',
            )

        self.assertEqual(str(extracted['authtime']), '20260428232532Z')
        self.assertEqual(str(extracted['starttime']), '20260428232532Z')
        self.assertEqual(str(extracted['endtime']), '20260429092532Z')
        self.assertEqual(str(extracted['renew-till']), '20260429092532Z')

    def test_createBasicTicket_request_stores_requested_ticket_times(self):
        # Covers createBasicTicket() wiring only: the extraction helper is
        # mocked here because its parsing behavior is verified by the helper
        # tests above.
        templateOptions = self.build_options()
        templateTicketer = TICKETER('templateuser', 'Password123!', 'a.local', templateOptions)
        templateReply, _ = templateTicketer.createBasicTicket()

        options = self.build_options(request=True)
        ticketer = TICKETER('baduser', 'Password123!', 'a.local', options)
        expectedTimes = {'marker': 'times'}

        with mock.patch('examples.ticketer.getKerberosTGT', return_value=(b'tgt-bytes', object(), b'reply-key', b'session-key')):
            with mock.patch('examples.ticketer.decoder.decode', return_value=[templateReply]):
                with mock.patch.object(TICKETER, '_extract_reply_ticket_times', return_value=expectedTimes) as extractMock:
                    ticketer.createBasicTicket()

        extractMock.assert_called_once()
        self.assertIs(ticketer._TICKETER__requested_ticket_times, expectedTimes)

    def test_customizeTicket_request_reuses_requested_lifetime(self):
        # Covers customizeTicket() consuming already-extracted lifetime values.
        # This test intentionally seeds the cached values directly; extraction
        # and request wiring are covered by the dedicated tests above.
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
        self.assertEqual(str(encRepPart['authtime']), '20260428232532Z')
        self.assertEqual(str(encRepPart['starttime']), '20260428232532Z')
        self.assertEqual(str(encRepPart['endtime']), '20260429092532Z')
        self.assertEqual(str(encRepPart['renew-till']), '20260429232504Z')


if __name__ == "__main__":
    unittest.main(verbosity=1)
