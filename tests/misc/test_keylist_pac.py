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
#   Local (no-DC) tests for the KERB-KEY-LIST partial TGT built by
#   KeyListSecrets.createPartialTGT(). Regression guard for the fix that embeds
#   a full, RODC-signed PAC so PAC-hardened DCs accept the RODC-issued ticket
#   (see issue #1667).
#
import unittest
from binascii import unhexlify

from impacket.krb5 import constants, pac
from impacket.krb5.asn1 import EncTicketPart, AuthorizationData
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.types import Principal
from impacket.examples.secretsdump import KeyListSecrets

from pyasn1.codec.der import decoder


class TestKeyListPac(unittest.TestCase):

    RODC_KEY = 'ab' * 32          # 32-byte AES256 key, hex
    RODC_NO = 5
    DOMAIN = 'contoso.com'
    DOMAIN_SID = 'S-1-5-21-1-2-3'
    USER = 'victim'
    USER_RID = 1103

    def _build_ticket(self):
        kl = KeyListSecrets(self.DOMAIN, 'dc01.%s' % self.DOMAIN, self.RODC_NO, self.RODC_KEY, None)
        userName = Principal(self.USER, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        partialTGT, sessionKey = kl.createPartialTGT(userName, self.USER_RID, self.DOMAIN_SID)
        return partialTGT, sessionKey

    def _decrypt_enc_ticket_part(self, partialTGT):
        cipher = _enctype_table[int(partialTGT['enc-part']['etype'])]
        key = Key(cipher.enctype, unhexlify(self.RODC_KEY))
        # Key usage 2 = AS/TGS-REP ticket, encrypted with the service (krbtgt) key
        plain = cipher.decrypt(key, 2, partialTGT['enc-part']['cipher'].asOctets())
        return decoder.decode(plain, asn1Spec=EncTicketPart())[0]

    @staticmethod
    def _parse_pac_buffers(pac_data):
        pac_type = pac.PACTYPE(pac_data)
        blob = pac_type['Buffers']
        infos = {}
        offset = 0
        for _ in range(pac_type['cBuffers']):
            info_buffer = pac.PAC_INFO_BUFFER(blob[offset:])
            offset += len(info_buffer)
            start = info_buffer['Offset']
            infos[info_buffer['ulType']] = pac_data[start:start + info_buffer['cbBufferSize']]
        return infos

    def test_kvno_encodes_rodc_number(self):
        partialTGT, _ = self._build_ticket()
        self.assertEqual(int(partialTGT['enc-part']['kvno']), self.RODC_NO << 16)

    def test_partial_tgt_embeds_win2k_pac(self):
        partialTGT, _ = self._build_ticket()
        encTicketPart = self._decrypt_enc_ticket_part(partialTGT)

        authData = encTicketPart['authorization-data']
        self.assertTrue(authData.hasValue(), 'authorization-data must be present (a PAC), not empty')
        self.assertEqual(int(authData[0]['ad-type']), constants.AuthorizationDataType.AD_IF_RELEVANT.value)

        inner = decoder.decode(authData[0]['ad-data'].asOctets(), asn1Spec=AuthorizationData())[0]
        self.assertEqual(int(inner[0]['ad-type']), constants.AuthorizationDataType.AD_WIN2K_PAC.value)

        infos = self._parse_pac_buffers(inner[0]['ad-data'].asOctets())
        # PAC_ATTRIBUTES_INFO / PAC_REQUESTOR are required by CVE-2021-42287-patched DCs
        for ulType in (pac.PAC_LOGON_INFO, pac.PAC_CLIENT_INFO_TYPE,
                       pac.PAC_ATTRIBUTES_INFO, pac.PAC_REQUESTOR_INFO,
                       pac.PAC_SERVER_CHECKSUM, pac.PAC_PRIVSVR_CHECKSUM):
            self.assertIn(ulType, infos)

        clientInfo = pac.PAC_CLIENT_INFO(infos[pac.PAC_CLIENT_INFO_TYPE])
        self.assertEqual(bytes(clientInfo['Name']).decode('utf-16le'), self.USER)

        # PAC_REQUESTOR SID must match the ticket client (domainSid-userRid)
        requestor = pac.PAC_REQUESTOR(infos[pac.PAC_REQUESTOR_INFO])
        self.assertEqual(requestor['UserSid'].formatCanonical(),
                         '%s-%d' % (self.DOMAIN_SID, self.USER_RID))

    def test_pac_signatures_use_rodc_key(self):
        # The DC re-checks the PAC signatures with the RODC krbtgt key. Re-sign the
        # extracted buffers with the same key and assert the embedded server
        # signature matches -> the PAC is validly RODC-signed (AES256, salt 17).
        partialTGT, _ = self._build_ticket()
        encTicketPart = self._decrypt_enc_ticket_part(partialTGT)
        inner = decoder.decode(encTicketPart['authorization-data'][0]['ad-data'].asOctets(),
                               asn1Spec=AuthorizationData())[0]
        infos = self._parse_pac_buffers(inner[0]['ad-data'].asOctets())

        embedded = pac.PAC_SIGNATURE_DATA(infos[pac.PAC_SERVER_CHECKSUM])
        self.assertEqual(int(embedded['SignatureType']), constants.ChecksumTypes.hmac_sha1_96_aes256.value)

        resigned = pac.sign_pac(
            dict(infos), aes_key=self.RODC_KEY,
            buffer_order=[pac.PAC_LOGON_INFO, pac.PAC_CLIENT_INFO_TYPE,
                          pac.PAC_ATTRIBUTES_INFO, pac.PAC_REQUESTOR_INFO,
                          pac.PAC_SERVER_CHECKSUM, pac.PAC_PRIVSVR_CHECKSUM],
            checksum_salt=constants.KERB_NON_KERB_CKSUM_SALT)
        reInfos = self._parse_pac_buffers(resigned.getData())
        reSig = pac.PAC_SIGNATURE_DATA(reInfos[pac.PAC_SERVER_CHECKSUM])
        self.assertEqual(bytes(embedded['Signature']), bytes(reSig['Signature']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
