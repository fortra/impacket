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
from datetime import datetime, timezone

from impacket.krb5 import constants, pac
from impacket.krb5.asn1 import EncTicketPart, AuthorizationData, TGS_REP, EncTGSRepPart, \
    KERB_KEY_LIST_REP, EncryptionKey
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.types import Principal, KerberosTime
from impacket.examples.secretsdump import KeyListSecrets

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import noValue


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

    def test_missing_rid_logs_warning(self):
        # A missing RID falls back to a placeholder requestor SID -- warn the operator.
        kl = KeyListSecrets(self.DOMAIN, 'dc01.%s' % self.DOMAIN,
                            self.RODC_NO, self.RODC_KEY, None)
        userName = Principal(self.USER, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        with self.assertLogs(level='WARNING') as cm:
            kl.createPartialTGT(userName, None, self.DOMAIN_SID)
        self.assertTrue(any('RID' in m for m in cm.output))


class TestKeyListGetKey(unittest.TestCase):
    # getKey() must find KERB-KEY-LIST-REP by PA-DATA type, not assume it is the
    # first entry of encrypted_pa_data. Modern DCs also return PA-SUPPORTED-ENCTYPES
    # (type 165) there, and the order is not guaranteed.

    DOMAIN = 'contoso.com'
    USER = 'victim'
    SESSION_KEY = b'\x11' * 16                       # rc4_hmac session key
    NT_HASH = unhexlify('cafebabecafebabecafebabecafebabe')

    def _build_tgs_rep(self, pa_entries):
        # pa_entries: list of (padata_type, padata_value_bytes), encoded in order.
        etype = int(constants.EncryptionTypes.rc4_hmac.value)
        now = KerberosTime.to_asn1(datetime.now(timezone.utc))

        enc = EncTGSRepPart()
        enc['key'] = noValue
        enc['key']['keytype'] = etype
        enc['key']['keyvalue'] = self.SESSION_KEY
        enc['last-req'] = noValue
        enc['last-req'][0] = noValue
        enc['last-req'][0]['lr-type'] = 0
        enc['last-req'][0]['lr-value'] = now
        enc['nonce'] = 0
        enc['flags'] = constants.encodeFlags([])
        enc['authtime'] = now
        enc['endtime'] = now
        enc['srealm'] = self.DOMAIN.upper()
        enc['sname'] = noValue
        enc['sname']['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
        enc['sname']['name-string'][0] = 'krbtgt'
        enc['sname']['name-string'][1] = self.DOMAIN.upper()
        enc['encrypted_pa_data'] = noValue
        for i, (paType, paValue) in enumerate(pa_entries):
            enc['encrypted_pa_data'][i] = noValue
            enc['encrypted_pa_data'][i]['padata-type'] = paType
            enc['encrypted_pa_data'][i]['padata-value'] = paValue

        cipher = _enctype_table[etype]
        key = Key(cipher.enctype, self.SESSION_KEY)
        # key usage 8 = TGS-REP enc-part encrypted with the TGS session key
        encPart = cipher.encrypt(key, 8, encoder.encode(enc), None)

        tgsRep = TGS_REP()
        tgsRep['pvno'] = 5
        tgsRep['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REP.value)
        tgsRep['crealm'] = self.DOMAIN.upper()
        tgsRep['cname'] = noValue
        tgsRep['cname']['name-type'] = constants.PrincipalNameType.NT_PRINCIPAL.value
        tgsRep['cname']['name-string'][0] = self.USER
        tgsRep['ticket'] = noValue
        tgsRep['ticket']['tkt-vno'] = 5
        tgsRep['ticket']['realm'] = self.DOMAIN.upper()
        tgsRep['ticket']['sname'] = noValue
        tgsRep['ticket']['sname']['name-type'] = constants.PrincipalNameType.NT_SRV_INST.value
        tgsRep['ticket']['sname']['name-string'][0] = 'krbtgt'
        tgsRep['ticket']['sname']['name-string'][1] = self.DOMAIN.upper()
        tgsRep['ticket']['enc-part'] = noValue
        tgsRep['ticket']['enc-part']['etype'] = int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value)
        tgsRep['ticket']['enc-part']['kvno'] = 2
        tgsRep['ticket']['enc-part']['cipher'] = b'\x00' * 16
        tgsRep['enc-part'] = noValue
        tgsRep['enc-part']['etype'] = etype
        tgsRep['enc-part']['cipher'] = encPart

        return encoder.encode(tgsRep)

    def _key_list_rep_value(self):
        ek = EncryptionKey()
        ek['keytype'] = int(constants.EncryptionTypes.rc4_hmac.value)
        ek['keyvalue'] = self.NT_HASH
        keyList = KERB_KEY_LIST_REP()
        keyList.setComponentByPosition(0, ek)
        return encoder.encode(keyList)

    def test_getkey_selects_key_list_rep_when_not_first(self):
        # A KERB-KEY-LIST-REP (162) preceded by PA-SUPPORTED-ENCTYPES (165). The 165
        # value is not a valid KERB-KEY-LIST-REP, so the old encrypted_pa_data[0]
        # assumption would have decoded the wrong buffer and failed.
        suppEnctypes = (constants.PreAuthenticationDataTypes.PA_SUPPORTED_ENCTYPES.value,
                        b'\x1f\x00\x00\x00')
        keyListRep = (constants.PreAuthenticationDataTypes.KERB_KEY_LIST_REP.value,
                      self._key_list_rep_value())

        raw = self._build_tgs_rep([suppEnctypes, keyListRep])
        key = KeyListSecrets.getKey(raw, self.SESSION_KEY)

        self.assertEqual(bytes.fromhex(key[2:]), self.NT_HASH)

        # Regression lock: the [0] entry really is 165 and would break the old path.
        with self.assertRaises(PyAsn1Error):
            decoder.decode(suppEnctypes[1], asn1Spec=KERB_KEY_LIST_REP())

    def test_getkey_raises_when_key_list_rep_absent(self):
        # No KERB-KEY-LIST-REP at all -> clear error instead of IndexError.
        suppEnctypes = (constants.PreAuthenticationDataTypes.PA_SUPPORTED_ENCTYPES.value,
                        b'\x1f\x00\x00\x00')
        raw = self._build_tgs_rep([suppEnctypes])
        with self.assertRaises(Exception) as ctx:
            KeyListSecrets.getKey(raw, self.SESSION_KEY)
        self.assertIn('KERB-KEY-LIST-REP', str(ctx.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
