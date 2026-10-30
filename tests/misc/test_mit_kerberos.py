from unittest import TestCase, mock

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import (AP_REQ, AS_REP, Authenticator, EncTGSRepPart,
                               KDC_REQ_BODY, TGS_REQ, seq_set)
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table, verify_checksum
from impacket.krb5.kerberosv5 import KerberosError, getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal


class MITKerberosInteropTests(TestCase):
    @staticmethod
    def _as_reply(enctype, cipher_text):
        reply = AS_REP()
        reply['pvno'] = 5
        reply['msg-type'] = constants.ApplicationTagNumbers.AS_REP.value
        reply['crealm'] = 'EXAMPLE.TEST'
        seq_set(reply, 'cname', Principal('alice', type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
        reply['ticket'] = noValue
        reply['ticket']['tkt-vno'] = 5
        reply['ticket']['realm'] = 'EXAMPLE.TEST'
        seq_set(reply['ticket'], 'sname', Principal('krbtgt/EXAMPLE.TEST', type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
        reply['ticket']['enc-part'] = noValue
        reply['ticket']['enc-part']['etype'] = enctype
        reply['ticket']['enc-part']['cipher'] = b'ticket'
        reply['enc-part'] = noValue
        reply['enc-part']['etype'] = enctype
        reply['enc-part']['cipher'] = cipher_text
        return encoder.encode(reply)

    def test_tag_26_as_reply_and_omitted_starttime(self):
        enctype = constants.EncryptionTypes.rc4_hmac.value
        key = Key(enctype, b'K' * 16)
        part = EncTGSRepPart()
        part['key']['keytype'] = enctype
        part['key']['keyvalue'] = b'S' * 16
        part['last-req'] = noValue
        part['nonce'] = 1
        part['flags'] = constants.encodeFlags([])
        part['authtime'] = '20260101000000Z'
        part['endtime'] = '20260102000000Z'
        part['srealm'] = 'EXAMPLE.TEST'
        seq_set(part, 'sname', Principal('krbtgt/EXAMPLE.TEST', type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
        reply = self._as_reply(enctype, _enctype_table[enctype].encrypt(key, 3, encoder.encode(part), None))

        with mock.patch('impacket.krb5.kerberosv5.sendReceive', return_value=reply):
            tgt, _, reply_key, session_key = getKerberosTGT(
                Principal('alice', type=constants.PrincipalNameType.NT_PRINCIPAL.value),
                '', 'EXAMPLE.TEST', b'', key.contents,
            )
        self.assertEqual(tgt, reply)
        self.assertEqual(session_key.contents, b'S' * 16)
        cache = CCache()
        cache.fromTGT(tgt, reply_key, session_key)
        times = cache.credentials[0]['time']
        self.assertEqual(times['starttime'], times['authtime'])

    def test_optional_tgs_body_checksum_uses_session_key_enctype(self):
        checksum_types = (
            (constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, constants.ChecksumTypes.hmac_sha1_96_aes128.value, 16),
            (constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, constants.ChecksumTypes.hmac_sha1_96_aes256.value, 32),
            (constants.EncryptionTypes.rc4_hmac.value, constants.ChecksumTypes.hmac_md5.value, 16),
        )
        for enctype, checksum_type, key_length in checksum_types:
            with self.subTest(enctype=enctype):
                session_key = Key(enctype, b'K' * key_length)

                def inspect_request(data, *args, **kwargs):
                    request = decoder.decode(data, asn1Spec=TGS_REQ())[0]
                    ap_req = decoder.decode(request['padata'][0]['padata-value'], asn1Spec=AP_REQ())[0]
                    plaintext = _enctype_table[enctype].decrypt(session_key, 7, ap_req['authenticator']['cipher'])
                    authenticator = decoder.decode(plaintext, asn1Spec=Authenticator())[0]
                    self.assertEqual(int(authenticator['cksum']['cksumtype']), checksum_type)
                    body = request['req-body'].clone(tagSet=KDC_REQ_BODY.tagSet, cloneValueFlag=True)
                    verify_checksum(checksum_type, session_key, 6, encoder.encode(body),
                                    authenticator['cksum']['checksum'].asOctets())
                    raise KerberosError(constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value)

                with mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=inspect_request):
                    with self.assertRaises(KerberosError):
                        getKerberosTGS(
                            Principal('HTTP/server.example.test', type=constants.PrincipalNameType.NT_SRV_INST.value),
                            'EXAMPLE.TEST', None, self._as_reply(enctype, b'reply'),
                            _enctype_table[enctype], session_key, request_body_checksum=True,
                        )
