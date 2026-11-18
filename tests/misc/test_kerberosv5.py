import datetime
from unittest import TestCase, mock

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REP, AS_REP, EncAPRepPart, TGS_REQ, seq_set
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import GSSAPI
from impacket.krb5.kerberosv5 import DEFAULT_TGS_ENCTYPES, RC4_PREFERRED_TGS_ENCTYPES, KerberosError, \
    getKerberosTGS, getKerberosTGSRequestEnctypes, getKerberosType3
from impacket.krb5.types import KerberosTime, Principal
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech


class _RC4Cipher:
    enctype = constants.EncryptionTypes.rc4_hmac.value

    @staticmethod
    def encrypt(key, keyUsage, data, iv):
        return b'encrypted-authenticator'


def _build_rc4_tgt(tgtService='krbtgt/EXAMPLE.COM', ticketRealm='EXAMPLE.COM'):
    asRep = AS_REP()
    asRep['pvno'] = 5
    asRep['msg-type'] = constants.ApplicationTagNumbers.AS_REP.value
    asRep['crealm'] = ticketRealm
    seq_set(
        asRep,
        'cname',
        Principal('user', type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1,
    )

    asRep['ticket'] = noValue
    asRep['ticket']['tkt-vno'] = 5
    asRep['ticket']['realm'] = ticketRealm
    seq_set(
        asRep['ticket'],
        'sname',
        Principal(
            tgtService,
            type=constants.PrincipalNameType.NT_SRV_INST.value,
        ).components_to_asn1,
    )
    asRep['ticket']['enc-part'] = noValue
    asRep['ticket']['enc-part']['etype'] = constants.EncryptionTypes.rc4_hmac.value
    asRep['ticket']['enc-part']['cipher'] = b'ticket'

    asRep['enc-part'] = noValue
    asRep['enc-part']['etype'] = constants.EncryptionTypes.rc4_hmac.value
    asRep['enc-part']['cipher'] = b'reply'
    return encoder.encode(asRep)


class KerberosTGSEnctypeTests(TestCase):
    def _assert_request_enctypes(self, requestedEtypes, expectedEtypes):
        requests = []

        def capture_request(data, domain, kdcHost, timeout=None):
            tgsReq = decoder.decode(data, asn1Spec=TGS_REQ())[0]
            requests.append(tuple(int(etype) for etype in tgsReq['req-body']['etype']))
            raise KerberosError(constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value)

        with mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=capture_request) as sendReceive:
            with self.assertRaises(KerberosError):
                getKerberosTGS(
                    Principal('cifs/server.example.com', type=constants.PrincipalNameType.NT_SRV_INST.value),
                    'EXAMPLE.COM',
                    None,
                    _build_rc4_tgt(),
                    _RC4Cipher(),
                    object(),
                    etypes=requestedEtypes,
                )

        sendReceive.assert_called_once()
        self.assertEqual(requests, [expectedEtypes])

    def test_default_tgs_enctypes_are_aes_first(self):
        self.assertEqual(
            getKerberosTGSRequestEnctypes(),
            (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                constants.EncryptionTypes.rc4_hmac.value,
                constants.EncryptionTypes.des3_cbc_sha1_kd.value,
                constants.EncryptionTypes.des_cbc_md5.value,
            ),
        )
        self.assertEqual(getKerberosTGSRequestEnctypes(), DEFAULT_TGS_ENCTYPES)

    def test_tgs_enctype_override_is_normalized(self):
        self.assertEqual(
            getKerberosTGSRequestEnctypes(
                (
                    constants.EncryptionTypes.rc4_hmac,
                    constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
                )
            ),
            (
                constants.EncryptionTypes.rc4_hmac.value,
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value,
            ),
        )

    def test_empty_tgs_enctype_override_is_rejected(self):
        with self.assertRaises(ValueError):
            getKerberosTGSRequestEnctypes(())

    def test_rc4_tgt_advertises_default_enctypes_in_one_request(self):
        self._assert_request_enctypes(None, DEFAULT_TGS_ENCTYPES)

    def test_rc4_preference_can_be_requested_explicitly(self):
        self._assert_request_enctypes(RC4_PREFERRED_TGS_ENCTYPES, RC4_PREFERRED_TGS_ENCTYPES)


class KerberosType3Tests(TestCase):
    def test_last_leg_carries_the_mech_list_mic(self):
        cipher = _enctype_table[constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value]()
        session_key = Key(cipher.enctype, b"\x11" * 32)
        acceptor_subkey = Key(cipher.enctype, b"\x22" * 32)

        enc_ap_rep_part = EncAPRepPart()
        enc_ap_rep_part["ctime"] = KerberosTime.to_asn1(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        enc_ap_rep_part["cusec"] = 0
        enc_ap_rep_part["subkey"]["keytype"] = acceptor_subkey.enctype
        enc_ap_rep_part["subkey"]["keyvalue"] = acceptor_subkey.contents
        enc_ap_rep_part["seq-number"] = 1234
        ap_rep = AP_REP()
        ap_rep["pvno"] = 5
        ap_rep["msg-type"] = int(constants.ApplicationTagNumbers.AP_REP.value)
        ap_rep["enc-part"]["etype"] = cipher.enctype
        ap_rep["enc-part"]["cipher"] = cipher.encrypt(session_key, 12, encoder.encode(enc_ap_rep_part), None)
        server_token = SPNEGO_NegTokenResp()
        server_token["NegState"] = b"\x01"  # accept-incomplete
        server_token["SupportedMech"] = TypesMech["MS KRB5 - Microsoft Kerberos 5"]
        server_token["ResponseToken"] = encoder.encode(ap_rep)

        _, new_session_key, last_leg = getKerberosType3(cipher, session_key, server_token.getData())

        neg_token_init = SPNEGO_NegTokenInit()
        neg_token_init["MechTypes"] = [TypesMech["MS KRB5 - Microsoft Kerberos 5"]]
        expected_mic = GSSAPI(cipher).GSS_GetMIC(acceptor_subkey, neg_token_init.getMechTypesDER(), 0, pad=False)
        self.assertEqual(new_session_key.contents, acceptor_subkey.contents)
        self.assertTrue(last_leg.endswith(expected_mic))


class KerberosTGSRealmTests(TestCase):
    def _request_realm(self, domain, tgtService, ticketRealm='EXAMPLE.COM'):
        """Returns the realm of the emitted TGS-REQ and the host it was sent to"""
        sent = []

        def capture_request(data, host, kdcHost, timeout=None):
            tgsReq = decoder.decode(data, asn1Spec=TGS_REQ())[0]
            sent.append((str(tgsReq['req-body']['realm']), host))
            raise KerberosError(constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value)

        with mock.patch('impacket.krb5.kerberosv5.sendReceive', side_effect=capture_request):
            with self.assertRaises(KerberosError):
                getKerberosTGS(
                    Principal('cifs/server.child.example.com', type=constants.PrincipalNameType.NT_SRV_INST.value),
                    domain,
                    None,
                    _build_rc4_tgt(tgtService, ticketRealm),
                    _RC4Cipher(),
                    object(),
                )

        self.assertEqual(len(sent), 1)
        return sent[0]

    def test_regular_tgt_keeps_the_requested_realm(self):
        self.assertEqual(self._request_realm('EXAMPLE.COM', 'krbtgt/EXAMPLE.COM'),
                         ('EXAMPLE.COM', 'EXAMPLE.COM'))

    def test_inter_realm_tgt_is_sent_to_the_realm_it_grants(self):
        # krbtgt/CHILD.EXAMPLE.COM@EXAMPLE.COM can only be used at CHILD.EXAMPLE.COM's KDC,
        # asking EXAMPLE.COM's own KDC returns KDC_ERR_WRONG_REALM
        self.assertEqual(self._request_realm('EXAMPLE.COM', 'krbtgt/CHILD.EXAMPLE.COM'),
                         ('CHILD.EXAMPLE.COM', 'CHILD.EXAMPLE.COM'))
        self.assertEqual(self._request_realm('example.com', 'krbtgt/child.example.com'),
                         ('CHILD.EXAMPLE.COM', 'CHILD.EXAMPLE.COM'))

    def test_realm_explicitly_asked_by_the_caller_is_kept(self):
        # Referral chasing walks the trust path, the caller's realm must win there
        self.assertEqual(self._request_realm('OTHER.COM', 'krbtgt/CHILD.EXAMPLE.COM'),
                         ('OTHER.COM', 'OTHER.COM'))

    def test_service_ticket_used_as_a_tgt_keeps_the_requested_realm(self):
        self.assertEqual(self._request_realm('EXAMPLE.COM', 'cifs/server.example.com'),
                         ('EXAMPLE.COM', 'EXAMPLE.COM'))
