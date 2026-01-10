# Written by Ozelis (https://github.com/ozelis)

import os, sys, re, uuid, logging, ssl, shlex

from base64 import b64encode, b64decode
from struct import pack, unpack
from random import randbytes
from pathlib import Path
from datetime import datetime, timezone

import xml.etree.ElementTree as ET

# pip install requests
from requests import Session, Request

from urllib3 import disable_warnings
from urllib3.util import SKIP_HEADER
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
disable_warnings(category=InsecureRequestWarning)

# -- impacket: ------------------------------------------------------------------------------------
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type.univ import ObjectIdentifier, noValue

from impacket.ntlm import getNTLMSSPType1, getNTLMSSPType3, SEALKEY, SIGNKEY, SEAL, SIGN
from impacket.ntlm import NTLMAuthNegotiate, NTLMAuthChallenge, NTLMAuthChallengeResponse
from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_CHANNEL_BINDINGS

from impacket.krb5.asn1 import AP_REQ, AP_REP, TGS_REP, Authenticator, EncAPRepPart
from impacket.krb5.asn1 import seq_set, _sequence_component, _sequence_optional_component
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.ccache import CCache
from impacket.krb5.constants import PrincipalNameType, ApplicationTagNumbers, encodeFlags
from impacket.krb5.kerberosv5 import getKerberosTGS, getKerberosTGT

from impacket.krb5.gssapi import GSSAPI, KRB5_AP_REQ, CheckSumField
from impacket.krb5.gssapi import GSS_C_MUTUAL_FLAG, GSS_C_REPLAY_FLAG, GSS_C_SEQUENCE_FLAG
from impacket.krb5.gssapi import GSS_C_CONF_FLAG, GSS_C_INTEG_FLAG, KG_USAGE_INITIATOR_SEAL
from impacket.krb5.gssapi import KG_USAGE_ACCEPTOR_SEAL

from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target

import pyasn1.type as asn1
from pyasn1.type import univ, namedtype, tag

from Cryptodome.Hash import HMAC, MD5, SHA256
from Cryptodome.Cipher import ARC4

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# -- helpers and constants: -----------------------------------------------------------------------
def chunks(xs, n):
    for off in range(0, len(xs), n):
        yield xs[off:off+n]

def b64str(s):
    if isinstance(s, str):
        return b64encode(s.encode()).decode()
    else:
        return b64encode(s).decode()

_utfstr = re.compile(r'_x([0-9a-fA-F]{4})_')
def utfstr(s):
    # strings inside clixml that have non-printable characters are encoded like this, eg:
    # '\n' would be "_x000A_", etc.. although i don't know how to tell if a charcter was
    # encoded during xml serialization or there was a literal *string* "_x000A_" somewhere
    # to begin with:
    try:
        return _utfstr.sub(lambda m: bytes.fromhex(m.group(1)).decode("utf-16be"), s)
    except:
        return s

zero_uuid = str(uuid.UUID(bytes_le=bytes(16))).upper()

# stolen from https://github.com/skelsec/asyauth/blob/main/asyauth/protocols/kerberos/gssapi.py
# this parses as GSSAPI structure from impacket.spnego but if i use that to create this it fails
# for whatever reason...
def krb5_mech_indep_token_encode(oid, data):
    payload = encoder.encode(ObjectIdentifier(oid)) + data
    n = len(payload)
    if n < 128:
        size = n.to_bytes(1, "big")
    else:
        size = n.to_bytes((n.bit_length() + 7) // 8, "big")
        size = (128 + len(size)).to_bytes(1, "big") + size

    return b"\x60" + size + payload

def krb5_mech_indep_token_decode(data):
    skip = 2 + (data[1] if data[1] < 128 else (data[1] - 128))
    return decoder.decode(data[skip:], asn1Spec=ObjectIdentifier)

def get_server_certificate(url):
    addr = (urlparse(url).hostname, urlparse(url).port or 443)
    cert = ssl.get_server_certificate(addr)
    cert = cert.removeprefix("-----BEGIN CERTIFICATE-----\n")
    cert = cert.removesuffix("-----END CERTIFICATE-----\n")
    return b64decode(cert)

# stolen from https://github.com/jborean93/pyspnego/blob/main/src/spnego/_credssp.py#L127
def tls_trailer_length(data_length, protocol, cipher_suite):
    if protocol == "TLSv1.3":
        trailer_length = 17
    elif re.match(r"^.*[-_]GCM[-_][\w\d]*$", cipher_suite):
        trailer_length = 16
    else:
        hash_algorithm = cipher_suite.split("-")[-1]
        hash_length = {"MD5": 16, "SHA": 20, "SHA256": 32, "SHA384": 48}.get(hash_algorithm, 0)
        pre_pad_length = data_length + hash_length
        if "RC4" in cipher_suite:
            padding_length = 0
        elif "DES" in cipher_suite or "3DES" in cipher_suite:
            padding_length = 8 - (pre_pad_length % 8)
        else:
            padding_length = 16 - (pre_pad_length % 16)
        trailer_length = (pre_pad_length + padding_length) - data_length
    return trailer_length


# -- missing CredSSP structures: ------------------------------------------------------------------
class NegoData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("negoToken", 0, univ.OctetString())
    )

class TSRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("version", 0, univ.Integer()),
        _sequence_optional_component("negoTokens", 1, univ.SequenceOf(componentType=NegoData())),
        _sequence_optional_component("authInfo", 2, univ.OctetString()),
        _sequence_optional_component("pubKeyAuth", 3, univ.OctetString()),
        _sequence_optional_component("errorCode", 4, univ.Integer()),
        _sequence_optional_component("clientNonce", 5, univ.OctetString())
    )

    @staticmethod
    def nego_response(token, version=6):
        tsreq = TSRequest()
        tsreq["version"] = version
        if token:
            data = NegoData()
            data["negoToken"] = token
            tsreq["negoTokens"].extend([data])
        return tsreq

class TSPasswordCreds(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("domainName", 0, univ.OctetString()),
        _sequence_component("userName", 1, univ.OctetString()),
        _sequence_component("password", 2, univ.OctetString())
    )

class TSCredentials(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("credType", 0, univ.Integer()),
        _sequence_component("credentials", 1, univ.OctetString())
    )

# -- wsman soap helpers: --------------------------------------------------------------------------
soap_actions = {
    "create"  : "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
    "delete"  : "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
    "receive" : "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
    "command" : "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
    "signal"  : "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
}

#https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/1c651dae-1f95-40b0-8d8d-ccd2793640e3
soap_ns = {
    "s"     : "http://www.w3.org/2003/05/soap-envelope",
    "wsa"   : "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "rsp"   : "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "wsman" : "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "wsmv"  : "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
}

def xml_get_text(root, xpath, default=None):
    el = root.find(xpath, soap_ns)
    if el is None:
        return default
    elif el.text is None:
        return default
    else:
        return utfstr(el.text)

def xml_get_attrib(root, xpath, attrib, default=None):
    el = root.find(xpath, soap_ns)
    if el is None:
        return default
    else:
        return el.get(attrib) or default

# fill in common fields for soap request:
def soap_req(action, session_id, shell_id=None, timeout=1, plugin="Microsoft.PowerShell"):
    message_id = str(uuid.uuid4()).upper()
    must_undestand = lambda v=True: { "s:mustUnderstand" : str(v).lower() }

    envelope = ET.Element("s:Envelope", { f"xmlns:{ns}" : uri for ns, uri in soap_ns.items() })
    header   = ET.SubElement(envelope, "s:Header")
    body     = ET.SubElement(envelope, "s:Body")

    ET.SubElement(header, "wsman:ResourceURI", must_undestand()).text \
        = f"http://schemas.microsoft.com/powershell/{plugin}"

    ET.SubElement(ET.SubElement(header, "wsa:ReplyTo"), "wsa:Address", must_undestand()).text \
        = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"

    ET.SubElement(header, "wsa:To").text = "http://localhost/wsman"
    ET.SubElement(header, "wsa:Action", must_undestand()).text = soap_actions[action]
    ET.SubElement(header, "wsa:MessageID").text = f"uuid:{message_id}"
    ET.SubElement(header, "wsman:MaxEnvelopeSize", must_undestand()).text = "153600"
    ET.SubElement(header, "wsman:Locale", must_undestand(False) | { "xml:lang" : "en-US" })
    ET.SubElement(header, "wsman:OperationTimeout").text = f"PT{timeout}S"
    ET.SubElement(header, "wsman:OptionSet", must_undestand())
    ET.SubElement(header, "wsmv:DataLocale", must_undestand(False) | { "xml:lang" : "en-US" })
    ET.SubElement(header, "wsmv:SessionId", must_undestand(False)).text = f"uuid:{session_id}"

    selector = ET.SubElement(header, "wsman:SelectorSet")
    if shell_id:
        ET.SubElement(selector, "wsman:Selector", { "Name": "ShellId" }).text = shell_id

    return envelope

# -- PSObjects: -----------------------------------------------------------------------------------
# bare minimum to get a basic shell going:
def ps_simple(name, kind, value):
    el = ET.Element(kind, { "N" : name })
    if value is not None:
        el.text = str(value)
    return el

def ps_enum(name, value):
    obj = ET.Element("Obj", { "N" : name })
    ET.SubElement(obj, "I32").text = str(value)
    return obj

def ps_struct(name, elements):
    obj = ET.Element("Obj", ({ "N" : name } if name else {}))
    ET.SubElement(obj, "MS").extend(elements)
    return obj

def ps_list(name, elements):
    obj = ET.Element("Obj", { "N" : name })
    ET.SubElement(obj, "LST").extend(elements)
    return obj

ps_capability = ps_struct(None, [
    ps_simple("protocolversion",      "Version", "2.1"),
    ps_simple("PSVersion",            "Version", "2.0"),
    ps_simple("SerializationVersion", "Version", "1.1.0.10")
])

ps_runspace_pool = ps_struct(None, [
    ps_simple("MinRunspaces", "I32", 1),
    ps_simple("MaxRunspaces", "I32", 1),
    ps_enum("PSThreadOptions", 0),
    ps_enum("ApartmentState",  2),
    ps_struct("HostInfo", [
        ps_simple("_isHostNull",      "B", "true"),
        ps_simple("_isHostUINull",    "B", "true"),
        ps_simple("_isHostRawUINull", "B", "true"),
        ps_simple("_useRunspaceHost", "B", "true")
    ]),
    ps_simple("ApplicationArguments", "Nil", None)
])

ps_args = lambda args, raw=False: [
    ps_struct(None, [
        ps_simple("N", "S", k),
        ps_simple("V", "S" if v else "Nil", v) if not raw else v
    ]) for k, v in args.items()
]

ps_command = lambda cmd, args : ps_struct(None, [
    ps_simple("Cmd", "S", cmd),
    ps_list("Args", ps_args(args)),
    ps_simple("IsScript", "B", "false"),
    ps_simple("UseLocalScope", "Nil", None),
    # these are PipelineResultTypes::None (Default streaming behavior):
    ps_enum("MergeMyResult",        0),
    ps_enum("MergeToResult",        0),
    ps_enum("MergePreviousResults", 0),
    ps_enum("MergeError",           0),
    ps_enum("MergeWarning",         0),
    ps_enum("MergeVerbose",         0),
    ps_enum("MergeDebug",           0),
    ps_enum("MergeInformation",     0),
])

ps_create_pipeline = lambda commands : ps_struct(None, [
    ps_simple("NoInput",      "B", "true"),
    ps_simple("AddToHistory", "B", "false"),
    ps_simple("IsNested",     "B", "false"),
    ps_enum("ApartmentState", 2),       # Unknown
    ps_enum("RemoteStreamOptions", 15), # AddInvocationInfo
    ps_struct("HostInfo", [
        ps_simple("_isHostNull",      "B", "true"),
        ps_simple("_isHostUINull",    "B", "true"),
        ps_simple("_isHostRawUINull", "B", "true"),
        ps_simple("_useRunspaceHost", "B", "true")
    ]),
    ps_struct("PowerShell", [
        ps_simple("IsNested", "B", "false"),
        ps_simple("RedirectShellErrorOutputPipe", "B", "false"),
        ps_simple("ExtraCmds", "Nil", None),
        ps_simple("History", "Nil", None),
        ps_list("Cmds", commands)
    ])
])


# -- message framing: -----------------------------------------------------------------------------
msg_ids = {
    0x00010002 : "SESSION_CAPABILITY",
    0x00010004 : "INIT_RUNSPACEPOOL",
    0x00010005 : "PUBLIC_KEY",
    0x00010006 : "ENCRYPTED_SESSION_KEY",
    0x00010007 : "PUBLIC_KEY_REQUEST",
    0x00010008 : "CONNECT_RUNSPACEPOOL",
    0x0002100B : "RUNSPACEPOOL_INIT_DATA",
    0x0002100C : "RESET_RUNSPACE_STATE",
    0x00021002 : "SET_MAX_RUNSPACES",
    0x00021003 : "SET_MIN_RUNSPACES",
    0x00021004 : "RUNSPACE_AVAILABILITY",
    0x00021005 : "RUNSPACEPOOL_STATE",
    0x00021006 : "CREATE_PIPELINE",
    0x00021007 : "GET_AVAILABLE_RUNSPACES",
    0x00021008 : "USER_EVENT",
    0x00021009 : "APPLICATION_PRIVATE_DATA",
    0x0002100A : "GET_COMMAND_METADATA",
    0x00021100 : "RUNSPACEPOOL_HOST_CALL",
    0x00021101 : "RUNSPACEPOOL_HOST_RESPONSE",
    0x00041002 : "PIPELINE_INPUT",
    0x00041003 : "END_OF_PIPELINE_INPUT",
    0x00041004 : "PIPELINE_OUTPUT",
    0x00041005 : "ERROR_RECORD",
    0x00041006 : "PIPELINE_STATE",
    0x00041007 : "DEBUG_RECORD",
    0x00041008 : "VERBOSE_RECORD",
    0x00041009 : "WARNING_RECORD",
    0x00041010 : "PROGRESS_RECORD",
    0x00041011 : "INFORMATION_RECORD",
    0x00041100 : "PIPELINE_HOST_CALL",
    0x00041101 : "PIPELINE_HOST_RESPONSE"
}

for k, v in msg_ids.items():
    globals()[v] = k

# -- transports: ----------------------------------------------------------------------------------
class TransportError(Exception):
    pass

class SPNEGOError(Exception):
    pass

class NTCredential:
    def __init__(self, domain, username, password="", nt_hash=""):
        self.domain = domain
        self.username = username
        self.password = password
        self.nt_hash = nt_hash

class KrbCredential:
    def __init__(self, domain, username, ticket, tgskey, password=""):
        self.domain = domain
        self.username = username
        self.password = password # for CredSSP only
        self.ticket = ticket
        self.tgskey = tgskey

class SPNEGOProxyNTLM:
    def __init__(self, creds, gss_bindings=None):
        self.creds = creds
        self.gss_bindings = gss_bindings
        self.complete = False

    def step(self, data_in=None):
        if data_in is None:
            self._type1 = getNTLMSSPType1()
            self._type1["flags"] = 0xe0088237 # wiresharked
            init = SPNEGO_NegTokenInit()
            init["MechTypes"] = [ TypesMech["NTLMSSP - Microsoft NTLM Security Support Provider"] ]
            init["MechToken"] = self._type1.getData()
            return init.getData()

        try:
            targ = SPNEGO_NegTokenResp(data_in)
            neg_state = targ["NegState"][0]
        except:
            raise SPNEGOError("SPNEGO: bad response")

        if neg_state == 0: # accept-completed
            self.complete = True

        elif neg_state == 1: # accept-incomplete
            type2 = targ["ResponseToken"] # NTLMAuthChallenge

            if self.gss_bindings:
                chal = NTLMAuthChallenge(type2)
                info = AV_PAIRS(chal['TargetInfoFields'])
                info[NTLMSSP_AV_CHANNEL_BINDINGS] = self.gss_bindings
                chal["TargetInfoFields"]          = info.getData()
                chal["TargetInfoFields_len"]      = len(info.getData())
                chal["TargetInfoFields_max_len"]  = len(info.getData())
                type2 = chal.getData()

            nt_hash = bytes.fromhex(self.creds.nt_hash) if self.creds.nt_hash else ""
            type3, key = getNTLMSSPType3(self._type1, type2, self.creds.username,
                                         self.creds.password, "", "", nt_hash)

            resp = SPNEGO_NegTokenResp()
            resp["NegState"] = b"\x01"
            resp["SupportedMech"] = b""
            resp["ResponseToken"] = type3.getData()

            self.seq_cli  = 0
            self.seq_srv  = 0
            self.key_cli = SIGNKEY(type3["flags"], key, "Client")
            self.key_srv = SIGNKEY(type3["flags"], key, "Server")
            self.rc4_cli = ARC4.new(SEALKEY(type3["flags"], key, "Client"))
            self.rc4_srv = ARC4.new(SEALKEY(type3["flags"], key, "Server"))
            return resp.getData()

        elif neg_state == 2: # reject
            raise SPNEGOError("NTLM rejected")

        else: # if neg_state == 3 (request-mic)
            raise NotImplementedError("request-mic")

    def wrap(self, req, joined=False):
        seq = pack("<I", self.seq_cli)
        enc = self.rc4_cli.encrypt(req)
        sig = HMAC.new(self.key_cli, seq + req, digestmod=MD5).digest()[:8]
        sig = pack("<I", 1) + self.rc4_cli.encrypt(sig) + seq
        self.seq_cli += 1
        return (sig + enc) if joined else (sig, enc)

    def unwrap(self, sig, enc):
        plaintext = self.rc4_srv.decrypt(enc)
        seq = pack("<I", self.seq_srv)
        sig_test = HMAC.new(self.key_srv, seq + plaintext, digestmod=MD5).digest()[:8]
        sig_test = self.rc4_srv.decrypt(sig_test)
        if sig[4:12] != sig_test:
            raise SPNEGOError("unwrap(): message integrity failure")
        self.seq_srv += 1
        return plaintext


class SPNEGOProxyKerberos:
    def __init__(self, creds, gss_bindings=None):
        self.creds = creds
        self.gss_bindings = gss_bindings
        self.complete = False

    def step(self, data_in=None):
        if data_in is None:
            user = Principal(self.creds.username, type=PrincipalNameType.NT_PRINCIPAL.value)
            cipher = _enctype_table[self.creds.tgskey.enctype]

            checksum = CheckSumField()
            checksum['Lgth']  = 16
            checksum['Flags'] = GSS_C_CONF_FLAG|GSS_C_INTEG_FLAG|GSS_C_SEQUENCE_FLAG|GSS_C_MUTUAL_FLAG
            if self.gss_bindings:
                checksum['Bnd'] = self.gss_bindings

            now = datetime.now(timezone.utc)
            auth = Authenticator()
            seq_set(auth, 'cname', user.components_to_asn1)
            auth['authenticator-vno']  = 5
            auth['crealm']             = self.creds.domain.upper()
            auth['cusec']              = now.microsecond
            auth['ctime']              = KerberosTime.to_asn1(now)
            auth['cksum']              = noValue
            auth['cksum']['cksumtype'] = 0x8003
            auth['cksum']['checksum']  = checksum.getData()
            auth['seq-number']         = 0
            # include a dummy subkey here with enctype=18 so that when in AP_REP when application
            # returns *it's* subkey it will have this enctype too, otherwise it will have
            # the same enctype as tgskey (eg 23) and WinRM can only work with AES (?):
            auth['subkey'] = noValue
            auth['subkey']['keyvalue'] = randbytes(32)
            auth['subkey']['keytype']  = 18
            enc_auth = cipher.encrypt(self.creds.tgskey, 11, encoder.encode(auth), None)

            ap_req = AP_REQ()
            ap_req['pvno']          = 5
            ap_req['msg-type']      = int(ApplicationTagNumbers.AP_REQ.value)
            ap_req['ap-options']    = encodeFlags([2]) # mutual-required
            ap_req['authenticator'] = noValue
            ap_req['authenticator']['etype'] = cipher.enctype
            ap_req['authenticator']['cipher'] = enc_auth
            seq_set(ap_req, 'ticket', self.creds.ticket.to_asn1)

            init = SPNEGO_NegTokenInit()
            init["MechTypes"] = [ TypesMech["MS KRB5 - Microsoft Kerberos 5" ] ]
            init["MechToken"] = encoder.encode(ap_req)
            return init.getData()

        try:
            targ = SPNEGO_NegTokenResp(data_in)
            neg_state = targ["NegState"][0]
        except:
            raise SPNEGOError("Kerberos: unexpected response")

        if neg_state == 0: # accept-completed
            blob    = krb5_mech_indep_token_decode(targ["ResponseToken"])[1]
            ap_rep  = decoder.decode(blob[2:], asn1Spec=AP_REP())[0]
            cipher  = _enctype_table[self.creds.tgskey.enctype]
            rep_enc = cipher.decrypt(self.creds.tgskey, 12, ap_rep["enc-part"]["cipher"])
            rep_dec = decoder.decode(rep_enc, asn1Spec=EncAPRepPart())[0]

            keydata = rep_dec["subkey"]["keyvalue"].asOctets()
            keytype = rep_dec["subkey"]["keytype"]

            self.subkey   = Key(keytype, keydata)
            self.cipher   = _enctype_table[keytype]
            self.seq_cli  = 0
            self.seq_srv  = int(rep_dec["seq-number"])
            self.complete = True

        elif neg_state == 1: # accept-incomplete
            # this is probably for GSS_C_DCE_STYLE... it would expect one more
            # client->server message after AP_REP (?)
            raise SPNEGOError("Kerberos: unexpected response")

        elif neg_state == 2: # reject
            raise SPNEGOError("Kerberos: rejected")

        else: # request-mic
            raise NotImplementedError("request-mic")

    def wrap(self, req, joined=False):
        sig = pack(">BBBBHHQ", 5, 4, 6, 0xff, 0, 0, self.seq_cli)
        enc = self.cipher.encrypt(self.subkey, KG_USAGE_INITIATOR_SEAL, req + sig, None)
        rot = len(enc) - (28 % len(enc))
        enc = enc[rot:] + enc[:rot]
        sig = pack(">BBBBHHQ", 5, 4, 6, 0xff, 0, 28, self.seq_cli)
        self.seq_cli += 1
        return sig + enc if joined else (sig + enc[:44], enc[44:])

    def unwrap(self, sig, enc):
        _, _, _, _, ec, rrc, seq_srv = unpack(">BBBBHHQ", sig[:16])
        if seq_srv != self.seq_srv:
            raise SPNEGOError("Kerberos: replay")

        self.seq_srv += 1
        enc = sig[16:] + enc
        rot = (rrc + ec) % len(enc)
        enc = enc[rot:] + enc[:rot]
        plaintext = self.cipher.decrypt(self.subkey, KG_USAGE_ACCEPTOR_SEAL, enc)
        return plaintext[:-(ec + 16)]


class Transport:
    def __init__(self, url):
        self.url = url
        self.ssl = urlparse(url).scheme == "https"
        self.session = Session()
        self.session.verify = False
        self.session.headers["User-Agent"] = SKIP_HEADER
        self.session.headers["Accept-Encoding"] = SKIP_HEADER

    def send(self, req):
        rsp = self._send(req) # implement _send() in subclasses

        if rsp.status_code == 401:
            self._auth()      # implement _auth() in subclasses
            rsp = self._send(req)

        if rsp.status_code not in (200, 500):
            raise TransportError(f"unexcpected response: {rsp.status_code}")

        return rsp.content

    # -- helper methods common to CredSSP/SPNEGO/Kerberos: ----------------------------------------
    def _send_auth(self, req, proto, phase=""):
        rsp = self.session.post(self.url, headers={ "Authorization" : f"{proto} {b64str(req)}" })
        www_auth = rsp.headers.get("WWW-Authenticate", "")

        if rsp.status_code == 200 and not www_auth:
            return b""
        elif not www_auth.startswith(f"{proto} "):
            raise TransportError(f"{proto}: {phase}")

        return b64decode(www_auth.removeprefix(f"{proto} "))

    def _encrypted_request(self, req, proto, wrap_fn):
        protocol  = f"application/HTTP-{proto}-session-encrypted"

        data = b""
        for chunk in chunks(req, 16384):
            data += b"--Encrypted Boundary\r\n"
            data += f"Content-Type: {protocol}\r\n".encode()
            data += f"OriginalContent: type=application/soap+xml;charset=UTF-8;Length={len(chunk)}\r\n".encode()
            data += b"--Encrypted Boundary\r\n"

            sig, enc = wrap_fn(chunk)
            data += b"Content-Type: application/octet-stream\r\n" + pack("<I", len(sig)) + sig + enc

        data += b"--Encrypted Boundary--\r\n"

        return self.session.prepare_request(Request("POST", url=self.url, data=data, headers={
            "Content-Type" : f'multipart/x-multi-encrypted;protocol="{protocol}";boundary="Encrypted Boundary"'
        }))

    def _decrypted_response(self, rsp, unwrap_fn):
        if rsp.status_code not in (200, 500):
            return rsp

        # The prefix can have tabs or spaces - let's handle both
        prefix_space = b"\r\nContent-Type: application/octet-stream\r\n"
        prefix_tab = b"\r\n\tContent-Type: application/octet-stream\r\n"
        plaintext = b""
        
        parts = rsp.content.split(b"--Encrypted Boundary")
        
        for i, part in enumerate(parts):
            if part.startswith(prefix_space):
                part = part.removeprefix(prefix_space)
            elif part.startswith(prefix_tab):
                part = part.removeprefix(prefix_tab)
            else:
                continue
                
            if len(part) < 4:
                continue
            sig_len = unpack("<I", part[:4])[0]
            if len(part) < 4 + sig_len:
                continue
            try:
                decrypted = unwrap_fn(part[4:4+sig_len], part[4+sig_len:])
                plaintext += decrypted
            except Exception as e:
                logging.debug(f"Part {i} decryption failed: {e}")

        rsp.headers["Content-Type"] = "application/soap+xml;charset=UTF-8"
        rsp.headers["Content-Length"] = str(len(plaintext))
        rsp._content = plaintext
        return rsp


class BasicTransport(Transport):
    def __init__(self, url, username, password):
        super().__init__(url)
        self.session.auth = (username, password)

    def _send(self, req):
        return self.session.post(self.url, data=req, headers={
            "Content-Type" : "application/soap+xml;charset=UTF-8"
        })

    def _auth(self):
        pass


class ClientCertTransport(Transport):
    def __init__(self, url, cert_pem, cert_key):
        super().__init__(url)
        self.session.cert = (cert_pem, cert_key)
        self.session.headers["Authorization"] \
            = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

    def _send(self, req):
        return self.session.post(self.url, data=req, headers={
            "Content-Type" : "application/soap+xml;charset=UTF-8"
        })

    def _auth(self):
        pass


class SPNEGOTransport(Transport):
    def __init__(self, url, creds):
        super().__init__(url)
        self.creds = creds

        if self.ssl:
            cert = SHA256.new(get_server_certificate(url)).digest()
            app_data = b"tls-server-end-point:" + cert
            self.gss_bindings = MD5.new(bytes(16) + pack("<I", len(app_data)) + app_data).digest()
        else:
            self.gss_bindings = None

        self._auth()

    def _send(self, req):
        rsp = self.session.send(self._encrypted_request(req, "SPNEGO", self.proxy.wrap))
        return self._decrypted_response(rsp, self.proxy.unwrap)

    def _auth(self):
        if isinstance(self.creds, NTCredential):
            self.proxy = SPNEGOProxyNTLM(self.creds, self.gss_bindings)
        else:
            self.proxy = SPNEGOProxyKerberos(self.creds, self.gss_bindings)

        token_out = self.proxy.step()
        while not self.proxy.complete:
            token_in = self._send_auth(token_out, "Negotiate", "SPNEGO")
            token_out = self.proxy.step(token_in)


class KerberosTransport(Transport):
    def __init__(self, url, creds):
        super().__init__(url)
        self.creds = creds

        if self.ssl:
            cert = SHA256.new(get_server_certificate(url)).digest()
            app_data = b"tls-server-end-point:" + cert
            self.gss_bindings = MD5.new(bytes(16) + pack("<I", len(app_data)) + app_data).digest()
        else:
            self.gss_bindings = None

        self._auth()

    def _send(self, req):
        rsp = self.session.send(self._encrypted_request(req, "Kerberos", self.proxy.wrap))
        return self._decrypted_response(rsp, self.proxy.unwrap)

    def _auth(self):
        # here i hijack implementation from SPNEGOProxyKerberos, because it can already gereate
        # AP_REQ and has wrap/unwrap functions. I just need to extract AP_REQ from
        # SPNEGO_NegTokenInit and then put response back into SPNEGO_NegTokenResp:
        self.proxy = SPNEGOProxyKerberos(self.creds, self.gss_bindings)
        init = self.proxy.step()
        ap_req = SPNEGO_NegTokenInit(init)["MechToken"]
        ap_req = krb5_mech_indep_token_encode("1.2.840.113554.1.2.2", KRB5_AP_REQ + ap_req)

        rsp = self._send_auth(ap_req, "Kerberos", "AP_REQ")
        targ = SPNEGO_NegTokenResp()
        targ["NegState"] = b"\x00" # accept-completed
        targ["SupportedMech"] = b""
        targ["ResponseToken"] = rsp
        self.proxy.step(targ.getData())


class CredSSPTransport(Transport):
    def __init__(self, url, creds):
        super().__init__(url)
        self.creds = creds
        self._auth()

    def _send(self, req):
        rsp = self.session.send(self._encrypted_request(req, "CredSSP", self._wrap))
        return self._decrypted_response(rsp, self._unwrap)

    def _auth(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= ssl.OP_NO_COMPRESSION | 0x00000200 | 0x00000800
        self.tls_in  = ssl.MemoryBIO()
        self.tls_out = ssl.MemoryBIO()
        self.tls_obj = ctx.wrap_bio(self.tls_in, self.tls_out, server_side=False)

        while True:
            try:
                self.tls_obj.do_handshake()
            except:
                pass
            if req := self.tls_out.read():
                rsp = self._send_auth(req, "CredSSP", "tls handshake")
                self.tls_in.write(rsp)
            else:
                break

        cert   = self.tls_obj.getpeercert(True)
        pubkey = x509.load_der_x509_certificate(cert).public_key()
        pubkey = pubkey.public_bytes(Encoding.DER, PublicFormat.PKCS1)
        nonce  = randbytes(32)
        pkhash = SHA256.new(b"CredSSP Client-To-Server Binding Hash\x00" + nonce + pubkey).digest()

        def _send_credssp(req, phase=""):
            sig, enc = self._wrap(encoder.encode(req))
            if rsp := self._send_auth(sig + enc, "CredSSP", phase):
                rsp = decoder.decode(self._unwrap(b"", rsp), asn1Spec=TSRequest())[0]
                if rsp["errorCode"].hasValue():
                    err = int.to_bytes(rsp["errorCode"]._value, length=4, signed=True).hex()
                    raise TransportError(f"CredSSP: {phase} NT_ERROR=0x{err}")
                return rsp

        if isinstance(self.creds, NTCredential):
            proxy = SPNEGOProxyNTLM(self.creds)
        else:
            proxy = SPNEGOProxyKerberos(self.creds)

        t1 = proxy.step()
        tsreq = TSRequest.nego_response(t1)
        tsrsp = _send_credssp(tsreq, "SPNEGO init")
        t3 = proxy.step(tsrsp["negoTokens"][0]["negoToken"].asOctets())

        # TODO versions upto 5 need to send full public key instead of
        # its hash but i can't find a windows version to test against:

        tsreq = TSRequest.nego_response(t3)
        tsreq["clientNonce"] = nonce
        tsreq["pubKeyAuth"] = proxy.wrap(pkhash, joined=True)
        tsrsp = _send_credssp(tsreq, "public key exchange")

        # TODO: check if server bounced back correct pk hash

        tspass = TSPasswordCreds()
        tspass["domainName"] = self.creds.domain.encode("utf-16le")
        tspass["userName"]   = self.creds.username.encode("utf-16le")
        tspass["password"]   = self.creds.password.encode("utf-16le")

        tscred = TSCredentials()
        tscred["credType"] = 1
        tscred["credentials"] = encoder.encode(tspass)

        tsreq = TSRequest()
        tsreq["version"]  = 6
        tsreq["authInfo"] = proxy.wrap(encoder.encode(tscred), joined=True)

        _send_credssp(tsreq, "credential delegation")

    def _wrap(self, data):
        self.tls_obj.write(data)
        enc = self.tls_out.read()
        cipher, proto, _ = self.tls_obj.cipher()
        trailer_length = tls_trailer_length(len(enc), proto, cipher)
        return enc[:trailer_length], enc[trailer_length:]

    def _unwrap(self, sig, data):
        self.tls_in.write(sig + data)
        chunks = []
        while True:
            try:
                chunks.append(self.tls_obj.read())
            except ssl.SSLWantReadError:
                break

        return b"".join(chunks)

# -- MS-PSRP stuff from https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp ------
class Runspace:
    def __init__(self, transport, timeout=1):
        self.transport       = transport
        self.timeout         = timeout
        self.fragment_buffer = {}
        self.next_object_id  = 1
        self.session_id      = str(uuid.uuid4()).upper()
        self.runspace_id     = str(uuid.uuid4()).upper()
        self.pipeline_id     = str(uuid.uuid4()).upper()
        self.shell_id        = None
        self.command_id      = None

    def __enter__(self):
        req = soap_req("create", self.session_id, timeout=10)
        options = req.find("s:Header").find("wsman:OptionSet")
        protocolversion = { "Name" : "protocolversion", "MustComply" : "true" }
        ET.SubElement(options, "wsman:Option", protocolversion).text = "2.1"

        shell = ET.SubElement(req.find("s:Body"), "rsp:Shell")
        ET.SubElement(shell, "rsp:ShellId").text = "http://localhost/wsman"
        ET.SubElement(shell, "rsp:InputStreams").text = "stdin"
        ET.SubElement(shell, "rsp:OutputStreams").text = "stdout"
        ET.SubElement(shell, "creationXml").text = b64str(self._fragment([
            (SESSION_CAPABILITY, ps_capability),
            (INIT_RUNSPACEPOOL,  ps_runspace_pool)
        ]))

        rsp = self._post(req)
        if "fault" in rsp:
            raise RuntimeError(rsp["reason"])

        self.shell_id = rsp.get("shell_id")
        self._receive()
        self._receive()
        return self

    def __exit__(self, exc_type, exc_value, tb):
        req = soap_req("delete", self.session_id, self.shell_id, self.timeout)
        self._post(req)

    def run_command(self, cmd):
        self.command_id = self._create_pipeline(cmd)
        if not self.command_id:
            yield { "error" : "failed to create pipeline, if this persists restart the shell" }
            return

        timeouts = 0
        while True:
            rsp = self._receive(self.command_id)
            if "fault" in rsp:
                if rsp["subcode"] == "w:TimedOut":
                    timeouts += 1                  # some commands take a while; this is fine, but
                    yield { "timeout" : timeouts } # yield anyway, maybe user wants to interrupt
                    continue
                else:
                    yield { "error" : rsp["reason"] + "\n" + rsp["detail"] }
                    return

            timeouts = 0
            for msg_type, msg in self._defragment(rsp["streams"]):
                if msg_type == PIPELINE_OUTPUT: # from Write-Output
                    if msg.tag == "S":
                        yield { "stdout" : utfstr(msg.text) or "" }

                elif msg_type == ERROR_RECORD: # from Write-Error
                    yield { "error" : xml_get_text(msg, ".//ToString", "unknown error") }

                elif msg_type == WARNING_RECORD: # from Write-Warning
                    yield { "warn" : xml_get_text(msg, ".//ToString", "unknown warning") }

                elif msg_type == VERBOSE_RECORD: # from Write-Verbose
                    yield { "verbose" : xml_get_text(msg, ".//ToString", "") }

                elif msg_type == INFORMATION_RECORD: # from Write-Host
                    info = xml_get_text(msg, ".//Props/S[@N='Message']", "")
                    endl = xml_get_text(msg, ".//Props/B[@N='NoNewLine']", "false") == "false"
                    yield { "info" : info, "endl" : "\n" if endl else "" }

                elif msg_type == PIPELINE_STATE: # yield exceptions as errors:
                    state = int(xml_get_text(msg, ".//I32[@N='PipelineState']"))
                    if state in (3, 5, 6): # Stopped, Failed, Disconnected
                        yield { "error" : xml_get_text(msg, ".//ToString", "") }

                elif msg_type == PROGRESS_RECORD: # from Write-Progress
                    status   = xml_get_text(msg, ".//S[@N='StatusDescription']", "status")
                    activity = xml_get_text(msg, ".//S[@N='Activity']", "activity")
                    yield { "progress" : status or activity }

            if rsp["state"].endswith("CommandState/Done"):
              break

        self.command_id = None

    def interrupt(self):
        if self.command_id:
            req = soap_req("signal", self.session_id, self.shell_id, self.timeout)
            body = req.find("s:Body")
            sig = ET.SubElement(body, "rsp:Signal", { "CommandId" : self.command_id })
            ET.SubElement(sig, "rsp:Code").text = "powershell/signal/crtl_c"
            return self._post(req)

    def _post(self, req):
        rsp = ET.fromstring(self.transport.send(ET.tostring(req, encoding="utf8")))
        #  print(ET.tostring(rsp))
        action = rsp.find("./s:Header/wsa:Action", soap_ns).text
        if action.endswith("wsman/fault"):
            return {
                "fault"   : "ok",
                "subcode" : xml_get_text(rsp, ".//s:Subcode/s:Value", ""),
                "reason"  : xml_get_text(rsp, ".//s:Reason/s:Text", ""),
                "detail"  : xml_get_text(rsp, ".//s:Detail/s:Message", "")
            }
        elif action.endswith("shell/ReceiveResponse"):
            return {
                "receive" : "ok",
                "streams" : [ b64decode(s.text) for s in rsp.findall(".//rsp:Stream", soap_ns) ],
                "state"   : xml_get_attrib(rsp, ".//rsp:CommandState", "State", "")
            }
        elif action.endswith("transfer/CreateResponse"):
            return {
                "create" : "ok",
                "shell_id" : xml_get_text(rsp, ".//rsp:Shell/rsp:ShellId", "")
            }
        elif action.endswith("shell/CommandResponse"):
            return {
                "command" : "ok",
                "command_id" : xml_get_text(rsp, ".//rsp:CommandId", "")
            }
        elif action.endswith("shell/SignalResponse"):
            return { "signal" : "ok" }
        elif action.endswith("transfer/DeleteResponse"):
            return { "delete" : "ok" }
        else:
            logging.debug(ET.tostring(rsp))
            raise NotImplementedError(action)

    def _receive(self, command_id=None):
        req = soap_req("receive", self.session_id, self.shell_id, self.timeout)

        options = req.find("s:Header").find("wsman:OptionSet")
        ET.SubElement(options, "wsman:Option", { "Name" : "WSMAN_CMDSHELL_OPTION_KEEPALIVE" }).text = "true"

        receive = ET.SubElement(req.find("s:Body"), "rsp:Receive")
        attr = { "CommandId" : command_id } if command_id else {}
        ET.SubElement(receive, "rsp:DesiredStream", attr).text = "stdout"

        rsp = self._post(req)

        return rsp

    def _create_pipeline(self, cmd, is_script=False):
        pipeline = ps_create_pipeline([
            ps_command("Invoke-Expression", { "Command" : cmd }),
            ps_command("Out-String", { "Stream" : None })
        ])
        req = soap_req("command", self.session_id, self.shell_id, self.timeout)
        cmdline = ET.SubElement(req.find("s:Body"), "rsp:CommandLine")
        ET.SubElement(cmdline, "rsp:Command")
        ET.SubElement(cmdline, "rsp:Arguments").text = b64str(self._fragment([
            (CREATE_PIPELINE, pipeline)
        ]))
        return self._post(req).get("command_id")

    def _fragment(self, messages):
        fragments = b""

        for msg_type, data in messages:
            msg_data  = pack("<II", 0x00002, msg_type)
            msg_data += uuid.UUID(self.runspace_id).bytes_le
            msg_data += uuid.UUID(self.pipeline_id).bytes_le
            msg_data += ET.tostring(data)
            fragments += pack(">QQBI", self.next_object_id, 0, 3, len(msg_data)) + msg_data
            self.next_object_id += 1

        return fragments

    def _defragment(self, streams):
        for buf in streams:
            fragments = []
            while buf:
                object_id, _, start_end, msg_len = unpack(">QQBI", buf[:21])
                partial = buf[21:21 + msg_len]
                buf = buf[21 + msg_len:]

                if start_end == 3: # start and end
                    fragments.append(partial)
                    continue

                if object_id not in self.fragment_buffer:
                    self.fragment_buffer[object_id] = b""

                if start_end == 2: # end
                    fragments.append(self.fragment_buffer[object_id] + partial)
                    del self.fragment_buffer[object_id]
                else: # start or middle
                    self.fragment_buffer[object_id] += partial

            for frag in fragments:
                _, msg_type = unpack("<II", frag[:8])
                if frag[40:]:
                    msg = ET.fromstring(frag[40:])
                    yield (msg_type, msg)
                else:
                    print(">>>>>>", msg_ids[msg_type])


# -------------------------------------------------------------------------------------------------
# so with Runspace class you can execute commands like this:
# >>> creds = NTCredential("domain", "username", "password")
# >>> transport = SPNEGOTransport("http://dc01.test.lab:5985/wsman", creds)
# >>> with Runspace(transport) as runspace:
# >>>     for output in runspace.run_command("whoami /all"):
# >>>         print(output)

# the rest of the code here parses impacket-style arguments and implements a
# simple shell that runs a REPL loop:

from signal import SIGINT, signal, getsignal
from argparse import ArgumentParser
from ipaddress import ip_address

try:
    from prompt_toolkit import prompt, ANSI
    from prompt_toolkit.history import FileHistory
    prompt_toolkit_available = sys.stdout.isatty()
except ModuleNotFoundError:
    print("'prompt_toolkit' not installed, using built-in 'readline'")
    import readline
    prompt_toolkit_available = False


class CtrlCHandler:
    def __init__(self, max_interrupts=4, timeout=5):
        self.max_interrupts = max_interrupts
        self.timeout = timeout

    def __enter__(self):
        self.interrupted = 0
        self.released = False
        self.original_handler = getsignal(SIGINT)

        def handler(signum, frame):
            self.interrupted += 1
            if self.interrupted > 1:
                n = self.max_interrupts - self.interrupted + 2
                print()
                print(f"Ctrl+C spammed, {n} more will terminate ungracefully.")
                print(f"Try waiting ~{self.timeout} more seconds for a client to get a "\
                        "chance to send the interrupt")

            if self.interrupted > self.max_interrupts:
                self.release()

        signal(SIGINT, handler)
        return self

    def __exit__(self, type, value, tb):
        self.release()

    def release(self):
        if self.released:
            return False

        signal(SIGINT, self.original_handler)
        self.released = True
        return True


class Shell:
    def __init__(self, runspace):
        self.runspace  = runspace
        self.cwd        = ""
        self.need_clear = False

        if prompt_toolkit_available:
            self.prompt_history = FileHistory(".winrmexec_history")

    def repl(self, inputs=None):
        if not inputs:
            inputs = self.read_cmd_prompt()
            self.update_cwd()

        for cmd in inputs:
            if not cmd:
                continue
            elif cmd in { "exit", "quit" }:
                return
            else:
                self.run_with_interrupt(cmd, self.write_line)
                self.update_cwd()

    def read_cmd_prompt(self):
        while True:
            try:
                pre = f"\x1b[1m\x1b[33mPS\x1b[0m {self.cwd}> "
                if prompt_toolkit_available:
                    cmd = prompt(ANSI(pre), history=self.prompt_history, enable_history_search=True)
                else:
                    cmd = input(pre)
            except KeyboardInterrupt:
                if not prompt_toolkit_available:
                    print()
                continue
            except EOFError:
                return
            else:
                yield cmd

    def write_line(self, out):
        clear = "\033[2K\r" if self.need_clear else ""
        self.need_clear = False

        if "stdout" in out: # from Write-Output
            print(clear + out["stdout"], flush=True)

        elif "info" in out: # from Write-Host
            print(clear + out["info"], end=out["endl"], flush=True)

        elif "error" in out: # from Write-Error and exceptions
            print(clear + "\x1b[31m" + out["error"] + "\x1b[0m", flush=True)

        elif "warn" in out: # from Write-Warning
            print(clear + "\x1b[33m" + out["warn"] + "\x1b[0m", flush=True)

        elif "verbose" in out: # from Write-Verbose
            print(clear + out["verbose"], flush=True)

        elif "progress" in out: # from Write-Progress
            print(clear + "\x1b[34m" + out["progress"] + "\x1b[0m", end="\r", flush=True)
            self.need_clear = True

    def update_cwd(self):
        self.cwd = self.run_sync("Get-Location | Select -Expand Path").strip()

    def run_sync(self, cmd):
        return "\n".join(out.get("stdout") for out in self.runspace.run_command(cmd) if "stdout" in out)

    def run_with_interrupt(self, cmd, output_handler=None, exception_handler=None):
        output_stream = self.runspace.run_command(cmd)
        while True:
            with CtrlCHandler(timeout=self.runspace.timeout) as h:
                try:
                    out = next(output_stream)
                except StopIteration:
                    break
                except Exception as e:
                    if exception_handler and exception_handler(e):
                        continue
                    else:
                        raise e

                if output_handler:
                    output_handler(out)

                if h.interrupted:
                    self.runspace.interrupt()

        return h.interrupted > 0


def get_krb_creds(dc_ip, spn, domain, username, password="", nt_hash="", aes_key="", use_ccache=True):
    user = Principal(username, type=PrincipalNameType.NT_PRINCIPAL.value)
    http = Principal(spn,      type=PrincipalNameType.NT_PRINCIPAL.value)
    ticket = Ticket()

    if use_ccache and os.getenv("KRB5CCNAME"):
        _, _, tgt, tgs = CCache.parseFile(target=spn)
        if tgt and not tgs:
            cipher = tgt["cipher"]
            tgtkey = tgt["sessionKey"]
            tgt    = tgt["KDC_REP"]
        elif tgs:
            ticket.from_asn1(decoder.decode(tgs["KDC_REP"], asn1Spec=TGS_REP())[0]["ticket"])
            tgskey = tgs["sessionKey"]
            return KrbCredential(domain, username, ticket, tgskey, password)
    else:
        logging.info(f"requesting TGT for {domain}\\{username}")
        tgt, cipher, _, tgtkey = getKerberosTGT(user, password, domain, "", nt_hash, aes_key, dc_ip)

    if not tgt:
        raise TransportError("Kerberos: could not get TGT or TGS")

    logging.info(f"requesting TGS for {spn}")
    tgs, cipher, _, tgskey = getKerberosTGS(http, domain, dc_ip, tgt, cipher, tgtkey)
    ticket.from_asn1(decoder.decode(tgs, asn1Spec=TGS_REP())[0]["ticket"])
    return KrbCredential(domain, username, ticket, tgskey, password)


# creates a transport class for winrm from common impacket-style arguments:
def create_transport(args):
    domain, username, password, targetName = parse_target(args.target)

    if args.cert_pem or args.cert_key:
        logging.info("'-cert-pem' specified, using ssl")
        args.ssl = True # client certificate implies ssl

    if args.aesKey and not args.k:
        logging.info("'-aesKey' specified, using kerberos")
        args.k = True # aesKey imples kerberos

    if sum((args.k, args.basic, bool(args.cert_pem or args.cert_key))) > 1:
        logging.fatal("'-k', '-basic', and '-cert-*' are mutually excluseive, pick one or none")
        return

    if args.credssp and (args.basic or args.cert_pem or args.cert_key):
        logging.fatal("'-credssp' does not work with '-basic' or '-cert-*'")
        return

    aes_key = args.aesKey
    nt_hash = args.hashes.split(':')[1] if ':' in args.hashes else ""
    has_creds = password or nt_hash or aes_key

    if username and not (has_creds or args.no_pass):
        from getpass import getpass
        password = getpass("Password:")
        has_creds = True

    if not args.target_ip and not args.url:
        target_ip = targetName
        logging.info(f"'-target_ip' not specified, using {targetName}")
    else:
        target_ip = args.target_ip

    if not args.port and not args.url:
        port = 5986 if args.ssl else 5985
        logging.info(f"'-port' not specified, using {port}")
    else:
        port = args.port

    if not args.url:
        if args.ssl:
            url = f"https://{target_ip}:{port}/wsman"
        else:
            url = f"http://{target_ip}:{port}/wsman"
        logging.info(f"'-url' not specified, using {url}")
    else:
        url = args.url

    if args.basic:
        if not username or not password:
            logging.fatal(f"Need username and password for basic auth")
            return
        return BasicTransport(url, username, password)

    elif args.cert_pem or args.cert_key:
        if not args.cert_pem:
            logging.fatal("Missing client certificate (-cert-pem)")
            return
        if not Path(args.cert_pem).is_file():
            logging.fatal(f"Could not find client certificate file {args.cert_pem}")
            return
        if not args.cert_key:
            logging.fatal("Missing client certificate private key (-cert-key)")
            return
        if not Path(args.cert_key).is_file():
            logging.fatal(f"Could not find client certificate key file {args.cert_key}")
            return
        if not urlparse(url).scheme == "https":
            logging.fatal("Authentication with client certificate works only over https")
            return

        return ClientCertTransport(url, args.cert_pem, args.cert_key)

    nt_creds = None
    krb_creds = None

    if not args.k:
        nt_creds = NTCredential(domain, username, password, nt_hash)
    else:
        if os.getenv("KRB5CCNAME"): # use domain/username from ccache
            domain, username, _, _ = CCache.parseFile()
            logging.info(f"using domain and username from ccache: {domain}\\{username}")

        elif not domain or not username or not has_creds:
            logging.fatal("Need domain, username and one of password/nthash/aes for kerberos auth")
            return

        if not args.spn:
            try:
                ip_address(targetName)
                logging.error(f"when '-spn' is not specified 'targetName' can not be IP")
                return
            except ValueError:
                spn = f"HTTP/{targetName}@{domain}"
                logging.info(f"'-spn' not specified, using {spn}")
        else:
            spn = args.spn

        if not args.dc_ip:
            logging.info(f"'-dc-ip' not specified, using {domain}")
            dc_ip = domain
        else:
            dc_ip = args.dc_ip

        krb_creds = get_krb_creds(dc_ip, spn, domain, username, password, nt_hash, aes_key)

    if args.credssp:
        creds = nt_creds or krb_creds
        if not creds.username or not creds.password:
            logging.error("CredSSP needs username and password, even for kerberos")
            return
        return CredSSPTransport(url, creds)

    elif args.k:
        try:
            return KerberosTransport(url, krb_creds)
        except TransportError:
            logging.info("Kerberos via GSS failed, trying SPNEGO")
            return SPNEGOTransport(url, krb_creds)
    else:
        return SPNEGOTransport(url, nt_creds)


def argument_parser():
    parser = ArgumentParser()

    parser.add_argument("target", help="[[domain/]username[:password]@]<target>")
    parser.add_argument('-ts', action='store_true', help='adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    # -- connection params: -----------------------------------------------------------------------
    group = parser.add_argument_group('connection')
    group.add_argument("-dc-ip", default="",
        help="IP Address of the domain controller. If omitted it will use the "\
             "domain part (FQDN) specified in the target parameter")

    group.add_argument("-target-ip", default="",
        help="IP Address of the target machine. If ommited it will use whatever "\
              "was specified as target. This is useful when target is the NetBIOS"\
              "name and you cannot resolve it")

    group.add_argument("-port", default="",
        help="Destination port to connect to WinRM http server, default is 5985")

    group.add_argument("-ssl", action="store_true", help="Use HTTPS")

    group.add_argument("-url", default="",
        help="Exact WSMan endpoint, eg. http://host:port/custom_wsman. "\
             "Otherwise it will be constructed as http(s)://target_ip:port/wsman")

    # -- authentication params: -------------------------------------------------------------------
    group = parser.add_argument_group('authentication')
    group.add_argument("-spn", default="", help="Specify exactly the SPN to request for TGS")

    group.add_argument("-hashes", default="", metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH")

    group.add_argument("-no-pass", action="store_true", help="don't ask for password (useful for -k)")

    group.add_argument("-k", action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME)"\
             "based on target parameters. If valid credentials cannot be found, it will "\
             "use the ones specified in the command line")

    group.add_argument('-aesKey', metavar = "HEXKEY", default="",
        help="AES key to use for Kerberos Authentication")

    group.add_argument("-basic", action="store_true", help="Use Basic auth")

    group.add_argument("-cert-pem", default="", help="Client certificate")

    group.add_argument("-cert-key", default="", help="Client certificate private key")

    group.add_argument("-credssp", action="store_true",
        help="Use CredSSP if enabled, works with NTLM and Kerberos but it needs "\
             "plaintext password either way")

    # -- shell params: ----------------------------------------------------------------------------
    parser.add_argument("-X", default="", metavar="COMMAND",
        help="Command to execute, if ommited it will spawn a janky interactive shell")

    parser.add_argument("-timeout", default="1", metavar="SECONDS", help="Timeout for requests to /wsman")

    return parser

def main():
    print(version.BANNER)
    args = argument_parser().parse_args()

    logger.init(args.ts)
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    transport = create_transport(args)
    if transport is None:
        exit()

    with Runspace(transport, int(args.timeout)) as runspace:
        shell = Shell(runspace)
        try:
            if args.X:
                shell.repl(iter([args.X]))
            else:
                shell.repl()
        except EOFError:
            pass

if __name__ == "__main__":
    main()
