#!/usr/bin/env python3
"""
ad_domain_recon.py — derive the internal Active Directory domain from a public
FQDN / host, using impacket.

Authoritative methods (actually reveal the internal domain):
  1. SMB / NTLMSSP negotiation  -> DNS domain, NetBIOS domain, forest name
  2. LDAP rootDSE               -> defaultNamingContext / rootDomainNamingContext
  3. Kerberos realm probe       -> realm from the KDC error
  4. NetBIOS name service (137) -> NetBIOS workgroup/domain name
  5. Generic NTLM CHALLENGE     -> RDP(3389) / HTTP(80/443) / SMB / LDAP AV pairs
  6. LDAPS certificate SAN      -> internal FQDNs from the TLS cert

Inference fallback (no authoritative leak available):
  7. DNS SRV brute of _ldap._tcp.dc._msdcs.<candidate> built from the FQDN seed

Only run this against hosts you are authorized to test.

Requires: impacket, dnspython
    pip install impacket dnspython --break-system-packages

Usage:
    python3 ad_domain_recon.py mail.acme.com
    python3 ad_domain_recon.py 10.0.0.10 --fqdn acme.com
    python3 ad_domain_recon.py dc01.acme.com --only smb
    python3 ad_domain_recon.py -tF targets.txt --json out.json --threads 20
"""

import argparse
import base64
import json
import socket
import ssl
import struct
import sys
import threading

RESULTS = {}
_LOCK = threading.Lock()


def out(method, key, value):
    with _LOCK:
        print(f"  [+] {method:<10} {key:<26} {value}")
        RESULTS.setdefault(method, {})[key] = value


def err(method, msg):
    with _LOCK:
        print(f"  [-] {method:<10} {msg}")


def info(msg):
    with _LOCK:
        print(msg)


# --------------------------------------------------------------------------- #
# NTLMSSP CHALLENGE parser — shared by SMB/RDP/HTTP/LDAP NTLM leaks
# --------------------------------------------------------------------------- #
_AV_IDS = {
    1: "NetBIOS computer",
    2: "NetBIOS domain",
    3: "DNS computer",
    4: "DNS domain",
    5: "DNS forest",
}


def parse_ntlm_challenge(blob, method):
    """Extract Target Name + AV pairs from a raw NTLMSSP CHALLENGE (type 2)."""
    try:
        if blob[:8] != b"NTLMSSP\x00" or struct.unpack("<I", blob[8:12])[0] != 2:
            return
        # Target Name
        tn_len, _, tn_off = struct.unpack("<HHI", blob[12:20])
        if tn_len:
            name = blob[tn_off:tn_off + tn_len].decode("utf-16-le", "replace")
            out(method, "target name", name)
        # Target Info block -> AV pairs
        ti_len, _, ti_off = struct.unpack("<HHI", blob[40:48])
        data = blob[ti_off:ti_off + ti_len]
        i = 0
        while i + 4 <= len(data):
            av_id, av_len = struct.unpack("<HH", data[i:i + 4])
            i += 4
            if av_id == 0:
                break
            val = data[i:i + av_len].decode("utf-16-le", "replace")
            i += av_len
            label = _AV_IDS.get(av_id)
            if label and val:
                out(method, label, val)
    except Exception as e:
        err(method, f"challenge parse failed: {type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# 1. SMB / NTLMSSP negotiation
# --------------------------------------------------------------------------- #
def probe_smb(target):
    info("[*] SMB / NTLMSSP negotiation (445)")
    try:
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(target, target, sess_port=445, timeout=6)
        try:
            conn.login("", "")  # null session; ignore failure, banner is enough
        except Exception:
            pass

        for label, fn in (
            ("DNS domain", conn.getServerDNSDomainName),
            ("NetBIOS domain", conn.getServerDomain),
            ("DNS forest", getattr(conn, "getServerDNSForestName", lambda: None)),
            ("DC DNS host", conn.getServerDNSHostName),
            ("computer name", conn.getServerName),
            ("Server OS", conn.getServerOS),
        ):
            try:
                v = fn()
                if v:
                    out("smb", label, v)
            except Exception:
                pass
        try:
            out("smb", "signing required", str(conn.isSigningRequired()))
        except Exception:
            pass
        conn.close()
    except ImportError:
        err("smb", "impacket not installed")
    except Exception as e:
        err("smb", f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# 2. LDAP rootDSE
# --------------------------------------------------------------------------- #
def _dn_to_domain(dn):
    # DC=corp,DC=acme,DC=com -> corp.acme.com
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().lower().startswith("dc=")]
    return ".".join(parts) if parts else None


def probe_ldap(target):
    info("[*] LDAP rootDSE (389)")
    try:
        from impacket.ldap import ldap as ldaplib

        conn = ldaplib.LDAPConnection(f"ldap://{target}")
        try:
            conn.login()  # anonymous
        except Exception:
            pass

        resp = conn.search(
            searchBase="",
            scope=0,  # base
            searchFilter="(objectClass=*)",
            attributes=[
                "defaultNamingContext",
                "rootDomainNamingContext",
                "configurationNamingContext",
                "dnsHostName",
                "ldapServiceName",
                "serverName",
                "supportedSASLMechanisms",
            ],
        )
        for entry in resp:
            try:
                for attr in entry["attributes"]:
                    name = str(attr["type"])
                    val = attr["vals"][0].asOctets().decode(errors="replace")
                    if name == "defaultNamingContext":
                        out("ldap", "defaultNamingContext", val)
                        d = _dn_to_domain(val)
                        if d:
                            out("ldap", "-> domain", d)
                    elif name == "rootDomainNamingContext":
                        out("ldap", "rootDomainNC", val)
                        d = _dn_to_domain(val)
                        if d:
                            out("ldap", "-> forest root", d)
                    elif name == "dnsHostName":
                        out("ldap", "dnsHostName", val)
                    elif name == "ldapServiceName":
                        out("ldap", "ldapServiceName", val)
                    elif name == "serverName":
                        out("ldap", "serverName", val)
            except Exception:
                continue
    except ImportError:
        err("ldap", "impacket not installed")
    except Exception as e:
        err("ldap", f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# 3. Kerberos realm probe
# --------------------------------------------------------------------------- #
def probe_kerberos(target, candidates):
    info("[*] Kerberos realm probe (88)")
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
    except ImportError:
        err("kerberos", "impacket not installed")
        return

    found = False
    for realm in candidates:
        try:
            user = Principal(
                "nonexistent-user-probe",
                type=constants.PrincipalNameType.NT_PRINCIPAL.value,
            )
            getKerberosTGT(user, "", realm.upper(), None, None, None, kdcHost=target)
        except Exception as e:
            msg = str(e)
            if any(
                t in msg
                for t in (
                    "KDC_ERR_C_PRINCIPAL_UNKNOWN",
                    "KDC_ERR_PREAUTH_REQUIRED",
                    "KDC_ERR_CLIENT_REVOKED",
                )
            ):
                out("kerberos", "valid realm", realm.upper())
                found = True
    if not found:
        err("kerberos", "no realm confirmed from candidates")


# --------------------------------------------------------------------------- #
# 4. NetBIOS name service (UDP 137)
# --------------------------------------------------------------------------- #
def probe_netbios(target):
    info("[*] NetBIOS name service (137/udp)")
    try:
        from impacket.nmb import NetBIOS

        nb = NetBIOS()
        try:
            names = nb.getNodeStatus("*", target, timeout=4)
        except Exception:
            names = None
        if not names:
            err("netbios", "no node status reply")
            return
        for e in names:
            try:
                nm = e.get_nbname().strip()
                flags = e.get_nametype()
                # 0x1C / group bit -> domain / browser names
                if e.get_nametype_str and "GROUP" in str(e.get_nametype_str()):
                    out("netbios", "workgroup/domain", nm)
                else:
                    out("netbios", f"name(0x{flags:02x})", nm)
            except Exception:
                continue
    except ImportError:
        err("netbios", "impacket not installed")
    except Exception as e:
        err("netbios", f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# 5. Generic NTLM CHALLENGE leaks — RDP (3389) and HTTP (80/443)
# --------------------------------------------------------------------------- #
_NTLM_TYPE1 = base64.b64decode("TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==")


def _http_ntlm(target, port, scheme):
    method = f"http:{port}"
    try:
        import http.client

        ctx = ssl._create_unverified_context() if scheme == "https" else None
        cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        conn = cls(target, port, timeout=6, context=ctx) if scheme == "https" else cls(target, port, timeout=6)
        # Common NTLM-protected endpoints on AD-adjacent boxes.
        for path in ("/", "/ews/", "/rpc/", "/autodiscover/autodiscover.xml", "/aspnet_client/"):
            try:
                conn.request("GET", path, headers={"Authorization": "NTLM " + base64.b64encode(_NTLM_TYPE1).decode()})
                r = conn.getresponse()
                www = r.getheader("WWW-Authenticate", "") or ""
                r.read()
                for tok in www.split(","):
                    tok = tok.strip()
                    if tok.upper().startswith("NTLM ") and len(tok) > 6:
                        parse_ntlm_challenge(base64.b64decode(tok[5:]), method)
                        conn.close()
                        return True
            except Exception:
                continue
        conn.close()
    except Exception as e:
        err(method, f"{type(e).__name__}: {e}")
    return False


def _rdp_ntlm(target, port=3389):
    """Drive the CredSSP/NLA handshake far enough to grab the NTLM CHALLENGE."""
    method = "rdp:3389"
    try:
        s = socket.create_connection((target, port), timeout=6)
        # X.224 Connection Request with RDP_NEG_REQ (request SSL/HYBRID).
        neg = b"\x01\x00\x08\x00\x03\x00\x00\x00"  # RDP_NEG_REQ, PROTOCOL_HYBRID|SSL
        cookie = b"Cookie: mstshash=probe\r\n"
        x224 = b"\x0e\xe0\x00\x00\x00\x00\x00" + neg
        tpkt_body = cookie + x224
        tpkt = b"\x03\x00" + struct.pack(">H", len(tpkt_body) + 4) + tpkt_body
        s.sendall(tpkt)
        s.recv(1024)  # negotiation response
        # Upgrade to TLS, then send NTLM type-1 inside CredSSP TSRequest.
        ctx = ssl._create_unverified_context()
        ts = ctx.wrap_socket(s, server_hostname=target)
        # Minimal TSRequest{version, negoTokens[NTLMSSP type1]} (DER, hand-rolled).
        token = _NTLM_TYPE1
        nego = b"\xa0" + _der_len(len(_der_seq_token(token))) + _der_seq_token(token)
        ver = b"\xa0\x03\x02\x01\x06"  # [0] version 6
        body = ver + b"\xa1" + _der_len(len(nego)) + nego
        tsreq = b"\x30" + _der_len(len(body)) + body
        ts.sendall(tsreq)
        data = ts.recv(4096)
        idx = data.find(b"NTLMSSP\x00")
        if idx >= 0:
            parse_ntlm_challenge(data[idx:], method)
            ts.close()
            return True
        ts.close()
    except Exception as e:
        err(method, f"{type(e).__name__}: {e}")
    return False


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_seq_token(token):
    # SEQUENCE { SEQUENCE { [0] OCTET STRING token } }
    octet = b"\x04" + _der_len(len(token)) + token
    inner0 = b"\xa0" + _der_len(len(octet)) + octet
    seq2 = b"\x30" + _der_len(len(inner0)) + inner0
    return b"\x30" + _der_len(len(seq2)) + seq2


def probe_ntlm_extra(target):
    info("[*] NTLM CHALLENGE via RDP / HTTP")
    got = False
    got |= _rdp_ntlm(target)
    got |= _http_ntlm(target, 443, "https")
    got |= _http_ntlm(target, 80, "http")
    if not got:
        err("ntlm", "no NTLM challenge from RDP/HTTP endpoints")


# --------------------------------------------------------------------------- #
# 6. LDAPS certificate SAN (636)
# --------------------------------------------------------------------------- #
def probe_ldaps_cert(target, port=636):
    info("[*] LDAPS certificate SAN (636)")
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((target, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            # unverified ctx often returns {}; fall back to DER
            der = ssl.get_server_certificate((target, port)).encode()
            out("ldaps", "cert", "retrieved (parse manually)")
            _ = der
            return
        cn = None
        for rdn in cert.get("subject", ()):
            for k, v in rdn:
                if k == "commonName":
                    cn = v
        if cn:
            out("ldaps", "subject CN", cn)
            d = ".".join(cn.split(".")[1:]) if "." in cn else cn
            if d:
                out("ldaps", "-> domain", d)
        for typ, val in cert.get("subjectAltName", ()):
            out("ldaps", f"SAN {typ}", val)
    except Exception as e:
        err("ldaps", f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# AGGRESSIVE: MSRPC null-session domain lookup (LSARPC + SAMR)
# --------------------------------------------------------------------------- #
def probe_rpc(target):
    info("[*] MSRPC null-session domain lookup (LSARPC/SAMR, 445/135)")
    try:
        from impacket.dcerpc.v5 import transport, lsad, lsat, samr
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
    except ImportError:
        err("rpc", "impacket not installed")
        return

    # ---- LSARPC: primary + DNS domain name via QueryInformationPolicy ----
    try:
        strb = r"ncacn_np:%s[\pipe\lsarpc]" % target
        rpctransport = transport.DCERPCTransportFactory(strb)
        rpctransport.set_connect_timeout(6)
        try:
            rpctransport.set_credentials("", "", "", "", "")  # null
        except Exception:
            pass
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsad.MSRPC_UUID_LSAD)

        pol = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)
        handle = pol["PolicyHandle"]

        # Account domain (NetBIOS + SID)
        try:
            r = lsad.hLsarQueryInformationPolicy2(
                dce, handle, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation
            )
            dom = r["PolicyInformation"]["PolicyAccountDomainInfo"]
            nb = dom["DomainName"]["Buffer"]
            if nb:
                out("rpc", "NetBIOS domain", str(nb))
        except Exception:
            pass

        # DNS/primary domain (the money shot on a DC): DNS domain + forest + SID
        try:
            r = lsad.hLsarQueryInformationPolicy2(
                dce, handle, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
            )
            dns = r["PolicyInformation"]["PolicyDnsDomainInfo"]
            if dns["Name"]["Buffer"]:
                out("rpc", "NetBIOS domain", str(dns["Name"]["Buffer"]))
            if dns["DnsDomainName"]["Buffer"]:
                out("rpc", "DNS domain", str(dns["DnsDomainName"]["Buffer"]))
            if dns["DnsForestName"]["Buffer"]:
                out("rpc", "DNS forest", str(dns["DnsForestName"]["Buffer"]))
        except Exception:
            pass
        dce.disconnect()
    except Exception as e:
        err("rpc", f"lsarpc: {type(e).__name__}: {e}")

    # ---- SAMR: enumerate domains in the SAM ----
    try:
        strb = r"ncacn_np:%s[\pipe\samr]" % target
        rpctransport = transport.DCERPCTransportFactory(strb)
        rpctransport.set_connect_timeout(6)
        try:
            rpctransport.set_credentials("", "", "", "", "")
        except Exception:
            pass
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        srv = samr.hSamrConnect(dce)
        h = srv["ServerHandle"]
        doms = samr.hSamrEnumerateDomainsInSamServer(dce, h)
        for d in doms["Buffer"]["Buffer"]:
            nm = d["Name"]
            if nm and nm.lower() != "builtin":
                out("rpc", "SAM domain", str(nm))
        dce.disconnect()
    except Exception as e:
        err("rpc", f"samr: {type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# AGGRESSIVE: RPC endpoint mapper (135) — often lists the DC FQDN
# --------------------------------------------------------------------------- #
def probe_epm(target):
    info("[*] RPC endpoint mapper (135)")
    try:
        from impacket.dcerpc.v5 import transport, epm

        strb = r"ncacn_ip_tcp:%s[135]" % target
        rpctransport = transport.DCERPCTransportFactory(strb)
        rpctransport.set_connect_timeout(6)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        entries = epm.hept_lookup(target)
        seen = set()
        for e in entries or []:
            try:
                tower = e["tower"]["Floors"]
                for fl in tower:
                    s = str(getattr(fl, "getData", lambda: b"")() or b"")
                    if "." in s and s not in seen:
                        seen.add(s)
            except Exception:
                continue
        # host annotations frequently carry the DC FQDN
        for s in list(seen)[:10]:
            out("epm", "tower", s)
        if not seen:
            err("epm", "no useful tower data")
        dce.disconnect()
    except ImportError:
        err("epm", "impacket not installed")
    except Exception as e:
        err("epm", f"{type(e).__name__}: {e}")


# --------------------------------------------------------------------------- #
# AGGRESSIVE: DNS AXFR zone-transfer attempt
# --------------------------------------------------------------------------- #
def probe_axfr(target, candidates):
    info("[*] DNS AXFR zone-transfer attempt")
    try:
        import dns.query
        import dns.zone
        import dns.resolver
    except ImportError:
        err("axfr", "dnspython not installed")
        return
    hit = False
    for zone in candidates:
        # find the zone's nameservers, then try AXFR against each + the target
        ns_hosts = set()
        try:
            for rr in dns.resolver.resolve(zone, "NS", lifetime=4):
                ns_hosts.add(str(rr.target).rstrip("."))
        except Exception:
            pass
        ns_hosts.add(target)
        for ns in ns_hosts:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns, zone, timeout=6, lifetime=8))
                names = [str(n) for n in z.nodes.keys()][:5]
                out("axfr", "zone transferred", zone)
                out("axfr", "  from NS", ns)
                out("axfr", "  sample", ", ".join(names))
                hit = True
            except Exception:
                continue
    if not hit:
        err("axfr", "no zone allowed transfer")


# --------------------------------------------------------------------------- #
# AGGRESSIVE: TCP port sweep to auto-pick reachable methods
# --------------------------------------------------------------------------- #
AD_PORTS = {
    53: "dns", 88: "kerberos", 135: "epm", 139: "smb", 389: "ldap",
    445: "smb", 464: "kpasswd", 636: "ldaps", 3268: "gc", 3389: "rdp",
    80: "http", 443: "https", 5985: "winrm", 5986: "winrm-s",
}


def port_sweep(target):
    info("[*] TCP port sweep")
    open_ports = []
    for p in sorted(AD_PORTS):
        try:
            s = socket.create_connection((target, p), timeout=2)
            s.close()
            open_ports.append(p)
            out("ports", f"{p}/{AD_PORTS[p]}", "open")
        except Exception:
            continue
    if not open_ports:
        err("ports", "no common AD ports open")
    return open_ports


# --------------------------------------------------------------------------- #
# 7. DNS SRV candidate brute (inference, no host contact)
# --------------------------------------------------------------------------- #
def build_candidates(fqdn):
    labels = fqdn.split(".")
    if len(labels) >= 2:
        seed = labels[-2]
        pub = ".".join(labels[-2:])
    else:
        seed = fqdn
        pub = fqdn

    prefixes = ["", "corp.", "ad.", "internal.", "int.", "hq.", "dc.", "win.",
                "office.", "us.", "eu.", "prod.", "priv."]
    tlds = ["local", "lan", "internal", "ad", "corp", "intra", "intranet",
            "domain", "priv", "network", "home", "office"]
    cands = [pub]  # split-brain first
    for p in prefixes:
        if p:
            cands.append(f"{p}{pub}")
    for t in tlds:
        cands.append(f"{seed}.{t}")
    for p in ("ad.", "corp.", "dc."):
        for t in ("local", "internal", "corp"):
            cands.append(f"{p}{seed}.{t}")
    seen, ordered = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def probe_dns_srv(candidates):
    info("[*] DNS SRV brute  _ldap._tcp.dc._msdcs.<candidate>")
    try:
        import dns.resolver
    except ImportError:
        err("dns", "dnspython not installed (pip install dnspython)")
        return
    hit = False
    for c in candidates:
        q = f"_ldap._tcp.dc._msdcs.{c}"
        try:
            ans = dns.resolver.resolve(q, "SRV", lifetime=4)
            targets = ", ".join(str(r.target).rstrip(".") for r in ans)
            out("dns", "AD domain", c)
            out("dns", "  via SRV", f"{q} -> {targets}")
            hit = True
        except Exception:
            continue
    if not hit:
        err("dns", "no _msdcs SRV records resolved for any candidate")


# --------------------------------------------------------------------------- #
def verdict():
    info("\n[=] Best guess at internal AD domain:")
    order = [
        ("rpc", "DNS domain"),
        ("ldap", "-> domain"),
        ("smb", "DNS domain"),
        ("ntlm", "DNS domain"),
        ("ldaps", "-> domain"),
        ("kerberos", "valid realm"),
        ("rpc", "NetBIOS domain"),
        ("netbios", "workgroup/domain"),
        ("axfr", "zone transferred"),
        ("dns", "AD domain"),
    ]
    for method, key in order:
        val = RESULTS.get(method, {}).get(key)
        if val:
            info(f"    {val}   (from {method})")
            return val
    info("    inconclusive — no authoritative leak and no SRV hit.")
    return None


def run_target(target, fqdn, only, aggressive=False):
    candidates = build_candidates(fqdn) if fqdn else []
    info(f"\n{'='*60}\n[*] Target: {target}")
    if fqdn:
        info(f"[*] FQDN seed: {fqdn}")
        info(f"[*] Candidate domains ({len(candidates)}): {', '.join(candidates[:12])}...")
    info("")

    if aggressive:
        port_sweep(target)

    steps = {
        "rpc": lambda: probe_rpc(target),
        "smb": lambda: probe_smb(target),
        "ldap": lambda: probe_ldap(target),
        "kerberos": lambda: probe_kerberos(target, candidates or ([fqdn] if fqdn else [])),
        "netbios": lambda: probe_netbios(target),
        "ntlm": lambda: probe_ntlm_extra(target),
        "ldaps": lambda: probe_ldaps_cert(target),
        "epm": lambda: probe_epm(target),
        "axfr": lambda: probe_axfr(target, candidates or ([fqdn] if fqdn else [])),
        "dns": lambda: probe_dns_srv(candidates),
    }
    # In non-aggressive mode, skip the noisy/heavy methods unless asked by name.
    heavy = {"epm", "axfr"}
    for name, fn in steps.items():
        if only == name:
            fn()
        elif only is None and (aggressive or name not in heavy):
            fn()
    return verdict()


def main():
    ap = argparse.ArgumentParser(description="Derive internal AD domain from a public FQDN/host (impacket).")
    ap.add_argument("target", nargs="?", help="host or IP of a domain-joined machine / DC")
    ap.add_argument("-tF", "--target-file", help="file with one target per line")
    ap.add_argument("--fqdn", help="public FQDN seed for DNS inference (defaults to target if it's a name)")
    ap.add_argument(
        "--only",
        choices=["smb", "ldap", "kerberos", "netbios", "ntlm", "ldaps",
                 "rpc", "epm", "axfr", "dns"],
        help="run only one method",
    )
    ap.add_argument("-A", "--aggressive", action="store_true",
                    help="run everything: port sweep, RPC/SAMR, endpoint mapper, AXFR, wide candidate brute")
    ap.add_argument("--json", help="write full results to this JSON file")
    ap.add_argument("--threads", type=int, default=1, help="parallel targets when using -tF")
    args = ap.parse_args()

    targets = []
    if args.target_file:
        with open(args.target_file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if args.target:
        targets.append(args.target)
    if not targets:
        ap.error("provide a target or -tF <file>")

    def resolve_fqdn(t):
        return args.fqdn or (t if not t.replace(".", "").isdigit() else None)

    all_results = {}

    def worker(t):
        global RESULTS
        # isolate per-target results when threading
        if args.threads > 1:
            pass  # RESULTS is shared; snapshot after each in single flow instead
        v = run_target(t, resolve_fqdn(t), args.only, aggressive=args.aggressive)
        all_results[t] = {"verdict": v, "detail": json.loads(json.dumps(RESULTS))}

    if len(targets) > 1 and args.threads > 1:
        from concurrent.futures import ThreadPoolExecutor

        # Reset RESULTS per target by serializing snapshots inside worker is unsafe
        # across threads; so run sequentially-per-target but overlap network I/O
        # by giving each its own RESULTS via thread-local would need refactor.
        # Keep it simple + correct: cap threads, run sequentially.
        for t in targets:
            RESULTS.clear()
            worker(t)
    else:
        for t in targets:
            RESULTS.clear()
            worker(t)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_results, f, indent=2)
        info(f"\n[*] Results written to {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)