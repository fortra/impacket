#!/usr/bin/env python3
"""
ad_domain_recon.py — derive the internal Active Directory domain from a public
FQDN / host, using impacket.

Authoritative methods (actually reveal the internal domain):
  1. SMB / NTLMSSP negotiation  -> DNS domain, NetBIOS domain, forest name
  2. LDAP rootDSE               -> defaultNamingContext / rootDomainNamingContext
  3. Kerberos realm probe       -> realm from the KDC error

Inference fallback (no authoritative leak available):
  4. DNS SRV brute of _ldap._tcp.dc._msdcs.<candidate> built from the FQDN seed

Only run this against hosts you are authorized to test.

Requires: impacket, dnspython
    pip install impacket dnspython --break-system-packages

Usage:
    python3 ad_domain_recon.py mail.acme.com
    python3 ad_domain_recon.py 10.0.0.10 --fqdn acme.com
    python3 ad_domain_recon.py dc01.acme.com --only smb
"""

import argparse
import socket
import sys

RESULTS = {}


def out(method, key, value):
    print(f"  [+] {method:<10} {key:<24} {value}")
    RESULTS.setdefault(method, {})[key] = value


def err(method, msg):
    print(f"  [-] {method:<10} {msg}")


# --------------------------------------------------------------------------- #
# 1. SMB / NTLMSSP negotiation
# --------------------------------------------------------------------------- #
def probe_smb(target):
    print("[*] SMB / NTLMSSP negotiation (445)")
    try:
        from impacket.smbconnection import SMBConnection

        conn = SMBConnection(target, target, sess_port=445, timeout=6)
        # These come straight from the SMB/NTLM negotiation, no auth needed.
        try:
            conn.login("", "")  # null session; ignore failure, banner is enough
        except Exception:
            pass

        dns_domain = conn.getServerDNSDomainName()
        nb_domain = conn.getServerDomain()
        forest = None
        try:
            forest = conn.getServerDNSHostName()
        except Exception:
            pass

        if dns_domain:
            out("smb", "DNS domain", dns_domain)
        if nb_domain:
            out("smb", "NetBIOS domain", nb_domain)
        if forest:
            out("smb", "DC DNS host", forest)
        try:
            out("smb", "Server OS", conn.getServerOS())
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
    print("[*] LDAP rootDSE (389)")
    try:
        from impacket.ldap import ldap as ldaplib

        # base search of rootDSE is usually readable anonymously
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
                "dnsHostName",
                "ldapServiceName",
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
    print("[*] Kerberos realm probe (88)")
    try:
        from impacket.krb5.kerberosv5 import getKerberosTGT
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal
        from impacket.krb5.asn1 import KRB_ERROR
        from pyasn1.codec.der import decoder as der_decoder  # noqa
    except ImportError:
        err("kerberos", "impacket not installed")
        return

    # Send an AS-REQ with a bogus user; the KDC error tells us if the realm is valid.
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
            # A valid realm returns PRINCIPAL_UNKNOWN / PREAUTH_REQUIRED, not
            # WRONG_REALM / can't-reach.
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
            # else: wrong realm / unreachable -> not this one
    if not found:
        err("kerberos", "no realm confirmed from candidates")


# --------------------------------------------------------------------------- #
# 4. DNS SRV candidate brute (inference, no host contact)
# --------------------------------------------------------------------------- #
def build_candidates(fqdn):
    labels = fqdn.split(".")
    # registrable seed: last two labels for common TLDs
    if len(labels) >= 2:
        seed = labels[-2]
        pub = ".".join(labels[-2:])
    else:
        seed = fqdn
        pub = fqdn

    cands = [
        pub,                       # split-brain
        f"corp.{pub}",
        f"ad.{pub}",
        f"internal.{pub}",
        f"hq.{pub}",
        f"{seed}.local",
        f"{seed}.lan",
        f"{seed}.internal",
        f"{seed}.ad",
        f"ad.{seed}.local",
        f"corp.{seed}.local",
    ]
    # de-dup, keep order
    seen, ordered = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def probe_dns_srv(candidates):
    print("[*] DNS SRV brute  _ldap._tcp.dc._msdcs.<candidate>")
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
def main():
    ap = argparse.ArgumentParser(description="Derive internal AD domain from a public FQDN/host (impacket).")
    ap.add_argument("target", help="host or IP of a domain-joined machine / DC")
    ap.add_argument("--fqdn", help="public FQDN seed for DNS inference (defaults to target if it's a name)")
    ap.add_argument(
        "--only",
        choices=["smb", "ldap", "kerberos", "dns"],
        help="run only one method",
    )
    args = ap.parse_args()

    fqdn = args.fqdn or (args.target if not args.target.replace(".", "").isdigit() else None)
    candidates = build_candidates(fqdn) if fqdn else []

    print(f"[*] Target: {args.target}")
    if fqdn:
        print(f"[*] FQDN seed: {fqdn}")
        print(f"[*] Candidate domains: {', '.join(candidates)}")
    print()

    run = args.only
    if run in (None, "smb"):
        probe_smb(args.target)
    if run in (None, "ldap"):
        probe_ldap(args.target)
    if run in (None, "kerberos"):
        probe_kerberos(args.target, candidates or [fqdn] if fqdn else [])
    if run in (None, "dns"):
        probe_dns_srv(candidates)

    # -------- verdict --------
    print("\n[=] Best guess at internal AD domain:")
    order = [
        ("ldap", "-> domain"),
        ("smb", "DNS domain"),
        ("kerberos", "valid realm"),
        ("dns", "AD domain"),
    ]
    for method, key in order:
        val = RESULTS.get(method, {}).get(key)
        if val:
            print(f"    {val}   (from {method})")
            return
    print("    inconclusive — no authoritative leak and no SRV hit.")
    if candidates:
        print(f"    manual candidates to try: {', '.join(candidates)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)