#!/usr/bin/env python3
"""Run one Python WHOIS/RDAP library on one query and print its parsed answer as JSON.

  pyrun.py python-whois example.com
  pyrun.py whoisit 8.8.8.8
  pyrun.py ipwhois 8.8.8.8

The output is what a user of the library would have in hand: the library's own fields,
renamed to the benchmark's names but not otherwise repaired. Exit 0 with {"status":
"available"} when the library reports the name as unregistered, exit 1 on any other error.
"""

import datetime as dt
import ipaddress
import json
import sys
import warnings

warnings.filterwarnings("ignore")


def clean(v):
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    if isinstance(v, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return str(v)
    if isinstance(v, (list, tuple, set)):
        return [clean(x) for x in v]
    if isinstance(v, dict):
        return {k: clean(x) for k, x in v.items()}
    return v


def is_ip(q):
    try:
        ipaddress.ip_address(q)
        return True
    except ValueError:
        return False


def python_whois(q):
    import whois

    try:
        w = whois.whois(q)
    except Exception as e:
        if any(s in str(e).lower() for s in ("no match", "not found", "no entries", "no data")):
            return {"status": "available"}
        raise
    if not w.get("domain_name") and not w.get("creation_date") and not w.get("registrar"):
        return {"status": "available"}
    return {
        "status": "registered",
        "registrar": w.get("registrar"),
        "created": w.get("creation_date"),
        "expires": w.get("expiration_date"),
        "nameservers": w.get("name_servers"),
    }


def whoisit_lookup(q):
    import whoisit
    from whoisit.errors import ResourceDoesNotExist

    whoisit.bootstrap()
    try:
        r = whoisit.ip(q) if is_ip(q) else whoisit.domain(q)
    except ResourceDoesNotExist:
        return {"status": "available"}
    ents = r.get("entities") or {}
    if is_ip(q):
        reg = (ents.get("registrant") or [{}])[0]
        return {
            "status": "found",
            "org": reg.get("name") or reg.get("organisation"),
            "cidr": r.get("network"),
            "country": r.get("country") or None,
            "net_name": r.get("name"),
            "asn": r.get("origin_autnums") or None,
        }
    registrar = (ents.get("registrar") or [{}])[0].get("name")
    return {
        "status": "registered",
        "registrar": registrar,
        "created": r.get("registration_date"),
        "expires": r.get("expiration_date"),
        "nameservers": r.get("nameservers"),
    }


def ipwhois_lookup(q):
    from ipwhois import IPWhois

    r = IPWhois(q).lookup_rdap(depth=1)
    net = r.get("network") or {}
    org = None
    for obj in (r.get("objects") or {}).values():
        if "registrant" in (obj.get("roles") or []):
            org = (obj.get("contact") or {}).get("name")
            break
    return {
        "status": "found",
        "org": org,
        "cidr": net.get("cidr"),
        "country": net.get("country") or r.get("asn_country_code"),
        "net_name": net.get("name"),
        "asn": r.get("asn"),
    }


TOOLS = {"python-whois": python_whois, "whoisit": whoisit_lookup, "ipwhois": ipwhois_lookup}

if __name__ == "__main__":
    tool, query = sys.argv[1], sys.argv[2]
    try:
        print(json.dumps(clean(TOOLS[tool](query)), ensure_ascii=False, indent=1))
    except Exception as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
