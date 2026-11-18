#!/usr/bin/env python3
"""Build the answer key (truth.json) from authoritative sources, independently of whoq.

  domains, registry has RDAP   -> the registry's RDAP record (registrar RDAP for a missing name)
  domains, registry without    -> the registry's port-43 WHOIS, drafted by heuristics, then
                                  checked by hand: corrections go in truth_manual.json
  IPs                          -> the RIR's RDAP record, plus the origin ASN as seen in BGP
                                  (RIPEstat), which no tool under test uses

A field is null when the authority does not publish it; scorers skip null fields.

  python build_truth.py            # fetch everything, write truth.json
  python build_truth.py --only d-bbc-co-uk
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import sys
import time

import lib

RAW = lib.HERE / "truth_raw"
NOT_FOUND = re.compile(
    r"no match|not found|no entries found|no data found|status:\s*(free|available)|"
    r"no object found|nothing found|domain not registered|is free|available for registration|"
    r"%% no entries|not registered|no information available",
    re.I,
)


def domain_rdap(name: str, base: str) -> dict:
    code, obj = lib.get_json(f"{base.rstrip('/')}/domain/{lib.ascii_name(name)}")
    if code == 404:
        return {"status": "available", "source": "rdap-registry"}
    if code != 200 or not obj:
        return {"error": f"registry RDAP HTTP {code}"}
    ent = lib.find_entity(obj, "registrar")
    registrar = lib.vcard_fn(ent) if ent else None
    if not registrar:
        for link in obj.get("links") or []:
            if link.get("rel") == "related" and "rdap" in (link.get("type") or "") and link.get("href"):
                c2, o2 = lib.get_json(link["href"])
                if c2 == 200 and o2:
                    e2 = lib.find_entity(o2, "registrar")
                    registrar = lib.vcard_fn(e2) if e2 else None
                break
    return {
        "status": "registered",
        "registrar": registrar,
        "created": lib.event(obj, "registration"),
        "expires": lib.event(obj, "expiration"),
        "nameservers": sorted({ns["ldhName"].lower().rstrip(".") for ns in obj.get("nameservers") or [] if ns.get("ldhName")}) or None,
        "source": "rdap-registry",
    }


def _line_value(text: str, keys: str) -> str | None:
    m = re.search(rf"^\s*(?:{keys})\s*[:.]*[ \t]*(\S.*)$", text, re.I | re.M)
    if m:
        return m.group(1).strip()
    # value on the following indented line (.uk style)
    m = re.search(rf"^\s*(?:{keys})\s*:\s*\n\s+(\S.*)$", text, re.I | re.M)
    return m.group(1).strip() if m else None


def domain_port43(item: dict, name: str) -> dict:
    tld = lib.ascii_name(name).rsplit(".", 1)[-1]
    server = lib.iana_whois_server(tld)
    if not server:
        return {"error": f"no RDAP and no WHOIS server for .{tld}", "review": True}
    q = lib.ascii_name(name)
    if server == "whois.denic.de":
        q = f"-T dn,ace {q}"
    text = lib.port43(server, q)
    RAW.mkdir(exist_ok=True)
    (RAW / f"{item['id']}.txt").write_text(f"% {server}\n{text}")
    if NOT_FOUND.search(text) and not re.search(r"^\s*(creat|regist)", text, re.I | re.M):
        return {"status": "available", "source": f"whois:{server}", "review": True}
    reg = _line_value(text, r"registrar|sponsoring registrar|registrar name|\[registrar\]|registrar handle")
    ns = re.findall(r"^\s*(?:nserver|name ?server|nameservers?|ns|\[name server\])\s*[:.]*\s*([a-z0-9.-]+\.[a-z]{2,})", text, re.I | re.M)
    if not ns:
        block = re.search(r"name servers?:\s*\n((?:\s+\S.*\n)+)", text, re.I)
        if block:
            ns = [ln.split()[0] for ln in block.group(1).splitlines() if ln.strip()]
    created = _line_value(text, r"creat\w*(?: date| on)?|registered(?: on)?|registration date|domain record activated|\[registered date\]|registered date")
    expires = _line_value(text, r"expir\w*(?: date| on)?|paid-till|renewal date|valid until|registry expiry date|\[expires on\]")
    return {
        "status": "registered",
        "registrar": reg,
        "created": lib.to_date(created).isoformat() if lib.to_date(created) else None,
        "expires": lib.to_date(expires).isoformat() if lib.to_date(expires) else None,
        "nameservers": sorted({n.lower().rstrip(".") for n in ns}) or None,
        "source": f"whois:{server}",
        "review": True,
    }


def ip_truth(ip: str) -> dict:
    base = lib.rdap_base_for_ip(ip)
    if not base:
        return {"error": "no RDAP service in IANA bootstrap"}
    code, obj = lib.get_json(f"{base.rstrip('/')}/ip/{ip}")
    if code != 200 or not obj:
        return {"error": f"RIR RDAP HTTP {code}"}
    rir = next((r for r in ("arin", "ripe", "apnic", "lacnic", "afrinic") if r in base), base)
    cidrs = []
    for c in obj.get("cidr0_cidrs") or []:
        p = c.get("v4prefix") or c.get("v6prefix")
        if p:
            cidrs.append(f"{p}/{c['length']}")
    if not cidrs and obj.get("startAddress") and obj.get("endAddress"):
        lo, hi = ipaddress.ip_address(obj["startAddress"]), ipaddress.ip_address(obj["endAddress"])
        cidrs = [str(n) for n in ipaddress.summarize_address_range(lo, hi)]
    reg = lib.find_entity(obj, "registrant")
    org = lib.vcard_fn(reg) if reg else None
    if org and " " not in org.strip():
        org = None  # a maintainer or handle (RIPE "BBC-MNT", "HOS-GUN"), not an organization name
    _, stat = lib.get_json(f"https://stat.ripe.net/data/network-info/data.json?resource={ip}&sourceapp=whoq-bench")
    asns = [int(a) for a in ((stat or {}).get("data") or {}).get("asns") or []]
    return {
        "status": "found",
        "rir": rir,
        "net_name": obj.get("name"),
        "cidr": cidrs[0] if len(cidrs) == 1 else None,
        "cidrs": cidrs or None,
        "country": (obj.get("country") or "").upper() or None,
        "org": org,
        "asns": asns or None,
        "source": f"rdap:{rir} + ripestat-bgp",
    }


def build_one(item: dict) -> dict:
    if item["kind"] == "ip":
        t = ip_truth(item["query"])
        if t.get("rir"):
            item["category"] = f"{item['category']}-{t['rir']}"
        return t
    name = item["registrable"]
    base = lib.rdap_base_for_domain(name)
    t = domain_rdap(name, base) if base else domain_port43(item, name)
    if item["category"] in ("cctld", "holdout", "fresh", "fresh2"):
        item["category"] = f"{item['category']}-{'rdap' if base else 'whois-only'}"
    t["registrable"] = name
    return t


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", help="item ids to rebuild (others are kept)")
    args = ap.parse_args()
    out_path = lib.HERE / "truth.json"
    old = json.loads(out_path.read_text())["items"] if out_path.exists() else {}
    manual = json.loads((lib.HERE / "truth_manual.json").read_text()) if (lib.HERE / "truth_manual.json").exists() else {}
    items: dict[str, dict] = {}
    for item in lib.load_corpus():
        if args.only and item["id"] not in args.only and item["id"] in old:
            items[item["id"]] = old[item["id"]]
            continue
        try:
            t = build_one(item)
        except Exception as e:  # network trouble: record it, don't stop the build
            t = {"error": f"{type(e).__name__}: {e}"}
        t.update({"query": item["query"], "kind": item["kind"], "category": item["category"]})
        items[item["id"]] = t
        flag = " (needs review)" if t.get("review") else ""
        print(f"{item['id']:40} {t.get('status') or t.get('error')}{flag}", file=sys.stderr)
        time.sleep(0.3)
    for iid, fix in manual.items():
        if iid.startswith("_"):
            continue
        if iid in items:
            items[iid].update({k: v for k, v in fix.items() if k != "note"})
            items[iid]["review"] = False
            items[iid]["checked_by_hand"] = fix.get("note", True)
    out_path.write_text(json.dumps({
        "built_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "items": items,
    }, indent=1, ensure_ascii=False) + "\n")
    pending = [i for i, t in items.items() if t.get("review")]
    errors = [i for i, t in items.items() if t.get("error")]
    print(f"{len(items)} items, {len(pending)} need review, {len(errors)} errors", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
