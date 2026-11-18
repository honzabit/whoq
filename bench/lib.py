"""Shared helpers for the whoq benchmarks: the corpus, registry access for the answer key,
and the normalization the scorers use. Standard library only."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import socket
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
UA = "whoq-bench/1 (+https://github.com/honzabit/whoq)"


# ---------------------------------------------------------------- corpus

def slug(q: str) -> str:
    s = q.lower() if _is_ip(q) else ascii_name(q)
    return re.sub(r"[^a-z0-9]+", "-", s).strip("-") or "x"


def _is_ip(q: str) -> bool:
    try:
        ipaddress.ip_address(q)
        return True
    except ValueError:
        return False


def load_corpus() -> list[dict]:
    """Every query as {id, query, kind, category, registrable}."""
    c = json.loads((HERE / "corpus.json").read_text())
    items = []
    for cat, names in c["domains"].items():
        for n in names:
            items.append({"query": n, "kind": "domain", "category": cat, "registrable": n})
    for s in c["subdomains"]:
        items.append({"query": s["query"], "kind": "domain", "category": "subdomain", "registrable": s["registrable"]})
    for ip in c["ips"]:
        cat = "ipv6" if ":" in ip else "ipv4"
        items.append({"query": ip, "kind": "ip", "category": cat, "registrable": None})
    for it in items:
        it["id"] = ("d-" if it["kind"] == "domain" else "ip-") + slug(it["query"])
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids)), "duplicate ids in corpus"
    return items


def ascii_name(name: str) -> str:
    return name.encode("idna").decode() if any(ord(ch) > 127 for ch in name) else name.lower()


# ---------------------------------------------------------------- network

def get_json(url: str, timeout: float = 20) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/rdap+json, application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 2:
                time.sleep(5 * (attempt + 1))
                continue
            try:
                body = json.loads(e.read())
            except Exception:
                body = None
            return e.code, body
        except (urllib.error.URLError, TimeoutError, socket.timeout):
            if attempt < 2:
                time.sleep(2)
                continue
            raise
    raise RuntimeError(f"unreachable: {url}")


def port43(server: str, query: str, timeout: float = 20) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            b = s.recv(65536)
            if not b:
                break
            chunks.append(b)
    raw = b"".join(chunks)
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return raw.decode("utf-8", "replace")


_bootstrap: dict[str, dict] = {}


def bootstrap(kind: str) -> dict:
    if kind not in _bootstrap:
        _, _bootstrap[kind] = get_json(f"https://data.iana.org/rdap/{kind}.json")
    return _bootstrap[kind]


def rdap_base_for_domain(name: str) -> str | None:
    labels = ascii_name(name).split(".")
    services = bootstrap("dns")["services"]
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        for tlds, urls in services:
            if suffix in tlds:
                return next((u for u in urls if u.startswith("https")), urls[0])
    return None


def rdap_base_for_ip(ip: str) -> str | None:
    addr = ipaddress.ip_address(ip)
    data = bootstrap("ipv6" if addr.version == 6 else "ipv4")
    best = None
    for nets, urls in data["services"]:
        for n in nets:
            net = ipaddress.ip_network(n)
            if addr in net and (best is None or net.prefixlen > best[0].prefixlen):
                best = (net, next((u for u in urls if u.startswith("https")), urls[0]))
    return best[1] if best else None


def iana_whois_server(tld: str) -> str | None:
    text = port43("whois.iana.org", tld)
    m = re.search(r"^whois:\s*(\S+)", text, re.M)
    return m.group(1) if m else None


# ---------------------------------------------------------------- RDAP parsing (answer key only)

def vcard_fn(entity: dict) -> str | None:
    for prop in (entity.get("vcardArray") or [None, []])[1]:
        if prop and prop[0] == "fn" and prop[3]:
            return str(prop[3]).strip()
    for prop in (entity.get("vcardArray") or [None, []])[1]:
        if prop and prop[0] == "org" and prop[3]:
            return str(prop[3] if not isinstance(prop[3], list) else prop[3][0]).strip()
    return None


def find_entity(obj: dict, role: str) -> dict | None:
    for e in obj.get("entities") or []:
        if role in (e.get("roles") or []):
            return e
    for e in obj.get("entities") or []:
        sub = find_entity(e, role)
        if sub:
            return sub
    return None


def event(obj: dict, action: str) -> str | None:
    for e in obj.get("events") or []:
        if e.get("eventAction") == action and e.get("eventDate"):
            return e["eventDate"][:10]
    return None


# ---------------------------------------------------------------- normalization (scoring)

STOPWORDS = {
    "inc", "llc", "ltd", "limited", "corp", "corporation", "co", "company", "gmbh", "ag", "sa", "sas",
    "srl", "bv", "nv", "ab", "as", "oy", "spa", "plc", "pty", "the", "of", "and", "registrar",
    "dba", "kg", "kk", "sl", "sro", "zrt", "ltda", "llp", "lp", "group", "holdings", "international",
}


def fold(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def name_tokens(s: str) -> set[str]:
    return {t for t in fold(s).split() if t not in STOPWORDS and len(t) > 1}


def same_name(truth: str, got: str | None) -> bool:
    """Organization names match when most of the truth's distinctive words are present."""
    if not got:
        return False
    t, g = name_tokens(truth), name_tokens(got)
    if not t:
        return fold(truth) == fold(got)
    return len(t & g) / len(t) >= 0.6


def name_in_text(truth: str, text: str) -> bool:
    t = name_tokens(truth)
    if not t:
        return fold(truth) in fold(text)
    words = set(fold(text).split())
    return len(t & words) / len(t) >= 0.6


MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}

_DATE_RES = [
    (re.compile(r"\b(\d{4})[-./](\d{1,2})[-./](\d{1,2})"), "ymd"),
    (re.compile(r"\b(\d{1,2})[-./ ]([A-Za-z]{3})[A-Za-z]*[-./ ](\d{4})\b"), "dMy"),
    (re.compile(r"\b(\d{1,2})[./](\d{1,2})[./](\d{4})\b"), "dmy"),
    (re.compile(r"\b(\d{4})(\d{2})(\d{2})\b"), "ymd"),
    (re.compile(r"\b([A-Za-z]{3})[a-z]* +(\d{1,2}),? +(\d{4})\b"), "Mdy"),
]


def dates_in(text: str) -> set[dt.date]:
    found: set[dt.date] = set()
    for rx, kind in _DATE_RES:
        for m in rx.finditer(text):
            try:
                if kind == "ymd":
                    y, mo, d = int(m[1]), int(m[2]), int(m[3])
                elif kind == "dmy":
                    d, mo, y = int(m[1]), int(m[2]), int(m[3])
                elif kind == "dMy":
                    d, mo, y = int(m[1]), MONTHS[m[2].lower()[:3]], int(m[3])
                else:
                    mo, d, y = MONTHS[m[1].lower()[:3]], int(m[2]), int(m[3])
                found.add(dt.date(y, mo, d))
            except (KeyError, ValueError):
                pass
    return found


def to_date(v) -> dt.date | None:
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
        if v is None:
            return None
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    ds = dates_in(str(v))
    return min(ds) if ds else None


def same_date(truth: str, got) -> bool:
    g = to_date(got)
    return g is not None and abs((g - dt.date.fromisoformat(truth)).days) <= 1


def date_in_text(truth: str, text: str) -> bool:
    t = dt.date.fromisoformat(truth)
    return any(abs((d - t).days) <= 1 for d in dates_in(text))


def ns_set(v) -> set[str]:
    if not v:
        return set()
    if isinstance(v, str):
        v = re.split(r"[\s,]+", v)
    return {str(x).lower().rstrip(".").split()[0] for x in v if str(x).strip()}


def asn_in_text(asns: list[int], text: str) -> bool:
    for a in asns:
        if re.search(rf"\bAS ?{a}\b", text, re.I) or re.search(rf"(origin|asn)\w*\W{{0,20}}{a}\b", text, re.I):
            return True
    return False


def cidr_in_text(cidr: str, text: str) -> bool:
    net = ipaddress.ip_network(cidr, strict=False)
    if str(net) in text or str(net).replace("/", " /") in text:
        return True
    lo, hi = str(net.network_address), str(net.broadcast_address)
    return lo in text and hi in text
