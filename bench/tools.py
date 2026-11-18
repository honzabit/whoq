"""The tools under test: how to run each one, and how to read its own named fields.

A tool with no `fields` function is scored only on whether the answer appears somewhere in
its output. Override binaries with WHOQ, WHOIS_GNU, WHOIS_MACOS and RDAP.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from typing import Callable

import lib

PY = str(lib.HERE / ".venv" / "bin" / "python")
WHOQ = os.environ.get("WHOQ", str(lib.HERE.parent / "target" / "release" / "whoq"))
WHOIS_GNU = os.environ.get("WHOIS_GNU", "/opt/homebrew/opt/whois/bin/whois")
WHOIS_MACOS = os.environ.get("WHOIS_MACOS", "/usr/bin/whois")
RDAP = os.environ.get("RDAP", shutil.which("rdap") or "rdap")


@dataclass
class Tool:
    name: str
    describe: str
    kinds: tuple[str, ...]
    cmd: Callable[[str], list[str]]
    version: list[str] | None
    fields: Callable[[str], dict | None] | None = None
    exe: str = ""

    def available(self) -> bool:
        return bool(shutil.which(self.exe) or os.path.exists(self.exe))


def _first_record(out: str) -> dict | None:
    try:
        v = json.loads(out)
    except json.JSONDecodeError:
        lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
        if not lines:
            return None
        v = json.loads(lines[0])
    return v[0] if isinstance(v, list) and v else v if isinstance(v, dict) else None


def whoq_fields(out: str) -> dict | None:
    r = _first_record(out)
    if not r:
        return None
    result = r.get("result")
    if r.get("kind") == "ip":
        net = r.get("network") or {}
        return {
            "status": result,
            "org": net.get("org") or (r.get("registrant") or {}).get("org"),
            "cidr": net.get("cidr") or None,
            "country": net.get("country"),
            "net_name": net.get("name"),
            "asn": (r.get("asn") or {}).get("start"),
        }
    return {
        "status": result,
        "registrar": (r.get("registrar") or {}).get("name"),
        "created": r.get("created"),
        "expires": r.get("expires"),
        "nameservers": r.get("nameservers"),
    }


def whoq_brief_fields(out: str) -> dict | None:
    r = _first_record(out)
    if not r:
        return None
    return {
        "status": r.get("result"),
        "registrar": r.get("registrar.name"),
        "created": r.get("created"),
        "expires": r.get("expires"),
        "nameservers": r.get("nameservers"),
        "org": r.get("network.org"),
        "cidr": r.get("network.cidr"),
        "country": r.get("network.country"),
        "net_name": r.get("network.name"),
        "asn": None,
    }


def py_fields(out: str) -> dict | None:
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


TOOLS = [
    Tool("whoq", f"whoq --json ({WHOQ})", ("domain", "ip"),
         lambda q: [WHOQ, "--json", "--no-cache", q], [WHOQ, "--version"], whoq_fields, WHOQ),
    Tool("whoq-brief", "whoq --brief", ("domain", "ip"),
         lambda q: [WHOQ, "--brief", "--no-cache", q], [WHOQ, "--version"], whoq_brief_fields, WHOQ),
    Tool("whois-gnu", "GNU whois (Debian/Linux default)", ("domain", "ip"),
         lambda q: [WHOIS_GNU, q], [WHOIS_GNU, "--version"], None, WHOIS_GNU),
    Tool("whois-macos", "macOS /usr/bin/whois", ("domain", "ip"),
         lambda q: [WHOIS_MACOS, q], None, None, WHOIS_MACOS),
    Tool("openrdap", "OpenRDAP rdap --json", ("domain", "ip"),
         lambda q: [RDAP, "--json", q], None, None, RDAP),
    Tool("python-whois", "python-whois (PyPI)", ("domain",),
         lambda q: [PY, str(lib.HERE / "pyrun.py"), "python-whois", q], [PY, "-m", "pip", "show", "python-whois"], py_fields, PY),
    Tool("whoisit", "whoisit (PyPI, RDAP)", ("domain", "ip"),
         lambda q: [PY, str(lib.HERE / "pyrun.py"), "whoisit", q], [PY, "-m", "pip", "show", "whoisit"], py_fields, PY),
    Tool("ipwhois", "ipwhois (PyPI, RDAP)", ("ip",),
         lambda q: [PY, str(lib.HERE / "pyrun.py"), "ipwhois", q], [PY, "-m", "pip", "show", "ipwhois"], py_fields, PY),
]

BY_NAME = {t.name: t for t in TOOLS}


def pick(names: list[str] | None) -> list[Tool]:
    if not names:
        return TOOLS
    unknown = [n for n in names if n not in BY_NAME]
    if unknown:
        sys.exit(f"unknown tool(s): {', '.join(unknown)}; known: {', '.join(BY_NAME)}")
    return [BY_NAME[n] for n in names]
