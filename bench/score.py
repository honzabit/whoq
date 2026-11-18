#!/usr/bin/env python3
"""Benchmark #1: correctness and coverage. Offline; scores a run against truth.json.

  python score.py results/2026-11-17

Two measures per tool and field:

  in output  the right answer appears anywhere in what the tool printed (lenient: a person
             or a script reading the text could find it). Every tool gets this.
  as field   the tool's own named field holds the right answer (registrar.name, expires...).
             Only tools that emit named fields get this; it is what a program relies on.

Writes correctness.md and score.json next to the run.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import lib
import tools as T

NOT_FOUND = re.compile(
    r"no match|not found|no entries found|no data found|status:\s*(free|available)|no object found|"
    r"nothing found|not registered|object does not exist|\"(?:result|status)\":\s*\"available\"",
    re.I,
)
DOMAIN_FIELDS = ("status", "registrar", "created", "expires", "nameservers")
IP_FIELDS = ("org", "cidr", "country", "asn")


def scored_fields(t: dict) -> list[str]:
    if t["kind"] == "ip":
        return [f for f in IP_FIELDS if t.get(f if f != "cidr" else "cidrs") or (f == "asn" and t.get("asns"))]
    if t.get("status") == "available":
        return ["status"]
    return [f for f in DOMAIN_FIELDS if f == "status" or t.get(f)]


def in_output(field: str, t: dict, text: str) -> bool:
    if field == "status":
        if t["status"] == "available":
            return bool(NOT_FOUND.search(text))
        others = [f for f in DOMAIN_FIELDS[1:] if t.get(f)]
        if others:
            return any(in_output(f, t, text) for f in others)
        return lib.ascii_name(t["registrable"]) in text.lower() and not NOT_FOUND.search(text)
    if field == "registrar":
        return lib.name_in_text(t["registrar"], text)
    if field in ("created", "expires"):
        return lib.date_in_text(t[field], text)
    if field == "nameservers":
        low = text.lower()
        return all(ns in low for ns in t["nameservers"])
    if field == "org":
        return lib.name_in_text(t["org"], text)
    if field == "cidr":
        return any(lib.cidr_in_text(c, text) for c in t["cidrs"])
    if field == "country":
        return bool(re.search(rf"country\W{{0,30}}{t['country']}\b", text, re.I))
    if field == "asn":
        return lib.asn_in_text(t["asns"], text)
    raise KeyError(field)


def _nets(v) -> set:
    vals = v if isinstance(v, list) else [v]
    out = set()
    for x in vals:
        try:
            out.add(ipaddress.ip_network(str(x).strip(), strict=False))
        except ValueError:
            pass
    return out


def as_field(field: str, t: dict, got: dict) -> bool:
    g = got.get(field)
    if field == "status":
        want = t["status"]
        return (g or "").lower() == want
    if g in (None, "", []):
        return False
    if field in ("registrar", "org"):
        return lib.same_name(t[field], g if isinstance(g, str) else str(g))
    if field in ("created", "expires"):
        return lib.same_date(t[field], g)
    if field == "nameservers":
        return lib.ns_set(g) == set(t["nameservers"])
    if field == "cidr":
        return bool(_nets(g) & _nets(t["cidrs"]))
    if field == "country":
        return str(g).upper() == t["country"]
    if field == "asn":
        vals = g if isinstance(g, list) else [g]
        return any(str(v).upper().removeprefix("AS").isdigit() and int(str(v).upper().removeprefix("AS")) in t["asns"] for v in vals)
    raise KeyError(field)


def pct(ok: int, n: int) -> str:
    return "–" if n == 0 else f"{100 * ok / n:.0f}% ({ok}/{n})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    args = ap.parse_args()
    run = args.run if args.run.is_absolute() else lib.HERE / args.run
    truth = json.loads((lib.HERE / "truth.json").read_text())["items"]
    meta = json.loads((run / "meta.json").read_text())
    runs = [json.loads(ln) for ln in (run / "runs.jsonl").read_text().splitlines()]
    tool_names = [n for n in meta["tools"]]

    # cell[tool][measure][(category|field)] = [ok, n]
    by_cat = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: [0, 0])))
    by_field = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: [0, 0])))
    overall = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    secs = defaultdict(list)
    empty = defaultdict(int)
    misses = defaultdict(list)

    for r in runs:
        t = truth.get(r["id"])
        if not t or t.get("error"):
            continue
        tool = T.BY_NAME[r["tool"]]
        out = (run / "raw" / r["tool"] / f"{r['id']}.out").read_text(errors="replace")
        text = out + "\n" + (r.get("stderr") or "")
        secs[r["tool"]].append(r["secs"])
        if not out.strip():
            empty[r["tool"]] += 1
        got = tool.fields(out) if tool.fields and out.strip() else None
        cat = t["category"]
        for f in scored_fields(t):
            measures = [("in output", in_output(f, t, text))]
            if tool.fields:
                ok = as_field(f, t, got or {})
                measures.append(("as field", ok))
                if not ok:
                    misses[r["tool"]].append({"id": r["id"], "query": t["query"], "field": f,
                                              "want": t.get(f if f not in ("cidr", "asn") else f + "s"),
                                              "got": (got or {}).get(f), "exit": r["exit"]})
            for m, ok in measures:
                for d, key in ((by_cat, cat), (by_field, f)):
                    d[r["tool"]][m][key][0] += ok
                    d[r["tool"]][m][key][1] += 1
                overall[r["tool"]][m][0] += ok
                overall[r["tool"]][m][1] += 1

    cats = sorted({t["category"] for t in truth.values()}, key=lambda c: (c.startswith("ip"), c))
    fields = list(DOMAIN_FIELDS) + list(IP_FIELDS)
    L = [f"# Correctness and coverage — run {run.name}", "",
         f"Answer key built {meta['truth_built_at']}; {meta['items']} queries. "
         "**in output** = the right answer appears anywhere in the tool's output; "
         "**as field** = the tool's own named field holds it (tools that emit fields only). "
         "Fields the authority does not publish are not scored.", "",
         "## Summary", "",
         "| Tool | Version | In output | As field | Empty output | Median s |", "|---|---|---|---|---|---|"]
    for n in tool_names:
        o = overall[n]
        L.append(f"| {n} | {meta['tools'][n]['version']} | {pct(*o['in output'])} | {pct(*o['as field']) if T.BY_NAME[n].fields else 'n/a'} "
                 f"| {empty[n]} | {statistics.median(secs[n]) if secs[n] else 0:.2f} |")
    for title, d, keys in (("By category", by_cat, cats), ("By field", by_field, fields)):
        for m in ("in output", "as field"):
            names = [n for n in tool_names if m == "in output" or T.BY_NAME[n].fields]
            L += ["", f"## {title} — {m}", "", "| | " + " | ".join(names) + " |", "|---" * (len(names) + 1) + "|"]
            for k in keys:
                if not any(d[n][m][k][1] for n in names):
                    continue
                L.append(f"| {k} | " + " | ".join(pct(*d[n][m][k]) for n in names) + " |")
    L += ["", "## whoq misses (as field)", ""]
    if misses["whoq"]:
        L += ["| Query | Field | Answer key | whoq |", "|---|---|---|---|"]
        for x in misses["whoq"]:
            L.append(f"| {x['query']} | {x['field']} | {json.dumps(x['want'], ensure_ascii=False)} | {json.dumps(x['got'], ensure_ascii=False)} |")
    else:
        L.append("None.")
    (run / "correctness.md").write_text("\n".join(L) + "\n")
    (run / "score.json").write_text(json.dumps({
        "overall": {n: dict(overall[n]) for n in tool_names},
        "by_category": {n: {m: dict(v) for m, v in by_cat[n].items()} for n in tool_names},
        "by_field": {n: {m: dict(v) for m, v in by_field[n].items()} for n in tool_names},
        "misses": misses,
    }, indent=1, ensure_ascii=False, default=str) + "\n")
    print(run / "correctness.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
