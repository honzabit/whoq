#!/usr/bin/env python3
"""Benchmark #5: what each tool's output costs an AI agent, and whether the agent gets the
answer right from it.

For each query and output format, Claude is shown only that tool's saved output (from a
run.py run, so no new registry traffic) and asked for the registration facts as JSON. The
answers are graded against truth.json with the same rules as score.py's "as field".

  python agent.py results/2026-11-17 --dry-run        # count requests, rough cost; no API calls
  python agent.py results/2026-11-17                  # needs ANTHROPIC_API_KEY (or `ant auth login`)
  python agent.py results/2026-11-17 --formats whoq-brief whois-gnu --sample 0   # every query

Measures per format: tokens of the tool output alone (count_tokens, exact for the model),
total input tokens per request, accuracy, and cost per 1,000 lookups at list prices.
Writes agent.md and agent.json next to the run; answers are cached in agent_cache.jsonl so
an interrupted run resumes without paying twice.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import lib
import score as S

DEFAULT_FORMATS = ["whoq-brief", "whoq", "whois-gnu", "whois-macos", "openrdap"]
PRICES = {  # USD per million tokens (input, output), list prices
    "claude-opus-5-5": (4.0, 20.0),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-fable-5-2": (8.0, 40.0),
}
MAX_OUTPUT_CHARS = 200_000  # a few registries return huge pages; never truncate below this

SYSTEM = (
    "You read the output of a domain/IP lookup tool and report what it says. Use only the "
    "tool output you are given, not your own knowledge. If the output does not state a value, "
    "use null. Dates as YYYY-MM-DD."
)

NULLABLE_STR = {"type": ["string", "null"]}
SCHEMAS = {
    "domain": {
        "type": "object",
        "properties": {
            "registered": {"type": ["boolean", "null"], "description": "true if registered, false if the output says it is not registered/available"},
            "registrar": NULLABLE_STR,
            "created": NULLABLE_STR,
            "expires": NULLABLE_STR,
            "nameservers": {"type": ["array", "null"], "items": {"type": "string"}},
        },
        "required": ["registered", "registrar", "created", "expires", "nameservers"],
        "additionalProperties": False,
    },
    "ip": {
        "type": "object",
        "properties": {
            "org": {**NULLABLE_STR, "description": "organization the network is registered to"},
            "cidr": {**NULLABLE_STR, "description": "the registered network in CIDR notation"},
            "country": {**NULLABLE_STR, "description": "two-letter country code of the network registration"},
            "asn": {"type": ["integer", "null"], "description": "origin autonomous system number"},
        },
        "required": ["org", "cidr", "country", "asn"],
        "additionalProperties": False,
    },
}
QUESTION = {
    "domain": "Is {q} registered? If so: registrar, creation date, expiry date and nameservers.",
    "ip": "Who holds {q}: registered organization, network (CIDR), country, and origin ASN.",
}


def tool_text(run: Path, fmt: str, item_id: str, stderr: str) -> str:
    out = (run / "raw" / fmt / f"{item_id}.out").read_text(errors="replace")
    text = out if out.strip() else stderr
    if len(text) > MAX_OUTPUT_CHARS:
        sys.exit(f"{fmt}/{item_id}: output is {len(text)} chars; raise MAX_OUTPUT_CHARS deliberately rather than truncate")
    return text


def user_message(t: dict, text: str) -> str:
    return f"{QUESTION[t['kind']].format(q=t['query'])}\n\n<tool_output>\n{text}\n</tool_output>"


def sample_items(truth: dict, n: int, seed: int) -> list[str]:
    ids = [i for i, t in truth.items() if not t.get("error")]
    if n <= 0 or n >= len(ids):
        return sorted(ids)
    by_cat = defaultdict(list)
    for i in sorted(ids):
        by_cat[truth[i]["category"]].append(i)
    rng = random.Random(seed)
    for v in by_cat.values():
        rng.shuffle(v)
    picked = []
    while len(picked) < n:  # round-robin across categories so small ones are represented
        for v in by_cat.values():
            if v and len(picked) < n:
                picked.append(v.pop())
    return sorted(picked)


def to_fields(t: dict, ans: dict) -> dict:
    if t["kind"] == "ip":
        return {k: ans.get(k) for k in ("org", "cidr", "country", "asn")}
    reg = ans.get("registered")
    return {
        "status": None if reg is None else ("registered" if reg else "available"),
        "registrar": ans.get("registrar"),
        "created": ans.get("created"),
        "expires": ans.get("expires"),
        "nameservers": ans.get("nameservers"),
    }


def ask(client, model: str, effort: str, t: dict, text: str) -> dict:
    import anthropic

    msg = user_message(t, text)
    counted = client.messages.count_tokens(model=model, messages=[{"role": "user", "content": text or " "}]).input_tokens
    try:
        r = client.beta.messages.create(
            model=model,
            max_tokens=16000,
            system=SYSTEM,
            messages=[{"role": "user", "content": msg}],
            output_config={"effort": effort, "format": {"type": "json_schema", "schema": SCHEMAS[t["kind"]]}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.BadRequestError as e:
        return {"error": f"400: {e.message}", "output_tokens_only": counted}
    if r.stop_reason == "refusal":
        return {"error": "refusal", "output_tokens_only": counted, "input_tokens": r.usage.input_tokens}
    body = next((b.text for b in r.content if b.type == "text"), "{}")
    return {
        "answer": json.loads(body),
        "output_tokens_only": counted,
        "input_tokens": r.usage.input_tokens,
        "output_tokens": r.usage.output_tokens,
        "model": r.model,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("--formats", nargs="*", default=DEFAULT_FORMATS)
    ap.add_argument("--model", default="claude-opus-5-5")
    ap.add_argument("--effort", default="low", help="low suits plain extraction; raise to test whether thinking harder rescues messy formats")
    ap.add_argument("--sample", type=int, default=60, help="queries, stratified by category (0 = all)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    run = args.run if args.run.is_absolute() else lib.HERE / args.run
    truth = json.loads((lib.HERE / "truth.json").read_text())["items"]
    runs = {(r["tool"], r["id"]): r for r in map(json.loads, (run / "runs.jsonl").read_text().splitlines())}
    ids = sample_items(truth, args.sample, args.seed)
    jobs = [(f, i) for f in args.formats for i in ids if (f, i) in runs]

    cache_path = run / "agent_cache.jsonl"
    key = lambda f, i: f"{args.model}|{args.effort}|{f}|{i}"
    cache = {}
    if cache_path.exists():
        for ln in cache_path.read_text().splitlines():
            rec = json.loads(ln)
            cache[rec["key"]] = rec
    todo = [(f, i) for f, i in jobs if key(f, i) not in cache]

    if args.dry_run:
        chars = sum(len(user_message(truth[i], tool_text(run, f, i, runs[(f, i)].get("stderr", "")))) for f, i in todo)
        pin, pout = PRICES.get(args.model, (0, 0))
        est = chars / 4  # rough: ~4 characters per token; the real run counts exactly
        print(f"{len(jobs)} requests ({len(todo)} not cached) over {len(ids)} queries x {len(args.formats)} formats")
        print(f"rough input ≈ {est / 1e6:.2f}M tokens -> ≈ ${est / 1e6 * pin + len(todo) * 400 / 1e6 * pout:.2f} on {args.model} (estimate, not a quote)")
        return 0

    import anthropic

    client = anthropic.Anthropic()
    lock = threading.Lock()

    def work(job):
        f, i = job
        t = truth[i]
        res = ask(client, args.model, args.effort, t, tool_text(run, f, i, runs[(f, i)].get("stderr", "")))
        rec = {"key": key(f, i), "format": f, "id": i, **res}
        with lock:
            with cache_path.open("a") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            cache[rec["key"]] = rec
        return rec

    with ThreadPoolExecutor(args.workers) as ex:
        for n, _ in enumerate(ex.map(work, todo), 1):
            if n % 25 == 0 or n == len(todo):
                print(f"{n}/{len(todo)}", file=sys.stderr)

    # ---------------------------------------------------------------- report
    pin, pout = PRICES.get(args.model, (0, 0))
    stats = {}
    by_field = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for f in args.formats:
        recs = [cache[key(f, i)] for i in ids if key(f, i) in cache]
        ok = n = 0
        for rec in recs:
            t = truth[rec["id"]]
            got = to_fields(t, rec.get("answer") or {})
            for fld in S.scored_fields(t):
                good = S.as_field(fld, t, got)
                ok += good
                n += 1
                by_field[f][fld][0] += good
                by_field[f][fld][1] += 1
        tin = [r.get("input_tokens", 0) for r in recs]
        tout = [r.get("output_tokens", 0) for r in recs]
        only = [r.get("output_tokens_only", 0) for r in recs]
        stats[f] = {
            "requests": len(recs),
            "errors": sum(1 for r in recs if r.get("error")),
            "accuracy": [ok, n],
            "tool_tokens_median": statistics.median(only) if only else 0,
            "tool_tokens_p90": sorted(only)[int(0.9 * (len(only) - 1))] if only else 0,
            "input_tokens_total": sum(tin),
            "output_tokens_total": sum(tout),
            "usd_per_1000": (sum(tin) * pin + sum(tout) * pout) / 1e6 / max(len(recs), 1) * 1000,
        }
    L = [f"# Agent cost — run {run.name}", "",
         f"{len(ids)} queries (stratified sample, seed {args.seed}); model `{args.model}`, effort `{args.effort}`. "
         "Claude sees only one tool's saved output per request and answers in a fixed JSON schema; answers are graded "
         "like score.py's *as field*. Tool tokens are the tool output alone, counted with count_tokens.", "",
         "| Format | Accuracy | Tool tokens (median) | Tool tokens (p90) | $ per 1,000 lookups | Errors |", "|---|---|---|---|---|---|"]
    for f, s in stats.items():
        L.append(f"| {f} | {S.pct(*s['accuracy'])} | {s['tool_tokens_median']:,.0f} | {s['tool_tokens_p90']:,.0f} | {s['usd_per_1000']:.2f} | {s['errors']} |")
    fields = [x for x in list(S.DOMAIN_FIELDS) + list(S.IP_FIELDS) if any(by_field[f][x][1] for f in args.formats)]
    L += ["", "## Accuracy by field", "", "| | " + " | ".join(args.formats) + " |", "|---" * (len(args.formats) + 1) + "|"]
    for x in fields:
        L.append(f"| {x} | " + " | ".join(S.pct(*by_field[f][x]) for f in args.formats) + " |")
    (run / "agent.md").write_text("\n".join(L) + "\n")
    (run / "agent.json").write_text(json.dumps({"model": args.model, "effort": args.effort, "ids": ids, "stats": stats,
                                                 "by_field": {f: dict(v) for f, v in by_field.items()}}, indent=1) + "\n")
    print(run / "agent.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
