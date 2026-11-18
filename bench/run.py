#!/usr/bin/env python3
"""Run every tool on every query in the corpus and keep the raw output.

  python run.py                       # all tools -> results/<UTC timestamp>/
  python run.py --tools whoq whois-gnu --only d-bbc-co-uk ip-8-8-8-8

Tools run side by side, but each tool's queries run one at a time with a pause between
them, so no registry sees more than one query per tool at once. Scoring is a separate,
offline step (score.py, agent.py) over the saved output.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import threading
import time

import lib
import tools as T


def version(tool: T.Tool) -> str:
    if not tool.version:
        return "unknown"
    try:
        out = subprocess.run(tool.version, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return "unknown"
    for line in out.splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return (out.strip().splitlines() or ["unknown"])[0]


def run_tool(tool: T.Tool, items: list[dict], out_dir, pause: float, timeout: float, log) -> None:
    raw = out_dir / "raw" / tool.name
    raw.mkdir(parents=True, exist_ok=True)
    for it in items:
        if it["kind"] not in tool.kinds:
            continue
        t0 = time.monotonic()
        try:
            p = subprocess.run(tool.cmd(it["query"]), capture_output=True, timeout=timeout)
            code, stdout, stderr = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            code, stdout, stderr = "timeout", e.stdout or b"", e.stderr or b""
        secs = round(time.monotonic() - t0, 3)
        (raw / f"{it['id']}.out").write_bytes(stdout)
        log({"tool": tool.name, "id": it["id"], "exit": code, "secs": secs,
             "stderr": stderr.decode("utf-8", "replace")[-500:]})
        time.sleep(pause)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", nargs="*")
    ap.add_argument("--only", nargs="*", help="item ids")
    ap.add_argument("--out", help="results directory (default results/<timestamp>)")
    ap.add_argument("--pause", type=float, default=1.0, help="seconds between one tool's queries")
    ap.add_argument("--timeout", type=float, default=60)
    args = ap.parse_args()

    truth = json.loads((lib.HERE / "truth.json").read_text())
    items = [i for i in lib.load_corpus() if i["id"] in truth["items"]]
    if args.only:
        items = [i for i in items if i["id"] in args.only]
    chosen = [t for t in T.pick(args.tools) if t.available() or print(f"skipping {t.name}: {t.exe} not found", file=sys.stderr)]

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = lib.HERE / "results" / (args.out or stamp)
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "started_at": stamp,
        "truth_built_at": truth["built_at"],
        "tools": {t.name: {"describe": t.describe, "version": version(t)} for t in chosen},
        "items": len(items),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")

    lock = threading.Lock()
    log_path = out_dir / "runs.jsonl"
    done = {"n": 0}
    total = sum(1 for t in chosen for i in items if i["kind"] in t.kinds)

    def log(rec: dict) -> None:
        with lock:
            with log_path.open("a") as f:
                f.write(json.dumps(rec) + "\n")
            done["n"] += 1
            if done["n"] % 50 == 0 or done["n"] == total:
                print(f"{done['n']}/{total}", file=sys.stderr)

    threads = [threading.Thread(target=run_tool, args=(t, items, out_dir, args.pause, args.timeout, log)) for t in chosen]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    print(out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
