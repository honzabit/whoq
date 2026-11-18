# whoq benchmarks

Two benchmarks that show where whoq is better or worse than other WHOIS/RDAP tools, measured against an answer key built independently of whoq.

1. **Correctness and coverage** (`score.py`): for about 150 domains and IPs, does each tool give the right registrar, dates, nameservers, network owner, CIDR, country and ASN?
2. **Agent cost** (`agent.py`): when Claude reads each tool's output, how many tokens does that cost, and does it answer correctly?

The latest results are in [`results/`](results/), with a summary in [Results](#results) below.

## Setup

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
brew install whois           # GNU whois, the Linux default (keg-only: /opt/homebrew/opt/whois/bin/whois)
cargo build --release        # from the repo root; the benchmark runs target/release/whoq
```

OpenRDAP's `rdap` and macOS's `/usr/bin/whois` are used when present. Each binary can be overridden with the `WHOQ`, `WHOIS_GNU`, `WHOIS_MACOS` and `RDAP` environment variables.

## Running

```
python3 build_truth.py                     # rebuild the answer key (truth.json); about 2 minutes
python3 run.py --out 2026-11-17            # run every tool on every query; about 20 minutes
python3 score.py results/2026-11-17        # -> results/2026-11-17/correctness.md
.venv/bin/python agent.py results/2026-11-17 --dry-run     # requests and a rough cost, no API calls
.venv/bin/python agent.py results/2026-11-17               # -> agent.md; needs ANTHROPIC_API_KEY
```

Lookups and scoring are separate steps. `run.py` keeps every tool's raw output, so `score.py` and `agent.py` can be re-run or changed without querying registries again. Raw output is not committed.

## How the answer key is built

`build_truth.py` asks the authority directly, with its own code, not whoq's:

| Query | Source |
|---|---|
| Domain whose registry has RDAP | the registry's RDAP record; the registrar's RDAP for a missing registrar name |
| Domain whose registry has no RDAP | the registry's port-43 WHOIS, drafted by heuristics, then **checked by hand** ([`truth_manual.json`](truth_manual.json); the raw responses go to `truth_raw/`, which is not committed because registry WHOIS includes personal contact details) |
| IP | the RIR's RDAP record, plus the origin ASN from BGP (RIPEstat), which no tool under test uses |

A field the authority does not publish is null and is not scored. For example, DENIC publishes no dates for `.de`, so no tool is marked down for missing them.

**Known bias:** whoq is RDAP-first, so where a registry has RDAP, whoq and the answer key read the same source. On those queries the benchmark checks that whoq reports the registry faithfully; it can't catch an error the registry itself makes. The categories that separate tools are the ones without RDAP (`cctld-whois-only`), subdomains, IDNs, unregistered names, and the IP fields (country, ASN) that need more than one source.

The key is a snapshot: registrations renew and move. Rebuild it before comparing runs made weeks apart (`build_truth.py` writes `built_at`).

## How tools are scored

- **In output:** the right answer appears anywhere in what the tool printed. This is lenient on purpose: it measures whether the information is there for a person or a careful script to find. Dates match in any common format, within a day for time zones. Names match when most of their distinctive words match ("MarkMonitor, Inc." = "MarkMonitor Inc.").
- **As field:** the tool's own named field holds the right answer (`registrar.name`, `expires`, `network.cidr`, ...). Only tools that emit fields get this score, and it's what a program can rely on without parsing text.
- Nameservers must match as a complete set. A CIDR matches when it overlaps the registered network. An ASN matches when it is one of the prefix's BGP origins.

## Corpus

[`corpus.json`](corpus.json): 20 gTLD, 15 new gTLD and 46 ccTLD domains, 3 IDNs, 10 unregistered names, 5 subdomains, and 46 IPs across all five RIRs (6 of them IPv6). Queries that no public source can answer were removed: `.es` (port 43 is limited to registered IPs), `.gr` (no public WHOIS), `.ch` (WHOIS refuses automated clients), and one `.za` domain whose WHOIS host didn't resolve. Three later sets test whether fixes generalize: `holdout` (32 registered and 10 unregistered names on the same registries as the fixes), `fresh` (one registered and one unregistered name on each of 20 registries used nowhere else) and `fresh2` (the same on 24 more). Each was hand-checked before whoq was run on it.

## Tools compared

| Name | What |
|---|---|
| whoq | `whoq --json --no-cache` |
| whoq-brief | `whoq --brief --no-cache`, the compact output meant for agents |
| whois-gnu | GNU whois 5.6, the default on Debian and Ubuntu |
| whois-macos | macOS `/usr/bin/whois` |
| openrdap | OpenRDAP `rdap --json` |
| python-whois | the `python-whois` PyPI package, port-43 based |
| whoisit | the `whoisit` PyPI package, RDAP based |
| ipwhois | the `ipwhois` PyPI package, RDAP based (IPs only) |

## Results

Run of 2026-11-17 against whoq 0.1.1, from macOS on a home connection: [full tables](results/2026-11-17/correctness.md). Percentages are fields answered correctly out of fields scored.

| Tool | In output | As field | Covers |
|---|---|---|---|
| whoq | 87% | 86% | domains, IPs |
| whoq --brief | 86% | 86% | domains, IPs |
| GNU whois | 83% | n/a | domains, IPs |
| macOS whois | 82% | n/a | domains, IPs |
| python-whois | 83% | 82% | domains only |
| OpenRDAP | 69% | n/a | domains, IPs |
| whoisit | 65% | 64% | domains, IPs |
| ipwhois | 100% | 97% | IPs only |

### Where whoq wins

- **gTLDs and new gTLDs: 100%**, against 73–85% for the port-43 tools. Some registries have switched port 43 off (`.info`, `.app`, `.dev` fail outright in GNU whois), and following registrar referrals timed out at 60 s for `stackoverflow.com`, `speedtest.net` and `nic.shop`.
- **Subdomains: 100%.** `mail.google.com` and friends: GNU and macOS whois 9%, OpenRDAP and whoisit 0%, python-whois 77%.
- **IDNs: 100%.** GNU whois, OpenRDAP and whoisit 0%; macOS whois and python-whois 44%.
- **Registered or not: 98% as a field** (100% after the fixes below), against 86% for python-whois and 62% for whoisit.
- `--brief` loses nothing that matters for domains: the same accuracy as `--json` in far fewer bytes.

### Where whoq lost, and what was fixed

The first run found gaps in whoq's port-43 parser. They are fixed in the working tree; a re-run of whoq alone ([tables](results/2026-11-17-fixes/correctness.md)) moved whoq from **86% to 91%** as a field:

| Category | Before | After |
|---|---|---|
| ccTLDs without RDAP | 79% | 100% |
| Unregistered names | 90% | 100% |
| ccTLDs with RDAP | 93% | 95% |
| LACNIC IPv4 | 56% | 72% |

What changed:
- **Section-aware parsing.** Fields under a heading are now read as part of it, whether the heading is `Registrar:` or a bare `Registrar` line (`.it`, `.be`, `.ee`, `.dk`, `.hk`, `.tr`). For `.dk`, `DNS: dr.dk` is no longer read as a nameserver.
- **JPRS `[Key] value` fields (`.jp`)**, including the expiry inside `Connected (2027/09/30)`. An unregistered `.jp` name was reported as **registered**; JPRS's `No match!!` is now recognized.
- **More date formats:** `DD-MM-YYYY` (`.il`, `.hk`), `1996-Oct-31.` (`.tr`), `Thu Feb 22 1996` (`.be`), `1996. 07. 20.` (`.kr`).
- **IP networks get a CIDR derived from the start and end address** when the RIR doesn't send one (LACNIC/registro.br).
- An empty registrar object is no longer emitted (`.kr` RDAP).

### Do the fixes generalize?

The fixes were written against this corpus's responses, so they were then tested on domains whoq had never seen. Each set's answers were checked by hand **before** whoq was run on it, and the parser was frozen for the run.

**Held-out set** ([tables](results/2026-11-17-holdout/correctness.md)): 32 registered domains and 10 unregistered names on the same registries as the fixes.

| | whoq | GNU whois (in output) | python-whois |
|---|---|---|---|
| Registered domains, all fields | **100%** (139/139) | 93% overall | 81% |
| Unregistered names | **40%** (4/10) | | 60% |

The parser fixes held on new domains. The unregistered result exposed a deeper bug: when whoq didn't recognize a response, it **assumed "registered"**. So every unfamiliar not-found wording (`Status: AVAILABLE` with odd spacing, "has not been registered", "No data was found", "% nothing found") became a false "registered". That is fixed in [whois43.rs](../src/whois43.rs) by changing behavior, not by adding wordings. An unrecognized response is now an **error** ("could not tell whether X is registered"), never a guess. A status field reading `available` or `free` counts as not registered, and not-found phrases match regardless of spacing.

**Fresh set** ([tables](results/2026-11-17-fresh/correctness.md)): 20 registries not used anywhere else, each with one registered domain and one unregistered name. This is the test of the second fix.

| | whoq | GNU whois (in output) | python-whois | whoisit |
|---|---|---|---|---|
| All fields | 89% | 97% | 79% | 15% |
| Unregistered names correct | 75% (15/20) | | 75% | 15% |
| Unregistered names reported as **registered** | **0** | | | |

whoq no longer reports an unregistered name as registered. The 5 it couldn't read (`.pt` "No Match", `.com.mx` "Object_Not_Found", `.hu` "No match", `.bg` "registration status: available", `.lu` "No such domain") came back as errors, not wrong answers. On registered domains it missed layouts it hadn't met: `.bg` nameservers with no label, `.lu` `registrar-name:`, `.kz` `Current Registrar......:`, and `.sk`'s registrar handle.

### Reading keys by their words, not their spelling

Patching each of those would never end, so the parser was changed instead. GNU whois avoids the problem by not parsing at all: its only per-registry knowledge is which server to ask, a few query flags (DENIC, `.dk`, JPRS), referral following and disclaimer text, and it prints the reply as is. whoq has to return fields, so it now borrows the idea at the level of words:

- **Keys are classified by the words they contain**, after reading `-`, `_` and `.` as spaces. Any key with "registrar" and no contact or date word is the registrar's name; "creat", "commence" or "registered" means created; "expir", "paid till", "valid" means expires; "name" + "server", "nserver" or "nameserver" is a nameserver. `Current Registrar......`, `registrar-name`, `Domain created` and `NAME SERVER INFORMATION` all land without an entry of their own. Values are still checked: a date must parse, a nameserver must be a hostname.
- **Sections are judged generically.** A field's own key decides when it means something on its own; only sub-fields (`Name`, `Organization`, `URL`, `Hostname`) take their meaning from the heading above. Fields under a heading that starts with a contact word (`Registrant`, `Administrative Contact`) are never read as the domain's.
- **Not-found wording is a short list of common phrases** ("no match", "not found", "no such domain"), matched with `_` read as a space, and only consulted when no registration data was found.
- **When whoq still can't tell, the error quotes the registry** (`Registry said: "…"`) and the full reply is kept in `raw`, as GNU whois would show it.
- Unrelated to parsing, the fresh2 run below also found that whoq tried a host's addresses one after another within one 15 s budget. `whois.nic.net.sa` publishes an IPv6 address that never answers, so `.sa` always timed out. Each address now gets 3 s.

On every earlier set (replaying the saved registry replies offline, plus live lookups) the only miss left is `.sk`'s registrar handle; the tests now include the fresh set's layouts, so that set no longer counts as unseen.

**Fresh2 set** ([tables](results/2026-11-17-fresh2/correctness.md)): 24 more registries used nowhere else (`google.<tld>` and one unregistered name each), hand-checked before whoq was run, parser frozen.

| | whoq | GNU whois (in output) | python-whois | whoisit |
|---|---|---|---|---|
| All fields | 89% (109/122) | 93% | 71% | 0% |
| Unregistered names correct | 22/24 | 23/24 | 21/24 | 0/24 |
| Unregistered names reported as **registered** | **0** | | | |

Of whoq's 13 misses, 7 were timeouts: `.sa` (the connect bug above, fixed after the run; both `.sa` names are now correct) and `.ws`, whose server was down for GNU whois too. The other 6 are layouts the word rules don't cover yet: nameservers under a `DNS servers:` heading (`.am`), `Name Server:ns1.google.com.` with no space after the colon (`.im`), and `Registered on 30th April 2003` as a sentence (`.gg`, `.je`).

GNU whois scores higher because the scorer only checks whether the answer appears somewhere in its raw text; it needs no parsing to "pass". As a tool that returns named fields, whoq is ahead of python-whois and whoisit on every set.

### whoq 0.1.2 on every set

Re-run of whoq alone on 2026-11-18, with the word classifier and the speed fixes below ([tables](results/2026-11-18-cache/correctness.md)). The other tools' numbers are from their 2026-11-17 runs. "Base" includes the IPs, as in the first table.

| | base | fresh | holdout | fresh2 |
|---|---|---|---|---|
| **whoq 0.1.2** | **91%** (524/576) | 94% (97/103) | **97%** (145/149) | **97%** (118/122) |
| whoq 0.1.1 (first runs) | 87% | 89% | 96% | 89% |
| GNU whois (in output) | 83% | **97%** | 93% | 93% |
| macOS whois | 82% | 94% | 90% | – |
| python-whois | 83% | 81% | 83% | 70% |
| OpenRDAP | 69% | 21% | 1% | – |
| whoisit | 65% | 18% | 1% | 0% |

Base domains alone are at 98% (415/424). What whoq still misses: origin ASN on IPs (see below), `gov.sg`, `.sk`'s registrar handle, the four fresh2 layouts above, and `.pt`, whose WHOIS server refused connections during the run (`sapo.pt`, `publico.pt`, `rtp.pt` and the unregistered `.pt` name). `.ws` was back up, so both `.ws` names are now correct.

### Speed

Seconds per domain lookup, every query uncached (`--no-cache`), 1 s apart:

| | median | p90 | slowest | over 5 s |
|---|---|---|---|---|
| **whoq 0.1.2** | 0.41 | 1.17 | **3.4** | **0 / 229** |
| whoq 0.1.1 | 0.57 | 1.22 | 22.3 | 12 / 328 |
| GNU whois | 0.24 | 0.83 | 60.0 | 8 / 229 |
| python-whois | 0.67 | 1.30 | 11.5 | 11 / 229 |

Two fixes made the difference:

- **A long `Retry-After` now fails at once.** Tucows' registrar RDAP answers rate-limited requests with `Retry-After: 60`. whoq waited 10 s, retried, was refused again, and waited another 10 s, so `php.net` and `archive.org` took about 21 s for a step that is best-effort anyway. When a server asks for more than 3 s, whoq now reports the rate limit without retrying; both lookups take about 1 s.
- **IANA's WHOIS-server answers are cached on disk for a week.** Before each port-43 lookup whoq asked `whois.iana.org` which server handles the TLD, a ~285 ms round trip GNU whois skips with its built-in table. On domains answered by one port-43 server, whoq's median went from 0.64 s to 0.24 s; side by side on 30 of them, whoq and GNU whois both took 0.18 s.

GNU whois is still faster where whoq asks the registrar too (`.com`, `.net` and most gTLDs): whoq makes two HTTPS requests in a row, each with its own TLS handshake, and some registrar RDAP servers are slow to connect (MarkMonitor takes about 0.9 s from here).

### Where whoq still loses

- **Origin ASN for IPs: 0%.** `whoq <ip>` does not report the announcing AS; ipwhois gets 96% and GNU whois prints it 63% of the time. (`whoq bulk` and `--dns` look ASNs up from Team Cymru; plain lookups don't.) This accounts for nearly all of whoq's remaining misses.
- **`gov.sg`** is rejected as a public suffix, although the registry has it registered.
- **IPs overall:** ipwhois is the most complete IP tool here; whoq ties the others on organization, country and CIDR.
- **Speed on a typical lookup:** GNU whois's median is 0.24 s against whoq's 0.41 s, mostly from whoq's second request to the registrar (see [Speed](#speed)).

### Agent cost

`agent.py` has not been run yet: it needs Anthropic API credentials. A dry run sizes the default sample (60 queries × 5 formats = 300 requests on `claude-opus-5-5`) at roughly $3, or about $8 for all 145 queries.
