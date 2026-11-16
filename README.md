# whoq

RDAP-first WHOIS for humans **and** agents. Single static binary, macOS + Linux.

```
$ whoq google.com 8.8.8.8 AS13335 https://www.bbc.co.uk/news
```

## Why not plain `whois`?

| classic `whois`                 | `whoq`                                                                 |
|---------------------------------|------------------------------------------------------------------------|
| port 43 plain text only         | **RDAP** via IANA bootstrap (RFC 9224), port‑43 fallback for ccTLDs without RDAP |
| every registry formats it differently | one **normalized, versioned schema** (`whoq schema`)              |
| you work out the date math      | computed **signals**: `age_days`, `expires_in_days`, `young`, `expiring_soon`, `recently_transferred`, `privacy_redacted`, `on_hold` |
| one query at a time             | batch from args or stdin, parallel, per‑host rate limits + backoff |
| exit 0 no matter what           | **meaningful exit codes**: 0 found · 1 failed · 2 usage · 10 available/not found |
| raw text gets echoed to your terminal | **sanitized**: ANSI escapes, control chars and bidi overrides stripped, lengths capped |
| `www.foo.co.uk` → "no match"    | takes URLs and emails and reduces them to the registrable domain (Public Suffix List, ICANN section) |
| —                               | **`--dns`**: hosting network, DNS provider, CAA and forward-confirmed reverse DNS for IPs; **`--mail`**: MX provider, SPF/DMARC/DKIM; **`--tls`**: certificate issuer, expiry, validity |
| —                               | **MCP server** built in: `whoq mcp`                                |
| —                               | disk cache (1h results, 24h bootstrap), works off stale bootstrap data when IANA is unreachable |

## Usage

```
whoq example.com                      # pretty on a TTY
whoq example.com | jq .expires        # NDJSON when piped
whoq --json a.com b.com               # JSON array
whoq -b example.com                   # brief, token-friendly
whoq -f registrar.name,expires,signals.expires_in_days example.com
cat domains.txt | whoq -j 16 -o ndjson
whoq --raw example.com                # include upstream responses
whoq --whois example.de               # force port 43
whoq --max-age 1d example.com         # cached if under a day old, else fetch fresh
whoq --max-age 0 example.com          # always fetch fresh (still refreshes the cache)
whoq --dns example.com 8.8.8.8        # + hosting, DNS provider, CAA, reverse DNS
whoq --mail example.com               # + MX provider, SPF, DMARC, DKIM
whoq --tls https://shop.example.com   # + certificate: issuer, names, expiry, valid? (connects to the host)
whoq schema                           # JSON Schema of the output
```

`--max-age` takes `90s`, `30m`, `6h`, `2d`, `1w` or plain seconds; the default is `1h`. Whether a result came from cache shows up in `source.cached`, and `source.fetched_at` gives its time. `--no-cache` skips both reading and writing. Cache location: `~/Library/Caches/whoq` (macOS) or `~/.cache/whoq` (Linux).

The same flags mean the same thing everywhere: `--max-age` (how old cached data may be), `--dns` (live DNS; reverse DNS in `bulk`), `--timeout` (seconds per request, default 15) and `--no-cache` work in lookup, `bulk` and `mcp` alike.

Environment: `WHOQ_CACHE_DIR`, `WHOQ_STATE_DIR`, `WHOQ_TIMEOUT`, `WHOQ_MAX_AGE`, `WHOQ_DNS_SERVER=ip[:port]`, `WHOQ_TLS_CA=file.pem` (trust only these roots for `--tls`), `WHOQ_WEBHOOK`, `NO_COLOR`, and `WHOQ_WHOIS_ADDR=host:port` (send every port-43 connection through one address, for proxies and tests).

## Live DNS: `--dns` and `--mail`

Registration data tells you who registered a name. `--dns` adds who runs it, and `--mail` adds whether mail claiming to be from it can be trusted. Both come from live DNS and can be combined:

```
$ whoq --dns --mail github.com
  …
  Hosting       GITHUB - GitHub, Inc. (AS36459, US)  140.82.121.3
  DNS           NS1 + AWS Route 53
  CAA           only digicert.com, globalsign.com, letsencrypt.org, sectigo.com
  Mail          Microsoft 365  github-com.mail.protection.outlook.com
  SPF           ~all  include spf.protection.outlook.com, _netblocks.google.com, …
  DMARC         quarantine
  DKIM          google, selector1, k1, k2, k3, s1, s2  (common selectors probed)

$ whoq --dns 66.249.66.1
  …
  rDNS          crawl-66-249-66-1.googlebot.com  ✓ forward-confirmed
```

- **`--dns` on domains** adds `dns`: A/AAAA, the networks announcing them via Team Cymru, NS and a recognized DNS provider, CAA. About 5 queries.
- **`--mail` on domains** adds `mail`: MX and a recognized provider, null MX, SPF, DMARC, DKIM selectors found among common names, MTA-STS, TLS-RPT, BIMI. About 25 queries, most of them DKIM probes. If the name doesn't exist in DNS, `mail.error` says so.
- **`--dns` on IPs** adds `rdns`: PTR names plus `verified`, meaning a PTR name resolves back to the IP. That is how real crawlers are told from fakes: anyone can set a PTR that says `googlebot.com`, only Google can make it resolve back.
- **New signals**: `resolves` and `parked` (nameservers of a parking service) from `--dns`; `accepts_mail` and `spoofable` (no DMARC, or `p=none`, so mail forging the domain is not rejected) from `--mail`.
- **DKIM is best effort**: selectors can't be listed, so whoq probes about 20 common ones. An empty list doesn't mean no DKIM.
- **It never connects to the target's own servers.** Queries go to your resolver (and Team Cymru for hosting), so investigating a phishing domain doesn't tip it off.
- **Resolver**: the system's, over UDP. Many home routers can't return large TXT sets, which would silently hide SPF, so failed queries are retried through 1.1.1.1. Queries the system resolver hasn't answered within 0.8s are also sent to 1.1.1.1, and the first definite answer wins (some routers take seconds over DKIM names). `WHOQ_DNS_SERVER=ip[:port]` pins one resolver with no fallback.
- **Not cached**: DNS is fetched live on every run; `--max-age` applies only to the registration data.
- **Speed**: queries run in parallel; either flag typically adds under a second.

## Certificates: `--tls`

`--tls` connects to the host and reads the certificate it presents:

```
$ whoq --tls github.com
  …
  TLS           ✓ valid  github.com · TLS 1.3
  Issuer        Sectigo Limited (Sectigo Public Server Authentication CA DV E36)
  Cert expires  2027-01-27  in 73d
  Cert names    github.com, www.github.com
```

- **It checks the exact host given**, not the registrable domain: `whoq --tls https://shop.example.com:8443/x` checks `shop.example.com` on port 8443. IPs work too (`whoq --tls 1.1.1.1`).
- **Broken certificates are still described.** `valid` is the chain checked against Mozilla's roots, the dates, and the host name; `problem` says what failed: `expired`, `self-signed`, `not valid for this name`, `issuer not trusted (…)`.
- **Fields**: `tls` holds the issuer, subject, SANs (`names`), validity dates and `expires_in_days`, protocol, key type and the leaf's SHA-256 (for searching CT logs). New signals: `cert_valid` and `cert_expiring_soon` (under 14 days).
- **It connects to the target.** `--dns` and `--mail` only talk to resolvers. `--tls` opens a connection to the host itself, which can log it. No HTTP request is sent; the connection closes after the handshake.
- **Not cached**, like the DNS checks.

## Watch mode

The useful thing to know about registration data is when it changes. `whoq watch` saves a snapshot of each record, compares it with the previous run, and reports the differences:

```
whoq watch mydomain.com mybrand.net          # first run records a baseline
whoq watch -i 6h --webhook "$SLACK_URL" < domains.txt
0 */6 * * * whoq watch -q < ~/domains.txt     # cron: exit 20 when something changed
whoq watch --dns --mail --tls mydomain.com   # also delegation, mail routing, certificate
```

```
github.com  ▲ changed (high)  since 2026-11-14T18:53:16Z
  nameservers       - ns1.legit-dns.example, ns2.legit-dns.example
                    + dns1.p08.nsone.net, …
  registrar.name    Old Registrar LLC → MarkMonitor Inc.
  status            - client transfer prohibited  ← transfer lock removed
  expires           2026-01-01 → 2028-10-09  ← renewed
```

- **Severity**: changes to nameservers, registrar, the transfer date, the creation date (a re-registration), the result (registered ↔ available), or removal of a transfer lock are **high**. Changes to status, DNSSEC or contacts are **medium**. A renewal (later expiry date) is **low**.
- **Alerts** fire once per expiry date: `expiring` (within `--expiry-warn`, default 30 days), `expired`, and `on_hold`. A renewal changes the expiry date and re-arms them.
- **Live checks**: `--dns`, `--mail` and `--tls` add those sections to the snapshot. Only fields that change on purpose are compared: the nameservers and DNS provider, hosting networks (by ASN, not address, since CDNs rotate addresses), CAA, MX and mail provider, SPF, DMARC, the certificate's issuer, names and validity, and reverse DNS. A change to the nameservers, MX, or certificate validity is **high**. The issuer, hosting, CAA or DMARC policy is **medium**. A section is compared only when both runs have it, so turning a flag on or off isn't a change. A transient failure (a timeout) keeps the last good copy. NXDOMAIN counts as a real change, because the domain's DNS is gone.
- **Certificate alerts** (`--tls`) fire once per certificate: `cert_expiring` (within `--cert-warn`, default 14 days), `cert_expired`, and `cert_invalid` with the `problem`. A renewed certificate re-arms them. Expiry dates and fingerprints aren't diffed, so routine renewals stay quiet.
- **Noise control**: nameserver and status lists are compared regardless of order. Fetch timestamps and computed signals are never compared. `--ignore updated,registrant` skips fields you don't care about.
- **Output**: events (`baseline`, `changed`, `alert`, `error`, plus `unchanged` with `--all`) as NDJSON when piped. `--webhook` POSTs `{text, events}`, which Slack-style webhooks accept.
- **State** is kept in the OS data directory (`~/Library/Application Support/whoq/watch` on macOS, `~/.local/share/whoq/watch` on Linux), or in `--state` / `WHOQ_STATE_DIR`. A failed lookup never overwrites a good snapshot. Each host is its own snapshot: `shop.example.com` and `example.com` are watched separately.
- **Exit codes**: 0 nothing changed · 1 lookups failed · 20 changes or alerts.

## Bulk mode: log enrichment

`whoq bulk` labels every IP in a log with who owns it. It finds IPs anywhere in each line, including IPv6, `ip:port`, `[v6]:port`, IPv4-mapped addresses and `X-Forwarded-For` lists, or only in one column with `--column`.

```
$ whoq bulk -m summary access.log
    HITS   SHARE     IPS        ASN  CC   OWNER
    7230   36.1%    2891    AS15169  US   GOOGLE - Google LLC, US
    6231   31.2%    2910    AS13335  US   CLOUDFLARENET - Cloudflare, Inc., US
    1909    9.5%    1909    AS16509  US   AMAZON-02 - Amazon.com, Inc., US
     969    4.8%     962                  private / reserved
whoq bulk: 20000 lines · 12077 unique IPs · 7 cymru queries · 0 rdap lookups · … · 3.3s
```

```
whoq bulk -c 1 -o tsv access.log > enriched.tsv            # original line + ip, asn, as_name, cc, prefix, org
whoq bulk -m unique --rdap -o csv fw.log > owners.csv      # one row per IP, with org + abuse contact
zcat auth.log.gz | whoq bulk | jq -c 'select(any(.ips[]; .asn == 14061))'
whoq bulk -c 1 -w 2 -m summary counts.tsv                  # pre-aggregated "ip<TAB>count": shares weighted by count
whoq bulk -m unique --dns -o csv access.log                # + ptr, ptr_verified (which "Googlebots" are real)
```

It scales because it looks up networks, not individual IPs:

- **Team Cymru IP-to-ASN bulk whois** (the default) answers up to 1,000 IPs per TCP connection with ASN, AS name, BGP prefix, country and RIR.
- **`--rdap`** adds the registry org, network name and abuse contact. Each RDAP answer is cached under its CIDR and reused for every other IP inside it; in testing, 2,269 IPs needed 71 RDAP requests. IPs in the same /24 (or /48) are looked up one after another so the first answer usually covers the rest. `--precise` limits reuse to /24 (/48) when sub-allocations matter.
- **A persistent network cache** (`--max-age`, default `7d`) makes repeat runs mostly offline. In testing the same 20k lines took 0.0s on the second run. Expired and superseded entries are compacted away automatically on load.
- **Streaming in chunks of 5,000 lines** keeps memory flat. Annotate output preserves line order and stops cleanly when piped to `head`.
- **`--dns`** adds `ptr` and `ptr_verified` per IP (annotate and unique modes; TSV and CSV gain two columns). It costs one or two DNS queries per unique public IP, 32 at a time, and is not cached between runs.
- **Private and reserved addresses** (RFC 1918, CGNAT, loopback, link-local, ULA, documentation ranges) are labelled locally and never sent upstream.

Privacy note: public IPs from your logs are sent to Team Cymru (default) and/or the RIRs' RDAP servers. Use `--no-cymru` to only talk to RIRs.

Modes: `annotate` (default; NDJSON or `-o tsv`), `unique` (NDJSON, CSV or table), `summary` (NDJSON, CSV or table, `--top N`).

## MCP

```json
{ "mcpServers": { "whoq": { "command": "whoq", "args": ["mcp"] } } }
```

Claude Code: `claude mcp add whoq -- whoq mcp`

Tools: `lookup` (queries, fields, brief, `max_age`: e.g. `"6h"`, or `0` to force fresh; `dns`, `mail` and `tls`: live checks as above), `check_availability` (domains) and `enrich_ips` (up to 1,000 IPs or log fragments; `rdap`, `summary`, `dns` for reverse DNS). All are read-only. Output is
wrapped in `<untrusted-registry-data>` and the tool descriptions warn the model that registrant-controlled
strings are data, not instructions.

## Caveats

- `available` means the registry has no record of the domain. Premium or reserved names can still be blocked.
- Port‑43 parsing is heuristic. Use `--raw` when a ccTLD's output looks wrong.
- Provider names (`dns.provider`, `mail.provider`) come from a built-in table of nameserver and MX suffixes. Unknown providers are left blank; the raw hosts are always there.

## Install

With Homebrew (macOS, Linux):

```
brew install honzabit/tap/whoq
```

Prebuilt binaries for macOS (Apple silicon, Intel) and Linux (x86_64, arm64; static musl) are on the [releases page](https://github.com/honzabit/whoq/releases). Or build from source:

```
cargo install --git https://github.com/honzabit/whoq
```

## Build

```
cargo build --release      # target/release/whoq
cargo test                 # unit tests + offline end-to-end tests
cargo clippy --all-targets && cargo fmt --check
```

The end-to-end tests in `tests/cli.rs` run the real binary against local fake RDAP and port-43 servers, using synthetic fixtures in `tests/fixtures/`. They need no network access.

## License

MIT. See [LICENSE](LICENSE).
