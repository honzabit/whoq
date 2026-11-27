# whoq

**Who owns this domain, IP or network? Ask `whoq`.**

`whoq` is a modern WHOIS for people and AI agents. It speaks RDAP first, falls back to classic WHOIS when it has to, and gives every answer the same clean shape, whichever registry it came from. One static binary for macOS and Linux.

```
$ whoq github.com
github.com  ● registered
  Registrar     MarkMonitor Inc.  IANA #292
  Created       2007-10-09  (19y ago)
  Updated       2026-09-07  (2mo ago)
  Expires       2028-10-09  (in 23mo)
  Status        client delete prohibited, client transfer prohibited, client update prohibited
  Nameservers   dns1.p08.nsone.net, dns2.p08.nsone.net, … ns-421.awsdns-52.com, ns-520.awsdns-01.net
  DNSSEC        unsigned
  Registrant    redacted · CA, US
  Abuse         abusecomplaints@markmonitor.com
  Source        rdap · https://rdap.verisign.com/com/v1/domain/github.com
```

Give it anything: a domain, an IP, an AS number, a URL or an email address. `whoq google.com 8.8.8.8 AS13335 https://www.bbc.co.uk/news` works.

## Install

```
brew trust honzabit/tap
brew install honzabit/tap/whoq
```

Homebrew 7 and later only load formulae from taps you trust, so the first line is needed once per machine.

Or `cargo install whoq`, or grab a prebuilt binary for macOS (Apple silicon, Intel) or Linux (x86_64, arm64, static musl) from the [releases page](https://github.com/honzabit/whoq/releases).

## Why not plain `whois`?

Classic `whois` sends a question to port 43 and prints whatever text comes back. Every registry formats it differently, and you're left to read it. `whoq` does the reading for you:

- 🧭 **Structured answers.** RDAP via IANA's bootstrap (RFC 9224), with port-43 fallback for ccTLDs without RDAP. One [versioned schema](#output) for all of them.
- 🧮 **The date math is done.** Signals like `age_days`, `expires_in_days`, `young`, `expiring_soon`, `recently_transferred`, `privacy_redacted` and `on_hold`.
- 🔗 **Forgiving input.** `www.foo.co.uk`, `https://shop.example.com/cart` or `bob@example.org` are reduced to the domain that's actually registered.
- 🚦 **Exit codes that mean something.** 0 found · 1 failed · 2 usage · 10 available or not found.
- 📦 **Batches.** Many queries from arguments or stdin, in parallel, with per-host rate limits and backoff.
- 🛡️ **Safe to print.** Registry text is cleaned of ANSI escapes, control characters and bidi overrides before it reaches your terminal (or your model).
- 🔍 **More than registration.** Optional live checks for hosting, DNS, mail security, TLS certificates and BGP routing.
- 🤖 **Built-in MCP server**, so an AI assistant can look things up too.
- ⚡ **Fast and tested.** A median lookup takes about 0.4 s, and whoq gets 91 to 97% of fields right on a [benchmark of about 275 real domains and IPs](bench/README.md), compared side by side with GNU whois and four other tools.

## A quick tour

```
whoq example.com                      # pretty output in a terminal
whoq example.com | jq .expires        # JSON lines when piped
whoq --json a.com b.com               # one JSON array
whoq -b example.com                   # brief: the key fields only, ideal for scripts and LLMs
whoq -f registrar.name,expires,signals.expires_in_days example.com
cat domains.txt | whoq -j 16 -o ndjson
```

Want to know more than who registered it? Add live checks:

```
whoq --dns example.com                # who hosts it, which DNS provider, CAA
whoq --mail example.com               # who handles its mail; SPF, DMARC, DKIM
whoq --tls https://shop.example.com   # the certificate: issuer, names, expiry, valid?
whoq --asn 8.8.8.8                    # which network announces this IP in BGP
```

And when you need control:

```
whoq --raw example.com                # include the registry's original response
whoq --whois example.de               # force classic port-43 WHOIS
whoq --max-age 1d example.com         # use a cached answer if it's under a day old
whoq --max-age 0 example.com          # always fetch fresh
whoq schema                           # the JSON Schema of the output
```

## Live checks

Registration data tells you who registered a name. Live checks tell you who runs it today.

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
```

**`--dns` and `--mail` never touch the target's own servers.** They ask your resolver (and Team Cymru for hosting), so looking into a phishing domain doesn't tip it off. `--tls` is the one exception: it has to connect to read the certificate.

### `--dns`: who hosts it

- **On a domain**, it adds `dns`: the A/AAAA records, the networks announcing them, the nameservers and a recognized DNS provider, and CAA. About 5 queries.
- **On an IP**, you get `rdns` without asking (`--no-rdns` skips it): the PTR names, and whether they're **verified** (the name resolves back to the IP). That's how you tell a real Googlebot from a fake: anyone can set a PTR that says `googlebot.com`, but only Google can make it resolve back.

  ```
  $ whoq 66.249.66.1
    …
    rDNS          crawl-66-249-66-1.googlebot.com  ✓ forward-confirmed
  ```
- New signals: `resolves`, and `parked` (the nameservers belong to a parking service).

### `--mail`: can its mail be trusted

It adds `mail`: the MX records and a recognized provider, null MX, SPF, DMARC, DKIM selectors, MTA-STS, TLS-RPT and BIMI. That's about 25 queries, most of them DKIM probes.

New signals: `accepts_mail`, and `spoofable`, which means there's no DMARC (or it's `p=none`), so mail forging the domain isn't rejected.

DKIM is best effort. Selectors can't be listed, so whoq tries about 20 common ones. An empty list doesn't mean there's no DKIM.

### `--tls`: the certificate

```
$ whoq --tls github.com
  …
  TLS           ✓ valid  github.com · TLS 1.3
  Issuer        Sectigo Limited (Sectigo Public Server Authentication CA DV E36)
  Cert expires  2027-01-27  in 73d
  Cert names    github.com, www.github.com
```

- **It checks the exact host you give it**, not the registered domain: `whoq --tls https://shop.example.com:8443/x` checks `shop.example.com` on port 8443. IPs work too.
- **Broken certificates are still described.** `valid` covers the chain (against Mozilla's roots), the dates and the host name. `problem` says what went wrong: `expired`, `self-signed`, `not valid for this name` or `issuer not trusted (…)`.
- `tls` holds the issuer, subject, names, validity dates, `expires_in_days`, protocol, key type and the leaf's SHA-256 (handy for searching CT logs). New signals: `cert_valid`, and `cert_expiring_soon` (under 14 days).
- It opens a connection to the host, which the host can log. No HTTP request is sent; it hangs up after the handshake.

### `--asn`: who routes an IP

```
$ whoq --asn 8.8.8.8
  …
  Origin AS     AS15169 GOOGLE - Google LLC (8.8.8.0/24, US)
```

It adds `origin`: the AS announcing the address in BGP, its name, the announced prefix and its country, from one Team Cymru query. This is routing data. It says whose network carries the address today, which can differ from the registered holder in `network`: `1.1.1.1` is registered to APNIC Labs but announced by Cloudflare. Private and reserved addresses are never sent out.

<details>
<summary>How live checks resolve and cache</summary>

- **Resolver:** your system's, over UDP. Many home routers can't return large TXT records, which would silently hide SPF, so failed queries are retried through 1.1.1.1. Queries your resolver hasn't answered within 0.8 s are also sent to 1.1.1.1, and the first definite answer wins. `WHOQ_DNS_SERVER=ip[:port]` pins one resolver with no fallback.
- **Speed:** queries run in parallel. Each flag typically adds under a second; `--asn` runs alongside the registry lookup and usually adds nothing.
- **Never cached:** live data is fetched on every run. `--max-age` only applies to registration data.

</details>

## Watch for changes

The most useful thing to know about a domain is when something about it changes. `whoq watch` saves a snapshot, compares it with the last run, and tells you what's different:

```
github.com  ▲ changed (high)  since 2026-11-14T18:53:16Z
  nameservers       - ns1.legit-dns.example, ns2.legit-dns.example
                    + dns1.p08.nsone.net, …
  registrar.name    Old Registrar LLC → MarkMonitor Inc.
  status            - client transfer prohibited  ← transfer lock removed
  expires           2026-01-01 → 2028-10-09  ← renewed
```

```
whoq watch mydomain.com mybrand.net          # the first run records a baseline
whoq watch -i 6h --webhook "$SLACK_URL" < domains.txt
0 */6 * * * whoq watch -q < ~/domains.txt     # cron: exits 20 when something changed
whoq watch --dns --mail --tls mydomain.com   # also watch delegation, mail and the certificate
```

Changes are ranked so the important ones stand out:

| | What changed |
|---|---|
| **High** | nameservers, registrar, transfer or creation date (a re-registration), registered ↔ available, a removed transfer lock; with live checks, nameservers, MX or certificate validity |
| **Medium** | status, DNSSEC, contacts; with live checks, the certificate issuer, hosting, CAA or DMARC policy |
| **Low** | a renewal (a later expiry date) |

It also raises **alerts**, once each, so you're not nagged: `expiring` (within `--expiry-warn`, default 30 days), `expired` and `on_hold`, plus `cert_expiring` (within `--cert-warn`, default 14 days), `cert_expired` and `cert_invalid` with `--tls`. A renewal re-arms them.

<details>
<summary>Watch details: noise control, output, state</summary>

- **Noise control:** nameserver and status lists are compared regardless of order. Timestamps and computed signals are never compared. `--ignore updated,registrant` skips fields you don't care about.
- **Live sections** are compared only when both runs have them, so turning a flag on or off isn't a change. Only fields that change on purpose are compared: hosting is compared by ASN, not address, because CDNs rotate addresses, and certificate expiry dates and fingerprints aren't diffed, so routine renewals stay quiet. A timeout keeps the last good copy; NXDOMAIN counts as a real change.
- **Output:** `baseline`, `changed`, `alert` and `error` events (plus `unchanged` with `--all`), as NDJSON when piped. `--webhook` POSTs `{text, events}`, which Slack-style webhooks accept.
- **State** lives in `~/Library/Application Support/whoq/watch` on macOS or `~/.local/share/whoq/watch` on Linux, or in `--state` / `WHOQ_STATE_DIR`. A failed lookup never overwrites a good snapshot. `shop.example.com` and `example.com` are watched separately.
- **Exit codes:** 0 nothing changed · 1 lookups failed · 20 changes or alerts.

</details>

## Label every IP in a log

`whoq bulk` reads a log and tells you who owns every IP in it. It finds IPs anywhere in a line (IPv6, `ip:port`, `[v6]:port`, IPv4-mapped addresses, `X-Forwarded-For` lists), or only in one column with `--column`.

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
whoq bulk -c 1 -o tsv access.log > enriched.tsv            # each line + ip, asn, as_name, cc, prefix, org
whoq bulk -m unique --rdap -o csv fw.log > owners.csv      # one row per IP, with org and abuse contact
zcat auth.log.gz | whoq bulk | jq -c 'select(any(.ips[]; .asn == 14061))'
whoq bulk -c 1 -w 2 -m summary counts.tsv                  # pre-counted "ip<TAB>count" input
whoq bulk -m unique --dns -o csv access.log                # + ptr, ptr_verified: which "Googlebots" are real
```

Modes: `annotate` (the default; NDJSON or `-o tsv`), `unique` and `summary` (NDJSON, CSV or a table; `--top N`).

> **Privacy:** public IPs from your logs are sent to Team Cymru and, with `--rdap`, to the regional registries. Use `--no-cymru` to talk only to the registries. Private and reserved addresses never leave your machine.

<details>
<summary>How it handles 20,000 lines in a few seconds</summary>

It looks up networks, not individual IPs:

- **Team Cymru's bulk whois** (the default) answers up to 1,000 IPs per connection with ASN, AS name, BGP prefix, country and RIR.
- **`--rdap`** adds the registry's org, network name and abuse contact. Each answer is cached under its CIDR and reused for every IP inside it: in testing, 2,269 IPs needed 71 RDAP requests. `--precise` limits reuse to the /24 (/48) when sub-allocations matter.
- **A persistent network cache** (`--max-age`, default `7d`) makes repeat runs mostly offline: the same 20k lines took 0.0 s the second time.
- **Streaming in chunks of 5,000 lines** keeps memory flat. Output keeps line order and stops cleanly when piped to `head`.
- **`--dns`** costs one or two DNS queries per unique public IP, 32 at a time, and isn't cached.

</details>

## Use it from an AI assistant (MCP)

whoq has a built-in [MCP](https://modelcontextprotocol.io) server. For Claude Code:

```
claude mcp add whoq -- whoq mcp
```

Or in any MCP client's config:

```json
{ "mcpServers": { "whoq": { "command": "whoq", "args": ["mcp"] } } }
```

Three read-only tools:

- **`lookup`**: domains, IPs and ASNs. Options: `fields`, `brief`, `max_age` (`"6h"`, or `0` for fresh), and the live checks `dns`, `mail`, `tls` and `asn`.
- **`check_availability`**: is this domain taken?
- **`enrich_ips`**: up to 1,000 IPs or log fragments at once, with `rdap`, `summary` and `dns` options.

Registry data is written by whoever registered the name, so it can contain anything. whoq wraps every answer in `<untrusted-registry-data>`, and the tool descriptions remind the model that it's data, not instructions.

## Output

Run `whoq schema` for the full JSON Schema. A few things worth knowing:

- In a terminal you get the pretty view; piped, you get one JSON object per line. `--json` gives an array, and `-o` picks `pretty`, `json` or `ndjson` yourself.
- `--brief` (`-b`) keeps only the fields most people want, which saves tokens for LLMs.
- `source` says where the answer came from, whether it was `cached`, and when it was `fetched_at`.

## Configuration

Answers are cached on disk for an hour (bootstrap data for a day), in `~/Library/Caches/whoq` on macOS or `~/.cache/whoq` on Linux. If IANA is unreachable, whoq keeps working from its last copy.

- `--max-age` takes `90s`, `30m`, `6h`, `2d`, `1w` or plain seconds (default `1h`). `--no-cache` skips reading and writing.
- `--timeout` is seconds per request (default 15).
- These flags mean the same thing in lookups, `bulk` and `mcp`.

<details>
<summary>Environment variables</summary>

| Variable | Does |
|---|---|
| `WHOQ_CACHE_DIR` | where the cache lives |
| `WHOQ_STATE_DIR` | where `watch` keeps snapshots |
| `WHOQ_TIMEOUT` | default `--timeout` |
| `WHOQ_MAX_AGE` | default `--max-age` |
| `WHOQ_DNS_SERVER=ip[:port]` | use one DNS resolver, with no fallback |
| `WHOQ_TLS_CA=file.pem` | trust only these roots for `--tls` |
| `WHOQ_WEBHOOK` | default `--webhook` for `watch` |
| `WHOQ_WHOIS_ADDR=host:port` | send every port-43 connection through one address (proxies, tests) |
| `NO_COLOR` | turn off colors |

</details>

## Good to know

- **"Available"** means the registry has no record of the domain. Premium or reserved names can still be unregistrable.
- **Classic WHOIS text is parsed heuristically.** If a ccTLD's answer looks wrong, `--raw` shows what the registry sent.
- **Provider names** (`dns.provider`, `mail.provider`) come from a built-in list. Unknown providers are left blank, but the raw hostnames are always there.

## Development

```
cargo build --release      # target/release/whoq
cargo test                 # unit tests + offline end-to-end tests
cargo clippy --all-targets && cargo fmt --check
```

The end-to-end tests in `tests/cli.rs` run the real binary against local fake RDAP and port-43 servers with synthetic fixtures from `tests/fixtures/`, so they need no network. Accuracy and speed against other WHOIS tools are tracked in [bench/](bench/README.md).

## License

MIT. See [LICENSE](LICENSE).
