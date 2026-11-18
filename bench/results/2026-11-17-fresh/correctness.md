# Correctness and coverage — run 2026-11-17-fresh

Answer key built 2026-11-17T04:28:09Z; 40 queries. **in output** = the right answer appears anywhere in the tool's output; **as field** = the tool's own named field holds it (tools that emit fields only). Fields the authority does not publish are not scored.

## Summary

| Tool | Version | In output | As field | Empty output | Median s |
|---|---|---|---|---|---|
| whoq | whoq 0.1.1 | 89% (92/103) | 89% (92/103) | 0 | 0.48 |
| whoq-brief | whoq 0.1.1 | 89% (92/103) | 89% (92/103) | 0 | 0.44 |
| whois-gnu | Version 5.6.6. | 97% (100/103) | n/a | 0 | 0.20 |
| whois-macos | unknown | 94% (97/103) | n/a | 0 | 0.48 |
| openrdap | unknown | 21% (22/103) | n/a | 36 | 0.01 |
| python-whois | 0.9.6 | 81% (83/103) | 79% (81/103) | 4 | 0.62 |
| whoisit | 4.1.0 | 18% (19/103) | 15% (15/103) | 34 | 0.26 |
| ipwhois | 1.3.0 | – | – | 0 | 0.00 |

## By category — in output

| | whoq | whoq-brief | whois-gnu | whois-macos | openrdap | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|---|---|---|
| fresh-rdap | 100% (17/17) | 100% (17/17) | 100% (17/17) | 100% (17/17) | 100% (17/17) | 94% (16/17) | 82% (14/17) | – |
| fresh-unregistered | 75% (15/20) | 75% (15/20) | 85% (17/20) | 85% (17/20) | 15% (3/20) | 90% (18/20) | 15% (3/20) | – |
| fresh-whois-only | 91% (60/66) | 91% (60/66) | 100% (66/66) | 95% (63/66) | 3% (2/66) | 74% (49/66) | 3% (2/66) | – |

## By category — as field

| | whoq | whoq-brief | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|
| fresh-rdap | 100% (17/17) | 100% (17/17) | 94% (16/17) | 71% (12/17) | – |
| fresh-unregistered | 75% (15/20) | 75% (15/20) | 75% (15/20) | 15% (3/20) | – |
| fresh-whois-only | 91% (60/66) | 91% (60/66) | 76% (50/66) | 0% (0/66) | – |

## By field — in output

| | whoq | whoq-brief | whois-gnu | whois-macos | openrdap | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|---|---|---|
| status | 85% (34/40) | 85% (34/40) | 92% (37/40) | 92% (37/40) | 20% (8/40) | 88% (35/40) | 20% (8/40) | – |
| registrar | 79% (11/14) | 79% (11/14) | 100% (14/14) | 100% (14/14) | 21% (3/14) | 64% (9/14) | 14% (2/14) | – |
| created | 94% (16/17) | 94% (16/17) | 100% (17/17) | 94% (16/17) | 24% (4/17) | 82% (14/17) | 18% (3/17) | – |
| expires | 100% (13/13) | 100% (13/13) | 100% (13/13) | 92% (12/13) | 23% (3/13) | 77% (10/13) | 15% (2/13) | – |
| nameservers | 95% (18/19) | 95% (18/19) | 100% (19/19) | 95% (18/19) | 21% (4/19) | 79% (15/19) | 21% (4/19) | – |

## By field — as field

| | whoq | whoq-brief | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|
| status | 85% (34/40) | 85% (34/40) | 82% (33/40) | 15% (6/40) | – |
| registrar | 79% (11/14) | 79% (11/14) | 64% (9/14) | 7% (1/14) | – |
| created | 94% (16/17) | 94% (16/17) | 82% (14/17) | 18% (3/17) | – |
| expires | 100% (13/13) | 100% (13/13) | 77% (10/13) | 15% (2/13) | – |
| nameservers | 95% (18/19) | 95% (18/19) | 79% (15/19) | 16% (3/19) | – |

## whoq misses (as field)

| Query | Field | Answer key | whoq |
|---|---|---|---|
| sme.sk | registrar | "Petit Printing Press, a.s., organizačná zložka" | "PPRP-0001" |
| dnevnik.bg | status | "registered" | "error" |
| dnevnik.bg | nameservers | ["curt.ns.cloudflare.com", "sneh.ns.cloudflare.com"] | null |
| rtl.lu | registrar | "EuroDNS SA" | null |
| tengrinews.kz | registrar | "ICPS" | null |
| tengrinews.kz | created | "2010-09-14" | null |
| whoq-fresh-k4t9z1q7.pt | status | "available" | "error" |
| whoq-fresh-k4t9z1q7.com.mx | status | "available" | "error" |
| whoq-fresh-k4t9z1q7.hu | status | "available" | "error" |
| whoq-fresh-k4t9z1q7.bg | status | "available" | "error" |
| whoq-fresh-k4t9z1q7.lu | status | "available" | "error" |
