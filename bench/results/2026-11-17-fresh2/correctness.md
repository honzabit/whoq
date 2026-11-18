# Correctness and coverage — run 2026-11-17-fresh2

Answer key built 2026-11-17T18:11:48Z; 48 queries. **in output** = the right answer appears anywhere in the tool's output; **as field** = the tool's own named field holds it (tools that emit fields only). Fields the authority does not publish are not scored.

## Summary

| Tool | Version | In output | As field | Empty output | Median s |
|---|---|---|---|---|---|
| whoq | whoq 0.1.1 | 89% (109/122) | 89% (109/122) | 0 | 0.65 |
| whois-gnu | Version 5.6.6. | 93% (113/122) | n/a | 1 | 0.27 |
| python-whois | 0.9.6 | 70% (86/122) | 71% (87/122) | 1 | 0.64 |
| whoisit | 4.1.0 | 0% (0/122) | 0% (0/122) | 48 | 0.27 |

## By category — in output

| | whoq | whois-gnu | python-whois | whoisit |
|---|---|---|---|---|
| fresh2-unregistered | 92% (22/24) | 96% (23/24) | 92% (22/24) | 0% (0/24) |
| fresh2-whois-only | 89% (87/98) | 92% (90/98) | 65% (64/98) | 0% (0/98) |

## By category — as field

| | whoq | python-whois | whoisit |
|---|---|---|---|
| fresh2-unregistered | 92% (22/24) | 88% (21/24) | 0% (0/24) |
| fresh2-whois-only | 89% (87/98) | 67% (66/98) | 0% (0/98) |

## By field — in output

| | whoq | whois-gnu | python-whois | whoisit |
|---|---|---|---|---|
| status | 92% (44/48) | 96% (46/48) | 83% (40/48) | 0% (0/48) |
| registrar | 94% (17/18) | 94% (17/18) | 83% (15/18) | 0% (0/18) |
| created | 82% (14/17) | 76% (13/17) | 53% (9/17) | 0% (0/17) |
| expires | 93% (14/15) | 93% (14/15) | 60% (9/15) | 0% (0/15) |
| nameservers | 83% (20/24) | 96% (23/24) | 54% (13/24) | 0% (0/24) |

## By field — as field

| | whoq | python-whois | whoisit |
|---|---|---|---|
| status | 92% (44/48) | 88% (42/48) | 0% (0/48) |
| registrar | 94% (17/18) | 83% (15/18) | 0% (0/18) |
| created | 82% (14/17) | 53% (9/17) | 0% (0/17) |
| expires | 93% (14/15) | 60% (9/15) | 0% (0/15) |
| nameservers | 83% (20/24) | 50% (12/24) | 0% (0/24) |

## whoq misses (as field)

| Query | Field | Answer key | whoq |
|---|---|---|---|
| google.am | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| google.gg | created | "2003-04-30" | null |
| google.im | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| google.je | created | "2002-10-31" | null |
| google.sa | status | "registered" | "error" |
| google.sa | nameservers | ["ns1.markmonitor.com", "ns3.markmonitor.com"] | null |
| google.ws | status | "registered" | "error" |
| google.ws | registrar | "MarkMonitor Inc." | null |
| google.ws | created | "2002-03-03" | null |
| google.ws | expires | "2027-03-04" | null |
| google.ws | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| whoq-fresh2-m5x8c3v6.sa | status | "available" | "error" |
| whoq-fresh2-m5x8c3v6.ws | status | "available" | "error" |
