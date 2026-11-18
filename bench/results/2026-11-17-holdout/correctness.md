# Correctness and coverage — run 2026-11-17-holdout

Answer key built 2026-11-17T04:23:54Z; 42 queries. **in output** = the right answer appears anywhere in the tool's output; **as field** = the tool's own named field holds it (tools that emit fields only). Fields the authority does not publish are not scored.

## Summary

| Tool | Version | In output | As field | Empty output | Median s |
|---|---|---|---|---|---|
| whoq | whoq 0.1.1 | 96% (143/149) | 96% (143/149) | 0 | 0.55 |
| whoq-brief | whoq 0.1.1 | 93% (139/149) | 93% (139/149) | 0 | 0.55 |
| whois-gnu | Version 5.6.6. | 93% (138/149) | n/a | 0 | 0.18 |
| whois-macos | unknown | 90% (134/149) | n/a | 0 | 0.57 |
| openrdap | unknown | 1% (2/149) | n/a | 42 | 0.01 |
| python-whois | 0.9.6 | 83% (124/149) | 79% (118/149) | 5 | 0.62 |
| whoisit | 4.1.0 | 1% (2/149) | 0% (0/149) | 42 | 0.26 |
| ipwhois | 1.3.0 | – | – | 0 | 0.00 |

## By category — in output

| | whoq | whoq-brief | whois-gnu | whois-macos | openrdap | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|---|---|---|
| holdout-unregistered | 40% (4/10) | 40% (4/10) | 80% (8/10) | 80% (8/10) | 0% (0/10) | 90% (9/10) | 0% (0/10) | – |
| holdout-whois-only | 100% (139/139) | 97% (135/139) | 94% (130/139) | 91% (126/139) | 1% (2/139) | 83% (115/139) | 1% (2/139) | – |

## By category — as field

| | whoq | whoq-brief | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|
| holdout-unregistered | 40% (4/10) | 40% (4/10) | 60% (6/10) | 0% (0/10) | – |
| holdout-whois-only | 100% (139/139) | 97% (135/139) | 81% (112/139) | 0% (0/139) | – |

## By field — in output

| | whoq | whoq-brief | whois-gnu | whois-macos | openrdap | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|---|---|---|
| status | 86% (36/42) | 83% (35/42) | 93% (39/42) | 90% (38/42) | 2% (1/42) | 90% (38/42) | 2% (1/42) | – |
| registrar | 100% (23/23) | 100% (23/23) | 96% (22/23) | 96% (22/23) | 4% (1/23) | 74% (17/23) | 4% (1/23) | – |
| created | 100% (30/30) | 97% (29/30) | 90% (27/30) | 87% (26/30) | 0% (0/30) | 83% (25/30) | 0% (0/30) | – |
| expires | 100% (23/23) | 96% (22/23) | 87% (20/23) | 83% (19/23) | 0% (0/23) | 83% (19/23) | 0% (0/23) | – |
| nameservers | 100% (31/31) | 97% (30/31) | 97% (30/31) | 94% (29/31) | 0% (0/31) | 81% (25/31) | 0% (0/31) | – |

## By field — as field

| | whoq | whoq-brief | python-whois | whoisit | ipwhois |
|---|---|---|---|---|---|
| status | 86% (36/42) | 83% (35/42) | 83% (35/42) | 0% (0/42) | – |
| registrar | 100% (23/23) | 100% (23/23) | 74% (17/23) | 0% (0/23) | – |
| created | 100% (30/30) | 97% (29/30) | 83% (25/30) | 0% (0/30) | – |
| expires | 100% (23/23) | 96% (22/23) | 83% (19/23) | 0% (0/23) | – |
| nameservers | 100% (31/31) | 97% (30/31) | 71% (22/31) | 0% (0/31) | – |

## whoq misses (as field)

| Query | Field | Answer key | whoq |
|---|---|---|---|
| whoq-holdout-r8p3w6n2.it | status | "available" | "registered" |
| whoq-holdout-r8p3w6n2.be | status | "available" | "registered" |
| whoq-holdout-r8p3w6n2.hk | status | "available" | "registered" |
| whoq-holdout-r8p3w6n2.com.tr | status | "available" | "registered" |
| whoq-holdout-r8p3w6n2.co.il | status | "available" | "registered" |
| whoq-holdout-r8p3w6n2.at | status | "available" | "registered" |
