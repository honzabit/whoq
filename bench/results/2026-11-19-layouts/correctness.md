# Correctness and coverage — run 2026-11-19-layouts

Answer key built 2026-11-17T18:11:48Z; 275 queries. **in output** = the right answer appears anywhere in the tool's output; **as field** = the tool's own named field holds it (tools that emit fields only). Fields the authority does not publish are not scored.

## Summary

| Tool | Version | In output | As field | Empty output | Median s |
|---|---|---|---|---|---|
| whoq | whoq 0.1.4 | 98% (931/950) | 98% (931/950) | 0 | 0.35 |

## By category — in output

| | whoq |
|---|---|
| cctld-rdap | 100% (102/102) |
| cctld-whois-only | 96% (103/107) |
| fresh-rdap | 100% (17/17) |
| fresh-unregistered | 95% (19/20) |
| fresh-whois-only | 94% (62/66) |
| fresh2-unregistered | 96% (23/24) |
| fresh2-whois-only | 95% (93/98) |
| gtld | 100% (100/100) |
| holdout-unregistered | 100% (10/10) |
| holdout-whois-only | 97% (135/139) |
| idn | 100% (9/9) |
| ngtld | 100% (74/74) |
| subdomain | 100% (22/22) |
| unregistered | 100% (10/10) |
| ipv4-afrinic | 100% (16/16) |
| ipv4-apnic | 100% (29/29) |
| ipv4-arin | 100% (30/30) |
| ipv4-lacnic | 100% (18/18) |
| ipv4-ripe | 100% (38/38) |
| ipv6-afrinic | 100% (4/4) |
| ipv6-apnic | 100% (3/3) |
| ipv6-arin | 100% (6/6) |
| ipv6-lacnic | 100% (4/4) |
| ipv6-ripe | 100% (4/4) |

## By category — as field

| | whoq |
|---|---|
| cctld-rdap | 100% (102/102) |
| cctld-whois-only | 96% (103/107) |
| fresh-rdap | 100% (17/17) |
| fresh-unregistered | 95% (19/20) |
| fresh-whois-only | 94% (62/66) |
| fresh2-unregistered | 96% (23/24) |
| fresh2-whois-only | 95% (93/98) |
| gtld | 100% (100/100) |
| holdout-unregistered | 100% (10/10) |
| holdout-whois-only | 97% (135/139) |
| idn | 100% (9/9) |
| ngtld | 100% (74/74) |
| subdomain | 100% (22/22) |
| unregistered | 100% (10/10) |
| ipv4-afrinic | 100% (16/16) |
| ipv4-apnic | 100% (29/29) |
| ipv4-arin | 100% (30/30) |
| ipv4-lacnic | 100% (18/18) |
| ipv4-ripe | 100% (38/38) |
| ipv6-afrinic | 100% (4/4) |
| ipv6-apnic | 100% (3/3) |
| ipv6-arin | 100% (6/6) |
| ipv6-lacnic | 100% (4/4) |
| ipv6-ripe | 100% (4/4) |

## By field — in output

| | whoq |
|---|---|
| status | 97% (223/229) |
| registrar | 99% (130/131) |
| created | 97% (144/148) |
| expires | 97% (124/128) |
| nameservers | 98% (158/162) |
| org | 100% (28/28) |
| cidr | 100% (46/46) |
| country | 100% (32/32) |
| asn | 100% (46/46) |

## By field — as field

| | whoq |
|---|---|
| status | 97% (223/229) |
| registrar | 99% (130/131) |
| created | 97% (144/148) |
| expires | 97% (124/128) |
| nameservers | 98% (158/162) |
| org | 100% (28/28) |
| cidr | 100% (46/46) |
| country | 100% (32/32) |
| asn | 100% (46/46) |

## whoq misses (as field)

| Query | Field | Answer key | whoq |
|---|---|---|---|
| sapo.pt | status | "registered" | "error" |
| sapo.pt | created | "2002-10-30" | null |
| sapo.pt | expires | "2027-11-02" | null |
| sapo.pt | nameservers | ["dns01.sapo.pt", "dns02.sapo.pt", "ns.sapo.pt", "ns2.sapo.pt"] | null |
| publico.pt | status | "registered" | "error" |
| publico.pt | created | "1995-05-11" | null |
| publico.pt | expires | "2027-11-02" | null |
| publico.pt | nameservers | ["ns-112.awsdns-14.com", "ns-1381.awsdns-44.org", "ns-1801.awsdns-33.co.uk", "ns-861.awsdns-43.net"] | null |
| rtp.pt | status | "registered" | "error" |
| rtp.pt | created | "1993-05-28" | null |
| rtp.pt | expires | "2027-11-02" | null |
| rtp.pt | nameservers | ["ns1.ptempresas.pt", "ns10.ptempresas.pt", "ns2.ptempresas.pt"] | null |
| whoq-fresh-k4t9z1q7.pt | status | "available" | "error" |
| google.ws | status | "registered" | "error" |
| google.ws | registrar | "MarkMonitor Inc." | null |
| google.ws | created | "2002-03-03" | null |
| google.ws | expires | "2027-03-04" | null |
| google.ws | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| whoq-fresh2-m5x8c3v6.ws | status | "available" | "error" |
