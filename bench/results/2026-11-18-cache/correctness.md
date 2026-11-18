# Correctness and coverage — run 2026-11-18-cache

Answer key built 2026-11-17T18:11:48Z; 275 queries. **in output** = the right answer appears anywhere in the tool's output; **as field** = the tool's own named field holds it (tools that emit fields only). Fields the authority does not publish are not scored.

## Summary

| Tool | Version | In output | As field | Empty output | Median s |
|---|---|---|---|---|---|
| whoq | whoq 0.1.1 | 93% (884/950) | 93% (881/950) | 0 | 0.41 |

## By category — in output

| | whoq |
|---|---|
| cctld-rdap | 95% (97/102) |
| cctld-whois-only | 96% (103/107) |
| fresh-rdap | 100% (17/17) |
| fresh-unregistered | 95% (19/20) |
| fresh-whois-only | 92% (61/66) |
| fresh2-unregistered | 100% (24/24) |
| fresh2-whois-only | 96% (94/98) |
| gtld | 100% (100/100) |
| holdout-unregistered | 100% (10/10) |
| holdout-whois-only | 97% (135/139) |
| idn | 100% (9/9) |
| ngtld | 100% (74/74) |
| subdomain | 100% (22/22) |
| unregistered | 100% (10/10) |
| ipv4-afrinic | 75% (12/16) |
| ipv4-apnic | 76% (22/29) |
| ipv4-arin | 67% (20/30) |
| ipv4-lacnic | 72% (13/18) |
| ipv4-ripe | 71% (27/38) |
| ipv6-afrinic | 75% (3/4) |
| ipv6-apnic | 67% (2/3) |
| ipv6-arin | 67% (4/6) |
| ipv6-lacnic | 75% (3/4) |
| ipv6-ripe | 75% (3/4) |

## By category — as field

| | whoq |
|---|---|
| cctld-rdap | 95% (97/102) |
| cctld-whois-only | 96% (103/107) |
| fresh-rdap | 100% (17/17) |
| fresh-unregistered | 95% (19/20) |
| fresh-whois-only | 92% (61/66) |
| fresh2-unregistered | 100% (24/24) |
| fresh2-whois-only | 96% (94/98) |
| gtld | 100% (100/100) |
| holdout-unregistered | 100% (10/10) |
| holdout-whois-only | 97% (135/139) |
| idn | 100% (9/9) |
| ngtld | 100% (74/74) |
| subdomain | 100% (22/22) |
| unregistered | 100% (10/10) |
| ipv4-afrinic | 69% (11/16) |
| ipv4-apnic | 69% (20/29) |
| ipv4-arin | 67% (20/30) |
| ipv4-lacnic | 72% (13/18) |
| ipv4-ripe | 71% (27/38) |
| ipv6-afrinic | 75% (3/4) |
| ipv6-apnic | 67% (2/3) |
| ipv6-arin | 67% (4/6) |
| ipv6-lacnic | 75% (3/4) |
| ipv6-ripe | 75% (3/4) |

## By field — in output

| | whoq |
|---|---|
| status | 98% (224/229) |
| registrar | 98% (129/131) |
| created | 96% (142/148) |
| expires | 97% (124/128) |
| nameservers | 96% (156/162) |
| org | 100% (28/28) |
| cidr | 100% (46/46) |
| country | 100% (32/32) |
| asn | 7% (3/46) |

## By field — as field

| | whoq |
|---|---|
| status | 98% (224/229) |
| registrar | 98% (129/131) |
| created | 96% (142/148) |
| expires | 97% (124/128) |
| nameservers | 96% (156/162) |
| org | 100% (28/28) |
| cidr | 100% (46/46) |
| country | 100% (32/32) |
| asn | 0% (0/46) |

## whoq misses (as field)

| Query | Field | Answer key | whoq |
|---|---|---|---|
| sapo.pt | status | "registered" | "error" |
| sapo.pt | created | "2002-10-30" | null |
| sapo.pt | expires | "2027-11-02" | null |
| sapo.pt | nameservers | ["dns01.sapo.pt", "dns02.sapo.pt", "ns.sapo.pt", "ns2.sapo.pt"] | null |
| gov.sg | status | "registered" | "error" |
| gov.sg | registrar | "SGNIC" | null |
| gov.sg | created | "2024-02-29" | null |
| gov.sg | expires | "3000-01-01" | null |
| gov.sg | nameservers | ["dsany2.sgnic.sg", "dsany3.sgnic.sg", "dsany4.sgnic.sg", "pch.sgzones.sg"] | null |
| publico.pt | status | "registered" | "error" |
| publico.pt | created | "1995-05-11" | null |
| publico.pt | expires | "2027-11-02" | null |
| publico.pt | nameservers | ["ns-112.awsdns-14.com", "ns-1381.awsdns-44.org", "ns-1801.awsdns-33.co.uk", "ns-861.awsdns-43.net"] | null |
| rtp.pt | status | "registered" | "error" |
| rtp.pt | created | "1993-05-28" | null |
| rtp.pt | expires | "2027-11-02" | null |
| rtp.pt | nameservers | ["ns1.ptempresas.pt", "ns10.ptempresas.pt", "ns2.ptempresas.pt"] | null |
| sme.sk | registrar | "Petit Printing Press, a.s., organizačná zložka" | "PPRP-0001" |
| whoq-fresh-k4t9z1q7.pt | status | "available" | "error" |
| google.am | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| google.gg | created | "2003-04-30" | null |
| google.im | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| google.je | created | "2002-10-31" | null |
| 8.8.8.8 | asn | [15169] | null |
| 9.9.9.9 | asn | [19281] | null |
| 208.67.222.222 | asn | [36692] | null |
| 4.2.2.2 | asn | [3356] | null |
| 17.253.144.10 | asn | [714] | null |
| 140.82.112.3 | asn | [36459] | null |
| 151.101.1.140 | asn | [54113] | null |
| 13.107.42.14 | asn | [8068] | null |
| 52.95.110.1 | asn | [16509] | null |
| 104.16.132.229 | asn | [13335] | null |
| 193.0.6.139 | asn | [3333] | null |
| 77.88.8.8 | asn | [13238, 208398] | null |
| 141.1.1.1 | asn | [1273] | null |
| 2.16.0.1 | asn | [20940] | null |
| 46.4.0.1 | asn | [24940] | null |
| 31.13.64.35 | asn | [32934] | null |
| 5.255.255.5 | asn | [13238, 208398] | null |
| 185.199.108.153 | asn | [54113] | null |
| 80.80.80.80 | asn | [61005] | null |
| 212.58.244.20 | asn | [2818] | null |
| 1.1.1.1 | asn | [13335] | null |
| 101.6.6.6 | asn | [4538] | null |
| 114.114.114.114 | asn | [21859, 137702] | null |
| 223.5.5.5 | asn | [45102] | null |
| 202.12.27.33 | asn | [7500] | null |
| 203.119.95.53 | asn | [18369] | null |
| 180.76.76.76 | asn | [38365, 55967] | null |
| 210.130.0.1 | asn | [2497] | null |
| 61.135.169.121 | asn | [4808] | null |
| 139.130.4.5 | asn | [1221] | null |
| 200.160.2.3 | asn | [22548] | null |
| 200.160.0.8 | asn | [22548] | null |
| 200.221.11.100 | asn | [7162] | null |
| 200.40.30.245 | asn | [6057] | null |
| 190.104.1.1 | asn | [27882] | null |
| 196.216.2.1 | asn | [33764] | null |
| 41.203.18.1 | asn | [37153] | null |
| 197.234.240.1 | asn | [13335] | null |
| 105.235.237.1 | asn | [37487] | null |
| 41.0.0.1 | asn | [36994] | null |
| 2001:4860:4860::8888 | asn | [15169] | null |
| 2606:4700:4700::1111 | asn | [13335] | null |
| 2001:67c:2e8:22::c100:68b | asn | [3333] | null |
| 2001:dc3::35 | asn | [7500] | null |
| 2001:12ff:0:4::22 | asn | [22548] | null |
| 2001:43f8:110::10 | asn | [37181] | null |
