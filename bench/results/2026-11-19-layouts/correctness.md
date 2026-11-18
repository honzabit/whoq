# Correctness and coverage — run 2026-11-19-layouts

Answer key built 2026-11-17T18:11:48Z; 275 queries. **in output** = the right answer appears anywhere in the tool's output; **as field** = the tool's own named field holds it (tools that emit fields only). Fields the authority does not publish are not scored.

## Summary

| Tool | Version | In output | As field | Empty output | Median s |
|---|---|---|---|---|---|
| whoq | whoq 0.1.4 | 98% (1856/1900) | 98% (1856/1900) | 0 | 0.40 |

## By category — in output

| | whoq |
|---|---|
| cctld-rdap | 100% (204/204) |
| cctld-whois-only | 92% (196/214) |
| fresh-rdap | 100% (34/34) |
| fresh-unregistered | 95% (38/40) |
| fresh-whois-only | 94% (124/132) |
| fresh2-unregistered | 96% (46/48) |
| fresh2-whois-only | 97% (190/196) |
| gtld | 100% (200/200) |
| holdout-unregistered | 100% (20/20) |
| holdout-whois-only | 97% (270/278) |
| idn | 100% (18/18) |
| ngtld | 100% (148/148) |
| subdomain | 100% (44/44) |
| unregistered | 100% (20/20) |
| ipv4-afrinic | 100% (32/32) |
| ipv4-apnic | 100% (58/58) |
| ipv4-arin | 100% (60/60) |
| ipv4-lacnic | 100% (36/36) |
| ipv4-ripe | 100% (76/76) |
| ipv6-afrinic | 100% (8/8) |
| ipv6-apnic | 100% (6/6) |
| ipv6-arin | 100% (12/12) |
| ipv6-lacnic | 100% (8/8) |
| ipv6-ripe | 100% (8/8) |

## By category — as field

| | whoq |
|---|---|
| cctld-rdap | 100% (204/204) |
| cctld-whois-only | 92% (196/214) |
| fresh-rdap | 100% (34/34) |
| fresh-unregistered | 95% (38/40) |
| fresh-whois-only | 94% (124/132) |
| fresh2-unregistered | 96% (46/48) |
| fresh2-whois-only | 97% (190/196) |
| gtld | 100% (200/200) |
| holdout-unregistered | 100% (20/20) |
| holdout-whois-only | 97% (270/278) |
| idn | 100% (18/18) |
| ngtld | 100% (148/148) |
| subdomain | 100% (44/44) |
| unregistered | 100% (20/20) |
| ipv4-afrinic | 100% (32/32) |
| ipv4-apnic | 100% (58/58) |
| ipv4-arin | 100% (60/60) |
| ipv4-lacnic | 100% (36/36) |
| ipv4-ripe | 100% (76/76) |
| ipv6-afrinic | 100% (8/8) |
| ipv6-apnic | 100% (6/6) |
| ipv6-arin | 100% (12/12) |
| ipv6-lacnic | 100% (8/8) |
| ipv6-ripe | 100% (8/8) |

## By field — in output

| | whoq |
|---|---|
| status | 97% (444/458) |
| registrar | 98% (258/262) |
| created | 97% (288/296) |
| expires | 97% (248/256) |
| nameservers | 97% (314/324) |
| org | 100% (56/56) |
| cidr | 100% (92/92) |
| country | 100% (64/64) |
| asn | 100% (92/92) |

## By field — as field

| | whoq |
|---|---|
| status | 97% (444/458) |
| registrar | 98% (258/262) |
| created | 97% (288/296) |
| expires | 97% (248/256) |
| nameservers | 97% (314/324) |
| org | 100% (56/56) |
| cidr | 100% (92/92) |
| country | 100% (64/64) |
| asn | 100% (92/92) |

## whoq misses (as field)

| Query | Field | Answer key | whoq |
|---|---|---|---|
| emol.cl | status | "registered" | "error" |
| emol.cl | registrar | "NIC Chile" | null |
| emol.cl | created | "2002-11-12" | null |
| emol.cl | expires | "2026-12-10" | null |
| emol.cl | nameservers | ["aragorn.ns.cloudflare.com", "rose.ns.cloudflare.com"] | null |
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
| google.qa | status | "registered" | "error" |
| google.qa | registrar | "RoutEdge" | null |
| google.qa | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| whoq-fresh2-m5x8c3v6.ws | status | "available" | "error" |
| emol.cl | status | "registered" | "error" |
| emol.cl | registrar | "NIC Chile" | null |
| emol.cl | created | "2002-11-12" | null |
| emol.cl | expires | "2026-12-10" | null |
| emol.cl | nameservers | ["aragorn.ns.cloudflare.com", "rose.ns.cloudflare.com"] | null |
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
| google.qa | status | "registered" | "error" |
| google.qa | registrar | "RoutEdge" | null |
| google.qa | nameservers | ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"] | null |
| whoq-fresh2-m5x8c3v6.ws | status | "available" | "error" |
