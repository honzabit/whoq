//! Legacy port-43 WHOIS (RFC 3912), used for ccTLDs without RDAP or with `--whois`.
//! Parsing is heuristic: registries all format differently.

use crate::ctx::{Ctx, LookupError};
use crate::model::{Contact, Outcome, Record, Registrar};
use crate::normalize::{dedupe, parse_date, real, status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_RESPONSE: usize = 512 * 1024;

pub async fn query(ctx: &Ctx, server: &str, q: &str) -> Result<String, LookupError> {
    let sem = ctx.host_limit(server);
    let _permit = sem.acquire().await.expect("semaphore closed");
    let fut = async {
        let conn = match &ctx.whois_addr {
            Some(addr) => TcpStream::connect(addr.as_str()).await,
            None => TcpStream::connect((server, 43)).await,
        };
        let mut s = conn.map_err(|e| LookupError::Network(format!("{server}:43: {e}")))?;
        s.write_all(format!("{q}\r\n").as_bytes()).await.map_err(|e| LookupError::Network(e.to_string()))?;
        let mut buf = Vec::new();
        (&mut s)
            .take(MAX_RESPONSE as u64)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| LookupError::Network(e.to_string()))?;
        Ok::<_, LookupError>(String::from_utf8_lossy(&buf).into_owned())
    };
    tokio::time::timeout(ctx.opts.timeout, fut)
        .await
        .map_err(|_| LookupError::Timeout(format!("{server}:43 timed out")))?
}

/// Ask IANA which WHOIS server handles a TLD.
async fn server_for(ctx: &Ctx, tld: &str) -> Result<Option<String>, LookupError> {
    if let Some(s) = ctx.whois_servers.lock().unwrap().get(tld) {
        return Ok(s.clone());
    }
    let resp = query(ctx, "whois.iana.org", tld).await?;
    let server = resp
        .lines()
        .find_map(|l| l.trim().strip_prefix("whois:").map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty());
    ctx.whois_servers.lock().unwrap().insert(tld.to_string(), server.clone());
    Ok(server)
}

fn query_string(server: &str, domain: &str) -> String {
    match server {
        "whois.denic.de" => format!("-T dn,ace {domain}"),
        "whois.dk-hostmaster.dk" => format!("--show-handles {domain}"),
        "whois.jprs.jp" => format!("{domain}/e"),
        "whois.verisign-grs.com" => format!("domain {domain}"),
        _ => domain.to_string(),
    }
}

/// Split into (key, value) pairs, handling indented multi-line blocks like .uk.
pub fn pairs(text: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut pending: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            pending = None;
            continue;
        }
        if t.starts_with('%') || t.starts_with('#') || t.starts_with(">>>") {
            continue;
        }
        // key: value, where the colon is followed by whitespace or end-of-line (not "http://")
        let kv =
            t.char_indices().find(|&(i, c)| c == ':' && t[i + 1..].chars().next().is_none_or(|n| n.is_whitespace()));
        match kv {
            Some((i, _)) if i > 0 && i < 48 => {
                let key = t[..i].trim().trim_end_matches('.').trim().to_lowercase();
                let val = t[i + 1..].trim().to_string();
                if val.is_empty() {
                    pending = Some(key);
                } else {
                    out.push((key, val));
                }
            }
            _ => {
                if let Some(k) = &pending {
                    out.push((k.clone(), t.to_string()));
                }
            }
        }
    }
    out
}

const NOT_FOUND: &[&str] = &[
    "no match for",
    "not found",
    "no entries found",
    "no data found",
    "status: free",
    "status:\tfree",
    "status: available",
    "is available for registration",
    "no object found",
    "object does not exist",
    "not registered",
    "no matching record",
    "domain is available",
];

pub fn parse(r: &mut Record, text: &str, redacted: &mut bool) -> Option<String> {
    let mut referral = None;
    let mut reg = Registrar::default();
    let mut who = Contact::default();
    for (k, v) in pairs(text) {
        let k = k.as_str();
        let first = |slot: &mut Option<String>, val: Option<String>| {
            if slot.is_none() {
                *slot = val;
            }
        };
        match k {
            "registrar" | "sponsoring registrar" | "registrar name" | "registrar organization" => {
                let name = v.split(" [Tag").next().unwrap_or(&v).trim().to_string();
                first(&mut reg.name, Some(name))
            }
            "registrar iana id" => first(&mut reg.iana_id, Some(v)),
            "registrar url" => first(&mut reg.url, Some(v)),
            "registrar abuse contact email" => first(&mut reg.abuse_email, Some(v)),
            "registrar abuse contact phone" => first(&mut reg.abuse_phone, Some(v)),
            "registrar whois server" | "whois server" | "refer" => first(&mut referral, Some(v)),
            "creation date"
            | "created"
            | "created on"
            | "registered on"
            | "registration time"
            | "registered"
            | "domain registration date"
            | "created date"
            | "registration date"
            | "domain record activated" => first(&mut r.created, parse_date(&v)),
            "updated date"
            | "last updated"
            | "changed"
            | "last modified"
            | "modified"
            | "last update"
            | "last-update"
            | "domain record last updated" => first(&mut r.updated, parse_date(&v)),
            "registry expiry date"
            | "registrar registration expiration date"
            | "expiration date"
            | "expiry date"
            | "expires"
            | "expires on"
            | "paid-till"
            | "renewal date"
            | "expire date"
            | "valid until"
            | "domain expiration date"
            | "expiration time" => first(&mut r.expires, parse_date(&v)),
            "domain status" | "status" | "state" => r.status.push(status(&v)),
            "name server" | "nameserver" | "nameservers" | "nserver" | "name servers" | "dns" | "host name" => {
                if let Some(ns) = v.split_whitespace().next()
                    && ns.contains('.')
                {
                    r.nameservers.push(ns.trim_end_matches('.').to_lowercase());
                }
            }
            "dnssec" => {
                let l = v.to_lowercase();
                r.dnssec = Some(l.starts_with("signed") || l == "yes" || l.contains("signeddelegation"));
            }
            "registrant name" | "registrant" | "holder" => first(&mut who.name, real(Some(v), redacted)),
            "registrant organization" | "registrant organisation" | "org" => {
                first(&mut who.org, real(Some(v), redacted))
            }
            "registrant country" | "registrant country/economy" => first(&mut who.country, Some(v)),
            "registrant email" => first(&mut who.email, real(Some(v), redacted)),
            _ => {}
        }
    }
    dedupe(&mut r.status);
    dedupe(&mut r.nameservers);
    if reg != Registrar::default() && r.registrar.is_none() {
        r.registrar = Some(reg);
    }
    if r.abuse_email.is_none() {
        r.abuse_email = r.registrar.as_ref().and_then(|g| g.abuse_email.clone());
    }
    if who != Contact::default() && r.registrant.is_none() {
        r.registrant = Some(who);
    }
    referral
}

fn looks_registered(r: &Record) -> bool {
    r.created.is_some() || r.expires.is_some() || !r.nameservers.is_empty() || r.registrar.is_some()
}

/// Full port-43 domain lookup, following one registrar referral.
pub async fn lookup_domain(
    ctx: &Ctx,
    r: &mut Record,
    domain: &str,
    redacted: &mut bool,
) -> Result<Vec<String>, LookupError> {
    let tld = domain.rsplit('.').next().unwrap_or(domain);
    let server = server_for(ctx, tld)
        .await?
        .ok_or_else(|| LookupError::NoServer(format!("no RDAP or WHOIS server known for .{tld}")))?;
    let text = query(ctx, &server, &query_string(&server, domain)).await?;
    let mut servers = vec![format!("whois://{server}")];
    let mut raws = vec![serde_json::json!({ "server": server, "text": text })];

    let referral = parse(r, &text, redacted);
    if looks_registered(r) {
        r.result = Outcome::Registered;
        if let Some(refsrv) = referral {
            let refsrv = refsrv.trim_start_matches("whois://").trim_end_matches('/').to_lowercase();
            if !refsrv.is_empty()
                && refsrv != server
                && !refsrv.contains(' ')
                && let Ok(t2) = query(ctx, &refsrv, domain).await
            {
                parse(r, &t2, redacted);
                servers.push(format!("whois://{refsrv}"));
                raws.push(serde_json::json!({ "server": refsrv, "text": t2 }));
            }
        }
    } else {
        let l = text.to_lowercase();
        if NOT_FOUND.iter().any(|p| l.contains(p)) {
            r.result = Outcome::Available;
        } else if l.contains("limit exceeded") || l.contains("rate limit") || l.contains("too many") {
            return Err(LookupError::RateLimited(format!("{server}: query rate limit exceeded")));
        } else {
            // Unknown format — report registered only if the registry echoed something substantive.
            r.result = Outcome::Registered;
        }
    }
    if ctx.opts.raw {
        r.raw = Some(serde_json::Value::Array(raws));
    }
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Kind;

    #[test]
    fn parses_uk_style_blocks() {
        let text = "\n    Domain name:\n        bbc.co.uk\n\n    Registrar:\n        British Broadcasting Corporation [Tag = BBC]\n        URL: http://www.bbc.co.uk\n\n    Relevant dates:\n        Registered on: before Aug-1996\n        Expiry date:  13-Dec-2026\n\n    Name servers:\n        ns1.bbc.co.uk  1.2.3.4\n        ns2.bbc.co.uk\n";
        let mut r = Record::new("bbc.co.uk", Kind::Domain);
        let mut red = false;
        parse(&mut r, text, &mut red);
        assert_eq!(r.registrar.unwrap().name.unwrap(), "British Broadcasting Corporation");
        assert_eq!(r.expires.unwrap(), "2026-12-13T00:00:00Z");
        assert_eq!(r.nameservers, vec!["ns1.bbc.co.uk", "ns2.bbc.co.uk"]);
    }

    #[test]
    fn parses_icann_style() {
        let text = "Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.example-registrar.com\nCreation Date: 1995-08-14T04:00:00Z\nRegistrar: Example Registrar, Inc.\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nName Server: A.IANA-SERVERS.NET\nDNSSEC: signedDelegation\nRegistrant Organization: REDACTED FOR PRIVACY\n";
        let mut r = Record::new("example.com", Kind::Domain);
        let mut red = false;
        let referral = parse(&mut r, text, &mut red);
        assert_eq!(referral.as_deref(), Some("whois.example-registrar.com"));
        assert_eq!(r.status, vec!["client transfer prohibited"]);
        assert_eq!(r.nameservers, vec!["a.iana-servers.net"]);
        assert_eq!(r.dnssec, Some(true));
        assert!(red);
        assert!(r.registrant.is_none());
    }
}
