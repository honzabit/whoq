//! Turn whatever the user (or agent) typed into a lookup target.
//! Accepts domains, IDNs, URLs, email addresses, IPs, CIDRs and ASNs.

use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum Query {
    Domain { ascii: String, unicode: Option<String> },
    Ip(IpAddr),
    Cidr(IpNet),
    Asn(u32),
}

pub fn parse(input: &str) -> Result<Query, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty query".into());
    }

    // ASN: AS15169, as15169
    let upper = s.to_ascii_uppercase();
    if let Some(rest) = upper.strip_prefix("AS") {
        if let Ok(n) = rest.parse::<u32>() {
            return Ok(Query::Asn(n));
        }
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Query::Ip(ip));
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(Query::Cidr(net.trunc()));
    }

    // Peel URL / email / port decorations down to a host.
    let mut host = s;
    if let Some(i) = host.find("://") {
        host = &host[i + 3..];
    }
    host = host.split(['/', '?', '#']).next().unwrap_or(host);
    if let Some(i) = host.rfind('@') {
        host = &host[i + 1..];
    }
    if let Some(inner) = host.strip_prefix('[') {
        // [v6]:port
        let inner = inner.split(']').next().unwrap_or(inner);
        return inner
            .parse::<IpAddr>()
            .map(Query::Ip)
            .map_err(|_| format!("invalid IPv6 address: {inner}"));
    }
    if let Some((h, port)) = host.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            host = h;
        }
    }
    let host = host.trim_end_matches('.');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(Query::Ip(ip));
    }

    let ascii = idna::domain_to_ascii(host).map_err(|_| format!("invalid domain name: {host}"))?;
    if ascii.len() > 253
        || !ascii.contains('.')
        || ascii.split('.').any(|l| {
            l.is_empty() || l.len() > 63 || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err(format!("invalid domain name: {host}"));
    }

    let registrable = registrable_domain(&ascii).ok_or_else(|| format!("{ascii} is a public suffix, not a registrable domain"))?;
    let (unicode, _) = idna::domain_to_unicode(&registrable);
    let unicode = (unicode != registrable).then_some(unicode);
    Ok(Query::Domain { ascii: registrable, unicode })
}

/// Reduce a hostname to the name actually held at the registry (`www.foo.co.uk` -> `foo.co.uk`).
/// Uses only ICANN suffixes: `foo.github.io` resolves to `github.io`, because that's what
/// the `.io` registry knows about.
pub fn registrable_domain(name: &str) -> Option<String> {
    let mut suffix = psl::suffix_str(name)?.to_string();
    loop {
        match psl::suffix(suffix.as_bytes()).and_then(|s| s.typ()) {
            Some(psl::Type::Private) => {
                // drop one label from the private suffix and re-resolve on the remainder
                let (_, rest) = suffix.split_once('.')?;
                suffix = psl::suffix_str(rest)?.to_string();
            }
            _ => break,
        }
    }
    if name == suffix {
        return None;
    }
    let prefix = name.strip_suffix(&suffix)?.trim_end_matches('.');
    let label = prefix.rsplit('.').next()?;
    Some(format!("{label}.{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dom(s: &str) -> String {
        match parse(s).unwrap() {
            Query::Domain { ascii, .. } => ascii,
            other => panic!("expected domain, got {other:?}"),
        }
    }

    #[test]
    fn domains() {
        assert_eq!(dom("Example.COM"), "example.com");
        assert_eq!(dom("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(dom("https://user@sub.example.org:8443/path?q=1"), "example.org");
        assert_eq!(dom("alice@mail.example.net"), "example.net");
        assert_eq!(dom("foo.github.io"), "github.io");
        assert_eq!(dom("münchen.de"), "xn--mnchen-3ya.de");
        assert!(parse("co.uk").is_err());
        assert!(parse("localhost").is_err());
    }

    #[test]
    fn numbers() {
        assert_eq!(parse("AS15169").unwrap(), Query::Asn(15169));
        assert_eq!(parse("as13335").unwrap(), Query::Asn(13335));
        assert!(matches!(parse("8.8.8.8").unwrap(), Query::Ip(_)));
        assert!(matches!(parse("2001:4860::8888").unwrap(), Query::Ip(_)));
        assert!(matches!(parse("http://[2001:db8::1]:80/").unwrap(), Query::Ip(_)));
        assert!(matches!(parse("1.1.1.0/24").unwrap(), Query::Cidr(_)));
    }
}
