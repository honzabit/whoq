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
    if let Some(rest) = upper.strip_prefix("AS")
        && let Ok(n) = rest.parse::<u32>()
    {
        return Ok(Query::Asn(n));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Query::Ip(ip));
    }
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(Query::Cidr(net.trunc()));
    }

    let mut host = authority(s);
    if let Some(inner) = host.strip_prefix('[') {
        // [v6]:port
        let inner = inner.split(']').next().unwrap_or(inner);
        return inner.parse::<IpAddr>().map(Query::Ip).map_err(|_| format!("invalid IPv6 address: {inner}"));
    }
    if let Some((h, port)) = host.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        host = h;
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

    let registrable =
        registrable_domain(&ascii).ok_or_else(|| format!("{ascii} is a public suffix, not a registrable domain"))?;
    let (unicode, _) = idna::domain_to_unicode(&registrable);
    let unicode = (unicode != registrable).then_some(unicode);
    Ok(Query::Domain { ascii: registrable, unicode })
}

/// Peel URL scheme, path and userinfo / email local part: `https://u@h:8443/x` -> `h:8443`.
fn authority(s: &str) -> &str {
    let mut host = s;
    if let Some(i) = host.find("://") {
        host = &host[i + 3..];
    }
    host = host.split(['/', '?', '#']).next().unwrap_or(host);
    if let Some(i) = host.rfind('@') {
        host = &host[i + 1..];
    }
    host
}

/// Where a TLS check should connect: the exact host given (not the registrable domain) and
/// its port, if any. `https://shop.example.com:8443/x` -> (`shop.example.com`, Some(8443)).
pub fn endpoint(input: &str) -> Option<(String, Option<u16>)> {
    let s = input.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some((ip.to_string(), None));
    }
    let host = authority(s);
    if let Some(inner) = host.strip_prefix('[') {
        let (ip, rest) = inner.split_once(']')?;
        let port = rest.strip_prefix(':').and_then(|p| p.parse().ok());
        return Some((ip.parse::<IpAddr>().ok()?.to_string(), port));
    }
    let (host, port) = match host.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse().ok()),
        _ => (host, None),
    };
    let host = host.trim_end_matches('.');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some((ip.to_string(), port));
    }
    Some((idna::domain_to_ascii(host).ok()?, port))
}

/// Reduce a hostname to the name actually held at the registry (`www.foo.co.uk` -> `foo.co.uk`).
/// Uses only ICANN suffixes: `foo.github.io` resolves to `github.io`, because that's what
/// the `.io` registry knows about.
pub fn registrable_domain(name: &str) -> Option<String> {
    let mut suffix = psl::suffix_str(name)?.to_string();
    while let Some(psl::Type::Private) = psl::suffix(suffix.as_bytes()).and_then(|s| s.typ()) {
        // drop one label from the private suffix and re-resolve on the remainder
        let (_, rest) = suffix.split_once('.')?;
        suffix = psl::suffix_str(rest)?.to_string();
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

    #[test]
    fn endpoints() {
        let e = |s: &str| endpoint(s).unwrap();
        assert_eq!(e("example.com"), ("example.com".into(), None));
        assert_eq!(e("https://Shop.Example.com:8443/x?y"), ("shop.example.com".into(), Some(8443)));
        assert_eq!(e("1.1.1.1"), ("1.1.1.1".into(), None));
        assert_eq!(e("https://[2001:db8::1]:444/"), ("2001:db8::1".into(), Some(444)));
        assert_eq!(e("münchen.de"), ("xn--mnchen-3ya.de".into(), None));
    }
}
