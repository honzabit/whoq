//! Legacy port-43 WHOIS (RFC 3912), used for ccTLDs without RDAP or with `--whois`.
//! Parsing is heuristic: registries all format differently.

use crate::ctx::{Ctx, LookupError};
use crate::model::{Contact, Outcome, Record, Registrar};
use crate::normalize::{dedupe, parse_date, real, status};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_RESPONSE: usize = 512 * 1024;

pub async fn query(ctx: &Ctx, server: &str, q: &str) -> Result<String, LookupError> {
    query_within(ctx, server, q, ctx.opts.timeout).await
}

/// [`query`] with an explicit deadline, for requests that carry a lot of work (bulk Cymru).
pub async fn query_within(
    ctx: &Ctx,
    server: &str,
    q: &str,
    timeout: std::time::Duration,
) -> Result<String, LookupError> {
    let sem = ctx.host_limit(server);
    let _permit = sem.acquire().await.expect("semaphore closed");
    let fut = async {
        let conn = match &ctx.whois_addr {
            Some(addr) => TcpStream::connect(addr.as_str()).await,
            None => connect_any(server, timeout).await,
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
    tokio::time::timeout(timeout, fut).await.map_err(|_| LookupError::Timeout(format!("{server}:43 timed out")))?
}

/// Connect to the first of the server's addresses that answers. Each address gets a few
/// seconds, so an unreachable one (whois.nic.net.sa publishes an IPv6 address that never
/// answers) can't use up the whole lookup before the working IPv4 address is tried.
async fn connect_any(server: &str, timeout: std::time::Duration) -> std::io::Result<TcpStream> {
    let per_addr = timeout.min(std::time::Duration::from_secs(3));
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses");
    for addr in tokio::net::lookup_host((server, 43)).await? {
        match tokio::time::timeout(per_addr, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{addr}: connect timed out")),
        }
    }
    Err(last)
}

/// How long IANA's answer about a TLD's WHOIS server is reused. These change rarely, and asking
/// IANA costs a round trip on every port-43 lookup.
const SERVER_TTL: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// Ask IANA which WHOIS server handles a TLD, remembering the answer in memory and on disk.
async fn server_for(ctx: &Ctx, tld: &str) -> Result<Option<String>, LookupError> {
    if let Some(s) = ctx.whois_servers.lock().unwrap().get(tld) {
        return Ok(s.clone());
    }
    let cached = |b: Vec<u8>| {
        serde_json::from_slice::<serde_json::Value>(&b).ok().map(|v| v["server"].as_str().map(String::from))
    };
    let server = match ctx.cache_get("whois-servers", tld, SERVER_TTL, false).await.and_then(cached) {
        Some(s) => s,
        None => match query(ctx, "whois.iana.org", tld).await {
            Ok(resp) => {
                let s = resp
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("whois:").map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty());
                ctx.cache_put("whois-servers", tld, serde_json::json!({ "server": s }).to_string().as_bytes()).await;
                s
            }
            // IANA unreachable: an old answer beats none.
            Err(e) => match ctx.cache_get("whois-servers", tld, SERVER_TTL, true).await.and_then(cached) {
                Some(s) => s,
                None => return Err(e),
            },
        },
    };
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

/// `key: value` where the colon is followed by whitespace or end-of-line (not "http://"),
/// or JPRS's `[Key]   value`.
fn split_kv(t: &str) -> Option<(String, String)> {
    if let Some(rest) = t.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return Some((rest[..end].trim().to_lowercase(), rest[end + 1..].trim().to_string()));
    }
    let spaced =
        t.char_indices().find(|&(i, c)| c == ':' && t[i + 1..].chars().next().is_none_or(|n| n.is_whitespace()));
    // .im writes "Name Server:ns1.google.com." with no space. Accept that only when the key is
    // plain words and the value isn't a URL's "//", so "http://..." and "12:30" stay values.
    let (i, _) = spaced.or_else(|| {
        let i = t.find(':')?;
        (t[..i].chars().all(|c| c.is_ascii_alphabetic() || c == ' ') && !t[i + 1..].starts_with('/'))
            .then_some((i, ':'))
    })?;
    if i == 0 || i >= 48 {
        return None;
    }
    Some((t[..i].trim().trim_end_matches('.').trim().to_lowercase(), t[i + 1..].trim().to_string()))
}

/// One `key: value` line, with the section heading it sits under, if any.
#[derive(Debug, PartialEq)]
pub struct Pair {
    pub section: Option<String>,
    pub key: String,
    pub val: String,
}

/// Split into key/value pairs. Registries group fields under section headers, either
/// `Registrar:` with nothing after it or a bare `Registrar` line (.it, .dk), so each pair
/// keeps its section: the parser can then tell the registrar's `Name:` from a contact's.
/// Lines without a key under a header (.uk, .it, .bg nameservers) become values of the
/// header itself.
pub fn pairs(text: &str) -> Vec<Pair> {
    let mut out = vec![];
    let mut section: Option<String> = None;
    let mut got_value = false;
    for line in text.lines() {
        let indented = line.starts_with([' ', '\t']);
        let mut t = line.trim().trim_start_matches("**").trim();
        if t.is_empty() {
            // A blank line ends a section, unless the header is still waiting for its values (.hk).
            if got_value {
                section = None;
            }
            continue;
        }
        if t.starts_with('%') || t.starts_with('#') || t.starts_with(">>>") {
            continue;
        }
        // JPRS prefixes some fields with a letter: "a. [Domain Name]"
        if let Some(rest) = t.get(3..)
            && t.as_bytes()[0].is_ascii_lowercase()
            && t[1..].starts_with(". [")
        {
            t = rest;
        }
        match split_kv(t) {
            Some((key, val)) if val.is_empty() => {
                section = Some(key);
                got_value = false;
            }
            Some((key, val)) => {
                got_value |= section.is_some();
                out.push(Pair { section: section.clone(), key, val });
            }
            None => match &section {
                Some(s) => {
                    out.push(Pair { section: None, key: s.clone(), val: t.to_string() });
                    got_value = true;
                }
                // A bare, unindented heading such as "Registrar" or "Nameservers".
                None if !indented && t.len() < 40 && !t.contains(['.', ',', '*', '[']) => {
                    section = Some(t.to_lowercase());
                    got_value = false;
                }
                None => {}
            },
        }
    }
    out
}

/// Which field a pair holds. The key decides when it means something on its own
/// ("Name Server", "Domain created"); the section only fills in a key that doesn't
/// ("Name" under "Registrar"). Under a contact heading the key is never read alone, so a
/// registrant's "State:" or "Name:" can't become the domain's.
fn field_of(p: &Pair) -> Option<Field> {
    match &p.section {
        Some(s) if is_contact(s) => classify(&format!("{s} {}", p.key)),
        Some(s) => classify(&p.key).or_else(|| {
            // Only a sub-field ("Name", "Organization", "URL", "Hostname") borrows the
            // section's meaning; an unrelated key after an empty field ("registrar:" then
            // "tech-c:" in .at) must not become "registrar tech-c".
            const SUB: &[&str] = &[
                "name",
                "organization",
                "organisation",
                "org",
                "url",
                "web",
                "www",
                "website",
                "hostname",
                "host",
                "dns",
            ];
            words(&p.key).iter().all(|w| SUB.contains(&w.as_str())).then(|| classify(&format!("{s} {}", p.key)))?
        }),
        None => classify(&p.key),
    }
}

/// A heading for a person or role rather than the domain itself ("Registrant",
/// "Administrative Contact"); judged by its first word, so "Registrar Abuse Contact Phone"
/// is not one.
fn is_contact(section: &str) -> bool {
    words(section).first().is_some_and(|w| {
        matches!(
            w.as_str(),
            "registrant"
                | "holder"
                | "owner"
                | "admin"
                | "administrative"
                | "tech"
                | "technical"
                | "billing"
                | "contact"
                | "contacts"
                | "person"
                | "zone"
        )
    })
}

/// A key's words: lowercased, with `-`, `_`, `.` and `/` read as spaces, so
/// "registrar-name", "Registrar_Name" and "Current Registrar......" all compare alike.
fn words(key: &str) -> Vec<String> {
    key.to_lowercase()
        .split(|c: char| c.is_whitespace() || "-_./".contains(c))
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Field {
    RegistrarName,
    RegistrarIana,
    RegistrarUrl,
    RegistrarAbuseEmail,
    RegistrarAbusePhone,
    Referral,
    Created,
    Updated,
    Expires,
    Status,
    Nameserver,
    Dnssec,
    HolderName,
    HolderOrg,
    HolderState,
    HolderCountry,
    HolderEmail,
}

/// Classify a key by the words in it, not by an exact spelling, so a registry's own
/// wording ("Current Registrar", "Domain created", "registrar-name", "NAME SERVER
/// INFORMATION") lands in the right field without a per-registry entry. Values are still
/// checked afterwards: a date field must parse as a date, a nameserver must be a hostname.
fn classify(key: &str) -> Option<Field> {
    use Field::*;
    let w = words(key);
    let is = |x: &str| w.iter().any(|y| y == x);
    let starts = |p: &str| w.iter().any(|y| y.starts_with(p));
    let joined = w.join(" ");

    if starts("dnssec") {
        return Some(Dnssec);
    }
    if (is("whois") && is("server")) || joined == "refer" {
        return Some(Referral);
    }
    if is("registrar") || is("sponsoring") {
        if starts("iana") {
            return Some(RegistrarIana);
        }
        if is("url") || is("website") || is("www") || is("web") {
            return Some(RegistrarUrl);
        }
        if is("abuse") {
            return if starts("mail") || is("email") || is("e") {
                Some(RegistrarAbuseEmail)
            } else if is("phone") {
                Some(RegistrarAbusePhone)
            } else {
                None
            };
        }
        // ICANN's "Registrar Registration Expiration Date" is the domain's expiry.
        if starts("expir") && is("registration") {
            return Some(Expires);
        }
        const NOT_NAME: &[&str] = &[
            "id",
            "handle",
            "mail",
            "email",
            "e",
            "phone",
            "fax",
            "address",
            "street",
            "city",
            "country",
            "postal",
            "zip",
            "code",
            "contact",
            "contacts",
            "technical",
            "admin",
            "status",
            "date",
            "created",
            "creation",
            "updated",
            "changed",
            "registration",
            "since",
            "lock",
            "locked",
        ];
        return if w.iter().any(|x| NOT_NAME.contains(&x.as_str()) || x.starts_with("creat")) {
            None
        } else {
            Some(RegistrarName)
        };
    }
    if is("status") || joined == "state" || joined == "domain state" {
        return Some(Status);
    }
    if starts("expir")
        || is("validity")
        || joined.starts_with("valid until")
        || joined.contains("paid till")
        || is("renewal")
    {
        return Some(Expires);
    }
    if starts("creat")
        || is("commencement")
        || is("activated")
        || is("assigned")
        || ((is("registered") || is("registration")) && !starts("registrant"))
    {
        return Some(Created);
    }
    if starts("updat") || starts("modif") || is("changed") {
        return Some(Updated);
    }
    if is("nserver")
        || starts("nameserver")
        || (is("name") && starts("server"))
        || ((is("domain") || is("dns")) && is("servers"))
        || joined.ends_with("host name")
        || joined.ends_with("hostname")
    {
        return if is("ip") || is("ipv4") || is("ipv6") || starts("address") { None } else { Some(Nameserver) };
    }
    if matches!(w.first().map(String::as_str), Some("registrant" | "holder" | "owner")) {
        if starts("organi") {
            return Some(HolderOrg);
        }
        if starts("country") {
            return Some(HolderCountry);
        }
        if is("state") || is("province") {
            return Some(HolderState);
        }
        if starts("mail") || is("email") {
            return Some(HolderEmail);
        }
        if w.len() == 1 || (w.len() == 2 && is("name")) {
            return Some(HolderName);
        }
        return None;
    }
    (joined == "org").then_some(HolderOrg)
}

/// Not-found wording, matched against the lowercased response with `_` read as a space and
/// runs of whitespace collapsed ("Object_Not_Found", "Status:\tAVAILABLE"). Short, common
/// phrases rather than each registry's sentence; only consulted when no registration data
/// was found, so a phrase elsewhere in a real record can't flip it.
const NOT_FOUND: &[&str] = &[
    "no match",
    "not found",
    "nothing found",
    "no such domain",
    "no entries found",
    "no data found",
    "no data was found",
    "is available for registration",
    "no object found",
    "object does not exist",
    "not registered",
    "has not been registered",
    "no matching record",
    "domain is available",
];

/// Whether the registry says the name is not registered: a not-found phrase, or a status
/// field whose whole value is "available" / "free".
fn says_available(text: &str) -> bool {
    let flat = text.to_lowercase().replace('_', " ").split_whitespace().collect::<Vec<_>>().join(" ");
    NOT_FOUND.iter().any(|p| flat.contains(p))
        || pairs(text).iter().any(|p| {
            field_of(p) == Some(Field::Status)
                && matches!(p.val.trim().to_lowercase().as_str(), "available" | "free" | "not registered")
        })
}

/// The registry's own words, for an error about a reply we couldn't read: the first two
/// lines that aren't comments (or, when every line is a comment, the last two).
fn excerpt(text: &str) -> String {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let body: Vec<&str> = lines.iter().copied().filter(|l| !l.starts_with(['%', '#'])).take(2).collect();
    let picked = if body.is_empty() {
        lines.iter().rev().take(2).rev().map(|l| l.trim_start_matches(['%', '#']).trim()).collect::<Vec<_>>()
    } else {
        body
    };
    let s = picked.join(" / ");
    if s.chars().count() > 160 { format!("{}…", s.chars().take(160).collect::<String>()) } else { s }
}

pub fn parse(r: &mut Record, text: &str, redacted: &mut bool) -> Option<String> {
    use Field::*;
    let mut referral = None;
    let mut reg = Registrar::default();
    let mut who = Contact::default();
    let first = |slot: &mut Option<String>, val: Option<String>| {
        if slot.is_none() {
            *slot = val;
        }
    };
    // .sk gives the registrar as a handle ("Registrar: PPRP-0001") with its name on the next line.
    let mut registrar_handle = false;
    for p in pairs(text) {
        let after_handle = std::mem::take(&mut registrar_handle);
        if after_handle && p.section.is_none() && p.key == "name" && !p.val.is_empty() {
            if let Some(g) = &mut reg.name {
                *g = p.val.clone();
            }
            continue;
        }
        let Some((field, v)) = field_of(&p).map(|f| (f, p.val.clone())).or_else(|| dated_line(&p)) else { continue };
        match field {
            RegistrarName => {
                let name = v.split(" [Tag").next().unwrap_or(&v).trim().to_string();
                if !name.is_empty() && reg.name.is_none() {
                    registrar_handle = is_handle(&name);
                    reg.name = Some(name);
                }
            }
            RegistrarIana => first(&mut reg.iana_id, Some(v)),
            RegistrarUrl => first(&mut reg.url, Some(v)),
            RegistrarAbuseEmail => first(&mut reg.abuse_email, Some(v)),
            RegistrarAbusePhone => first(&mut reg.abuse_phone, Some(v)),
            Referral => first(&mut referral, Some(v)),
            Created => first(&mut r.created, parse_date(&v)),
            Updated => first(&mut r.updated, parse_date(&v)),
            Expires => first(&mut r.expires, parse_date(&v)),
            Status => {
                // JPRS: "[State]  Connected (2027/09/30)" is the end of the paid period.
                if let Some((_, rest)) = v.split_once('(')
                    && let Some(d) = parse_date(rest.trim_end_matches(')'))
                {
                    first(&mut r.expires, Some(d));
                }
                for s in v.split(',') {
                    let s = s.split(" (").next().unwrap_or(s).trim();
                    if !s.is_empty() {
                        r.status.push(status(s))
                    }
                }
            }
            Nameserver => {
                if let Some(ns) = v.split_whitespace().next().map(|n| n.trim_end_matches('.').to_lowercase())
                    && ns.contains('.')
                    && ns.chars().any(|c| c.is_ascii_alphabetic())
                    && ns.parse::<std::net::IpAddr>().is_err()
                {
                    r.nameservers.push(ns);
                }
            }
            Dnssec => {
                let l = v.to_lowercase();
                r.dnssec = Some(l.starts_with("signed") || l == "yes" || l.contains("signeddelegation"));
            }
            HolderName => first(&mut who.name, real(Some(v), redacted)),
            HolderOrg => first(&mut who.org, real(Some(v), redacted)),
            HolderState => first(&mut who.state, real(Some(v), redacted)),
            HolderCountry => first(&mut who.country, Some(v)),
            HolderEmail => first(&mut who.email, real(Some(v), redacted)),
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
    if who.name.is_none() {
        who.name = listed_holder(text, redacted);
    }
    if who != Contact::default() && r.registrant.is_none() {
        r.registrant = Some(who);
    }
    referral
}

/// The holder from .im's block layout: a "Domain Owners / Registrant" heading, or "Domain
/// Managers" when that's all there is, followed by "Name: X" or by "Name" and X on the next line.
fn listed_holder(text: &str, redacted: &mut bool) -> Option<String> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let at = |heading: &str| lines.iter().position(|l| l.to_lowercase().starts_with(heading));
    let i = at("domain owners").or_else(|| at("domain managers"))?;
    let next = *lines.get(i + 1)?;
    let name = match split_kv(next) {
        Some((k, v)) if k == "name" => v,
        None if next.eq_ignore_ascii_case("name") => lines.get(i + 2)?.to_string(),
        _ => return None,
    };
    real(Some(name), redacted)
}

/// A registry handle rather than a name: one word of capitals, digits and dashes with a digit
/// in it ("PPRP-0001").
fn is_handle(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_digit())
        && s.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// A date written as a sentence under a heading, as .gg and .je do under "Relevant dates":
/// "Registered on 30th April 2003 at 00:00:00.000". Only date fields are read this way, and
/// only when the date parses, so "Registry fee due on 30th April each year" is skipped.
fn dated_line(p: &Pair) -> Option<(Field, String)> {
    if p.section.is_some() {
        return None;
    }
    let (key, rest) = p.val.split_once(" on ")?;
    let field = classify(key).filter(|f| matches!(f, Field::Created | Field::Updated | Field::Expires))?;
    parse_date(rest)?;
    Some((field, rest.to_string()))
}

fn looks_registered(r: &Record) -> bool {
    r.created.is_some() || r.expires.is_some() || !r.nameservers.is_empty() || r.registrar.is_some()
}

/// A record with no dates, nameservers or registrar that still names the domain and lists
/// who holds it, as .im does for its own nic.im ("Domain Name:nic.im", then "Domain Managers").
/// Only checked after `says_available`, since .im echoes "Domain Name:" for unregistered names too.
fn echoes_holder(text: &str, domain: &str) -> bool {
    let mut echoed = false;
    let mut holder = false;
    for line in text.lines().map(str::trim) {
        let l = line.to_lowercase();
        if let Some((k, v)) = split_kv(line)
            && k == "domain name"
            && v.trim_end_matches('.').eq_ignore_ascii_case(domain)
        {
            echoed = true;
        } else if l.starts_with("domain managers") || l.starts_with("domain owners") || l.starts_with("registrant") {
            holder = true;
        }
    }
    echoed && holder
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
    } else if says_available(&text) {
        r.result = Outcome::Available;
    } else if echoes_holder(&text, domain) {
        r.result = Outcome::Registered;
    } else {
        let l = text.to_lowercase();
        if l.contains("limit exceeded") || l.contains("rate limit") || l.contains("too many") {
            return Err(LookupError::RateLimited(format!("{server}: query rate limit exceeded")));
        }
        // Neither registration data nor a not-found answer: don't guess. Guessing
        // "registered" here turned every unfamiliar not-found wording into a false positive.
        // Keep the registry's reply (always, not only with --raw) and quote it in the error,
        // so a reader can still see what the registry said.
        r.raw = Some(serde_json::Value::Array(raws));
        return Err(LookupError::Upstream(format!(
            "{server}: unrecognized response; could not tell whether {domain} is registered. Registry said: \"{}\"",
            excerpt(&text)
        )));
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
    fn registry_record_with_only_a_holder_counts_as_registered() {
        let own = "\nDomain Name:nic.im\nDomain Managers\nName\nThe IM Registry\nAddress\nIsle of Man\n";
        let mut r = Record::new("nic.im", Kind::Domain);
        let mut red = false;
        parse(&mut r, own, &mut red);
        assert!(!looks_registered(&r));
        assert!(!says_available(own));
        assert!(echoes_holder(own, "nic.im"));
        assert!(!echoes_holder(own, "other.im"));
        let missing = "\nDomain Name:\tzz-none.im\nThe domain zz-none.im was not found.\n";
        assert!(says_available(missing));
        assert!(!echoes_holder(missing, "zz-none.im"));
    }

    #[test]
    fn reads_the_registrant_state() {
        let text = "Domain Name: example.org\nRegistrar: Example\nRegistrant Name: REDACTED FOR PRIVACY\nRegistrant State/Province: Attica\nRegistrant Country: GR\n";
        let mut r = Record::new("example.org", Kind::Domain);
        let mut red = false;
        parse(&mut r, text, &mut red);
        let c = r.registrant.unwrap();
        assert_eq!((c.state.as_deref(), c.country.as_deref()), (Some("Attica"), Some("GR")));

        let hidden = "Domain Name: example.org\nRegistrar: Example\nRegistrant State/Province: REDACTED FOR PRIVACY\n";
        let mut r = Record::new("example.org", Kind::Domain);
        let mut red = false;
        parse(&mut r, hidden, &mut red);
        assert!(r.registrant.is_none());
        assert!(red);
    }

    #[test]
    fn reads_the_holder_from_im_blocks() {
        let own = "Domain Name:nic.im\nDomain Managers\nName\nThe IM Registry\nAddress\nIsle of Man\n";
        let mut r = Record::new("nic.im", Kind::Domain);
        let mut red = false;
        parse(&mut r, own, &mut red);
        assert_eq!(r.registrant.and_then(|c| c.name).as_deref(), Some("The IM Registry"));
        assert!(!red);

        let hidden = "Domain Name:\tgoogle.im\nDomain Managers\nName: Redacted\nAddress\nRedacted\nDomain Owners / Registrant\nName: Redacted\nAddress\nRedacted\nExpiry Date: 16/08/2027 23:59:39\n";
        let mut r = Record::new("google.im", Kind::Domain);
        let mut red = false;
        parse(&mut r, hidden, &mut red);
        assert!(r.registrant.is_none());
        assert!(red);
    }

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

    fn parsed(text: &str) -> Record {
        let mut r = Record::new("example.test", Kind::Domain);
        let mut red = false;
        parse(&mut r, text, &mut red);
        r
    }

    fn registrar(r: &Record) -> &str {
        r.registrar.as_ref().and_then(|g| g.name.as_deref()).unwrap_or("")
    }

    // Each fixture below is synthetic, shaped like one registry's port-43 layout.

    #[test]
    fn parses_indented_dns_servers_heading() {
        // .am: everything indented, nameservers under "DNS servers:".
        let r = parsed(
            "   Domain name: example.am\n   Registrar:   exreg (Example Registrar LLC)\n   Registrant:\n      Example Holder\n      AM\n   DNS servers:\n      ns1.example.net\n      ns2.example.net\n   Registered:    2001-02-03\n   Expires:       2027-02-03\n",
        );
        assert_eq!(registrar(&r), "exreg (Example Registrar LLC)");
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.net"]);
        assert_eq!(r.created.as_deref(), Some("2001-02-03T00:00:00Z"));
    }

    #[test]
    fn parses_keys_without_a_space_after_the_colon() {
        // .im: "Name Server:host." under a bare heading; a URL or a time must not split.
        let r = parsed(
            "Domain Name:\texample.im\nDomain Details\nExpiry Date: 16/08/2027 23:59:39\nName Server:ns1.example.net.\nName Server:ns2.example.net.\n",
        );
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.net"]);
        assert_eq!(r.expires.as_deref(), Some("2027-08-16T23:59:39Z"));
        assert_eq!(split_kv("http://example.net"), None);
        assert_eq!(split_kv("12:30"), None);
    }

    #[test]
    fn parses_dates_written_as_sentences() {
        // .gg and .je: "Registered on 30th April 2003 at 00:00:00.000" under "Relevant dates:";
        // the yearly fee line has no year and must not become a date.
        let r = parsed(
            "Domain:\n     example.gg\nRegistrar:\n     Example Registrar Inc. (http://registrar.example)\nRelevant dates:\n     Registry fee due on 2nd March each year\n     Registered on 1st March 2004 at 00:00:00.000\nName servers:\n     ns1.example.net\n",
        );
        assert_eq!(r.created.as_deref(), Some("2004-03-01T00:00:00Z"));
        assert_eq!(r.expires, None);
        assert_eq!(r.nameservers, vec!["ns1.example.net"]);
        assert_eq!(parse_date("22nd November 2019").as_deref(), Some("2019-11-22T00:00:00Z"));
    }

    #[test]
    fn registrar_handle_takes_the_name_on_the_next_line() {
        // .sk: "Registrar: HANDLE" followed by "Name:"; the registrant block before it has the
        // same shape and must not change the registrar.
        let r = parsed(
            "Domain:            example.sk\nDomain registrant: HOLD-0001\nName:              Example Holder s.r.o.\nRegistrar:         EXRG-0042\nName:              Example Registrar, a.s.\nOrganization:      Example Registrar, a.s.\n",
        );
        assert_eq!(registrar(&r), "Example Registrar, a.s.");
        // A plain name is kept even when a Name line follows.
        let r = parsed("Registrar: Example Registrar\nName: Someone Else\n");
        assert_eq!(registrar(&r), "Example Registrar");
    }

    #[test]
    fn parses_bare_section_headings() {
        // .it: "Registrar" and "Nameservers" headings without colons, indented fields;
        // a contact's own Created date must not win over the domain's.
        let r = parsed(
            "Domain:             example.it\nCreated:            1999-01-29 00:00:00\nExpire Date:        2027-08-05\n\nRegistrant\n  Organization:     Example Holder S.p.A\n\nAdmin Contact\n  Name:             Someone\n  Created:          2013-08-05 00:42:43\n\nRegistrar\n  Organization:     Example Registrar S.r.l.\n  Name:             EXAMPLE-REG\n\nNameservers\n  ns1.example.net\n  ns2.example.org\n",
        );
        assert_eq!(registrar(&r), "Example Registrar S.r.l.");
        assert_eq!(r.created.as_deref(), Some("1999-01-29T00:00:00Z"));
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.org"]);
    }

    #[test]
    fn parses_colon_sections_and_tab_layouts() {
        // .be: tab-separated, "Registrar:" section with a Name field, weekday dates,
        // nameservers followed by glue addresses.
        let r = parsed(
            "Domain:\texample.be\nStatus:\tNOT AVAILABLE\nRegistered:\tThu Feb 22 1996\n\nRegistrar Technical Contacts:\n\tOrganisation:\tSOMEONE ELSE\n\nRegistrar:\n\tName:\tExample Registrar\n\tWebsite:\thttps://registrar.example\n\nNameservers:\n\tns1.example.be (192.0.2.1)\n\tns2.example.net\n",
        );
        assert_eq!(registrar(&r), "Example Registrar");
        assert_eq!(r.created.as_deref(), Some("1996-02-22T00:00:00Z"));
        assert_eq!(r.nameservers, vec!["ns1.example.be", "ns2.example.net"]);

        // .ee: unindented fields under "Registrar:", "expire:".
        let r = parsed(
            "Domain:\nname:       example.ee\nregistered: 2010-07-04 03:59:01 +03:00\nexpire:     2027-11-17\n\nRegistrant:\nname:       Example Holder AS\n\nRegistrar:\nname:       Example Registrar OÜ\nurl:        http://registrar.example\n\nName servers:\nnserver:   ns1.example.net\n",
        );
        assert_eq!(registrar(&r), "Example Registrar OÜ");
        assert_eq!(r.expires.as_deref(), Some("2027-11-17T00:00:00Z"));
    }

    #[test]
    fn dns_line_is_not_a_nameserver_outside_a_nameserver_section() {
        // .dk prints the domain itself as "DNS:"; its nameservers are "Hostname:" lines.
        let r = parsed(
            "Domain:               example.dk\nDNS:                  example.dk\nRegistered:           1998-03-11\nExpires:              2027-03-31\n\nNameservers\nHostname:             ns1.example.net\nHostname:             ns2.example.net\n",
        );
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.net"]);
        // .mx keeps its nameservers as "DNS:" lines inside "Name Servers:".
        let r = parsed(
            "Domain Name:       example.mx\nName Servers:\n   DNS:            ns3.example.mx       192.0.2.3\n   DNS:            ns4.example.mx\n",
        );
        assert_eq!(r.nameservers, vec!["ns3.example.mx", "ns4.example.mx"]);
    }

    #[test]
    fn parses_day_first_dates_and_star_headings() {
        // .il: DD-MM-YYYY "assigned"/"validity"; "registrar name:".
        let r = parsed(
            "domain:       example.co.il\nassigned:     01-11-2016\nvalidity:     01-11-2027\nregistrar name: Example Registrar Ltd\n",
        );
        assert_eq!(r.created.as_deref(), Some("2016-11-01T00:00:00Z"));
        assert_eq!(r.expires.as_deref(), Some("2027-11-01T00:00:00Z"));
        assert_eq!(registrar(&r), "Example Registrar Ltd");

        // .hk: a blank line between a heading and its values.
        let r = parsed(
            "Domain Name Commencement Date: 03-01-1990\nExpiry Date: 07-06-2033 \nRegistrar Name: Example Registrar Limited\n\nName Servers Information:\n\nNS1.EXAMPLE.HK\nNS2.EXAMPLE.NET\n\nStatus Information:\n",
        );
        assert_eq!(r.created.as_deref(), Some("1990-01-03T00:00:00Z"));
        assert_eq!(r.expires.as_deref(), Some("2033-06-07T00:00:00Z"));
        assert_eq!(r.nameservers, vec!["ns1.example.hk", "ns2.example.net"]);

        // .tr: "** Section:" headings, dotted keys, "1996-Oct-31." dates.
        let r = parsed(
            "** Domain Name: example.com.tr\n** Registrar:\nNIC Handle\t\t: abc12\nOrganization Name\t: Example Registrar A.Ş.\n\n** Domain Servers:\nns1.example.net\nns2.example.org\n\n** Additional Info:\nCreated on..............: 1996-Oct-31.\nExpires on..............: 2029-Oct-30.\n",
        );
        assert_eq!(registrar(&r), "Example Registrar A.Ş.");
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.org"]);
        assert_eq!(r.created.as_deref(), Some("1996-10-31T00:00:00Z"));
        assert_eq!(r.expires.as_deref(), Some("2029-10-30T00:00:00Z"));
    }

    #[test]
    fn parses_jprs_and_kr() {
        let r = parsed(
            "[ JPRS database provides information on network administration. ]\nDomain Information:\na. [Domain Name]                EXAMPLE.CO.JP\np. [Name Server]                ns1.example.co.jp\np. [Name Server]                ns2.example.co.jp\n[State]                         Connected (2027/09/30)\n[Registered Date]               2019/09/27\n",
        );
        assert_eq!(r.nameservers, vec!["ns1.example.co.jp", "ns2.example.co.jp"]);
        assert_eq!(r.created.as_deref(), Some("2019-09-27T00:00:00Z"));
        assert_eq!(r.expires.as_deref(), Some("2027-09-30T00:00:00Z"));
        assert_eq!(r.status, vec!["connected"]);

        let r = parsed(
            "   Registered Date             : 1996. 07. 20.\n   Expiration Date             : 9999. 12. 31.\n   Primary Name Server\n      Host Name                : ns1.example.or.kr\n",
        );
        assert_eq!(r.created.as_deref(), Some("1996-07-20T00:00:00Z"));
        assert_eq!(r.nameservers, vec!["ns1.example.or.kr"]);
    }

    #[test]
    fn recognizes_not_found_wordings() {
        for text in [
            "[ JPRS database provides information on network administration. ]\nNo match!!\n",
            "Domain:             example.it\nStatus:             AVAILABLE\n",
            "Domain:\texample.be\nStatus:\tAVAILABLE\n",
            "The domain has not been registered.\n",
            "No match found for example.com.tr\n",
            "% No data was found to match the request criteria.\n",
            "% nothing found\n",
            "state: free\n",
        ] {
            assert!(!looks_registered(&parsed(text)), "{text}");
            assert!(says_available(text), "{text}");
        }
        // A registered record that merely mentions availability elsewhere is not "available".
        assert!(!says_available("Domain: example.se\nstatus: ok\nregistry-lock: unlocked\n"));
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

    #[test]
    fn classifies_keys_by_their_words() {
        use Field::*;
        for (k, f) in [
            ("Current Registrar", Some(RegistrarName)),
            ("registrar-name", Some(RegistrarName)),
            ("Registrar_Organisation_Name", Some(RegistrarName)),
            ("registrar-email", None),
            ("Registrar created", None),
            ("Registrar Registration Expiration Date", Some(Expires)),
            ("Domain created", Some(Created)),
            ("Expiration date", Some(Expires)),
            ("paid-till", Some(Expires)),
            ("Last modified", Some(Updated)),
            ("registration status", Some(Status)),
            ("NAME SERVER INFORMATION", Some(Nameserver)),
            ("Name Server IP", None),
            ("Registrar WHOIS Server", Some(Referral)),
            ("Registrant Country/Economy", Some(HolderCountry)),
            ("Registrant Street", None),
            ("dns", None),
        ] {
            assert_eq!(classify(k), f, "{k}");
        }
    }

    #[test]
    fn parses_dotted_keys_and_unlabeled_nameservers() {
        // Dotted keys, contacts under bare headings, a registrar field that is a date.
        let r = parsed(
            "Domain Name............: example.kz\nRegistrant\nName...................: Someone\nState..................: Somewhere\nName Server list\nName Server............: ns1.example.net\nName Server............: ns2.example.net\nDomain created.........: 2010-09-14 07:42:02 (GMT+0:00)\nExpiration date........: 2029-09-14 07:42:02 (GMT+0:00)\nDomain status..........: ok\nRegistrar created......: OLDREG\nCurrent Registrar......: NEWREG\n",
        );
        assert_eq!(registrar(&r), "NEWREG");
        assert_eq!(r.created.as_deref().map(|d| &d[..10]), Some("2010-09-14"));
        assert_eq!(r.expires.as_deref().map(|d| &d[..10]), Some("2029-09-14"));
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.net"]);
        assert!(!r.status.iter().any(|s| s.to_lowercase().contains("somewhere")), "{:?}", r.status);
        assert_eq!(r.registrant.as_ref().and_then(|c| c.name.as_deref()), Some("Someone"));

        // Nameservers listed under a heading, with no key on each line.
        let r = parsed(
            "DOMAIN NAME: example.bg (example.bg)\nregistration status: busy, active\n\nNAME SERVER INFORMATION:\nns1.example.net \nns2.example.net \n\nDNSSEC: inactive\n",
        );
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.net"]);
        assert!(looks_registered(&r));

        let r = parsed(
            "domainname: example.lu\nnserver: ns1.example.net\nregistrar-name: Example Registrar S.A.\nregistrar-email: x@example.net\n",
        );
        assert_eq!(registrar(&r), "Example Registrar S.A.");
    }

    #[test]
    fn recognizes_generic_not_found_phrases() {
        for text in [
            "example.pt - No Match\n",
            "No_Se_Encontro_El_Objeto/Object_Not_Found\n",
            "% Whois server 4.1\nNincs talalat / No match\n",
            "DOMAIN NAME: example.bg (example.bg)\nregistration status: available\n",
            "% policy text\n% WHOIS example.lu\n% No such domain\n",
        ] {
            assert!(!looks_registered(&parsed(text)), "{text}");
            assert!(says_available(text), "{text}");
        }
    }

    #[test]
    fn excerpt_quotes_the_registry() {
        assert_eq!(excerpt("% header\n\nweird reply\nsecond line\nthird\n"), "weird reply / second line");
        assert_eq!(excerpt("% long policy\n% WHOIS x.lu\n% Something odd\n"), "WHOIS x.lu / Something odd");
    }

    #[test]
    fn empty_icann_field_does_not_swallow_later_fields() {
        let r = parsed(
            "Domain Name: example.so\nRegistrar: Example Registrar\nRegistrar Abuse Contact Phone:\nDomain Status: active https://icann.org/epp#active\nName Server: ns1.example.net\nName Server: ns2.example.net\n",
        );
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.net"]);
        assert!(r.registrar.as_ref().unwrap().abuse_phone.is_none());
        assert!(!r.status.is_empty());
    }

    #[test]
    fn empty_registrar_field_does_not_adopt_the_next_key() {
        let r = parsed(
            "domain:         example.at\nregistrar:      \nregistrant:     ABC123-NICAT\ntech-c:         ABC123-NICAT\nnserver:        ns1.example.net\nnserver:        ns2.example.net\nchanged:        20200101 10:00:00\n",
        );
        assert!(r.registrar.is_none(), "{:?}", r.registrar);
        assert_eq!(r.nameservers, vec!["ns1.example.net", "ns2.example.net"]);
    }
}
