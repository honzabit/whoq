//! Live DNS. `--dns`: reverse DNS with forward confirmation for IPs; addresses, hosting
//! network, nameserver provider and CAA for domains. `--mail`: mail posture (MX, SPF, DMARC,
//! DKIM, MTA-STS, TLS-RPT, BIMI) for domains.
//!
//! Everything here comes from DNS data the domain or IP owner controls: it is sanitized
//! like registry data and must be treated as untrusted.

use crate::ctx::{Ctx, Live};
use crate::model::{Dmarc, Dns, Hosting, Mail, Mx, Rdns, Record, Spf};
use crate::sanitize::clean;
use futures::future::join_all;
use hickory_resolver::config::{
    CLOUDFLARE, ConnectionConfig, NameServerConfig, ProtocolConfig, ResolveHosts, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{Name, RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Selectors probed for DKIM. Selectors can't be enumerated, so this is best effort.
const DKIM_SELECTORS: &[&str] = &[
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "default",
    "dkim",
    "mail",
    "sig1",
    "fm1",
    "protonmail",
    "mandrill",
    "zmail",
    "pm",
    "mxvault",
];

/// Nameserver suffix -> DNS provider. Parking services carry a "(parking)" suffix,
/// which drives the `parked` signal. A trailing `-` means "contains" rather than "ends with".
const DNS_PROVIDERS: &[(&str, &str)] = &[
    ("cloudflare.com", "Cloudflare"),
    ("awsdns-", "AWS Route 53"),
    ("googledomains.com", "Google Cloud DNS"),
    ("google.com", "Google"),
    ("azure-dns.com", "Azure DNS"),
    ("azure-dns.net", "Azure DNS"),
    ("azure-dns.org", "Azure DNS"),
    ("azure-dns.info", "Azure DNS"),
    ("nsone.net", "NS1"),
    ("akam.net", "Akamai"),
    ("ultradns.com", "UltraDNS"),
    ("ultradns.net", "UltraDNS"),
    ("ultradns.org", "UltraDNS"),
    ("ultradns.biz", "UltraDNS"),
    ("dynect.net", "Oracle Dyn"),
    ("domaincontrol.com", "GoDaddy"),
    ("registrar-servers.com", "Namecheap"),
    ("dnsimple.com", "DNSimple"),
    ("dnsimple-edge.net", "DNSimple"),
    ("digitalocean.com", "DigitalOcean"),
    ("hetzner.com", "Hetzner"),
    ("hetzner.de", "Hetzner"),
    ("your-server.de", "Hetzner"),
    ("ovh.net", "OVHcloud"),
    ("ovh.ca", "OVHcloud"),
    ("gandi.net", "Gandi"),
    ("name-services.com", "Enom"),
    ("vercel-dns.com", "Vercel"),
    ("wixdns.net", "Wix"),
    ("dns-parking.com", "Hostinger"),
    ("bluehost.com", "Bluehost"),
    ("dreamhost.com", "DreamHost"),
    ("linode.com", "Akamai (Linode)"),
    ("porkbun.com", "Porkbun"),
    ("ui-dns.com", "IONOS"),
    ("ui-dns.de", "IONOS"),
    ("ui-dns.org", "IONOS"),
    ("ui-dns.biz", "IONOS"),
    ("name.com", "Name.com"),
    ("dnsmadeeasy.com", "DNS Made Easy"),
    ("cscdns.net", "CSC"),
    ("markmonitor.com", "MarkMonitor"),
    ("alidns.com", "Alibaba Cloud DNS"),
    ("hichina.com", "Alibaba Cloud DNS"),
    ("dnspod.net", "Tencent DNSPod"),
    ("dnspod.com", "Tencent DNSPod"),
    ("he.net", "Hurricane Electric"),
    ("desec.io", "deSEC"),
    ("sedoparking.com", "Sedo (parking)"),
    ("parkingcrew.net", "ParkingCrew (parking)"),
    ("bodis.com", "Bodis (parking)"),
    ("above.com", "Above.com (parking)"),
    ("dan.com", "Dan.com (parking)"),
    ("afternic.com", "Afternic (parking)"),
];

/// MX suffix -> mail provider.
const MAIL_PROVIDERS: &[(&str, &str)] = &[
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("protection.outlook.com", "Microsoft 365"),
    ("pphosted.com", "Proofpoint"),
    ("ppe-hosted.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("mimecast.co.za", "Mimecast"),
    ("messagelabs.com", "Broadcom Email Security"),
    ("barracudanetworks.com", "Barracuda"),
    ("iphmx.com", "Cisco Secure Email"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("zoho.in", "Zoho Mail"),
    ("zohomail.com", "Zoho Mail"),
    ("protonmail.ch", "Proton Mail"),
    ("messagingengine.com", "Fastmail"),
    ("icloud.com", "iCloud Mail"),
    ("yahoodns.net", "Yahoo"),
    ("secureserver.net", "GoDaddy"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("amazonaws.com", "Amazon SES"),
    ("mx.cloudflare.net", "Cloudflare Email Routing"),
    ("cf-emailsecurity.net", "Cloudflare Email Security"),
    ("hornetsecurity.com", "Hornetsecurity"),
    ("trendmicro.com", "Trend Micro"),
    ("trendmicro.eu", "Trend Micro"),
    ("mailcontrol.com", "Forcepoint"),
    ("ovh.net", "OVHcloud"),
    ("ionos.com", "IONOS"),
    ("ionos.de", "IONOS"),
    ("kundenserver.de", "IONOS"),
    ("titan.email", "Titan"),
    ("yandex.net", "Yandex 360"),
    ("emailsrvr.com", "Rackspace"),
    ("privateemail.com", "Namecheap Private Email"),
    ("improvmx.com", "ImprovMX"),
    ("forwardemail.net", "Forward Email"),
    ("migadu.com", "Migadu"),
    ("mailbox.org", "mailbox.org"),
];

fn provider(host: &str, table: &[(&str, &'static str)]) -> Option<&'static str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    table.iter().find_map(|(pat, name)| {
        let hit = if pat.ends_with('-') {
            host.contains(pat)
        } else {
            host == *pat || host.strip_suffix(pat).is_some_and(|rest| rest.ends_with('.'))
        };
        hit.then_some(*name)
    })
}

pub fn dns_provider(ns: &[String]) -> Option<String> {
    let mut uniq: Vec<&str> = vec![];
    for n in ns.iter().filter_map(|h| provider(h, DNS_PROVIDERS)) {
        if !uniq.contains(&n) {
            uniq.push(n);
        }
    }
    (!uniq.is_empty()).then(|| uniq.join(" + "))
}

pub fn mail_provider(mx: &[Mx]) -> Option<String> {
    let best = mx.iter().min_by_key(|m| m.preference)?;
    provider(&best.host, MAIL_PROVIDERS).map(str::to_string)
}

// ---------------- resolver ----------------

/// The system resolver, plus a public fallback for queries it fails or answers slowly. Home
/// routers often can't answer large TXT sets (they need EDNS0 or TCP), which would silently
/// hide SPF, and some take seconds over names their upstream is slow to resolve.
pub struct Resolvers {
    primary: TokioResolver,
    fallback: Option<TokioResolver>,
}

/// `WHOQ_DNS_SERVER=ip[:port]` pins one resolver with no fallback (tests, split-horizon,
/// privacy); otherwise the system configuration, retrying failures via Cloudflare.
pub fn build_resolvers(timeout: Duration) -> Result<Resolvers, String> {
    let pinned = std::env::var("WHOQ_DNS_SERVER").ok().filter(|s| !s.is_empty());
    let primary = build_resolver(pinned.as_deref(), timeout, pinned.is_some())?;
    let fallback = match pinned {
        Some(_) => None,
        None => Some(public(timeout)?),
    };
    Ok(Resolvers { primary, fallback })
}

fn public(timeout: Duration) -> Result<TokioResolver, String> {
    let mut b =
        Resolver::builder_with_config(ResolverConfig::udp_and_tcp(&CLOUDFLARE), TokioRuntimeProvider::default());
    tune(b.options_mut(), timeout, 2);
    b.build().map_err(|e| format!("resolver: {e}"))
}

fn tune(o: &mut hickory_resolver::config::ResolverOpts, timeout: Duration, attempts: usize) {
    o.timeout = timeout.min(Duration::from_secs(5));
    o.attempts = attempts;
    // Big TXT sets (SPF + verification tokens) overflow 512-byte UDP; EDNS0 avoids most TCP retries.
    o.edns0 = true;
    o.use_hosts_file = ResolveHosts::Never;
}

fn build_resolver(pinned: Option<&str>, timeout: Duration, final_say: bool) -> Result<TokioResolver, String> {
    let mut b = match pinned {
        Some(s) => {
            let addr: SocketAddr = s
                .parse()
                .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
                .map_err(|_| format!("WHOQ_DNS_SERVER: expected ip or ip:port, got {s:?}"))?;
            let (mut udp, mut tcp) = (ConnectionConfig::udp(), ConnectionConfig::tcp());
            udp.port = addr.port();
            tcp.port = addr.port();
            let ns = NameServerConfig::new(addr.ip(), true, vec![udp, tcp]);
            Resolver::builder_with_config(ResolverConfig::from_name_servers(vec![ns]), TokioRuntimeProvider::default())
        }
        None => match hickory_resolver::system_conf::read_system_conf() {
            // UDP only: a truncated answer then fails at once and goes to the fallback, instead of
            // waiting out a TCP connection that many home routers never accept.
            Ok((cfg, opts)) => {
                let (domain, search, mut servers) = cfg.into_parts();
                for s in &mut servers {
                    s.connections.retain(|c| c.protocol == ProtocolConfig::Udp);
                }
                servers.retain(|s| !s.connections.is_empty());
                Resolver::builder_with_config(
                    ResolverConfig::from_parts(domain, search, servers),
                    TokioRuntimeProvider::default(),
                )
                .with_options(opts)
            }
            Err(_) => return public(timeout),
        },
    };
    // With a fallback behind it, fail fast (one try, short timeout) and let the fallback answer.
    if final_say {
        tune(b.options_mut(), timeout, 2);
    } else {
        tune(b.options_mut(), timeout.min(Duration::from_secs(3)), 1);
    }
    b.build().map_err(|e| format!("resolver: {e}"))
}

async fn resolver(ctx: &Ctx) -> Result<&Resolvers, String> {
    ctx.resolver.get_or_init(|| async { build_resolvers(ctx.opts.timeout) }).await.as_ref().map_err(Clone::clone)
}

#[derive(Debug, PartialEq)]
enum Fail {
    NxDomain,
    Other(String),
}

fn fqdn(name: &str) -> String {
    if name.ends_with('.') { name.to_string() } else { format!("{name}.") }
}

/// Records of exactly `rt` (CNAME hops are followed by the resolver and dropped here).
/// "No records" is an empty list; NXDOMAIN and failures are errors.
async fn query(r: &Resolvers, name: &str, rt: RecordType) -> Result<Vec<RData>, Fail> {
    let n = Name::from_ascii(fqdn(name)).map_err(|e| Fail::Other(e.to_string()))?;
    query_name(r, n, rt).await
}

async fn query_name(r: &Resolvers, n: Name, rt: RecordType) -> Result<Vec<RData>, Fail> {
    let primary = lookup_one(&r.primary, n.clone(), rt);
    match &r.fallback {
        None => primary.await,
        Some(f) => hedge(primary, || lookup_one(f, n, rt), HEDGE_AFTER).await,
    }
}

/// How long the system resolver gets before the fallback is asked too. Home routers can take
/// seconds to answer a name their upstream finds slow (e.g. a DKIM CNAME into another provider).
const HEDGE_AFTER: Duration = Duration::from_millis(800);

/// Run `primary`; if it fails, ask `fallback`. If it is still running after `after`, start
/// `fallback` as well and return the first definite answer (records, empty, or NXDOMAIN).
async fn hedge<T, P, F>(primary: P, fallback: impl FnOnce() -> F, after: Duration) -> Result<T, Fail>
where
    P: std::future::Future<Output = Result<T, Fail>>,
    F: std::future::Future<Output = Result<T, Fail>>,
{
    tokio::pin!(primary);
    match tokio::time::timeout(after, &mut primary).await {
        Ok(Err(Fail::Other(_))) => return fallback().await,
        Ok(done) => return done,
        Err(_) => {}
    }
    let fallback = fallback();
    tokio::pin!(fallback);
    tokio::select! {
        p = &mut primary => match p {
            Err(Fail::Other(_)) => fallback.await,
            done => done,
        },
        f = &mut fallback => match f {
            Err(Fail::Other(_)) => primary.await,
            done => done,
        },
    }
}

async fn lookup_one(r: &TokioResolver, n: Name, rt: RecordType) -> Result<Vec<RData>, Fail> {
    match r.lookup(n, rt).await {
        Ok(l) => Ok(l.answers().iter().filter(|rec| rec.record_type() == rt).map(|rec| rec.data.clone()).collect()),
        Err(e) if e.is_nx_domain() => Err(Fail::NxDomain),
        Err(e) if e.is_no_records_found() => Ok(vec![]),
        Err(e) => Err(Fail::Other(e.to_string())),
    }
}

fn host(n: &Name) -> String {
    clean(n.to_ascii().trim_end_matches('.'), 253).to_ascii_lowercase()
}

/// TXT strings at `name` (each record's character-strings joined, as SPF/DMARC require).
async fn txt(r: &Resolvers, name: &str) -> Vec<String> {
    query(r, name, RecordType::TXT)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| match d {
            RData::TXT(t) => Some(t.txt_data.iter().map(|s| String::from_utf8_lossy(s).into_owned()).collect()),
            _ => None,
        })
        .collect()
}

fn starts_with_tag(s: &str, tag: &str) -> bool {
    let s = s.trim_start();
    s.len() >= tag.len()
        && s[..tag.len()].eq_ignore_ascii_case(tag)
        && s[tag.len()..].chars().next().is_none_or(|c| c == ' ' || c == ';')
}

// ---------------- reverse DNS ----------------

/// PTR names for `ip`, plus forward confirmation (a PTR name resolves back to `ip`).
pub async fn rdns(ctx: &Ctx, ip: IpAddr) -> Rdns {
    let r = match resolver(ctx).await {
        Ok(r) => r,
        Err(e) => return Rdns { error: Some(e), ..Default::default() },
    };
    let ptr: Vec<String> = match query_name(r, Name::from(ip), RecordType::PTR).await {
        Ok(v) => v
            .into_iter()
            .filter_map(|d| match d {
                RData::PTR(p) => Some(host(&p.0)),
                _ => None,
            })
            .filter(|h| !h.is_empty())
            .take(4)
            .collect(),
        Err(Fail::NxDomain) => vec![],
        Err(Fail::Other(e)) => return Rdns { error: Some(clean(&e, 200)), ..Default::default() },
    };
    if ptr.is_empty() {
        return Rdns::default();
    }
    let rt = if ip.is_ipv4() { RecordType::A } else { RecordType::AAAA };
    let forward = join_all(ptr.iter().map(|h| query(r, h, rt))).await;
    let verified = forward.into_iter().flatten().flatten().any(|d| match d {
        RData::A(a) => IpAddr::V4(a.0) == ip,
        RData::AAAA(a) => IpAddr::V6(a.0) == ip,
        _ => false,
    });
    Rdns { ptr, verified: Some(verified), error: None }
}

// ---------------- domains ----------------

async fn addresses(r: &Resolvers, name: &str) -> Result<(Vec<String>, Vec<String>), Fail> {
    let (a, aaaa) = tokio::join!(query(r, name, RecordType::A), query(r, name, RecordType::AAAA));
    let a = a?.into_iter().filter_map(|d| if let RData::A(x) = d { Some(x.0.to_string()) } else { None }).collect();
    let aaaa = aaaa
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| if let RData::AAAA(x) = d { Some(x.0.to_string()) } else { None })
        .collect();
    Ok((a, aaaa))
}

/// Cymru appends the AS's registration country (", US") to AS names; drop it; the
/// address's own country has its own field.
fn strip_cc(name: &str) -> String {
    match name.rsplit_once(", ") {
        Some((head, cc)) if cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_uppercase()) => head.to_string(),
        _ => name.to_string(),
    }
}

/// The AS announcing `ip` in BGP (`--asn`). Private and reserved addresses are never announced.
pub async fn origin(ctx: &Ctx, ip: IpAddr) -> crate::model::Origin {
    use crate::model::Origin;
    if crate::bulk::is_private(&ip) {
        return Origin {
            error: Some("private or reserved address; not announced in BGP".into()),
            ..Default::default()
        };
    }
    match crate::bulk::cymru_lookup(ctx, &[ip]).await {
        Ok(answers) => match answers.into_iter().find(|(a, _)| *a == ip).map(|(_, i)| i) {
            Some(i) if i.asn.is_some() => Origin {
                asn: i.asn,
                name: i.as_name.as_deref().map(strip_cc),
                prefix: i.prefix,
                country: i.country,
                error: None,
            },
            _ => Origin { error: Some("not announced in BGP".into()), ..Default::default() },
        },
        Err(e) => Origin { error: Some(e.message().to_string()), ..Default::default() },
    }
}

async fn hosting(ctx: &Ctx, ips: &[String]) -> Vec<Hosting> {
    let ips: Vec<IpAddr> =
        ips.iter().filter_map(|s| s.parse().ok()).filter(|ip| !crate::bulk::is_private(ip)).take(16).collect();
    if ips.is_empty() {
        return vec![];
    }
    let Ok(answers) = crate::bulk::cymru_lookup(ctx, &ips).await else { return vec![] };
    let mut out: Vec<Hosting> = vec![];
    for ip in &ips {
        let Some((_, info)) = answers.iter().find(|(a, _)| a == ip) else { continue };
        match out.iter_mut().find(|h| h.asn == info.asn && info.asn.is_some()) {
            Some(h) => h.ips.push(ip.to_string()),
            None => out.push(Hosting {
                asn: info.asn,
                name: info.as_name.as_deref().map(strip_cc),
                country: info.country.clone(),
                ips: vec![ip.to_string()],
            }),
        }
    }
    out
}

pub fn parse_spf(records: &[String]) -> Option<Spf> {
    let spf: Vec<&String> = records.iter().filter(|t| starts_with_tag(t, "v=spf1")).collect();
    let first = spf.first()?;
    let mut s = Spf { record: clean(first, 512), ..Default::default() };
    for tok in first.split_whitespace().skip(1) {
        let lower = tok.to_ascii_lowercase();
        let bare = lower.trim_start_matches(['+', '-', '~', '?']);
        if bare == "all" {
            s.all = Some(if lower == "all" { "+all".into() } else { lower.clone() });
        } else if let Some(d) = bare.strip_prefix("include:").or_else(|| bare.strip_prefix("redirect=")) {
            s.includes.push(clean(d, 253));
        }
    }
    if spf.len() > 1 {
        s.error = Some(format!("{} SPF records (receivers treat this as a permanent error)", spf.len()));
    }
    Some(s)
}

pub fn parse_dmarc(records: &[String]) -> Option<Dmarc> {
    let dm: Vec<&String> = records.iter().filter(|t| starts_with_tag(t, "v=DMARC1")).collect();
    let first = dm.first()?;
    let mut d = Dmarc { record: clean(first, 512), ..Default::default() };
    let policy = |v: &str| {
        let v = v.to_ascii_lowercase();
        ["none", "quarantine", "reject"].contains(&v.as_str()).then_some(v)
    };
    for part in first.split(';') {
        let Some((k, v)) = part.split_once('=') else { continue };
        let v = v.trim();
        match k.trim().to_ascii_lowercase().as_str() {
            "p" => d.policy = policy(v),
            "sp" => d.subdomain_policy = policy(v),
            "pct" => d.pct = v.parse().ok().filter(|p| *p <= 100),
            "rua" => d.rua = v.split(',').map(|x| clean(x.trim(), 253)).filter(|x| !x.is_empty()).collect(),
            _ => {}
        }
    }
    if dm.len() > 1 {
        // RFC 7489: more than one record means no DMARC policy applies.
        d.policy = None;
    }
    Some(d)
}

async fn mail(r: &Resolvers, domain: &str) -> Mail {
    let dkim_names: Vec<String> = DKIM_SELECTORS.iter().map(|s| format!("{s}._domainkey.{domain}")).collect();
    let (dmarc_n, sts_n, tlsrpt_n, bimi_n) = (
        format!("_dmarc.{domain}"),
        format!("_mta-sts.{domain}"),
        format!("_smtp._tls.{domain}"),
        format!("default._bimi.{domain}"),
    );
    let (mx, root_txt, dmarc_txt, sts, tlsrpt, bimi, dkim) = tokio::join!(
        query(r, domain, RecordType::MX),
        txt(r, domain),
        txt(r, &dmarc_n),
        txt(r, &sts_n),
        txt(r, &tlsrpt_n),
        txt(r, &bimi_n),
        join_all(dkim_names.iter().map(|n| txt(r, n))),
    );
    let mut m = Mail::default();
    let mx = match mx {
        Ok(mx) => mx,
        Err(Fail::NxDomain) => return Mail { error: Some(NXDOMAIN.into()), ..Default::default() },
        Err(Fail::Other(e)) => return Mail { error: Some(clean(&e, 200)), ..Default::default() },
    };
    for d in mx {
        if let RData::MX(x) = d {
            if x.exchange.is_root() {
                m.null_mx = true;
            } else {
                m.mx.push(Mx { preference: x.preference, host: host(&x.exchange) });
            }
        }
    }
    m.mx.sort_by(|a, b| a.preference.cmp(&b.preference).then(a.host.cmp(&b.host)));
    m.mx.truncate(10);
    m.provider = mail_provider(&m.mx);
    m.spf = parse_spf(&root_txt);
    m.dmarc = parse_dmarc(&dmarc_txt);
    m.mta_sts = sts.iter().any(|t| starts_with_tag(t, "v=STSv1"));
    m.tls_rpt = tlsrpt.iter().any(|t| starts_with_tag(t, "v=TLSRPTv1"));
    m.bimi = bimi.iter().any(|t| starts_with_tag(t, "v=BIMI1"));
    m.dkim_selectors = DKIM_SELECTORS
        .iter()
        .zip(dkim)
        .filter(|(_, recs)| recs.iter().any(|t| t.contains("p=")))
        .map(|(s, _)| s.to_string())
        .collect();
    m
}

const NXDOMAIN: &str = "NXDOMAIN: the domain does not exist in DNS";

/// Fill `rec.dns` and/or `rec.mail` for a domain, as `live` asks.
pub async fn domain(ctx: &Ctx, rec: &mut Record, domain: &str, live: Live) {
    let r = match resolver(ctx).await {
        Ok(r) => r,
        Err(e) => {
            rec.dns = live.dns.then(|| Dns { error: Some(e.clone()), ..Default::default() });
            rec.mail = live.mail.then(|| Mail { error: Some(e), ..Default::default() });
            return;
        }
    };
    let (d, m) = tokio::join!(async { if live.dns { Some(dns_part(ctx, r, domain).await) } else { None } }, async {
        if live.mail { Some(mail(r, domain).await) } else { None }
    },);
    (rec.dns, rec.mail) = (d, m);
}

async fn dns_part(ctx: &Ctx, r: &Resolvers, domain: &str) -> Dns {
    let mut d = Dns { host: Some(domain.to_string()), ..Default::default() };
    let (addrs, ns, caa) =
        tokio::join!(addresses(r, domain), query(r, domain, RecordType::NS), query(r, domain, RecordType::CAA),);
    match addrs {
        Err(Fail::NxDomain) => {
            d.error = Some(NXDOMAIN.into());
            return d;
        }
        Err(Fail::Other(e)) => {
            d.error = Some(clean(&e, 200));
            return d;
        }
        Ok((a, aaaa)) => (d.a, d.aaaa) = (a, aaaa),
    }
    if d.a.is_empty() && d.aaaa.is_empty() {
        let www = format!("www.{domain}");
        if let Ok((a, aaaa)) = addresses(r, &www).await
            && !(a.is_empty() && aaaa.is_empty())
        {
            (d.a, d.aaaa) = (a, aaaa);
            d.host = Some(www);
        }
    }
    d.a.truncate(16);
    d.aaaa.truncate(16);
    let all: Vec<String> = d.a.iter().chain(&d.aaaa).cloned().collect();
    d.hosting = hosting(ctx, &all).await;
    d.ns = ns
        .unwrap_or_default()
        .into_iter()
        .filter_map(|x| if let RData::NS(n) = x { Some(host(&n.0)) } else { None })
        .collect();
    d.ns.sort();
    d.ns.truncate(13);
    d.provider = dns_provider(&d.ns);
    d.caa = caa
        .unwrap_or_default()
        .into_iter()
        .filter_map(|x| {
            if let RData::CAA(c) = x {
                Some(clean(&format!("{} {}", c.tag, String::from_utf8_lossy(&c.value)), 256))
            } else {
                None
            }
        })
        .collect();
    d.caa.truncate(10);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn after(ms: u64, r: Result<&'static str, Fail>) -> Result<&'static str, Fail> {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        r
    }

    #[tokio::test(start_paused = true)]
    async fn hedge_races_a_slow_primary() {
        let hedged = Duration::from_millis(800);
        let other = || Err(Fail::Other("timeout".into()));
        let fast = hedge(after(100, Ok("primary")), || after(10, Ok("fallback")), hedged).await;
        assert_eq!(fast, Ok("primary"), "a quick primary never touches the fallback");
        let slow = hedge(after(6000, Err(Fail::NxDomain)), || after(50, Ok("fallback")), hedged).await;
        assert_eq!(slow, Ok("fallback"), "a slow primary is overtaken");
        let t0 = tokio::time::Instant::now();
        let failed = hedge(after(100, other()), || after(50, Ok("fallback")), hedged).await;
        assert_eq!((failed, t0.elapsed()), (Ok("fallback"), Duration::from_millis(150)), "failure: fallback at once");
        let slow_bad = hedge(after(2000, Ok("primary")), || after(50, other()), hedged).await;
        assert_eq!(slow_bad, Ok("primary"), "a failing fallback waits for the primary");
    }

    #[test]
    fn providers() {
        let ns = |v: &[&str]| dns_provider(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(ns(&["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]).as_deref(), Some("Cloudflare"));
        assert_eq!(ns(&["ns-12.awsdns-01.com"]).as_deref(), Some("AWS Route 53"));
        assert_eq!(ns(&["ns1.sedoparking.com"]).as_deref(), Some("Sedo (parking)"));
        assert_eq!(ns(&["ns1.notcloudflare.com"]), None, "suffix must match on a label boundary");
        assert_eq!(ns(&["ns1.example.net"]), None);
        let mx = |h: &str| mail_provider(&[Mx { preference: 1, host: h.into() }]);
        assert_eq!(mx("aspmx.l.google.com").as_deref(), Some("Google Workspace"));
        assert_eq!(mx("example-com.mail.protection.outlook.com").as_deref(), Some("Microsoft 365"));
    }

    #[test]
    fn spf_and_dmarc() {
        let s =
            parse_spf(&["google-site-verification=x".into(), "v=spf1 include:_spf.google.com ~all".into()]).unwrap();
        assert_eq!(s.all.as_deref(), Some("~all"));
        assert_eq!(s.includes, vec!["_spf.google.com"]);
        assert!(s.error.is_none());
        assert_eq!(parse_spf(&["v=spf1 all".into()]).unwrap().all.as_deref(), Some("+all"));
        assert!(parse_spf(&["v=spf1 -all".into(), "v=spf1 ~all".into()]).unwrap().error.is_some());
        assert!(parse_spf(&["v=spf10 -all".into()]).is_none());

        let d = parse_dmarc(&["v=DMARC1; p=Reject; sp=quarantine; pct=50; rua=mailto:a@x.com,mailto:b@y.com".into()])
            .unwrap();
        assert_eq!(d.policy.as_deref(), Some("reject"));
        assert_eq!(d.subdomain_policy.as_deref(), Some("quarantine"));
        assert_eq!(d.pct, Some(50));
        assert_eq!(d.rua.len(), 2);
        assert_eq!(parse_dmarc(&["v=DMARC1; p=bogus".into()]).unwrap().policy, None);
        assert_eq!(parse_dmarc(&["v=DMARC1; p=reject".into(), "v=DMARC1; p=none".into()]).unwrap().policy, None);
    }
}
